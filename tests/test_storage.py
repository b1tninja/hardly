"""Storage modes, atomic cache writes, read-only open, persist."""

from __future__ import annotations

import os
import sqlite3
import sys
import time
from pathlib import Path

import pytest

from hardly import session as sess
from hardly.index import ingest as ingest_mod
from hardly.index import query as q
from hardly.index.atomic import cleanup_stray_temps
from hardly.index.ingest import ingest_har, ingest_memory
from hardly.index.schema import open_readonly, path_to_ro_uri

FIXTURE = Path(__file__).parent / "fixtures" / "sample.har"


@pytest.fixture(autouse=True)
def _cache(tmp_path, monkeypatch):
    monkeypatch.setenv("HARDLY_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.delenv("HARDLY_INDEX", raising=False)
    monkeypatch.delenv("HARDLY_INDEX_MEMORY_MAX_MB", raising=False)
    for sid in list(sess._sessions):  # other modules leave live sessions behind
        sess.close_session(sid)
    yield
    for sid in list(sess._sessions):
        sess.close_session(sid)


def _cache_files(tmp_path):
    d = tmp_path / "cache"
    return sorted(p.name for p in d.iterdir()) if d.exists() else []


def test_default_is_disk_and_no_wal(tmp_path):
    info = sess.open_har(FIXTURE)
    assert info["storage"] == "disk"
    sid = info["session_id"]
    assert _cache_files(tmp_path) == [f"{sid}.db", f"{sid}.json"]
    assert not sess._is_wal(tmp_path / "cache" / f"{sid}.db")


def test_memory_mode_leaves_no_files(tmp_path):
    info = sess.open_har(FIXTURE, storage="memory")
    assert info["storage"] == "memory"
    assert "gone after a restart" in info["note"]
    assert _cache_files(tmp_path) == []
    conn = sess.require_conn(info["session_id"])
    assert q.summary(conn)["entries"] == 22
    rows = [r for r in sess.list_sessions() if r["session_id"] == info["session_id"]]
    assert rows[0]["storage"] == "memory" and rows[0]["open"] is True


def test_memory_session_gone_after_close_with_clear_message():
    sid = sess.open_har(FIXTURE, storage="memory")["session_id"]
    closed = sess.close_session(sid)
    assert closed["storage"] == "memory"
    res = sess.reopen_session(sid)
    assert "error" in res and "storage=memory" in res["hint"]
    with pytest.raises(KeyError, match="storage=memory"):
        sess.require_conn(sid)


def test_env_selects_storage(tmp_path, monkeypatch):
    monkeypatch.setenv("HARDLY_INDEX", "memory")
    assert sess.open_har(FIXTURE)["storage"] == "memory"
    assert _cache_files(tmp_path) == []
    monkeypatch.setenv("HARDLY_INDEX", "bogus")  # ignored -> default
    assert sess.resolve_storage(None, FIXTURE) == "disk"


def test_explicit_storage_overrides_and_switches():
    a = sess.open_har(FIXTURE, storage="memory")
    assert sess.open_har(FIXTURE)["storage"] == "memory"  # no explicit: reuse live
    b = sess.open_har(FIXTURE, storage="disk")
    assert a["session_id"] == b["session_id"] and b["storage"] == "disk"
    assert sess.get_storage(b["session_id"]) == "disk"
    assert "error" in sess.open_har(FIXTURE, storage="floppy")


def test_auto_threshold(monkeypatch):
    size_mb = FIXTURE.stat().st_size / 1024 / 1024
    monkeypatch.setenv("HARDLY_INDEX_MEMORY_MAX_MB", str(size_mb + 1))
    assert sess.resolve_storage("auto", FIXTURE) == "memory"
    monkeypatch.setenv("HARDLY_INDEX_MEMORY_MAX_MB", str(size_mb / 2))
    assert sess.resolve_storage("auto", FIXTURE) == "disk"
    monkeypatch.setenv("HARDLY_INDEX", "auto")
    monkeypatch.setenv("HARDLY_INDEX_MEMORY_MAX_MB", "25")
    assert sess.open_har(FIXTURE)["storage"] == "memory"


def test_session_connection_rejects_writes():
    for storage in ("disk", "memory"):
        sid = sess.open_har(FIXTURE, force=True, storage=storage)["session_id"]
        conn = sess.require_conn(sid)
        with pytest.raises(sqlite3.OperationalError):
            conn.execute("UPDATE entries SET status = 0")
        with pytest.raises(sqlite3.OperationalError):
            conn.execute("CREATE TABLE x (a)")
        assert conn.row_factory is sqlite3.Row
        sess.close_session(sid)


def test_ro_uri_is_quoted(tmp_path):
    odd = tmp_path / "we ird#dir" / "a b.db"
    odd.parent.mkdir()
    c = sqlite3.connect(odd)
    c.execute("CREATE TABLE t (a)")
    c.commit()
    c.close()
    uri = path_to_ro_uri(odd)
    assert uri.startswith("file:") and uri.endswith("?mode=ro")
    assert "#" not in uri and " " not in uri
    open_readonly(odd).close()


@pytest.mark.skipif(
    sys.platform == "win32" or (hasattr(os, "geteuid") and os.geteuid() == 0),
    reason="chmod is ineffective on Windows / as root",
)
def test_opens_from_read_only_cache_dir(tmp_path):
    sid = sess.open_har(FIXTURE)["session_id"]
    sess.close_session(sid)
    cache = tmp_path / "cache"
    cache.chmod(0o555)
    try:
        info = sess.open_har(FIXTURE)
        assert info["cached"] is True and info["entries"] == 22
        assert q.summary(sess.require_conn(sid))["entries"] == 22
    finally:
        cache.chmod(0o755)


def test_failed_ingest_leaves_no_partial_cache(tmp_path, monkeypatch):
    cache = tmp_path / "cache"
    real = ingest_mod._store_headers
    calls = {"n": 0}

    def boom(*a, **k):
        calls["n"] += 1
        if calls["n"] > 3:
            raise RuntimeError("simulated crash")
        return real(*a, **k)

    monkeypatch.setattr(ingest_mod, "_store_headers", boom)
    with pytest.raises(RuntimeError):
        sess.open_har(FIXTURE)
    assert _cache_files(tmp_path) == []
    assert sess._sessions == {}
    # An existing good cache survives a failed rebuild untouched.
    monkeypatch.setattr(ingest_mod, "_store_headers", real)
    sid = sess.open_har(FIXTURE)["session_id"]
    before = (cache / f"{sid}.db").read_bytes()
    monkeypatch.setattr(ingest_mod, "_store_headers", boom)
    calls["n"] = 0
    with pytest.raises(RuntimeError):
        sess.open_har(FIXTURE, force=True)
    assert (cache / f"{sid}.db").read_bytes() == before
    assert _cache_files(tmp_path) == [f"{sid}.db", f"{sid}.json"]


def test_stray_temp_cleanup(tmp_path):
    cache = tmp_path / "cache"
    cache.mkdir()
    old = cache / ".hardly-db-abc-12345678.tmp"
    old.write_bytes(b"x")
    fresh = cache / ".hardly-db-abc-87654321.tmp"
    fresh.write_bytes(b"x")
    other = cache / "keep.json"
    other.write_text("{}")
    past = time.time() - 3600
    os.utime(old, (past, past))
    assert cleanup_stray_temps(cache) == [old.name]
    assert not old.exists() and fresh.exists() and other.exists()
    os.utime(fresh, (past, past))
    sess.open_har(FIXTURE)  # open sweeps too
    assert not fresh.exists()


def test_legacy_wal_cache_is_rebuilt(tmp_path):
    sid = sess.open_har(FIXTURE)["session_id"]
    sess.close_session(sid)
    db = tmp_path / "cache" / f"{sid}.db"
    c = sqlite3.connect(db)
    c.execute("PRAGMA journal_mode=WAL")
    c.close()
    assert sess._is_wal(db)
    info = sess.open_har(FIXTURE)
    assert info["cached"] is False
    assert not sess._is_wal(db)


def test_ingest_har_wrapper_and_memory_agree(tmp_path):
    stats = ingest_har(FIXTURE, tmp_path / "x.db")
    mstats, conn = ingest_memory(FIXTURE)
    assert stats["entries"] == mstats["entries"] == 22
    assert mstats["db_path"] == ":memory:"
    disk = open_readonly(tmp_path / "x.db")
    assert q.summary(disk) == q.summary(conn)
    disk.close()
    conn.close()
    assert [p.name for p in tmp_path.iterdir() if p.name != "cache"] == ["x.db"]


def test_persist_round_trip(tmp_path):
    sid = sess.open_har(FIXTURE, storage="memory")["session_id"]
    expected = q.summary(sess.require_conn(sid))
    out = tmp_path / "out" / "copy.db"
    res = sess.persist_session(sid, out)
    assert res["persisted"] and res["size_bytes"] > 0
    assert Path(res["path"]) == out.absolute()
    assert _cache_files(tmp_path) == []  # nothing in the cache for an explicit path
    ro = open_readonly(out)
    assert q.summary(ro) == expected
    ro.close()
    assert "error" in sess.persist_session(sid, out)  # refuses to overwrite
    assert sess.persist_session(sid, out, overwrite=True)["persisted"]
    assert [p.name for p in out.parent.iterdir()] == ["copy.db"]


def test_persist_into_cache_reattaches_after_restart(tmp_path):
    sid = sess.open_har(FIXTURE, storage="memory")["session_id"]
    expected = q.summary(sess.require_conn(sid))
    res = sess.persist_session(sid)
    assert res["cache_entry"] is True
    sess.close_session(sid)
    again = sess.reopen_session(sid)
    assert again["storage"] == "disk"
    assert q.summary(sess.require_conn(sid)) == expected
    # disk session: persist without a path is a no-op; never in place
    assert "Already stored" in sess.persist_session(sid)["note"]
    own = tmp_path / "cache" / f"{sid}.db"
    assert "error" in sess.persist_session(sid, own, overwrite=True)


def test_persist_disk_session_to_path(tmp_path):
    sid = sess.open_har(FIXTURE)["session_id"]
    out = tmp_path / "copy.db"
    assert sess.persist_session(sid, out)["persisted"]
    ro = open_readonly(out)
    assert q.summary(ro)["entries"] == 22
    ro.close()


def test_contract_uses_memory_and_leaves_nothing(tmp_path, monkeypatch):
    import tempfile

    from hardly.core.contract import check_contract

    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    spec = {"openapi": "3.0.3", "info": {"title": "t", "version": "1"}, "paths": {}}
    res = check_contract(str(FIXTURE), spec)
    assert "host" in res
    assert [p.name for p in tmp_path.iterdir() if p.name != "cache"] == []
