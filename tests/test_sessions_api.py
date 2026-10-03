"""Public session API: one rule (an output path saves, otherwise nothing is written)."""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import sqlite3
import sys
import threading
from pathlib import Path

import pytest

import hardly
from hardly import server
from hardly import session as sess
from hardly.index import ingest as ingest_mod
from hardly.index import query as q
from hardly.index.ingest import ingest_memory
from hardly.index.schema import open_readonly
from hardly.session import OutputExists, UnknownSession, open_session

FIXTURE = Path(__file__).parent / "fixtures" / "sample.har"


@pytest.fixture(autouse=True)
def _env(tmp_path, monkeypatch):
    monkeypatch.setenv("HARDLY_RUNTIME_DIR", str(tmp_path / "runtime"))


@pytest.fixture()
def har(tmp_path):
    p = tmp_path / "in" / "a.har"
    p.parent.mkdir()
    shutil.copy(FIXTURE, p)
    return p


def _files(root: Path) -> list[str]:
    return sorted(str(p.relative_to(root)) for p in root.rglob("*") if p.is_file())


def _count_ingests(monkeypatch):
    calls = {"n": 0}
    real = sess.ingest_memory

    def counting(*a, **k):
        calls["n"] += 1
        return real(*a, **k)

    monkeypatch.setattr(sess, "ingest_memory", counting)
    return calls


# ---------------------------------------------------------------- the one rule


def test_public_exports_and_no_storage_concepts():
    for name in ("open_session", "Session", "UnknownSession", "OutputExists"):
        assert getattr(hardly, name) is getattr(sess, name)
    for gone in ("Memory", "File", "Persist", "Cache", "Auto", "StorageConflict", "parse_storage"):
        assert not hasattr(sess, gone)
    assert not hasattr(server, "hardly_persist") and not hasattr(server, "hardly_reopen")


def test_no_output_path_writes_nothing(har, tmp_path):
    before = _files(tmp_path)
    with open_session(har) as s:
        assert s.saved_to is None and s.info["saved_to"] is None
        assert q.summary(s.conn)["entries"] == 22
    assert _files(tmp_path) == before


def test_output_path_saves_atomically_and_opens_readonly(har, tmp_path):
    out = tmp_path / "out" / "idx.db"
    with open_session(har, out) as s:
        assert out.is_file() and s.info["saved_to"] == str(out.resolve())
        first = s.info
    assert [p.name for p in out.parent.iterdir()] == ["idx.db"]  # no temp leftovers
    ro = open_readonly(out)
    with pytest.raises(sqlite3.OperationalError):
        ro.execute("UPDATE entries SET status = 0")
    ro.close()
    # Reopen from the saved index: no re-ingest, identical summary, source HAR not needed.
    har.unlink()
    with open_session(out) as s2:
        assert s2.info["opened_from"] == "index"
        for key in ("entries", "api", "noise", "hosts", "methods", "statuses", "har_path"):
            assert s2.info[key] == first[key]
        with pytest.raises(sqlite3.OperationalError):
            s2.conn.execute("CREATE TABLE x (a)")


def test_output_refused_if_exists_unless_overwrite(har, tmp_path):
    out = tmp_path / "idx.db"
    out.write_text("mine")
    with pytest.raises(OutputExists) as ei:
        open_session(har, out)
    assert ei.value.code == "output_exists" and "overwrite" in ei.value.hint
    assert out.read_text() == "mine" and sess._sessions == {}
    with open_session(har, out, overwrite=True):
        pass
    assert open_readonly(out).execute("SELECT COUNT(*) FROM entries").fetchone()[0] == 22
    with pytest.raises(sess.OutputError):
        open_session(har, har, overwrite=True)  # never over the input


def test_open_again_with_output_saves_live_session_without_reingest(har, tmp_path, monkeypatch):
    calls = _count_ingests(monkeypatch)
    out = tmp_path / "later.db"
    with open_session(har) as a:
        assert not out.exists()
        with open_session(har, out) as b:  # replaces a separate "persist" step
            assert b.session_id == a.session_id and out.is_file()
        assert a.conn.execute("SELECT 1").fetchone()[0] == 1
    assert calls["n"] == 1


def test_saved_index_must_match_this_build(har, tmp_path):
    out = tmp_path / "idx.db"
    open_session(har, out).close()
    db = sqlite3.connect(out)
    db.execute("UPDATE meta SET value='1' WHERE key='index_version'")
    db.commit()
    db.close()
    with pytest.raises(sess.IndexOutdated) as ei:
        open_session(out)
    assert ei.value.code == "index_outdated"
    assert "output_path" in ei.value.hint and str(har.resolve()) in ei.value.hint
    res = sess.open_har(out)
    assert res["code"] == "index_outdated"


def test_non_index_sqlite_or_garbage_is_not_an_index(tmp_path):
    other = tmp_path / "x.db"
    c = sqlite3.connect(other)
    c.execute("CREATE TABLE t (a)")
    c.commit()
    c.close()
    assert sess._read_index_meta(other) is None
    assert sess._read_index_meta(FIXTURE) is None


def test_index_embeds_validity_meta(har):
    with open_session(har) as s:
        m = {r[0]: r[1] for r in s.conn.execute("SELECT key, value FROM meta")}
    assert m["index_version"] == str(ingest_mod.INDEX_VERSION)
    assert m["har_size"] == str(har.stat().st_size)
    assert m["har_path"] == str(har.resolve())


# ---------------------------------------------------------------- context manager


def test_context_manager_closes_on_exception(har):
    with pytest.raises(ValueError), open_session(har) as s:
        conn = s.conn
        raise ValueError("x")
    assert s.closed and sess._sessions == {}
    with pytest.raises(sqlite3.ProgrammingError):
        conn.execute("SELECT 1")


def test_exception_saves_nothing_extra(har, tmp_path):
    # The index is saved at open (before the body runs); an exception later does not add files.
    with pytest.raises(RuntimeError), open_session(har) as s:
        assert s.saved_to is None
        raise RuntimeError("boom")
    assert _files(tmp_path / "in") == ["a.har"]


def test_close_is_idempotent_and_refcounted(har):
    a = open_session(har)
    b = open_session(har)
    assert a.session_id == b.session_id and a.conn is b.conn
    a.close()
    a.close()  # must not release b's reference
    assert b.conn.execute("SELECT 1").fetchone()[0] == 1
    b.close()
    b.close()
    assert sess._sessions == {}


def test_nested_with_does_not_close_outer(har):
    with open_session(har) as outer:
        with open_session(har) as inner:
            assert inner.conn is outer.conn
        assert outer.conn.execute("SELECT COUNT(*) FROM entries").fetchone()[0] == 22
    assert sess._sessions == {}


def test_exit_stack_and_closing(har):
    with contextlib.ExitStack() as stack:
        a = stack.enter_context(open_session(har))
        b = stack.enter_context(open_session(har))
        assert a.session_id == b.session_id
    assert sess._sessions == {} and a.closed and b.closed
    s = open_session(har)
    with contextlib.closing(s):
        pass
    assert s.closed


def test_read_only_connection_rejects_writes(har, tmp_path):
    for out in (None, tmp_path / "i.db"):
        with open_session(har, out) as s:
            with pytest.raises(sqlite3.OperationalError):
                s.conn.execute("UPDATE entries SET status = 0")
            with pytest.raises(sqlite3.OperationalError):
                s.conn.execute("CREATE TABLE x (a)")
        sess._sessions.clear()


def test_connections_closed_before_replacing_a_file(har, tmp_path):
    """Windows cannot replace a file that a live connection holds: refuse, then succeed."""
    out = tmp_path / "i.db"
    open_session(har, out).close()
    held = open_session(out)  # live read-only handle on the index file
    other = tmp_path / "in" / "b.har"
    shutil.copy(FIXTURE, other)
    with pytest.raises(sess.OutputError):
        open_session(other, out, overwrite=True)
    held.close()
    with open_session(other, out, overwrite=True):
        pass


# ---------------------------------------------------------------- idempotence


def test_same_open_same_id_no_reingest(har, monkeypatch):
    calls = _count_ingests(monkeypatch)
    with open_session(har) as a, open_session(har) as b:
        assert a.session_id == b.session_id
    assert calls["n"] == 1


def test_session_id_is_pure_function_of_input_path(har, tmp_path):
    sid = sess.session_id_for(har)
    assert sid == sess.session_id_for(str(har)) == sess.session_id_for(har.parent / ".." / "in" / "a.har")
    with open_session(har, tmp_path / "x.db") as s:  # output path is not part of the id
        assert s.session_id == sid
    with open_session(har) as s:
        assert s.session_id == sid
    other = tmp_path / "in" / "b.har"
    shutil.copy(FIXTURE, other)
    assert sess.session_id_for(other) != sid


def test_reopen_after_close_gives_identical_summary(har):
    with open_session(har) as s:
        first = s.info
    with open_session(har) as s:
        assert s.info == first


def test_thread_safety_two_threads_one_session(har, monkeypatch):
    calls = _count_ingests(monkeypatch)
    barrier = threading.Barrier(2)
    out: list = []

    def work():
        barrier.wait()
        out.append(open_session(har))

    threads = [threading.Thread(target=work) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(out) == 2 and out[0].session_id == out[1].session_id
    assert out[0].conn is out[1].conn and calls["n"] == 1
    for s in out:
        s.close()
    assert sess._sessions == {}


def test_ingest_is_deterministic(har):
    def dump():
        _stats, conn = ingest_memory(har)
        tables = [
            r[0]
            for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' "
                "ORDER BY name"
            )
        ]
        out = {}
        for t in tables:
            ncols = len(conn.execute(f"PRAGMA table_info({t})").fetchall())
            order = ",".join(str(i) for i in range(1, ncols + 1))
            out[t] = [tuple(r) for r in conn.execute(f"SELECT * FROM {t} ORDER BY {order}")]
        conn.close()
        return out

    first, second = dump(), dump()
    assert first == second
    assert first["entries"] and first["meta"]


# ---------------------------------------------------------------- MCP / dict layer


def test_mcp_open_save_and_unknown_session(har, tmp_path):
    a = json.loads(server.hardly_session_open(str(har)))
    assert a["saved_to"] is None and "storage" not in a and "note" in a
    again = json.loads(server.hardly_session_open(str(har)))
    assert again["session_id"] == a["session_id"]
    out = tmp_path / "idx.db"
    saved = json.loads(server.hardly_write_session_copy(a["session_id"], str(out), format="index"))
    assert saved["format"] == "index" and saved["saved_to"] == str(out.resolve())
    clash = json.loads(server.hardly_write_session_copy(a["session_id"], str(out), format="index"))
    assert clash["code"] == "output_exists"
    assert json.loads(server.hardly_session_overview(a["session_id"]))["index_path"] == str(out.resolve())
    rows = json.loads(server.hardly_session_list())["sessions"]
    assert rows[0]["index_path"] == str(out.resolve())
    assert json.loads(server.hardly_session_close(a["session_id"]))["closed"] is True
    gone = json.loads(server.hardly_session_overview(a["session_id"]))
    assert gone["code"] == "unknown_session"
    assert "hardly_session_open(har_path=" in gone["hint"] and "saved index" in gone["hint"]
    # reopen from the saved index by path
    ix = json.loads(server.hardly_session_open(str(out)))
    assert ix["opened_from"] == "index" and ix["entries"] == 22
    with pytest.raises(UnknownSession):
        sess.require_conn("nope")


def test_export_har(har, tmp_path):
    sid = sess.open_har(har)["session_id"]
    dest = tmp_path / "keep" / "copy.har"
    out = sess.export_har(sid, dest)
    assert out["exported"] and dest.read_bytes() == har.read_bytes()
    assert [p.name for p in dest.parent.iterdir()] == ["copy.har"]
    assert sess.export_har(sid, dest)["code"] == "output_exists"
    assert sess.export_har(sid, har, overwrite=True)["code"] == "output_error"  # never in place
    assert sess.export_har(sid, dest, overwrite=True)["exported"]
    if os.name != "nt":
        assert (dest.stat().st_mode & 0o777) == 0o600
    assert sess.export_har("nope", dest)["code"] == "unknown_session"
    res = json.loads(server.hardly_write_session_copy(sid, str(tmp_path / "k2.har")))
    assert res["exported"] is True


# ---------------------------------------------------------------- ephemeral captures


def _fake_impl(monkeypatch, *, fail=False):
    from hardly import capture

    seen = {}

    def impl(url, har_path, *, _ephemeral=False, **kw):
        target = Path(har_path)
        shutil.copy(FIXTURE, target)
        seen["path"] = target
        out = {"status": "stopped", "har_path": str(target), "har_exists": True}
        if _ephemeral:
            capture.secure_file(target)
            seen["secured"] = target.stat().st_mode & 0o777
            out["session"] = sess.open_har(str(target), force=True, ephemeral=True)
            out["session_id"] = out["session"]["session_id"]
        if fail:
            raise RuntimeError("capture failed")
        return out

    monkeypatch.setattr(capture, "_capture_headless_impl", impl)
    return seen


def test_ephemeral_capture_file_removed_after_success(tmp_path, monkeypatch):
    from hardly import capture
    from hardly.ephemeral import ephemeral_dir

    seen = _fake_impl(monkeypatch)
    out = capture.capture_headless("https://example.com/")
    assert out["har_path"] is None and out["ephemeral"] is True
    assert "-o" in out["keep_hint"] and "output path" in out["keep_hint"]
    assert not seen["path"].exists() and list(ephemeral_dir().iterdir()) == []
    assert out["session"]["har_path"] is None and out["session"]["ephemeral"] is True
    assert q.summary(sess.require_conn(out["session_id"]))["entries"] == 22
    if os.name != "nt":
        assert seen["secured"] == 0o600
        assert (ephemeral_dir().stat().st_mode & 0o777) == 0o700
    assert sess.export_har(out["session_id"], tmp_path / "x.har")["code"] == "har_ephemeral_gone"
    rows = [r for r in sess.list_sessions() if r["session_id"] == out["session_id"]]
    assert rows[0]["ephemeral"] is True and rows[0]["har_path"] is None


def test_ephemeral_capture_file_removed_after_error(monkeypatch):
    from hardly import capture
    from hardly.ephemeral import ephemeral_dir

    seen = _fake_impl(monkeypatch, fail=True)
    with pytest.raises(RuntimeError):
        capture.capture_headless("https://example.com/")
    assert not seen["path"].exists() and list(ephemeral_dir().iterdir()) == []


def test_capture_output_path_is_kept(tmp_path, monkeypatch):
    from hardly import capture

    _fake_impl(monkeypatch)
    target = tmp_path / "keep.har"
    out = capture.capture_headless("https://example.com/", str(target))
    assert target.is_file() and out["har_path"] == str(target) and out["ephemeral"] is False


def test_no_session_without_output_path_warns_that_har_is_discarded(monkeypatch):
    from hardly import capture

    _fake_impl(monkeypatch)
    out = capture.capture_headless("https://example.com/", open_session=False)
    assert out["ephemeral"] is True and out.get("har_path") is None
    assert any("discarded" in w for w in out["warnings"])


def test_startup_sweep_removes_only_old_orphans():
    from hardly.ephemeral import ephemeral_dir, sweep_ephemeral

    d = ephemeral_dir()
    old, fresh = d / "old.har", d / "fresh.har"
    old.write_bytes(b"x")
    fresh.write_bytes(b"x")
    past = old.stat().st_mtime - 7200
    os.utime(old, (past, past))
    assert sweep_ephemeral() == ["old.har"]
    assert not old.exists() and fresh.exists()


def test_discard_never_leaves_the_ephemeral_dir(tmp_path):
    from hardly.ephemeral import discard

    outside = tmp_path / "precious.har"
    outside.write_bytes(b"x")
    assert discard(outside) is False and outside.exists()


# ---------------------------------------------------------------- nothing left behind


def test_default_flows_leave_nothing_behind(tmp_path, monkeypatch):
    import tempfile

    from hardly import capture

    home, tmp = tmp_path / "home", tmp_path / "tmp"
    home.mkdir()
    tmp.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("TMPDIR", str(tmp))
    monkeypatch.setattr(tempfile, "tempdir", str(tmp))
    monkeypatch.delenv("HARDLY_RUNTIME_DIR", raising=False)
    sess.open_har(FIXTURE)
    with open_session(FIXTURE) as s:
        q.summary(s.conn)
    _fake_impl(monkeypatch)
    out = capture.capture_headless("https://example.com/")
    assert out["ephemeral"] is True
    assert _files(home) == [], "default flows must not create files under HOME"
    assert [p for p in tmp.rglob("*") if p.is_file()] == []  # ephemeral HAR already deleted
    assert not (home / ".cache").exists()


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX modes")
def test_runtime_dir_is_private():
    from hardly.ephemeral import runtime_dir

    assert (runtime_dir().stat().st_mode & 0o777) == 0o700
