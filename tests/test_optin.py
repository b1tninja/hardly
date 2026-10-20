"""confirm and overwrite are gates only when the value is the boolean True."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from hardly import server
from hardly import session as sess
from hardly.core.arcgis import explore
from hardly.core.catalog import Catalog, CatalogRunner, DefaultAdapter, Endpoint, Target
from hardly.core.flow_replay import replay_flow
from hardly.core.har_tools import _check_paths
from hardly.core.optin import is_explicit_true
from hardly.core.probe import probe_entry
from hardly.index import query as q

FIXTURE = Path(__file__).parent / "fixtures" / "sample.har"


def test_only_real_true():
    assert is_explicit_true(True) is True
    for value in (False, None, 0, 1, "true", "false", "0", "yes", "no", "", " "):
        assert is_explicit_true(value) is False


def test_send_string_does_not_call(monkeypatch):
    def _boom(*_a, **_k):
        raise AssertionError("sent")

    monkeypatch.setattr("hardly.core.redirect_diag.diagnose_redirects", _boom)
    for value in ("false", "0", "no", 1, "yes"):
        out = json.loads(server.hardly_send_redirect_walk("https://example.com", confirm=value))
        assert out["sent"] is False
        assert out["confirmed"] is False


def test_send_real_true_calls(monkeypatch):
    monkeypatch.setattr(
        "hardly.core.redirect_diag.diagnose_redirects",
        lambda url, **_kw: {"outcome": "planned", "url": url},
    )
    out = json.loads(server.hardly_send_redirect_walk("https://example.com", confirm=True))
    assert out["outcome"] == "planned"


def test_overwrite_string_leaves_the_file(tmp_path):
    target = tmp_path / "keep.txt"
    target.write_text("keep", encoding="utf-8")
    with pytest.raises(sess.OutputExists):
        server._out(str(target), "false")
    assert target.read_text(encoding="utf-8") == "keep"
    with pytest.raises(FileExistsError):
        _check_paths([], target, "yes")
    assert target.read_text(encoding="utf-8") == "keep"


def test_open_har_string_overwrite(tmp_path, monkeypatch):
    monkeypatch.setenv("HARDLY_RUNTIME_DIR", str(tmp_path / "rt"))
    dest = tmp_path / "idx.sqlite"
    first = sess.open_har(FIXTURE, output_path=dest)
    assert "session_id" in first
    again = sess.open_har(FIXTURE, output_path=dest, overwrite="false")
    assert again["code"] == "output_exists"
    assert dest.is_file()


def test_inner_gates_ignore_truthy_strings(tmp_path, monkeypatch):
    monkeypatch.setenv("HARDLY_RUNTIME_DIR", str(tmp_path / "rt"))
    sid = sess.open_har(FIXTURE, force=True)["session_id"]
    conn = sess.require_conn(sid)

    def _sent(*_a, **_k):
        raise AssertionError("sent")

    monkeypatch.setattr("hardly.core.probe.new_client", _sent)
    denied = probe_entry(conn, 1, confirm="yes")
    assert "confirm=true" in denied["error"]

    assert "confirm=true" in explore("https://example.com/arcgis/rest/services/X/MapServer", confirm="1")["error"]

    ep = Endpoint(role="page", url="https://example.com/x")
    assert "confirm" in (DefaultAdapter().verify(ep, confirm="false").error or "")
    runner = CatalogRunner(Catalog(name="t", targets=[Target(id="t", endpoints=[ep])]), confirm="yes")
    planned = runner.run()
    assert "planned" in planned and "confirm" in planned["error"]

    monkeypatch.setattr("hardly.core.flow_replay.check_url", lambda *_a, **_k: [])
    monkeypatch.setattr("hardly.core.flow_replay.new_client", _sent)
    dry = replay_flow(conn, entry_ids=[0], confirm="false")
    assert dry.get("sent") is False


def test_probe_real_true_reaches_the_client(tmp_path, monkeypatch):
    monkeypatch.setenv("HARDLY_RUNTIME_DIR", str(tmp_path / "rt"))
    sid = sess.open_har(FIXTURE, force=True)["session_id"]
    conn = sess.require_conn(sid)
    monkeypatch.setattr("hardly.core.probe.check_url", lambda *_a, **_k: [])

    class _Boom(Exception):
        pass

    def _client(**_k):
        raise _Boom("sent")

    monkeypatch.setattr("hardly.core.probe.new_client", _client)
    with pytest.raises(_Boom):
        probe_entry(conn, 1, confirm=True)
    # entry id is whatever the fixture's first row is; the confirm gate is what this asserts
    assert q.summary(conn)["entries"] > 0
