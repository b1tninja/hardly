"""Integration tests against the sample HAR fixture."""

from __future__ import annotations

from pathlib import Path

import pytest

from hardly import session as sess
from hardly.core.auth import detect_auth
from hardly.core.curl import entry_to_curl
from hardly.core.export_md import export_markdown
from hardly.core.export_openapi import export_openapi
from hardly.core.flows import get_flow
from hardly.core.probe import probe_entry
from hardly.index import query as q

FIXTURE = Path(__file__).parent / "fixtures" / "sample.har"


@pytest.fixture()
def session_id(tmp_path, monkeypatch):
    monkeypatch.setattr(sess, "cache_dir", lambda: tmp_path / "cache")
    result = sess.open_har(FIXTURE, force=True)
    assert "error" not in result
    return result["session_id"]


def test_open_summary(session_id):
    conn = sess.require_conn(session_id)
    summary = q.summary(conn)
    assert summary["entries"] == 22
    assert summary["noise"] >= 3  # js, options, analytics
    assert summary["api"] >= 3


def test_open_har_marks_archive_mode(tmp_path, monkeypatch):
    monkeypatch.setattr(sess, "cache_dir", lambda: tmp_path / "cache")
    result = sess.open_har(FIXTURE, force=True)
    assert result.get("mode") == "archive"
    assert "session_id" in result
    assert "archive" in (result.get("next") or "").lower()


def test_endpoints_template(session_id):
    conn = sess.require_conn(session_id)
    eps = q.list_endpoints(conn, host="api.example.com", exclude_noise=True)
    templates = {e["path_template"] for e in eps["endpoints"]}
    assert "/login" in templates
    assert "/users/{id}/2fa/google/validate" in templates
    assert "/organizations/{id}/transactions" in templates


def test_password_redacted_in_entry(session_id):
    conn = sess.require_conn(session_id)
    # entry 1 is first login
    entry = q.get_entry(conn, 1)
    body = entry["bodies"]["request"]["text"]
    assert "s3cret" not in body
    assert "***REDACTED***" in body
    # Authorization header redacted
    auth_headers = [
        h for h in entry["headers"]["request"] if h["name"].lower() == "authorization"
    ]
    # entry 1 may not have auth; entry 3 does
    entry3 = q.get_entry(conn, 3)
    auth_headers = [
        h for h in entry3["headers"]["request"] if h["name"].lower() == "authorization"
    ]
    assert auth_headers
    assert auth_headers[0]["value"] == "***REDACTED***"


def test_auth_detection(session_id):
    conn = sess.require_conn(session_id)
    auth = detect_auth(conn, host="api.example.com")
    assert auth["auth_path_count"] >= 2
    assert auth["token_response_count"] >= 1


def test_flow_order(session_id):
    conn = sess.require_conn(session_id)
    flow = get_flow(conn, host="api.example.com", exclude_options=True)
    paths = [s["path"] for s in flow["steps"]]
    assert paths[0] == "/login"
    assert "2fa" in paths[1]


def test_search_and_schema(session_id):
    conn = sess.require_conn(session_id)
    found = q.search_entries(conn, host="api.example.com", path_contains="login")
    assert found["total"] >= 2
    schema = q.endpoint_schema(
        conn,
        method="POST",
        host="api.example.com",
        path_template="/login",
    )
    assert schema["request_schema"] is not None
    assert schema["response_schema"] is not None


def test_sql_readonly(session_id):
    conn = sess.require_conn(session_id)
    ok = q.run_sql(conn, "SELECT method, path FROM entries WHERE is_noise = 0")
    assert "rows" in ok
    bad = q.run_sql(conn, "DELETE FROM entries")
    assert "error" in bad


def test_compare_and_curl(session_id):
    conn = sess.require_conn(session_id)
    diff = q.compare_entries(conn, 1, 3)
    assert "request_body_keys" in diff
    curl = entry_to_curl(conn, 1)
    assert "curl" in curl
    assert "s3cret" not in curl["curl"]


def test_probe_requires_confirm(session_id):
    conn = sess.require_conn(session_id)
    result = probe_entry(conn, 1, confirm=False)
    assert "error" in result


def test_export_md_and_openapi(session_id, tmp_path):
    conn = sess.require_conn(session_id)
    md_path = tmp_path / "API.md"
    result = export_markdown(conn, md_path, host="api.example.com")
    assert md_path.exists()
    text = md_path.read_text(encoding="utf-8")
    assert "login" in text
    assert "s3cret" not in text

    oa_path = tmp_path / "openapi.json"
    oa = export_openapi(conn, oa_path, host="api.example.com")
    assert oa_path.exists()
    assert oa["paths"] >= 1


def test_cache_reuse(session_id, tmp_path, monkeypatch):
    monkeypatch.setattr(sess, "cache_dir", lambda: tmp_path / "cache")
    again = sess.open_har(FIXTURE, force=False)
    assert again["cached"] is True
    assert again["session_id"] == session_id


def test_stale_index_version_is_rebuilt(tmp_path, monkeypatch):
    """A cache written by an older ingest (unredacted queries, old shapes) is rebuilt."""
    import json as _json

    monkeypatch.setattr(sess, "cache_dir", lambda: tmp_path / "cache")
    info = sess.open_har(FIXTURE, force=True)
    assert sess.open_har(FIXTURE).get("cached") is True
    meta_path = tmp_path / "cache" / f"{info['session_id']}.json"
    meta = _json.loads(meta_path.read_text())
    assert meta["index_version"] >= 3
    meta["index_version"] = 1
    meta_path.write_text(_json.dumps(meta))
    sess._sessions.pop(info["session_id"], None)
    assert sess.open_har(FIXTURE).get("cached") is False
