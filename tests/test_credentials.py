"""Credential / login / shape map (names and shapes only)."""

from pathlib import Path

from hardly import session as sess
from hardly.core.credentials import map_credentials
from hardly.core.redact import classify_value_shape

FIX = Path(__file__).parent / "fixtures" / "sample.har"


def test_html_autocomplete_fields():
    from hardly.core.secrets import html_autocomplete_fields

    html = (
        '<input name="usr" autocomplete="username" />'
        '<input id="pw" name="pwd" type="password" autocomplete="current-password" />'
    )
    fields = html_autocomplete_fields(html)
    kinds = {(n, k, ac) for n, k, ac in fields}
    assert ("usr", "html_identity", "username") in kinds
    assert ("pwd", "html_password", "current-password") in kinds


def test_classify_value_shapes():
    assert classify_value_shape(
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    ) == "jwt"
    assert (
        classify_value_shape(
            "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        )
        == "bearer_jwt"
    )
    assert classify_value_shape("Bearer secret-token") == "bearer_token"
    assert classify_value_shape("abcdef0123456789abcdef0123456789") == "hex"
    assert classify_value_shape("***REDACTED***") is None
    assert classify_value_shape("hello") is None


def test_map_credentials_sample(tmp_path, monkeypatch):
    monkeypatch.setenv("HARDLY_CACHE_DIR", str(tmp_path))
    info = sess.open_har(str(FIX), force=True)
    conn = sess.require_conn(info["session_id"])
    result = map_credentials(
        conn,
        har_path=sess.get_har_path(info["session_id"]),
        host="api.example.com",
    )
    assert result["password_field_count"] >= 1
    names = {f["name"].lower() for f in result["password_fields"]}
    assert "password" in names
    id_names = {f["name"].lower() for f in result["identity_fields"]}
    assert "email" in id_names
    assert any(f.get("paired_with_password") for f in result["identity_fields"])
    assert result["login_flow"]["step_count"] >= 1
    roles = {s["role"] for s in result["login_flow"]["steps"]}
    assert "login_submit" in roles or "credential_submit" in roles
    assert "token_issue" in roles or result["token_responses"]
    shapes = {s["shape"] for s in result["shapes"]}
    assert "jwt" in shapes or "bearer_jwt" in shapes or "bearer_token" in shapes
    blob = str(result)
    assert "s3cret" not in blob
    assert "secret-token" not in blob
    assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in blob


def test_map_credentials_portal_session(tmp_path, monkeypatch):
    monkeypatch.setenv("HARDLY_CACHE_DIR", str(tmp_path))
    info = sess.open_har(str(FIX), force=True)
    conn = sess.require_conn(info["session_id"])
    result = map_credentials(
        conn,
        har_path=sess.get_har_path(info["session_id"]),
        host="portal.example.com",
    )
    assert "SESSIONID" in result["session_cookies"] or any(
        "session" in n.lower() for n in result["session_cookies"]
    )
    assert result["cookie_flags_by"].get("httponly") or any(
        f.get("httponly") for f in result.get("cookie_flags") or []
    )
    assert any(
        "password" in f["name"].lower() or f.get("kind") == "html_password"
        for f in result["password_fields"]
    ) or result["csrf_names"]


def test_brief_includes_credentials(tmp_path, monkeypatch):
    monkeypatch.setenv("HARDLY_CACHE_DIR", str(tmp_path))
    from hardly.core.brief import portal_brief

    info = sess.open_har(str(FIX), force=True)
    conn = sess.require_conn(info["session_id"])
    brief = portal_brief(
        conn,
        har_path=sess.get_har_path(info["session_id"]),
        host="api.example.com",
    )
    assert "credentials" in brief
    assert brief["credentials"]["password_field_count"] >= 1
    assert "hardly_credentials" in (brief.get("next") or "")


def test_ingest_stores_value_shapes(tmp_path, monkeypatch):
    monkeypatch.setenv("HARDLY_CACHE_DIR", str(tmp_path))
    info = sess.open_har(str(FIX), force=True)
    conn = sess.require_conn(info["session_id"])
    n = conn.execute("SELECT COUNT(*) AS n FROM value_shapes").fetchone()["n"]
    assert n >= 1
    result = map_credentials(
        conn,
        har_path=sess.get_har_path(info["session_id"]),
        host="api.example.com",
    )
    assert any(s.get("source") == "index" for s in result["shapes"])


def test_diff_includes_credentials(tmp_path, monkeypatch):
    monkeypatch.setenv("HARDLY_CACHE_DIR", str(tmp_path))
    from hardly.core.diff import diff_sessions

    info = sess.open_har(str(FIX), force=True)
    conn = sess.require_conn(info["session_id"])
    out = diff_sessions(conn, conn, host="api.example.com", credentials=True)
    assert "credentials" in out
    assert out["credentials"]["changed"] is False
    assert "shared" in out["credentials"]["session_cookies"]


def test_entry_includes_shapes(tmp_path, monkeypatch):
    monkeypatch.setenv("HARDLY_CACHE_DIR", str(tmp_path))
    from hardly.index import query as q

    info = sess.open_har(str(FIX), force=True)
    conn = sess.require_conn(info["session_id"])
    # Login response carries a JWT in the body.
    entry = q.get_entry(conn, 2)
    assert "shapes" in entry
    assert isinstance(entry["shapes"], list)
    # Password must not appear in query dump.
    blob = str(entry)
    assert "s3cret" not in blob
