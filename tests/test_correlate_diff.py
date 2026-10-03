"""Token correlation, cookies, session diff, recipe plan."""

from pathlib import Path

from hardly import session as sess
from hardly.core.brief import portal_brief
from hardly.core.cookies import cookie_timeline
from hardly.core.correlate import correlate_tokens
from hardly.core.diff import diff_sessions
from hardly.core.recipe_plan import recipe_from_story
from hardly.core.issues import find_issues
from hardly.core.redirects import redirect_chains

FIX = Path(__file__).parent / "fixtures" / "sample.har"


def test_correlate_finds_csrf_and_session(tmp_path, monkeypatch):
    monkeypatch.setenv("HARDLY_CACHE_DIR", str(tmp_path))
    info = sess.open_har(str(FIX), force=True)
    conn = sess.require_conn(info["session_id"])
    result = correlate_tokens(
        conn,
        har_path=sess.get_har_path(info["session_id"]),
        host="portal.example.com",
    )
    assert result["source"] == "har"
    assert result["correlation_count"] >= 2
    hints = {c.get("name_hint") for c in result["correlations"]}
    assert "SESSIONID" in hints or any(
        c.get("to_where") == "cookie" for c in result["correlations"]
    )
    assert any(
        c.get("name_hint")
        in {"__VIEWSTATE", "__RequestVerificationToken"}
        or c.get("to_where") == "request.form"
        for c in result["correlations"]
    )
    # Never leak raw token values
    blob = str(result)
    assert "csrf-token-xyz-7788" not in blob
    assert "abc123sessionvalue99" not in blob
    assert "longtoken" not in blob


def test_cookie_timeline_names(tmp_path, monkeypatch):
    monkeypatch.setenv("HARDLY_CACHE_DIR", str(tmp_path))
    info = sess.open_har(str(FIX), force=True)
    conn = sess.require_conn(info["session_id"])
    result = cookie_timeline(
        conn,
        har_path=sess.get_har_path(info["session_id"]),
        host="portal.example.com",
    )
    assert "SESSIONID" in result["names_set"]
    assert "SESSIONID" in result["names_sent"]


def test_diff_sessions_self(tmp_path, monkeypatch):
    monkeypatch.setenv("HARDLY_CACHE_DIR", str(tmp_path))
    info = sess.open_har(str(FIX), force=True)
    conn = sess.require_conn(info["session_id"])
    result = diff_sessions(conn, conn, host="portal.example.com")
    assert result["shared_count"] >= 1
    assert result["only_in_a"] == []
    assert result["only_in_b"] == []


def test_recipe_plan_writes_json(tmp_path, monkeypatch):
    monkeypatch.setenv("HARDLY_CACHE_DIR", str(tmp_path))
    info = sess.open_har(str(FIX), force=True)
    conn = sess.require_conn(info["session_id"])
    out = tmp_path / "recipe.json"
    result = recipe_from_story(
        conn, host="portal.example.com", output_path=out
    )
    assert result.get("output_path")
    assert out.is_file()
    assert result["step_count"] >= 1


def test_redirect_chains(tmp_path, monkeypatch):
    monkeypatch.setenv("HARDLY_CACHE_DIR", str(tmp_path))
    info = sess.open_har(str(FIX), force=True)
    conn = sess.require_conn(info["session_id"])
    result = redirect_chains(conn, host="portal.example.com")
    assert result["chain_count"] >= 1
    chain = result["chains"][0]
    assert chain["status"] == 302
    assert chain["target"]["path"] == "/new-landing"
    assert chain["target"]["follow_entry_id"] is not None


def test_issues_runs(tmp_path, monkeypatch):
    monkeypatch.setenv("HARDLY_CACHE_DIR", str(tmp_path))
    info = sess.open_har(str(FIX), force=True)
    conn = sess.require_conn(info["session_id"])
    result = find_issues(conn)
    assert "issue_count" in result
    assert "by_kind" in result


def test_portal_brief(tmp_path, monkeypatch):
    monkeypatch.setenv("HARDLY_CACHE_DIR", str(tmp_path))
    info = sess.open_har(str(FIX), force=True)
    conn = sess.require_conn(info["session_id"])
    result = portal_brief(
        conn,
        har_path=sess.get_har_path(info["session_id"]),
        host="portal.example.com",
    )
    assert result["host"] == "portal.example.com"
    assert result["step_count"] >= 1
    assert "correlations" in result
    assert "js_routes" in result
    assert "coverage" in result


def test_portal_brief_auto_host(tmp_path, monkeypatch):
    monkeypatch.setenv("HARDLY_CACHE_DIR", str(tmp_path))
    info = sess.open_har(str(FIX), force=True)
    conn = sess.require_conn(info["session_id"])
    result = portal_brief(conn, har_path=sess.get_har_path(info["session_id"]))
    assert result["host"] == "portal.example.com"
    assert result["step_count"] >= 1
    assert result.get("apex") == "example.com"
    assert isinstance(result.get("related_hosts"), list)


def _entry(i, url, *, req_headers=None, body="", status=200):
    return {
        "startedDateTime": f"2026-01-01T00:00:0{i}.000Z",
        "time": 10,
        "request": {
            "method": "GET", "url": url, "httpVersion": "HTTP/1.1",
            "headers": [{"name": k, "value": v} for k, v in (req_headers or {}).items()],
            "queryString": [], "cookies": [], "headersSize": -1, "bodySize": 0,
        },
        "response": {
            "status": status, "statusText": "OK", "httpVersion": "HTTP/1.1",
            "headers": [{"name": "Content-Type", "value": "application/json"}],
            "cookies": [], "redirectURL": "", "headersSize": -1, "bodySize": len(body),
            "content": {"size": len(body), "mimeType": "application/json", "text": body},
        },
    }


def test_correlate_server_issued_key_replayed_in_custom_headers(tmp_path, monkeypatch):
    import json

    key, pw = "Zk9vQmFyQmF6S2V5MTIzNDU2Nzg5MA==", "p4ssW0rdValue99xyz"
    har = {"log": {"version": "1.2", "creator": {"name": "t", "version": "1"}, "entries": [
        _entry(1, "https://api.example.com/handshake",
               body=json.dumps({"EncryptedKey": key, "Password": pw})),
        _entry(2, "https://api.example.com/search",
               req_headers={"X-Key": key, "X-Pass": pw, "Accept": "application/json"},
               body=json.dumps({"rows": []})),
    ]}}
    path = tmp_path / "hs.har"
    path.write_text(json.dumps(har))
    monkeypatch.setenv("HARDLY_CACHE_DIR", str(tmp_path / "cache"))
    info = sess.open_har(str(path), force=True)
    conn = sess.require_conn(info["session_id"])
    out = correlate_tokens(conn, har_path=sess.get_har_path(info["session_id"]))
    hits = {(c["to_where"], c["name_hint"]) for c in out["correlations"]}
    assert ("header", "x-key") in hits and ("header", "x-pass") in hits
    blob = str(out)
    assert key not in blob and pw not in blob
