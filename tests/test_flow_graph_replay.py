"""flow_graph / replay_flow against the loopback synthetic site only."""

import json
import urllib.error
import urllib.request

import pytest

from hardly import local_site
from hardly import session as sess
from hardly.core.flow_graph import flow_graph
from hardly.core.flow_replay import replay_flow

SECRET = "pw-SECRET-value-123"


def _get(base, path, headers=None):
    req = urllib.request.Request(base + path, headers=headers or {})
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, dict(r.headers), r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode()


def _entry(base, method, path, req_headers, status, hdrs, body, query=None):
    url = base + path + (("?" + query) if query else "")
    return {
        "startedDateTime": "2024-01-01T00:00:00.000Z",
        "time": 1,
        "request": {
            "method": method, "url": url, "httpVersion": "HTTP/1.1",
            "headers": [{"name": k, "value": v} for k, v in req_headers.items()],
            "queryString": [], "cookies": [], "headersSize": -1, "bodySize": 0,
        },
        "response": {
            "status": status, "statusText": "", "httpVersion": "HTTP/1.1",
            "headers": [{"name": k, "value": v} for k, v in hdrs.items()],
            "cookies": [], "redirectURL": "", "headersSize": -1, "bodySize": 0,
            "content": {"mimeType": hdrs.get("Content-Type", "text/html"), "text": body, "size": len(body)},
        },
    }


@pytest.fixture()
def flow(tmp_path, monkeypatch):
    monkeypatch.setenv("HARDLY_CACHE_DIR", str(tmp_path / "cache"))
    with local_site.serve() as base:
        s, h, login_body = _get(base, "/login")
        cookie = h["Set-Cookie"]
        sid = cookie.split(";")[0].split("=", 1)[1]
        token = login_body.split('name="token" value="')[1].split('"')[0]
        s2, h2, items = _get(base, "/api/items")
        entries = [
            _entry(base, "GET", "/login", {}, s, h, login_body),
            _entry(base, "GET", "/api/items",
                   {"Cookie": f"JSESSIONID={sid}", "X-Page-Token": token, "Authorization": f"Bearer {SECRET}"},
                   s2, h2, items, query=f"t={token}&q=widgets"),
            _entry(base, "GET", "/private", {"Authorization": f"Bearer {SECRET}"}, 200,
                   {"Content-Type": "text/html; charset=utf-8"}, "ok"),
            _entry(base, "GET", "/limited", {}, 429, {"Retry-After": "30", "Content-Type": "text/html"}, "x"),
        ]
        har = tmp_path / "t.har"
        har.write_text(json.dumps({"log": {"version": "1.2", "creator": {"name": "t", "version": "1"}, "entries": entries}}))
        info = sess.open_har(str(har), force=True)
        yield sess.require_conn(info["session_id"]), token, sid


def test_graph_names_only(flow):
    conn, token, sid = flow
    g = flow_graph(conn, 1)
    assert [s["entry_id"] for s in g["steps"]] == [0, 1]
    assert g["steps"][1]["role"] == "target"
    wired = {(e["to_where"], e["to_name"]): e for e in g["edges"]}
    assert wired[("query", "t")]["from_where"] == "html.hidden"
    assert wired[("header", "X-Page-Token")]["from_entry_id"] == 0
    assert wired[("cookie", "JSESSIONID")]["via"] == "cookie_jar"
    assert [u["kind"] for u in g["user_inputs"]] == ["token"]
    blob = json.dumps(g)
    assert token not in blob and sid not in blob and SECRET not in blob


def test_graph_unknown_and_depth(flow):
    conn, *_ = flow
    assert "error" in flow_graph(conn, 99)
    g = flow_graph(conn, 1, max_depth=0)
    assert g["truncated"] and len(g["steps"]) == 1


def test_replay_dry_run_and_missing(flow):
    conn, *_ = flow
    dry = replay_flow(conn, target=1)
    assert dry["sent"] is False and dry["missing_inputs"][0]["env_var"] == "HARDLY_INPUT_AUTHORIZATION"
    res = replay_flow(conn, target=1, confirm=True, delay_s=0, allow_gates=["login"])
    assert res["error"] == "missing inputs" and res["requests_used"] == 0


def test_replay_live_matches(flow):
    conn, token, sid = flow
    base = conn.execute("SELECT host FROM entries WHERE entry_id=0").fetchone()["host"]
    res = replay_flow(conn, target=1, env={"Authorization": SECRET}, confirm=True, delay_s=0, hosts=[base], allow_gates=["login"])
    assert res["all_match"], (res["results"], res["halted"], res["first_divergence"])
    assert res["requests_used"] == 2 and res["first_divergence"] is None
    assert SECRET not in json.dumps(res) and token not in json.dumps(res)


def test_replay_env_var(flow, monkeypatch):
    conn, *_ = flow
    monkeypatch.setenv("HARDLY_INPUT_AUTHORIZATION", SECRET)
    res = replay_flow(conn, entry_ids=[0, 1], confirm=True, delay_s=0, allow_gates=["login"])
    assert res["all_match"]


def _writable_copy(conn):
    """Session connections are read-only; tamper with a private in-memory copy instead."""
    import sqlite3

    copy = sqlite3.connect(":memory:")
    copy.row_factory = sqlite3.Row
    conn.backup(copy)
    return copy


def test_replay_divergence(flow):
    conn, *_ = flow
    conn = _writable_copy(conn)
    conn.execute("UPDATE entries SET status = 201 WHERE entry_id = 0")
    res = replay_flow(conn, target=1, env={"Authorization": SECRET}, confirm=True, delay_s=0, allow_gates=["login"])
    assert res["first_divergence"]["entry_id"] == 0
    assert "status" in res["first_divergence"]["fields"]
    assert res["requests_used"] == 1


def test_replay_stops_on_429(flow):
    conn, *_ = flow
    res = replay_flow(conn, entry_ids=[3, 2], env={"Authorization": SECRET}, confirm=True, delay_s=0, allow_gates=["login"])
    assert res["halted"]["reason"] in ("http_429", "retry_after")
    assert res["requests_used"] == 1


def test_unsafe_refused_and_budget(flow):
    conn, *_ = flow
    conn = _writable_copy(conn)
    conn.execute("UPDATE entries SET method = 'POST' WHERE entry_id = 0")
    r = replay_flow(conn, target=1, env={"Authorization": SECRET}, confirm=True)
    assert "allow_unsafe" in r["error"]
    r = replay_flow(conn, target=1, env={"Authorization": SECRET}, confirm=True, allow_unsafe=True, max_requests=1)
    assert "max_requests" in r["error"]
