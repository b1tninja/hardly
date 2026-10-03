"""replay_check: required vs optional pieces of a replay (MockTransport, no network)."""

import json
from urllib.parse import parse_qsl

import httpx

from hardly import session as sess
from hardly.core.replay_check import replay_check

HOST = "app.example.com"
SECRET_COOKIE = "sidSECRETVALUE123"
SECRET_TOKEN = "tokSECRETVALUE456"
SECRET_AUTH = "authSECRETVALUE789"


def _entry(method, path, query=None, headers=None, post=None, mime="application/json", resp_text="{}"):
    url = f"https://{HOST}{path}"
    if query:
        url += "?" + "&".join(f"{k}={v}" for k, v in query)
    req = {
        "method": method,
        "url": url,
        "httpVersion": "HTTP/1.1",
        "headers": [{"name": k, "value": v} for k, v in (headers or {}).items()],
        "queryString": [{"name": k, "value": v} for k, v in (query or [])],
        "cookies": [],
        "headersSize": -1,
        "bodySize": 0,
    }
    if post:
        req["postData"] = post
    return {
        "startedDateTime": "2024-01-01T00:00:00.000Z",
        "time": 5,
        "request": req,
        "response": {
            "status": 200,
            "statusText": "OK",
            "httpVersion": "HTTP/1.1",
            "headers": [],
            "cookies": [],
            "redirectURL": "",
            "headersSize": -1,
            "bodySize": 0,
            "content": {"mimeType": mime, "text": resp_text, "size": len(resp_text)},
        },
    }


def _open(tmp_path, monkeypatch, entries):
    monkeypatch.setenv("HARDLY_RUNTIME_DIR", str(tmp_path / "cache"))
    har = tmp_path / "t.har"
    har.write_text(json.dumps({"log": {"version": "1.2", "creator": {"name": "t", "version": "1"}, "entries": entries}}))
    info = sess.open_har(str(har), force=True)
    return sess.require_conn(info["session_id"])


class Server:
    def __init__(self, rate_limit_after=None):
        self.seen: list[httpx.Request] = []
        self.rate_limit_after = rate_limit_after

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.seen.append(request)
        if self.rate_limit_after is not None and len(self.seen) > self.rate_limit_after:
            return httpx.Response(429, headers={"Retry-After": "30"}, text="slow down")
        path = request.url.path
        if path == "/prior":
            return httpx.Response(200, headers={"Set-Cookie": "flow=1; Path=/"}, text="<html>ok</html>")
        if path == "/data":
            q = dict(request.url.params)
            ok = (
                request.headers.get("x-requested-with") == "XMLHttpRequest"
                and "flow=1" in request.headers.get("cookie", "")
                and "page" in q
            )
            if ok:
                return httpx.Response(200, json={"items": [], "total": 0})
            return httpx.Response(500, headers={"content-type": "text/html"}, text="<html><body>boom</body></html>")
        if path == "/submit":
            fields = dict(parse_qsl(request.content.decode()))
            if fields.get("csrf_token") == SECRET_TOKEN:
                return httpx.Response(200, json={"saved": True})
            return httpx.Response(400, json={"error": "bad"})
        return httpx.Response(404, text="nope")


def _client(server):
    return httpx.Client(transport=httpx.MockTransport(server), follow_redirects=False)


GET_HEADERS = {
    "X-Requested-With": "XMLHttpRequest",
    "Accept": "application/json",
    "X-Trace": "t1",
    "Authorization": f"Bearer {SECRET_AUTH}",
}


def _flow_entries():
    return [
        _entry("GET", "/prior", mime="text/html", resp_text="<html>x</html>"),
        _entry("GET", "/data", query=[("page", "1"), ("junk", "z")], headers=GET_HEADERS),
    ]


def test_required_vs_optional(tmp_path, monkeypatch):
    conn = _open(tmp_path, monkeypatch, _flow_entries())
    srv = Server()
    res = replay_check(conn, [0, 1], delay_s=0, client=_client(srv), max_requests=40)
    assert res["baseline"]["status"] == 200
    assert res["baseline"]["signature"]["kind"] == "json"
    assert res["baseline"]["signature"]["keys"] == ["items", "total"]
    assert "X-Requested-With" in res["required"]["headers"]
    assert "page" in res["required"]["query"]
    assert "flow" in res["required"]["cookies"]
    assert 0 in res["required"]["prior_steps"]
    assert "junk" in res["optional"]["query"]
    assert "Accept" in res["optional"]["headers"]
    assert "X-Trace" in res["optional"]["headers"]
    assert "Authorization" in res["needs_override"]["headers"]
    assert any("X-Requested-With" in f and "200 JSON -> 500 HTML" in f for f in res["findings"])
    assert all("authorization" not in r.headers for r in srv.seen)
    assert not res["halted"]


def test_overrides_applied_not_leaked(tmp_path, monkeypatch):
    conn = _open(tmp_path, monkeypatch, _flow_entries())
    srv = Server()
    res = replay_check(
        conn,
        [0, 1],
        overrides={"headers": {"Authorization": f"Bearer {SECRET_AUTH}"}, "cookies": {"sess": SECRET_COOKIE}},
        delay_s=0,
        client=_client(srv),
        max_requests=40,
    )
    assert any(r.headers.get("authorization") == f"Bearer {SECRET_AUTH}" for r in srv.seen)
    assert "Authorization" in res["optional"]["headers"]
    assert "sess" in res["optional"]["cookies"]
    assert "Authorization" not in res["needs_override"].get("headers", [])
    blob = json.dumps(res)
    for secret in (SECRET_AUTH, SECRET_COOKIE):
        assert secret not in blob


def test_budget_not_tested(tmp_path, monkeypatch):
    conn = _open(tmp_path, monkeypatch, _flow_entries())
    srv = Server()
    res = replay_check(conn, [0, 1], delay_s=0, client=_client(srv), max_requests=4)
    assert res["requests_used"] <= 4 and len(srv.seen) <= 4
    assert sum(len(v) for v in res["not_tested"].values()) > 0
    tested_h = res["required"]["headers"] + res["optional"]["headers"]
    assert "X-Requested-With" in tested_h
    assert any("not tested" in f for f in res["findings"])


def test_budget_too_small_for_baseline(tmp_path, monkeypatch):
    conn = _open(tmp_path, monkeypatch, _flow_entries())
    res = replay_check(conn, [0, 1], delay_s=0, client=_client(Server()), max_requests=1)
    assert "error" in res


def test_unsafe_method_refused(tmp_path, monkeypatch):
    post = {"mimeType": "application/x-www-form-urlencoded", "text": "csrf_token=abc&name=bob"}
    conn = _open(tmp_path, monkeypatch, [_entry("POST", "/submit", post=post, headers={"Content-Type": post["mimeType"]})])
    srv = Server()
    res = replay_check(conn, 0, delay_s=0, client=_client(srv))
    assert "error" in res and res["refused"][0]["method"] == "POST"
    assert srv.seen == []


def test_unsafe_allowed_with_hidden_token_and_captcha_skip(tmp_path, monkeypatch):
    post = {
        "mimeType": "application/x-www-form-urlencoded",
        "text": "csrf_token=abc&name=bob&g-recaptcha-response=CAPTCHAVALUE&extra=1",
    }
    conn = _open(tmp_path, monkeypatch, [_entry("POST", "/submit", post=post, headers={"Content-Type": post["mimeType"]})])
    srv = Server()
    res = replay_check(
        conn, 0, overrides={"body": {"csrf_token": SECRET_TOKEN}}, allow_unsafe=True, delay_s=0, client=_client(srv)
    )
    assert res["baseline"]["status"] == 200
    assert "csrf_token" in res["required"]["fields"]
    assert "name" in res["optional"]["fields"] and "extra" in res["optional"]["fields"]
    assert res["skipped_captcha"] == ["g-recaptcha-response"]
    assert "g-recaptcha-response" not in sum(res["required"].values(), [])
    assert "g-recaptcha-response" not in sum(res["optional"].values(), [])
    for r in srv.seen:
        assert b"recaptcha" not in r.content.lower()
        assert b"CAPTCHAVALUE" not in r.content
    assert SECRET_TOKEN not in json.dumps(res)


def test_hidden_token_missing_reports_needs_override(tmp_path, monkeypatch):
    post = {"mimeType": "application/x-www-form-urlencoded", "text": "csrf_token=abc&name=bob"}
    conn = _open(tmp_path, monkeypatch, [_entry("POST", "/submit", post=post)])
    res = replay_check(conn, 0, allow_unsafe=True, delay_s=0, client=_client(Server()))
    assert "csrf_token" in res["needs_override"]["body"]
    assert res["halted"]["reason"] == "baseline_not_ok"


def test_429_halts(tmp_path, monkeypatch):
    conn = _open(tmp_path, monkeypatch, _flow_entries())
    srv = Server(rate_limit_after=2)
    res = replay_check(conn, [0, 1], delay_s=0, client=_client(srv), max_requests=40)
    assert res["halted"]["reason"] == "http_429"
    assert len(srv.seen) == 3
    assert sum(len(v) for v in res["not_tested"].values()) > 0


def test_baseline_429_halts(tmp_path, monkeypatch):
    conn = _open(tmp_path, monkeypatch, _flow_entries())
    res = replay_check(conn, [0, 1], delay_s=0, client=_client(Server(rate_limit_after=0)))
    assert res["halted"]["reason"] == "http_429"
    assert res["baseline"] is None


def test_redirect_chain_reported(tmp_path, monkeypatch):
    conn = _open(tmp_path, monkeypatch, [_entry("GET", "/old")])

    def handler(request):
        if request.url.path == "/old":
            return httpx.Response(302, headers={"Location": "/data?page=1"})
        return httpx.Response(200, json={"a": 1})

    res = replay_check(conn, 0, delay_s=0, client=httpx.Client(transport=httpx.MockTransport(handler)))
    assert res["baseline"]["redirect_chain"] == [302, 200]


def test_unknown_entry_and_no_bodies(tmp_path, monkeypatch):
    conn = _open(tmp_path, monkeypatch, _flow_entries())
    assert "error" in replay_check(conn, 99, delay_s=0, client=_client(Server()))
    res = replay_check(conn, [0, 1], delay_s=0, client=_client(Server()), max_requests=40)
    assert "boom" not in json.dumps(res)
