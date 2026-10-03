"""End-to-end: generated stubs carry server-issued tokens forward.

A loopback http.server enforces WebForms hidden fields, an antiforgery
field+cookie pair, an XSRF cookie echoed into a header, and a double-encoded
JSON handshake key sent back in a header. The generated client must pass all
of it with no secret value written into its source.
"""

from __future__ import annotations

import importlib.util
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, quote, unquote

import pytest

from hardly import session as sess
from hardly.core.stub import client_stub

ORIG = "https://portal.test"
VIEWSTATE = "dGhpcy1pcy1hLXZpZXdzdGF0ZS1ibG9iLXNlY3JldA=="
EVENTVAL = "ZXZlbnQtdmFsaWRhdGlvbi1zZWNyZXQtdmFsdWU9PQ=="
VSGEN = "CA0B0334Z9"
AF_FIELD = "af-field-token-SECRET-7788"
AF_COOKIE = "af-cookie-token-SECRET-9911"
XSRF = "xsrf/secret+value==9922"
SESSION_KEY = "sesskey-SECRET-5566-abcdef"
PASSWORD = "hunter2-very-secret"
SECRETS = [VIEWSTATE, EVENTVAL, AF_FIELD, AF_COOKIE, XSRF, quote(XSRF, safe=""),
           SESSION_KEY, PASSWORD]


class _H(BaseHTTPRequestHandler):
    def log_message(self, *a):  # silence
        pass

    def _send(self, code, body, ctype="text/html", cookies=()):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for c in cookies:
            self.send_header("Set-Cookie", c)
        self.end_headers()
        self.wfile.write(data)

    def _cookies(self):
        out = {}
        for part in (self.headers.get("Cookie") or "").split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                out[k] = v
        return out

    def do_GET(self):  # noqa: N802
        if self.path == "/webforms":
            self._send(200, (
                '<form method="post"><input type="hidden" name="__VIEWSTATE" '
                f'id="__VIEWSTATE" value="{VIEWSTATE}">'
                f'<input TYPE="hidden" name="__EVENTVALIDATION" value="{EVENTVAL}">'
                f'<input type="hidden" name="__VIEWSTATEGENERATOR" value="{VSGEN}">'
                '<input type="text" name="txtSearch"></form>'))
        elif self.path == "/form":
            self._send(200, (
                '<form method="post"><input type="hidden" '
                f'name="__RequestVerificationToken" value="{AF_FIELD}">'
                '<input name="comment"></form>'),
                cookies=[f"af={AF_COOKIE}; Path=/; HttpOnly"])
        elif self.path == "/app":
            self._send(200, "<html>app</html>",
                       cookies=[f"XSRF-TOKEN={quote(XSRF, safe='')}; Path=/"])
        elif self.path == "/handshake":
            inner = json.dumps({"result": {"key": SESSION_KEY, "ttl": 60}})
            self._send(200, json.dumps(inner), "application/json")
        elif self.path == "/api/data":
            if self.headers.get("X-Session-Key") != SESSION_KEY:
                return self._send(403, "{}", "application/json")
            self._send(200, '{"ok": true}', "application/json")
        else:
            self._send(404, "nope")

    def do_POST(self):  # noqa: N802
        raw = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode()
        if self.path == "/webforms":
            f = parse_qs(raw, keep_blank_values=True)
            ok = (f.get("__VIEWSTATE") == [VIEWSTATE]
                  and f.get("__EVENTVALIDATION") == [EVENTVAL]
                  and f.get("__VIEWSTATEGENERATOR") == [VSGEN]
                  and f.get("txtSearch") == ["widgets"]
                  and f.get("txtPassword") == ["pw-from-caller"])
            self._send(200 if ok else 500, "<html>results</html>")
        elif self.path == "/form":
            f = parse_qs(raw)
            ok = (f.get("__RequestVerificationToken") == [AF_FIELD]
                  and self._cookies().get("af") == AF_COOKIE)
            self._send(200 if ok else 500, "<html>saved</html>")
        elif self.path == "/api/json":
            hdr = self.headers.get("X-XSRF-TOKEN")
            ok = hdr == XSRF and self._cookies().get("XSRF-TOKEN") == quote(XSRF, safe="")
            self._send(200 if ok else 403, '{"ok": true}', "application/json")
        else:
            self._send(404, "nope")


@pytest.fixture()
def server():
    srv = HTTPServer(("127.0.0.1", 0), _H)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def _hdrs(d):
    return [{"name": k, "value": v} for k, v in d.items()]


def _entry(method, path, status=200, *, req_headers=None, body=None, ctype="text/html",
           resp_text="", set_cookie=(), req_ct=None):
    req = {"method": method, "url": ORIG + path, "httpVersion": "HTTP/1.1",
           "headers": _hdrs(req_headers or {}), "queryString": [], "cookies": [],
           "headersSize": -1, "bodySize": -1}
    if body is not None:
        req["postData"] = {"mimeType": req_ct or "application/x-www-form-urlencoded",
                           "text": body}
    resp_headers = _hdrs({"Content-Type": ctype}) + [
        {"name": "Set-Cookie", "value": c} for c in set_cookie]
    return {
        "startedDateTime": "2024-01-01T00:00:00.000Z", "time": 5,
        "request": req,
        "response": {"status": status, "statusText": "OK", "httpVersion": "HTTP/1.1",
                     "headers": resp_headers, "cookies": [],
                     "content": {"size": len(resp_text), "mimeType": ctype,
                                 "text": resp_text},
                     "redirectURL": "", "headersSize": -1, "bodySize": -1},
        "cache": {}, "timings": {"send": 0, "wait": 5, "receive": 0},
    }


def _build_har(path):
    wf_html = (f'<form><input type="hidden" name="__VIEWSTATE" value="{VIEWSTATE}">'
               f'<input type="hidden" name="__EVENTVALIDATION" value="{EVENTVAL}">'
               f'<input type="hidden" name="__VIEWSTATEGENERATOR" value="{VSGEN}"></form>')
    af_html = ('<form><input type="hidden" name="__RequestVerificationToken" '
               f'value="{AF_FIELD}"></form>')
    inner = json.dumps({"result": {"key": SESSION_KEY, "ttl": 60}})
    wf_body = ("__EVENTTARGET=&__EVENTARGUMENT=&"
               f"__VIEWSTATE={quote(VIEWSTATE, safe='')}&"
               f"__EVENTVALIDATION={quote(EVENTVAL, safe='')}&"
               f"__VIEWSTATEGENERATOR={VSGEN}&txtSearch=widgets&txtPassword={PASSWORD}")
    entries = [
        _entry("GET", "/webforms", resp_text=wf_html),
        _entry("POST", "/webforms", body=wf_body, resp_text="<html>ok</html>"),
        _entry("GET", "/form", resp_text=af_html, set_cookie=[f"af={AF_COOKIE}; Path=/"]),
        _entry("POST", "/form", req_headers={"Cookie": f"af={AF_COOKIE}"},
               body=f"__RequestVerificationToken={AF_FIELD}&comment=hello-world-1",
               resp_text="<html>saved</html>"),
        _entry("GET", "/app", resp_text="<html>app</html>",
               set_cookie=[f"XSRF-TOKEN={quote(XSRF, safe='')}; Path=/"]),
        _entry("POST", "/api/json",
               req_headers={"X-XSRF-TOKEN": XSRF,
                            "Cookie": f"XSRF-TOKEN={quote(XSRF, safe='')}"},
               body='{"q": "search-term-value"}', req_ct="application/json",
               ctype="application/json", resp_text='{"ok": true}'),
        _entry("GET", "/handshake", ctype="application/json", resp_text=json.dumps(inner)),
        _entry("GET", "/api/data", req_headers={"X-Session-Key": SESSION_KEY},
               ctype="application/json", resp_text='{"ok": true}'),
    ]
    har = {"log": {"version": "1.2", "creator": {"name": "t", "version": "1"},
                   "entries": entries}}
    path.write_text(json.dumps(har), encoding="utf-8")
    return list(range(len(entries)))


def test_generated_client_carries_tokens_forward(tmp_path, monkeypatch, server):
    monkeypatch.setenv("HARDLY_CACHE_DIR", str(tmp_path / "cache"))
    har = tmp_path / "flow.har"
    ids = _build_har(har)
    info = sess.open_har(str(har), force=True)
    conn = sess.require_conn(info["session_id"])
    out = tmp_path / "client.py"
    result = client_stub(conn, entry_ids=ids, output_path=out, class_name="Flow")
    assert result.get("output_path")
    src = out.read_text(encoding="utf-8")

    # No secret values in generated source (raw or URL-encoded).
    for secret in SECRETS:
        assert secret not in src, secret
    # Extraction code, not placeholders, for issued tokens.
    assert "_hidden_fields(self.resp[0])" in src
    assert "_hidden_fields(self.resp[2])" in src
    assert "_cookie(self._jar, 'XSRF-TOKEN')" in src
    assert "_json_path(self.resp[6]" in src
    assert "self._jar" in src
    # User input stays a keyword default.
    assert "PLACEHOLDER_TXTPASSWORD" in src
    compile(src, "client.py", "exec")

    # Point at the loopback server and actually run it.
    src = src.replace(ORIG, server)
    out.write_text(src, encoding="utf-8")
    spec = importlib.util.spec_from_file_location("gen_flow", out)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    client = mod.Flow()
    # Without the caller's input the server (correctly) rejects the placeholder.
    with pytest.raises(Exception):
        mod.Flow().run()
    client.run(txtpassword="pw-from-caller")
    assert len(client.resp) == len(ids)


def test_helpers_unit():
    from hardly.core import stub

    ns: dict = {}
    from http.cookiejar import CookieJar

    exec(  # noqa: S102
        "import json\nfrom html.parser import HTMLParser\n"
        "from http.cookiejar import CookieJar\nfrom urllib.parse import unquote\n"
        + stub._HELPERS, ns)
    assert ns["_hidden_fields"]('<INPUT type="Hidden" name="a" value="x&amp;y">') == {"a": "x&y"}
    dbl = json.dumps(json.dumps({"a": {"b": [{"c": "v"}]}}))
    assert ns["_json_path"](dbl, "a.b.0.c") == "v"
    assert ns["_json_path"](dbl, "c") == "v"  # deep fallback
    with pytest.raises(AssertionError):
        ns["_cookie"](CookieJar(), "x")
