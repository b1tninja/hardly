"""Run-time behaviour of generated stubs and their embedded helpers (loopback only)."""

from __future__ import annotations

import importlib.util
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest
from test_stub_compile import _delta, _entry, _har

from hardly import session as sess
from hardly.core.ajax_delta import delta_hidden, parse_delta, summarize_delta
from hardly.core.grids import count_rows, iter_pages, paging_params
from hardly.core.pagination import detect_pagination, find_next, iter_follow
from hardly.core.retry import backoff_delay, retry_after_seconds
from hardly.core.stub import client_stub

ORIG = "https://runtime.test"
VS1 = "VS-1-aGVsbG8tdmlld3N0YXRlLWJsb2I9PQ=="
VS2 = "VS-2-aGVsbG8tdmlld3N0YXRlLWJsb2IyPQ=="


# --- unit: delta / retry / pagination shapes ---------------------------------
def test_parse_delta_and_summary():
    text = _delta(("updatePanel", "up1", "<b>a|b</b>"), ("hiddenField", "__VIEWSTATE", VS2),
                  ("pageTitle", "", "T"))
    segs = parse_delta(text)
    assert [s[0] for s in segs] == ["updatePanel", "hiddenField", "pageTitle"]
    assert segs[0][2] == "<b>a|b</b>"  # pipes inside content survive (length-prefixed)
    assert delta_hidden(text) == {"__VIEWSTATE": VS2}
    s = summarize_delta(text)
    assert s["hidden_fields"] == ["__VIEWSTATE"] and VS2 not in json.dumps(s)
    for bad in ("", "<html>", "5|x|y|abc|", "abc|t|i|c|", '{"a": 1}', "1|t|i"):
        assert parse_delta(bad) == []
    assert summarize_delta("<html>") is None


def test_retry_helpers():
    assert retry_after_seconds("7") == 7.0
    assert retry_after_seconds(" ") is None and retry_after_seconds("soon") is None
    assert retry_after_seconds("Thu, 01 Jan 1970 00:01:40 GMT", now=40.0) == 60.0
    assert retry_after_seconds("Thu, 01 Jan 1970 00:00:10 GMT", now=40.0) == 0.0
    assert [backoff_delay(i, base=1.0) for i in range(4)] == [1, 2, 4, 8]
    assert backoff_delay(0, 30) == 30 and backoff_delay(0, 999, cap=60) == 60
    assert backoff_delay(10, cap=5) == 5


def test_find_next_shapes():
    link = {"Link": '<https://x.test/a?page=2>; rel="next", <https://x.test/a?page=9>; rel="last"'}
    assert find_next(link, "")["value"] == "https://x.test/a?page=2"
    assert find_next({"link": '<u>; rel="prev"'}, "") is None
    assert find_next({}, '{"next": "https://x.test/p2", "results": []}')["kind"] == "next-link"
    assert find_next({}, '{"next": null, "results": []}') is None
    assert find_next({}, '{"@odata.nextLink": "/odata/x?$skip=5"}')["kind"] == "next-link"
    cur = find_next({}, '{"meta": {"next_cursor": "c1"}}')
    assert (cur["kind"], cur["param"], cur["name"]) == ("cursor", "cursor", "meta.next_cursor")
    relay = '{"data": {"pageInfo": {"hasNextPage": true, "endCursor": "e1"}}}'
    assert find_next({}, relay)["param"] == "after"
    assert find_next({}, relay.replace("true", "false")) is None
    assert find_next({}, '{"nextPageToken": ""}') is None
    assert find_next({}, "not json") is None


def test_iter_follow_stops():
    pages = {None: ({}, '{"next": "/p2"}'), "/p2": ({}, '{"next": "/p3"}'),
             "/p3": ({}, '{"next": "/p2"}')}  # loop guard
    got = list(iter_follow(lambda ref: pages[ref["value"] if ref else None]))
    assert len(got) == 3


def test_paging_params_and_iter_pages():
    assert paging_params({"page": "3", "pageSize": "20"})["size"] == 20
    assert paging_params({"start": "0", "length": "10"})["offset_param"] == "start"
    assert paging_params({"$skip": "0"})["style"] == "odata"
    assert paging_params({"__EVENTARGUMENT": "Page$4"})["first"] == 4
    assert paging_params({"q": "x"}) is None

    data = [list(range(i, i + 2)) for i in (0, 2, 4)] + [[6]]
    calls = []

    def fetch(p):
        calls.append(dict(p))
        i = int(p["page"]) - 1
        return json.dumps({"rows": data[i]}) if i < len(data) else json.dumps({"rows": []})

    assert len(list(iter_pages(fetch, page_param="page", size_param="n", size=2))) == 4
    assert calls[0] == {"n": "2", "page": "1"}  # stops on the short page, no extra call
    assert len(calls) == 4

    offsets = []

    def fetch_off(p):
        offsets.append(p["start"])
        s = int(p["start"])
        return json.dumps({"data": list(range(s, min(s + 3, 7)))}) if s < 7 else "[]"

    assert len(list(iter_pages(fetch_off, offset_param="start", size_param="length", size=3))) == 3
    assert offsets == ["0", "3", "6"]
    assert count_rows("<table><tr><th>h</th></tr></table>") == 0
    assert count_rows("1|updatePanel|x|a|") is None

    # postback-style argument: stops on the first empty page
    seen = []

    def fetch_pb(p):
        seen.append(p)
        return "<tr><tr>" + str(len(seen)) if len(seen) < 3 else ""

    list(iter_pages(fetch_pb, page_param="__EVENTARGUMENT", value_fmt="Page${n}", first=2))
    assert [s["__EVENTARGUMENT"] for s in seen] == ["Page$2", "Page$3", "Page$4"]


def test_detect_pagination_conn(tmp_path):
    entries = [
        _entry(1, "GET", "https://p.test/a", resp_body='{"items": [1], "next": "/a?page=2"}',
               resp_ct="application/json"),
        _entry(2, "GET", "https://p.test/b", resp_body="[1]", resp_ct="application/json",
               resp_headers=[("Link", '<https://p.test/b?page=2>; rel="next"')]),
    ]
    har = tmp_path / "p.har"
    har.write_text(json.dumps(_har(entries)), encoding="utf-8")
    conn = sess.require_conn(sess.open_har(str(har), force=True)["session_id"])
    rep = detect_pagination(conn)
    kinds = {s["kind"] for s in rep["pagination"]}
    assert kinds == {"next-link", "link-header"}
    assert "page=2" not in json.dumps(rep)


# --- loopback: generated stub retries, pages, follows, carries delta state ----
class _H(BaseHTTPRequestHandler):
    hits = {"rate": 0}
    seen_vs: list[str] = []

    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json", extra=()):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in extra:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):  # noqa: N802
        u = urlsplit(self.path)
        q = parse_qs(u.query)
        if u.path == "/limited":
            _H.hits["rate"] += 1
            if _H.hits["rate"] < 3:
                return self._send(429, "{}", extra=[("Retry-After", "0")])
            return self._send(200, '{"ok": true}')
        if u.path == "/rows":
            page = int(q.get("page", ["1"])[0])
            rows = [page * 10 + i for i in range(2)] if page <= 3 else []
            return self._send(200, json.dumps({"rows": rows}))
        if u.path == "/feed":
            n = int(q.get("cursor", ["0"])[0])
            nxt = {"next_cursor": str(n + 1)} if n < 2 else {"next_cursor": None}
            return self._send(200, json.dumps({"items": [n], **nxt}))
        if u.path == "/form":
            return self._send(200, f'<input type="hidden" name="__VIEWSTATE" value="{VS1}">',
                              "text/html")
        self._send(404, "{}")

    def do_POST(self):  # noqa: N802
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode()
        form = parse_qs(body)
        _H.seen_vs.append(form.get("__VIEWSTATE", [""])[0])
        want = VS1 if len(_H.seen_vs) == 1 else VS2
        if _H.seen_vs[-1] != want:
            return self._send(400, "{}")
        self._send(200, _delta(("updatePanel", "up", "<i>x</i>"),
                               ("hiddenField", "__VIEWSTATE", VS2)), "text/plain")


@pytest.fixture()
def loopback():
    srv = HTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    _H.hits["rate"] = 0
    _H.seen_vs.clear()
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


def test_generated_stub_runtime(tmp_path, monkeypatch, loopback):
    monkeypatch.setenv("HARDLY_STUB_BACKOFF", "0")
    monkeypatch.setenv("HARDLY_STUB_RETRIES", "3")
    o = ORIG
    post = "application/x-www-form-urlencoded"
    entries = [
        _entry(1, "GET", f"{o}/limited", resp_body='{"ok": true}'),
        _entry(2, "GET", f"{o}/rows?page=1&pageSize=2", resp_body='{"rows": [1, 2]}'),
        _entry(3, "GET", f"{o}/feed", resp_body='{"items": [0], "next_cursor": "1"}',
               resp_ct="application/json"),
        _entry(4, "GET", f"{o}/form",
               resp_body=f'<input type="hidden" name="__VIEWSTATE" value="{VS1}">'),
        _entry(5, "POST", f"{o}/form", req_ct=post, resp_ct="text/plain",
               req_body=f"__VIEWSTATE={VS1}&__EVENTARGUMENT=Page%242&__ASYNCPOST=true",
               resp_body=_delta(("hiddenField", "__VIEWSTATE", VS2))),
        _entry(6, "POST", f"{o}/form", req_ct=post, resp_ct="text/plain",
               req_body=f"__VIEWSTATE={VS2}&__EVENTARGUMENT=Page%243&__ASYNCPOST=true",
               resp_body=_delta(("hiddenField", "__VIEWSTATE", VS2))),
    ]
    har = tmp_path / "r.har"
    har.write_text(json.dumps(_har(entries)), encoding="utf-8")
    conn = sess.require_conn(sess.open_har(str(har), force=True)["session_id"])
    out = tmp_path / "rt.py"
    client_stub(conn, entry_ids=list(range(6)), output_path=out, class_name="RT")
    src = out.read_text(encoding="utf-8")
    assert VS1 not in src and VS2 not in src
    out.write_text(src.replace(ORIG, loopback), encoding="utf-8")
    spec = importlib.util.spec_from_file_location("gen_rt", out)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    c = mod.RT()

    c.run()  # retries the two 429s (Retry-After: 0), then walks the form flow
    assert _H.hits["rate"] == 3
    assert _H.seen_vs == [VS1, VS2]  # step 6 used the VIEWSTATE from the delta

    pages = list(c.pages(1))
    assert len(pages) == 3 and json.loads(pages[0])["rows"] == [10, 11]
    assert len(list(c.follow(2))) == 3
