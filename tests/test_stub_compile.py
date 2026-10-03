"""Generated stubs must always be valid Python, whatever the capture holds.

All HARs are synthetic and built in-memory (nothing committed); the stubs are
only compiled, never executed, so no network is involved.
"""

from __future__ import annotations

import ast
import json

import pytest

from hardly import session as sess
from hardly.core.stub import client_stub

SECRET = "s3cr3t-Value-0123456789abcdef"


def _entry(i, method, url, *, req_ct=None, req_body=None, resp_body="", resp_ct="text/html",
           req_headers=(), resp_headers=()):
    req = {
        "method": method, "url": url, "httpVersion": "HTTP/1.1",
        "headers": [{"name": k, "value": v} for k, v in req_headers], "cookies": [],
        "headersSize": -1, "bodySize": 0, "queryString": [],
    }
    if req_body is not None:
        req["postData"] = {"mimeType": req_ct, "text": req_body}
    return {
        "startedDateTime": f"2026-01-01T00:00:{i:02d}.000Z", "time": 5, "request": req,
        "response": {
            "status": 200, "statusText": "OK", "httpVersion": "HTTP/1.1",
            "headers": [{"name": "Content-Type", "value": resp_ct},
                        *[{"name": k, "value": v} for k, v in resp_headers]],
            "cookies": [], "redirectURL": "", "headersSize": -1,
            "bodySize": len(resp_body),
            "content": {"size": len(resp_body), "mimeType": resp_ct, "text": resp_body},
        },
    }


def _delta(*segs):
    return "".join(f"{len(c)}|{t}|{i}|{c}|" for t, i, c in segs)


def _form_html(vs):
    return (f'<form><input type="hidden" name="__VIEWSTATE" value="{vs}">'
            f'<input type="hidden" name="__EVENTVALIDATION" value="{vs}ev">'
            '<input type="hidden" name="__EVENTARGUMENT" value="">'
            "<table><tr><td>h</td></tr><tr><td>1</td></tr></table></form>")


def _har(entries):
    return {"log": {"version": "1.2", "creator": {"name": "t", "version": "1"},
                    "entries": entries}}


H = "https://app.example.test"
CASES = {
    "form_post": [
        _entry(1, "GET", f"{H}/login", resp_body=_form_html("VS-1-aGVsbG8tdmlld3N0YXRlLWJsb2I9PQ==")),
        _entry(2, "POST", f"{H}/login", req_ct="application/x-www-form-urlencoded",
               req_body=f"__VIEWSTATE=VS-1-aGVsbG8tdmlld3N0YXRlLWJsb2I9PQ==&__EVENTVALIDATION=VSEV-1-aGVsbG8tZXZlbnQtdmFsaWRhdGlvbg==&user=bob&password={SECRET}"),
    ],
    "json": [
        _entry(1, "POST", f"{H}/api/items", req_ct="application/json",
               req_body=json.dumps({"q": "x", "token": SECRET, "tags": ["a", "b"], "n": 1}),
               resp_body='{"ok": true}', resp_ct="application/json"),
    ],
    "graphql": [
        _entry(1, "POST", f"{H}/graphql", req_ct="application/json",
               req_body=json.dumps({"query": "query Q($id: ID!) { item(id: $id) { id name } }",
                                    "variables": {"id": "7"}, "operationName": "Q"}),
               resp_body='{"data": {"item": {"id": "7"}}}', resp_ct="application/json"),
    ],
    "multipart": [
        _entry(1, "POST", f"{H}/upload",
               req_ct="multipart/form-data; boundary=----X",
               req_body=('------X\r\nContent-Disposition: form-data; name="f"; '
                         'filename="a.txt"\r\n\r\nhello\r\n------X--\r\n')),
    ],
    "ajax_delta": [
        _entry(1, "GET", f"{H}/grid", resp_body=_form_html("VS-1-aGVsbG8tdmlld3N0YXRlLWJsb2I9PQ==")),
        _entry(2, "POST", f"{H}/grid", req_ct="application/x-www-form-urlencoded",
               req_body="ScriptManager1=up%7Cgrid&__EVENTTARGET=grid&__EVENTARGUMENT=Page%242"
                        "&__VIEWSTATE=VS-1-aGVsbG8tdmlld3N0YXRlLWJsb2I9PQ==&__EVENTVALIDATION=VSEV-1-aGVsbG8tZXZlbnQtdmFsaWRhdGlvbg==&__ASYNCPOST=true",
               resp_ct="text/plain",
               resp_body=_delta(("updatePanel", "up", "<table><tr><td>x</td></tr></table>"),
                                ("hiddenField", "__VIEWSTATE", "VS-2-aGVsbG8tdmlld3N0YXRlLWJsb2IyPQ=="),
                                ("hiddenField", "__EVENTVALIDATION", "VSEV-2-aGVsbG8tZXZlbnQtdmFsaWRhdGlvbg=="))),
        _entry(3, "POST", f"{H}/grid", req_ct="application/x-www-form-urlencoded",
               req_body="ScriptManager1=up%7Cgrid&__EVENTTARGET=grid&__EVENTARGUMENT=Page%243"
                        "&__VIEWSTATE=VS-2-aGVsbG8tdmlld3N0YXRlLWJsb2IyPQ==&__EVENTVALIDATION=VSEV-2-aGVsbG8tZXZlbnQtdmFsaWRhdGlvbg==&__ASYNCPOST=true",
               resp_ct="text/plain",
               resp_body=_delta(("updatePanel", "up", "<b>y</b>"),
                                ("hiddenField", "__VIEWSTATE", "VS-3-aGVsbG8tdmlld3N0YXRlLWJsb2IzPQ=="))),
    ],
    "paging_query": [
        _entry(1, "GET", f"{H}/api/rows?page=2&pageSize=25&sort=name",
               resp_body='{"data": [1, 2], "next": "/api/rows?page=3"}',
               resp_ct="application/json"),
        _entry(2, "GET", f"{H}/api/rows?start=0&length=10&draw=1",
               resp_body='{"data": [[1]], "recordsTotal": 3}', resp_ct="application/json"),
    ],
    "cursor_and_link": [
        _entry(1, "GET", f"{H}/v1/events",
               resp_body='{"items": [1], "nextPageToken": "abc"}',
               resp_ct="application/json"),
        _entry(2, "GET", f"{H}/v1/list?limit=5",
               resp_body="[1,2]", resp_ct="application/json",
               resp_headers=[("Link", '<https://app.example.test/v1/list?page=2>; rel="next"')]),
    ],
    "auth_and_weird_names": [
        _entry(1, "GET", f"{H}/a b/ü?x=1&x=2&é=%22q%22&empty=", resp_body="{}",
               resp_ct="application/json",
               req_headers=[("Authorization", f"Bearer {SECRET}"), ("X-Api-Key", SECRET)]),
    ],
}


@pytest.mark.parametrize("case", sorted(CASES))
def test_stub_compiles(tmp_path, case):
    har = tmp_path / f"{case}.har"
    har.write_text(json.dumps(_har(CASES[case])), encoding="utf-8")
    info = sess.open_har(str(har), force=True)
    conn = sess.require_conn(info["session_id"])
    out = client_stub(conn, entry_ids=list(range(len(CASES[case]))))
    code = out["code"]
    assert code, out
    ast.parse(code)
    compile(code, f"<stub:{case}>", "exec")
    assert SECRET not in code
    assert "hunter2" not in code


def test_ajax_delta_stub_carries_viewstate_names_only(tmp_path):
    har = tmp_path / "d.har"
    har.write_text(json.dumps(_har(CASES["ajax_delta"])), encoding="utf-8")
    info = sess.open_har(str(har), force=True)
    conn = sess.require_conn(info["session_id"])
    code = client_stub(conn, entry_ids=[0, 1, 2])["code"]
    # entry 3 takes its VIEWSTATE from the delta response of entry 2 at run time
    assert "_hidden(self.resp[1], '__VIEWSTATE')" in code
    assert "VS-2-aGVsbG8tdmlld3N0YXRlLWJsb2IyPQ==" not in code and "VS-3-aGVsbG8tdmlld3N0YXRlLWJsb2IzPQ==" not in code


def test_paging_and_follow_emitted(tmp_path):
    har = tmp_path / "p.har"
    har.write_text(json.dumps(_har(CASES["paging_query"] + CASES["cursor_and_link"])),
                   encoding="utf-8")
    info = sess.open_har(str(har), force=True)
    conn = sess.require_conn(info["session_id"])
    code = client_stub(conn, entry_ids=[0, 1, 2, 3])["code"]
    assert "self.pagers[0]" in code and "'page_param': 'page'" in code
    assert "self.pagers[1]" in code and "'offset_param': 'start'" in code
    assert "self.followers[2]" in code and "self.followers[3]" in code
    assert "HARDLY_STUB_RETRIES" in code and "Retry-After" in code
    compile(code, "<stub>", "exec")
