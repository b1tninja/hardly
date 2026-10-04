"""Robustness limits: pathological bodies must not stall, crash or exhaust memory.

* every body-text detector and every redaction function runs on regex bait within a wall-clock budget;
* JSON nesting and decompression are capped;
* a HAR with 100k tiny entries plus one 50 MB body ingests in bounded time and memory (subprocess).
"""

from __future__ import annotations

import base64
import inspect
import json
import os
import subprocess
import sys
import textwrap
import time
import zlib

import pytest

from hardly import server
from hardly import session as sess
from hardly.core import redact as R
from hardly.core.safe_json import MAX_DEPTH, safe_loads

#: Budget for one detector on one hostile input (generous: CI machines are slow, bait is quadratic).
BUDGET_S = 2.0
N = 200_000  # characters per bait; the stored HTML preview cap is 64k, raw scans are clipped at 1 MB


def _rep(unit: str, chars: int = N) -> str:
    return unit * max(1, chars // len(unit))


BAITS: dict[str, str] = {
    "unclosed_input": _rep("<input value='"),
    "unclosed_tag": _rep("<a href="),
    "class_quote": _rep('class="'),
    "deep_div": _rep("<div>"),
    "forms_unclosed": _rep("<form><input name=a>"),
    "form_actions": _rep("<form action=x><input name=a>"),
    "table_unclosed": _rep("<table><tr><td>x</td>"),
    "table_rows": "<table>" + _rep("<tr><td>1</td><td>x</td></tr>") + "</table>",
    "long_word": "a" * N,
    "dots": "dataTables" + _rep(".a"),
    "quotes": "'" * N,
    "dquotes": '"' * N,
    "slashes": "/" * N,
    "backslashes": "\\" * N,
    "assign": _rep("a.b="),
    "equals": _rep("a="),
    "amp_pairs": _rep("&a=b"),
    "query_hash": _rep("?a=b#c=d"),
    "eyj": "eyJ" + "a" * N,
    "hex": _rep("0123456789abcdef"),
    "newlines": _rep("a=b\n"),
    "spaces": " " * N,
    "escaped_kv": _rep('\\"k\\":'),
    "attr_repeat": "<input " + _rep('type="hidden" '),
    "script_unclosed": _rep("<script>"),
    "style_unclosed": _rep("<style>"),
    "title_unclosed": _rep("<title>"),
    "comment_open": _rep("<!--"),
    "lt": "<" * N,
    "gt": ">" * N,
    "angle_pairs": _rep("<>"),
    "href_many": _rep("<a href='/x?a=1'>x</a>"),
    "js_fetch": _rep('fetch("/api/v1/x");'),
    "js_concat": _rep('"/a/"+b+"/c"+'),
    "js_template": _rep("`/a/${b}`"),
    "js_headers": "headers: {" * (N // 10),
    "do_postback": _rep("__doPostBack('a$GridView','Page$2');"),
    "bearer": _rep("Bearer " + "a" * 20 + " "),
    "nested_arrays": "[" * 20_000,
    "nested_objects": '{"a":' * 20_000,
}


def _hidden_fields(text):
    from hardly.core.correlate import _hidden_fields as f

    return f(text)


def _detectors():
    from hardly.core import gates, secrets
    from hardly.core.data_attrs import extract_data_attributes
    from hardly.core.grids import html_grid_signals
    from hardly.core.html_forms import extract_html_structure
    from hardly.core.js_routes import extract_js_routes
    from hardly.core.outline import outline_markup
    from hardly.core.search_nav import page_candidates
    from hardly.core.stack import fingerprint_response
    from hardly.core.tables import extract_tables

    return {
        "html_forms": lambda t: extract_html_structure(t, base_url="https://a.example.com/"),
        "js_routes": lambda t: extract_js_routes(t, base_url="https://a.example.com/"),
        "grids": html_grid_signals,
        "tables": extract_tables,
        "stack": lambda t: fingerprint_response(200, {"Content-Type": "text/html"}, t, "https://a.example.com/"),
        "data_attrs": lambda t: extract_data_attributes(t, base_url="https://a.example.com/"),
        "outline": lambda t: outline_markup(t, mime="text/html"),
        "gates": lambda t: gates.classify_response(200, {"Content-Type": "text/html"}, t, "https://a.example.com/"),
        "autocomplete": secrets.html_autocomplete_fields,
        "hidden_fields": _hidden_fields,
        "search_nav": lambda t: page_candidates(t, base_url="https://a.example.com/", keywords=("a",), limit=10),
        "redact_string": R.redact_string,
        "redact_url": R.redact_url,
        "redact_urls_in_text": R.redact_urls_in_text,
        "redact_markup_text": R.redact_markup_text,
        "redact_form": R.redact_form,
        "redact_body_text": lambda t: R.redact_body_text(t, max_chars=8000),
        "redact_body_text_markup": lambda t: R.redact_body_text(t, max_chars=len(t) + 1, markup=True),
        "classify_value_shape": R.classify_value_shape,
        "scrub_text": _scrub_text,
        "body_query_snippet": _redact_snippet,
    }


def _scrub_text(t):
    from hardly.core.har_tools import _scrub_text

    return _scrub_text(t, "text/html")


def _redact_snippet(t):
    from hardly.core.body_query import redact_snippet

    return redact_snippet(t)


DETECTORS = _detectors()


@pytest.mark.parametrize("bait", sorted(BAITS))
def test_detectors_and_redaction_finish_within_budget(bait):
    text = BAITS[bait]
    slow = {}
    for name, fn in DETECTORS.items():
        t0 = time.perf_counter()
        try:
            fn(text)
        except RecursionError:  # tools turn this into a coded error; it must not be a hang
            pass
        dt = time.perf_counter() - t0
        if dt > BUDGET_S:
            slow[name] = round(dt, 1)
    assert not slow, f"{bait}: over {BUDGET_S}s: {slow}"


# ------------------------------------------------------------------ nesting, decompression


def test_safe_loads_caps_nesting_and_keeps_normal_documents():
    assert safe_loads('{"a": [1, {"b": 2}]}') == {"a": [1, {"b": 2}]}
    deep_ok = "[" * (MAX_DEPTH - 1) + "]" * (MAX_DEPTH - 1)
    assert safe_loads(deep_ok)
    for text in ("[" * (MAX_DEPTH + 5) + "]" * (MAX_DEPTH + 5), "[" * 100_000 + "]" * 100_000, '{"a":' * 5000 + "1" + "}" * 5000):
        with pytest.raises(ValueError):
            safe_loads(text)


def test_redaction_survives_deep_json():
    for text in ("[" * 100_000 + "]" * 100_000, '{"a":' * 50_000 + '"password"' + "}" * 50_000):
        out = R.redact_body_text(text, max_chars=500)
        assert out["json"] is False and out["size"] == len(text)
        R.redact_json(safe_loads('{"a":[[[[1]]]]}'))


def test_saml_deflate_bomb_is_capped():
    from hardly.core import auth_patterns as A

    bomb = zlib.compress(b"<samlp:AuthnRequest " + b"A" * 300_000_000, 9)[2:-4]  # raw deflate, ~300 MB inflated
    assert len(bomb) < 1_000_000
    t0 = time.perf_counter()
    info = A._saml_shape(base64.b64encode(bomb).decode())
    assert time.perf_counter() - t0 < BUDGET_S * 3
    assert info["encoding"] in ("base64+deflate", "unknown")
    assert A.MAX_INFLATE <= 4_000_000


def test_grpc_web_text_decode_is_capped():
    from hardly.core import encodings as E

    big = base64.b64encode(b"x" * 1_000_000).decode()
    out = E.decode_grpc_text((big + "\n") * 20)  # 20 MB decoded would exceed the cap
    assert out is None or len(out) <= E.MAX_DECODED_BYTES


# ------------------------------------------------------------------ tools on hostile bodies


def _hostile_har(tmp_path):
    def entry(i, body, mime, post=None):
        req = {"method": "POST" if post else "GET", "url": f"https://app.example.com/p{i}?a=1", "httpVersion": "HTTP/1.1",
               "headers": [], "queryString": [{"name": "a", "value": "1"}], "cookies": [], "headersSize": -1, "bodySize": 0}
        if post:
            req["postData"] = post
        return {
            "startedDateTime": "2024-01-01T00:00:00.000Z", "time": 5, "request": req,
            "response": {"status": 200, "statusText": "OK", "httpVersion": "HTTP/1.1",
                         "headers": [{"name": "Content-Type", "value": mime}], "cookies": [],
                         "content": {"size": len(body), "mimeType": mime, "text": body}, "redirectURL": "",
                         "headersSize": -1, "bodySize": len(body)},
            "cache": {}, "timings": {"send": 0, "wait": 1, "receive": 1},
        }

    bodies = [
        ("[" * 50_000 + "]" * 50_000, "application/json"),
        ('{"a":' * 30_000 + "1" + "}" * 30_000, "application/json"),
        (BAITS["unclosed_input"], "text/html"),
        (BAITS["forms_unclosed"], "text/html"),
        (BAITS["table_unclosed"], "text/html"),
        (BAITS["js_fetch"], "application/javascript"),
        (BAITS["equals"], "text/plain"),
        (BAITS["amp_pairs"], "application/x-www-form-urlencoded"),
        (json.dumps({"k": "x" * N}), "application/json"),
    ]
    entries = [
        entry(i, b, m, post={"mimeType": m, "text": b[:50_000]} if i % 2 == 0 else None) for i, (b, m) in enumerate(bodies)
    ]
    p = tmp_path / "hostile.har"
    p.write_text(json.dumps({"log": {"version": "1.2", "creator": {"name": "x", "version": "1"}, "entries": entries}}))
    return p, len(entries)


def test_every_read_tool_survives_hostile_bodies_within_budget(tmp_path):
    p, n = _hostile_har(tmp_path)
    sid = sess.open_har(str(p), force=True)["session_id"]
    skip = {"hardly_browser_start", "hardly_session_open", "hardly_session_close", "hardly_send_catalog_verify",
            "hardly_catalog_list", "hardly_write_catalog_record", "hardly_spec_contract_check",
            "hardly_write_screenshot", "hardly_browser_interact", "hardly_browser_run_steps"}
    slow, crashed = [], []
    for name in sorted(dir(server)):
        fn = getattr(server, name)
        if not name.startswith("hardly_") or not callable(fn) or name in skip or name.startswith("hardly_write_"):
            continue
        params = inspect.signature(fn).parameters
        for eid in range(n) if ("entry_id" in params or "entry_ids" in params) else [0]:
            kw = {}
            for pn, prm in params.items():
                if pn in ("session_id", "other_session_id"):
                    kw[pn] = sid
                elif pn == "entry_id":
                    kw[pn] = eid
                elif pn == "other_entry_id":
                    kw[pn] = (eid + 1) % n
                elif pn == "entry_ids":
                    kw[pn] = [eid]
                elif pn == "har_path":
                    kw[pn] = str(p)
                elif pn == "sql":
                    kw[pn] = "select * from bodies"
                elif pn == "method":
                    kw[pn] = "POST"
                elif pn == "path_template":
                    kw[pn] = "/p0"
                elif pn == "url":
                    kw[pn] = "https://app.example.com/"
                elif prm.default is inspect._empty:
                    kw[pn] = None
            extra = [{}]
            if name == "hardly_entry_body_query":
                extra = [{}, {"regex": "a+"}, {"regex": r"(a+)+$"}, {"jsonpath": "$..*"}, {"side": "request"}]
            for ex in extra:
                t0 = time.perf_counter()
                try:
                    fn(**kw, **ex)
                except Exception as exc:  # noqa: BLE001
                    crashed.append((name, eid, type(exc).__name__, str(exc)[:80]))
                dt = time.perf_counter() - t0
                if dt > 4 * BUDGET_S:
                    slow.append((name, eid, round(dt, 1)))
    assert not crashed, crashed[:10]
    assert not slow, slow[:10]


# ------------------------------------------------------------------ scale


@pytest.mark.skipif(os.name == "nt", reason="uses resource.getrusage")
def test_100k_tiny_entries_and_one_50mb_body_ingest_in_bounded_time_and_memory(tmp_path):
    har = tmp_path / "big.har"
    script = textwrap.dedent(
        f"""
        import json, resource, sys, time
        sys.path.insert(0, {os.path.join(os.path.dirname(__file__), "..", "src")!r})

        def entry(i, body="{{}}", mime="application/json"):
            return {{"startedDateTime": "2024-01-01T00:00:00.000Z", "time": 5,
                "request": {{"method": "GET", "url": f"https://app.example.com/api/item/{{i}}?x={{i}}",
                            "httpVersion": "HTTP/1.1", "headers": [], "queryString": [{{"name": "x", "value": str(i)}}],
                            "cookies": [], "headersSize": -1, "bodySize": 0}},
                "response": {{"status": 200, "statusText": "OK", "httpVersion": "HTTP/1.1",
                            "headers": [{{"name": "Content-Type", "value": mime}}], "cookies": [],
                            "content": {{"size": len(body), "mimeType": mime, "text": body}},
                            "redirectURL": "", "headersSize": -1, "bodySize": len(body)}},
                "cache": {{}}, "timings": {{"send": 0, "wait": 1, "receive": 1}}}}

        row = json.dumps({{"id": 1, "name": "widget", "owner": "alice", "note": "hello"}})
        big = "[" + ",".join([row] * (50_000_000 // len(row))) + "]"
        with open({str(har)!r}, "w") as f:
            f.write('{{"log": {{"version": "1.2", "creator": {{"name": "x", "version": "1"}}, "entries": [')
            for i in range(100_000):
                f.write(json.dumps(entry(i)) + ",")
            f.write(json.dumps(entry(100_000, big)) + "]}}}}")
        del big

        from hardly import session as sess
        t = time.time()
        info = sess.open_har({str(har)!r}, force=True)
        dt = time.time() - t
        rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024  # MB on Linux
        print(json.dumps({{"seconds": dt, "rss_mb": rss, "entries": info.get("entries") or info.get("entry_count")}}))
        """
    )
    out = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=900)
    assert out.returncode == 0, out.stderr[-2000:]
    res = json.loads(out.stdout.strip().splitlines()[-1])
    # Measured: ~25 s and ~600 MB here (the generator holds the 50 MB string too); budgets are 4-5x that.
    assert res["seconds"] < 150, res
    assert res["rss_mb"] < 3000, res
