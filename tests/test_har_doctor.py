"""HAR doctor + hygiene tools, on synthetic HARs written to tmp_path."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from hardly.core.har_doctor import add_cli_flags, config_from_namespace, diagnose_har, normalize_config
from hardly.core.har_tools import merge_hars, prune_har, scrub_har, split_har


def ent(url="https://a.example.com/x", method="GET", status=200, text="hello", size=None, mime="text/plain",
        t="2026-01-01T00:00:00.000Z", req_headers=None, resp_headers=None, **extra):
    content = {"size": len(text or "") if size is None else size, "mimeType": mime}
    if text is not None:
        content["text"] = text
    e = {
        "startedDateTime": t,
        "time": 10,
        "request": {"method": method, "url": url, "httpVersion": "HTTP/1.1", "headers": req_headers or [],
                    "queryString": [], "cookies": [], "headersSize": -1, "bodySize": 0},
        "response": {"status": status, "statusText": "", "httpVersion": "HTTP/1.1", "headers": resp_headers or [],
                     "cookies": [], "content": content, "redirectURL": "", "headersSize": -1, "bodySize": len(text or "")},
        "cache": {},
        "timings": {"send": 1, "wait": 5, "receive": 4},
    }
    e.update(extra)
    return e


def write(tmp_path: Path, entries, pages=None, creator="Playwright", version="1.2", name="t.har") -> Path:
    log = {"version": version, "entries": entries}
    if creator:
        log["creator"] = {"name": creator, "version": "1"}
    if pages is not None:
        log["pages"] = pages
    p = tmp_path / name
    p.write_text(json.dumps({"log": log}))
    return p


def codes(res):
    return {f["code"]: f for f in res["findings"]}


def test_clean_har_has_no_warnings(tmp_path):
    p = write(tmp_path, [ent()], creator="hardly-fixture")
    res = diagnose_har(None, p)
    assert res["summary"]["warn"] == 0 and res["summary"]["error"] == 0
    assert res["exit_code"] == 0


def test_body_problems(tmp_path):
    es = [
        ent(text=None, size=-1),
        ent(text="abc", size=1000),
        ent(text="!!!notb64", mime="application/json"),
        ent(text="x" * 70_000, mime="text/html"),
        ent(text="aGk=", mime="application/json"),
    ]
    es[2]["response"]["content"]["encoding"] = "base64"
    es[4]["response"]["content"]["encoding"] = "base64"
    es[4]["response"]["content"]["size"] = 2
    c = codes(diagnose_har(None, write(tmp_path, es)))
    assert c["body_omitted"]["entry_ids"] == [0]
    assert c["body_truncated"]["entry_ids"] == [1]
    assert c["bad_encoding"]["entry_ids"] == [2]
    assert c["preview_capped"]["entry_ids"] == [3]
    assert c["base64_text"]["entry_ids"] == [2, 4]
    assert "omit_content=False" in c["body_omitted"]["fix_hint"]


def test_request_and_status_and_redirect(tmp_path):
    post = ent(method="POST")
    post["request"]["bodySize"] = 20
    es = [
        post,
        ent(status=0, text=""),
        ent(status=302, text="", resp_headers=[]),
        ent(status=302, text="", resp_headers=[{"name": "Location", "value": "/y"}]),
        ent(status=200, _error="net::ERR_FAILED"),
    ]
    c = codes(diagnose_har(None, write(tmp_path, es)))
    assert c["request_body_missing"]["entry_ids"] == [0]
    assert c["status_zero"]["entry_ids"] == [1, 4]
    assert c["redirect_no_location"]["entry_ids"] == [2]


def test_timing_and_clock(tmp_path):
    es = [ent(t="2026-01-01T00:00:10Z"), ent(t="2026-01-01T00:00:00Z"), ent(t="garbage"), ent()]
    es[3]["timings"] = {"send": -1, "wait": -1, "receive": -1}
    es[3]["time"] = -1
    es[0]["timings"] = {"send": -5, "wait": 1}
    c = codes(diagnose_har(None, write(tmp_path, es)))
    assert c["out_of_order"]["entry_ids"] == [1, 3]
    assert c["bad_start_time"]["entry_ids"] == [2]
    assert c["no_timings"]["entry_ids"] == [3]
    assert c["bad_timings"]["entry_ids"] == [0]
    c2 = codes(diagnose_har(None, write(tmp_path, es), {"thresholds": {"clock_skew_s": 60}}))
    assert "out_of_order" not in c2


def test_pages(tmp_path):
    pages = [{"id": "p1", "startedDateTime": "2026-01-01T00:01:00Z", "title": "a"},
             {"id": "p2", "startedDateTime": "2026-01-01T00:00:00Z", "title": "b"}]
    es = [ent(pageref="p1"), ent(pageref="nope"), ent()]
    c = codes(diagnose_har(None, write(tmp_path, es, pages=pages)))
    assert "page_no_entries" in c and "p2" in c["page_no_entries"]["message"]
    assert c["dangling_pageref"]["entry_ids"] == [1]
    assert c["missing_pageref"]["entry_ids"] == [2]
    assert c["clock_skew"]["entry_ids"] == [0]


def test_duplicates_giant_pseudo(tmp_path):
    big = ent(text="ab", size=50_000_000)
    es = [ent(), ent(), big, ent(t="2026-01-01T00:00:01Z", req_headers=[{"name": ":path", "value": "/"}])]
    c = codes(diagnose_har(None, write(tmp_path, es)))
    assert c["duplicate_entry"]["entry_ids"] == [1]
    assert c["giant_entry"]["entry_ids"] == [2]
    assert c["http2_pseudo_headers"]["entry_ids"] == [3]
    c2 = codes(diagnose_har(None, write(tmp_path, es), {"thresholds": {"max_entry_bytes": 10**9}}))
    assert "giant_entry" not in c2


def test_sanitised(tmp_path):
    red = [{"name": "Authorization", "value": "[REDACTED]"}]
    es = [ent(req_headers=red, resp_headers=[{"name": "Set-Cookie", "value": "a=b"}])]
    c = codes(diagnose_har(None, write(tmp_path, es)))
    assert c["headers_redacted"]["entry_ids"] == [0]
    assert c["cookies_stripped"]["count"] == 1
    es.append(ent(req_headers=[{"name": "Cookie", "value": "a=b"}]))
    assert "cookies_stripped" not in codes(diagnose_har(None, write(tmp_path, es)))


def test_hosts(tmp_path):
    es = [ent(url="https://www.google-analytics.com/c") for _ in range(8)] + [
        ent(url=f"https://h{i}.example.com/") for i in range(4)
    ]
    c = codes(diagnose_har(None, write(tmp_path, es), {"thresholds": {"noise_ratio": 0.3}}))
    assert "noise_hosts" in c and "mixed_hosts" in c
    c2 = codes(diagnose_har(None, write(tmp_path, es), {"thresholds": {"noise_ratio": 0.99}}))
    assert "noise_hosts" not in c2 and "mixed_hosts" not in c2


def test_version_and_creator(tmp_path):
    c = codes(diagnose_har(None, write(tmp_path, [ent()], creator=None, version="1.0")))
    assert "har_version" in c
    c = codes(diagnose_har(None, write(tmp_path, [ent()], creator="mitmproxy")))
    assert "mitmproxy" in c["creator_quirk"]["message"]


def test_knobs(tmp_path):
    es = [ent(text=None, size=-1), ent(url="https://skip.example.org/q")]
    p = write(tmp_path, es)
    assert codes(diagnose_har(None, p, {"checks": ["status_*"]})) == {}
    assert "body_omitted" not in codes(diagnose_har(None, p, {"exclude": ["body_*"]}))
    assert "body_omitted" not in codes(diagnose_har(None, p, {"ignore_hosts": ["a.example.com"]}))
    assert "body_omitted" not in codes(diagnose_har(None, p, {"host": "skip.*"}))
    assert "body_omitted" not in codes(diagnose_har(None, p, {"ignore_paths": ["/x"]}))
    r = diagnose_har(None, p, {"severity_overrides": {"body_omitted": "info"}})
    assert codes(r)["body_omitted"]["severity"] == "info"
    r = diagnose_har(None, p)
    assert r["exit_code"] == 0 and codes(r)["body_omitted"]["severity"] == "warn"
    r = diagnose_har(None, p, {"strict": True})
    assert codes(r)["body_omitted"]["severity"] == "error" and r["exit_code"] == 1
    assert diagnose_har(None, p, {"strict": True, "fail_on": "never"})["exit_code"] == 0
    assert diagnose_har(None, p, {"fail_on": "warn"})["exit_code"] == 1
    r = diagnose_har(None, p, {"fix": False})
    assert all(f["fix_hint"] == "" for f in r["findings"]) and r["recapture"] == {}
    assert diagnose_har(None, p)["recapture"] == {"omit_content": False}
    r = diagnose_har(None, p, {"max_findings": 1})
    assert len(r["findings"]) == 1 and r["dropped_findings"] >= 1
    with pytest.raises(ValueError):
        normalize_config({"bogus": 1})
    cfgp = tmp_path / "c.json"
    cfgp.write_text('{"strict": true}')
    assert normalize_config(str(cfgp))["strict"] is True
    assert normalize_config('{"checks": {"include": ["a*"], "exclude": ["b"]}}')["exclude"] == ["b"]


def test_cli_flags():
    import argparse

    ap = argparse.ArgumentParser()
    add_cli_flags(ap)
    ns = ap.parse_args(["--strict", "--noise-ratio", "0.2", "--severity", "no_timings=error",
                        "--ignore-host", "x*", "--checks", "no_timings,body_omitted"])
    full = normalize_config(config_from_namespace(ns))
    assert full["strict"] and full["thresholds"]["noise_ratio"] == 0.2
    assert full["severity_overrides"] == {"no_timings": "error"}
    assert full["checks"] == ["no_timings", "body_omitted"] and full["ignore_hosts"] == ["x*"]


def test_index_stale(tmp_path):
    from hardly.index.ingest import ingest_har
    from hardly.index.schema import connect

    p = write(tmp_path, [ent()])
    db = tmp_path / "x.db"
    ingest_har(p, db)
    conn = connect(str(db))
    assert "index_stale" not in codes(diagnose_har(conn, p))
    write(tmp_path, [ent(), ent(url="https://z.example.com/")])
    assert "index_stale" in codes(diagnose_har(conn, p))
    write(tmp_path, [ent()])
    (tmp_path / "x.json").write_text('{"index_version": 0}')
    assert "index_version 0" in codes(diagnose_har(conn, p))["index_stale"]["message"]


# ------------------------------------------------------------------ tools


def load(p):
    return json.loads(Path(p).read_text())["log"]


def test_prune(tmp_path):
    pages = [{"id": "p1"}, {"id": "p2"}]
    es = [
        ent(url="https://a.example.com/api", pageref="p1", mime="application/json"),
        ent(url="https://cdn.example.com/i.png", pageref="p1", mime="image/png"),
        ent(url="https://www.google-analytics.com/c", pageref="p2"),
        ent(url="https://t.example.com/k"),
    ]
    src = write(tmp_path, es, pages=pages)
    before = src.read_bytes()
    r = prune_har(src, tmp_path / "o.har", drop_hosts=["t.*"], drop_mime=["image/*"], drop_noise=True)
    assert r["kept"] == 1 and r["dropped"] == 3 and r["pages_dropped"] == 1
    assert [p["id"] for p in load(tmp_path / "o.har")["pages"]] == ["p1"]
    assert src.read_bytes() == before
    with pytest.raises(ValueError):
        prune_har(src, src)
    with pytest.raises(FileExistsError):
        prune_har(src, tmp_path / "o.har")
    prune_har(src, tmp_path / "o.har", overwrite=True)


def test_split_merge(tmp_path):
    pages = [{"id": "p1"}, {"id": "p2"}]
    es = [ent(url="https://a.example.com/1", pageref="p1"), ent(url="https://b.example.com/2", pageref="p2"),
          ent(url="https://a.example.com/3", pageref="p1")]
    src = write(tmp_path, es, pages=pages)
    r = split_har(src, "host", tmp_path / "out")
    assert {k: v["entries"] for k, v in r["files"].items()} == {"a.example.com": 2, "b.example.com": 1}
    assert len(load(r["files"]["a.example.com"]["path"])["entries"]) == 2
    r2 = split_har(src, "page", tmp_path / "outp")
    assert [p["id"] for p in load(r2["files"]["p2"]["path"])["pages"]] == ["p2"]
    paths = [v["path"] for v in r["files"].values()]
    m = merge_hars(paths + [paths[0]], tmp_path / "m.har")
    assert m["entries"] == 3 and m["duplicates"] == 2
    log = load(tmp_path / "m.har")
    assert len(log["entries"]) == 3 and {p["id"] for p in log["pages"]} >= {"f1_p1", "f2_p2"}
    assert diagnose_har(None, tmp_path / "m.har")["entries"] == 3
    with pytest.raises(ValueError):
        split_har(src, "bogus", tmp_path)


def test_scrub(tmp_path):
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.abcdefghijklmnop"
    e = ent(
        url="https://a.example.com/x?api_key=SECRET1&q=hi",
        method="POST",
        req_headers=[{"name": "Authorization", "value": "Bearer " + jwt},
                     {"name": "Cookie", "value": "sid=abc; theme=dark"},
                     {"name": "Accept", "value": "*/*"}],
        resp_headers=[{"name": "Set-Cookie", "value": "sid=zzz; Path=/; HttpOnly"}],
        text=json.dumps({"access_token": "tok123", "name": "bob", "n": 5, "nested": [{"password": "pw"}]}),
        mime="application/json",
    )
    e["request"]["cookies"] = [{"name": "sid", "value": "abc"}]
    e["request"]["postData"] = {"mimeType": "application/x-www-form-urlencoded", "text": "user=bob&password=hunter2"}
    src = write(tmp_path, [e])
    scrub_har(src, tmp_path / "s.har")
    raw = (tmp_path / "s.har").read_text()
    for secret in ("SECRET1", jwt, "zzz", "tok123", "hunter2", '"pw"', "sid=abc", "sid=\"abc"):
        assert secret not in raw, secret
    out = load(tmp_path / "s.har")["entries"][0]
    hdr = {h["name"]: h["value"] for h in out["request"]["headers"]}
    assert hdr["Authorization"].startswith("Bearer ") and "REDACTED" in hdr["Authorization"]
    assert hdr["Accept"] == "*/*" and "sid=" in hdr["Cookie"] and "theme=" in hdr["Cookie"]
    body = json.loads(out["response"]["content"]["text"])
    assert body["name"] == "bob" and body["n"] == 5 and body["access_token"] == "***REDACTED***"
    assert "user=bob" in out["request"]["postData"]["text"]
    assert "headers_redacted" in codes(diagnose_har(None, tmp_path / "s.har"))
