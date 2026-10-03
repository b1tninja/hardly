"""Bot-protection product identification (synthetic HARs)."""

import json

from hardly import session as sess
from hardly.core.botwalls import CATALOG, detect_bot_protection


def _entry(i, url, *, status=200, resp_headers=None, set_cookies=(), body="", ct="text/html", req_cookies=()):
    hdrs = [{"name": "Content-Type", "value": ct}] + [
        {"name": k, "value": v} for k, v in (resp_headers or {}).items()
    ]
    return {
        "startedDateTime": f"2026-01-01T00:00:{i:02d}.000Z", "time": 5,
        "request": {
            "method": "GET", "url": url, "httpVersion": "HTTP/1.1",
            "headers": ([{"name": "Cookie", "value": "; ".join(f"{k}=v{ n }" for n, k in enumerate(req_cookies))}] if req_cookies else []),
            "queryString": [], "cookies": [{"name": k, "value": "x"} for k in req_cookies],
            "headersSize": -1, "bodySize": 0,
        },
        "response": {
            "status": status, "statusText": "x", "httpVersion": "HTTP/1.1",
            "headers": hdrs + [{"name": "Set-Cookie", "value": f"{c}=SECRETVALUE; Path=/"} for c in set_cookies],
            "cookies": [{"name": c, "value": "SECRETVALUE"} for c in set_cookies],
            "redirectURL": "", "headersSize": -1, "bodySize": len(body),
            "content": {"size": len(body), "mimeType": ct, "text": body},
        },
    }


def _open(tmp_path, monkeypatch, entries):
    path = tmp_path / "w.har"
    path.write_text(json.dumps({"log": {"version": "1.2", "creator": {"name": "t", "version": "1"}, "entries": entries}}))
    monkeypatch.setenv("HARDLY_RUNTIME_DIR", str(tmp_path / "cache"))
    info = sess.open_har(str(path), force=True)
    return sess.require_conn(info["session_id"]), sess.get_har_path(info["session_id"])


def test_catalog_ids_unique_and_compile():
    ids = [v.id for v in CATALOG]
    assert len(ids) == len(set(ids))
    from hardly.core.botwalls import _compiled

    for v in CATALOG:
        _compiled(v)


def test_cloudflare_challenge_blocked(tmp_path, monkeypatch):
    conn, har = _open(tmp_path, monkeypatch, [
        _entry(1, "https://shop.example.com/", status=403,
               resp_headers={"Server": "cloudflare", "CF-RAY": "abc-LAX", "cf-mitigated": "challenge"},
               set_cookies=["__cf_bm"],
               body="<html><title>Just a moment...</title><script src='/cdn-cgi/challenge-platform/h/b/orchestrate/x'></script></html>"),
    ])
    out = detect_bot_protection(conn, har_path=har)
    top = out["vendors"][0]
    assert top["id"] == "cloudflare" and top["confidence"] == "high" and top["state"] == "blocked"
    assert out["blocking"] == ["cloudflare"] and out["needs_person"] == ["cloudflare"]
    kinds = {e["kind"] for e in top["evidence"]}
    assert {"header", "cookie"} <= kinds
    assert "SECRETVALUE" not in json.dumps(out)


def test_clearance_cookie_and_multiple_vendors(tmp_path, monkeypatch):
    conn, har = _open(tmp_path, monkeypatch, [
        _entry(1, "https://a.example.com/", resp_headers={"Server": "cloudflare"}, set_cookies=["cf_clearance"]),
        _entry(2, "https://a.example.com/login", body=(
            '<div class="g-recaptcha" data-sitekey="K"></div>'
            '<script src="https://www.google.com/recaptcha/api.js"></script>')),
        _entry(3, "https://a.example.com/x", set_cookies=["datadome"],
               resp_headers={"X-DataDome": "protected"}),
    ], )
    out = detect_bot_protection(conn, har_path=har)
    by = {v["id"]: v for v in out["vendors"]}
    assert by["cloudflare"]["state"] == "clearance_seen"
    assert by["recaptcha"]["category"] == "captcha" and by["recaptcha"]["state"] == "present"
    assert by["datadome"]["clearance_cookies_seen"] == ["datadome"]
    assert out["blocking"] == []


def test_akamai_access_denied_and_generic_fallback(tmp_path, monkeypatch):
    conn, har = _open(tmp_path, monkeypatch, [
        _entry(1, "https://b.example.com/", status=403, set_cookies=["_abck", "bm_sz"],
               resp_headers={"Server": "AkamaiGHost"},
               body="<h1>Access Denied</h1>Reference #18.2d351ab8.1700000000.1a2b3c"),
        _entry(2, "https://c.example.com/", status=403,
               body="<h1>Request blocked</h1> unusual traffic detected"),
    ])
    out = detect_bot_protection(conn, har_path=har)
    ids = [v["id"] for v in out["vendors"]]
    assert ids[0] == "akamai" and out["vendors"][0]["state"] == "blocked"
    # the second host is not explained by Akamai, so the generic fallback stays
    assert "generic-block" in ids
    generic = next(v for v in out["vendors"] if v["id"] == "generic-block")
    assert generic["state"] == "blocked" and generic["confidence"] != "high"


def test_clean_capture_has_no_vendors(tmp_path, monkeypatch):
    conn, har = _open(tmp_path, monkeypatch, [_entry(1, "https://plain.example.com/", body="<html>hello</html>")])
    out = detect_bot_protection(conn, har_path=har)
    assert out["vendors"] == [] and "recommendation" not in out  # evidence only by default
    assert "No known" in detect_bot_protection(conn, har_path=har, explain=True)["recommendation"]


def test_generic_suppressed_when_product_explains_it(tmp_path, monkeypatch):
    conn, har = _open(tmp_path, monkeypatch, [
        _entry(1, "https://b.example.com/", status=403, set_cookies=["_abck"],
               resp_headers={"Server": "AkamaiGHost"}, body="<h1>Access Denied</h1>"),
    ])
    ids = [v["id"] for v in detect_bot_protection(conn, har_path=har)["vendors"]]
    assert ids == ["akamai"]


def test_wall_ignores_cdn_header_on_ok_page_but_reports_real_blocks(tmp_path, monkeypatch):
    from hardly.core.wall import detect_walls

    conn, _ = _open(tmp_path, monkeypatch, [
        _entry(1, "https://ok.example.com/", resp_headers={"Server": "cloudflare", "CF-RAY": "x-LAX"}),
        _entry(2, "https://ok.example.com/api/me", status=403, body='{"error":"forbidden"}', ct="application/json"),
    ])
    out = detect_walls(conn, explain=True)
    assert "next" not in detect_walls(conn)
    assert out["hit_count"] == 0 and out["hits"] == []          # CDN header + plain 403 are not a wall
    assert [p["id"] for p in out["protection"]] == ["cloudflare"]
    assert out["protection"][0]["state"] == "present"
    assert out["status_only"] and out["status_only"][0]["status"] == 403
    assert "informational" in out["next"]

    (tmp_path / "b").mkdir()
    conn, _ = _open(tmp_path / "b", monkeypatch, [
        _entry(1, "https://blocked.example.com/", status=403,
               resp_headers={"Server": "cloudflare", "cf-mitigated": "challenge"},
               body="<title>Just a moment...</title>"),
    ])
    out = detect_walls(conn)
    assert out["hit_count"] == 1 and out["blocking"] == ["cloudflare"]
