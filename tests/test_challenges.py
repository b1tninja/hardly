"""Auth challenges, throttling and captcha widget detection (synthetic HAR)."""

import json

from hardly import session as sess
from hardly.core.challenges import detect_challenges, parse_challenges


def _entry(i, url, *, status=200, req_headers=None, resp_headers=None, body="", ct="text/html"):
    hdrs = [{"name": "Content-Type", "value": ct}] + [
        {"name": k, "value": v} for k, v in (resp_headers or {}).items()
    ]
    return {
        "startedDateTime": f"2026-01-01T00:00:{i:02d}.000Z", "time": 5,
        "request": {
            "method": "GET", "url": url, "httpVersion": "HTTP/1.1",
            "headers": [{"name": k, "value": v} for k, v in (req_headers or {}).items()],
            "queryString": [], "cookies": [], "headersSize": -1, "bodySize": 0,
        },
        "response": {
            "status": status, "statusText": "x", "httpVersion": "HTTP/1.1",
            "headers": hdrs, "cookies": [], "redirectURL": "", "headersSize": -1,
            "bodySize": len(body),
            "content": {"size": len(body), "mimeType": ct, "text": body},
        },
    }


def test_parse_multiple_schemes_hides_nonce():
    out = parse_challenges(
        'Digest realm="area", qop="auth", nonce="SECRETNONCE123", opaque="OPQ", algorithm=MD5, '
        'Basic realm="area", Bearer error="invalid_token", scope="read"'
    )
    schemes = [c["scheme"] for c in out]
    assert schemes == ["Digest", "Basic", "Bearer"]
    digest = out[0]
    assert {"realm", "qop", "nonce", "opaque", "algorithm"} <= set(digest["params"])
    assert "nonce" not in digest["values"] and "opaque" not in digest["values"]
    assert out[2]["values"]["error"] == "invalid_token"


def test_detect_challenges(tmp_path, monkeypatch):
    entries = [
        _entry(1, "https://api.example.com/private", status=401,
               resp_headers={"WWW-Authenticate": 'Digest realm="r", nonce="NONCEVALUE9999", qop="auth"'}),
        _entry(2, "https://api.example.com/private", status=200,
               req_headers={"Authorization": 'Digest username="u", response="deadbeef"'}),
        _entry(3, "https://api.example.com/login", status=429,
               resp_headers={"Retry-After": "30", "X-RateLimit-Remaining": "0"},
               body="Too many attempts, try again later"),
        _entry(4, "https://api.example.com/ok", status=200,
               resp_headers={"X-RateLimit-Limit": "100", "X-RateLimit-Remaining": "99"}),
        _entry(5, "https://app.example.com/signin", body=(
            '<form><div class="g-recaptcha" data-sitekey="K"></div>'
            '<div class="cf-turnstile" data-sitekey="K2"></div>'
            '<textarea name="g-recaptcha-response"></textarea></form>'
            '<script src="https://www.google.com/recaptcha/api.js"></script>')),
    ]
    path = tmp_path / "c.har"
    path.write_text(json.dumps({"log": {"version": "1.2", "creator": {"name": "t", "version": "1"}, "entries": entries}}))
    monkeypatch.setenv("HARDLY_CACHE_DIR", str(tmp_path / "cache"))
    info = sess.open_har(str(path), force=True)
    out = detect_challenges(sess.require_conn(info["session_id"]))

    ch = out["auth_challenges"][0]
    assert ch["schemes"][0]["scheme"] == "Digest"
    assert ch["retried_with_credentials"]["status"] == 200
    thr = {t["status"]: t for t in out["throttling"]}
    assert thr[429]["lockout_text"] and any(r["name"] == "retry-after" for r in thr[429]["rate_headers"])
    assert any(t.get("advertised_only") for t in out["throttling"])
    caps = {c["name"]: c for c in out["captcha_widgets"]}
    assert {"recaptcha", "turnstile"} <= set(caps)
    assert "g-recaptcha-response" in caps["recaptcha"]["response_fields"]
    blob = json.dumps(out)
    assert "NONCEVALUE9999" not in blob and "deadbeef" not in blob
