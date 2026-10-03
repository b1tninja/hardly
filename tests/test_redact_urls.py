"""URL / path-parameter redaction and sensitive-key precision."""

import json

from hardly import session as sess
from hardly.core.html_forms import extract_html_structure
from hardly.core.redact import REDACTED, is_sensitive_key, redact_string, redact_url


def test_redact_url_hides_oauth_values_keeps_names():
    url = "https://idp.example/cb?code=AUTHCODE1&state=STATE9&foo=bar&session_state=SS&nonce=N1#access_token=TOK"
    out = redact_url(url)
    for secret in ("AUTHCODE1", "STATE9", "SS&", "N1", "TOK"):
        assert secret not in out
    assert "foo=bar" in out and "code=" in out and "state=" in out
    assert out.count(REDACTED) == 5


def test_redact_url_path_params():
    assert redact_url("/bank/login.htm;jsessionid=ABCDEF1234567890") == f"/bank/login.htm;jsessionid={REDACTED}"
    assert "ABCDEF" not in redact_string('<form action="/l.htm;jsessionid=ABCDEF1234567890?x=1">')
    assert redact_url("/plain/path?page=2") == "/plain/path?page=2"


def test_forms_do_not_leak_path_session_ids():
    html = '<form action="/bank/login.htm;jsessionid=ABCDEF1234567890" method="post"><input name="u"></form>'
    out = extract_html_structure(html, base_url="https://x.example/")
    assert "ABCDEF" not in json.dumps(out)


def test_sensitive_key_precision():
    for ok in ("password", "access_token", "authToken", "clientSecret", "auth", "credentials", "session", "cookie", "ctl00$txtPwd"):
        assert is_sensitive_key(ok), ok
    for noise in ("authenticatorSelection", "allowCredentials", "excludeCredentials", "Access-Control-Allow-Credentials",
                  "sessionCount", "cookieBanner", "authorName"):
        assert not is_sensitive_key(noise), noise


def test_redirects_redacts_location(tmp_path, monkeypatch):
    from hardly.core.redirects import redirect_chains

    def entry(i, url, status, headers=()):
        return {
            "startedDateTime": f"2026-01-01T00:00:0{i}.000Z", "time": 5,
            "request": {"method": "GET", "url": url, "httpVersion": "HTTP/1.1", "headers": [],
                        "queryString": [], "cookies": [], "headersSize": -1, "bodySize": 0},
            "response": {"status": status, "statusText": "x", "httpVersion": "HTTP/1.1",
                         "headers": [{"name": k, "value": v} for k, v in headers], "cookies": [],
                         "redirectURL": "", "headersSize": -1, "bodySize": 0,
                         "content": {"size": 0, "mimeType": "text/html", "text": ""}},
        }

    har = {"log": {"version": "1.2", "creator": {"name": "t", "version": "1"}, "entries": [
        entry(1, "https://idp.example/login", 302,
              [("Location", "https://app.example/cb?code=AUTHCODESECRET&state=S1&lang=en")]),
        entry(2, "https://app.example/cb?code=AUTHCODESECRET&state=S1&lang=en", 200),
    ]}}
    path = tmp_path / "r.har"
    path.write_text(json.dumps(har))
    monkeypatch.setenv("HARDLY_CACHE_DIR", str(tmp_path / "cache"))
    info = sess.open_har(str(path), force=True)
    out = redirect_chains(sess.require_conn(info["session_id"]))
    blob = json.dumps(out)
    assert "AUTHCODESECRET" not in blob and "S1&" not in blob
    assert "lang=en" in blob and out["chains"][0]["target"]["follow_entry_id"] is not None


def test_redact_url_keeps_len_truncation_marker_intact():
    out = redact_url("/a?authtoken_value_long…(len=900)&q=2…(len=5)")
    assert out == "/a?authtoken_value_long…(len=900)&q=2…(len=5)"
    out = redact_url("/a?token=abc…(len=900)")
    assert "abc" not in out and out.endswith("…(len=900)") and REDACTED in out
