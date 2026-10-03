"""Credential-analysis fixes found by live testing (synthetic HARs)."""

import json

from hardly import session as sess
from hardly.core.credentials import map_credentials


def _entry(i, method, url, *, status=200, req_headers=None, resp_headers=None, req_body=None,
           req_ct="application/x-www-form-urlencoded", body="", ct="text/html", set_cookies=()):
    req = {
        "method": method, "url": url, "httpVersion": "HTTP/1.1",
        "headers": [{"name": k, "value": v} for k, v in (req_headers or {}).items()],
        "queryString": [], "cookies": [], "headersSize": -1, "bodySize": 0,
    }
    if req_body is not None:
        req["postData"] = {"mimeType": req_ct, "text": req_body}
    hdrs = [{"name": "Content-Type", "value": ct}] + [{"name": k, "value": v} for k, v in (resp_headers or {}).items()]
    hdrs += [{"name": "Set-Cookie", "value": c} for c in set_cookies]
    return {
        "startedDateTime": f"2026-01-01T00:00:{i:02d}.000Z", "time": 5, "request": req,
        "response": {"status": status, "statusText": "x", "httpVersion": "HTTP/1.1", "headers": hdrs,
                     "cookies": [], "redirectURL": "", "headersSize": -1, "bodySize": len(body),
                     "content": {"size": len(body), "mimeType": ct, "text": body}},
    }


def _creds(tmp_path, monkeypatch, entries):
    path = tmp_path / "c.har"
    path.write_text(json.dumps({"log": {"version": "1.2", "creator": {"name": "t", "version": "1"}, "entries": entries}}))
    monkeypatch.setenv("HARDLY_CACHE_DIR", str(tmp_path / "cache"))
    info = sess.open_har(str(path), force=True)
    return map_credentials(sess.require_conn(info["session_id"]), har_path=sess.get_har_path(info["session_id"]))


LOGIN_PAGE = '<form method="post" action="/login"><input type="hidden" name="csrfmiddlewaretoken" value="x"><input name="email"><input type="password" name="password"></form>'


def test_login_flow_roles_outcomes_and_cookie_classes(tmp_path, monkeypatch):
    out = _creds(tmp_path, monkeypatch, [
        _entry(1, "GET", "https://app.example.com/login", body=LOGIN_PAGE,
               set_cookies=["csrftoken=AAAA; Path=/; SameSite=Lax"]),
        _entry(2, "POST", "https://app.example.com/login", status=302,
               req_body="csrfmiddlewaretoken=AAAA&_token=BBBB&email=a%40b.co&password=hunter22",
               resp_headers={"Location": "https://app.example.com/home?session_state=S1"},
               set_cookies=["orangehrm=SESSVALUE; Path=/; HttpOnly; Secure; SameSite=Lax"]),
        _entry(3, "GET", "https://app.example.com/home", body="<html>welcome</html>"),
    ])
    steps = {s["entry_id"]: s for s in out["login_flow"]["steps"] if s["role"] in {"login_page", "login_submit", "credential_submit"}}
    assert steps[0]["role"] == "login_page"
    assert steps[1]["role"] in {"login_submit", "credential_submit"}
    assert steps[1]["outcome"] == "redirect" and steps[1]["redirect_to"] == "/home"
    assert "orangehrm" in out["session_cookies"]            # HttpOnly cookie set at the credential POST
    assert "csrftoken" not in out["session_cookies"]         # a CSRF cookie is not the session
    assert "csrftoken" in out["csrf_names"] and "_token" in out["csrf_names"]
    assert "hunter22" not in json.dumps(out) and "SESSVALUE" not in json.dumps(out)


def test_failed_login_is_not_a_redirect(tmp_path, monkeypatch):
    out = _creds(tmp_path, monkeypatch, [
        _entry(1, "GET", "https://a.example.com/login", body=LOGIN_PAGE),
        _entry(2, "POST", "https://a.example.com/login", status=200, body=LOGIN_PAGE,
               req_body="email=a%40b.co&password=bad"),
    ])
    submit = next(s for s in out["login_flow"]["steps"] if s.get("entry_id") == 1)
    assert submit["outcome"] == "page_returned" and "redisplayed" in submit["note"]


def test_oidc_callback_via_location_and_token_body(tmp_path, monkeypatch):
    out = _creds(tmp_path, monkeypatch, [
        _entry(1, "GET", "https://idp.example/connect/authorize?client_id=web&response_type=code&scope=openid&state=ST&nonce=NO&code_challenge=CC&code_challenge_method=S256&redirect_uri=https%3A%2F%2Fapp.example%2Fcb",
               status=302, resp_headers={"Location": "https://idp.example/Account/Login?ReturnUrl=x"}),
        _entry(2, "POST", "https://idp.example/Account/Login", status=302,
               req_body="username=u&password=p", resp_headers={"Location": "https://app.example/cb?code=AUTHCODE9&state=ST&session_state=SS"}),
        _entry(3, "POST", "https://idp.example/connect/token",
               req_body="grant_type=authorization_code&code=AUTHCODE9&code_verifier=VERIFIERSECRET&client_id=web&redirect_uri=https%3A%2F%2Fapp.example%2Fcb",
               body=json.dumps({"access_token": "Zk9vQmFyQmF6S2V5MTIzNDU2Nzg5MEFCQ0Q=", "token_type": "Bearer"}), ct="application/json"),
    ])
    flow = out["oauth"]["flow"]
    assert flow["has_authorize"] and flow["has_callback"] and flow["has_token"] and flow["has_pkce"] and flow["stitched"]
    names = set(out["oauth"]["param_names"])
    assert {"code_verifier", "grant_type", "code", "state"} <= names
    blob = json.dumps(out)
    assert "AUTHCODE9" not in blob and "VERIFIERSECRET" not in blob


def test_webauthn_ceremony(tmp_path, monkeypatch):
    options = json.dumps({"challenge": "Zm9vYmFy", "rp": {"id": "x", "name": "x"}, "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
                          "authenticatorSelection": {"userVerification": "preferred"}})
    verify = json.dumps({"id": "abc", "rawId": "abc", "response": {"clientDataJSON": "e30", "attestationObject": "o2M"}, "type": "public-key"})
    out = _creds(tmp_path, monkeypatch, [
        _entry(1, "POST", "https://w.example/registration/options", body=options, ct="application/json", req_body="{}", req_ct="application/json"),
        _entry(2, "POST", "https://w.example/registration/verification", req_body=verify, req_ct="application/json", body='{"verified":true}', ct="application/json"),
    ])
    wa = out["webauthn"]
    assert wa["likely"] and wa["has_options"] and wa["has_verify"]
    roles = [s["role"] for s in out["login_flow"]["steps"]]
    assert "webauthn_options" in roles and "webauthn_verify" in roles
    # not secrets: WebAuthn option keys must not pollute secret_names
    assert not {"authenticatorSelection", "allowCredentials", "excludeCredentials"} & set(out["secret_names"])


def test_spa_login_and_aborted_entries_notes(tmp_path, monkeypatch):
    shell = '<!doctype html><html><body><div id="root"></div><script src="/bundle.js"></script></body></html>'
    entries = [_entry(1, "GET", "https://spa.example/", body=shell)]
    entries += [_entry(i + 2, "GET", f"https://spa.example/api/{i}", status=-1, body="") for i in range(4)]
    out = _creds(tmp_path, monkeypatch, entries)
    assert out["spa_login_suspected"] is True
    assert any("Client-rendered" in n for n in out["notes"])
    assert out["aborted_entries"]["count"] == 4
    assert any("no response" in n for n in out["notes"])


def test_login_flow_ignores_echoed_passwords_and_models_http_challenges(tmp_path, monkeypatch):
    token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJlLXZhbHVlLWhlcmU"
    out = _creds(tmp_path, monkeypatch, [
        _entry(1, "POST", "https://dj.example/auth/login", req_ct="application/json",
               req_body=json.dumps({"username": "emilys", "password": "hunter22"}),
               body=json.dumps({"accessToken": token, "refreshToken": token, "email": "e@x.co"}), ct="application/json"),
        # profile echoes the password and a userAgent field; it is NOT a login
        _entry(2, "GET", "https://dj.example/auth/me", req_headers={"Authorization": f"Bearer {token}"},
               body=json.dumps({"id": 1, "username": "emilys", "email": "e@x.co", "password": "hunter22", "userAgent": "Mozilla/5.0 X"}),
               ct="application/json"),
        # echo endpoint: returns the token the client already sent
        _entry(3, "GET", "https://hb.example/bearer", req_headers={"Authorization": f"Bearer {token}"},
               body=json.dumps({"authenticated": True, "token": token}), ct="application/json"),
        # Basic challenge then retry
        _entry(4, "GET", "https://hb.example/basic-auth/u/p", status=401,
               resp_headers={"WWW-Authenticate": 'Basic realm="Fake Realm"'}),
        _entry(5, "GET", "https://hb.example/basic-auth/u/p", req_headers={"Authorization": "Basic dTpw"},
               body='{"authenticated":true}', ct="application/json"),
    ])
    flow = out["login_flow"]["steps"]
    by_entry = {}
    for s in flow:
        by_entry.setdefault(s["entry_id"], []).append(s["role"])
    assert "login_submit" in by_entry[0] or "credential_submit" in by_entry[0]
    assert not {"login_submit", "credential_submit"} & set(by_entry.get(1, []))      # /auth/me is not a login
    assert "token_issue" not in by_entry.get(2, [])                                  # echo endpoint
    assert "auth_challenge" in by_entry[3] and "auth_retry" in by_entry[4]
    login = next(s for s in flow if s["entry_id"] == 0 and s["role"] in {"login_submit", "credential_submit"})
    assert login["identity_field"] == "username"
    names = [f["name"] for f in out["identity_fields"]]
    assert "userAgent" not in names
    assert "hunter22" not in json.dumps(out) and token not in json.dumps(out)


def test_openapi_and_stub_reflect_auth_scheme_and_parameters(tmp_path, monkeypatch):
    from hardly.core.export_openapi import export_openapi
    from hardly.core.stub import client_stub

    token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJlLXZhbHVlLWhlcmU"
    entries = [
        _entry(1, "GET", "https://api.example.com/auth/login", body='{"ok":true}', ct="application/json"),
        _entry(2, "GET", "https://api.example.com/items/42?status=available&page=2",
               req_headers={"Authorization": f"Basic dTpw", "api_key": "special"}, body='{"id":42}', ct="application/json"),
        _entry(3, "GET", "https://api.example.com/items/43?status=sold",
               req_headers={"Authorization": f"Bearer {token}"}, body='{"id":43}', ct="application/json"),
    ]
    path = tmp_path / "o.har"
    path.write_text(json.dumps({"log": {"version": "1.2", "creator": {"name": "t", "version": "1"}, "entries": entries}}))
    monkeypatch.setenv("HARDLY_CACHE_DIR", str(tmp_path / "cache"))
    info = sess.open_har(str(path), force=True)
    conn = sess.require_conn(info["session_id"])
    out = tmp_path / "o.json"
    export_openapi(conn, out)
    doc = json.loads(out.read_text())
    op = doc["paths"]["/items/{id}"]["get"]
    params = {(p["name"], p["in"]): p for p in op["parameters"]}
    assert params[("id", "path")]["required"] is True and params[("id", "path")]["schema"]["type"] == "integer"
    assert ("status", "query") in params and ("page", "query") in params
    assert params[("page", "query")]["schema"]["type"] == "integer"
    assert "security" not in doc                                  # public operations stay open
    assert "security" not in doc["paths"]["/auth/login"]["get"]
    assert op["security"] in ([{"basicAuth": []}], [{"bearerAuth": []}])
    schemes = doc["components"]["securitySchemes"]
    assert schemes["basicAuth"]["scheme"] == "basic" and schemes["bearerAuth"]["bearerFormat"] == "JWT"
    stub = client_stub(conn, entry_ids=[1], output_path=tmp_path / "s.py")
    text = (tmp_path / "s.py").read_text()
    assert "Basic PLACEHOLDER_BASIC_CREDENTIALS" in text and "PLACEHOLDER_API_KEY" in text
    assert "dTpw" not in text and "special" not in text and token not in text
    compile(text, "s.py", "exec")
