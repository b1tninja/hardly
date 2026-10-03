"""Generic auth-pattern detectors, using synthetic HARs built in-test."""

import base64
import hashlib
import json
import threading
import urllib.error
import urllib.parse
import urllib.request
import zlib
from http.server import BaseHTTPRequestHandler, HTTPServer

from hardly.core.auth_patterns import detect_auth_patterns

ACC = "acc-" + "A1b2C3d4" * 4
ACC2 = "acc-" + "Z9y8X7w6" * 4
REF = "ref-" + "Q1w2E3r4" * 4
REF2 = "ref-" + "T5y6U7i8" * 4
SECRETS = [ACC, ACC2, REF, REF2]


def ent(method, url, *, req_h=None, resp_h=None, body=None, mime=None, status=200,
        resp_text=None, resp_mime="application/json", cookies=None):
    req = {"method": method, "url": url, "headers": [{"name": k, "value": v} for k, v in (req_h or {}).items()],
           "cookies": [{"name": k, "value": v} for k, v in (cookies or {}).items()]}
    if body is not None:
        req["postData"] = {"mimeType": mime or "application/json", "text": body}
    rh = []
    for k, v in (resp_h or {}).items():
        for x in (v if isinstance(v, list) else [v]):
            rh.append({"name": k, "value": x})
    resp = {"status": status, "headers": rh, "content": {"mimeType": resp_mime, "text": resp_text or ""}}
    return {"request": req, "response": resp}


def har(tmp_path, entries):
    p = tmp_path / "t.har"
    p.write_text(json.dumps({"log": {"entries": entries}}))
    return p


def test_bearer_refresh(tmp_path):
    h = {"Content-Type": "application/json"}
    p = har(tmp_path, [
        ent("POST", "https://api.test/auth/login", body='{"user":"u","password":"pw"}',
            resp_text=json.dumps({"access_token": ACC, "refresh_token": REF, "expires_in": 300})),
        ent("GET", "https://api.test/v1/items", req_h={"Authorization": "Bearer " + ACC}),
        ent("GET", "https://api.test/v1/items", req_h={"Authorization": "Bearer " + ACC}, status=401),
        ent("POST", "https://api.test/auth/refresh", req_h=h,
            body=json.dumps({"refresh_token": REF}),
            resp_text=json.dumps({"access_token": ACC2, "refresh_token": REF2, "expires_in": 300})),
        ent("GET", "https://api.test/v1/items", req_h={"Authorization": "Bearer " + ACC2}),
    ])
    r = detect_auth_patterns(p, kinds=["bearer_refresh"])["bearer_refresh"]
    assert r["detected"]
    login = next(t for t in r["token_endpoints"] if t["path"] == "/auth/login")
    assert login["access_field"] == "access_token" and login["refresh_field"] == "refresh_token"
    assert login["uses"][0]["header"] == "authorization" and login["uses"][0]["scheme"] == "Bearer"
    assert "expires_in" in login["expiry_fields"]
    fl = r["refresh_flows"][0]
    assert fl["path"] == "/auth/refresh" and fl["refresh_matches_issued"] and fl["rotates_refresh"]
    assert fl["follows_401"] and fl["issues_new_access"]
    blob = json.dumps(r)
    assert not any(s in blob for s in SECRETS)


def _auth_url(base, verifier, state="st" + "x" * 20):
    chal = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    q = urllib.parse.urlencode({"response_type": "code", "client_id": "app", "scope": "openid profile",
                                "redirect_uri": "http://127.0.0.1:8765/cb", "state": state, "nonce": "n" * 16,
                                "code_challenge": chal, "code_challenge_method": "S256"})
    return f"{base}/authorize?{q}", state


def test_oidc_pkce_synthetic(tmp_path):
    verifier = "v" * 50
    url, state = _auth_url("https://idp.test", verifier)
    p = har(tmp_path, [
        ent("GET", url, status=302, resp_h={"Location": f"http://127.0.0.1:8765/cb?code=thecode123&state={state}"}),
        ent("POST", "https://idp.test/token", mime="application/x-www-form-urlencoded",
            body=urllib.parse.urlencode({"grant_type": "authorization_code", "code": "thecode123",
                                         "code_verifier": verifier, "client_id": "app"}),
            resp_text=json.dumps({"access_token": ACC, "id_token": "a.b.c", "expires_in": 60})),
    ])
    r = detect_auth_patterns(p, kinds=["oidc_pkce"])["oidc_pkce"]
    f = r["flows"][0]
    assert f["pkce"] and f["oidc"] and f["loopback_redirect"] and f["state_roundtrip"]
    assert {"state", "nonce", "code_challenge"} <= set(f["params_present"])
    x = f["token_exchange"]
    assert x["verifier_matches_challenge"] is True and x["code_matches_callback"] is True
    assert x["client_auth"] == "none_or_public"
    blob = json.dumps(r)
    assert verifier not in blob and ACC not in blob and "thecode123" not in blob


def test_oidc_pkce_loopback_fake_server(tmp_path):
    seen = {}

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            q = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(self.path).query))
            self.send_response(302)
            self.send_header("Location", f"{q['redirect_uri']}?code=c0de&state={q['state']}")
            self.end_headers()

        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            seen["body"] = dict(urllib.parse.parse_qsl(self.rfile.read(n).decode()))
            out = json.dumps({"access_token": ACC, "token_type": "Bearer"}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_port}"

    class NoRedir(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None

    opener = urllib.request.build_opener(NoRedir)
    verifier = "w" * 60
    url, state = _auth_url(base, verifier)
    entries = []
    try:
        try:
            opener.open(url)
        except urllib.error.HTTPError as e:
            entries.append(ent("GET", url, status=e.code, resp_h={"Location": e.headers["Location"]}))
        data = urllib.parse.urlencode({"grant_type": "authorization_code", "code": "c0de", "code_verifier": verifier}).encode()
        with opener.open(urllib.request.Request(base + "/token", data=data)) as resp:
            entries.append(ent("POST", base + "/token", mime="application/x-www-form-urlencoded",
                               body=data.decode(), resp_text=resp.read().decode()))
    finally:
        srv.shutdown()
    r = detect_auth_patterns(har(tmp_path, entries), kinds=["oidc_pkce"])["oidc_pkce"]
    f = r["flows"][0]
    assert f["state_roundtrip"] and f["token_exchange"]["verifier_matches_challenge"]
    assert f["token_exchange"]["code_matches_callback"]


def test_oidc_wrong_verifier(tmp_path):
    url, state = _auth_url("https://idp.test", "right" * 10)
    p = har(tmp_path, [
        ent("GET", url, status=302, resp_h={"Location": f"https://app.test/cb?code=k&state={state}"}),
        ent("POST", "https://idp.test/token", mime="application/x-www-form-urlencoded",
            body="grant_type=authorization_code&code=k&code_verifier=wrong", resp_text="{}"),
    ])
    f = detect_auth_patterns(p, kinds=["oidc_pkce"])["oidc_pkce"]["flows"][0]
    assert f["token_exchange"]["verifier_matches_challenge"] is False


def test_saml_post(tmp_path):
    xml = b'<samlp:AuthnRequest xmlns:samlp="u" ID="x"><ds:Signature/></samlp:AuthnRequest>'
    co = zlib.compressobj(wbits=-15)
    deflated = base64.b64encode(co.compress(xml) + co.flush()).decode()
    resp_xml = base64.b64encode(b"<saml2p:Response xmlns:saml2p='u'><saml2:EncryptedAssertion/></saml2p:Response>").decode()
    html = (f'<html><form method="post" action="https://sp.test/acs/saml"><input type="hidden" name="SAMLResponse" '
            f'value="{resp_xml}"/><input type="hidden" name="RelayState" value="rs1"/></form></html>')
    p = har(tmp_path, [
        ent("GET", "https://sp.test/login?SAMLRequest=" + urllib.parse.quote(deflated) + "&RelayState=r", status=302),
        ent("POST", "https://idp.test/sso", mime="application/x-www-form-urlencoded",
            body=urllib.parse.urlencode({"SAMLRequest": base64.b64encode(xml).decode(), "RelayState": "abc"}),
            status=200, resp_text=html, resp_mime="text/html"),
        ent("POST", "https://sp.test/acs/saml", mime="application/x-www-form-urlencoded",
            body=urllib.parse.urlencode({"SAMLResponse": resp_xml, "RelayState": "rs1"}), status=302,
            resp_h={"Location": "https://sp.test/home"}),
    ])
    r = detect_auth_patterns(p, kinds=["saml_post"])["saml_post"]
    by = {(m["direction"], m["message"]): m for m in r["messages"]}
    assert by[("redirect_binding_query", "SAMLRequest")]["payload"]["encoding"] == "base64+deflate"
    post = by[("request_form_post", "SAMLRequest")]
    assert post["payload"]["root"] == "AuthnRequest" and post["payload"]["signed"] and post["relay_state"]
    form = by[("auto_post_form_in_html", "SAMLResponse")]
    assert form["form_action_path"] == "/acs/saml" and form["payload"]["encrypted_assertion"]
    acs = by[("request_form_post", "SAMLResponse")]
    assert acs["redirect_after"] and acs["payload"]["root"] == "Response"
    assert resp_xml not in json.dumps(r)


def test_double_submit_csrf(tmp_path):
    tok = "csrf" + "k9Lm2Pq8" * 4
    p = har(tmp_path, [
        ent("GET", "https://api.test/", resp_h={"Set-Cookie": f"XSRF-TOKEN={tok}; Path=/; SameSite=Lax"}),
        ent("POST", "https://api.test/api/save", req_h={"Cookie": f"sid=abc; XSRF-TOKEN={tok}", "X-XSRF-TOKEN": tok},
            body='{"a":1}'),
        ent("PUT", "https://api.test/api/save", req_h={"Cookie": f"XSRF-TOKEN={tok}", "X-XSRF-TOKEN": tok},
            body='{"a":2}'),
        ent("GET", "https://api.test/api/x", req_h={"Cookie": "sid=abc", "X-Other": "short"}),
    ])
    r = detect_auth_patterns(p, kinds=["double_submit_csrf"])["double_submit_csrf"]
    assert r["detected"] and len(r["pairs"]) == 1
    pr = r["pairs"][0]
    assert (pr["cookie"], pr["header"], pr["count"]) == ("XSRF-TOKEN", "x-xsrf-token", 2)
    assert pr["cookie_set_by_entry"] == 0 and pr["cookie_http_only"] is False and pr["json_requests"] == 2
    assert tok not in json.dumps(r)


def test_signed_requests(tmp_path):
    es = []
    for i in range(3):
        sig = hashlib.sha256(f"s{i}".encode()).hexdigest()
        es.append(ent("POST", "https://api.test/v2/order", req_h={
            "X-Signature": sig, "X-Timestamp": str(1700000000 + i), "X-Nonce": f"n-{i}-abcdef"}, body="{}"))
    es.append(ent("GET", "https://api.test/v2/ping", req_h={
        "Authorization": "HMAC-SHA256 Credential=k1, Signature=" + "ab" * 32}))
    r = detect_auth_patterns(har(tmp_path, es), kinds=["signed_requests"])["signed_requests"]
    assert r["detected"] and len(r["groups"]) == 2
    g = next(x for x in r["groups"] if x["request_count"] == 3)
    assert g["signature_shape"] == "hex64" and g["timestamp_shape"] == "epoch_s"
    assert g["signature_varies_per_request"] and g["nonce_unique_per_request"]
    names = {f["name"] for f in g["fields"]}
    assert {"x-signature", "x-timestamp", "x-nonce"} == names
    assert any(x["auth_scheme"] == "HMAC-SHA256" for x in r["groups"])
    assert hashlib.sha256(b"s0").hexdigest() not in json.dumps(r)


def test_negative_and_host_filter(tmp_path):
    p = har(tmp_path, [ent("GET", "https://a.test/x", resp_text="{}")])
    r = detect_auth_patterns(p)
    assert r["detected"] == [] and r["entry_count"] == 1
    assert detect_auth_patterns(p, host="other.test")["entry_count"] == 0
