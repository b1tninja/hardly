"""Gate taxonomy, session aggregation and wall/brief/challenges integration."""

import json

from hardly import session as sess
from hardly.core.botwalls import detect_bot_protection
from hardly.core.challenges import detect_challenges
from hardly.core.gates import POLICY, classify_gates, classify_response
from hardly.core.wall import detect_walls
from tests.test_botwalls import _entry, _open


def classes(gates):
    return {g["class"] for g in gates}


def by_class(gates, cls):
    return next(g for g in gates if g["class"] == cls)


# --- single responses --------------------------------------------------------


def test_environment_blocked_header_never_site_wall():
    gates = classify_response(
        403, {"X-Deny-Reason": "host_not_allowed"}, "<html>Access denied. Request blocked.</html>", "x.example/"
    )
    assert classes(gates) == {"environment_blocked"}
    g = gates[0]
    assert g["action"] == "unknown_rerun" and "header:x-deny-reason" in g["evidence"]


def test_environment_blocked_any_deny_reason_value():
    assert classes(classify_response(403, {"x-deny-reason": "other"}, "")) == {"environment_blocked"}


def test_environment_blocked_proxy_style():
    gates = classify_response(502, {"Via": "1.1 squid", "Server": "squid"}, "proxy error")
    assert classes(gates) == {"environment_blocked"}
    gates = classify_response(403, {}, "Connection blocked by proxy: host not allowed")
    assert classes(gates) == {"environment_blocked"}


def test_plain_403_is_not_environment():
    assert "environment_blocked" not in classes(classify_response(403, {}, "forbidden"))


def test_site_waf_with_via_is_not_environment():
    gates = classify_response(
        403, {"Server": "cloudflare", "CF-RAY": "1-LAX", "Via": "1.1 proxy"}, "<title>Just a moment...</title>"
    )
    assert "environment_blocked" not in classes(gates) and "bot_wall" in classes(gates)


def test_bot_wall_vendors():
    g = classify_response(403, {"Server": "cloudflare", "cf-mitigated": "challenge"}, "Just a moment...")
    assert by_class(g, "bot_wall")["vendor"] == "cloudflare" and by_class(g, "bot_wall")["action"] == "stop"


def test_azure_header_informational_only():
    assert classify_response(403, {"x-azure-ref": "0ABC"}, "<html>Forbidden</html>") == [] or \
        "bot_wall" not in classes(classify_response(403, {"x-azure-ref": "0ABC"}, "Forbidden"))
    assert classify_response(200, {"x-azure-ref": "0ABC"}, "ok") == []
    g = classify_response(403, {"x-azure-ref": "0ABC"}, "<h1>The request is blocked.</h1>")
    assert by_class(g, "bot_wall")["vendor"] == "azure-front-door"


def test_f5_rejected_and_tspd():
    g = classify_response(
        200, {"Server": "volt-adc"}, "<html>The requested URL was rejected. Please consult with your administrator. "
        "Your support ID is: 12345</html>"
    )
    assert by_class(g, "bot_wall")["vendor"] == "f5"
    g = classify_response(403, {"Set-Cookie": "TSPD_101=SECRETVALUE; Path=/"}, "Request Rejected")
    assert by_class(g, "bot_wall")["vendor"] == "f5"
    assert "SECRETVALUE" not in json.dumps(g)


def test_aws_waf_202_challenge():
    g = classify_response(202, {"x-amzn-waf-action": "challenge"}, "")
    assert by_class(g, "bot_wall")["vendor"] == "aws-waf"
    assert "header:x-amzn-waf-action=challenge" in by_class(g, "bot_wall")["evidence"]


def test_imperva_503_block():
    g = classify_response(503, {"X-Iinfo": "1-2-3"}, "Request unsuccessful. Incapsula incident ID: 123")
    assert by_class(g, "bot_wall")["vendor"] == "imperva"


def test_app_rate_limit():
    g = classify_response(429, {"Retry-After": "30"}, "Too many requests in the past minute")
    r = by_class(g, "rate_limit")
    assert r["vendor"] == "app-rate-limit" and r["action"] == "stop"
    g = classify_response(302, {"Location": "/challenge?next=/x"}, "")
    assert "bot_wall" in classes(g)


def test_rate_limit_lockout_wording():
    assert "rate_limit" in classes(classify_response(200, {}, "Too many login attempts. Try again in 15 minutes."))
    assert "rate_limit" in classes(classify_response(429, {}, ""))


def test_captcha_and_pow_and_waiting_room():
    html = '<div class="g-recaptcha" data-sitekey="K"></div><script src="https://www.google.com/recaptcha/api.js"></script>'
    assert "captcha" in classes(classify_response(200, {}, html))
    pow_ = classify_response(200, {}, "<title>Making sure you're not a bot</title>"
                             "<script src='/.within.website/x/cmd/anubis/static/js/main.mjs'></script>")
    assert "proof_of_work" in classes(pow_)
    wr = classify_response(200, {"x-queueit-connector": "1"}, "<html>queue</html>")
    assert "waiting_room" in classes(wr)


def test_click_through_terms_accept():
    html = ('<form method="post" action="/accept"><h1>Disclaimer</h1><p>By using this site you agree to the terms.</p>'
            '<input type="submit" name="accept" value="I Agree"></form>')
    g = by_class(classify_response(200, {}, html, "https://x.example/disclaimer"), "click_through_terms")
    assert g["action"] == "accept_click_through"


def test_click_through_path_only():
    html = '<form method="post"><button type="submit">Accept</button></form>'
    g = classify_response(200, {}, html, "https://x.example/termaccept.aspx")
    assert by_class(g, "click_through_terms")["action"] == "accept_click_through"


def test_click_through_forbidding_automation_is_stop():
    html = ('<form method="post"><p>Terms of use: automated access, scraping and robots are prohibited.</p>'
            '<input type="submit" value="I Accept"></form>')
    g = by_class(classify_response(200, {}, html, "https://x.example/tos"), "click_through_terms")
    assert g["action"] == "stop" and "terms:forbid-automation" in g["evidence"]


def test_login_and_401():
    g = classify_response(200, {}, '<form><input type="password" name="pw"></form>')
    assert by_class(g, "login")["action"] == "stop"
    g = classify_response(401, {"WWW-Authenticate": 'Basic realm="r"'}, "")
    assert "scheme:basic" in by_class(g, "login")["evidence"]


def test_paywall():
    for text in ("Access costs $20 a day", "Plans start at $50 per month", "Purchase a pass to continue",
                 "Pricing: $1.50 per page"):
        assert "paywall" in classes(classify_response(200, {}, text)), text
    assert "paywall" in classes(classify_response(402, {}, ""))
    assert "paywall" not in classes(classify_response(200, {}, "Subscribe to our newsletter"))


def test_clean_page_has_no_gates():
    assert classify_response(200, {"Content-Type": "text/html"}, "<h1>Hello</h1>") == []


def test_policy_shape():
    assert "click_through_terms" not in POLICY["stop_classes"]
    assert "environment_blocked" in POLICY["unknown_classes"]


# --- session level -------------------------------------------------------------


def test_classify_gates_session_and_no_leak(tmp_path, monkeypatch):
    conn, har = _open(tmp_path, monkeypatch, [
        _entry(1, "https://a.example.com/", status=403, resp_headers={"x-deny-reason": "host_not_allowed"},
               body="Access denied"),
        _entry(2, "https://b.example.com/", status=403,
               resp_headers={"Server": "cloudflare", "cf-mitigated": "challenge"}, set_cookies=["__cf_bm"],
               body="<title>Just a moment...</title>"),
        _entry(3, "https://b.example.com/disclaimer", body=(
            '<form method="post"><p>Disclaimer. I agree to the terms.</p><input type="submit" value="I Agree"></form>')),
        _entry(4, "https://b.example.com/signin", body='<input type="password" name="pw">'),
    ])
    out = classify_gates(conn)
    assert {"environment_blocked", "bot_wall", "click_through_terms", "login"} <= set(out["by_class"])
    env = out["environment_blocked"]
    assert env["detected"] and env["entry_ids"] == [0]
    assert "re-run from another network" in env["verdict"]
    bw = [g for g in out["gates"] if g["class"] == "bot_wall"]
    assert all(0 not in g["entry_ids"] for g in bw)
    assert "SECRETVALUE" not in json.dumps(out)

    walls = detect_walls(conn)
    assert walls["environment_blocked"]["detected"]
    assert all(h["entry_id"] != 0 for h in walls["hits"])
    assert any(g["class"] == "click_through_terms" for g in walls["gates"])


def test_environment_only_session_not_walled(tmp_path, monkeypatch):
    conn, har = _open(tmp_path, monkeypatch, [
        _entry(1, "https://a.example.com/", status=403, resp_headers={"x-deny-reason": "host_not_allowed"},
               body="Access denied. Request blocked."),
    ])
    walls = detect_walls(conn, explain=True)
    assert walls["hit_count"] == 0 and walls["blocking"] == []
    assert walls["environment_blocked"]["detected"]
    assert "Not a site wall" in walls["next"]


def test_brief_prints_gate_summary(tmp_path, monkeypatch):
    from hardly.core.brief import portal_brief

    conn, har = _open(tmp_path, monkeypatch, [
        _entry(1, "https://a.example.com/signin", body='<input type="password" name="pw">'),
    ])
    out = portal_brief(conn, host="a.example.com")
    assert out["gates"]["by_class"].get("login") == 1
    assert out["gates"]["by_action"].get("stop") == 1
    assert "walls" in out


def test_azure_catalog_state(tmp_path, monkeypatch):
    conn, har = _open(tmp_path, monkeypatch, [
        _entry(1, "https://a.example.com/", status=403, resp_headers={"x-azure-ref": "0ABC"}, body="Forbidden"),
    ])
    out = detect_bot_protection(conn, har_path=har)
    az = next(v for v in out["vendors"] if v["id"] == "azure-front-door")
    assert az["state"] == "present"


# --- challenges: sitekeys + token endpoints ----------------------------------


def test_captcha_sitekeys_and_token_endpoints(tmp_path, monkeypatch):
    conn, har = _open(tmp_path, monkeypatch, [
        _entry(1, "https://app.example.com/signin", body=(
            '<div class="g-recaptcha" data-sitekey="PUBLICSITEKEY123456789"></div>'
            '<script src="https://www.google.com/recaptcha/api.js"></script>')),
    ])
    # a POST carrying a token field
    post = _entry(2, "https://app.example.com/api/verify?cf-turnstile-response=TOKENQUERYVALUE")
    post["request"]["method"] = "POST"
    post["request"]["postData"] = {
        "mimeType": "application/x-www-form-urlencoded",
        "text": "g-recaptcha-response=TOKENBODYVALUE&user=bob",
    }
    path = tmp_path / "t.har"
    path.write_text(json.dumps({"log": {"version": "1.2", "creator": {"name": "t", "version": "1"},
                                        "entries": [_entry(1, "https://app.example.com/signin", body=(
                                            '<div class="g-recaptcha" data-sitekey="PUBLICSITEKEY123456789"></div>'
                                            '<script src="https://www.google.com/recaptcha/api.js"></script>')), post]}}))
    info = sess.open_har(str(path), force=True)
    out = detect_challenges(sess.require_conn(info["session_id"]))
    cap = next(c for c in out["captcha_widgets"] if c["name"] == "recaptcha")
    assert cap["sitekeys"] and len(cap["sitekeys"]) <= 3
    assert all(len(k) <= 15 for k in cap["sitekeys"])
    fields = {t["field"] for t in out["token_endpoints"]}
    assert fields & {"g-recaptcha-response", "cf-turnstile-response"}
    t = out["token_endpoints"][0]
    assert {"entry_id", "method", "path", "field"} <= set(t) and t["method"] == "POST"
    blob = json.dumps(out)
    assert "TOKENBODYVALUE" not in blob and "TOKENQUERYVALUE" not in blob
