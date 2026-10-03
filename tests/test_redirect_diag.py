"""Redirect-loop diagnosis (the usual cause of ERR_TOO_MANY_RETRIES)."""

import httpx

from hardly.core.redirect_diag import diagnose_redirects

SECRET = "SESSIONSECRET123"


def _client(handler):
    return httpx.Client(transport=httpx.MockTransport(handler), headers={"User-Agent": "t"})


def test_www_apex_flip_loop_and_working_variant():
    def handler(req):
        host = req.url.host
        if host == "example.org":
            return httpx.Response(301, headers={"location": "https://www.example.org/"})
        if host == "www.example.org" and req.url.path == "/":
            return httpx.Response(301, headers={"location": "https://example.org/"})
        return httpx.Response(200, text="ok")

    out = diagnose_redirects("https://example.org/", client=_client(handler), delay_s=0)
    assert out["outcome"] == "loop" and "host_flip" in out["shape"]
    # the loop is on "/" for both hosts, so the variant also loops; findings say so
    assert any("www and the apex" in f for f in out["findings"])
    assert out["requests_used"] <= 40


def test_variant_that_resolves_is_suggested():
    def handler(req):
        if req.url.host == "example.org":
            return httpx.Response(302, headers={"location": "https://example.org/x"}) if req.url.path != "/x" else httpx.Response(302, headers={"location": "https://example.org/"})
        return httpx.Response(200, text="fine")  # www host works

    out = diagnose_redirects("https://example.org/", client=_client(handler), delay_s=0)
    assert out["outcome"] == "loop"
    assert out["variants"] and out["variants"][0]["outcome"] == "ok"
    assert any("www.example.org" in f and "resolves" in f for f in out["findings"])


def test_cookie_dependent_chain_needs_a_jar_and_never_leaks_values():
    def handler(req):
        if "sid" in req.headers.get("cookie", ""):
            return httpx.Response(200, text="hello")
        return httpx.Response(302, headers={"location": str(req.url), "set-cookie": f"sid={SECRET}; Path=/"})

    out = diagnose_redirects("https://example.org/start", client=_client(handler), delay_s=0)
    assert out["outcome"] == "ok" and out["without_cookies"]["outcome"] in {"loop", "too_many"}
    assert any("cookie" in f.lower() and "sid" in f for f in out["findings"])
    assert SECRET not in str(out)


def test_trailing_slash_fight_and_query_growth():
    def slash(req):
        if req.url.path.endswith("/"):
            return httpx.Response(301, headers={"location": req.url.path.rstrip("/")})
        return httpx.Response(301, headers={"location": req.url.path + "/"})

    out = diagnose_redirects("https://example.org/a", client=_client(slash), delay_s=0, probe_variants=False)
    assert out["outcome"] == "loop" and "trailing_slash_flip" in out["shape"]

    def grow(req):
        return httpx.Response(302, headers={"location": f"/login?ReturnUrl={req.url.query.decode() or 'x'}x"})

    out = diagnose_redirects("https://example.org/p", client=_client(grow), delay_s=0, probe_variants=False, max_hops=6)
    assert "query_growth" in out["shape"]


def test_plain_single_redirect_is_ok_and_secret_query_values_are_redacted():
    def handler(req):
        if req.url.path == "/old":
            return httpx.Response(301, headers={"location": "/new?code=AUTHCODE9&lang=en"})
        return httpx.Response(200, text="ok")

    out = diagnose_redirects("https://example.org/old", client=_client(handler), delay_s=0)
    assert out["outcome"] == "ok" and out["with_cookies"]["hops"] == 2
    assert "AUTHCODE9" not in str(out) and "lang=en" in str(out)
    assert any("transient" in f or "ends normally" in f for f in out["findings"])


def test_request_cap():
    calls = []

    def handler(req):
        calls.append(1)
        return httpx.Response(302, headers={"location": f"/{len(calls)}"})  # never repeats

    out = diagnose_redirects("https://example.org/", client=_client(handler), delay_s=0, max_hops=50)
    assert out["requests_used"] <= 40 and len(calls) <= 40
