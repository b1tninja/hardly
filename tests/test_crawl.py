"""hardly.core.crawl against httpx.MockTransport sites (no live network)."""

from __future__ import annotations

import json

import httpx

from hardly.core import crawl as C

HTML = {"content-type": "text/html; charset=utf-8"}


def site(routes: dict[str, tuple], seen: list[str] | None = None):
    """routes: 'host/path' or '/path' (any host) -> (status, headers, body)."""

    def handler(request: httpx.Request) -> httpx.Response:
        url = request.url
        if seen is not None:
            seen.append(str(url))
        for key in (f"{url.host}{url.path}", url.path):
            if key in routes:
                status, headers, body = routes[key]
                return httpx.Response(status, headers=headers, text=body)
        return httpx.Response(404, headers=HTML, text="<html><title>nf</title></html>")

    return httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)


def page(title: str, body: str) -> tuple:
    return 200, HTML, f"<html><head><title>{title}</title></head><body>{body}</body></html>"


LANDING = page("Home", '<a href="/services">Online Services</a><a href="/about">About</a>'
                        '<a href="/login">Sign in</a>')
SERVICES = page("Services", '<a href="/gadget-lookup">Gadget Lookup</a><a href="/news">News</a>')
LOOKUP = page(
    "Gadget Lookup",
    '<form action="/gadget-results" method="get"><input name="gadget_id"><input name="owner">'
    '<input type="submit" value="Go"></form>',
)


def run(routes, **kw):
    seen: list[str] = []
    kw.setdefault("delay_s", 0)
    out = C.crawl("https://a.test/", kw.pop("keywords", ("gadget",)), client=site(routes, seen), **kw)
    return out, seen


def test_landing_services_lookup_form():
    out, seen = run({"/": LANDING, "/services": SERVICES, "/gadget-lookup": LOOKUP})
    assert out["pages_fetched"] == 3
    top = out["candidates"][0]
    assert top["url"].endswith("/gadget-lookup") and top["looks_like_search"]
    lookup = [p for p in out["pages"] if p["url"].endswith("/gadget-lookup")][0]
    assert {"gadget_id", "owner"} <= set(lookup["forms"][0]["fields"])
    assert lookup["forms"][0]["looks_like_search"] and lookup["depth"] == 2
    assert not any("/login" in u or "/about" in u for u in seen)
    assert "<html" not in json.dumps(out)


def test_deterministic():
    routes = {"/": LANDING, "/services": SERVICES, "/gadget-lookup": LOOKUP}
    assert run(routes)[0] == run(routes)[0]


def test_robots_disallow():
    routes = {
        "/robots.txt": (200, {"content-type": "text/plain"}, "User-agent: *\nDisallow: /gadget-lookup\n"),
        "/": LANDING, "/services": SERVICES, "/gadget-lookup": LOOKUP,
    }
    out, seen = run(routes)
    assert any(u.endswith("/gadget-lookup") for u in out["robots_disallowed"])
    assert not any(u.endswith("/gadget-lookup") for u in seen)
    assert sum(u.endswith("/robots.txt") for u in seen) == 1
    out2, seen2 = run(routes, respect_robots=False)
    assert any(u.endswith("/gadget-lookup") for u in seen2) and not out2["robots_disallowed"]


def test_external_not_followed_by_default_then_one_hop():
    home = page("Home", '<a href="https://other.test/gadget-search">Gadget Search</a>'
                        '<a href="/svc">Gadget Services</a>')
    routes = {
        "/": home, "/svc": page("Svc", "<p>x</p>"),
        "other.test/gadget-search": page(
            "Ext", '<a href="https://third.test/gadget-lookup">Gadget Lookup</a>'
        ),
        "third.test/gadget-lookup": page("Third", "x"),
    }
    out, seen = run(routes)
    assert not any("other.test" in u for u in seen)
    assert out["external_links"][0]["host"] == "other.test" and not out["external_links"][0]["fetched"]
    out, seen = run(routes, follow_external=True)
    assert any("other.test/gadget-search" in u for u in seen)
    assert not any("third.test" in u for u in seen)  # one hop only
    assert out["external_links"][0]["fetched"]
    assert [p for p in out["pages"] if p.get("external_hop")]


def test_gate_page_not_followed_nor_retried():
    wall = (200, HTML, "<html><title>Just a moment</title><body>Just a moment... "
                       '<div class="g-recaptcha"></div><a href="/gadget-lookup">Gadget Lookup</a></body></html>')
    routes = {"/": LANDING, "/services": wall, "/gadget-lookup": LOOKUP}
    out, seen = run(routes)
    assert out["blocked"] and out["blocked"][0]["url"].endswith("/services")
    assert not any(u.endswith("/gadget-lookup") for u in seen)
    assert sum(u.endswith("/services") for u in seen) == 1
    assert any("interactive" in n for n in out["next"])


def test_environment_blocked_reported_separately(monkeypatch):
    monkeypatch.setattr(
        C, "_classify_response",
        lambda s, h, b, u="": [{"class": "environment_blocked", "action": "unknown_rerun"}]
        if "blocked" in b else [],
    )
    routes = {"/": LANDING, "/services": (403, HTML, "blocked by egress policy")}
    out, _ = run(routes)
    assert out["environment_blocked"] and not out["blocked"]


def test_429_halts_host():
    seen: list[str] = []
    routes = {
        "/": page("Home", '<a href="/gadget-a">Gadget Search A</a><a href="/gadget-b">Gadget Search B</a>'),
        "/gadget-a": (429, {**HTML, "retry-after": "120"}, "slow down"),
        "/gadget-b": LOOKUP,
    }
    out = C.crawl("https://a.test/", ("gadget",), delay_s=0, client=site(routes, seen))
    assert out["halted_hosts"] == [{"host": "a.test", "reason": "429"}]
    assert not any(u.endswith("/gadget-b") for u in seen)
    assert out["blocked"][0]["class"] == "rate_limit"


def test_session_ids_stripped_and_deduped():
    home = page("Home", '<a href="/gadget-lookup;jsessionid=ABC123SECRET">Gadget Lookup</a>'
                        '<a href="/gadget-lookup?sid=ZZ99SECRET">Gadget Lookup Again</a>'
                        '<a href="/gadget-lookup">Gadget Lookup</a>')
    out, seen = run({"/": home, "/gadget-lookup": LOOKUP})
    assert sum("/gadget-lookup" in u for u in seen) == 1
    blob = json.dumps(out) + " ".join(seen)
    assert "ABC123SECRET" not in blob and "ZZ99SECRET" not in blob


def test_id_paths_dedupe():
    home = page("Home", "".join(f'<a href="/gadget-records/{i}">Gadget Record</a>' for i in (1, 2, 3)))
    out, seen = run({"/": home})
    assert sum("/gadget-records/" in u for u in seen) == 1


def test_spa_shell_needs_browser():
    spa = (200, HTML, '<html><head><title>App</title></head><body><div id="root"></div>'
                      '<script src="/app.js"></script></body></html>')
    home = page("Home", '<a href="/gadget-app">Gadget Search App</a>')
    out, _ = run({"/": home, "/gadget-app": spa})
    assert out["needs_browser"] and out["needs_browser"][0].endswith("/gadget-app")
    assert any("capture discover" in n for n in out["next"])


def test_caps():
    links = "".join(f'<a href="/gadget-lookup-x{i}">Gadget Lookup {chr(97 + i)}</a>' for i in range(8))
    routes = {"/": page("Home", links)}
    for i in range(8):
        routes[f"/gadget-lookup-x{i}"] = page("p", f'<a href="/gadget-deep-{i}">Gadget Lookup deep {chr(97 + i)}</a>')
    out, _ = run(routes, max_pages=4)
    assert out["pages_fetched"] == 4
    out, _ = run(routes, max_pages=500, depth=99)
    assert out["limits"]["max_pages"] == 40 and out["limits"]["depth"] == 4
    out, _ = run(routes, depth=0)
    assert out["pages_fetched"] == 1
    out, _ = run(routes, depth=1)
    assert max(p["depth"] for p in out["pages"]) == 1


def test_no_hostnames_guessed():
    seen: list[str] = []
    routes = {"/": LANDING, "/services": SERVICES, "/gadget-lookup": LOOKUP}
    C.crawl("https://a.test/", ("gadget",), delay_s=0, client=site(routes, seen))
    assert {httpx.URL(u).host for u in seen} == {"a.test"}
    assert all(httpx.URL(u).path in {"/", "/robots.txt", "/services", "/gadget-lookup"} for u in seen)


def test_redaction_of_secret_query_values():
    home = page("Home", '<a href="/gadget-lookup?token=TOPSECRETVAL&x=1">Gadget Lookup</a>')
    seen: list[str] = []
    out = C.crawl(
        "https://a.test/?api_key=STARTSECRET", ("gadget",), delay_s=0,
        client=site({"/": home, "/gadget-lookup": LOOKUP}, seen),
    )
    blob = json.dumps(out)
    assert "TOPSECRETVAL" not in blob and "STARTSECRET" not in blob
    assert "TOPSECRETVAL" not in " ".join(seen)  # never re-sent from a redacted link


def test_redirect_chain_and_leaving_site():
    routes = {
        "/": page("Home", '<a href="/gadget-old">Gadget Lookup</a><a href="/gadget-away">Gadget Search</a>'),
        "/gadget-old": (301, {"location": "/gadget-new"}, ""),
        "/gadget-new": LOOKUP,
        "/gadget-away": (302, {"location": "https://elsewhere.test/x"}, ""),
    }
    out, seen = run(routes)
    old = [p for p in out["pages"] if p["url"].endswith("/gadget-old")][0]
    assert old["redirect_chain"] == [301, 200] and old["final_url"].endswith("/gadget-new")
    assert not any("elsewhere.test" in u for u in seen)


def test_transient_error_retried_once():
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/robots.txt":
            return httpx.Response(404)
        calls["n"] += 1
        raise httpx.ConnectError("boom")

    out = C.crawl("https://a.test/", delay_s=0, client=httpx.Client(transport=httpx.MockTransport(handler)))
    assert calls["n"] == 2 and out["errors"][0]["error"] == "ConnectError" and out["pages_fetched"] == 0


def test_bad_start_url():
    assert "error" in C.crawl("ftp://x.test/")
