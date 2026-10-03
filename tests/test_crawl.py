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
    kw.setdefault("explain", True)
    out = C.crawl("https://a.test/", kw.pop("keywords", ("gadget",)), client=site(routes, seen), **kw)
    return out, seen


def test_landing_services_lookup_form():
    out, seen = run({"/": LANDING, "/services": SERVICES, "/gadget-lookup": LOOKUP})
    assert out["pages_fetched"] >= 3  # zero-score same-site links are walked after the scored ones
    top = out["candidates"][0]
    assert top["url"].endswith("/gadget-lookup") and top["looks_like_search"]
    lookup = [p for p in out["pages"] if p["url"].endswith("/gadget-lookup")][0]
    assert {"gadget_id", "owner"} <= set(lookup["forms"][0]["fields"])
    assert lookup["forms"][0]["looks_like_search"] and lookup["depth"] == 2
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
    assert any("capture-discover" in n for n in out["next"])


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
    linked = {"/", "/robots.txt", "/services", "/gadget-lookup", "/about", "/login", "/news", "/gadget-results"}
    assert all(httpx.URL(u).path in linked for u in seen)  # only paths that appear as links


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


# --- honest UA, robots 403, zero-score links, external links, delay report ---


def _ua_site(routes, uas):
    def handler(request: httpx.Request) -> httpx.Response:
        uas.append(request.headers.get("user-agent", ""))
        r = routes.get(request.url.path)
        if r:
            return httpx.Response(r[0], headers=r[1], text=r[2])
        return httpx.Response(404, headers=HTML, text="x")

    return httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)


def test_default_user_agent_is_honest_and_browser_opt_in():
    uas: list[str] = []
    out = C.crawl("https://a.test/", delay_s=0, depth=0, client=_ua_site({"/": LANDING}, uas))
    assert uas and all(u.startswith("hardly/") and "Mozilla" not in u for u in uas)
    assert out["limits"]["user_agent"] == uas[0]
    uas.clear()
    C.crawl("https://a.test/", delay_s=0, depth=0, user_agent="browser", client=_ua_site({"/": LANDING}, uas))
    assert all(u.startswith("Mozilla/5.0") for u in uas)
    uas.clear()
    C.crawl("https://a.test/", delay_s=0, depth=0, user_agent="my-bot/1", client=_ua_site({"/": LANDING}, uas))
    assert set(uas) == {"my-bot/1"}


def test_robots_403_is_disallow_all_and_reported():
    routes = {"/robots.txt": (403, HTML, "forbidden"), "/": LANDING}
    out, seen = run(routes)
    assert out["pages_fetched"] == 0
    assert out["robots"][0]["status"] == 403 and out["robots"][0]["policy"] == "forbidden_disallow_all"
    assert any("403" in n for n in out["next"])
    assert not any(u.endswith("/services") for u in seen)


def test_robots_404_allows_all():
    out, _ = run({"/robots.txt": (404, HTML, "nf"), "/": LANDING, "/services": SERVICES})
    assert out["pages_fetched"] >= 2 and out["robots"][0]["policy"] == "missing_allow_all"


def test_effective_robots_delay_reported():
    routes = {"/robots.txt": (200, {"content-type": "text/plain"}, "User-agent: *\nCrawl-delay: 4\n"), "/": LANDING}
    C._sleep, old = (lambda s: None), C._sleep
    try:
        out, _ = run(routes, depth=0)
    finally:
        C._sleep = old
    row = out["robots"][0]
    assert row["crawl_delay_s"] == 4.0 and row["effective_delay_s"] == 4.0


def test_walks_through_zero_score_links_and_lists_all_external():
    hub = page("Hub", '<a href="/misc">Misc</a><a href="https://other.test/x">Partner</a>'
                      '<a href="https://third.test/y">Third</a><a href="/logout">Log out</a>')
    misc = page("Misc", '<a href="/gadget-lookup">Gadget Lookup</a>')
    out, seen = run({"/": hub, "/misc": misc, "/gadget-lookup": LOOKUP}, depth=2)
    assert out["candidates"][0]["url"].endswith("/gadget-lookup")
    assert not any("/logout" in u for u in seen)
    assert {r["host"] for r in out["external_links"]} == {"other.test", "third.test"}
    assert out["external_links_total"] == 2


def test_external_links_listed_at_max_depth_and_over_30():
    links = "".join(f'<a href="https://h{i}.test/p">Site {i}</a>' for i in range(45))
    out, _ = run({"/": page("Home", links)}, depth=0)
    assert out["external_links_total"] == 45 and len(out["external_links"]) == 45


def test_looks_like_search_consistent_page_and_form():
    f = ('<form action="/r"><input name="gadget_id"><input name="owner"></form>'
         '<form action="/s"><input name="q"></form>')
    out, _ = run({"/": page("Home", f)}, depth=0)
    p = out["pages"][0]
    assert p["looks_like_search"] is True
    assert [x["looks_like_search"] for x in p["forms"]] == [True, False]
    assert out["candidates"][0]["looks_like_search"] is True


def test_stack_drops_low_confidence():
    got = C._stack(200, {}, '<div id="root"></div>', "https://a.test/")
    assert "React" not in got


def test_next_advice_only_with_explain():
    routes = {"/": LANDING}
    out, _ = run(routes, explain=False)
    assert "next" not in out
    out, _ = run(routes, explain=True)
    assert isinstance(out["next"], list)
