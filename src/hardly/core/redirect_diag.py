"""Diagnose redirect loops (the usual cause of ``ERR_TOO_MANY_RETRIES``).

A browser that gives up with ``ERR_TOO_MANY_RETRIES`` / ``ERR_TOO_MANY_REDIRECTS``
has almost always been bounced around a redirect loop. Typical causes are a bad
rewrite rule, an unexpected (non-canonical) domain such as ``www`` vs the apex
or ``http`` vs ``https``, a trailing-slash rule that fights another rule, or a
server that keeps redirecting until it sees a cookie it set on an earlier hop.

``diagnose_redirects`` follows the chain **by hand** with plain HTTP, once with a
cookie jar and once without, reports what repeats, and tries the obvious
alternate host. It is a few polite GETs against the URL that already failed.

Reported: statuses, redacted URLs, cookie *names* set. Never cookie values.
"""

from __future__ import annotations

import time
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx

from hardly.core.redact import redact_url

_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)
_MAX_REQUESTS = 40


def _norm(url: str) -> str:
    p = urlsplit(url)
    return urlunsplit((p.scheme.lower(), p.netloc.lower(), p.path or "/", p.query, ""))


def _follow(
    client: httpx.Client, start: str, *, max_hops: int, keep_cookies: bool, budget: list[int], delay_s: float
) -> dict[str, Any]:
    """Follow redirects manually; classify how the chain ended."""
    chain: list[dict[str, Any]] = []
    seen: dict[tuple[str, tuple[str, ...]], int] = {}
    url = start
    outcome = "too_many"
    for _ in range(max_hops):
        if budget[0] <= 0:
            outcome = "budget"
            break
        budget[0] -= 1
        # Cookies this request will carry: a repeat of (url, cookies sent) can
        # never end differently, but the same url with a new cookie can.
        sent_names = tuple(sorted({c.name for c in client.cookies.jar})) if keep_cookies else ()
        try:
            resp = client.get(url, follow_redirects=False)
        except httpx.HTTPError as exc:
            chain.append({"url": redact_url(url), "error": type(exc).__name__})
            outcome = "error"
            break
        set_names = sorted({k.split("=", 1)[0].strip() for k in resp.headers.get_list("set-cookie")})
        loc = resp.headers.get("location")
        chain.append(
            {
                "status": resp.status_code,
                "url": redact_url(url),
                **({"location": redact_url(urljoin(url, loc))} if loc else {}),
                **({"sets_cookies": [n for n in set_names if n]} if set_names else {}),
            }
        )
        if not (300 <= resp.status_code < 400 and loc):
            outcome = "ok" if resp.status_code < 400 else "http_error"
            break
        key = (_norm(url), sent_names)
        seen[key] = seen.get(key, 0) + 1
        if seen[key] >= 2:
            outcome = "loop"  # same URL again with the same cookies: it will never end
            break
        url = urljoin(url, loc)
        if not keep_cookies:
            client.cookies.clear()
        if delay_s:
            time.sleep(delay_s)
    return {"outcome": outcome, "hops": len(chain), "chain": chain}


def _flips(chain: list[dict[str, Any]]) -> list[str]:
    """Name the kind of back-and-forth the chain shows."""
    urls = [c["url"] for c in chain if "url" in c] + [c["location"] for c in chain if "location" in c]
    parts = [urlsplit(u) for u in urls]
    out: list[str] = []
    hosts = {p.netloc.lower() for p in parts}
    bare = {h[4:] if h.startswith("www.") else h for h in hosts}
    if len(hosts) > 1 and len(bare) < len(hosts):
        out.append("host_flip")  # www <-> apex
    if len({p.scheme for p in parts}) > 1:
        out.append("scheme_flip")  # http <-> https
    paths = {p.path.rstrip("/") for p in parts}
    if len(paths) == 1 and len({p.path for p in parts}) > 1:
        out.append("trailing_slash_flip")
    queries = [len(urlsplit(c["url"]).query) for c in chain if "url" in c]  # in request order
    if len(queries) >= 3 and queries[-1] > queries[0] and all(b >= a for a, b in zip(queries, queries[1:])):
        out.append("query_growth")  # e.g. a ReturnUrl nesting itself
    return out


def _variants(url: str) -> list[str]:
    p = urlsplit(url)
    host = p.netloc
    alt_host = host[4:] if host.lower().startswith("www.") else f"www.{host}"
    out = [urlunsplit((p.scheme, alt_host, p.path or "/", p.query, ""))]
    if p.scheme == "http":
        out.append(urlunsplit(("https", host, p.path or "/", p.query, "")))
    return out


def diagnose_redirects(
    url: str,
    *,
    client: httpx.Client | None = None,
    max_hops: int = 12,
    timeout_s: float = 10.0,
    delay_s: float = 0.3,
    probe_variants: bool = True,
) -> dict[str, Any]:
    """Explain why a URL bounces: loop shape, cookie dependence, better host."""
    budget = [_MAX_REQUESTS]
    own = client is None
    http = client or httpx.Client(headers={"User-Agent": _UA}, timeout=timeout_s)
    try:
        with_jar = _follow(http, url, max_hops=max_hops, keep_cookies=True, budget=budget, delay_s=delay_s)
        http.cookies.clear()
        no_jar = _follow(http, url, max_hops=max_hops, keep_cookies=False, budget=budget, delay_s=delay_s)
        http.cookies.clear()

        findings: list[str] = []
        flips = _flips(with_jar["chain"])
        looping = with_jar["outcome"] in {"loop", "too_many"}
        if with_jar["outcome"] == "ok" and no_jar["outcome"] in {"loop", "too_many"}:
            sets = sorted({n for c in with_jar["chain"] for n in c.get("sets_cookies", [])})
            findings.append(
                "The redirect chain only ends when a cookie set on an earlier hop is sent back"
                + (f" (cookies set: {', '.join(sets)})" if sets else "")
                + ". Use a client with a cookie jar and start from the page that sets it; "
                "a first visit without cookies loops."
            )
        elif looping and no_jar["outcome"] in {"loop", "too_many"}:
            findings.append("The chain loops with and without cookies: a server-side rewrite/redirect rule problem, not a cookie issue.")
        elif with_jar["outcome"] == "ok":
            findings.append("The chain ends normally with plain HTTP; the browser failure may be transient or specific to the browser.")
        if "host_flip" in flips:
            findings.append("Hops alternate between www and the apex host: the site expects one canonical host. Use the one it redirects to as the start URL.")
        if "scheme_flip" in flips:
            findings.append("Hops alternate between http and https: a proxy/CDN scheme rule conflicts with the origin. Prefer the https URL and check for a TLS-terminating proxy.")
        if "trailing_slash_flip" in flips:
            findings.append("The same path alternates with and without a trailing slash: two rewrite rules disagree. Try the other form.")
        if "query_growth" in flips:
            findings.append("The query string grows on every hop (a return/redirect parameter nesting itself): an authentication or locale redirect is stuck.")

        variants: list[dict[str, Any]] = []
        if probe_variants and looping:
            for v in _variants(url):
                if budget[0] <= 0:
                    break
                r = _follow(http, v, max_hops=max_hops, keep_cookies=True, budget=budget, delay_s=delay_s)
                http.cookies.clear()
                final = r["chain"][-1] if r["chain"] else {}
                variants.append(
                    {"url": redact_url(v), "outcome": r["outcome"], "final_status": final.get("status"), "hops": r["hops"]}
                )
            good = [v for v in variants if v["outcome"] == "ok"]
            if good:
                findings.append(f"This variant resolves normally: {good[0]['url']} — the original host/scheme is likely not the one the site expects.")
            elif variants:
                findings.append("The obvious alternate host/scheme variants also fail; check for a rewrite rule, a login redirect, or a bot/geo rule keyed on the request.")

        return {
            "url": redact_url(url),
            "outcome": with_jar["outcome"],
            "with_cookies": with_jar,
            "without_cookies": {"outcome": no_jar["outcome"], "hops": no_jar["hops"]},
            "shape": flips,
            "variants": variants,
            "findings": findings,
            "requests_used": _MAX_REQUESTS - budget[0],
        }
    finally:
        if own:
            http.close()
