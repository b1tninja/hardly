"""Curl-first, robots-aware, polite crawl that finds candidate pages.

Plain HTTP usually works where headless Chromium is blocked, and most useful
facts live in static HTML, so this walks links found in fetched HTML (never
guessed hostnames or paths), ranks them with ``search_nav`` and reports small,
redacted per-page facts. Content-neutral: callers pass domain ``keywords``.

Live GETs: callers (MCP / CLI) must gate this behind an explicit confirm.
"""

from __future__ import annotations

import re
import time
import urllib.robotparser
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

import httpx

from hardly.core.grids import html_grid_signals
from hardly.core.redact import REDACTED, redact_url
from hardly.core.search_nav import page_candidates, score_link, search_form_reached
from hardly.core.urls import path_template

try:  # optional sibling modules; degrade gracefully when absent
    from hardly.core.gates import classify_response as _classify_response
except ImportError:  # pragma: no cover - depends on sibling branch
    _classify_response = None
try:
    from hardly.core.stack import fingerprint_response as _fingerprint_response
except ImportError:  # pragma: no cover
    _fingerprint_response = None

MAX_PAGES_HARD = 40
MAX_DEPTH_HARD = 4
MAX_REDIRECTS = 5
_LINKS_PER_PAGE = 60
_MAX_BODY_CHARS = 400_000
_STOP_ACTIONS = frozenset({"stop", "unknown_rerun"})
from hardly import __version__ as _VERSION

# Honest by default: the crawler says what it is. ``user_agent="browser"`` opts
# into a browser-like string (only where the site's terms allow it).
HONEST_USER_AGENT = f"hardly/{_VERSION} (+https://github.com/b1tninja/hardly; polite HAR-analysis crawler)"
BROWSER_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)
_USER_AGENT = HONEST_USER_AGENT  # back-compat alias
_ACCEPT = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}
_HEADERS = {"User-Agent": HONEST_USER_AGENT, **_ACCEPT}
_MAX_EXTERNAL_ROWS = 500
_AVOID_LINK_RE = re.compile(r"log-?out|sign-?out|signoff|/delete\b|/remove\b|unsubscribe", re.I)


def resolve_user_agent(user_agent: str | None) -> str:
    """None/"" -> honest default; "browser" -> browser-like; else the given string."""
    ua = (user_agent or "").strip()
    if not ua or ua.lower() in ("honest", "default"):
        return HONEST_USER_AGENT
    if ua.lower() == "browser":
        return BROWSER_USER_AGENT
    return re.sub(r"[\r\n]+", " ", ua)[:200]
_SESSION_PARAMS = frozenset(
    {"jsessionid", "sid", "sessionid", "session_id", "phpsessid", "sessid", "aspsessionid",
     "cfid", "cftoken", "sessionkey", "session"}
)
_SESSION_PATH_RE = re.compile(r";(?:jsessionid|sid|phpsessid|sessionid)=[^/?#;]*", re.I)
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_ROOT_DIV_RE = re.compile(
    r"<div[^>]+id=[\"'](?:root|app|__next|__nuxt|app-root|svelte)[\"']|<app-root", re.I
)
_JS_REDIRECT_RE = re.compile(
    r"(?:window\.|document\.|top\.)?location(?:\.href)?\s*=(?!=)|location\.(?:replace|assign)\s*\(", re.I
)
_NEEDS_JS_RE = re.compile(r"enable javascript|requires javascript|javascript is (?:required|disabled)", re.I)
_SCRIPT_RE = re.compile(r"<script\b[^>]*>(.*?)</script>", re.I | re.S)
_STRIP_RE = re.compile(r"<(script|style|noscript)\b.*?</\1>|<!--.*?-->|<[^>]+>", re.I | re.S)
_SECOND_LEVEL = frozenset({"co", "com", "org", "gov", "net", "ac", "edu", "go", "ne", "or"})

# Replaceable in tests so politeness delays never really sleep.
_sleep = time.sleep
_now = time.monotonic


# --------------------------------------------------------------------- urls


def registrable_domain(host: str) -> str:
    """Cheap registrable-domain guess (no public-suffix list)."""
    host = (host or "").lower().split(":")[0].strip(".")
    labels = host.split(".")
    if len(labels) <= 2 or re.fullmatch(r"[\d.]+", host):
        return host
    if len(labels[-1]) == 2 and labels[-2] in _SECOND_LEVEL and len(labels) >= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def clean_url(url: str) -> str:
    """Drop fragments, session-id params/segments and already-redacted params."""
    parts = urlsplit(url.strip())
    path = _SESSION_PATH_RE.sub("", parts.path)
    pairs = [
        (k, v)
        for k, v in parse_qsl(parts.query, keep_blank_values=True)
        if k.lower().replace("-", "_") not in _SESSION_PARAMS and REDACTED not in v
    ]
    netloc = parts.netloc.lower()
    if parts.scheme == "http" and netloc.endswith(":80"):
        netloc = netloc[:-3]
    if parts.scheme == "https" and netloc.endswith(":443"):
        netloc = netloc[:-4]
    return urlunsplit((parts.scheme.lower(), netloc, path or "/", urlencode(pairs), ""))


def dedupe_key(url: str) -> str:
    """Host + templated path + sorted query *names* (values ignored)."""
    parts = urlsplit(clean_url(url))
    path = path_template(parts.path)
    if len(path) > 1:
        path = path.rstrip("/")
    names = sorted({k for k, _ in parse_qsl(parts.query, keep_blank_values=True)})
    return f"{parts.netloc}{path}?{'&'.join(names)}"


def _safe(url: str) -> str:
    return redact_url(clean_url(url)) if url else url


# ------------------------------------------------------------------- gates

_FALLBACK_MARKERS = (
    (re.compile(r"host[_ ]not[_ ]allowed|egress|blocked by (?:network|proxy)|proxy denied", re.I),
     "environment_blocked", "unknown_rerun"),
    (re.compile(r"g-recaptcha|h-captcha|hcaptcha|cf-turnstile|captcha", re.I), "captcha", "stop"),
    (re.compile(r"just a moment|attention required|verify you are (?:a )?human|access denied|"
                r"unusual traffic|are you a robot", re.I), "bot_wall", "stop"),
)


def _fallback_classify(status: int, headers: dict[str, str], body: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    head = body[:20000]
    for pat, cls, action in _FALLBACK_MARKERS:
        if pat.search(head) and (status >= 400 or cls != "bot_wall" or len(head) < 6000):
            out.append({"class": cls, "action": action, "source": "fallback"})
    if status == 429:
        out.append({"class": "rate_limit", "action": "stop", "source": "fallback"})
    elif status == 403 and not out:
        out.append({"class": "bot_wall", "action": "stop", "source": "fallback"})
    elif status == 401:
        out.append({"class": "login", "action": "report", "source": "fallback"})
    seen: set[str] = set()
    return [g for g in out if not (g["class"] in seen or seen.add(g["class"]))]  # type: ignore[func-returns-value]


def _gates(status: int, headers: dict[str, str], body: str, url: str) -> list[dict[str, Any]]:
    if _classify_response is not None:
        try:
            got = _classify_response(status, headers, body, url)
            return [g for g in (got or []) if isinstance(g, dict) and g.get("class")]
        except Exception:  # noqa: BLE001 - sibling must never break the crawl
            pass
    return _fallback_classify(status, headers, body)


def _stack(status: int, headers: dict[str, str], body: str, url: str) -> list[str]:
    if _fingerprint_response is None:
        return []
    try:
        techs = _fingerprint_response(status, headers, body, url) or []
    except Exception:  # noqa: BLE001
        return []
    names = [
        str(t.get("name") or t.get("id"))
        for t in techs
        if isinstance(t, dict) and t.get("confidence") != "low"  # one weak signal is noise
    ]
    return sorted({n for n in names if n})[:6]


# ----------------------------------------------------------- page analysis


def _title(html: str) -> str:
    m = _TITLE_RE.search(html)
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", "", m.group(1))).strip()[:120] if m else ""


def _needs_browser(html: str, structure: dict[str, Any]) -> str | None:
    """Reason a plain GET is not enough (SPA shell / JS-only redirect), else None."""
    text = re.sub(r"\s+", " ", _STRIP_RE.sub(" ", html)).strip()
    scripts = _SCRIPT_RE.findall(html)
    has_script = bool(scripts) or "<script" in html.lower()
    if structure.get("form_count") or len(text) >= 400:
        return None
    if _ROOT_DIV_RE.search(html) and has_script:
        return "spa_shell"
    if has_script and not structure.get("links") and any(_JS_REDIRECT_RE.search(s) for s in scripts):
        return "js_redirect"
    if has_script and _NEEDS_JS_RE.search(html):
        return "requires_javascript"
    return None


def _form_rows(structure: dict[str, Any], keywords: tuple[str, ...] = ()) -> list[dict[str, Any]]:
    """Per-form rows; ``looks_like_search`` uses the same test as the page-level flag."""
    rows = []
    for f in (structure.get("forms") or [])[:5]:
        names = [str(n) for n in (f.get("field_names") or []) if n][:12]
        one = search_form_reached({"forms": [f]}, keywords=keywords)
        rows.append(
            {
                "action": _safe(f.get("action") or ""),
                "method": f.get("method") or "",
                "fields": names,
                "looks_like_search": one is not None,
                "_hit": one,
            }
        )
    return rows


def _all_links(structure: dict[str, Any], ranked: list[dict[str, Any]], keywords: tuple[str, ...]) -> list[dict[str, Any]]:
    """Ranked links first, then every other absolute http(s) link at score 0."""
    out = list(ranked)
    seen = {r.get("href") for r in out}
    for ln in structure.get("links") or []:
        href = ln.get("href") or ""
        if not href.startswith(("http://", "https://")) or href in seen:
            continue
        seen.add(href)
        if _AVOID_LINK_RE.search(href) or _AVOID_LINK_RE.search(ln.get("text") or ""):
            continue
        score, matched = score_link((ln.get("text") or "").strip(), href, keywords)
        out.append({"href": href, "text": (ln.get("text") or "").strip(), "score": max(score, 0),
                    "matched_keywords": matched})
        if len(out) >= 400:
            break
    return out


# -------------------------------------------------------------------- core


class _Host:
    __slots__ = ("robots", "last", "halted", "delay", "robots_status", "robots_policy")

    def __init__(self) -> None:
        self.robots: urllib.robotparser.RobotFileParser | None = None
        self.last = 0.0
        self.halted: str | None = None
        self.delay = 0.0
        self.robots_status: int | None = None
        self.robots_policy = "unknown"


def crawl(
    start_url: str,
    keywords: tuple[str, ...] | list[str] = (),
    *,
    max_pages: int = 12,
    depth: int = 2,
    delay_s: float = 1.0,
    follow_external: bool = False,
    timeout_s: float = 15.0,
    client: httpx.Client | None = None,
    respect_robots: bool = True,
    user_agent: str | None = None,
) -> dict[str, Any]:
    """Polite breadth-first crawl from ``start_url`` following only fetched links.

    ``user_agent``: None -> honest hardly UA; ``"browser"`` -> browser-like UA;
    any other string is sent as given.
    """
    ua = resolve_user_agent(user_agent)
    headers_out = {"User-Agent": ua, **_ACCEPT}
    kw = tuple(k.strip() for k in keywords if k and k.strip())
    max_pages = max(1, min(int(max_pages), MAX_PAGES_HARD))
    depth = max(0, min(int(depth), MAX_DEPTH_HARD))
    delay_s = max(0.0, float(delay_s))
    parts = urlsplit(start_url.strip())
    if parts.scheme not in ("http", "https") or not parts.netloc:
        return {"error": "start_url must be an absolute http(s) URL"}
    start = clean_url(start_url)
    home = registrable_domain(parts.hostname or "")

    own = client is None
    http = client or httpx.Client(timeout=timeout_s, follow_redirects=False, headers=headers_out)
    hosts: dict[str, _Host] = {}
    pages: list[dict[str, Any]] = []
    robots_disallowed: list[str] = []
    errors: list[dict[str, str]] = []
    external: dict[str, dict[str, Any]] = {}
    seen: set[str] = {dedupe_key(start)}
    state = {"fetched": 0}

    def host_state(host: str) -> _Host:
        return hosts.setdefault(host, _Host())

    def polite_get(url: str, *, follow: bool = False) -> httpx.Response:
        host = urlsplit(url).netloc.lower()
        hs = host_state(host)
        wait = max(delay_s, hs.delay) - (_now() - hs.last)
        if hs.last and wait > 0:
            _sleep(wait)
        last_exc: Exception | None = None
        for attempt in range(2):  # one retry, transient network errors only
            try:
                resp = http.get(url, headers=headers_out, follow_redirects=follow, timeout=timeout_s)
                hs.last = _now()
                return resp
            except httpx.TransportError as exc:
                hs.last = _now()
                last_exc = exc
                if attempt == 0 and delay_s:
                    _sleep(delay_s)
        assert last_exc is not None
        raise last_exc

    def robots_for(url: str) -> urllib.robotparser.RobotFileParser | None:
        sp = urlsplit(url)
        hs = host_state(sp.netloc.lower())
        if hs.robots is not None:
            return hs.robots
        rp = urllib.robotparser.RobotFileParser()
        robots_url = f"{sp.scheme}://{sp.netloc}/robots.txt"
        try:
            resp = polite_get(robots_url, follow=True)
        except httpx.HTTPError:
            rp.parse([])  # unreachable robots.txt: nothing disallowed
            hs.robots_policy = "unreachable_allow_all"
        else:
            _check_halt(hs, resp)
            hs.robots_status = resp.status_code
            if resp.status_code >= 500 or resp.status_code in (401, 403):
                # Server error, or access to robots.txt itself refused (often a bot gate):
                # the conservative reading is "no crawling", not "nothing disallowed".
                rp.parse(["User-agent: *", "Disallow: /"])
                hs.robots_policy = "forbidden_disallow_all" if resp.status_code < 500 else "error_disallow_all"
            elif resp.status_code >= 400:
                rp.parse([])
                hs.robots_policy = "missing_allow_all"
            else:
                rp.parse(resp.text.splitlines())
                hs.robots_policy = "parsed"
                cd = rp.crawl_delay(ua) or rp.crawl_delay("*")
                if cd:
                    hs.delay = min(float(cd), 30.0)
        hs.robots = rp
        return rp

    def _check_halt(hs: _Host, resp: httpx.Response) -> None:
        if resp.status_code == 429:
            hs.halted = "429"
        elif resp.status_code >= 300 and "retry-after" in resp.headers:
            hs.halted = "retry-after"

    def allowed(url: str) -> bool:
        if not respect_robots:
            return True
        return robots_for(url).can_fetch(ua, url)  # type: ignore[union-attr]

    def fetch(url: str, *, external_hop: bool) -> dict[str, Any]:
        """GET with manual redirects (chain recorded). Returns page record + body."""
        chain: list[int] = []
        cur = url
        resp: httpx.Response | None = None
        note: str | None = None
        for _ in range(MAX_REDIRECTS + 1):
            host = urlsplit(cur).netloc.lower()
            if host_state(host).halted:
                note = f"host halted ({host_state(host).halted})"
                break
            if not allowed(cur):
                robots_disallowed.append(_safe(cur))
                note = "robots_disallowed"
                resp = None
                break
            resp = polite_get(cur)
            _check_halt(host_state(host), resp)
            chain.append(resp.status_code)
            loc = resp.headers.get("location")
            if resp.status_code in (301, 302, 303, 307, 308) and loc:
                nxt = clean_url(urljoin(cur, loc))
                if urlsplit(nxt).scheme not in ("http", "https"):
                    note = "redirect to non-http scheme"
                    break
                if registrable_domain(urlsplit(nxt).hostname or "") != home and not (
                    follow_external and external_hop
                ):
                    note = f"redirect left site: {urlsplit(nxt).hostname}"
                    break
                if len(chain) > MAX_REDIRECTS:
                    note = "redirect cap"
                    break
                cur = nxt
                continue
            break
        return {"final": cur, "resp": resp, "chain": chain, "note": note}

    def analyse(url: str, got: dict[str, Any], meta: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        resp: httpx.Response = got["resp"]
        status = resp.status_code
        ctype = (resp.headers.get("content-type") or "").split(";")[0].strip().lower()
        final = got["final"]
        body = resp.text[:_MAX_BODY_CHARS] if resp.content else ""
        hdrs = {k.lower(): v for k, v in resp.headers.items()}
        gates = _gates(status, hdrs, body, final)
        stops = [g for g in gates if g.get("action") in _STOP_ACTIONS]
        page: dict[str, Any] = {
            "url": _safe(url),
            "final_url": _safe(final),
            "status": status,
            "content_type": ctype,
            "depth": meta["depth"],
            "score": meta["score"],
            "matched_keywords": meta["matched"],
            "redirect_chain": got["chain"][:MAX_REDIRECTS] if len(got["chain"]) > 1 else [],
            "title": "",
            "forms": [],
            "looks_like_search": False,
            "grids": [],
            "data_endpoints": 0,
            "gates": sorted({str(g["class"]) for g in gates}),
            "stack": _stack(status, hdrs, body, final),
            "needs_browser": False,
            "evidence": list(meta["evidence"]),
        }
        links: list[dict[str, Any]] = []
        is_html = "html" in ctype or (not ctype and "<html" in body[:2000].lower())
        if is_html and body:
            page["title"] = _title(body)
            ranked, structure = page_candidates(body, base_url=final, keywords=kw, limit=_LINKS_PER_PAGE)
            hit = search_form_reached(structure, keywords=kw)
            page["forms"] = _form_rows(structure, kw)
            hit = next((f["_hit"] for f in page["forms"] if f["_hit"]), None) or hit
            for f in page["forms"]:
                f.pop("_hit", None)
            if hit or any(f["looks_like_search"] for f in page["forms"]):
                page["looks_like_search"] = True
                page["evidence"].append("search-like form: " + ",".join((hit or {}).get("fields") or []))
            page["grids"] = html_grid_signals(body)[:5]
            if page["grids"]:
                page["evidence"].append("grid library: " + ",".join(page["grids"]))
            if "data-" in body:
                try:
                    from hardly.core.data_attrs import extract_data_attributes

                    page["data_endpoints"] = len(
                        extract_data_attributes(body, base_url=final).get("endpoints") or []
                    )
                except Exception:  # noqa: BLE001 - hints only
                    pass
            reason = _needs_browser(body, structure)
            if reason:
                page["needs_browser"] = True
                page["needs_browser_reason"] = reason
                page["evidence"].append(f"needs browser: {reason}")
            if meta["depth"] == 0:
                s, m = score_link(page["title"], urlsplit(final).path, kw)
                page["score"], page["matched_keywords"] = s, m
            if not stops and 200 <= status < 300:
                links = _all_links(structure, ranked, kw)
        if stops:
            page["stop"] = [{"class": g["class"], "action": g.get("action")} for g in stops]
            page["evidence"].append("gate: " + ",".join(sorted({str(g["class"]) for g in stops})))
        page["evidence"] = page["evidence"][:6]
        return page, links

    # Level-by-level breadth-first walk; within a level, best score first.
    frontier: list[dict[str, Any]] = [
        {"url": start, "score": 0, "matched": [], "depth": 0, "external": False, "evidence": ["start url"]}
    ]
    level = 0
    try:
        while frontier and state["fetched"] < max_pages:
            frontier.sort(key=lambda f: (f["external"], -f["score"], f["url"]))
            nxt: dict[str, dict[str, Any]] = {}
            for item in frontier:
                if state["fetched"] >= max_pages:
                    break
                url = item["url"]
                if host_state(urlsplit(url).netloc.lower()).halted:
                    continue
                try:
                    got = fetch(url, external_hop=item["external"])
                except httpx.HTTPError as exc:
                    errors.append({"url": _safe(url), "error": type(exc).__name__})
                    continue
                if got["resp"] is None:
                    continue
                state["fetched"] += 1
                final_key = dedupe_key(got["final"])
                seen.add(final_key)
                page, links = analyse(url, got, item)
                if item["external"]:
                    page["external_hop"] = True
                if got["note"]:
                    page["note"] = got["note"]
                pages.append(page)
                if item["external"]:
                    continue
                for link in links:
                    href = link.get("href") or ""
                    if not href.startswith(("http://", "https://")):
                        continue
                    target = clean_url(href)
                    lhost = urlsplit(target).hostname or ""
                    is_ext = registrable_domain(lhost) != home
                    key = dedupe_key(target)
                    if is_ext:
                        ek = f"{lhost}|{urlsplit(target).path}"
                        external.setdefault(
                            ek,
                            {
                                "host": lhost,
                                "url": _safe(target),
                                "text": (link.get("text") or "")[:80],
                                "score": link["score"],
                                "found_on": page["final_url"],
                                "fetched": False,
                                "_target": target,
                            },
                        )
                        if not follow_external:
                            continue
                    if key in seen or level >= depth:
                        continue
                    cand = nxt.get(key)
                    if cand is None or link["score"] > cand["score"]:
                        nxt[key] = {
                            "url": target,
                            "score": link["score"],
                            "matched": link.get("matched_keywords") or [],
                            "depth": level + 1,
                            "external": is_ext,
                            "evidence": [
                                f"linked from {urlsplit(page['final_url']).path or '/'} as "
                                f"{(link.get('text') or '')[:40]!r} (score {link['score']})"
                            ]
                            + (["matched keywords: " + ",".join(link["matched_keywords"])]
                               if link.get("matched_keywords") else []),
                        }
            for item in nxt.values():
                seen.add(dedupe_key(item["url"]))
            frontier = list(nxt.values())
            level += 1
            if level > depth:
                break
    finally:
        if own:
            http.close()

    fetched_keys = {dedupe_key(p["final_url"]) for p in pages if p.get("external_hop")}
    for row in external.values():
        row["fetched"] = dedupe_key(row.pop("_target")) in fetched_keys

    return _summarise(
        start, kw, pages, robots_disallowed, errors, external, hosts,
        max_pages=max_pages, depth=depth, delay_s=delay_s,
        follow_external=follow_external, respect_robots=respect_robots,
        user_agent=ua,
    )


def _summarise(
    start: str,
    kw: tuple[str, ...],
    pages: list[dict[str, Any]],
    robots_disallowed: list[str],
    errors: list[dict[str, str]],
    external: dict[str, dict[str, Any]],
    hosts: dict[str, _Host],
    *,
    max_pages: int,
    depth: int,
    delay_s: float,
    follow_external: bool,
    respect_robots: bool,
    user_agent: str = HONEST_USER_AGENT,
) -> dict[str, Any]:
    blocked: list[dict[str, Any]] = []
    env_blocked: list[dict[str, Any]] = []
    for p in pages:
        for g in p.get("stop") or []:
            row = {"url": p["final_url"], "status": p["status"], "class": g["class"], "action": g["action"]}
            (env_blocked if g["class"] == "environment_blocked" else blocked).append(row)
    ok = [p for p in pages if 200 <= p["status"] < 300 and not p.get("stop")]
    ok.sort(key=lambda p: (not p["looks_like_search"], -p["score"], p["depth"], p["url"]))
    candidates = [
        {
            "url": p["final_url"],
            "score": p["score"],
            "looks_like_search": p["looks_like_search"],
            "needs_browser": p["needs_browser"],
            "matched_keywords": p["matched_keywords"],
            "title": p["title"],
            "evidence": p["evidence"][:3],
        }
        for p in ok[:10]
    ]
    needs_browser = [p["final_url"] for p in pages if p["needs_browser"]]
    halted = [{"host": h, "reason": st.halted} for h, st in sorted(hosts.items()) if st.halted]
    ext_all = sorted(external.values(), key=lambda r: (-r["score"], r["host"], r["url"]))
    ext_rows = ext_all[:_MAX_EXTERNAL_ROWS]
    robots_rows = [
        {
            "host": h,
            "status": st.robots_status,
            "policy": st.robots_policy,
            "crawl_delay_s": st.delay or None,
            "effective_delay_s": max(delay_s, st.delay),
        }
        for h, st in sorted(hosts.items())
        if st.robots is not None
    ]
    nxt: list[str] = []
    searchy = [c for c in candidates if c["looks_like_search"]]
    if searchy:
        nxt.append(
            f"search-like form at {searchy[0]['url']}: inspect its fields, then replay with curl "
            "or run `hardly capture discover <url>` to capture the real request."
        )
    elif candidates:
        nxt.append(f"no search form found; best lead {candidates[0]['url']} - raise depth or refine keywords.")
    else:
        nxt.append("no usable pages; check blocked / environment_blocked / robots_disallowed.")
    if needs_browser:
        nxt.append(
            f"{len(needs_browser)} page(s) need a browser: use `hardly capture discover <url> --recipe` "
            "with a find_click step for the needs_browser pages."
        )
    if env_blocked:
        nxt.append("environment_blocked is the sandbox/network, not the site: fix egress, do not retry in a loop.")
    if blocked:
        nxt.append("site gate(s) hit: stop; use an interactive capture with a person, do not evade or retry.")
    if halted:
        nxt.append("host rate-limited (429/Retry-After): wait before re-running; crawl halted for that host.")
    if robots_disallowed:
        nxt.append("robots.txt disallowed some links; they were not fetched.")
    if any(r["policy"] == "forbidden_disallow_all" for r in robots_rows):
        nxt.append(
            "robots.txt itself returned 401/403 (often a bot gate); treated as disallow-all. "
            "Do not evade: ask the site owner, or use an interactive capture with a person."
        )
    if ext_rows and not follow_external:
        nxt.append("external links were recorded but not fetched; pass follow_external to take one hop.")
    return {
        "start_url": _safe(start),
        "keywords": list(kw),
        "limits": {
            "max_pages": max_pages, "depth": depth, "delay_s": delay_s,
            "follow_external": follow_external, "respect_robots": respect_robots,
            "user_agent": user_agent,
        },
        "robots": robots_rows,
        "pages_fetched": len(pages),
        "candidates": candidates,
        "pages": pages,
        "blocked": blocked,
        "environment_blocked": env_blocked,
        "halted_hosts": halted,
        "robots_disallowed": sorted(set(robots_disallowed)),
        "external_links": ext_rows,
        "external_links_total": len(ext_all),
        "needs_browser": needs_browser,
        "errors": errors,
        "next": nxt,
    }
