# Integrating `hardly_crawl`

Core: `src/hardly/core/crawl.py` (`crawl(...)`), tests: `tests/test_crawl.py`.
Optional siblings (`hardly.core.gates`, `hardly.core.stack`) are imported
defensively; without them a minimal built-in gate check runs and `stack` is empty.

## 1. server.py (MCP tool)

```python
@mcp.tool
def hardly_crawl(
    start_url: str,
    keywords_json: str | None = None,
    confirm: bool = False,
    max_pages: int = 12,
    depth: int = 2,
    delay_s: float = 1.0,
    follow_external: bool = False,
    respect_robots: bool = True,
    timeout_s: float = 15.0,
) -> str:
    """Curl-first, robots-aware, polite crawl that finds candidate pages. LIVE GETs: requires confirm=true.

    Plain HTTP often works where headless Chromium is blocked and most facts are in
    static HTML. Follows only links found in fetched HTML (never guesses hosts or
    paths), ranks them with your domain `keywords_json` (JSON list of nouns), honours
    robots.txt, waits delay_s between requests per host, strips session ids, and
    stops at gates (bot wall / captcha / environment block) and on 429/Retry-After.
    Caps: max_pages <= 40, depth <= 4. External registrable domains are only recorded
    unless follow_external=true (one hop). Returns candidates (search forms first),
    per-page form field NAMES, gate classes, needs_browser pages and `next` advice -
    no bodies, URLs redacted. Pages flagged needs_browser: use hardly_capture_recipe /
    `capture discover` with a find_click step.
    """
    if not confirm:
        return _ok(
            {
                "error": "crawl requires confirm=true (performs live GET requests)",
                "hint": "Pass confirm=true; keep max_pages/depth small and respect robots.",
            }
        )
    keywords: list[str] = []
    if keywords_json:
        try:
            keywords = [str(k) for k in json.loads(keywords_json)]
        except (json.JSONDecodeError, TypeError) as exc:
            return _err(exc)
    from hardly.core.crawl import crawl

    try:
        return _ok(
            crawl(
                start_url,
                tuple(keywords),
                max_pages=max_pages,
                depth=depth,
                delay_s=delay_s,
                follow_external=follow_external,
                respect_robots=respect_robots,
                timeout_s=timeout_s,
            )
        )
    except Exception as exc:  # noqa: BLE001
        return _err(exc)
```

## 2. cli.py

```python
def cmd_crawl(args: argparse.Namespace) -> int:
    from hardly.core.crawl import crawl

    if not args.yes:
        _print({"error": "crawl requires --yes (performs live GET requests)"})
        return 1
    result = crawl(
        args.url,
        tuple(args.keyword or ()),
        max_pages=args.max_pages,
        depth=args.depth,
        delay_s=args.delay,
        follow_external=args.follow_external,
        respect_robots=not args.ignore_robots,
        timeout_s=args.timeout,
    )
    _print(result)
    return 1 if "error" in result else 0
```

Parser registration (next to `probe_p`):

```python
    crawl_p = sub.add_parser(
        "crawl",
        help="Curl-first polite crawl for candidate pages (live GETs; requires --yes)",
    )
    crawl_p.add_argument("url")
    crawl_p.add_argument("-k", "--keyword", action="append", help="Domain keyword (repeatable)")
    crawl_p.add_argument("--max-pages", type=int, default=12)
    crawl_p.add_argument("--depth", type=int, default=2)
    crawl_p.add_argument("--delay", type=float, default=1.0, help="Seconds between requests per host")
    crawl_p.add_argument("--follow-external", action="store_true")
    crawl_p.add_argument("--ignore-robots", action="store_true", help="Only where you are permitted")
    crawl_p.add_argument("--timeout", type=float, default=15.0)
    crawl_p.add_argument("--yes", action="store_true", help="Confirm live requests")
    crawl_p.set_defaults(func=cmd_crawl)
```

## 3. capabilities.py

- In the tools tuple (next to `"hardly_probe"`): `"hardly_crawl",`
- In `FEATURES`: `"crawl",` and `"crawl_robots",`
- Then regenerate docs (`scripts/gen_tool_docs.py`) so `docs/tools.md` lists the tool.

## 4. Docs

### docs/capture.md (new subsection)

> **Curl-first crawl (`hardly crawl` / `hardly_crawl`).** Before launching a
> browser, try a polite plain-HTTP crawl: `hardly crawl https://site.example/ -k <domain noun> --yes`.
> It follows only links found in fetched HTML (never guessed hosts or paths),
> reads robots.txt once per host and does not fetch disallowed URLs (listed as
> `robots_disallowed`), waits `--delay` seconds per host, strips session ids,
> and stops at gates: a bot wall/CAPTCHA is recorded and never retried or
> followed, `environment_blocked` (sandbox/egress) is reported apart from site
> walls, and a 429 or Retry-After halts that host. Other registrable domains
> are only listed in `external_links` unless `--follow-external` (one hop).
> Output is small and redacted: ranked `candidates` (search-like forms first,
> with field names), grid/data-endpoint hints, `needs_browser` pages (SPA
> shells, JS-only redirects) and `next` advice. Hand the `needs_browser` pages
> to `hardly capture discover <url>` with a `find_click` recipe step. The MCP
> tool and CLI both require explicit confirmation (`confirm=true` / `--yes`)
> because they perform live GETs.

### docs/crawl-handoff.md (replace the open item)

In §7 "Open items", add (or, if a "plain HTTP first" item exists, replace it with):

> - ~~Plain-HTTP first pass~~ **Fixed**: `hardly crawl` / `hardly_crawl` is a
>   curl-first, robots-aware, polite crawl (caps 40 pages / depth 4, per-host
>   delay, session-id stripping, gate stop signs, 429 halt). Try it before a
>   headless capture; use a browser only for its `needs_browser` pages.

And in §2 ground rules, optionally append: "Prefer `hardly crawl` for the first
pass; it already honours robots, delays and rate limits."
