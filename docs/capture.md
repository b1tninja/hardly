# Capturing HARs

> Purpose: How to record HARs: bring your own, headless discovery, interactive capture, recipes, env vars and containers.

You can bring your own HAR (browser DevTools "Save all as HAR with content" or
any proxy export) and use [archive mode](concepts.md#three-modes) directly.
hardly can also record one with Playwright. Capture is optional:

```bash
pip install -e ".[capture]"
playwright install chromium      # or use system Chrome / a prebuilt browser (below)
hardly server status --sections browser_setup   # diagnoses the package, browsers, features
```

## Headless (agent drives)

```bash
hardly browser capture-discover https://site.example --analyze --wait-seconds 5 --confirm
hardly browser capture-discover https://site.example --analyze --steps steps.json --confirm
```

MCP: `hardly_browser_capture_discover(url, analyze=true, wait_seconds=5, steps=[...], confirm=true)`
loads the page, runs the steps, stops, indexes the HAR and returns a `session_id` plus a
brief, already in archive mode. Without `confirm=true` it only returns the plan. If the brief shows
a wall (`hardly_gate_bot_protection`), switch to interactive. With `analyze=false` it is a plain
time-boxed capture (`wait_seconds`, default 20) that returns the raw HAR.

### Recipes

A recipe is a JSON list of steps (the `steps` argument; CLI `--steps FILE`). Headless one-shots run **in-process**:

| op | Fields | Notes |
|----|--------|-------|
| `goto` | `url` | waits for `domcontentloaded` |
| `wait` | `ms` | capped at 30 000 |
| `click` | `css` (or `selector`), `timeout_ms` | Playwright selectors: `#id`, `a:has-text("Next")` |
| `fill` | `css`, `value` | |
| `press` | `key` | default `Enter` |
| `find_click` | `keywords` (your domain terms), `max_hops` (default 4, max 8), `min_fields` (default 2) | follows the best-ranked link/button/postback each hop until a real search form appears; result has `reached`, `form`, `hops` (each hop's `via` is `click` or `goto`). The goal check skips login forms, one-box site search, newsletter/feedback/translate widgets, email-only and select-only forms, and nameless inputs; hidden elements and `target=_blank` links fall back to navigating to the link's `href` |
| `dismiss_consent` | `prefer` (`reject` default, or `accept`), `timeout_ms` | dismisses cookie/consent dialogs only, reject first. Refuses login, captcha, terms/disclaimer and form-bearing dialogs and bot-wall pages (listed in `refused[]`); no banner is not an error (`dismissed: false`) |
| `evaluate` | `js` | result is returned in the step output |
| `fetch` | `url`, `method`, `headers`, `body` | same-tab `fetch`, so APIs/GraphQL land in the HAR without clicking through a UI |

`find_click` and `dismiss_consent` run both in headless one-shots and in the live
session runner. `find_click` also searches same-origin iframes and open shadow DOM
(not closed roots or cross-origin frames) and hovers menu triggers to reveal hidden
submenu links (`hover: false` disables; hops report `via: hover+click`). The live capture session (`hardly_browser_start` + `hardly_browser_run_steps`)
additionally supports `elements`, `aria`, `screenshot`, `note`, `url`, and
selecting by `ref`/`text`/`role` from the accessibility snapshot. Use
`hardly_browser_inspect` to get Playwright accessibility YAML with `refs[]`, then
prefer `ref` over fragile CSS. `hardly_session_plan_steps` (CLI `hardly session plan-steps`) drafts
steps from a captured story; `hardly_page_ui(sections=['search_links'])` (CLI `hardly page ui HAR
--sections search_links`) proposes the next `click` when you are still on a landing page.

Selecting by durable worker (`HARDLY_CAPTURE_SUBPROCESS=1`) is only needed when
you want a long-lived browser with aria RPC across calls.

## Curl-first crawl

Before launching a browser, try a polite plain-HTTP crawl:
`hardly send site-crawl https://site.example/ --keywords <domain noun> --confirm`. It follows only
links found in fetched HTML (never guessed hosts or paths), reads robots.txt
once per host and does not fetch disallowed URLs (`robots_disallowed`), waits
`--delay-seconds` per host, strips session ids, and stops at gates: a bot
wall/CAPTCHA is recorded and never retried or followed, `environment_blocked`
(sandbox/egress) is reported apart from site walls, and a 429 or `Retry-After`
halts that host. Other registrable domains are listed in `external_links` unless
`--follow-external` (one hop). Output is small and redacted: ranked
`candidates` (search-like forms first, with field names), grid/data hints,
`needs_browser` pages (SPA shells, JS-only redirects) and `next` advice. Hand
the `needs_browser` pages to `hardly browser capture-discover <url> --analyze` with a `find_click`
step. The MCP tool and CLI require explicit confirmation (`confirm=true`
/ `--confirm`) because they perform live GETs.

## Interactive (a person drives)

For bot walls, CAPTCHA, MFA, or UIs an agent cannot script:

```bash
hardly browser start https://site.example -o capture.har --foreground   # browser opens; click; Enter/close to stop
```

MCP: `hardly_browser_start(url, headed=true, channel="chrome")` → **ask the person
what to click** → `hardly_browser_stop`. Headed capture needs a local
(non-container) MCP server with a display.

## Useful options

| Option (MCP parameter) | Purpose |
|--------|---------|
| `--channel chrome\|msedge` (`channel`) | Use installed browser; better against bot detection |
| `--url-filter GLOB` (`url_filter`) | Only record matching URLs |
| `--omit-content` (`omit_content`) | Smaller HAR without bodies (loses most analysis) |
| `--profile DIR` (`profile`) | Persistent profile (cookies survive) |
| `--trace` (`trace`) | Also write a Playwright `.trace.zip` |
| `--no-same-tab` (`same_tab=false`) | Keep popup windows |

Playwright often leaves `content.size == -1` for XHR; hardly backfills those
bodies. `hardly session body-coverage HAR` shows what is still empty or truncated.

## Environment variables

| Variable | Meaning |
|----------|---------|
| `HARDLY_RUNTIME_DIR` | Scratch dir for capture state, slot locks and ephemeral HARs (default `<tempdir>/hardly-<uid>`) |
| `HARDLY_BROWSER_CHANNEL` | Default `channel` (`chrome`, `msedge`) |
| `HARDLY_BROWSER_EXECUTABLE` | Path to a Chromium binary to launch instead of Playwright's own download |
| `HARDLY_CAPTURE_SLOTS` | Max concurrent browser captures across processes (default 4; `0` = unlimited); extra captures queue and report `slot.queue_depth` |
| `HARDLY_CAPTURE_SLOT_TIMEOUT` | Seconds to wait for a slot (default 300) before failing with "waited Ns for a capture slot" |
| `HARDLY_CAPTURE_BUDGET` | Default hard per-call budget in seconds for headless capture (`--budget-seconds`) |
| `HARDLY_CAPTURE_SUBPROCESS` | `1` = durable capture worker (aria RPC) for headless |
| `HARDLY_CAPTURE_TRACE` | `1` = always write a trace |
| `HARDLY_LIVE_CAPTURE` | `1` = enable live Playwright tests and live soak in pytest |
| `HARDLY_PATH_MAP`, `HARDLY_WORKSPACE` | Docker: map host HAR paths into the container |

## Robustness options

- `--budget-seconds` / `budget_seconds`: remaining recipe steps are skipped once
  exceeded; the HAR is still written; the result has
  `budget: {limit_s, used_s, exceeded, skipped_steps}`.
- `--exclude-noise` / `exclude_noise`: abort analytics, ad, font, map-tile and heavy
  media requests (reports `blocked_requests`, `blocked_hosts`). Off by default;
  blocking can break sites.
- Capture errors carry `error_class` (`environment_blocked|transient|cert|dns|
  timeout|refused|unknown`), `error_retryable` and `error_advice`. A capture that
  finishes without a HAR is an error (`har_exists: false`), never a success.
- `hardly server status --sections browser_setup` reports installed browser builds, the build Playwright
  expects, `mismatch`, `suggested_executable` and `browser_executable_source`;
  when Playwright's own browser is missing, an installed Chromium under
  `PLAYWRIGHT_BROWSERS_PATH`, `/opt/pw-browsers` or `~/.cache/ms-playwright` is
  used automatically.

## Containers and managed environments

- Docker deployments are good for archive mode; headed capture needs a local
  MCP server.
- If a prebuilt browser exists but its build does not match the installed
  Playwright (`browser_setup` says the binary is missing), set
  `HARDLY_BROWSER_EXECUTABLE=/path/to/chromium`.
- Browser traffic uses the environment's egress policy. If navigation fails
  with `ERR_TUNNEL_CONNECTION_FAILED`, the host is not allowed — add it to the
  network allowlist.

## Safety

Capture writes full request and response bodies, including credentials. Treat
every HAR as a secret: `*.har` is git-ignored; don't share or commit them.

## Redirect loops (`ERR_TOO_MANY_RETRIES`)

`net::ERR_TOO_MANY_RETRIES` / `ERR_TOO_MANY_REDIRECTS` almost always means a redirect loop:
a bad rewrite rule, an unexpected (non-canonical) domain (www vs apex, http vs https,
trailing slash), or a redirect that needs a cookie set on an earlier hop. Capture classifies
it as `redirect_loop` and retries once. Run `hardly send redirect-walk <url> --confirm`
(MCP `hardly_send_redirect_walk`, `confirm=true`) to follow the chain by hand with and without
cookies, name the loop shape, and probe the alternate host. Output: statuses, redacted URLs
and cookie names only.

### Per-step navigation options

`goto` takes `wait_until` (`commit`, `domcontentloaded`, `load`, `networkidle`) and `timeout_ms` (default 60000, max 300000); `click` takes `wait_until` and `timeout_ms` (default 10000); `find_click` takes `hover`, `timeout_ms` and `wait_until`.
