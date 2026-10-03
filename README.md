# hardly

HAR analysis MCP server and CLI — index, query, document, and probe APIs
**without** loading giant HAR files into the model context.

You *hardly* need the whole file.

## Why

Browser HAR captures are often tens of megabytes. Agents that `Read` them burn
tokens and still miss structure. **hardly** streams a HAR into SQLite once, then
exposes small, redacted, paginated tools over MCP (and a matching CLI).

## Quick start

```bash
# 1) Have a HAR? → archive mode
hardly modes archive --har path/to/capture.har
hardly brief path/to/capture.har

# 2) Only a URL, agent can drive? → headless
hardly capture discover https://example.com --channel chrome

# 3) Need a person (walls / MFA / complex UI)? → interactive
hardly capture start https://example.com --channel chrome
# ask them to click, then:
hardly capture stop
```

MCP agents: call `hardly_modes` first, then `hardly_mode` / the entry tools above.

## Install

```bash
cd D:\code\hardly
python -m venv .venv
.venv\Scripts\activate
pip install -e ".[dev]"
# Optional: record HARs with Playwright
pip install -e ".[capture]"
playwright install chromium
```

## Cursor MCP

### Local venv (recommended for headed capture)

```json
{
  "mcpServers": {
    "hardly": {
      "command": "D:\\code\\hardly\\.venv\\Scripts\\python.exe",
      "args": ["-m", "hardly"]
    }
  }
}
```

```bash
python -m hardly
# or
hardly serve
```

Headed Playwright capture needs a display. Use this entry for live capture;
Docker is fine for offline analysis only.

### Docker

```powershell
powershell -File scripts\deploy-docker.ps1
```

```json
{
  "mcpServers": {
    "hardly": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "-v", "D:/code:/workspace",
        "-e", "HARDLY_CACHE_DIR=/workspace/.hardly-cache",
        "-e", "HARDLY_WORKSPACE=/workspace",
        "hardly-mcp:latest"
      ]
    }
  }
}
```

Host paths under `D:\code\...` map to `/workspace/...`. Exports written under
the mount land on the host.

The image carries an `io.docker.server.metadata` label for Docker MCP Toolkit
profiles (`docker mcp profile server add …`). The direct `hardly` entry above is
usually simpler (tools appear as `hardly_*`).

## Three modes

Call `hardly_modes` / `hardly_mode` (or `hardly modes`) before other tools:

| Mode | When | Entry |
|------|------|--------|
| **archive** | HAR path already exists | `hardly_open` → brief / endpoints |
| **headless** | URL only; agent can drive the page | `hardly_discover(url)` (or start headed=false + aria/recipe) |
| **interactive** | Bot wall, CAPTCHA, MFA, complex UI | `hardly_capture_start(headed=true, channel=chrome)` → **ask the person** → stop |

```bash
hardly modes
hardly modes archive --har path/to/capture.har
hardly modes headless --url https://portal.example.com
hardly modes --goal "ask the user to search the county portal"
```

MCP prompts: `analyze_har`, `discover_apis`, `capture_portal`.

### Archive — existing HAR file

1. `hardly_open(path)` → `session_id`  
2. `hardly_hosts` → `preferred_host` (apex HTML, not payment CDNs)  
3. Portal: `hardly_brief` → forms / outline / correlate / trace  
4. JSON API: `hardly_endpoints` → content → auth → schema  
5. Export: stub / export_brief / export_openapi  

Never `Read` the raw HAR into the model.

### Headless — agent discovers APIs

```bash
hardly capture discover https://example.com --channel chrome --wait 8
# optional: --recipe steps.json
```

MCP: `hardly_discover(url, channel="chrome")` loads headless, optional
`recipe_json`, stops, opens a session (`session_id` + `brief`), then leaves
you in **archive** mode for drill-down. Or loop with
`hardly_capture_start(headed=false)` → aria → click/fill refs → stop.
If the brief shows a wall or empty bodies, switch to **interactive**.

### Interactive — person drives the browser

Cursor’s IDE browser does **not** hand hardly a HAR path.

1. `hardly_capture_doctor` if `capture_available` is false  
2. `hardly_capture_start(url=…, headed=true, channel="chrome")`  
3. **Ask the person** to use the open window (search, detail, login, …)  
4. `hardly_capture_stop` → continue in archive mode on `session_id`  

Capture backfills bodies that Playwright often leaves as `content.size == -1`.

For California county portals, prefer `python -m asspy.sample <county>` (writes
under `$ASSPY_HOME/samples/`).

## MCP tools

| Area | Tools |
|------|--------|
| Modes | `modes`, `mode`, `capabilities`, `help`, `recommend` |
| Session | `open`, `reopen`, `list_sessions`, `close`, `summary`, `stats`, `coverage` |
| Discovery | `summary`, `stats`, `hosts` (`preferred_host`), `endpoints`, `content`, `search`, `entry`, `compare_entries` |
| Portal / HTML | `brief`, `story`, `forms` / `ui` (incl. Acclaim / MPTSWEB / KoFile labels), `outline`, `pages`, `wall` |
| Tokens / credentials | `credentials` (login map + jwt/hex/base64 shapes), `correlate`, `trace`, `cookies`, `secrets`, `redirects` |
| Structure | `routes`, `around`, `tree`, `params`, `graphql`, `duplicates`, `slow` |
| Quality | `coverage`, `issues`, `diff`, `recommend` |
| Auth / schema | `auth`, `flow`, `schema` |
| Export | `export_md`, `export_openapi`, `export_postman`, `export_brief`, `stub`, `recipe_plan`, `curl`, `sql` |
| Live probe | `probe` (`confirm=true`; secrets only via overrides) |
| Capture | `discover`, `capture_doctor`, `capture_start` / `stop` / `list` / `status`, `capture_aria`, `capture_screenshot`, `capture_elements`, `capture_click` / `fill` / `press`, `capture_goto` / `url`, `capture_recipe`, `capture_once` |

**Token rules:** bodies truncated, secrets redacted, lists paginated. Never
returns the full HAR.

## Capture CLI

```bash
pip install -e ".[capture]"
playwright install chromium   # or HARDLY_BROWSER_CHANNEL=chrome
hardly capture doctor
hardly capabilities           # modes + playwright: {ready, version, hint}
hardly modes                  # archive / headless / interactive

# Headless discover (agent, no person)
hardly capture discover https://example.com --channel chrome --wait 8
hardly capture discover https://example.com --recipe steps.json

# Interactive: browser opens; person clicks; Enter or close to stop
hardly capture https://example.com -o D:/code/captures/example.har

# Agent click loop (headless or headed)
hardly capture start https://example.com -o out.har --channel chrome --headless
hardly capture aria                      # YAML + refs[] (mode=ai)
hardly capture click --ref e15
hardly capture fill "EXAMPLE" --ref e12
hardly capture recipe steps.json
hardly capture stop                      # optional --trace

# Timed / filtered
hardly capture https://example.com -o out.har --wait 20 --headless
hardly capture start https://apps.example.org/ --url-filter "**/api/**"
```

Convenience: `HARDLY_BROWSER_CHANNEL=chrome`, `--profile` for persistent cookies,
`--omit-content` for smaller files, on-page recording banner, disk sidecars under
`~/.cache/hardly/captures/active/` so stop works across processes. By default
`target=_blank` / `window.open` stay in the same tab (`--allow-popups` to opt
out); popups in the Playwright context are recorded either way.

## Analysis CLI

```bash
hardly summary path/to/capture.har
hardly hosts path/to/capture.har
hardly endpoints path/to/capture.har --host api.example.com
hardly content path/to/capture.har --host portal.example.com
hardly outline path/to/capture.har 12 --format markdown
hardly brief path/to/capture.har --host portal.example.com
hardly story path/to/capture.har --host portal.example.com
hardly search path/to/capture.har --host portal.example.com --kind json
hardly correlate path/to/capture.har --host portal.example.com
hardly trace path/to/capture.har --name __VIEWSTATE --host portal.example.com
hardly secrets path/to/capture.har
hardly credentials path/to/capture.har --host api.example.com
hardly wall path/to/capture.har --host portal.example.com
hardly stub path/to/capture.har --host portal.example.com -o client.py
hardly recipe-plan path/to/capture.har -o steps.json
hardly diff capture_a.har capture_b.har --host portal.example.com
hardly export-brief path/to/capture.har -o portal.md --host portal.example.com
hardly export-openapi path/to/capture.har -o openapi.json --host api.example.com
hardly help-tools portal
hardly recommend "guest portal csrf tokens"
hardly serve
```

Cache: `~/.cache/hardly/` (override with `HARDLY_CACHE_DIR`).

Maintainer soak against local HARs (edit `HARS` in the script):  
`python scripts/soak.py` — opens each capture, runs brief/credentials/walls,
and fails if soak JSON appears to contain secret values.

## Library

```python
from hardly.session import open_har, require_conn
from hardly.index import query as q

info = open_har("capture.har")
conn = require_conn(info["session_id"])
print(q.list_endpoints(conn, host="api.example.com"))
```

## Features

- Stream ingest (`ijson`) for large HARs  
- Noise filter (static assets, trackers, `OPTIONS`, non-API MIME)  
- Path templating (`/users/42` → `/users/{id}`)  
- Preferred host (apex HTML) and related same-apex API hosts  
- Response content kinds (json / jsonl / jsonp / csv / html_table / pdf / …)  
- Offline HTML/XML outlines (markdown, tag tree, approx ARIA)  
- Portal brief / story, forms/UI, token correlation & field tracing  
- Initiator trees, param variance, GraphQL, redirects, pagerefs  
- Duplicates, slowest requests, bot-wall detection, capture-quality issues  
- Session reopen after MCP restart; categorized help; tool recommend  
- OpenAPI (with `securitySchemes`), Postman, brief Markdown, urllib stubs  
- Recipe planning with aria-ref steps after goto  
- Three agent modes: archive (HAR file), headless discover, interactive person  
- Optional Playwright capture: doctor, aria refs, screenshot, trace on stop  
- Body backfill for Playwright `content.size == -1` portal XHR  
- Gated live probe via `httpx`

## Tests

```bash
pytest
# Live Playwright tests stay skipped unless:
#   set HARDLY_LIVE_CAPTURE=1
```

### Live soak (public demos, no private HARs)

Headless Chromium captures known public sites on the fly — ASP.NET VIEWSTATE,
HTML forms, login pages, SPAs — then asserts analysis signals. HARs land under
the cache dir and are never committed.

```bash
pip install -e ".[capture]"
playwright install chromium
hardly soak-live --list
hardly soak-live --ids example,wyobiz,countries-gql,jsonplaceholder
hardly soak-live --write-fixtures tmp/live-fixtures
# or: python -m hardly.soak_live
HARDLY_LIVE_CAPTURE=1 pytest tests/test_live_soak.py -q
```

Catalog: `hardly.live_targets` — ASP.NET (`wyobiz`), HTML forms, login,
GraphQL (in-page `fetch` recipe), JSON/OpenAPI. `--write-fixtures` saves small
redacted HTML/JSON snippets (not full HARs) for offline unit tests.
Archive soak against local HARs remains `python scripts/soak.py`.

## Security

HAR files often contain live passwords and session tokens. hardly redacts by
default, but treat captures as secrets: do not commit them, and rotate
credentials if a HAR was shared. Capture writes full bodies into the HAR.
