# hardly

HAR analysis MCP server and CLI — index, query, document, and probe APIs
**without** loading giant HAR files into the model context.

You *hardly* need the whole file.

## Why

Browser HAR captures are often tens of megabytes. Agents that `Read` them burn
tokens and still miss structure. **hardly** streams a HAR into SQLite once, then
exposes small, redacted, paginated tools over MCP (and a matching CLI).

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

## Agent workflow

Prefer tools over reading the HAR file:

1. `hardly_capabilities` if tools look missing (stale MCP) → restart server  
2. `hardly_open(path)` → `session_id` + counts (`hardly_reopen` after restart)  
3. `hardly_hosts` → note `preferred_host` (apex HTML page, not payment CDNs)  
4. `hardly_endpoints` / `hardly_content` — API surface and payload kinds  
5. HTML portals: `hardly_brief`, then `hardly_story` / `hardly_forms` /
   `hardly_ui` / `hardly_outline` (markdown / tag tree / approx ARIA from HAR
   bodies — do not parse raw HTML in the model)  
6. Tokens: `hardly_correlate` / `hardly_trace` / `hardly_cookies` /
   `hardly_secrets` (names only; values never returned)  
7. Missing detail URLs: `hardly_routes` + `hardly_around(entry_id)` /
   `hardly_tree`  
8. Client sketch: `hardly_stub`; next capture: `hardly_recipe_plan`  
9. Quality: `hardly_wall` / `hardly_issues` / `hardly_coverage` /
   `hardly_diff` vs an earlier session  

Prompts `document_api`, `find_auth_flow`, and `capture_portal` guide those paths.
`hardly_help("portal"|"tokens"|"capture")` and `hardly_recommend` pick tools.

### Record a portal (Playwright)

Cursor’s IDE browser does **not** hand hardly a HAR path. Use Playwright:

1. `hardly_capture_doctor` if `capture_available` is false  
2. `hardly_capture_start(url=…, headed=true, channel="chrome")`  
   (Chrome channel helps on Akamai/bot walls; optional `trace=true`)  
3. Drive UI: `hardly_capture_aria` (`mode=ai`) →
   `hardly_capture_click` / `fill` with `ref` from `refs[]`  
   (fallback: `hardly_capture_elements` → xpath/css, or a person clicks)  
4. `hardly_capture_stop` → `session_id` + analysis hint  
5. Continue with `hardly_brief` / the workflow above  

Capture backfills text/JSON/HTML bodies that Playwright’s HAR recorder often
leaves as `content.size == -1`, so forms and entry tools see portal XHR payloads.

For California county portals, prefer `python -m asspy.sample <county>` (writes
under `$ASSPY_HOME/samples/`).

## MCP tools

| Area | Tools |
|------|--------|
| Session | `capabilities`, `help`, `open`, `reopen`, `list_sessions`, `close` |
| Discovery | `summary`, `stats`, `hosts` (`preferred_host`), `endpoints`, `content`, `search`, `entry`, `compare_entries` |
| Portal / HTML | `brief`, `story`, `forms`, `ui`, `outline`, `pages`, `wall` |
| Tokens | `correlate`, `trace`, `cookies`, `secrets`, `redirects` |
| Structure | `routes`, `around`, `tree`, `params`, `graphql`, `duplicates`, `slow` |
| Quality | `coverage`, `issues`, `diff`, `recommend` |
| Auth / schema | `auth`, `flow`, `schema` |
| Export | `export_md`, `export_openapi`, `export_postman`, `export_brief`, `stub`, `recipe_plan`, `curl`, `sql` |
| Live probe | `probe` (`confirm=true`; secrets only via overrides) |
| Capture | `capture_doctor`, `capture_start` / `stop` / `list` / `status`, `capture_aria`, `capture_screenshot`, `capture_elements`, `capture_click` / `fill` / `press`, `capture_goto` / `url`, `capture_recipe` |

**Token rules:** bodies truncated, secrets redacted, lists paginated. Never
returns the full HAR.

## Capture CLI

```bash
pip install -e ".[capture]"
playwright install chromium   # or HARDLY_BROWSER_CHANNEL=chrome
hardly capture doctor
hardly capabilities           # playwright: {ready, version, hint}

# Interactive: browser opens; press Enter or close the window
hardly capture https://example.com -o D:/code/captures/example.har

# Agent-style: start / aria-ref / stop
hardly capture start https://example.com -o out.har --channel chrome
hardly capture aria                      # YAML + refs[] (mode=ai)
hardly capture click --ref e15
hardly capture fill "EXAMPLE" --ref e12
hardly capture click --xpath '/html/body/div[1]/a[1]'   # fallback
hardly capture recipe steps.json
hardly capture stop                      # optional --trace

# Timed / headless / filtered
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

Maintainer soak against local HARs (paths edited in the script):  
`python scripts/soak.py`

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
- Optional Playwright capture: doctor, aria refs, screenshot, trace on stop  
- Body backfill for Playwright `content.size == -1` portal XHR  
- Gated live probe via `httpx`

## Tests

```bash
pytest
# Live Playwright tests stay skipped unless:
#   set HARDLY_LIVE_CAPTURE=1
```

## Security

HAR files often contain live passwords and session tokens. hardly redacts by
default, but treat captures as secrets: do not commit them, and rotate
credentials if a HAR was shared. Capture writes full bodies into the HAR.
