# hardly

HAR analysis CLI and MCP server. Index a capture into SQLite once, then query
with small, redacted, paginated tools — so agents need hardly any of the raw
file.

Human setup (venv, Docker, Cursor MCP): **[README.md](README.md)**.

## Commands

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -e ".[dev]"
pytest
```

```bash
hardly modes                              # pick archive / headless / interactive
hardly summary path/to/capture.har
hardly endpoints path/to/capture.har --host api.example.com
hardly content path/to/capture.har --host portal.example.com
hardly outline path/to/capture.har 12 --format markdown
hardly export-md path/to/capture.har -o API.md --host api.example.com
hardly capture doctor
hardly capture discover https://example.com --channel chrome
hardly capture https://example.com -o capture.har   # interactive; needs [capture]
hardly serve
```

Docker deploy for Cursor: `powershell -File scripts\deploy-docker.ps1` (see
README). Headed capture needs the **local venv** MCP entry (not Docker).

## Three modes (pick one first)

Call `hardly_modes` / `hardly_mode` (or `hardly modes` / `hardly help-tools archive`):

| Mode | Entry | Prompt |
|------|--------|--------|
| **archive** | `hardly_open` → brief / endpoints | `analyze_har` |
| **headless** | `hardly_discover(url)` (or start headed=false + aria) | `discover_apis` |
| **interactive** | start headed=true channel=chrome → **ASK PERSON** → stop | `capture_portal` |

Rule: HAR path → archive. Scriptable URL → headless. Person / wall / MFA → interactive.
After any capture stop, continue in **archive** mode on the new `session_id`.

## Agent workflow (after a session exists)

Prefer MCP/CLI helpers over reading the HAR:

0. `hardly_capabilities` if tools look missing (stale MCP) -> restart server;
   `hardly_help("modes"|"portal")` / `hardly_recommend` to pick tools
1. `hardly_open` / `hardly summary` -> counts. After MCP restart,
   `hardly_reopen(session_id)` (other tools also auto-reattach from cache)
2. `hardly_hosts` -> use `preferred_host` (apex HTML), not payment/CDN hosts;
   `hardly_endpoints` / `hardly_content` for API surface and payload kinds
3. HTML portals: `hardly_brief` first (includes a credentials summary +
   cookie flags), then `hardly_story` / `hardly_forms` / `hardly_ui` /
   `hardly_outline`. `hardly_forms` labels cover div label/value pairs,
   th/td, dt/dd, bold-cell tables, and `span.base` rows — prefer
   those over scraping bodies. Live tab: `hardly_capture_aria` for
   Playwright accessibility YAML + `refs[]`
4. Credentials / login: `hardly_credentials` for the full map (password +
   username/email pairing, session cookies + HttpOnly/Secure/SameSite flags,
   CSRF, OAuth params, jwt/hex/base64 *shapes*, login_flow — never values).
   Then `hardly_correlate` / `hardly_trace` / `hardly_cookies` /
   `hardly_secrets`; `hardly_redirects` for 3xx. Unsure? `hardly_recommend("…")`
5. Missing detail URL: `hardly_routes` + `handler_functions`, then
   `hardly_tree(entry_id=…)` / `hardly_around(entry_id=…)`. GraphQL:
   `hardly_graphql`. Param drift: `hardly_params`
5b. Landing page, no search form yet: `hardly_find_search(keywords=[...])`
   ranks links (generic signals + your domain terms) and returns a `next_step` click for the next headless hop
6. Client sketch: `hardly_stub`; next capture: `hardly_recipe_plan`
7. After a capture: `hardly_wall` (Akamai/CF), `hardly_issues` /
   `hardly_coverage` if bodies look empty; `hardly_slow` /
   `hardly_duplicates` for odd traffic; `hardly_pages` for pageref groups;
   `hardly_diff` vs an earlier session (includes credentials delta)
8. `hardly_entry` / `hardly_schema` / export — only for needed details

Optional dep for capture: `pip install -e ".[capture]"` +
`playwright install chromium` (or `HARDLY_BROWSER_CHANNEL=chrome`). hardly stays content-neutral (technology helpers and generic
resource kinds only; no site-specific logic). Do not use Cursor's IDE browser
expecting a HAR path.

## Boundaries

- Do **not** load giant HAR bodies into the model. Use summary/endpoints (and
  paginated entry tools) instead of `Read` on the capture.
- Do **not** commit captured HARs. `*.har` is gitignored; treat captures as
  secrets. The checked-in `tests/fixtures/sample.har` is synthetic.
- Live probe (`hardly_probe`) requires explicit confirm; secrets only via
  overrides.
- Capture writes full request/response bodies into the HAR — treat like any
  other secret capture.
- Live Playwright tests require `HARDLY_LIVE_CAPTURE=1`; default CI stays offline.
- Prefer **live soak** over private HAR fixtures when checking stacks:
  `hardly soak-live --list`, then `hardly soak-live` (or
  `python -m hardly.soak_live`). Catalog in `hardly.live_targets` — ASP.NET
  VIEWSTATE (wyobiz), HTML forms, login password fields, SPA, GraphQL
  (`countries-gql` recipe `fetch`), JSON/OpenAPI. Optional
  `--write-fixtures DIR` for small redacted snippets (not full HARs).
  Headless one-shots use in-process `capture_headless` (set
  `HARDLY_CAPTURE_SUBPROCESS=1` only when you need the durable worker + aria RPC).
  In-process recipes support `goto` / `wait` / `click` / `fill` / `fetch` /
  `evaluate`.
- In interactive mode, ask the person — do not claim you can see their screen.
