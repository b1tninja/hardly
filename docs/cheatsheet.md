# hardly cheatsheet

> Purpose: One-page quick reference: modes, first calls, and the tools you reach for most.

## Names tell the effect
`hardly_send_*` sends requests (needs `confirm=true`, otherwise returns a plan), `hardly_write_*`
writes a file (needs `output_path`, refuses to replace unless `overwrite=true`), `hardly_browser_*`
drives a real browser; every other tool only reads loaded data. Merged tools take `sections`, for
example `hardly_auth_report(session_id='S', sections=['credentials','cookies'])`. On the command line the
command is the tool name without `hardly_` (`hardly send entry HAR 12 --confirm`, [cli.md](cli.md)).

## First call
Never Read a raw HAR; index it and query it. `hardly_guide_task_plan(goal="build a client SDK", har_path="/data/a.har")` returns an ordered
plan plus environment state (browser available? sessions open?).

## Pick a mode
| You have | Mode | Entry |
|----------|------|-------|
| a .har file | archive | `hardly_session_open(har_path)` |
| a URL, scriptable page | headless | `hardly_browser_capture_discover(url, analyze=true, channel="chrome", confirm=true)` |
| wall / captcha / MFA / login | interactive | `hardly_browser_start(url, headed=true, channel="chrome")`, ASK THE PERSON, `hardly_browser_stop(open_session=true)` |

After any capture you are in archive mode on the new `session_id`.

## Drill-down order
1. `hardly_session_report(session_id, detail="summary")` - findings with severity, blockers
2. `hardly_session_overview` - note `main_host`; pass it as `host=`
3. `hardly_session_site_brief` (HTML portals) or `hardly_endpoint_list` (JSON APIs)
4. `hardly_session_story`, `hardly_page_forms`, `hardly_entry_outline` - pages and fields
5. `hardly_auth_report(sections=['credentials','patterns'])`, `hardly_session_trace_value` - login and carried tokens
6. `hardly_entry_get(session_id, entry_id)` for one request; `hardly_entry_body_query` for big bodies

## Output
`hardly_client_build(session_id)` returns a Python client as text; `hardly_write_export(session_id, format,
output_path)` writes `openapi`, `postman`, `api_markdown`, `site_brief`, `report`, `client_python` or `plan_steps`.

## Verify
`hardly_entry_dependencies` (offline), `hardly_send_entry_ablation` / `hardly_send_entry_series` (live),
`hardly_spec_contract_check` (spec drift), `hardly_session_compare` (two captures).

## Safety
- Live tools (every `hardly_send_*`, and `hardly_browser_capture_discover`) need `confirm=true`.
  Tell the person what will be sent.
- Gates (bot wall, captcha, paywall, login, rate limit): stop; use interactive
  capture with a person. Never evade, never retry a challenged URL in a loop.
- Secret values are never returned (supply them via overrides / env). Paged tools take `limit` / `offset`.

## Saving
Give an output path to save; otherwise nothing is written.
- `hardly_session_open(har_path)` keeps the index in memory only (gone after a restart; same path = same id).
- `hardly_write_session_copy(session_id, output_path='idx.db', format='index')` saves the index (atomic; refuses an
  existing file unless `overwrite=true`). `hardly_session_open('idx.db')` later reopens it without re-ingesting.
- `format='har'` saves a copy of the source HAR. Captures without `har_output_path` are ephemeral (HAR
  deleted after ingest); pass `har_output_path` to keep it.

## Lost?
`hardly_guide_help(topic)`, `hardly_session_list`, `hardly_session_open` again after a restart,
`hardly_server_status` if a tool is missing.
