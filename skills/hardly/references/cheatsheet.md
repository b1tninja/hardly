# hardly cheatsheet

> Purpose: One-page quick reference: modes, first calls, and the tools you reach for most.

Content-neutral HAR analysis. Never Read a raw HAR; index it and query it.

## First call
`hardly_guide_task_plan(goal="build a client SDK", har_path="/data/a.har")` returns an ordered
plan plus environment state (browser available? sessions open?).

## Pick a mode
| You have | Mode | Entry |
|----------|------|-------|
| a .har file | archive | `hardly_session_open(har_path)` |
| a URL, scriptable page | headless | `hardly_browser_capture_discover(url, channel="chrome")` |
| wall / captcha / MFA / login | interactive | `hardly_browser_start(url, headed=true, channel="chrome")`, ASK THE PERSON, `hardly_browser_stop(open_session=true)` |

After any capture you are in archive mode on the new `session_id`.

## Drill-down order
1. `hardly_session_report(session_id, detail="summary")` - evidence index, blockers
2. `hardly_session_overview` - note `preferred_host`; pass it as `host=`
3. `hardly_session_site_brief` (HTML portals) or `hardly_endpoint_list` (JSON APIs)
4. `hardly_session_story`, `hardly_page_forms`, `hardly_entry_outline` - pages and fields
5. `hardly_auth_report`, `hardly_session_trace_value`, `hardly_session_trace_value` - login and carried tokens
6. `hardly_entry_get(entry_id)` for one request; `hardly_entry_body_query` for big bodies

## Output
`hardly_client_build` (Python client), `hardly_write_export`, `hardly_write_export`,
`hardly_write_export`, `hardly_write_export`. Use `output_path` in a scratch dir.

## Verify
`hardly_entry_dependencies` (offline dependencies), `hardly_send_entry_ablation` / `hardly_send_entry_series`
(live), `hardly_spec_contract_check` (spec drift), `hardly_session_compare` (two captures).

## Safety
- Live tools need `confirm=true`: probe, crawl, replay_check, flow_replay,
  catalog_verify, arcgis_explore, redirect_diag. Tell the person what will be sent.
- Gates (bot wall, captcha, paywall, login, rate limit): stop; use interactive
  capture with a person. Never evade, never retry a challenged URL in a loop.
- Secret values are never returned. Supply secrets via overrides / env only.
- Paged tools take `limit` / `offset`; keep `limit` small.

## Saving
Give an output path to save; otherwise nothing is written.
- `hardly_session_open(path)` keeps the index in memory only; the session is gone after `hardly_session_close` or a
  restart (repeat `hardly_session_open`). Same path again = same session id, no re-ingest.
- `hardly_session_open(path, output_path='idx.db')` also saves the index (atomic; refuses an existing file
  unless `overwrite=true`). `hardly_session_open('idx.db')` later reopens it without re-ingesting.
- `hardly_write_session_copy(session_id, output_path)` saves a copy of the source HAR.
- Captures without `har_path` are ephemeral (HAR deleted after ingest); pass `har_path` to keep it.

## Lost?
`hardly_guide_help(topic)`, `hardly_guide_task_plan(goal)`, `hardly_session_list`,
`hardly_session_open` again after an MCP restart, `hardly_server_status` if a tool is missing.
