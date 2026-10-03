# hardly cheatsheet

> Purpose: One-page quick reference: modes, first calls, and the tools you reach for most.

Content-neutral HAR analysis. Never Read a raw HAR; index it and query it.

## First call
`hardly_start(goal="build a client SDK", har_path="/data/a.har")` returns an ordered
plan plus environment state (browser available? sessions open?).

## Pick a mode
| You have | Mode | Entry |
|----------|------|-------|
| a .har file | archive | `hardly_open(har_path)` |
| a URL, scriptable page | headless | `hardly_discover(url, channel="chrome")` |
| wall / captcha / MFA / login | interactive | `hardly_capture_start(url, headed=true, channel="chrome")`, ASK THE PERSON, `hardly_capture_stop(open_session=true)` |

After any capture you are in archive mode on the new `session_id`.

## Drill-down order
1. `hardly_report(session_id, detail="summary")` - evidence index, blockers
2. `hardly_hosts` - note `preferred_host`; pass it as `host=`
3. `hardly_brief` (HTML portals) or `hardly_endpoints` (JSON APIs)
4. `hardly_story`, `hardly_forms`, `hardly_outline` - pages and fields
5. `hardly_credentials`, `hardly_correlate`, `hardly_trace` - login and carried tokens
6. `hardly_entry(entry_id)` for one request; `hardly_body_query` for big bodies

## Output
`hardly_stub` (Python client), `hardly_export_openapi`, `hardly_export_md`,
`hardly_export_postman`, `hardly_export_brief`. Use `output_path` in a scratch dir.

## Verify
`hardly_flow_graph` (offline dependencies), `hardly_replay_check` / `hardly_flow_replay`
(live), `hardly_contract_check` (spec drift), `hardly_diff` (two captures).

## Safety
- Live tools need `confirm=true`: probe, crawl, replay_check, flow_replay,
  catalog_verify, arcgis_explore, redirect_diag. Tell the person what will be sent.
- Gates (bot wall, captcha, paywall, login, rate limit): stop; use interactive
  capture with a person. Never evade, never retry a challenged URL in a loop.
- Secret values are never returned. Supply secrets via overrides / env only.
- Paged tools take `limit` / `offset`; keep `limit` small.

## Storage
- Default `disk`: cached, `hardly_reopen` works after a restart. For sensitive HARs use
  `hardly_open(path, storage='memory')` (or `HARDLY_INDEX=memory`): nothing derived is written to
  disk, the session vanishes on restart. `hardly_persist(session_id)` saves it if you need to keep it.

## Lost?
`hardly_help(topic)`, `hardly_recommend(goal)`, `hardly_list_sessions`,
`hardly_reopen(session_id)` after an MCP restart, `hardly_capabilities` if a tool is missing.
