---
name: hardly
description: Analyze HAR files and recorded browser traffic to discover an API, understand a login or session flow, and build a client SDK, OpenAPI spec or request stub. Use when the user asks to read, inspect or summarize a HAR, reverse engineer or discover an API from network traffic, find endpoints, forms, cookies, CSRF tokens or pagination, capture a site with a browser, diagnose why a capture was blocked (bot wall, captcha, rate limit), or verify a generated client. Works through the hardly MCP server or the hardly CLI. Content-neutral; no site-specific logic.
---

# hardly: HAR analysis for building clients

hardly indexes a HAR once into SQLite and answers small, redacted, paged
queries. Use it instead of reading HAR files. Everything is content-neutral:
you supply the site vocabulary, hardly supplies technology detectors.

Prefer the MCP tools (`hardly_*`). If the MCP server is not connected, the same
commands exist on the CLI (`hardly brief a.har`, `hardly --help`).

## Start

Call `hardly_start(goal=..., har_path=..., url=...)`. It returns an ordered plan
and whether a browser is available. Then follow the workflow below.

## Workflow

1. Choose a mode:
   - Have a `.har` file: archive. `hardly_open(har_path)` returns `session_id`.
   - Have a URL and the page is scriptable: headless.
     `hardly_discover(url, channel="chrome")`.
   - Wall, captcha, MFA or login: interactive. `hardly_capture_start(url,
     headed=true, channel="chrome")`, ask the person to use the window, then
     `hardly_capture_stop(open_session=true)`.
2. Orient: `hardly_report(session_id, detail="summary")`, `hardly_hosts` (use
   `preferred_host` as `host=`), then `hardly_brief` for HTML portals or
   `hardly_endpoints` for JSON APIs.
3. Drill down: `hardly_story`, `hardly_forms`, `hardly_outline`,
   `hardly_credentials`, `hardly_correlate`, `hardly_trace`, `hardly_entry`,
   `hardly_body_query` (large bodies), `hardly_schema`, `hardly_pagination`.
4. Produce output: `hardly_stub` (Python client), `hardly_export_openapi`,
   `hardly_export_md`. Write files to a scratch directory, not the repo.
5. Verify: `hardly_flow_graph` (offline), then `hardly_flow_replay` or
   `hardly_replay_check` (live, confirm-gated), `hardly_contract_check`.

## Safety rules

- Never Read a raw HAR file into context.
- Live tools (`probe`, `crawl`, `replay_check`, `flow_replay`, `catalog_verify`,
  `arcgis_explore`, `redirect_diag`) send nothing without `confirm=true`. Tell the
  person what will be sent before setting it.
- Gates (bot wall, captcha, proof of work, waiting room, login, paywall, rate
  limit) are stop signs. Do not evade or retry in a loop. Switch to interactive
  capture with a person. See references/gate-policy.md.
- Secret values are never printed. Pass secrets through overrides or env vars.
- Keep outputs small: use `limit`, `offset`, `detail="summary"`.

## When stuck

`hardly_help(topic)`, `hardly_recommend(goal)`, `hardly_list_sessions`,
`hardly_reopen(session_id)` after a server restart, `hardly_capabilities` when a
tool seems missing, `hardly_capture_doctor` when the browser will not start.

## References (read only when needed)

- references/cheatsheet.md: one-page quick reference
- references/concepts.md: sessions, index, redaction, modes
- references/sdk-workflow.md: building a client step by step
- references/capture.md: recording HARs, recipes, environment variables
- references/gate-policy.md: what to do at each kind of gate
- references/reporting.md: the evidence index
- references/tools.md: every tool with arguments
