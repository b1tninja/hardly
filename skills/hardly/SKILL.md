---
name: hardly
description: Analyze HAR files and recorded browser traffic to discover an API, understand a login or session flow, and build a client SDK, OpenAPI spec or request stub. Use when the user asks to read, inspect or summarize a HAR, reverse engineer or discover an API from network traffic, find endpoints, forms, cookies, CSRF tokens or pagination, capture a site with a browser, diagnose why a capture was blocked (bot wall, captcha, rate limit), or verify a generated client. Works through the hardly MCP server or the hardly CLI. Content-neutral; no site-specific logic.
---

# hardly: HAR analysis for building clients

hardly indexes a HAR once into SQLite and answers small, redacted, paged
queries. Use it instead of reading HAR files. Everything is content-neutral:
you supply the site vocabulary, hardly supplies technology detectors.

Prefer the MCP tools (`hardly_*`). If the MCP server is not connected, the same
commands exist on the CLI with the same names: the command is the tool name without `hardly_`
(`hardly session open a.har`, `hardly endpoint list a.har`, `hardly --help`).

Names tell the effect: `hardly_send_*` sends requests (needs `confirm=true`, otherwise returns a plan),
`hardly_write_*` writes a file (needs `output_path`, `overwrite=true` to replace),
`hardly_browser_*` drives a real browser; everything else only reads loaded data. Merged tools take
a `sections` list, for example `hardly_auth_report(session_id, sections=['credentials', 'cookies'])`.

## Start

Call `hardly_guide_task_plan(goal=..., har_path=..., url=...)`. It returns an ordered plan
and whether a browser is available. Then follow the workflow below.

## Workflow

1. Choose a mode:
   - Have a `.har` file: archive. `hardly_session_open(har_path)` returns `session_id`.
   - Have a URL and the page is scriptable: headless.
     `hardly_browser_capture_discover(url, analyze=true, channel="chrome", confirm=true)`.
   - Wall, captcha, MFA or login: interactive. `hardly_browser_start(url,
     headed=true, channel="chrome")`, ask the person to use the window, then
     `hardly_browser_stop(open_session=true)`.
2. Orient: `hardly_session_report(session_id, detail="summary")`, `hardly_session_overview`
   (use `main_host` as `host=`), then `hardly_session_site_brief` for HTML portals or
   `hardly_endpoint_list` for JSON APIs.
3. Drill down: `hardly_session_story`, `hardly_page_forms`, `hardly_entry_outline`,
   `hardly_auth_report(sections=['credentials', 'patterns'])`, `hardly_session_trace_value`,
   `hardly_entry_get`, `hardly_entry_body_query` (large bodies), `hardly_endpoint_schema`,
   `hardly_endpoint_pagination`.
4. Produce output: `hardly_client_build` (Python client as text),
   `hardly_write_export(format='openapi' | 'api_markdown' | 'client_python', output_path=...)`.
   Write files to a scratch directory, not the repo.
5. Verify: `hardly_entry_dependencies` (offline), then `hardly_send_entry_series` or
   `hardly_send_entry_ablation` (live, confirm-gated), `hardly_spec_contract_check`.

## Safety rules

- Never Read a raw HAR file into context.
- Live tools (`hardly_send_entry`, `hardly_send_entry_ablation`, `hardly_send_entry_series`,
  `hardly_send_site_crawl`, `hardly_send_catalog_verify`, `hardly_send_arcgis_explore`,
  `hardly_send_redirect_walk`, `hardly_browser_capture_discover`) send nothing without
  `confirm=true`. Tell the person what will be sent before setting it.
- Gates (bot wall, captcha, proof of work, waiting room, login, paywall, rate
  limit) are stop signs. Do not evade or retry in a loop. Switch to interactive
  capture with a person. See references/gate-policy.md.
- Secret values are never printed. Pass secrets through overrides or env vars.
- Keep outputs small: use `limit`, `offset`, `detail="summary"`.

## When stuck

`hardly_guide_help(topic)`, `hardly_guide_task_plan(goal)`, `hardly_session_list`,
`hardly_session_open` again after a server restart, `hardly_server_status` when a
tool seems missing, `hardly_server_status(sections=['browser_setup'])` when the browser will not start.

## References (read only when needed)

- references/cheatsheet.md: one-page quick reference
- references/concepts.md: sessions, index, redaction, modes
- references/sdk-workflow.md: building a client step by step
- references/capture.md: recording HARs, recipes, environment variables
- references/gate-policy.md: what to do at each kind of gate
- references/reporting.md: the findings report
- references/tools.md: every tool with arguments
- references/cli.md: the same names on the command line
