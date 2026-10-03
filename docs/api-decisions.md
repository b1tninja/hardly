# API decisions: how the v1 vocabulary was chosen

> Purpose: Decision record for the v1 tool, CLI and parameter names: principles, the evidence behind them, and the old to new name table.

hardly had 97 MCP tools whose names grew by accretion. Before the first release they were replaced by
71 names chosen against one question: *given only the names, does a model pick the right tool for a
task?* The result is frozen by `tests/api_surface.json` and `tests/cli_surface.json`
([api-stability.md](api-stability.md)). Nothing had been published, so no aliases exist.

## Principles

1. **Effect markers.** The first word says what the tool does outside the loaded data: `send_`
   sends requests to a real server (always `confirm`, plan only without it), `write_` creates a
   file (always `output_path`/`output_dir`, `overwrite=false` by default), `browser_` needs or
   drives a real browser. No marker means read-only. Every `send_` tool has an offline twin
   (`session_redirect_history` / `send_redirect_walk`, `endpoint_arcgis` / `send_arcgis_explore`).
2. **Closed verb vocabulary.** `open`/`close`, `get`, `list`, `search`, `check`, `compare`,
   `build`, `plan`, `query`, `trace`, and one detector word (`gate_bot_protection`). A new verb or
   marker needs this document to change first.
3. **Noun first, grouped.** `<object>_<view>`: `session_`, `entry_`, `endpoint_`, `page_`, `auth_`,
   `gate_`, `tech_`, `spec_`, `har_`, `catalog_`, `capture_`, `client_`, `guide_`, `server_`.
   At most three words after `hardly_`. A name must work without alphabetical neighbours.
4. **Name the output, never a container.** The last word is what comes back (`overview` = counts,
   `traffic_stats` = distributions, `story` = narrative, `timeline` = ordered list, `report` =
   findings, `site_brief` = digest). `health`, `context`, `summary` and `detect` as umbrellas are
   banned.
5. **The `sections` rule.** A tool takes `sections` only when (a) its name already names the common
   subject, (b) all sections take the same selectors, (c) sections never cross the effect boundary.
   Different output kind or different question means a separate tool. A scalar enum (`format`,
   `action`) is allowed for artefact kinds and single operations on a target.
6. **Parameter vocabulary.** One name per concept: `session_id`, `other_session_id`, `capture_id`;
   `har_path(s)`, `spec_path`, `catalog_path`, `url`; `output_path`/`output_dir` + `overwrite`;
   `host`; `entry_id(s)`/`other_entry_id`; `limit`/`offset` and `max_*` caps; `confirm`;
   `exclude_noise` (true by default); native JSON lists and objects, never `*_json` strings.
7. **Units in the name.** Durations are seconds: `timeout_seconds`, `delay_seconds`,
   `wait_seconds`, `min_elapsed_seconds`. No `_ms`, `_s` or bare `timeout`.
8. **Null for unset.** Omit the key or pass `null`; never `""`, `0` or `-1` as "not set".
9. **CLI mirrors tools.** `hardly <group> <command>` is the tool name without `hardly_`, split at
   the first underscore, hyphens for the rest; flags are the parameter names ([cli.md](cli.md)).

## Evidence (summary)

Each candidate scheme renamed or merged the same capabilities. Respondents saw only the tool names
(randomised order) and a task description, and chose a tool; about 2000 answers were scored across
two model tiers, four runs per scheme.

| Scheme (names only) | Tool-choice accuracy |
|---|---|
| Current names (97 tools) | 73% |
| A | 78% |
| D (58 tools) | 81% |
| B | 84% |
| C | 88% |
| Final scheme (71 tools) | 88% |

With a one-line description beside each name, every scheme reached about 100%: names matter most
for the first guess, descriptions repair the rest. Lessons that shaped the final scheme:

- **Merging hides capabilities when the merged name is generic.** A generic container
  (`tech_detect`, `session_health`, `session_summary`) scored 17-50%
  on the capabilities folded into it, against 83-100% when each had its own name. The final scheme
  un-merged those (`endpoint_arcgis`, `session_timeline`, `session_body_coverage`...) and kept only
  merges whose name carries the subject (`auth_report`, `gate_bot_protection`, `page_ui`).
- **Live tools must be marked in the name.** With `send_`/`write_`/`browser_` first, live-action
  tasks were answered correctly 98% of the time (current names 64%).
- **Random catalogue order costs ten points** versus alphabetical order, so a name cannot lean on
  its neighbours: each carries its own subject and kind.
- **Orientation tools were confused in every scheme** (56-79%). The fix was distinct output kinds
  in the names, not better synonyms.
- Words that appear in task texts (`target`, `url`, `paging`, `summary`, `goal`) leak the answer and
  were avoided in names.

## Merges: old to new

43 old tools were folded into 17 tools; the section or value that selects the old behaviour is shown.

| Old tools | New tool | Selector |
|---|---|---|
| `auth`, `auth_patterns`, `credentials`, `secrets`, `cookies` | `auth_report` | `sections` quick, patterns, credentials, secret_names, cookies |
| `challenges`, `gates`, `wall` | `gate_bot_protection` | `sections` http_challenges, barriers, bot_protection |
| `ui`, `find_search` | `page_ui` | `sections` links, handlers, labels, search_links |
| `routes`, `data_attrs` | `page_embedded_routes` | `sections` script_routes, data_attrs |
| `schema`, `params` | `endpoint_schema` | `sections` schema, param_roles |
| `stack`, `grids` | `tech_stack` | data grids under `data_grids` |
| `summary`, `hosts` | `session_overview` | hosts are part of the counts |
| `stats`, `content` | `session_traffic_stats` | `kind` filters `payload_kinds` |
| `trace`, `correlate` | `session_trace_value` | no `name`/`value` lists reused values |
| `capabilities`, `capture_doctor` | `server_status` | `sections` capabilities, browser_setup |
| `modes`, `mode` | `guide_mode` | `mode` omitted lists the modes |
| `start`, `recommend` | `guide_task_plan` | `goal` |
| `capture_once`, `discover` | `browser_capture_discover` | `analyze` false / true |
| `capture_url`, `capture_elements`, `capture_aria` | `browser_inspect` | `sections` url, elements, aria |
| `capture_goto`, `capture_click`, `capture_fill`, `capture_press` | `browser_interact` | `action` goto, click, fill, press |
| `capture_list`, `capture_status` | `capture_list` | `capture_id` |
| `export_openapi`, `export_postman`, `export_md`, `export_brief` | `write_export` | `format` openapi, postman, api_markdown, site_brief |

`write_export` also writes `report`, `client_python` and `plan_steps`; `write_session_copy` replaces
`export_har` and the index half of `open(output_path=...)` (`format` har or index).

## Renames: old to new

| Old | New | Old | New | Old | New |
|---|---|---|---|---|---|
| `open` | `session_open` | `close` | `session_close` | `list_sessions` | `session_list` |
| `help` | `guide_help` | `capture_start` | `browser_start` | `capture_stop` | `browser_stop` |
| `capture_recipe` | `browser_run_steps` | `capture_screenshot` | `write_screenshot` | `recipe_plan` | `session_plan_steps` |
| `export_har` | `write_session_copy` | `coverage` | `session_body_coverage` | `issues` | `session_issues` |
| `duplicates` | `session_duplicates` | `slow` | `session_slow_requests` | `report` | `session_report` |
| `brief` | `session_site_brief` | `story` | `session_story` | `flow` | `session_timeline` |
| `redirects` | `session_redirect_history` | `sql` | `session_sql` | `diff` | `session_compare` |
| `forms` | `page_forms` | `pages` | `page_list` | `tables` | `page_tables` |
| `endpoints` | `endpoint_list` | `graphql` | `endpoint_graphql` | `streams` | `endpoint_streams` |
| `pagination` | `endpoint_pagination` | `arcgis` | `endpoint_arcgis` | `search` | `entry_search` |
| `entry` | `entry_get` | `around` | `entry_around` | `tree` | `entry_initiators` |
| `compare_entries` | `entry_compare` | `curl` | `entry_build_curl` | `body_query` | `entry_body_query` |
| `outline` | `entry_outline` | `flow_graph` | `entry_dependencies` | `contract_check` | `spec_contract_check` |
| `stub` | `client_build` | `har_doctor` | `har_file_check` | `har_prune` | `write_har_pruned` |
| `har_scrub` | `write_har_scrubbed` | `har_split` | `write_har_split` | `har_merge` | `write_har_merged` |
| `catalog_upsert` | `write_catalog_record` | `catalog_verify` | `send_catalog_verify` | `probe` | `send_entry` |
| `replay_check` | `send_entry_ablation` | `flow_replay` | `send_entry_series` | `crawl` | `send_site_crawl` |
| `arcgis_explore` | `send_arcgis_explore` | `redirect_diag` | `send_redirect_walk` |  |  |

Unchanged: `capture_list`, `catalog_list`. Old tools had the `hardly_` prefix. Parameter renames
(`src`->`har_path`, `top`->`limit`, `timeout_ms`->`timeout_seconds`, `*_json`->native, `dry_run`
removed, `--yes`->`--confirm`) follow the parameter vocabulary above; the current signatures are in [tools.md](tools.md).
