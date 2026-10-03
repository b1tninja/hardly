# Troubleshooting

> Purpose: Fixes for the problems people hit on first use: missing browser, blocked environments, redirect loops, gates, stale indexes, truncated bodies, slot timeouts and MCP restarts.

Start with `hardly_server_status` (CLI `hardly server status`) and
`hardly_server_status(sections=['browser_setup'])` (CLI `hardly server status --sections browser_setup`):
they report modes, Playwright state and browser builds.

| Symptom | Cause and fix |
|---------|---------------|
| `capture_available` is false, "no browser" | Install the extra and a browser: `pip install -e ".[capture]"` then `playwright install chromium`. Or point at an installed Chrome with `HARDLY_BROWSER_CHANNEL=chrome` or `HARDLY_BROWSER_EXECUTABLE=/path`. The `browser_setup` section shows `mismatch` and `suggested_executable`. |
| Headed capture fails in Docker or over SSH | Headed mode needs a display. Use the local-venv MCP entry for interactive capture; Docker is for offline analysis. |
| Capture error `error_class: environment_blocked` | The sandbox or network blocked egress (proxy-style 403/407, `x-deny-reason`), not the site. Do not treat the site as walled; re-run from another network. See [gate-policy.md](gate-policy.md). |
| `ERR_TOO_MANY_REDIRECTS` / redirect loop | Run `hardly send redirect-walk URL --confirm` (MCP `hardly_send_redirect_walk`, confirm-gated). It follows the chain with and without cookies and shows what differs, usually a missing cookie or a scheme/host bounce. |
| Brief shows a bot wall, captcha or a gate | hardly identifies gates but never evades them. Stop, switch to interactive mode and ask the person, or accept the verdict. See [gate-policy.md](gate-policy.md). |
| Live tool returns "requires confirm=true" | By design. Show the person what will be sent, then repeat with `confirm=true` (CLI `--confirm`). |
| Results look old after upgrading hardly | Unsaved sessions are rebuilt on every open. A saved index from an older build returns `index_outdated`: re-open the original HAR and rewrite the index with `hardly_write_session_copy(session_id, output_path, format='index', overwrite=true)`, or delete the index. |
| Tools missing in the MCP client | The server process is stale. Run `hardly_server_status`, then restart the MCP server. |
| Empty, truncated or `size == -1` bodies | Run `hardly har file-check path.har` (MCP `hardly_har_file_check`), `hardly_session_body_coverage` and `hardly_session_issues`. Re-capture with content (not `omit_content`); hardly backfills Playwright bodies where it can. Bodies are also truncated by design: use `hardly_entry_get` / `hardly_entry_outline` for detail. |
| Slot timeout / capture queue busy | Concurrent captures are limited. Stop unused ones (`hardly capture list`, `hardly browser stop`) or raise `HARDLY_CAPTURE_SLOTS` / `HARDLY_CAPTURE_SLOT_TIMEOUT`. |
| Recipe stopped early | Check `budget` in the result (`HARDLY_CAPTURE_BUDGET`, `budget_seconds` / `--budget-seconds`); skipped steps are listed. |
| A saved index cannot be replaced (Windows `WinError 32`) | Close the session (`hardly_session_close`) first; another process (antivirus, an editor, a second MCP server) holding the file blocks replacing it. Leftover `.hardly-*.tmp` files next to your output file are safe to delete. |
| Where are the files hardly leaves behind? | By default none: give an output path to save, otherwise nothing is written. Only paths you named exist (`output_path` of a `hardly_write_*` tool, `har_output_path` of a capture). Ephemeral captures live briefly in `<tempdir>/hardly-<uid>/ephemeral/` and are deleted after ingest; orphans older than an hour are swept at startup. Nothing is created under the home directory. Files from earlier development versions under `~/.cache/hardly` can be deleted. |
| Session vanished after a restart | Sessions are in memory and never survive a restart. Call `hardly_session_open` again with the same path; save an index with `hardly_write_session_copy(session_id, output_path, format='index')` and reopen that file next time to skip re-ingest. |
| `unknown_session` error | The id is gone (restart, `hardly_session_close`, or an ephemeral capture). Call `hardly_session_open` again with the HAR path - or the saved index path - exactly as before. An ephemeral capture's HAR was deleted: capture again with `har_output_path` (CLI `-o`). |
| `output_exists` error | The output file already exists. Pass `overwrite=true` (CLI `--overwrite`) or choose another path. |
| A capture produced no file | No output path was given, so it was ephemeral (memory only). Pass `har_output_path` (CLI `-o`), or save the session with `hardly_write_session_copy(session_id, output_path, format='index')` before closing it. |
| HAR path not found inside Docker | Host paths must be under the mounted directory (`/workspace/...`); see `HARDLY_PATH_MAP` in [capture.md](capture.md). |
| Tests import the wrong checkout in a worktree | Run `PYTHONPATH=src python -m pytest -q`. |

Still stuck? `hardly_guide_help(topic)` and `hardly_guide_task_plan("what you are trying to do")` suggest tools.
