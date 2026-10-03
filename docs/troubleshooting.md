# Troubleshooting

> Purpose: Fixes for the problems people hit on first use: missing browser, blocked environments, redirect loops, gates, stale indexes, truncated bodies, slot timeouts and MCP restarts.

Start with `hardly_capabilities` (CLI `hardly capabilities`) and `hardly capture doctor`: they report
modes, Playwright state and browser builds.

| Symptom | Cause and fix |
|---------|---------------|
| `capture_available` is false, "no browser" | Install the extra and a browser: `pip install -e ".[capture]"` then `playwright install chromium`. Or point at an installed Chrome with `HARDLY_BROWSER_CHANNEL=chrome` or `HARDLY_BROWSER_EXECUTABLE=/path`. `hardly capture doctor` shows `mismatch` and `suggested_executable`. |
| Headed capture fails in Docker or over SSH | Headed mode needs a display. Use the local-venv MCP entry for interactive capture; Docker is for offline analysis. |
| Capture error `error_class: environment_blocked` | The sandbox or network blocked egress (proxy-style 403/407, `x-deny-reason`), not the site. Do not treat the site as walled; re-run from another network. See [gate-policy.md](gate-policy.md). |
| `ERR_TOO_MANY_REDIRECTS` / redirect loop | Run `hardly redirect-diag URL --yes` (MCP `hardly_redirect_diag`, confirm-gated). It follows the chain with and without cookies and shows what differs, usually a missing cookie or a scheme/host bounce. |
| Brief shows a bot wall, captcha or `gates` | hardly identifies gates but never evades them. Stop, switch to interactive mode and ask the person, or accept the verdict. See [gate-policy.md](gate-policy.md). |
| Live tool returns "requires confirm=true" | By design. Show the person what will be sent, then repeat with `confirm=true` (CLI `--yes`). |
| Results look old after upgrading hardly | A cached index older than `INDEX_VERSION` rebuilds automatically on open. Force with `hardly_open(path, force=true)` or delete the session files under the cache dir. |
| Tools missing in the MCP client | The server process is stale. Run `hardly_capabilities`, then restart the MCP server. |
| Empty, truncated or `size == -1` bodies | Run `hardly har-doctor path.har`, `hardly_coverage` and `hardly_issues`. Re-capture with content (not `--omit-content`); hardly backfills Playwright bodies where it can. Bodies are also truncated by design: use `hardly_entry` / `hardly_outline` for detail. |
| Slot timeout / capture queue busy | Concurrent captures are limited. Stop unused ones (`hardly capture list`, `hardly capture stop`) or raise `HARDLY_CAPTURE_SLOTS` / `HARDLY_CAPTURE_SLOT_TIMEOUT`. |
| Recipe stopped early | Check `budget` in the result (`HARDLY_CAPTURE_BUDGET`, `--budget`); skipped steps are listed. |
| Cache looks stale, half-written or locked (Windows `WinError 32`) | Caches are written atomically and opened read-only, so a crash should not corrupt one. Close the session (`hardly_close`) and run `hardly_open(path, force=true)`; leftover `.hardly-*.tmp` files in the cache dir are safe to delete. Another process (antivirus, an editor, a second MCP server) holding the `.db` blocks replacing it: close it or set a different `HARDLY_CACHE_DIR`. |
| Cache directory is read-only | Opening an existing cache works read-only. Building a new one needs a writable dir: set `HARDLY_CACHE_DIR`, or use `storage=memory` (`HARDLY_INDEX=memory`) which writes nothing. |
| Session vanished after a restart and `hardly_reopen` fails | It was opened with `storage=memory` (or `HARDLY_INDEX=memory/auto`), which is never cached. Call `hardly_open(har_path)` again, or `hardly_persist(session_id)` beforehand. |
| Unknown `session_id` after an MCP restart | Call `hardly_reopen(session_id)`; most tools also reattach from the cache. `hardly_list_sessions` lists known sessions. |
| HAR path not found inside Docker | Host paths must be under the mounted directory (`/workspace/...`); see `HARDLY_PATH_MAP` in [capture.md](capture.md). |
| Tests import the wrong checkout in a worktree | Run `PYTHONPATH=src python -m pytest -q`. |

Still stuck? `hardly_help(topic)` and `hardly_recommend("what you are trying to do")` suggest tools.
