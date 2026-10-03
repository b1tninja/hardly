# Integration notes: capture robustness

Core logic lives in `capture.py`, `capture_worker.py`, and new modules
`core/slots.py`, `core/noise_hosts.py`, `core/capture_errors.py`,
`core/browser_detect.py`. Wiring still to do in the files that are off limits
here (server.py, cli.py, docs).

## 1. server.py (MCP tools)

### hardly_discover
Add two params after `brief`, pass through to `discover_apis`:

```python
def hardly_discover(
    url: str,
    wait_seconds: float = 5,
    har_path: str = "",
    channel: str = "",
    url_filter: str = "",
    recipe_json: str = "",
    open_session: bool = True,
    brief: bool = True,
    budget_seconds: float = 0,      # NEW (0 = use HARDLY_CAPTURE_BUDGET / none)
    block_noise: bool = False,      # NEW
) -> str:
    ...
    discover_apis(..., budget_seconds=(budget_seconds or None), block_noise=block_noise)
```

Docstring lines to add:

```
budget_seconds (or env HARDLY_CAPTURE_BUDGET) is a hard per-call budget: once
exceeded, remaining recipe steps are skipped, the HAR is still written, and
the result has budget={limit_s, used_s, exceeded, skipped_steps}.
block_noise=true aborts analytics/ads/font/map-tile/heavy-media requests
(result: blocked_requests, blocked_hosts); default off - can break sites.
Concurrent captures queue on a cross-process slot limiter
(HARDLY_CAPTURE_SLOTS, default 4); results include slot={waited_s,
queue_depth, slot}. Errors carry error_class / error_advice.
```

### hardly_capture_start
Add `block_noise: bool = False` (only meaningful for `headed=false`) and pass
`start_capture(..., block_noise=block_noise)`. Docstring: "Waits for a capture
slot (HARDLY_CAPTURE_SLOTS); the worker holds it until the capture stops.
Result carries `slot`."

### Other
* Any tool that wraps `capture_for` may pass `budget_seconds` / `block_noise`
  (both new optional kwargs on `capture_for`, headless in-process path only).
* Error handling: `CaptureError.to_dict()` returns
  `{"status": "error", "error", "error_class", "error_retryable", "error_advice"}`.
  `_err(exc)` for `CaptureError` can merge that dict. `CaptureError` messages
  from `capture_headless` / `start_capture` already end with
  `[error_class=...] <advice>`.
* Optional new tool `hardly_capture_slots()` -> `core.slots.slot_status()`
  (`{slots, in_use, waiting, unlimited}`); `capture doctor` can include it too.
* `playwright_status()` new keys (flow through `capture doctor` / capabilities
  unchanged): `installed_builds`, `expected_build`, `mismatch`,
  `suggested_executable`, `browser_executable_source`
  (`env|autodetect|playwright|channel`), `pin_hint`, `browser_executable`.

## 2. cli.py

In `_add_capture_flags` (applies to run/start/discover):

```python
p.add_argument("--budget", type=float, default=None, metavar="SECONDS",
               help="Hard per-call budget (headless): skip remaining recipe steps "
                    "once exceeded; env HARDLY_CAPTURE_BUDGET")
p.add_argument("--block-noise", action="store_true",
               help="Headless: abort analytics/ads/fonts/map tiles/heavy media")
p.add_argument("--slot-timeout", type=float, default=None, metavar="SECONDS",
               help="Max wait for a capture slot (env HARDLY_CAPTURE_SLOT_TIMEOUT, default 300)")
```

Mapping in `cmd_capture`:

| arg | kwarg |
|---|---|
| `args.budget` | `budget_seconds=` on `discover_apis`, `capture_for` (headless) |
| `args.block_noise` | `block_noise=` on `discover_apis`, `capture_for`, `start_capture` |
| `args.slot_timeout` | `slot_timeout_s=` on `start_capture` / `capture_headless` (set `HARDLY_CAPTURE_SLOT_TIMEOUT` env for `discover_apis`/`capture_for`, which do not take it) |

`capture_interactive` and `start_capture` take the slot internally; interactive
captures therefore hold a slot for the whole session.

## 3. docs/capture.md - env vars

| Var | Default | Meaning |
|---|---|---|
| `HARDLY_CAPTURE_SLOTS` | `4` | Max concurrent browser captures across processes (file locks under `<cache>/slots/`). `0` or negative = unlimited. |
| `HARDLY_CAPTURE_SLOT_TIMEOUT` | `300` | Seconds to wait for a slot before failing with "waited Ns for a capture slot; N running". `0` = fail immediately. |
| `HARDLY_CAPTURE_BUDGET` | unset | Default per-call hard budget (seconds) for headless capture/discover; measured after the slot is acquired. |
| `HARDLY_BROWSER_EXECUTABLE` | unset | Chromium binary to launch (wins over autodetect/channel). If set to a missing file it is NOT silently replaced. |
| `PLAYWRIGHT_BROWSERS_PATH` | unset | First root scanned when Playwright's own chromium is missing; then `/opt/pw-browsers`, `~/.cache/ms-playwright`. |

Doctor semantics: `mismatch: true` means installed chromium builds exist but
not the build the installed Playwright expects (autodetect then launches the
installed one). Known mapping only: chromium build 1194 <-> playwright 1.56.x;
others are reported `unknown`.

Result shapes: `slot: {waited_s, queue_depth, slot}`;
`budget: {limit_s, used_s, exceeded, skipped_steps}`;
`blocked_requests`, `blocked_hosts`; `error_class` in
`environment_blocked|transient|cert|dns|timeout|refused|unknown`, plus
`error_retryable`, `error_advice` (also on recipe step errors).
A capture that ends without a HAR is `status: "error"`, `har_exists: false`.
