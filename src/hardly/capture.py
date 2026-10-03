"""Spawn a browser and record a HAR 1.2 session.

Internal: not part of the public API (see docs/api-stability.md); use the ``hardly_browser_*``
tools or ``hardly browser`` commands.

Uses Playwright's built-in ``record_har_path``. The browser runs in a
**subprocess** (``python -m hardly.capture_worker``) so recording survives
after the CLI / MCP call returns. Optional dependency:
``pip install -e ".[capture]"`` then ``playwright install chromium``.

Control files under ``<tempdir>/hardly-<uid>/captures/active/``:

- ``{id}.json`` — status
- ``{id}.stop`` — request stop
- ``{id}.cmd`` — commands (``goto <url>``)
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from hardly.core.browser_detect import (
    expected_chromium_build,
    pick_executable,
    pin_hint,
    scan_chromium_builds,
)
from hardly.core.capture_errors import TRANSIENT_NAV, with_error_class
from hardly.core.slots import SlotTimeoutError, acquire_slot, capture_slot
from hardly.ephemeral import (
    INTERACTIVE_WARNING,
    KEEP_HINT,
    is_ephemeral_path,
    new_ephemeral_har,
    secure_file,
)
from hardly.ephemeral import discard as discard_ephemeral
from hardly.session import resolve_path

_BANNER_JS = """
(() => {
  if (window.__hardlyRecordingBanner) return;
  window.__hardlyRecordingBanner = true;
  const bar = document.createElement('div');
  bar.id = 'hardly-recording-banner';
  bar.textContent = 'hardly: recording network — close this window or stop the capture when done';
  Object.assign(bar.style, {
    position: 'fixed', top: '0', left: '0', right: '0', zIndex: '2147483647',
    background: '#1a1a2e', color: '#eaeaea', font: '12px/1.4 system-ui,sans-serif',
    padding: '6px 12px', textAlign: 'center', opacity: '0.92',
    pointerEvents: 'none',
  });
  const mount = () => {
    if (!document.body) return;
    if (!document.getElementById('hardly-recording-banner'))
      document.body.prepend(bar);
  };
  if (document.readyState === 'loading')
    document.addEventListener('DOMContentLoaded', mount);
  else mount();
})();
"""

# Force target=_blank / window.open into the current tab so one window stays
# under the Playwright context (and the recording banner stays visible).
_SAME_TAB_JS = """
(() => {
  if (window.__hardlySameTab) return;
  window.__hardlySameTab = true;
  const navigate = (url) => {
    if (!url || url === 'about:blank') return false;
    try { window.location.assign(url); return true; }
    catch (e) { return false; }
  };
  window.open = function (url, name, features) {
    if (navigate(url)) return window;
    // Common pattern: open about:blank then set location on the handle.
    const loc = {
      get href() { return window.location.href; },
      set href(u) { navigate(u); },
      assign(u) { navigate(u); },
      replace(u) { navigate(u); },
      toString() { return window.location.href; },
    };
    return {
      closed: false,
      close() {},
      focus() {},
      blur() {},
      get location() { return loc; },
      set location(u) { if (typeof u === 'string') navigate(u); },
      document: { write() {}, writeln() {}, close() {}, open() {} },
    };
  };
  document.addEventListener('click', (e) => {
    const el = e.target && e.target.closest
      ? e.target.closest('a[target="_blank"], area[target="_blank"]')
      : null;
    if (el) el.setAttribute('target', '_self');
  }, true);
})();
"""


class CaptureError(RuntimeError):
    """Browser capture failed or Playwright is not installed."""

    #: Set (opt-in ``diagnose_redirects``) when the failure was a redirect loop.
    redirect_diagnosis: dict[str, Any] | None = None

    @property
    def classification(self) -> dict[str, Any]:
        from hardly.core.capture_errors import classify_capture_error

        return classify_capture_error(str(self))

    def to_dict(self) -> dict[str, Any]:
        """Error dict with ``error_class`` / ``error_advice`` for tool results."""
        out = with_error_class({"status": "error", "error": str(self)})
        if self.redirect_diagnosis:
            out["redirect_diagnosis"] = self.redirect_diagnosis
        return out


@dataclass
class CaptureHandle:
    """Lightweight view of a capture (subprocess-owned)."""

    capture_id: str
    har_path: Path
    url: str
    headed: bool
    channel: str = ""
    url_filter: str = ""
    omit_content: bool = False
    label: str = ""
    status: str = "starting"
    error: str = ""
    started_at: float = 0.0
    stopped_at: float | None = None
    entry_count_hint: int | None = None
    pid: int | None = None


def playwright_available() -> bool:
    """True when the ``playwright`` package imports (browsers may still be missing)."""
    try:
        import playwright  # noqa: F401

        return True
    except ImportError:
        return False


def playwright_status() -> dict[str, Any]:
    """Diagnose the optional Playwright stack for agents and ``capture doctor``.

    Distinguishes package-missing vs browser-binary-missing — the usual
    failure after ``pip install -e ".[capture]"`` without ``playwright install``.
    """
    out: dict[str, Any] = {
        "package": False,
        "version": None,
        "ready": False,
        "browsers": {},
        "features": {
            "record_har": False,
            "aria_snapshot": False,
            "aria_mode_ai": False,
        },
        "env": {
            "HARDLY_BROWSER_CHANNEL": default_channel() or None,
            "HARDLY_BROWSER_EXECUTABLE": (
                os.environ.get("HARDLY_BROWSER_EXECUTABLE") or None
            ),
        },
        "installed_builds": [],
        "expected_build": None,
        "mismatch": False,
        "suggested_executable": None,
        "browser_executable_source": None,
        "pin_hint": None,
        "install": [
            'pip install -e ".[capture]"',
            "playwright install chromium",
        ],
        "hint": None,
    }
    try:
        import playwright
        from playwright.sync_api import sync_playwright
    except ImportError:
        out["hint"] = (
            'Playwright package missing. Run: pip install -e ".[capture]" '
            "&& playwright install chromium"
        )
        return out

    out["package"] = True
    try:
        from importlib.metadata import version as pkg_version

        out["version"] = pkg_version("playwright")
    except Exception:  # noqa: BLE001
        out["version"] = getattr(playwright, "__version__", None)
    out["features"]["record_har"] = True
    # aria_snapshot: 1.49+; mode="ai" (refs): 1.59+
    parts = _version_tuple(out["version"])
    out["features"]["aria_snapshot"] = parts >= (1, 49)
    out["features"]["aria_mode_ai"] = parts >= (1, 59)

    browsers: dict[str, Any] = {}
    try:
        with sync_playwright() as pw:
            for name in ("chromium", "firefox", "webkit"):
                browser_type = getattr(pw, name, None)
                if browser_type is None:
                    continue
                exe = None
                try:
                    exe = browser_type.executable_path
                except Exception:  # noqa: BLE001
                    exe = None
                present = bool(exe and Path(str(exe)).is_file())
                browsers[name] = {
                    "executable": str(exe) if exe else None,
                    "installed": present,
                }
    except Exception as exc:  # noqa: BLE001
        out["hint"] = (
            f"Playwright imported but failed to start driver ({exc}). "
            "Try: playwright install chromium"
        )
        out["browsers"] = browsers
        _annotate_browser_detection(out, chromium_ok=False, channel=default_channel())
        return out

    out["browsers"] = browsers
    chromium_ok = bool((browsers.get("chromium") or {}).get("installed"))
    channel = default_channel()
    _annotate_browser_detection(out, chromium_ok=chromium_ok, channel=channel)
    exe_override = bool(out.get("browser_executable_source") in ("env", "autodetect"))
    exe_ok = exe_override and bool(out.get("suggested_executable"))
    # channel=chrome uses system Chrome - no playwright browser download needed
    out["ready"] = chromium_ok or bool(channel) or exe_ok
    out["browser_executable"] = out["suggested_executable"] if exe_ok else None
    if not out["ready"]:
        out["hint"] = (
            "Chromium browser binary missing. Run: playwright install chromium "
            "(or set HARDLY_BROWSER_CHANNEL=chrome to use system Chrome, or "
            "HARDLY_BROWSER_EXECUTABLE=/path/to/chromium)"
        )
        if out.get("pin_hint"):
            out["hint"] += f" {out['pin_hint']}"
    elif exe_ok and not chromium_ok and not channel:
        out["hint"] = (
            f"Ready via {out['browser_executable_source']} executable "
            f"{out['suggested_executable']}."
            + (
                " The Playwright package expects a different Chromium build than the one "
                "found; that is fine while captures launch. Only if launches fail, pin the "
                "matching Playwright version: " + out["pin_hint"]
                if out.get("mismatch") and out.get("pin_hint")
                else ""
            )
        )
    elif channel:
        out["hint"] = (
            f"Ready (channel={channel}). Prefer channel=chrome for Akamai / bot walls."
        )
    else:
        out["hint"] = (
            "Ready with bundled Chromium. For bot-walled sites (Akamai etc.) prefer "
            "channel=chrome (system Chrome)."
        )
    return out


def _annotate_browser_detection(
    out: dict[str, Any], *, chromium_ok: bool, channel: str
) -> None:
    """Fill installed_builds / expected_build / mismatch / source fields."""
    builds = scan_chromium_builds()
    out["installed_builds"] = [
        {"build": b["build"], "kind": b["kind"], "path": b["path"]} for b in builds
    ]
    own = (out.get("browsers", {}).get("chromium") or {}).get("executable")
    expected = expected_chromium_build(own)
    out["expected_build"] = expected
    have = {str(b["build"]) for b in builds}
    out["mismatch"] = bool(builds) and (expected not in have) and not chromium_ok
    picked = pick_executable(builds, headless=True)
    out["suggested_executable"] = picked["path"] if picked else None
    out["pin_hint"] = pin_hint(builds, expected) if (builds and out["mismatch"]) else None
    env_exe = (os.environ.get("HARDLY_BROWSER_EXECUTABLE") or "").strip()
    if env_exe and Path(env_exe).expanduser().is_file():
        out["browser_executable_source"] = "env"
        out["suggested_executable"] = env_exe
    elif channel:
        out["browser_executable_source"] = "channel"
    elif chromium_ok:
        out["browser_executable_source"] = "playwright"
    elif picked and not env_exe:
        out["browser_executable_source"] = "autodetect"
    else:
        out["browser_executable_source"] = "playwright"


def require_playwright(*, need_browser: bool = True) -> dict[str, Any]:
    """Raise CaptureError with install guidance when the stack is not ready."""
    status = playwright_status()
    if not status.get("package"):
        raise CaptureError(status.get("hint") or "Playwright package missing")
    if need_browser and not status.get("ready"):
        raise CaptureError(status.get("hint") or "Playwright browsers not installed")
    return status


def active_dir() -> Path:
    from hardly.ephemeral import runtime_dir

    path = runtime_dir() / "captures" / "active"
    path.mkdir(parents=True, exist_ok=True)
    return path


KEEP_HINT_START = (
    "No output path: the HAR is ephemeral (private temp file, ingested into memory and deleted "
    "at stop). Pass har_output_path (MCP) or -o (CLI) to keep it."
)


def _public_row(row: dict[str, Any]) -> dict[str, Any]:
    """Hide the temp path of an ephemeral capture from callers."""
    if row.get("har_path") and is_ephemeral_path(row["har_path"]):
        row = {**row, "har_path": None, "ephemeral": True}
    return row


def _require_output_for_no_session(har_path: Any, open_session: bool) -> None:
    if not har_path and not open_session:
        raise CaptureError(
            "open_session=false needs an output path (har_path / -o): without one the HAR is "
            "ephemeral and would be deleted with nothing to show for it."
        )


def _mark_ephemeral(out: dict[str, Any]) -> dict[str, Any]:
    out["har_path"] = None
    out["har_exists"] = False
    out["ephemeral"] = True
    out["keep_hint"] = KEEP_HINT
    out.pop("trace_path", None)
    nxt = out.get("next")
    out["next"] = f"{nxt} {KEEP_HINT}" if nxt else KEEP_HINT
    return out


def default_channel() -> str:
    return (os.environ.get("HARDLY_BROWSER_CHANNEL") or "").strip()


# Navigation errors worth another try (list lives in core.capture_errors).
_TRANSIENT_NAV = TRANSIENT_NAV


def _sync_playwright() -> Any:
    from playwright.sync_api import sync_playwright

    return sync_playwright()


def _playwright_expected_path() -> str | None:
    """Path Playwright's own chromium would use (starts the driver once)."""
    try:
        with _sync_playwright() as pw:
            return str(pw.chromium.executable_path)
    except Exception:  # noqa: BLE001
        return None


def resolve_browser_executable(
    *,
    channel: str = "",
    headless: bool = True,
    playwright_path: str | None = None,
) -> dict[str, Any]:
    """Decide which browser binary to launch.

    Returns ``{"executable": str | None, "source": env|autodetect|playwright|channel}``.
    ``executable`` is None when Playwright should pick its own (channel or
    bundled chromium). Precedence: HARDLY_BROWSER_EXECUTABLE, channel,
    Playwright's bundled chromium when present, then on-disk autodetect.
    """
    env_exe = (os.environ.get("HARDLY_BROWSER_EXECUTABLE") or "").strip()
    if env_exe and Path(env_exe).expanduser().is_file():
        return {"executable": str(Path(env_exe).expanduser()), "source": "env"}
    if env_exe:
        # Explicit but missing: do not silently autodetect; doctor reports it.
        return {"executable": None, "source": "playwright", "env_missing": env_exe}
    if (channel or default_channel()).strip():
        return {"executable": None, "source": "channel"}
    if playwright_path is None:
        playwright_path = _playwright_expected_path()
    if playwright_path and Path(str(playwright_path)).is_file():
        return {"executable": None, "source": "playwright"}
    picked = pick_executable(scan_chromium_builds(), headless=headless)
    if picked:
        return {"executable": picked["path"], "source": "autodetect", "build": picked["build"]}
    return {"executable": None, "source": "playwright"}


def default_executable(
    *, channel: str = "", headless: bool = True, playwright_path: str | None = None
) -> str:
    """Chromium executable to pass to Playwright, or '' to let Playwright choose.

    Uses HARDLY_BROWSER_EXECUTABLE when set; otherwise, when Playwright's own
    chromium is missing, scans PLAYWRIGHT_BROWSERS_PATH, /opt/pw-browsers and
    ~/.cache/ms-playwright for a usable build.
    """
    return (
        resolve_browser_executable(
            channel=channel, headless=headless, playwright_path=playwright_path
        ).get("executable")
        or ""
    )


def apply_executable(
    launch_kwargs: dict[str, Any],
    playwright: Any,
    *,
    channel: str,
    headless: bool,
) -> str:
    """Add ``executable_path`` to launch kwargs when needed; return the source."""
    try:
        pw_path: str | None = str(playwright.chromium.executable_path)
    except Exception:  # noqa: BLE001
        pw_path = ""
    info = resolve_browser_executable(
        channel=channel, headless=headless, playwright_path=pw_path or ""
    )
    if info.get("executable"):
        launch_kwargs["executable_path"] = info["executable"]
    return str(info["source"])


def _precheck_output_path(har_path: str | Path | None) -> Path | None:
    """Validate ``-o`` / ``har_path`` up front; raise CaptureError, never a traceback."""
    if not har_path:
        return None
    raw = str(har_path)
    if "\x00" in raw:
        raise CaptureError(f"invalid output path {raw!r}: contains a NUL byte")
    try:
        target = resolve_path(har_path)
    except (OSError, ValueError, RuntimeError) as exc:
        raise CaptureError(f"invalid output path {raw!r}: {exc}") from exc
    if target.is_dir():
        raise CaptureError(
            f"output path {str(target)!r} is a directory; give a HAR file name, e.g. {target / 'out.har'}"
        )
    parent = target.parent
    for anc in (parent, *parent.parents):
        if anc.exists():
            if not anc.is_dir():
                raise CaptureError(
                    f"output path {str(target)!r} is not writable: {str(anc)!r} is a file, not a directory"
                )
            break
    try:
        parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise CaptureError(
            f"output path {str(target)!r} is not writable: cannot create {str(parent)!r} ({exc.strerror or exc})"
        ) from exc
    if not os.access(parent, os.W_OK | os.X_OK):
        raise CaptureError(
            f"output path {str(target)!r} is not writable: no write permission in {str(parent)!r}"
        )
    return target


def start_capture(
    url: str = "",
    har_path: str | Path | None = None,
    *,
    headed: bool = True,
    channel: str = "",
    url_filter: str = "",
    omit_content: bool = False,
    label: str = "",
    viewport_width: int = 1280,
    viewport_height: int = 900,
    user_data_dir: str | Path | None = None,
    show_banner: bool = True,
    same_tab: bool = True,
    trace: bool | None = None,
    slot_timeout_s: float | None = None,
) -> dict[str, Any]:
    """Launch Chromium with HAR recording in a durable subprocess.

    Waits for a capture slot first (``HARDLY_CAPTURE_SLOTS``); the worker
    process holds the slot until it exits.

    ``same_tab`` (default True) rewrites ``target=_blank`` / ``window.open``
    into the current tab. Popups in the same Playwright context are still
    recorded either way (HAR is context-scoped).

    ``trace`` writes a Playwright ``.trace.zip`` beside the HAR (view with
    ``playwright show-trace``). Default: env ``HARDLY_CAPTURE_TRACE=1``.
    """
    pre_target = _precheck_output_path(har_path)
    require_playwright(need_browser=True)

    label_key = (label or _host_label(url) or "capture").strip()
    ephemeral = not pre_target
    target = pre_target if pre_target else new_ephemeral_har(label_key)
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        slot_handle = acquire_slot(slot_timeout_s)
    except SlotTimeoutError as exc:
        if ephemeral:
            discard_ephemeral(target)
        raise _classified(CaptureError(str(exc))) from exc
    try:
        return _public_row(_start_capture_locked(
            slot_handle,
            url,
            target,
            label_key,
            headed=headed,
            channel=channel,
            url_filter=url_filter,
            omit_content=omit_content,
            viewport_width=viewport_width,
            viewport_height=viewport_height,
            user_data_dir=user_data_dir,
            show_banner=show_banner,
            same_tab=same_tab,
            trace=trace,
        ))
    except BaseException:
        slot_handle.release()
        if ephemeral:
            discard_ephemeral(target)
        raise
    finally:
        # The worker inherited the descriptor; our copy is no longer needed.
        slot_handle.close_fd()


def _start_capture_locked(
    slot_handle: Any,
    url: str,
    target: Path,
    label_key: str,
    *,
    headed: bool,
    channel: str,
    url_filter: str,
    omit_content: bool,
    viewport_width: int,
    viewport_height: int,
    user_data_dir: str | Path | None,
    show_banner: bool,
    same_tab: bool,
    trace: bool | None,
) -> dict[str, Any]:
    if target.exists():
        target.unlink()

    capture_id = uuid.uuid4().hex[:12]
    use_channel = (channel or default_channel()).strip()
    profile = str(resolve_path(user_data_dir)) if user_data_dir else ""
    started_at = time.time()
    if trace is None:
        trace = (os.environ.get("HARDLY_CAPTURE_TRACE") or "").strip() in {
            "1",
            "true",
            "yes",
            "on",
        }

    job = {
        "capture_id": capture_id,
        "har_path": str(target),
        "url": str(url or "").strip(),
        "headed": headed,
        "channel": use_channel,
        "url_filter": str(url_filter or "").strip(),
        "omit_content": bool(omit_content),
        "label": label_key,
        "viewport_width": viewport_width,
        "viewport_height": viewport_height,
        "user_data_dir": profile or None,
        "show_banner": show_banner,
        "same_tab": same_tab,
        "trace": bool(trace),
        "started_at": started_at,
        "slot": {k: slot_handle.info[k] for k in ("waited_s", "queue_depth", "slot")},
    }
    job_path = active_dir() / f"{capture_id}.job.json"
    job_path.write_text(json.dumps(job, indent=2) + "\n", encoding="utf-8")
    (active_dir() / f"{capture_id}.stop").unlink(missing_ok=True)

    _persist_payload(
        capture_id,
        {
            "capture_id": capture_id,
            "har_path": str(target),
            "url": job["url"],
            "headed": headed,
            "channel": use_channel or None,
            "url_filter": job["url_filter"] or None,
            "omit_content": omit_content,
            "label": label_key,
            "same_tab": same_tab,
            "trace": bool(trace),
            "status": "starting",
            "error": None,
            "started_at": started_at,
            "stopped_at": None,
            "entry_count_hint": None,
            "har_exists": False,
            "har_bytes": 0,
            "pid": None,
            "pages": 0,
            "slot": job["slot"],
        },
    )

    creationflags = 0
    if sys.platform == "win32":
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP  # type: ignore[attr-defined]

    log_path = active_dir() / f"{capture_id}.log"
    log_handle = log_path.open("w", encoding="utf-8")
    try:
        proc = subprocess.Popen(
            [sys.executable, "-m", "hardly.capture_worker", str(job_path)],
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            creationflags=creationflags,
            close_fds=False if sys.platform == "win32" else True,
            **(
                {"pass_fds": [slot_handle.fd]}
                if slot_handle.fd is not None and sys.platform != "win32"
                else {}
            ),
        )
    except OSError as exc:
        log_handle.close()
        raise CaptureError(f"failed to spawn capture worker: {exc}") from exc

    # Wait until running / error / timeout.
    deadline = time.time() + 45
    row: dict[str, Any] | None = None
    while time.time() < deadline:
        row = _load_sidecar(capture_id)
        if row and row.get("status") in ("running", "stopped", "error"):
            break
        if proc.poll() is not None:
            # Worker exited early
            row = _load_sidecar(capture_id) or {}
            if row.get("status") not in ("stopped", "error"):
                tail = ""
                try:
                    tail = log_path.read_text(encoding="utf-8")[-500:]
                except OSError:
                    pass
                raise _classified(
                    CaptureError(
                        row.get("error")
                        or f"capture worker exited early (code={proc.returncode}): {tail}"
                    )
                )
            break
        time.sleep(0.1)

    row = row or _load_sidecar(capture_id) or {}
    if row.get("status") == "error":
        raise _classified(CaptureError(str(row.get("error") or "capture failed")))
    if row.get("status") == "starting":
        raise CaptureError(
            "capture did not become ready in time; see "
            f"{log_path}"
        )
    mode = "interactive" if headed else "headless"
    row["mode"] = mode
    if headed:
        next_bits = [
            "Mode=interactive: ASK THE PERSON to use the open browser "
            "(search, open detail, accept cookies, login).",
            "Optional: hardly_write_screenshot / _status while they work.",
            "When they finish: hardly_browser_stop(open_session=true) then "
            "hardly_session_site_brief.",
        ]
        row["ask_user"] = (
            "A headed browser is recording. Ask the person to complete the "
            "portal steps you need traffic for, then call hardly_browser_stop."
        )
    else:
        next_bits = [
            "Mode=headless: drive with hardly_browser_inspect -> "
            "click/fill ref='eN' (or hardly_browser_run_steps), then "
            "hardly_browser_stop.",
            "Or use hardly_browser_capture_discover(url) for a one-shot load+optional recipe.",
        ]
        row["ask_user"] = None
    if not use_channel:
        next_bits.insert(
            0,
            "No channel set - for Akamai/bot walls restart with channel=chrome "
            "or HARDLY_BROWSER_CHANNEL=chrome.",
        )
        row["channel_hint"] = "chrome"
    if is_ephemeral_path(target):
        next_bits.insert(0, INTERACTIVE_WARNING if headed else KEEP_HINT_START)
        row["ephemeral"] = True
    row["next"] = " ".join(next_bits)
    return row


def stop_capture(
    capture_id: str | None = None,
    *,
    open_session: bool = True,
    force: bool = False,
    export_path: str | Path | None = None,
) -> dict[str, Any]:
    """Stop recording (latest running if id omitted), optionally open_har.

    An ephemeral capture (started with no output path) is ingested into a Memory session and its
    temp file is deleted here. ``export_path`` first copies that HAR to the given path (kept).
    """
    cid0 = capture_id or latest_running_id()
    row0 = _load_sidecar(cid0) if cid0 else None
    eph_path = Path(str(row0.get("har_path"))) if row0 and row0.get("har_path") else None
    eph = bool(eph_path and is_ephemeral_path(eph_path))
    try:
        result = _stop_capture_impl(
            capture_id, open_session=open_session, force=force, _ephemeral=eph, export_path=export_path
        )
    finally:
        if eph:
            discard_ephemeral(eph_path)
    return _mark_ephemeral(result) if eph and not result.get("exported_har") else result


def _stop_capture_impl(
    capture_id: str | None = None,
    *,
    open_session: bool = True,
    force: bool = False,
    _ephemeral: bool = False,
    export_path: str | Path | None = None,
) -> dict[str, Any]:
    cid = capture_id or latest_running_id()
    if not cid:
        raise CaptureError(
            f"unknown capture_id {capture_id!r}"
            if capture_id
            else "no running capture; pass capture_id or start one first"
        )

    row = _load_sidecar(cid) or {}
    if row.get("status") in ("stopped", "error"):
        result = dict(row)
    else:
        pid = row.get("pid")
        orphan = pid is None or not _pid_alive(int(pid))
        if orphan:
            # Orphan sidecar (worker already gone) — finalize from disk.
            result = dict(row)
            har = Path(str(result.get("har_path") or ""))
            result["status"] = "stopped" if har.is_file() else "error"
            if result["status"] == "error" and not result.get("error"):
                result["error"] = "capture worker exited without flushing"
            result["stopped_at"] = result.get("stopped_at") or time.time()
            _persist_payload(cid, result)
        else:
            (active_dir() / f"{cid}.stop").write_text("stop\n", encoding="utf-8")
            deadline = time.time() + 120
            try:
                while time.time() < deadline:
                    row = _load_sidecar(cid) or {}
                    if row.get("status") in ("stopped", "error"):
                        break
                    if pid and not _pid_alive(int(pid)):
                        break
                    time.sleep(0.25)
            except KeyboardInterrupt:
                # Windows process-group quirks (and IDE stop) can interrupt the
                # wait; still finalize from the sidecar / HAR on disk.
                row = _load_sidecar(cid) or row
            result = dict(row)
            if result.get("status") not in ("stopped", "error"):
                if pid and _pid_alive(int(pid)):
                    try:
                        os.kill(int(pid), 9)
                    except OSError:
                        pass
                result["status"] = (
                    "stopped" if Path(result.get("har_path") or "").is_file() else "error"
                )
                if result["status"] == "error" and not result.get("error"):
                    result["error"] = "capture did not stop cleanly"
                result["stopped_at"] = result.get("stopped_at") or time.time()
                _persist_payload(cid, result)

    har = Path(str(result.get("har_path") or ""))
    result["har_exists"] = har.is_file()
    result["har_bytes"] = har.stat().st_size if har.is_file() else 0
    if result.get("status") == "stopped" and not har.is_file():
        # Never report success for a capture that produced no HAR.
        result["status"] = "error"
        result["error"] = result.get("error") or "capture finished but no HAR was written"
    with_error_class(result)
    if result.get("entry_count_hint") is None and har.is_file():
        result["entry_count_hint"] = _count_har_entries(har)

    if _ephemeral and har.is_file():
        secure_file(har)
        if export_path:
            from hardly.session import copy_atomic

            dest = _precheck_output_path(export_path)
            if dest is not None:
                copy_atomic(har, dest)
                result["exported_har"] = str(dest)
                result["har_path"] = str(dest)
                result["ephemeral"] = False
    if open_session and result.get("status") == "stopped" and har.is_file():
        from hardly import session as sess

        opened = sess.open_har(
            str(har), force=force, **({"ephemeral": True} if _ephemeral else {})
        )
        result["session"] = opened
        if isinstance(opened, dict) and opened.get("session_id"):
            result["session_id"] = opened["session_id"]
    # After stop, analysis is always archive mode (query the HAR on disk).
    if result.get("status") == "stopped":
        result["mode"] = "archive"
    result["next"] = _next_steps(result)
    return result


def navigate_capture(capture_id: str | None, url: str) -> dict[str, Any]:
    cid = capture_id or latest_running_id()
    if not cid:
        raise CaptureError("no running capture to navigate")
    row = _load_sidecar(cid)
    if not row or row.get("status") != "running":
        raise CaptureError(f"capture {cid} is not running")
    if not str(url or "").strip():
        raise CaptureError("url is required")
    cmd_path = active_dir() / f"{cid}.cmd"
    with cmd_path.open("a", encoding="utf-8") as handle:
        handle.write(f"goto {str(url).strip()}\n")
    return get_capture(cid)


_RPC_OPS = frozenset(
    {
        "elements", "click", "fill", "press", "url", "aria", "screenshot",
        "goto", "find_click", "dismiss_consent",
    }
)


def capture_rpc(
    capture_id: str | None,
    op: str,
    *,
    timeout: float = 30.0,
    **args: Any,
) -> dict[str, Any]:
    """Send a request to the capture worker and wait for a JSON reply.

    Ops: ``elements`` (visible controls + xpath/css), ``click``, ``fill``,
    ``press``, ``url``.
    """
    cid = capture_id or latest_running_id()
    if not cid:
        raise CaptureError("no running capture")
    row = _load_sidecar(cid)
    if not row or row.get("status") != "running":
        raise CaptureError(f"capture {cid} is not running")
    op = str(op or "").strip().lower()
    if op not in _RPC_OPS:
        raise CaptureError(f"unknown capture op {op!r}; known: {sorted(_RPC_OPS)}")

    req_id = uuid.uuid4().hex[:12]
    req_path = active_dir() / f"{cid}.rpc.json"
    out_path = active_dir() / f"{cid}.rpc.out.json"
    out_path.unlink(missing_ok=True)
    payload = {"id": req_id, "op": op, "args": args}
    req_path.write_text(json.dumps(payload), encoding="utf-8")

    deadline = time.time() + max(1.0, float(timeout))
    while time.time() < deadline:
        if out_path.is_file():
            try:
                result = json.loads(out_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                time.sleep(0.05)
                continue
            if result.get("id") != req_id:
                time.sleep(0.05)
                continue
            out_path.unlink(missing_ok=True)
            if result.get("error"):
                raise CaptureError(str(result["error"]))
            return result.get("result") if "result" in result else result
        # Worker died?
        pid = row.get("pid")
        if pid and not _pid_alive(int(pid)):
            raise CaptureError("capture worker exited while waiting for reply")
        time.sleep(0.05)
        row = _load_sidecar(cid) or row
        if row.get("status") not in ("running", "starting"):
            raise CaptureError(f"capture stopped ({row.get('status')})")
    req_path.unlink(missing_ok=True)
    raise CaptureError(f"capture rpc {op!r} timed out after {timeout}s")


def list_capture_elements(
    capture_id: str | None = None,
    *,
    limit: int = 40,
    query: str = "",
) -> dict[str, Any]:
    """Visible interactive elements on the active capture tab."""
    args: dict[str, Any] = {"limit": min(max(1, int(limit)), 100)}
    if query:
        args["query"] = query
    return capture_rpc(capture_id, "elements", **args)


def click_capture(
    capture_id: str | None = None,
    *,
    ref: str = "",
    xpath: str = "",
    css: str = "",
    text: str = "",
    role: str = "",
    name: str = "",
    timeout_ms: int = 10_000,
    wait_until: str = "",
) -> dict[str, Any]:
    """Click a visible control on the active capture tab.

    Prefer ``ref`` from ``hardly_browser_inspect`` (``e12`` / ``[ref=e12]``).
    """
    if not any((ref, xpath, css, text, role)):
        raise CaptureError("pass ref, xpath, css, text, or role (+ optional name)")
    return capture_rpc(
        capture_id,
        "click",
        ref=ref,
        xpath=xpath,
        css=css,
        text=text,
        role=role,
        name=name,
        timeout_ms=int(timeout_ms),
        wait_until=str(wait_until or ""),
    )


def goto_capture(
    capture_id: str | None = None,
    *,
    url: str,
    wait_until: str = "domcontentloaded",
    timeout_ms: int = 60_000,
) -> dict[str, Any]:
    """Navigate the active tab and wait for ``wait_until`` (synchronous, unlike ``navigate_capture``)."""
    if not str(url or "").strip():
        raise CaptureError("goto requires url")
    return capture_rpc(
        capture_id,
        "goto",
        timeout=float(timeout_ms) / 1000.0 + 15.0,
        url=str(url).strip(),
        wait_until=_step_wait_until({"wait_until": wait_until}),
        timeout_ms=int(timeout_ms),
    )


def find_click_capture(
    capture_id: str | None = None,
    *,
    keywords: list[str] | None = None,
    max_hops: int = 4,
    min_fields: int = 2,
    hover: bool = True,
    timeout_ms: int = 0,
    wait_until: str = "domcontentloaded",
) -> dict[str, Any]:
    """Run ``find_click`` (rank links/buttons, hop until a search form) on the live tab.

    Same behaviour as the in-process recipe op, including same-origin iframes,
    open shadow DOM and hover-to-reveal menus.
    """
    hops = min(max(int(max_hops), 1), 8)
    args: dict[str, Any] = {
        "keywords": [str(k) for k in (keywords or [])],
        "max_hops": hops,
        "min_fields": int(min_fields),
        "hover": bool(hover),
        "wait_until": _step_wait_until({"wait_until": wait_until}),
    }
    if timeout_ms:
        args["timeout_ms"] = int(timeout_ms)
    return capture_rpc(capture_id, "find_click", timeout=45.0 * (hops + 1) + 15.0, **args)


def dismiss_consent_capture(
    capture_id: str | None = None, *, prefer: str = "reject", timeout_ms: int = 5_000
) -> dict[str, Any]:
    """Dismiss a cookie/consent dialog on the live tab (reject-first; never gates)."""
    return capture_rpc(
        capture_id, "dismiss_consent", prefer=str(prefer or "reject"), timeout_ms=int(timeout_ms)
    )


def fill_capture(
    capture_id: str | None = None,
    *,
    value: str,
    ref: str = "",
    xpath: str = "",
    css: str = "",
    timeout_ms: int = 10_000,
) -> dict[str, Any]:
    """Fill an input/textarea on the active capture tab.

    Prefer ``ref`` from ``hardly_browser_inspect`` when available.
    """
    if not any((ref, xpath, css)):
        raise CaptureError("pass ref, xpath, or css for the field to fill")
    return capture_rpc(
        capture_id,
        "fill",
        value=value,
        ref=ref,
        xpath=xpath,
        css=css,
        timeout_ms=int(timeout_ms),
    )


def press_capture(
    capture_id: str | None = None,
    *,
    key: str = "Enter",
    ref: str = "",
    xpath: str = "",
    css: str = "",
    timeout_ms: int = 10_000,
) -> dict[str, Any]:
    """Press a key on the page or a focused locator."""
    return capture_rpc(
        capture_id,
        "press",
        key=key,
        ref=ref,
        xpath=xpath,
        css=css,
        timeout_ms=int(timeout_ms),
    )


def capture_page_url(capture_id: str | None = None) -> dict[str, Any]:
    """Current URL / title of the active capture tab."""
    return capture_rpc(capture_id, "url")


def capture_aria_snapshot(
    capture_id: str | None = None,
    *,
    selector: str = "",
    mode: str = "ai",
) -> dict[str, Any]:
    """Playwright ``ariaSnapshot`` YAML for the live page (or a CSS scope).

    ``mode="ai"`` (default when supported) includes ``[ref=eN]`` markers.
    The response also returns a compact ``refs`` list — pass ``ref`` to
    ``click_capture`` / ``fill_capture``. Falls back to default on older builds.
    """
    args: dict[str, Any] = {"mode": mode or "ai"}
    if selector:
        args["selector"] = selector
    return capture_rpc(capture_id, "aria", **args)


def capture_screenshot(
    capture_id: str | None = None,
    *,
    path: str = "",
    full_page: bool = False,
) -> dict[str, Any]:
    """Take a PNG screenshot of the live capture tab (path optional)."""
    args: dict[str, Any] = {"full_page": bool(full_page)}
    if path:
        args["path"] = str(resolve_path(path))
    return capture_rpc(capture_id, "screenshot", **args)


_RECIPE_OPS = frozenset(
    {
        "goto",
        "wait",
        "elements",
        "click",
        "fill",
        "press",
        "url",
        "aria",
        "screenshot",
        "note",
        "find_click",
        "dismiss_consent",
    }
)


def run_capture_recipe(
    steps: list[dict[str, Any]] | list[Any],
    *,
    capture_id: str | None = None,
    stop_on_error: bool = True,
    deadline: float | None = None,
) -> dict[str, Any]:
    """Run a sequence of capture ops against the live browser.

    ``deadline`` (``time.monotonic()`` instant) skips remaining steps once
    passed; the result then carries ``skipped_steps``.

    Each step is ``{"op": "click"|"fill"|"goto"|"wait"|"elements"|"press"|"url",
    ...}``. ``wait`` takes ``ms`` (default 1000). Other ops mirror the
    corresponding capture_* helpers.
    """
    if not isinstance(steps, list) or not steps:
        raise CaptureError("steps must be a non-empty list")
    cid = capture_id or latest_running_id()
    if not cid:
        raise CaptureError("no running capture")
    results: list[dict[str, Any]] = []
    for i, raw in enumerate(steps):
        if deadline is not None and time.monotonic() >= deadline:
            return {
                "capture_id": cid,
                "completed": len(results),
                "stopped_on_error": False,
                "steps": results,
                "skipped_steps": len(steps) - i,
            }
        if not isinstance(raw, dict):
            raise CaptureError(f"step {i} must be an object")
        op = str(raw.get("op") or "").strip().lower()
        if op not in _RECIPE_OPS:
            raise CaptureError(
                f"step {i}: unknown op {op!r}; known: {sorted(_RECIPE_OPS)}"
            )
        step_out: dict[str, Any] = {"index": i, "op": op}
        try:
            bad = _unsupported_step_keys(op, raw, inprocess=False)
            if bad:
                raise CaptureError(bad)
            if op == "goto":
                url = str(raw.get("url") or "").strip()
                if not url:
                    raise CaptureError("goto requires url")
                if raw.get("wait_until") or raw.get("timeout_ms"):
                    # Synchronous navigation: honours wait_until / timeout_ms.
                    step_out["result"] = goto_capture(
                        cid,
                        url=url,
                        wait_until=str(raw.get("wait_until") or "domcontentloaded"),
                        timeout_ms=_step_timeout(raw, 60_000) or 60_000,
                    )
                else:
                    navigate_capture(cid, url)
                    # Give navigation a moment; url rpc confirms.
                    time.sleep(min(_wait_ms(raw, 500) / 1000.0, 10.0))
                    step_out["result"] = capture_page_url(cid)
            elif op == "wait":
                ms = min(max(_wait_ms(raw, 1000), 0), 30_000)
                time.sleep(ms / 1000.0)
                step_out["result"] = {"waited_ms": ms}
            elif op == "elements":
                step_out["result"] = list_capture_elements(
                    cid,
                    limit=int(raw.get("limit") or 40),
                    query=str(raw.get("query") or ""),
                )
            elif op == "aria":
                step_out["result"] = capture_aria_snapshot(
                    cid,
                    selector=str(raw.get("selector") or ""),
                    mode=str(raw.get("mode") or "ai"),
                )
            elif op == "screenshot":
                step_out["result"] = capture_screenshot(
                    cid,
                    path=str(raw.get("path") or ""),
                    full_page=bool(raw.get("full_page", False)),
                )
            elif op == "note":
                step_out["result"] = {
                    "note": str(raw.get("text") or raw.get("note") or ""),
                }
            elif op == "click":
                step_out["result"] = click_capture(
                    cid,
                    ref=str(raw.get("ref") or ""),
                    xpath=str(raw.get("xpath") or ""),
                    css=str(raw.get("css") or ""),
                    text=str(raw.get("text") or ""),
                    role=str(raw.get("role") or ""),
                    name=str(raw.get("name") or ""),
                    timeout_ms=_step_timeout(raw, 10_000) or 10_000,
                    wait_until=str(raw.get("wait_until") or ""),
                )
            elif op == "find_click":
                step_out["result"] = find_click_capture(
                    cid,
                    keywords=[str(k) for k in (raw.get("keywords") or [])],
                    max_hops=int(raw.get("max_hops") or 4),
                    min_fields=int(raw.get("min_fields") or 2),
                    hover=raw.get("hover") is not False,
                    timeout_ms=_step_timeout(raw) or 0,
                    wait_until=str(raw.get("wait_until") or "domcontentloaded"),
                )
            elif op == "dismiss_consent":
                step_out["result"] = dismiss_consent_capture(
                    cid,
                    prefer=str(raw.get("prefer") or "reject"),
                    timeout_ms=_step_timeout(raw, 5_000) or 5_000,
                )
            elif op == "fill":
                step_out["result"] = fill_capture(
                    cid,
                    value=str(raw.get("value") or ""),
                    ref=str(raw.get("ref") or ""),
                    xpath=str(raw.get("xpath") or ""),
                    css=str(raw.get("css") or ""),
                    timeout_ms=int(raw.get("timeout_ms") or 10_000),
                )
            elif op == "press":
                step_out["result"] = press_capture(
                    cid,
                    key=str(raw.get("key") or "Enter"),
                    ref=str(raw.get("ref") or ""),
                    xpath=str(raw.get("xpath") or ""),
                    css=str(raw.get("css") or ""),
                    timeout_ms=int(raw.get("timeout_ms") or 10_000),
                )
            elif op == "url":
                step_out["result"] = capture_page_url(cid)
            step_out["ok"] = True
        except CaptureError as exc:
            step_out["ok"] = False
            step_out["error"] = str(exc)
            with_error_class(step_out)
            results.append(step_out)
            if stop_on_error:
                return {
                    "capture_id": cid,
                    "completed": i,
                    "stopped_on_error": True,
                    "steps": results,
                }
            continue
        results.append(step_out)
    return {
        "capture_id": cid,
        "completed": len(results),
        "stopped_on_error": False,
        "steps": results,
    }


def list_captures(*, include_disk: bool = True) -> list[dict[str, Any]]:
    del include_disk  # always disk-backed now
    found: list[dict[str, Any]] = []
    for path in active_dir().glob("*.json"):
        if path.name.endswith(".job.json"):
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(payload, dict) and payload.get("capture_id"):
            found.append(_public_row(payload))
    return sorted(found, key=lambda row: row.get("started_at") or 0, reverse=True)


def get_capture(capture_id: str) -> dict[str, Any]:
    row = _load_sidecar(capture_id)
    if not row:
        raise CaptureError(f"unknown capture_id {capture_id!r}")
    return _public_row(row)


def latest_running_id() -> str | None:
    for row in list_captures():
        if row.get("status") == "running":
            return str(row["capture_id"])
    return None


def capture_interactive(
    url: str = "",
    har_path: str | Path | None = None,
    *,
    headed: bool = True,
    channel: str = "",
    url_filter: str = "",
    omit_content: bool = False,
    label: str = "",
    user_data_dir: str | Path | None = None,
    same_tab: bool = True,
    trace: bool | None = None,
    slot_timeout_s: float | None = None,
) -> dict[str, Any]:
    """Start, wait for Enter or window close, stop and open."""
    info = start_capture(
        url,
        har_path,
        headed=headed,
        channel=channel,
        url_filter=url_filter,
        omit_content=omit_content,
        label=label,
        user_data_dir=user_data_dir,
        same_tab=same_tab,
        trace=trace,
        slot_timeout_s=slot_timeout_s,
    )
    if info.get("har_path"):
        print(f"Recording to {info['har_path']}")
    else:
        print(INTERACTIVE_WARNING)
    print(f"capture_id={info['capture_id']}  status={info['status']}")
    if url:
        print(f"Opened {url}")
    print(
        "Interact with the browser, then press Enter here to stop "
        "(or just close the browser window)."
    )
    done = __import__("threading").Event()

    def _wait_enter() -> None:
        try:
            input()
        except EOFError:
            pass
        done.set()

    __import__("threading").Thread(target=_wait_enter, daemon=True).start()
    while not done.wait(0.5):
        row = get_capture(info["capture_id"])
        if row["status"] in ("stopped", "error"):
            break
    export_path = None
    if not info.get("har_path"):
        print(INTERACTIVE_WARNING)
        try:
            typed = input("Save the HAR to (path, blank = keep only the in-memory session): ")
        except EOFError:
            typed = ""
        export_path = typed.strip() or None
    return stop_capture(info["capture_id"], open_session=True, export_path=export_path)


def capture_for(
    url: str,
    har_path: str | Path | None = None,
    *,
    wait_seconds: float = 30,
    headed: bool = True,
    channel: str = "",
    url_filter: str = "",
    omit_content: bool = False,
    label: str = "",
    open_session: bool = True,
    same_tab: bool = True,
    trace: bool | None = None,
    budget_seconds: float | None = None,
    block_noise: bool = False,
    slot_timeout_s: float | None = None,
    diagnose_redirects: bool = False,
) -> dict[str, Any]:
    _require_output_for_no_session(har_path, open_session)
    # Headless one-shots prefer in-process capture (no subprocess stop race).
    if not headed and not (os.environ.get("HARDLY_CAPTURE_SUBPROCESS") or "").strip():
        return capture_headless(
            url,
            har_path,
            wait_seconds=wait_seconds,
            recipe=None,
            channel=channel,
            url_filter=url_filter,
            omit_content=omit_content,
            label=label,
            open_session=open_session,
            same_tab=same_tab,
            budget_seconds=budget_seconds,
            block_noise=block_noise,
            slot_timeout_s=slot_timeout_s,
            diagnose_redirects=diagnose_redirects,
        )
    info = start_capture(
        url,
        har_path,
        headed=headed,
        channel=channel,
        url_filter=url_filter,
        omit_content=omit_content,
        label=label,
        same_tab=same_tab,
        trace=trace,
        slot_timeout_s=slot_timeout_s,
    )
    try:
        time.sleep(max(0.0, float(wait_seconds)))
    except BaseException:
        stop_capture(info["capture_id"], open_session=False)
        raise
    out = stop_capture(info["capture_id"], open_session=open_session)
    _note_unsupported_options(out, block_noise=block_noise, budget_seconds=budget_seconds)
    return out


def capture_headless(url: str, har_path: str | Path | None = None, **kwargs: Any) -> dict[str, Any]:
    """In-process headless capture. Without ``har_path`` the HAR is ephemeral (see below).

    An explicit ``har_path`` is kept as-is. With none, the HAR is recorded to a private temp
    file, ingested into a Memory session and deleted straight away; the result then carries
    ``har_path: null, ephemeral: true``. Details of the options: ``_capture_headless_impl``.
    """
    if har_path:
        out = _capture_headless_impl(url, har_path, **kwargs)
        out.setdefault("ephemeral", False)
        return out
    label = (kwargs.get("label") or _host_label(str(url or "")) or "capture").strip()
    target = new_ephemeral_har(label)
    try:
        out = _capture_headless_impl(url, target, _ephemeral=True, **kwargs)
    finally:
        discard_ephemeral(target)
    out = _mark_ephemeral(out)
    if not kwargs.get("open_session", True):
        out.setdefault("warnings", []).append(
            "open_session=false and no output path: the HAR was discarded after the capture "
            "(recipe results are still returned). Pass har_path / -o to keep it."
        )
    return out


def _capture_headless_impl(
    url: str,
    har_path: str | Path | None = None,
    *,
    _ephemeral: bool = False,
    wait_seconds: float = 3,
    recipe: list[dict[str, Any]] | None = None,
    channel: str = "",
    url_filter: str = "",
    omit_content: bool = False,
    label: str = "",
    open_session: bool = True,
    same_tab: bool = True,
    brief: bool = False,
    budget_seconds: float | None = None,
    block_noise: bool = False,
    slot_timeout_s: float | None = None,
    diagnose_redirects: bool = False,
) -> dict[str, Any]:
    """In-process headless HAR capture for soak / unit tests.

    Waits for a cross-process capture slot (``HARDLY_CAPTURE_SLOTS``), then
    runs. ``budget_seconds`` (env ``HARDLY_CAPTURE_BUDGET``) is a hard wall
    budget measured from slot acquisition: once exceeded, remaining recipe
    steps and the settle wait are skipped but the HAR is still written.
    ``block_noise`` aborts analytics/ads/font/map-tile/heavy-media requests.
    ``diagnose_redirects`` (opt-in) attaches a capped ``redirect_diagnosis``
    (a few polite GETs, see ``core.redirect_diag``) when navigation fails with
    a redirect loop; it is never run otherwise.

    Unlike ``start_capture`` (subprocess worker for interactive MCP use), this
    runs Playwright in the current process, flushes the HAR on context close,
    and returns immediately — no ``.stop`` sidecar race.
    """
    pre_target = _precheck_output_path(har_path)
    require_playwright(need_browser=True)
    target_url = str(url or "").strip()
    if not target_url:
        raise CaptureError("capture_headless requires url")

    label_key = (label or _host_label(target_url) or "capture").strip()
    target = pre_target if pre_target else new_ephemeral_har(label_key)
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        target.unlink()

    use_channel = (channel or default_channel()).strip()
    body_sidecar: list[dict[str, Any]] = []
    recipe_result: dict[str, Any] | None = None
    started_at = time.time()

    budget_limit = resolve_budget(budget_seconds)
    blocker = None
    if block_noise:
        from hardly.core.noise_hosts import NoiseBlocker

        blocker = NoiseBlocker()
    try:
        slot_cm = capture_slot(slot_timeout_s)
        slot = slot_cm.__enter__()
    except SlotTimeoutError as exc:
        raise _classified(CaptureError(str(exc))) from exc
    exe_source = ""
    t0 = time.monotonic()
    deadline = t0 + budget_limit if budget_limit else None
    try:
        with _sync_playwright() as playwright:
            launch_kwargs: dict[str, Any] = {"headless": True}
            if use_channel:
                launch_kwargs["channel"] = use_channel
            exe_source = apply_executable(
                launch_kwargs, playwright, channel=use_channel, headless=True
            )
            context_kwargs: dict[str, Any] = {
                "record_har_path": str(target),
                "record_har_mode": "full",
                "record_har_content": "omit" if omit_content else "embed",
                "viewport": {"width": 1280, "height": 900},
                "ignore_https_errors": True,
            }
            if url_filter:
                context_kwargs["record_har_url_filter"] = url_filter

            browser = playwright.chromium.launch(**launch_kwargs)
            try:
                context = browser.new_context(**context_kwargs)
                if blocker is not None:
                    blocker.install(context)
                if same_tab:
                    context.add_init_script(_SAME_TAB_JS)
                if not omit_content:
                    from hardly.core.har_bodies import interesting_mime, shape_body

                    def on_response(response: Any) -> None:
                        try:
                            mime = (response.headers or {}).get("content-type") or ""
                            if not interesting_mime(mime):
                                return
                            text = response.text()
                            if not text:
                                return
                            body_sidecar.append(
                                {
                                    "method": response.request.method,
                                    "url": response.url,
                                    "status": response.status,
                                    "mime": mime,
                                    "text": shape_body(text),
                                }
                            )
                        except Exception:  # noqa: BLE001
                            return

                    context.on("response", on_response)

                page = context.new_page()
                goto_error: str | None = None
                main_resp: Any = None
                goto_http_status = False
                goto_timeout = 60_000
                if deadline is not None:
                    goto_timeout = int(
                        min(60_000, max(1_000, (deadline - time.monotonic()) * 1000))
                    )
                try:
                    if target_url and target_url != "about:blank":
                        main_resp = _goto_with_retry(page, target_url, timeout=goto_timeout)
                    elif target_url == "about:blank":
                        page.goto("about:blank")
                except Exception as exc:  # noqa: BLE001
                    # API roots that return 204 / abort navigation still allow
                    # recipe fetch/evaluate against absolute URLs.
                    goto_error = str(exc)
                    if any(t in goto_error for t in _HTTP_STATUS_NAV):
                        # The server answered 401/429/503...: that response IS the
                        # finding and is in the HAR. Do not abort, do not navigate away.
                        goto_http_status = True
                    elif not recipe:
                        raise CaptureError(goto_error) from exc
                    else:
                        try:
                            page.goto("about:blank")
                        except Exception:  # noqa: BLE001
                            pass
                if recipe:
                    recipe_result = _run_inprocess_recipe(
                        page, recipe, deadline=deadline
                    )
                    if goto_error:
                        recipe_result = {
                            **(recipe_result or {}),
                            "goto_error": goto_error,
                            "goto_recovered": True,
                            **{
                                k.replace("error_", "goto_error_"): v
                                for k, v in with_error_class({"error": goto_error}).items()
                                if k != "error"
                            },
                        }
                settle_ms = int(max(0.0, float(wait_seconds)) * 1000)
                if deadline is not None:
                    settle_ms = min(
                        settle_ms, int(max(0.0, deadline - time.monotonic()) * 1000)
                    )
                if settle_ms:
                    page.wait_for_timeout(min(settle_ms, 60_000))
                context.close()  # flushes HAR
            finally:
                browser.close()
    except CaptureError as exc:
        wrapped = _classified(exc)
        if diagnose_redirects and wrapped.classification["class"] == "redirect_loop":
            wrapped.redirect_diagnosis = _redirect_diagnosis(target_url)
        raise wrapped from exc
    finally:
        slot_cm.__exit__(None, None, None)

    bodies_filled = 0
    if body_sidecar and target.is_file():
        from hardly.core.har_bodies import merge_bodies_into_har

        stats = merge_bodies_into_har(target, body_sidecar)
        bodies_filled = int(stats.get("filled") or 0)

    out: dict[str, Any] = {
        "status": "stopped" if target.is_file() else "error",
        "mode": "archive",
        "capture_mode": "headless",
        "har_path": str(target),
        "har_exists": target.is_file(),
        "har_bytes": target.stat().st_size if target.is_file() else 0,
        "url": target_url,
        "headed": False,
        "channel": use_channel or None,
        "label": label_key,
        "started_at": started_at,
        "stopped_at": time.time(),
        "entry_count_hint": _count_har_entries(target) if target.is_file() else None,
        "bodies_filled": bodies_filled,
        "discover": {
            "url": target_url,
            "recipe_steps": len(recipe or []),
            "wait_seconds": float(wait_seconds),
            "recipe": recipe_result,
            "inprocess": True,
            **(
                {
                    "goto_error": goto_error,
                    **{
                        k.replace("error_", "goto_error_"): v
                        for k, v in with_error_class({"error": goto_error}).items()
                        if k != "error"
                    },
                    "goto_http_status": goto_http_status,
                }
                if goto_error
                else {}
            ),
        },
        "slot": {k: slot[k] for k in ("waited_s", "queue_depth", "slot")},
        "browser_executable_source": exe_source or None,
    }
    warnings_out: list[str] = []
    main_status = _response_status(main_resp)
    if main_status is not None:
        out["main_status"] = main_status
    warn = _main_document_warning(main_status, _response_headers(main_resp), goto_error)
    if warn:
        out["main_document_ok"] = False
        warnings_out.append(warn)
    if diagnose_redirects and goto_error:
        if with_error_class({"error": goto_error}).get("error_class") == "redirect_loop":
            out["discover"]["redirect_diagnosis"] = _redirect_diagnosis(target_url)
    skipped_total = int((recipe_result or {}).get("skipped_steps") or 0)
    used = round(time.monotonic() - t0, 3)
    if budget_limit:
        out["budget"] = {
            "limit_s": budget_limit,
            "used_s": used,
            "exceeded": used >= budget_limit or skipped_total > 0,
            "skipped_steps": skipped_total,
        }
        if skipped_total:
            warnings_out.append(
                f"budget of {budget_limit:g}s reached: {skipped_total} recipe step(s) skipped "
                "(the budget runs from slot acquisition and includes page load and settle time)"
            )
        elif used >= budget_limit:
            warnings_out.append(
                f"budget of {budget_limit:g}s reached during load/settle; "
                "the settle wait was cut short and the HAR may be thin"
            )
    if block_noise:
        # Same keys whether or not anything was blocked (blocker always exists here).
        out.update(blocker.summary() if blocker is not None else {"block_noise": True})
    if warnings_out:
        out["warnings"] = warnings_out
    if out["status"] != "stopped":
        out["error"] = "capture finished but no HAR was written"
        out["har_exists"] = False
        with_error_class(out)
        return out

    if open_session:
        from hardly import session as sess

        if _ephemeral:
            secure_file(target)
        opened = sess.open_har(
            str(target), force=True, **({"ephemeral": True} if _ephemeral else {})
        )
        out["session"] = opened
        if isinstance(opened, dict) and opened.get("session_id"):
            out["session_id"] = opened["session_id"]
            if brief:
                try:
                    from hardly.core.brief import portal_brief
                    from hardly.session import require_conn

                    out["brief"] = portal_brief(require_conn(str(out["session_id"])))
                except Exception as exc:  # noqa: BLE001
                    out["brief_error"] = str(exc)
    out["next"] = _next_steps(out)
    return out


def _redirect_diagnosis(url: str) -> dict[str, Any]:
    """Capped, polite redirect diagnosis (opt-in); never raises."""
    try:
        from hardly.core.redirect_diag import diagnose_redirects as _diag

        return _diag(url, max_hops=6, timeout_s=8.0, delay_s=0.3)
    except Exception as exc:  # noqa: BLE001
        return {"error": f"redirect diagnosis failed: {exc}"}


def _response_status(resp: Any) -> int | None:
    try:
        return int(resp.status) if resp is not None else None
    except Exception:  # noqa: BLE001
        return None


def _response_headers(resp: Any) -> dict[str, str]:
    try:
        return {str(k).lower(): str(v) for k, v in (resp.headers or {}).items()}
    except Exception:  # noqa: BLE001
        return {}


def _main_document_warning(
    status: int | None, headers: dict[str, str], goto_error: str | None
) -> str | None:
    """Warn when the main document is an error (a written HAR is not a successful visit)."""
    if headers.get("x-deny-reason"):
        return (
            f"main document was refused by the network path (x-deny-reason: "
            f"{headers['x-deny-reason'][:80]}); the HAR holds the proxy's answer, not the site"
        )
    if status is not None and status >= 500:
        extra = (
            " A 502 usually comes from an egress proxy that could not reach the origin "
            "(e.g. invalid/untrusted TLS certificate or blocked host), not from the site itself."
            if status in (502, 504)
            else ""
        )
        return f"main document returned HTTP {status}; the capture succeeded but the page did not.{extra}"
    if goto_error and any(t in goto_error for t in _HTTP_STATUS_NAV):
        return "main document answered with an error status (see discover.goto_error_*); the HAR holds that response"
    return None


def _note_unsupported_options(
    out: dict[str, Any], *, block_noise: bool, budget_seconds: float | None
) -> None:
    """Tell callers when headless-only options were ignored by a worker-based capture."""
    notes: list[str] = []
    if block_noise:
        out["block_noise"] = False
        notes.append("block_noise ignored: only in-process headless capture can block requests")
    if budget_seconds or resolve_budget(budget_seconds):
        notes.append("budget ignored: only in-process headless capture enforces a budget")
    if notes:
        out.setdefault("warnings", []).extend(notes)


def resolve_budget(budget_seconds: float | None) -> float:
    """Effective per-call budget in seconds (0 = none); env HARDLY_CAPTURE_BUDGET."""
    if budget_seconds is None:
        raw = (os.environ.get("HARDLY_CAPTURE_BUDGET") or "").strip()
        try:
            budget_seconds = float(raw) if raw else 0.0
        except ValueError:
            budget_seconds = 0.0
    return max(0.0, float(budget_seconds or 0.0))


def _classified(exc: CaptureError) -> CaptureError:
    """Attach error_class/advice text to a CaptureError message (once)."""
    msg = str(exc)
    if "[error_class=" in msg:
        return exc
    info = exc.classification
    return CaptureError(f"{msg} [error_class={info['class']}] {info['advice']}")


_NAV_INFO: dict[int, tuple[int, dict[str, str]]] = {}
_HTTP_STATUS_NAV = ("ERR_HTTP_RESPONSE_CODE_FAILURE", "ERR_INVALID_AUTH_CREDENTIALS")


def _remember_nav(page: Any, resp: Any) -> None:
    """Keep the real status/headers of the last main-document response."""
    try:
        if resp is not None:
            _NAV_INFO[id(page)] = (int(resp.status), {k.lower(): v for k, v in (resp.headers or {}).items()})
    except Exception:  # noqa: BLE001
        pass


def _goto_with_retry(
    page: Any, url: str, *, wait_until: str = "domcontentloaded", timeout: int = 60_000, attempts: int = 3
) -> Any:
    """``page.goto`` that retries transient network errors (not proxy denials).

    A redirect loop (``ERR_TOO_MANY_RETRIES/REDIRECTS``) gets one retry only: the
    browser's cookie jar fills while it loops, so a second try sometimes succeeds,
    but a real loop never will.
    """
    last: Exception | None = None
    for attempt in range(attempts):
        try:
            resp = page.goto(url, wait_until=wait_until, timeout=timeout)
            _remember_nav(page, resp)
            return resp
        except Exception as exc:  # noqa: BLE001
            last = exc
            msg = str(exc)
            limit = 2 if "ERR_TOO_MANY_" in msg else attempts
            if not any(t in msg for t in _TRANSIENT_NAV) or attempt >= limit - 1:
                raise
            page.wait_for_timeout(1_200 * (attempt + 1))
    raise last  # pragma: no cover — loop always returns or raises


def _wait_ms(raw: dict[str, Any], default: int) -> int:
    """Wait length in ms from ``ms`` or (friendlier) ``seconds``."""
    if raw.get("ms") not in (None, ""):
        return int(float(raw["ms"]))
    if raw.get("seconds") not in (None, ""):
        return int(float(raw["seconds"]) * 1000)
    return default


def _settled_content(page: Any) -> str:
    """``page.content()`` that survives in-flight navigations and empty shells."""
    try:
        page.wait_for_load_state("domcontentloaded", timeout=8_000)
    except Exception:  # noqa: BLE001
        pass
    # Client-rendered apps build their forms after load. Only when the page has
    # nothing to type into yet: let the network go quiet, then wait (briefly)
    # for an input to appear.
    try:
        has_inputs = page.locator("input:visible, select:visible, textarea:visible").count() > 0
    except Exception:  # noqa: BLE001
        has_inputs = False
    if not has_inputs:
        try:
            page.wait_for_load_state("networkidle", timeout=3_000)
        except Exception:  # noqa: BLE001
            pass
        try:
            page.wait_for_selector("input:visible, select:visible, textarea:visible", timeout=1_500)
        except Exception:  # noqa: BLE001
            pass
    html = ""
    for _ in range(4):
        try:
            html = page.content()
        except Exception:  # noqa: BLE001 — "page is navigating and changing the content"
            page.wait_for_timeout(600)
            continue
        if len(html) > 120:
            return html
        page.wait_for_timeout(600)
    return html


_STOP_GATES = {"bot_wall", "captcha", "login", "paywall", "rate_limit"}


def _page_gate_classes(page: Any, html: str) -> list[str]:
    """Stop-sign gate classes the settled page classifies as (never click through)."""
    from hardly.core.gates import classify_response

    status, headers = _NAV_INFO.get(id(page), (200, {}))
    try:
        gates = classify_response(status, headers, html or "", getattr(page, "url", "") or "")
    except Exception:  # noqa: BLE001
        return []
    classes = {g["class"] for g in gates if g["class"] in _STOP_GATES}
    # A full site page with a header "Sign in" box is not a login wall; only a
    # page that is essentially the login form stops navigation.
    if "login" in classes and (html or "").lower().count("<a ") >= 15:
        classes.discard("login")
    return sorted(classes)


def _landed_on_new_page(before: str, after: str) -> bool:
    """A click landed somewhere new: a different host (a dedicated search
    subdomain's root counts) or a different non-root path, not the same
    homepage re-rendered."""
    if not after or after == before or after.startswith("chrome-error://"):
        return False
    b, a = urlparse(before), urlparse(after)
    if a.netloc.lower() != b.netloc.lower():
        return True
    return bool(a.path.strip("/")) and a.path != b.path


_WAIT_UNTIL_VALUES = ("commit", "domcontentloaded", "load", "networkidle")


def _step_wait_until(raw: dict[str, Any], default: str = "domcontentloaded") -> str:
    """Validated ``wait_until`` of a step (``commit|domcontentloaded|load|networkidle``)."""
    val = str(raw.get("wait_until") or default).strip().lower()
    if val not in _WAIT_UNTIL_VALUES:
        raise CaptureError(f"wait_until must be one of {list(_WAIT_UNTIL_VALUES)}, got {val!r}")
    return val


def _step_timeout(raw: dict[str, Any], default: int | None = None) -> int | None:
    """``timeout_ms`` of a step, clamped to 100 ms .. 300 s (``default`` when absent)."""
    if raw.get("timeout_ms") in (None, "", 0):
        return default
    try:
        return min(max(int(float(raw["timeout_ms"])), 100), 300_000)
    except (TypeError, ValueError) as exc:
        raise CaptureError(f"timeout_ms must be a number, got {raw['timeout_ms']!r}") from exc


def _after_click_wait(page: Any, wait_until: str | None, timeout: int) -> dict[str, Any]:
    """Wait for the load state a click step asked for; a timeout is reported, not raised."""
    if not wait_until or wait_until == "commit":
        return {}
    try:
        page.wait_for_load_state(wait_until, timeout=timeout)
    except Exception as exc:  # noqa: BLE001
        return {"wait_timeout": wait_until, "wait_error": str(exc)[:120]}
    return {}


# --- frames and shadow DOM ---------------------------------------------------


def _nav_frames(page: Any) -> list[Any]:
    """Main frame plus same-origin child frames (their DOM is readable)."""
    from hardly.core.page_nav import same_origin_frame

    main = page.main_frame
    out = [main]
    try:
        for fr in page.frames:
            if fr is main:
                continue
            try:
                if fr.is_detached() or not same_origin_frame(fr.url, page.url):
                    continue
            except Exception:  # noqa: BLE001
                continue
            out.append(fr)
    except Exception:  # noqa: BLE001
        pass
    return out


def _collect_nav_links(page: Any) -> list[dict[str, Any]]:
    """Clickable controls in the page, its same-origin iframes and open shadow roots."""
    from hardly.core.page_nav import PAGE_NAV_JS

    rows: list[dict[str, Any]] = []
    for fi, fr in enumerate(_nav_frames(page)):
        try:
            items = fr.evaluate(PAGE_NAV_JS, {"op": "links"}) or []
        except Exception:  # noqa: BLE001 — frame navigated away / detached
            continue
        for it in items:
            it["frame"] = fi
            rows.append(it)
    return rows


def _link_row(it: dict[str, Any]) -> dict[str, Any] | None:
    """Link-shaped row (for ranking) from a ``_collect_nav_links`` item."""
    from hardly.core.search_nav import _q

    text = (it.get("text") or "").strip()
    if not text:
        return None
    tag = it.get("tag") or "a"
    href = it.get("href") or f"action:{it.get('kind')}:{it['frame']}:{it['idx']}"
    return {
        "text": text,
        "href": href,
        "kind": it.get("kind"),
        "target": it.get("target") or "",
        "css": f"{tag}:has-text({_q(text)})" if len(text) <= 80 else f"{tag}",
        "frame": it["frame"],
        "idx": it["idx"],
        "shadow": bool(it.get("shadow")),
        "visible": bool(it.get("visible")),
    }


def _extra_dom(page: Any) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Links and forms the static HTML misses: same-origin iframes and shadow roots."""
    from hardly.core.page_nav import PAGE_NAV_JS

    links = [
        r for r in (
            _link_row(it) for it in _collect_nav_links(page) if it["frame"] > 0 or it.get("shadow")
        ) if r
    ]
    forms: list[dict[str, Any]] = []
    for fi, fr in enumerate(_nav_frames(page)):
        try:
            items = fr.evaluate(PAGE_NAV_JS, {"op": "forms"}) or []
        except Exception:  # noqa: BLE001
            continue
        for f in items:
            if (fi == 0 and not f.get("shadow")) or not f.get("visible"):
                continue
            forms.append({**f, "frame": fr.url if fi else "", "shadow": bool(f.get("shadow"))})
    return links, forms


def _element_handle(page: Any, row: dict[str, Any]) -> Any:
    """Playwright element handle for a collected row (works across frames/shadow)."""
    from hardly.core.page_nav import PAGE_NAV_JS

    frames = _nav_frames(page)
    if row["frame"] >= len(frames):
        raise CaptureError("frame is gone")
    el = frames[row["frame"]].evaluate_handle(PAGE_NAV_JS, {"op": "get", "idx": row["idx"]}).as_element()
    if el is None:
        raise CaptureError("element is gone")
    return el


def _pick_key(c: dict[str, Any]) -> str:
    if c.get("idx") is not None:
        return f"{c.get('frame', 0)}:{c['idx']}:{c['click']['css']}"
    return c["click"]["css"]


# --- hover-to-reveal menus ---------------------------------------------------


def _hover_reveal(
    page: Any, accept: Any, *, keywords: list[str] | tuple[str, ...] = (), limit: int = 6
) -> tuple[dict[str, Any], Any] | None:
    """Hover menu triggers until ``accept(rows)`` finds a newly revealed link.

    A trigger is a visible control that has hidden submenu links beside it (or
    ``aria-haspopup`` / ``aria-expanded=false``). ``accept`` gets link-shaped
    rows that were hidden before the hover and visible after it, and returns
    the one to follow (or ``None``). Returns ``(trigger_row, accepted)``; the
    pointer is parked away from the menu when nothing matches.
    """
    from hardly.core.search_nav import score_link

    before = _collect_nav_links(page)
    seen = {(r.get("href") or "", r["text"]) for r in before if r.get("visible")}
    triggers = [r for r in before if r.get("visible") and r.get("trigger") and r.get("text")]
    kw = tuple(keywords)
    triggers.sort(key=lambda r: -score_link(r["text"], r.get("href") or "", kw)[0])
    for trig in triggers[:limit]:
        try:
            _element_handle(page, trig).hover(timeout=2_000)
            page.wait_for_timeout(300)
        except Exception:  # noqa: BLE001
            continue
        rows = [
            lr for it in _collect_nav_links(page)
            if it.get("visible") and (it.get("href") or "", it["text"]) not in seen
            for lr in [_link_row(it)] if lr
        ]
        hit = accept(rows) if rows else None
        if hit is not None:
            return trig, hit
        try:
            page.mouse.move(0, 0)
            page.wait_for_timeout(120)
        except Exception:  # noqa: BLE001
            pass
    return None


def _click_row(page: Any, row: dict[str, Any], trigger: dict[str, Any] | None, timeout: int) -> None:
    """Click a collected row, re-hovering its menu trigger first when it has one."""
    if trigger is not None:
        _element_handle(page, trigger).hover(timeout=2_000)
        page.wait_for_timeout(250)
    _element_handle(page, row).click(timeout=timeout)


def _find_click(page: Any, raw: dict[str, Any]) -> dict[str, Any]:
    """Follow ranked links/buttons hop by hop until a search form appears.

    Step fields: ``keywords`` (list of domain terms), ``max_hops`` (default 4,
    cap 8), ``min_fields`` (default 2), ``hover`` (default true: hover menu
    triggers to reveal hidden submenu links), ``timeout_ms`` (per click /
    navigation) and ``wait_until`` (load state to wait for after a click).
    Generic signals plus caller keywords choose the click; visited targets are
    never re-clicked. Same-origin iframes and open shadow roots are searched
    too. Hidden elements, ``target=_blank`` links and failed clicks fall back
    to navigating straight to the link's ``href``.
    """
    from hardly.core.search_nav import has_search_term, page_candidates, rank_search_links, search_form_reached

    keywords = [str(k) for k in (raw.get("keywords") or [])]
    max_hops = min(max(int(raw.get("max_hops") or 4), 1), 8)
    min_fields = max(int(raw.get("min_fields") or 2), 1)
    use_hover = raw.get("hover") is not False
    step_to = _step_timeout(raw)
    click_to = step_to or 6_000
    goto_to = step_to or 30_000
    load_to = step_to or 8_000
    wait_until = _step_wait_until(raw)
    visited: set[str] = set()
    hops: list[dict[str, Any]] = []
    form = None
    last_strong = False  # the last successful hop followed a link that named a search

    def _on_response(resp: Any) -> None:
        try:
            if resp.request.is_navigation_request() and resp.frame == page.main_frame:
                _remember_nav(page, resp)
        except Exception:  # noqa: BLE001
            pass

    try:
        page.on("response", _on_response)
    except Exception:  # noqa: BLE001 - test doubles / old pages
        _on_response = None  # type: ignore[assignment]
    kw_lower = [k.lower() for k in keywords if k.strip()]
    for _ in range(max_hops + 1):
        html = _settled_content(page)
        blocked = _page_gate_classes(page, html)
        if blocked:
            return {
                "reached": False,
                "form": None,
                "hops": hops,
                "url": page.url,
                "blocked": blocked,
            }
        try:
            extra_links, extra_forms = _extra_dom(page)
        except Exception:  # noqa: BLE001 — test doubles / mid-navigation
            extra_links, extra_forms = [], []
        cands, structure = page_candidates(
            html, base_url=page.url, keywords=keywords, extra_links=extra_links, extra_forms=extra_forms
        )
        form = search_form_reached(
            structure, min_fields=min_fields, keywords=keywords, allow_site_search=last_strong
        )
        if form:
            break
        if len(hops) >= max_hops:
            break
        # After the first successful hop only follow links that name a search
        # action AND (when keywords were given) mention a keyword: generic
        # gateway words and keyword-only links ("Tanks - fire permit
        # application") lead to content pages, not to the lookup.
        ok_hops = [h for h in hops if not h.get("error")]

        def _eligible(c: dict[str, Any]) -> bool:
            if _pick_key(c) in visited:
                return False
            if not ok_hops:
                return c["score"] >= 1
            text = (c.get("text") or "").lower()
            if not has_search_term(text):
                return False
            return (not kw_lower) or any(k in text for k in kw_lower)

        pick = next((c for c in cands if _eligible(c)), None)
        trigger: dict[str, Any] | None = None
        if pick is None and use_hover:
            # Nothing eligible is showing: open hover menus and rank what appears.
            def _accept_ranked(rows: list[dict[str, Any]]) -> dict[str, Any] | None:
                return next(
                    (c for c in rank_search_links(rows, keywords=tuple(keywords)) if _eligible(c)), None
                )

            try:
                hit = _hover_reveal(page, _accept_ranked, keywords=keywords)
            except Exception:  # noqa: BLE001
                hit = None
            if hit:
                trigger, pick = hit
        if pick is None:
            break
        visited.add(_pick_key(pick))
        before = page.url
        href = pick.get("href") or ""
        has_href = href.startswith(("http://", "https://"))
        in_extra = pick.get("idx") is not None
        via = "click"
        try:
            if trigger is not None:
                _click_row(page, pick, trigger, click_to)
                via = "hover+click"
            elif has_href and pick.get("target") == "_blank":
                via = "goto"  # would open a new tab we are not tracking
                _goto_with_retry(page, href, wait_until=wait_until, timeout=goto_to)
            elif in_extra:
                try:
                    _element_handle(page, pick).click(timeout=min(click_to, 3_000))
                except Exception:  # noqa: BLE001 — hidden/covered element
                    if not has_href or pick.get("frame"):
                        raise
                    via = "goto"
                    _goto_with_retry(page, href, wait_until=wait_until, timeout=goto_to)
            else:
                # first *visible* match: the same text often also sits in a hidden mega-menu
                loc = page.locator(pick["click"]["css"] + ":visible").first
                try:
                    loc.wait_for(state="visible", timeout=1_500)
                    loc.click(timeout=click_to)
                except Exception:  # noqa: BLE001 — hidden/covered element
                    # A submenu link that is only visible while its parent is hovered.
                    revealed = None
                    if use_hover:
                        try:
                            revealed = _hover_reveal(
                                page,
                                lambda rows, p=pick: next(
                                    (r for r in rows if r["text"] == p["text"] and (r["href"] == p["href"] or not has_href)),
                                    None,
                                ),
                                keywords=keywords,
                            )
                        except Exception:  # noqa: BLE001
                            revealed = None
                    if revealed:
                        trigger = revealed[0]
                        _click_row(page, revealed[1], trigger, click_to)
                        via = "hover+click"
                    elif has_href:
                        via = "goto"
                        _goto_with_retry(page, href, wait_until=wait_until, timeout=goto_to)
                    else:
                        raise
        except Exception as exc:  # noqa: BLE001
            hops.append({"from": before, "clicked": pick["text"], "error": str(exc)[:120]})
            continue
        try:
            page.wait_for_load_state(
                "domcontentloaded" if wait_until == "commit" else wait_until, timeout=load_to
            )
        except Exception:  # noqa: BLE001
            pass
        page.wait_for_timeout(400)
        if page.url.startswith("chrome-error://"):
            # The destination failed to load: step back and try the next candidate.
            hops.append({"from": before, "clicked": pick["text"], "error": "navigation failed (browser error page)"})
            try:
                _goto_with_retry(page, before, timeout=30_000, attempts=2)
            except Exception:  # noqa: BLE001
                break
            continue
        hop = {"from": before, "clicked": pick["text"], "css": pick["click"]["css"], "to": page.url, "via": via}
        if trigger is not None:
            hop["hover"] = trigger["text"]
        if in_extra and (pick.get("frame") or pick.get("shadow")):
            hop["where"] = "iframe" if pick.get("frame") else "shadow"
        hops.append(hop)
        # A one-box search counts as THE search only if the click really landed
        # on a new, non-root page (not the homepage's own header search).
        landed = _landed_on_new_page(before, page.url)
        last_strong = landed and has_search_term(pick["text"]) and (
            not kw_lower or any(k in (pick["text"] or "").lower() for k in kw_lower)
        )
    try:
        if _on_response is not None:
            page.remove_listener("response", _on_response)
    except Exception:  # noqa: BLE001
        pass
    return {"reached": form is not None, "form": form, "hops": hops, "url": page.url}


# --- consent banners ---------------------------------------------------------


def _dismiss_consent(page: Any, raw: dict[str, Any]) -> dict[str, Any]:
    """Dismiss a cookie / consent dialog by clicking its reject (else accept) control.

    ``prefer`` is ``"reject"`` (default) or ``"accept"``. Only dialogs whose
    text is about cookies/consent are touched; login, captcha, terms/disclaimer
    and form-bearing dialogs are refused and listed under ``refused`` (they stay
    governed by docs/gate-policy.md), as is any page that is itself a bot wall
    or captcha. No banner is not an error: ``dismissed`` is false.
    """
    from hardly.core.page_nav import PAGE_NAV_JS, consent_refusal, pick_consent_control

    prefer = "accept" if str(raw.get("prefer") or "reject").lower() == "accept" else "reject"
    timeout = _step_timeout(raw, 5_000) or 5_000
    walls = [g for g in _page_gate_classes(page, _settled_content(page)) if g in {"bot_wall", "captcha"}]
    if walls:
        return {"dismissed": False, "refused": [{"reason": w} for w in walls], "url": page.url}

    def scan() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        ready: list[dict[str, Any]] = []
        refused: list[dict[str, Any]] = []
        for fi, fr in enumerate(_nav_frames(page)):
            try:
                containers = fr.evaluate(PAGE_NAV_JS, {"op": "consent"}) or []
            except Exception:  # noqa: BLE001
                continue
            for c in sorted(containers, key=lambda c: len(c.get("text") or "")):
                reason = consent_refusal(c)
                if reason == "not_consent":
                    continue
                if reason:
                    refused.append({"reason": reason, "frame": fi, "text": (c.get("text") or "")[:80]})
                    continue
                ctrl, kind = pick_consent_control(c.get("controls") or [], prefer)
                if ctrl:
                    ready.append({"frame": fi, "idx": ctrl["idx"], "label": ctrl["label"], "action": kind})
        return ready, refused

    ready, refused = scan()
    if not ready:
        return {
            "dismissed": False,
            "refused": refused,
            "url": page.url,
            "note": (
                "dialog(s) left alone: gate policy applies"
                if refused
                else "no cookie/consent dialog with a reject/accept control"
            ),
        }
    pick = ready[0]
    try:
        _element_handle(page, pick).click(timeout=timeout)
    except Exception as exc:  # noqa: BLE001
        return {
            "dismissed": False,
            "refused": refused,
            "label": pick["label"],
            "error": str(exc)[:120],
            "url": page.url,
        }
    page.wait_for_timeout(400)
    again, _ = scan()
    return {
        "dismissed": True,
        "action": pick["action"],
        "label": pick["label"],
        "gone": not any(a["label"] == pick["label"] for a in again),
        "refused": refused,
        "url": page.url,
    }


_COMMON_STEP_KEYS = frozenset({"op", "note", "comment", "label"})
#: Allowed keys per op; ops absent here are not key-checked.
_STEP_KEYS: dict[str, frozenset[str]] = {
    "wait": frozenset({"ms", "seconds"}),
    "goto": frozenset({"url", "ms", "seconds", "timeout_ms", "wait_until"}),
    "click": frozenset({"css", "selector", "timeout_ms", "wait_until"}),
    "fill": frozenset({"css", "selector", "value", "timeout_ms", "allow_login"}),
    "press": frozenset({"key"}),
    "find_click": frozenset({"keywords", "max_hops", "min_fields", "hover", "timeout_ms", "wait_until"}),
    "dismiss_consent": frozenset({"prefer", "timeout_ms"}),
    "evaluate": frozenset({"js", "expression", "allow_login"}),
    "fetch": frozenset({"url", "method", "headers", "body"}),
}
#: Worker-backed runner accepts richer targets for click/fill/press.
_STEP_KEYS_WORKER: dict[str, frozenset[str]] = {
    "click": frozenset({"css", "selector", "ref", "xpath", "text", "role", "name", "timeout_ms", "wait_until"}),
    "fill": frozenset({"css", "selector", "ref", "xpath", "value", "timeout_ms", "allow_login"}),
    "press": frozenset({"key", "ref", "xpath", "css", "selector", "timeout_ms"}),
}


def _unsupported_step_keys(op: str, raw: dict[str, Any], *, inprocess: bool) -> str:
    """Message naming keys a step's op does not support (empty when fine)."""
    table = dict(_STEP_KEYS)
    if not inprocess:
        table.update(_STEP_KEYS_WORKER)
    allowed = table.get(op)
    if allowed is None:
        return ""
    extra = sorted(str(k) for k in raw if k not in allowed and k not in _COMMON_STEP_KEYS)
    if not extra:
        return ""
    hint = ""
    if inprocess and op == "click" and set(extra) & {"text", "role", "name", "ref", "xpath"}:
        hint = " To click by visible text use op 'find_click' or a css selector."
    return (
        f"unsupported key(s) {extra} for recipe op {op!r}; "
        f"supported: {sorted(allowed | _COMMON_STEP_KEYS)}.{hint}"
    )


def _run_inprocess_recipe(
    page: Any, steps: list[dict[str, Any]], *, deadline: float | None = None
) -> dict[str, Any]:
    """Minimal recipe runner for in-process headless capture (goto/wait/click/fill).

    ``deadline`` is a ``time.monotonic()`` instant; once passed, remaining
    steps are skipped (counted in ``skipped_steps``).
    """
    results: list[dict[str, Any]] = []
    skipped = 0
    for idx, raw in enumerate(steps):
        if deadline is not None and time.monotonic() >= deadline:
            skipped = len(steps) - idx
            break
        if not isinstance(raw, dict):
            results.append({"ok": False, "error": "step must be an object"})
            continue
        op = str(raw.get("op") or "").strip().lower()
        step_out: dict[str, Any] = {"op": op, "ok": True}
        if not op:
            step_out.update(ok=False, error=f"step {idx} has no 'op' key")
            results.append(step_out)
            continue
        from hardly.core.recipe_policy import check_step

        allowed, reason = check_step(raw)
        if not allowed:
            step_out.update(ok=False, error=reason)
            results.append(step_out)
            continue
        try:
            bad = _unsupported_step_keys(op, raw, inprocess=True)
            if bad:
                raise CaptureError(bad)
            if op == "wait":
                ms = min(max(_wait_ms(raw, 1000), 0), 30_000)
                page.wait_for_timeout(ms)
                step_out["result"] = {"waited_ms": ms}
            elif op == "goto":
                dest = str(raw.get("url") or "").strip()
                if not dest:
                    raise CaptureError("goto requires url")
                _goto_with_retry(
                    page,
                    dest,
                    wait_until=_step_wait_until(raw),
                    timeout=_step_timeout(raw, 60_000) or 60_000,
                )
                step_out["result"] = {"url": page.url}
            elif op == "click":
                css = str(raw.get("css") or raw.get("selector") or "").strip()
                if not css:
                    raise CaptureError("click requires css")
                click_to = _step_timeout(raw, 10_000) or 10_000
                wu = _step_wait_until(raw, "") if raw.get("wait_until") else ""
                page.locator(css).first.click(timeout=click_to)
                page.wait_for_timeout(300)
                step_out["result"] = {"url": page.url, **_after_click_wait(page, wu, click_to)}
            elif op == "fill":
                css = str(raw.get("css") or raw.get("selector") or "").strip()
                if not css:
                    raise CaptureError("fill requires css")
                target = page.locator(css).first
                if not raw.get("allow_login"):
                    # Selectors can reach a password input without naming it
                    # ("input >> nth=1"): check what was actually selected.
                    try:
                        itype = str(target.evaluate("e => (e.type || '').toLowerCase()", timeout=3_000))
                    except Exception:  # noqa: BLE001
                        itype = ""
                    if itype == "password":
                        raise CaptureError('policy: fill into a password input needs "allow_login": true')
                target.fill(
                    str(raw.get("value") or ""),
                    timeout=int(raw.get("timeout_ms") or 10_000),
                )
                step_out["result"] = {"url": page.url}
            elif op == "press":
                page.keyboard.press(str(raw.get("key") or "Enter"))
                step_out["result"] = {"url": page.url}
            elif op == "find_click":
                step_out["result"] = _find_click(page, raw)
            elif op == "dismiss_consent":
                step_out["result"] = _dismiss_consent(page, raw)
            elif op == "evaluate":
                js = str(raw.get("js") or raw.get("expression") or "").strip()
                if not js:
                    raise CaptureError("evaluate requires js")
                # Playwright runs the expression in-page; async functions are awaited.
                step_out["result"] = {"value": page.evaluate(js)}
            elif op == "fetch":
                # Issue a same-tab fetch so the HAR records JSON/GraphQL APIs
                # without needing a GraphiQL click. Prefer same-origin URLs.
                dest = str(raw.get("url") or "").strip()
                if not dest:
                    raise CaptureError("fetch requires url")
                method = str(raw.get("method") or "GET").upper()
                headers = raw.get("headers") if isinstance(raw.get("headers"), dict) else {}
                body = raw.get("body")
                step_out["result"] = page.evaluate(
                    """async ({url, method, headers, body}) => {
                      const init = { method, headers: headers || {} };
                      if (body !== null && body !== undefined) {
                        init.body = typeof body === 'string' ? body : JSON.stringify(body);
                      }
                      const resp = await fetch(url, init);
                      const text = await resp.text();
                      return {
                        status: resp.status,
                        ok: resp.ok,
                        url: resp.url,
                        bytes: text.length,
                      };
                    }""",
                    {
                        "url": dest,
                        "method": method,
                        "headers": headers,
                        "body": body,
                    },
                )
                page.wait_for_timeout(200)
            elif op in {"note", "elements", "url", "aria", "screenshot"}:
                step_out["result"] = {"skipped": op, "note": "in-process soak recipe"}
            else:
                step_out["ok"] = False
                step_out["error"] = f"unsupported in-process op {op!r}"
        except Exception as exc:  # noqa: BLE001
            step_out["ok"] = False
            step_out["error"] = str(exc)
            with_error_class(step_out)
        results.append(step_out)
    out: dict[str, Any] = {
        "steps": results,
        "ok": all(s.get("ok") for s in results) and not skipped,
        "step_count": len(results),
    }
    if skipped:
        out["skipped_steps"] = skipped
    return out


def discover_apis(
    url: str,
    har_path: str | Path | None = None,
    *,
    recipe: list[dict[str, Any]] | None = None,
    wait_seconds: float = 5,
    channel: str = "",
    url_filter: str = "",
    omit_content: bool = False,
    label: str = "",
    open_session: bool = True,
    brief: bool = True,
    same_tab: bool = True,
    trace: bool | None = None,
    budget_seconds: float | None = None,
    block_noise: bool = False,
    slot_timeout_s: float | None = None,
    diagnose_redirects: bool = False,
) -> dict[str, Any]:
    """Headless mode: load URL, optional recipe, stop, open session, brief.

    For agent-driven API discovery without asking a person to click. If the
    page walls the headless browser, switch to interactive mode
    (``hardly_browser_start(headed=true, channel=chrome)``).

    Default path is in-process (``capture_headless``) so soak/tests and one-shot
    discover do not depend on the subprocess ``.stop`` sidecar. Set
    ``HARDLY_CAPTURE_SUBPROCESS=1`` to force the durable worker (needed only when
    you will drive the tab after start with aria/click RPCs).
    """
    target = str(url or "").strip()
    if not target:
        raise CaptureError("discover_apis requires url")
    _require_output_for_no_session(har_path, open_session)

    use_subprocess = (os.environ.get("HARDLY_CAPTURE_SUBPROCESS") or "").strip() in {
        "1",
        "true",
        "yes",
        "on",
    }
    # Recipes that need live aria refs / RPC must use the subprocess worker.
    recipe_needs_rpc = bool(
        recipe
        and any(
            str((step or {}).get("op") or "").lower()
            in {"aria", "elements", "screenshot", "ref"}
            or (step or {}).get("ref")
            for step in recipe
            if isinstance(step, dict)
        )
    )
    if not use_subprocess and not recipe_needs_rpc:
        out = capture_headless(
            target,
            har_path,
            wait_seconds=wait_seconds,
            recipe=recipe,
            channel=channel,
            url_filter=url_filter,
            omit_content=omit_content,
            label=label,
            open_session=open_session,
            same_tab=same_tab,
            brief=brief,
            budget_seconds=budget_seconds,
            block_noise=block_noise,
            slot_timeout_s=slot_timeout_s,
            diagnose_redirects=diagnose_redirects,
        )
        session_id = out.get("session_id")
        if brief and session_id and open_session and "brief" in out:
            brief_out = out.get("brief") or {}
            walls = brief_out.get("walls") if isinstance(brief_out, dict) else None
            wall_hits = 0
            if isinstance(walls, dict):
                wall_hits = int(
                    walls.get("hit_count")
                    or len(walls.get("sample") or walls.get("hits") or [])
                    or 0
                )
            elif isinstance(walls, list):
                wall_hits = len(walls)
            cred = (brief_out.get("credentials") if isinstance(brief_out, dict) else None) or {}
            auth_thin = not (
                cred.get("session_cookies")
                or cred.get("shapes_by_kind")
                or cred.get("password_field_count")
            )
            if wall_hits or (isinstance(brief_out, dict) and brief_out.get("error")):
                out["next"] = (
                    f"Mode=archive (session_id={session_id}). Brief looks empty "
                    "or walled — switch to interactive: "
                    "hardly_browser_start(headed=true, channel='chrome') and "
                    "ASK THE PERSON to click."
                )
                out["suggest_mode"] = "interactive"
            elif auth_thin and brief_out.get("host"):
                out["next"] = (
                    f"Mode=archive (session_id={session_id}). Little auth/"
                    "session material — try interactive capture or a richer "
                    "recipe; else hardly_endpoint_list / hardly_auth_report."
                )
                out["suggest_mode"] = "interactive"
            else:
                out["next"] = (
                    f"Mode=archive (session_id={session_id}). Drill with "
                    "hardly_auth_report / hardly_endpoint_list / hardly_session_trace_value; "
                    "if traffic looks thin, retry interactive with channel=chrome."
                )
        return out

    info = start_capture(
        target,
        har_path,
        headed=False,
        channel=channel,
        url_filter=url_filter,
        omit_content=omit_content,
        label=label,
        same_tab=same_tab,
        trace=trace,
        show_banner=False,
        slot_timeout_s=slot_timeout_s,
    )
    cid = str(info["capture_id"])
    recipe_result: dict[str, Any] | None = None
    try:
        if recipe:
            # Keep going even if a step fails — stop_capture still indexes traffic.
            recipe_result = run_capture_recipe(
                recipe, capture_id=cid, stop_on_error=False
            )
        settle = max(0.0, float(wait_seconds))
        if settle:
            time.sleep(settle)
    except BaseException:
        stop_capture(cid, open_session=False)
        raise

    out = stop_capture(cid, open_session=open_session)
    _note_unsupported_options(out, block_noise=block_noise, budget_seconds=budget_seconds)
    # Capture was headless; analysis continues in archive mode (set by stop).
    out["capture_mode"] = "headless"
    out["mode"] = out.get("mode") or "archive"
    out["discover"] = {
        "url": target,
        "recipe_steps": len(recipe or []),
        "wait_seconds": float(wait_seconds),
        "recipe": recipe_result,
    }
    session = out.get("session") if isinstance(out.get("session"), dict) else {}
    session_id = out.get("session_id") or session.get("session_id")
    if session_id:
        out["session_id"] = session_id
    if brief and session_id and open_session:
        try:
            from hardly.core.brief import portal_brief
            from hardly.session import require_conn

            conn = require_conn(str(session_id))
            brief_out = portal_brief(conn)
            out["brief"] = brief_out
            walls = (brief_out or {}).get("walls") if isinstance(brief_out, dict) else None
            wall_hits = 0
            if isinstance(walls, dict):
                wall_hits = int(
                    walls.get("hit_count")
                    or len(walls.get("sample") or walls.get("hits") or [])
                    or 0
                )
            elif isinstance(walls, list):
                wall_hits = len(walls)
            cred = (
                (brief_out or {}).get("credentials")
                if isinstance(brief_out, dict)
                else None
            ) or {}
            auth_thin = not (
                cred.get("session_cookies")
                or cred.get("shapes_by_kind")
                or cred.get("password_field_count")
            )
            if wall_hits or (isinstance(brief_out, dict) and brief_out.get("error")):
                out["next"] = (
                    f"Mode=archive (session_id={session_id}). Brief looks empty "
                    "or walled — switch to interactive: "
                    "hardly_browser_start(headed=true, channel='chrome') and "
                    "ASK THE PERSON to click."
                )
                out["suggest_mode"] = "interactive"
            elif auth_thin and (brief_out or {}).get("host"):
                out["next"] = (
                    f"Mode=archive (session_id={session_id}). Little auth/"
                    "session material — try interactive capture or a richer "
                    "recipe; else hardly_endpoint_list / hardly_auth_report."
                )
                out["suggest_mode"] = "interactive"
            else:
                out["next"] = (
                    f"Mode=archive (session_id={session_id}). Drill with "
                    "hardly_auth_report / hardly_endpoint_list / hardly_session_trace_value; "
                    "if traffic looks thin, retry interactive with channel=chrome."
                )
        except Exception as exc:  # noqa: BLE001
            out["brief_error"] = str(exc)
            out["next"] = (
                f"Mode=archive (session_id={session_id}). "
                "Call hardly_session_site_brief / hardly_endpoint_list next."
            )
    else:
        out["next"] = (
            "Headless capture stopped. Mode=archive — hardly_session_open the HAR "
            "or use session_id with hardly_session_site_brief / hardly_endpoint_list."
        )
    return out


def _persist_payload(capture_id: str, payload: dict[str, Any]) -> None:
    path = active_dir() / f"{capture_id}.json"
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _load_sidecar(capture_id: str) -> dict[str, Any] | None:
    path = active_dir() / f"{capture_id}.json"
    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _next_steps(result: dict[str, Any]) -> str:
    if result.get("status") != "stopped":
        return f"Capture status={result.get('status')}; check error field."
    session = result.get("session") or {}
    sid = session.get("session_id")
    if sid:
        return (
            f"Mode=archive. Indexed as session_id={sid}. "
            "Call hardly_session_site_brief (portals) or hardly_endpoint_list (APIs); "
            "then correlate / forms / schema as needed — do not Read the HAR."
        )
    return (
        f"Mode=archive. HAR at {result.get('har_path')}. "
        "Call hardly_session_open on that path."
    )


def _version_tuple(version: str | None) -> tuple[int, ...]:
    if not version:
        return (0,)
    parts: list[int] = []
    for chunk in str(version).split(".")[:3]:
        digits = "".join(ch for ch in chunk if ch.isdigit())
        if digits:
            parts.append(int(digits))
    return tuple(parts) or (0,)


def _host_label(url: str) -> str:
    from urllib.parse import urlparse

    host = urlparse(url).hostname or "capture"
    return host.replace(".", "-")


def _count_har_entries(path: Path) -> int | None:
    if not path.is_file():
        return None
    try:
        import ijson

        count = 0
        with path.open("rb") as handle:
            for _ in ijson.items(handle, "log.entries.item"):
                count += 1
        return count
    except Exception:  # noqa: BLE001
        return None


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        # Windows: os.kill(pid, 0) is not always supported the same way.
        if sys.platform == "win32":
            return _pid_alive_win(pid)
        return False
    return True


def _pid_alive_win(pid: int) -> bool:
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid)
        if not handle:
            return False
        kernel32.CloseHandle(handle)
        return True
    except Exception:  # noqa: BLE001
        return False
