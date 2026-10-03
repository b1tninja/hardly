"""Spawn a browser and record a HAR 1.2 session.

Uses Playwright's built-in ``record_har_path``. The browser runs in a
**subprocess** (``python -m hardly.capture_worker``) so recording survives
after the CLI / MCP call returns. Optional dependency:
``pip install -e ".[capture]"`` then ``playwright install chromium``.

Control files under ``~/.cache/hardly/captures/active/``:

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

from hardly.core.browser_detect import (
    expected_chromium_build,
    pick_executable,
    pin_hint,
    scan_chromium_builds,
)
from hardly.core.capture_errors import TRANSIENT_NAV, with_error_class
from hardly.core.slots import SlotTimeoutError, acquire_slot, capture_slot
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

    @property
    def classification(self) -> dict[str, Any]:
        from hardly.core.capture_errors import classify_capture_error

        return classify_capture_error(str(self))

    def to_dict(self) -> dict[str, Any]:
        """Error dict with ``error_class`` / ``error_advice`` for tool results."""
        return with_error_class({"status": "error", "error": str(self)})


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
            + (" Playwright build mismatch: " + out["pin_hint"] if out.get("mismatch") and out.get("pin_hint") else "")
        )
    elif channel:
        out["hint"] = (
            f"Ready (channel={channel}). Prefer channel=chrome for Akamai / bot walls."
        )
    else:
        out["hint"] = (
            "Ready with bundled Chromium. For county / Akamai portals prefer "
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
    if env_exe:
        out["browser_executable_source"] = "env"
        out["suggested_executable"] = env_exe
    elif channel:
        out["browser_executable_source"] = "channel"
    elif chromium_ok:
        out["browser_executable_source"] = "playwright"
    elif picked:
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
    from hardly.session import cache_dir

    path = cache_dir() / "captures" / "active"
    path.mkdir(parents=True, exist_ok=True)
    return path


def default_har_path(label: str = "capture") -> Path:
    from hardly.session import cache_dir

    stamp = time.strftime("%Y%m%d-%H%M%S")
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in label)[:40] or "capture"
    path = cache_dir() / "captures" / f"{safe}-{stamp}.har"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


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
    if env_exe:
        return {"executable": str(Path(env_exe).expanduser()), "source": "env"}
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
) -> dict[str, Any]:
    """Launch Chromium with HAR recording in a durable subprocess.

    ``same_tab`` (default True) rewrites ``target=_blank`` / ``window.open``
    into the current tab. Popups in the same Playwright context are still
    recorded either way (HAR is context-scoped).

    ``trace`` writes a Playwright ``.trace.zip`` beside the HAR (view with
    ``playwright show-trace``). Default: env ``HARDLY_CAPTURE_TRACE=1``.
    """
    require_playwright(need_browser=True)

    label_key = (label or _host_label(url) or "capture").strip()
    target = resolve_path(har_path) if har_path else default_har_path(label_key)
    target.parent.mkdir(parents=True, exist_ok=True)
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
                raise CaptureError(
                    row.get("error")
                    or f"capture worker exited early (code={proc.returncode}): {tail}"
                )
            break
        time.sleep(0.1)

    row = row or _load_sidecar(capture_id) or {}
    if row.get("status") == "error":
        raise CaptureError(str(row.get("error") or "capture failed"))
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
            "Optional: hardly_capture_screenshot / _status while they work.",
            "When they finish: hardly_capture_stop(open_session=true) then "
            "hardly_brief.",
        ]
        row["ask_user"] = (
            "A headed browser is recording. Ask the person to complete the "
            "portal steps you need traffic for, then call hardly_capture_stop."
        )
    else:
        next_bits = [
            "Mode=headless: drive with hardly_capture_aria -> "
            "click/fill ref='eN' (or hardly_capture_recipe), then "
            "hardly_capture_stop.",
            "Or use hardly_discover(url) for a one-shot load+optional recipe.",
        ]
        row["ask_user"] = None
    if not use_channel:
        next_bits.insert(
            0,
            "No channel set - for Akamai/bot walls restart with channel=chrome "
            "or HARDLY_BROWSER_CHANNEL=chrome.",
        )
        row["channel_hint"] = "chrome"
    row["next"] = " ".join(next_bits)
    return row


def stop_capture(
    capture_id: str | None = None,
    *,
    open_session: bool = True,
    force: bool = False,
) -> dict[str, Any]:
    """Stop recording (latest running if id omitted), optionally open_har."""
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
    if result.get("entry_count_hint") is None and har.is_file():
        result["entry_count_hint"] = _count_har_entries(har)

    if open_session and result.get("status") == "stopped" and har.is_file():
        from hardly import session as sess

        opened = sess.open_har(str(har), force=force)
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
    {"elements", "click", "fill", "press", "url", "aria", "screenshot"}
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
) -> dict[str, Any]:
    """Click a visible control on the active capture tab.

    Prefer ``ref`` from ``hardly_capture_aria`` (``e12`` / ``[ref=e12]``).
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

    Prefer ``ref`` from ``hardly_capture_aria`` when available.
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
    }
)


def run_capture_recipe(
    steps: list[dict[str, Any]] | list[Any],
    *,
    capture_id: str | None = None,
    stop_on_error: bool = True,
) -> dict[str, Any]:
    """Run a sequence of capture ops against the live browser.

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
        if not isinstance(raw, dict):
            raise CaptureError(f"step {i} must be an object")
        op = str(raw.get("op") or "").strip().lower()
        if op not in _RECIPE_OPS:
            raise CaptureError(
                f"step {i}: unknown op {op!r}; known: {sorted(_RECIPE_OPS)}"
            )
        step_out: dict[str, Any] = {"index": i, "op": op}
        try:
            if op == "goto":
                url = str(raw.get("url") or "").strip()
                if not url:
                    raise CaptureError("goto requires url")
                navigate_capture(cid, url)
                # Give navigation a moment; url rpc confirms.
                time.sleep(min(float(raw.get("ms") or 500) / 1000.0, 10.0))
                step_out["result"] = capture_page_url(cid)
            elif op == "wait":
                ms = min(max(int(raw.get("ms") or 1000), 0), 30_000)
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
                    timeout_ms=int(raw.get("timeout_ms") or 10_000),
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
            found.append(payload)
    return sorted(found, key=lambda row: row.get("started_at") or 0, reverse=True)


def get_capture(capture_id: str) -> dict[str, Any]:
    row = _load_sidecar(capture_id)
    if not row:
        raise CaptureError(f"unknown capture_id {capture_id!r}")
    return row


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
    )
    print(f"Recording to {info['har_path']}")
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
    return stop_capture(info["capture_id"], open_session=True)


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
) -> dict[str, Any]:
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
    )
    try:
        time.sleep(max(0.0, float(wait_seconds)))
    except BaseException:
        stop_capture(info["capture_id"], open_session=False)
        raise
    return stop_capture(info["capture_id"], open_session=open_session)


def capture_headless(
    url: str,
    har_path: str | Path | None = None,
    *,
    wait_seconds: float = 3,
    recipe: list[dict[str, Any]] | None = None,
    channel: str = "",
    url_filter: str = "",
    omit_content: bool = False,
    label: str = "",
    open_session: bool = True,
    same_tab: bool = True,
    brief: bool = False,
) -> dict[str, Any]:
    """In-process headless HAR capture for soak / unit tests.

    Unlike ``start_capture`` (subprocess worker for interactive MCP use), this
    runs Playwright in the current process, flushes the HAR on context close,
    and returns immediately — no ``.stop`` sidecar race.
    """
    require_playwright(need_browser=True)
    target_url = str(url or "").strip()
    if not target_url:
        raise CaptureError("capture_headless requires url")

    label_key = (label or _host_label(target_url) or "capture").strip()
    target = resolve_path(har_path) if har_path else default_har_path(label_key)
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        target.unlink()

    use_channel = (channel or default_channel()).strip()
    body_sidecar: list[dict[str, Any]] = []
    recipe_result: dict[str, Any] | None = None
    started_at = time.time()

    from playwright.sync_api import sync_playwright

    with sync_playwright() as playwright:
        launch_kwargs: dict[str, Any] = {"headless": True}
        if use_channel:
            launch_kwargs["channel"] = use_channel
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
            try:
                if target_url and target_url != "about:blank":
                    page.goto(
                        target_url, wait_until="domcontentloaded", timeout=60_000
                    )
                elif target_url == "about:blank":
                    page.goto("about:blank")
            except Exception as exc:  # noqa: BLE001
                # API roots that return 204 / abort navigation still allow
                # recipe fetch/evaluate against absolute URLs.
                goto_error = str(exc)
                if not recipe:
                    raise CaptureError(goto_error) from exc
                try:
                    page.goto("about:blank")
                except Exception:  # noqa: BLE001
                    pass
            if recipe:
                recipe_result = _run_inprocess_recipe(page, recipe)
                if goto_error:
                    recipe_result = {
                        **(recipe_result or {}),
                        "goto_error": goto_error,
                        "goto_recovered": True,
                    }
            settle_ms = int(max(0.0, float(wait_seconds)) * 1000)
            if settle_ms:
                page.wait_for_timeout(min(settle_ms, 60_000))
            context.close()  # flushes HAR
        finally:
            browser.close()

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
        },
    }
    if out["status"] != "stopped":
        out["error"] = "HAR was not written"
        return out

    if open_session:
        from hardly import session as sess

        opened = sess.open_har(str(target), force=True)
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


def _run_inprocess_recipe(page: Any, steps: list[dict[str, Any]]) -> dict[str, Any]:
    """Minimal recipe runner for in-process headless capture (goto/wait/click/fill)."""
    results: list[dict[str, Any]] = []
    for raw in steps:
        if not isinstance(raw, dict):
            results.append({"ok": False, "error": "step must be an object"})
            continue
        op = str(raw.get("op") or "").strip().lower()
        step_out: dict[str, Any] = {"op": op, "ok": True}
        try:
            if op == "wait":
                ms = min(max(int(raw.get("ms") or 1000), 0), 30_000)
                page.wait_for_timeout(ms)
                step_out["result"] = {"waited_ms": ms}
            elif op == "goto":
                dest = str(raw.get("url") or "").strip()
                if not dest:
                    raise CaptureError("goto requires url")
                page.goto(dest, wait_until="domcontentloaded", timeout=60_000)
                step_out["result"] = {"url": page.url}
            elif op == "click":
                css = str(raw.get("css") or raw.get("selector") or "").strip()
                if not css:
                    raise CaptureError("click requires css")
                page.locator(css).first.click(timeout=int(raw.get("timeout_ms") or 10_000))
                page.wait_for_timeout(300)
                step_out["result"] = {"url": page.url}
            elif op == "fill":
                css = str(raw.get("css") or raw.get("selector") or "").strip()
                if not css:
                    raise CaptureError("fill requires css")
                page.locator(css).first.fill(
                    str(raw.get("value") or ""),
                    timeout=int(raw.get("timeout_ms") or 10_000),
                )
                step_out["result"] = {"url": page.url}
            elif op == "press":
                page.keyboard.press(str(raw.get("key") or "Enter"))
                step_out["result"] = {"url": page.url}
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
        results.append(step_out)
    return {
        "steps": results,
        "ok": all(s.get("ok") for s in results),
        "step_count": len(results),
    }


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
) -> dict[str, Any]:
    """Headless mode: load URL, optional recipe, stop, open session, brief.

    For agent-driven API discovery without asking a person to click. If the
    page walls the headless browser, switch to interactive mode
    (``hardly_capture_start(headed=true, channel=chrome)``).

    Default path is in-process (``capture_headless``) so soak/tests and one-shot
    discover do not depend on the subprocess ``.stop`` sidecar. Set
    ``HARDLY_CAPTURE_SUBPROCESS=1`` to force the durable worker (needed only when
    you will drive the tab after start with aria/click RPCs).
    """
    target = str(url or "").strip()
    if not target:
        raise CaptureError("discover_apis requires url")

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
                    "hardly_capture_start(headed=true, channel='chrome') and "
                    "ASK THE PERSON to click."
                )
                out["suggest_mode"] = "interactive"
            elif auth_thin and brief_out.get("host"):
                out["next"] = (
                    f"Mode=archive (session_id={session_id}). Little auth/"
                    "session material — try interactive capture or a richer "
                    "recipe; else hardly_endpoints / hardly_credentials."
                )
                out["suggest_mode"] = "interactive"
            else:
                out["next"] = (
                    f"Mode=archive (session_id={session_id}). Drill with "
                    "hardly_credentials / hardly_endpoints / hardly_correlate; "
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
                    "hardly_capture_start(headed=true, channel='chrome') and "
                    "ASK THE PERSON to click."
                )
                out["suggest_mode"] = "interactive"
            elif auth_thin and (brief_out or {}).get("host"):
                out["next"] = (
                    f"Mode=archive (session_id={session_id}). Little auth/"
                    "session material — try interactive capture or a richer "
                    "recipe; else hardly_endpoints / hardly_credentials."
                )
                out["suggest_mode"] = "interactive"
            else:
                out["next"] = (
                    f"Mode=archive (session_id={session_id}). Drill with "
                    "hardly_credentials / hardly_endpoints / hardly_correlate; "
                    "if traffic looks thin, retry interactive with channel=chrome."
                )
        except Exception as exc:  # noqa: BLE001
            out["brief_error"] = str(exc)
            out["next"] = (
                f"Mode=archive (session_id={session_id}). "
                "Call hardly_brief / hardly_endpoints next."
            )
    else:
        out["next"] = (
            "Headless capture stopped. Mode=archive — hardly_open the HAR "
            "or use session_id with hardly_brief / hardly_endpoints."
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
            "Call hardly_brief (portals) or hardly_endpoints (APIs); "
            "then correlate / forms / schema as needed — do not Read the HAR."
        )
    return (
        f"Mode=archive. HAR at {result.get('har_path')}. "
        "Call hardly_open on that path."
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
