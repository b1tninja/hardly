"""Long-lived Playwright process that owns one HAR capture.

Started by ``hardly.capture.start_capture`` as a subprocess so the browser
survives after the CLI / MCP call returns. Controlled via sidecar files in
``~/.cache/hardly/captures/active/``:

- ``{id}.json`` — status
- ``{id}.stop`` — request stop
- ``{id}.cmd`` — one command per line (``goto <url>``)
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m hardly.capture_worker")
    p.add_argument("job", help="Path to job JSON written by start_capture")
    args = p.parse_args(argv)
    job_path = Path(args.job)
    job = json.loads(job_path.read_text(encoding="utf-8"))
    return run_job(job)


def run_job(job: dict) -> int:
    from hardly.capture import (
        _BANNER_JS,
        _SAME_TAB_JS,
        _count_har_entries,
        _persist_payload,
        active_dir,
    )

    capture_id = job["capture_id"]
    har_path = Path(job["har_path"])
    url = str(job.get("url") or "")
    headed = bool(job.get("headed", True))
    channel = str(job.get("channel") or "")
    url_filter = str(job.get("url_filter") or "")
    omit_content = bool(job.get("omit_content"))
    show_banner = bool(job.get("show_banner", True))
    same_tab = bool(job.get("same_tab", True))
    trace = bool(job.get("trace"))
    viewport_width = int(job.get("viewport_width") or 1280)
    viewport_height = int(job.get("viewport_height") or 900)
    profile = job.get("user_data_dir") or None
    started_at = float(job.get("started_at") or time.time())
    trace_path = har_path.with_suffix(".trace.zip")

    def publish(**extra) -> None:
        payload = {
            "capture_id": capture_id,
            "har_path": str(har_path),
            "url": url,
            "headed": headed,
            "channel": channel or None,
            "url_filter": url_filter or None,
            "omit_content": omit_content,
            "label": job.get("label"),
            "same_tab": same_tab,
            "trace": trace,
            "trace_path": str(trace_path) if trace else None,
            "status": "starting",
            "error": None,
            "started_at": started_at,
            "stopped_at": None,
            "entry_count_hint": None,
            "har_exists": har_path.is_file(),
            "har_bytes": har_path.stat().st_size if har_path.is_file() else 0,
            "pid": __import__("os").getpid(),
            "pages": 0,
        }
        payload.update(extra)
        payload["har_exists"] = har_path.is_file()
        payload["har_bytes"] = har_path.stat().st_size if har_path.is_file() else 0
        _persist_payload(capture_id, payload)

    stop_path = active_dir() / f"{capture_id}.stop"
    cmd_path = active_dir() / f"{capture_id}.cmd"
    rpc_path = active_dir() / f"{capture_id}.rpc.json"
    rpc_out_path = active_dir() / f"{capture_id}.rpc.out.json"
    stop_path.unlink(missing_ok=True)
    cmd_path.unlink(missing_ok=True)
    rpc_path.unlink(missing_ok=True)
    rpc_out_path.unlink(missing_ok=True)

    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        publish(
            status="error",
            error=(
                f"{exc}. Install with: pip install -e \".[capture]\" "
                "&& playwright install chromium"
            ),
            stopped_at=time.time(),
        )
        return 1

    try:
        with sync_playwright() as playwright:
            launch_kwargs: dict = {"headless": not headed}
            if channel:
                launch_kwargs["channel"] = channel
            else:
                from hardly.capture import default_executable

                if default_executable():
                    launch_kwargs["executable_path"] = default_executable()

            context_kwargs: dict = {
                "record_har_path": str(har_path),
                "record_har_mode": "full",
                "record_har_content": "omit" if omit_content else "embed",
                "viewport": {"width": viewport_width, "height": viewport_height},
                "ignore_https_errors": True,
            }
            if url_filter:
                context_kwargs["record_har_url_filter"] = url_filter

            try:
                if profile:
                    Path(profile).mkdir(parents=True, exist_ok=True)
                    context = playwright.chromium.launch_persistent_context(
                        str(profile),
                        **launch_kwargs,
                        **context_kwargs,
                    )
                    browser = None
                    page = context.pages[0] if context.pages else context.new_page()
                else:
                    browser = playwright.chromium.launch(**launch_kwargs)
                    context = browser.new_context(**context_kwargs)
                    page = context.new_page()
            except Exception as exc:  # noqa: BLE001
                msg = str(exc)
                if "Executable doesn't exist" in msg or "browserType.launch" in msg:
                    msg = (
                        f"{msg}. Browser binary missing — run: "
                        "playwright install chromium "
                        "(or pass channel=chrome / HARDLY_BROWSER_CHANNEL=chrome)"
                    )
                publish(status="error", error=msg, stopped_at=time.time())
                return 1

            # Init scripts apply to every page/popup in this context.
            if same_tab:
                context.add_init_script(_SAME_TAB_JS)
            if show_banner and headed:
                context.add_init_script(_BANNER_JS)

            if trace:
                try:
                    context.tracing.start(
                        screenshots=True, snapshots=True, sources=False
                    )
                except Exception:  # noqa: BLE001
                    trace = False
                    publish(trace=False, trace_path=None)

            # Playwright often leaves XHR content.size == -1 with no text.
            # Keep text-ish bodies here and merge after the HAR is flushed.
            body_sidecar: list[dict] = []

            if not omit_content:
                from hardly.core.har_bodies import interesting_mime, shape_body

                def on_response(response) -> None:
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
                    except Exception:  # noqa: BLE001 — body already consumed / binary
                        return

                context.on("response", on_response)

            pages = list(context.pages) or [page]

            def on_page(new_page) -> None:
                # Do not wait/load here — sync handlers that block prevent CDP
                # from sending Runtime.runIfWaitingForDebugger to other targets.
                pages.append(new_page)

            context.on("page", on_page)

            def active_page():
                for candidate in reversed(pages):
                    try:
                        if not candidate.is_closed():
                            return candidate
                    except Exception:  # noqa: BLE001
                        continue
                for candidate in context.pages:
                    try:
                        if not candidate.is_closed():
                            return candidate
                    except Exception:  # noqa: BLE001
                        continue
                return None

            def page_count() -> int:
                n = 0
                for candidate in context.pages:
                    try:
                        if not candidate.is_closed():
                            n += 1
                    except Exception:  # noqa: BLE001
                        continue
                return n

            def pump(ms: int = 250) -> None:
                # Must use Playwright waits, not time.sleep — sleep blocks the
                # sync driver so new popups stay paused waiting for debugger.
                target = active_page()
                if target is not None:
                    try:
                        target.wait_for_timeout(ms)
                        return
                    except Exception:  # noqa: BLE001
                        pass
                time.sleep(ms / 1000.0)

            if url:
                page.goto(url, wait_until="domcontentloaded", timeout=60_000)
            last_pages = page_count()
            publish(status="running", pages=last_pages)

            def handle_rpc(req: dict) -> dict:
                from hardly.core.dom_elements import LIST_ELEMENTS_JS

                target = active_page()
                if target is None:
                    return {"error": "no active page"}
                op = str(req.get("op") or "")
                args = req.get("args") or {}
                if not isinstance(args, dict):
                    args = {}
                try:
                    if op == "url":
                        return {
                            "url": target.url,
                            "title": target.title(),
                            "pages": page_count(),
                        }
                    if op == "elements":
                        data = target.evaluate(
                            LIST_ELEMENTS_JS,
                            {
                                "limit": int(args.get("limit") or 40),
                                "query": str(args.get("query") or ""),
                            },
                        )
                        return data if isinstance(data, dict) else {"elements": data}
                    if op == "click":
                        locator = _resolve_locator(target, args)
                        locator.click(timeout=int(args.get("timeout_ms") or 10_000))
                        target.wait_for_timeout(300)
                        return {
                            "ok": True,
                            "url": target.url,
                            "title": target.title(),
                        }
                    if op == "fill":
                        locator = _resolve_locator(target, args)
                        locator.fill(
                            str(args.get("value") or ""),
                            timeout=int(args.get("timeout_ms") or 10_000),
                        )
                        return {"ok": True, "url": target.url}
                    if op == "press":
                        key = str(args.get("key") or "Enter")
                        has_target = any(
                            args.get(k)
                            for k in ("ref", "xpath", "css", "text", "role")
                        )
                        locator = _resolve_locator(target, args) if has_target else None
                        if locator is not None:
                            locator.press(key, timeout=int(args.get("timeout_ms") or 10_000))
                        else:
                            target.keyboard.press(key)
                        return {"ok": True, "url": target.url}
                    if op == "aria":
                        # Playwright accessibility-tree YAML (rendered DOM).
                        # Prefer mode="ai" (refs) when the installed Playwright supports it.
                        sel = str(args.get("selector") or "").strip()
                        mode = str(args.get("mode") or "ai").strip().lower()
                        if mode not in {"ai", "default"}:
                            mode = "ai"
                        loc = target.locator(sel).first if sel else target.locator("body")
                        snap = None
                        used_mode = mode
                        try:
                            snap = loc.aria_snapshot(mode=mode)
                        except TypeError:
                            # Older Playwright (<1.59) — no mode kwarg
                            snap = loc.aria_snapshot()
                            used_mode = "default"
                        except Exception:
                            if mode != "default":
                                snap = loc.aria_snapshot()
                                used_mode = "default"
                            else:
                                raise
                        from hardly.core.aria_refs import parse_aria_refs

                        refs = parse_aria_refs(snap or "", limit=80)
                        return {
                            "url": target.url,
                            "title": target.title(),
                            "selector": sel or "body",
                            "mode": used_mode,
                            "aria": snap,
                            "refs": refs,
                            "ref_count": len(refs),
                            "format": "playwright_aria_snapshot_yaml",
                            "note": (
                                "Live accessibility tree. "
                                + (
                                    "Use refs[].ref with hardly_capture_click/"
                                    "fill (ref='e12'). "
                                    if refs
                                    else ""
                                )
                                +                             "Offline HAR bodies: hardly_outline."
                            ),
                        }
                    if op == "screenshot":
                        out = str(args.get("path") or "").strip()
                        if not out:
                            stamp = time.strftime("%Y%m%d-%H%M%S")
                            out = str(
                                active_dir()
                                / f"{capture_id}-shot-{stamp}.png"
                            )
                        Path(out).parent.mkdir(parents=True, exist_ok=True)
                        target.screenshot(
                            path=out,
                            full_page=bool(args.get("full_page")),
                        )
                        return {
                            "ok": True,
                            "path": out,
                            "url": target.url,
                            "full_page": bool(args.get("full_page")),
                        }
                    return {"error": f"unknown op {op!r}"}
                except Exception as exc:  # noqa: BLE001
                    return {"error": str(exc)}

            while True:
                if stop_path.is_file():
                    break
                if rpc_path.is_file():
                    try:
                        req = json.loads(rpc_path.read_text(encoding="utf-8"))
                        rpc_path.unlink(missing_ok=True)
                    except (OSError, json.JSONDecodeError):
                        req = None
                    if isinstance(req, dict) and req.get("id"):
                        result = handle_rpc(req)
                        reply = {"id": req["id"]}
                        if isinstance(result, dict) and result.get("error"):
                            reply["error"] = result["error"]
                        else:
                            reply["result"] = result
                        try:
                            rpc_out_path.write_text(
                                json.dumps(reply), encoding="utf-8"
                            )
                        except OSError:
                            pass
                if cmd_path.is_file():
                    try:
                        lines = cmd_path.read_text(encoding="utf-8").splitlines()
                        cmd_path.unlink(missing_ok=True)
                    except OSError:
                        lines = []
                    for line in lines:
                        line = line.strip()
                        if not line:
                            continue
                        if line.startswith("goto "):
                            url = line[5:].strip()
                            target = active_page()
                            if target is None:
                                target = context.new_page()
                                pages.append(target)
                            target.goto(
                                url, wait_until="domcontentloaded", timeout=60_000
                            )
                            last_pages = page_count()
                            publish(status="running", url=url, pages=last_pages)
                try:
                    n = page_count()
                    # Closing every window does NOT disconnect Chromium —
                    # treat zero pages as "user closed the browser".
                    if headed and n == 0:
                        break
                    if browser is not None and not browser.is_connected():
                        break
                    if n != last_pages:
                        last_pages = n
                        publish(status="running", pages=n)
                except Exception:  # noqa: BLE001
                    break
                pump(250)

            publish(status="stopping", pages=page_count())
            trace_written = False
            if trace:
                try:
                    context.tracing.stop(path=str(trace_path))
                    trace_written = trace_path.is_file()
                except Exception:  # noqa: BLE001
                    try:
                        context.tracing.stop()
                    except Exception:  # noqa: BLE001
                        pass
            context.close()
            if browser is not None:
                browser.close()
            bodies_filled = 0
            if body_sidecar and har_path.is_file():
                from hardly.core.har_bodies import merge_bodies_into_har

                try:
                    bodies_filled = merge_bodies_into_har(
                        har_path, body_sidecar
                    ).get("filled", 0)
                except Exception:  # noqa: BLE001 — keep the HAR even if merge fails
                    bodies_filled = 0
            publish(
                status="stopped",
                stopped_at=time.time(),
                entry_count_hint=_count_har_entries(har_path),
                bodies_filled=bodies_filled,
                trace_path=str(trace_path) if trace_written else None,
                pages=0,
            )
            return 0
    except Exception as exc:  # noqa: BLE001
        publish(status="error", error=str(exc), stopped_at=time.time())
        return 1
    finally:
        stop_path.unlink(missing_ok=True)
        job_path = active_dir() / f"{capture_id}.job.json"
        job_path.unlink(missing_ok=True)


def _resolve_locator(page, args: dict):
    """Build a Playwright locator from ref / xpath / css / role / text args.

    ``ref`` comes from ``hardly_capture_aria(mode="ai")`` markers like
    ``[ref=e12]`` and is resolved via Playwright's ``aria-ref`` engine.
    """
    from hardly.core.aria_refs import normalize_aria_ref

    ref = normalize_aria_ref(str(args.get("ref") or ""))
    xpath = str(args.get("xpath") or "").strip()
    css = str(args.get("css") or "").strip()
    text = str(args.get("text") or "").strip()
    role = str(args.get("role") or "").strip()
    name = str(args.get("name") or "").strip()
    if ref:
        return page.locator(f"aria-ref={ref}").first
    if xpath:
        return page.locator(f"xpath={xpath}").first
    if css:
        return page.locator(css).first
    if role:
        kwargs = {}
        if name:
            kwargs["name"] = name
        return page.get_by_role(role, **kwargs).first
    if text:
        return page.get_by_text(text, exact=False).first
    raise ValueError("pass ref, xpath, css, text, or role")


if __name__ == "__main__":
    sys.exit(main())
