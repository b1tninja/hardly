"""First-use onboarding: an ordered, goal-aware plan plus environment state."""

from __future__ import annotations

from typing import Any

from hardly.core.modes import (
    MODE_ARCHIVE,
    MODE_HEADLESS,
    MODE_INTERACTIVE,
    pick_mode,
)

_SID = "<session_id>"

RULES = (
    "Never Read a raw HAR file; use hardly_session_open and the query tools.",
    "send_* tools and hardly_browser_capture_discover send nothing unless "
    "confirm=true (without it they return a plan); tell the person what will be "
    "sent first. write_* tools refuse to overwrite a file unless overwrite=true.",
    "Bot wall / captcha / MFA / login: stop and use interactive capture with a "
    "person; never evade or retry a challenged URL.",
    "Secret values are never returned; supply them via overrides/env only.",
)


def environment_state() -> dict[str, Any]:
    """Cheap, never-raising snapshot: browser availability and sessions."""
    env: dict[str, Any] = {"capture_available": False}
    try:
        from hardly.capture import playwright_status

        status = playwright_status()
        env["capture_available"] = bool(status.get("ready"))
        if not env["capture_available"]:
            env["capture_hint"] = (
                status.get("hint") or "run hardly_server_status(sections=['browser_setup']) for install steps"
            )
    except Exception as exc:  # noqa: BLE001
        env["capture_hint"] = f"capture unavailable ({type(exc).__name__}); archive mode still works"
    try:
        from hardly import session as sess

        rows = sess.list_sessions()
        env["sessions_open"] = sum(1 for r in rows if r.get("open"))
        env["sessions_cached"] = len(rows)
        env["recent_sessions"] = [r["session_id"] for r in rows if r.get("open")][:3]
    except Exception:  # noqa: BLE001
        env["sessions_open"] = 0
        env["sessions_cached"] = 0
        env["recent_sessions"] = []
    return env


def _has(text: str, *words: str) -> bool:
    return any(w in text for w in words)


def build_plan(goal: str = "", har_path: str = "", url: str = "") -> dict[str, Any]:
    text = (goal or "").lower()
    picked = pick_mode(goal=goal, har_path=har_path, url=url)
    mode = picked["mode"]
    env = environment_state()

    steps: list[dict[str, Any]] = []

    def add(tool: str, args: dict[str, Any], why: str) -> None:
        steps.append({"n": len(steps) + 1, "tool": tool, "args": args, "why": why})

    needs_browser = mode in (MODE_HEADLESS, MODE_INTERACTIVE)
    if needs_browser and not env["capture_available"]:
        add("hardly_server_status", {"sections": ["browser_setup"]}, "browser capture is not ready; get install commands")

    if mode == MODE_ARCHIVE:
        add("hardly_session_open", {"har_path": har_path or "<path/to/capture.har>"}, "index the HAR -> session_id")
    elif mode == MODE_HEADLESS:
        add(
            "hardly_browser_capture_discover",
            {
                "url": url or "<https://example.com>",
                "analyze": True,
                "channel": "chrome",
                "wait_seconds": 8,
                "confirm": True,
            },
            "headless load (confirm-gated) -> session_id + brief",
        )
    else:
        add(
            "hardly_browser_start",
            {"url": url or "<https://example.com>", "headed": True, "channel": "chrome"},
            "opens a visible browser",
        )
        add("(ask the person)", {}, "tell them what to click, wait until they say done")
        add("hardly_browser_stop", {"open_session": True}, "flush the HAR -> session_id")

    add("hardly_session_report", {"session_id": _SID, "detail": "summary"}, "evidence index: auth, stack, gates, blockers (~1 KB)")
    add("hardly_session_overview", {"session_id": _SID}, "pick main_host for host= arguments")
    add("hardly_session_site_brief", {"session_id": _SID}, "portal overview (or hardly_endpoint_list for JSON APIs)")

    if _has(text, "login", "auth", "token", "csrf", "credential", "session cookie"):
        add("hardly_auth_report", {"session_id": _SID, "sections": ["quick", "credentials"]}, "login/token map, names and shapes only")
        add("hardly_session_trace_value", {"session_id": _SID}, "values reused across requests (call without name or value)")
    if _has(text, "block", "captcha", "wall", "403", "denied", "gate"):
        add("hardly_gate_bot_protection", {"session_id": _SID, "explain": True}, "classify blocks; stop signs are not retried")
    if _has(text, "sdk", "client", "stub", "library", "wrapper", "scrape"):
        add("hardly_session_story", {"session_id": _SID, "host": "<main_host>"}, "annotated steps")
        add("hardly_entry_dependencies", {"session_id": _SID, "entry_id": "<target entry>"}, "dependencies of the key request")
        add("hardly_client_build", {"session_id": _SID}, "starter client source (nothing written); secrets are placeholders")
        add("hardly_write_export", {"session_id": _SID, "format": "client_python", "output_path": "<scratch>/client.py"}, "save the starter client")
        add("hardly_send_entry_series", {"session_id": _SID, "entry_id": "<entry>", "confirm": False}, "dry run plan; confirm=true only after the person agrees")
    elif _has(text, "openapi", "spec", "document", "api"):
        add("hardly_endpoint_list", {"session_id": _SID, "host": "<main_host>"}, "API surface")
        add("hardly_endpoint_schema", {"session_id": _SID, "method": "GET", "path_template": "<template>"}, "request/response shapes")
        add("hardly_write_export", {"session_id": _SID, "format": "openapi", "output_path": "<scratch>/api.yaml"}, "write the spec")
    else:
        add("hardly_entry_search", {"session_id": _SID, "limit": 10}, "find a specific request, then hardly_entry_get")

    out: dict[str, Any] = {
        "goal": goal or None,
        "mode": mode,
        "reason": picked.get("reason"),
        "environment": env,
        "plan": steps,
        "rules": list(RULES),
        "more": "Resources: hardly://cheatsheet, hardly://docs/concepts. Prompts: reverse_engineer_api, build_client_sdk, diagnose_blocked_capture, verify_client. hardly_guide_help(topic) lists all tools.",
    }
    if (goal or "").strip():
        from hardly.core.recommend import recommend_tools

        out["recommended_tools"] = recommend_tools(goal).get("suggestions", [])[:2]
    if env.get("recent_sessions"):
        out["hint"] = (
            "A session is already open: skip the open/capture step and use "
            f"session_id={env['recent_sessions'][0]!r}."
        )
    return out
