"""Three operating modes for agents: archive, headless, interactive."""

from __future__ import annotations

from typing import Any

MODE_ARCHIVE = "archive"
MODE_HEADLESS = "headless"
MODE_INTERACTIVE = "interactive"

MODES: tuple[dict[str, Any], ...] = (
    {
        "id": MODE_ARCHIVE,
        "title": "Archive (existing HAR file)",
        "when": (
            "A HAR path is already available — DevTools export, prior capture, "
            "or asspy sample. No Playwright needed."
        ),
        "needs_playwright": False,
        "needs_user": False,
        "entry_tools": [
            "hardly_open",
            "hardly_brief",
            "hardly_endpoints",
            "hardly_content",
        ],
        "tools": [
            "hardly_open",
            "hardly_reopen",
            "hardly_hosts",
            "hardly_summary",
            "hardly_endpoints",
            "hardly_content",
            "hardly_brief",
            "hardly_story",
            "hardly_forms",
            "hardly_ui",
            "hardly_outline",
            "hardly_correlate",
            "hardly_trace",
            "hardly_cookies",
            "hardly_secrets",
            "hardly_routes",
            "hardly_around",
            "hardly_tree",
            "hardly_auth",
            "hardly_schema",
            "hardly_stub",
            "hardly_export_brief",
            "hardly_export_openapi",
        ],
        "steps": [
            "hardly_open(har_path) -> session_id",
            "hardly_hosts — note preferred_host (apex HTML)",
            "Portal: hardly_brief -> forms/outline/correlate/trace",
            "JSON API: hardly_endpoints -> content -> auth -> schema",
            "Export: stub / export_brief / export_openapi as needed",
            "Never Read the raw HAR into the model",
        ],
        "prompt": "analyze_har",
        "ask_user": None,
    },
    {
        "id": MODE_HEADLESS,
        "title": "Headless Playwright (agent discovers APIs)",
        "when": (
            "No HAR yet, and the agent can drive the page itself "
            "(aria refs, recipe steps, or a timed load). Prefer when the UI "
            "is scriptable and bot walls are mild."
        ),
        "needs_playwright": True,
        "needs_user": False,
        "entry_tools": [
            "hardly_capture_doctor",
            "hardly_discover",
            "hardly_capture_start",
            "hardly_capture_aria",
            "hardly_capture_recipe",
        ],
        "tools": [
            "hardly_capture_doctor",
            "hardly_discover",
            "hardly_capture_once",
            "hardly_capture_start",
            "hardly_capture_goto",
            "hardly_capture_aria",
            "hardly_capture_click",
            "hardly_capture_fill",
            "hardly_capture_press",
            "hardly_capture_recipe",
            "hardly_capture_stop",
            "hardly_brief",
            "hardly_endpoints",
            "hardly_content",
        ],
        "steps": [
            "hardly_capture_doctor if capture_available is false",
            "One-shot: hardly_discover(url, recipe=optional steps) "
            "-> session_id + brief",
            "Or loop: hardly_capture_start(url, headed=false) -> "
            "hardly_capture_aria -> click/fill with ref -> "
            "hardly_capture_stop(open_session=true)",
            "Then continue in archive mode on the new session",
            "If wall/403: switch to interactive + channel=chrome",
        ],
        "prompt": "discover_apis",
        "ask_user": None,
    },
    {
        "id": MODE_INTERACTIVE,
        "title": "Interactive Playwright (person drives the browser)",
        "when": (
            "Bot walls, CAPTCHA, MFA, complex search UIs, or any flow the "
            "agent cannot reliably script. A headed window stays open; the "
            "agent asks the person to click, then stops and analyzes."
        ),
        "needs_playwright": True,
        "needs_user": True,
        "entry_tools": [
            "hardly_capture_doctor",
            "hardly_capture_start",
            "hardly_capture_stop",
            "hardly_brief",
        ],
        "tools": [
            "hardly_capture_doctor",
            "hardly_capture_start",
            "hardly_capture_status",
            "hardly_capture_screenshot",
            "hardly_capture_aria",
            "hardly_capture_stop",
            "hardly_brief",
            "hardly_wall",
            "hardly_issues",
        ],
        "steps": [
            "hardly_capture_doctor if capture_available is false",
            "hardly_capture_start(url, headed=true, channel='chrome')",
            "ASK THE PERSON to use the open browser "
            "(accept cookies, search, open a detail, login, …)",
            "Optionally hardly_capture_screenshot / _status while they work",
            "When they are done: hardly_capture_stop -> session_id",
            "hardly_brief / endpoints — same as archive mode from here",
        ],
        "prompt": "capture_portal",
        "ask_user": (
            "A headed browser window is recording. Ask the person to "
            "complete the portal steps you need traffic for, then call "
            "hardly_capture_stop when they say they are finished."
        ),
    },
)


def list_modes() -> dict[str, Any]:
    """Catalog of operating modes for agents."""
    return {
        "modes": [
            {
                "id": m["id"],
                "title": m["title"],
                "when": m["when"],
                "needs_playwright": m["needs_playwright"],
                "needs_user": m["needs_user"],
                "entry_tools": list(m["entry_tools"]),
                "prompt": m["prompt"],
            }
            for m in MODES
        ],
        "summary": [
            "archive — open an existing .har (hardly_open); no browser",
            "headless — hardly_discover(url) or capture_start(headed=false)",
            "interactive — capture_start(headed=true); ask the person to click",
        ],
        "pick": (
            "Call hardly_mode(mode) for a full playbook, or "
            "hardly_mode(goal=…) / hardly_mode(har_path=…, url=…) to pick."
        ),
        "rule": (
            "HAR path known -> archive. "
            "URL only and scriptable -> headless (hardly_discover). "
            "Walls / MFA / person needed -> interactive."
        ),
    }


def get_mode(mode_id: str) -> dict[str, Any] | None:
    key = (mode_id or "").strip().lower()
    aliases = {
        "file": MODE_ARCHIVE,
        "har": MODE_ARCHIVE,
        "offline": MODE_ARCHIVE,
        "analyze": MODE_ARCHIVE,
        "auto": MODE_HEADLESS,
        "discover": MODE_HEADLESS,
        "agent": MODE_HEADLESS,
        "headed": MODE_INTERACTIVE,
        "manual": MODE_INTERACTIVE,
        "user": MODE_INTERACTIVE,
        "human": MODE_INTERACTIVE,
    }
    key = aliases.get(key, key)
    for m in MODES:
        if m["id"] == key:
            return dict(m)
    return None


def pick_mode(
    *,
    goal: str = "",
    har_path: str = "",
    url: str = "",
    prefer: str = "",
) -> dict[str, Any]:
    """Choose a mode from inputs; optional prefer= overrides heuristics."""
    if prefer:
        chosen = get_mode(prefer)
        if chosen:
            return {
                "mode": chosen["id"],
                "reason": f"explicit prefer={prefer!r}",
                "playbook": mode_playbook(chosen["id"], har_path=har_path, url=url),
            }
        return {"error": f"unknown mode {prefer!r}", "modes": list_modes()["modes"]}

    text = (goal or "").strip().lower()
    har = (har_path or "").strip()
    target = (url or "").strip()

    interactive_kw = (
        "interactive",
        "headed",
        "ask user",
        "ask the user",
        "person",
        "human",
        "captcha",
        "mfa",
        "2fa",
        "bot wall",
        "akamai",
        "cloudflare",
        "login page",
    )
    headless_kw = (
        "headless",
        "discover",
        "auto",
        "automate",
        "script",
        "recipe",
        "no har",
        "record",
        "capture url",
    )
    archive_kw = (
        "archive",
        "file",
        "existing har",
        "open har",
        "analyze har",
        "offline",
        ".har",
    )

    if har and not any(k in text for k in interactive_kw + headless_kw):
        mid = MODE_ARCHIVE
        reason = "har_path provided — analyze the archive without a browser"
    elif any(k in text for k in interactive_kw):
        mid = MODE_INTERACTIVE
        reason = "goal needs a person (wall/MFA/interactive)"
    elif any(k in text for k in headless_kw) or (target and not har):
        mid = MODE_HEADLESS
        reason = (
            "URL to discover without a person"
            if target
            else "goal asks for automated/headless discovery"
        )
    elif any(k in text for k in archive_kw) or har:
        mid = MODE_ARCHIVE
        reason = "analyze an existing HAR archive"
    elif target:
        mid = MODE_HEADLESS
        reason = "URL only — try headless discover first"
    else:
        mid = MODE_ARCHIVE
        reason = "default: open a HAR archive if you have one; else pick headless/interactive"

    return {
        "mode": mid,
        "reason": reason,
        "playbook": mode_playbook(mid, har_path=har, url=target, goal=goal),
    }


def mode_playbook(
    mode_id: str,
    *,
    har_path: str = "",
    url: str = "",
    goal: str = "",
) -> dict[str, Any]:
    """Concrete steps and tool calls for one mode."""
    mode = get_mode(mode_id)
    if not mode:
        return {"error": f"unknown mode {mode_id!r}", "modes": [m["id"] for m in MODES]}

    har = (har_path or "").strip()
    target = (url or "").strip()
    steps = list(mode["steps"])
    calls: list[dict[str, Any]] = []

    if mode["id"] == MODE_ARCHIVE:
        if har:
            calls.append(
                {
                    "tool": "hardly_open",
                    "args": {"har_path": har},
                    "note": "then use returned session_id",
                }
            )
            calls.append(
                {
                    "tool": "hardly_brief",
                    "args": {"session_id": "<from open>"},
                    "note": "or hardly_endpoints for JSON APIs",
                }
            )
        else:
            calls.append(
                {
                    "tool": "hardly_open",
                    "args": {"har_path": "<path/to/capture.har>"},
                }
            )
    elif mode["id"] == MODE_HEADLESS:
        calls.append({"tool": "hardly_capture_doctor", "args": {}})
        if target:
            calls.append(
                {
                    "tool": "hardly_discover",
                    "args": {
                        "url": target,
                        "wait_seconds": 8,
                        "channel": "chrome",
                    },
                    "note": (
                        "one-shot headless load (+ optional recipe); "
                        "or use capture_start(headed=false) for a click loop"
                    ),
                }
            )
        else:
            calls.append(
                {
                    "tool": "hardly_discover",
                    "args": {"url": "<https://portal.example.com>"},
                }
            )
    else:  # interactive
        calls.append({"tool": "hardly_capture_doctor", "args": {}})
        calls.append(
            {
                "tool": "hardly_capture_start",
                "args": {
                    "url": target or "<https://portal.example.com>",
                    "headed": True,
                    "channel": "chrome",
                },
                "note": "then ASK THE PERSON — do not click for them unless asked",
            }
        )
        calls.append(
            {
                "tool": "hardly_capture_stop",
                "args": {"open_session": True},
                "note": "after the person finishes",
            }
        )
        calls.append(
            {
                "tool": "hardly_brief",
                "args": {"session_id": "<from stop>"},
            }
        )

    out: dict[str, Any] = {
        "mode": mode["id"],
        "title": mode["title"],
        "when": mode["when"],
        "needs_playwright": mode["needs_playwright"],
        "needs_user": mode["needs_user"],
        "steps": steps,
        "calls": calls,
        "entry_tools": list(mode["entry_tools"]),
        "tools": list(mode["tools"]),
        "prompt": mode["prompt"],
        "ask_user": mode["ask_user"],
        "next": (
            mode["ask_user"]
            if mode["needs_user"]
            else f"Follow steps; prompt name for MCP clients: {mode['prompt']}"
        ),
    }
    if goal:
        out["goal"] = goal
    if har:
        out["har_path"] = har
    if target:
        out["url"] = target
    return out
