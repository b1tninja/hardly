"""Categorized tool catalog so agents can navigate 50+ tools."""

from __future__ import annotations

from typing import Any

from hardly import __version__
from hardly.capabilities import TOOLS

_CATEGORIES: tuple[dict[str, Any], ...] = (
    {
        "id": "modes",
        "title": "Operating modes",
        "when": "Choose archive / headless / interactive before other tools",
        "tools": [
            "hardly_start",
            "hardly_modes",
            "hardly_mode",
            "hardly_capabilities",
            "hardly_help",
            "hardly_recommend",
        ],
    },
    {
        "id": "session",
        "title": "Session",
        "when": "Open / reattach a HAR; check version after MCP restart",
        "tools": [
            "hardly_capabilities",
            "hardly_open",
            "hardly_list_sessions",
            "hardly_close",
            "hardly_export_har",
            "hardly_summary",
            "hardly_stats",
            "hardly_coverage",
        ],
    },
    {
        "id": "discover",
        "title": "Discovery",
        "when": "Map hosts, endpoints, search, pages",
        "tools": [
            "hardly_hosts",
            "hardly_endpoints",
            "hardly_search",
            "hardly_pages",
            "hardly_flow",
            "hardly_duplicates",
            "hardly_slow",
        ],
    },
    {
        "id": "portal",
        "title": "HTML guest portals",
        "when": "Server-rendered HTML portals: ASP.NET WebForms, search grids, detail pages",
        "tools": [
            "hardly_report",
            "hardly_brief",
            "hardly_story",
            "hardly_forms",
            "hardly_ui",
            "hardly_outline",
            "hardly_routes",
            "hardly_around",
            "hardly_tree",
            "hardly_recipe_plan",
            "hardly_stub",
        ],
    },
    {
        "id": "tokens",
        "title": "Tokens & secrets",
        "when": "CSRF, ViewState, cookies, credentials",
        "tools": [
            "hardly_credentials",
            "hardly_correlate",
            "hardly_trace",
            "hardly_cookies",
            "hardly_secrets",
            "hardly_auth",
            "hardly_params",
        ],
    },
    {
        "id": "quality",
        "title": "Capture quality & walls",
        "when": "Empty bodies, 403/Akamai, redirects, errors",
        "tools": [
            "hardly_wall",
            "hardly_issues",
            "hardly_coverage",
            "hardly_redirects",
            "hardly_diff",
        ],
    },
    {
        "id": "api",
        "title": "API detail",
        "when": "JSON APIs, GraphQL, schemas",
        "tools": [
            "hardly_entry",
            "hardly_content",
            "hardly_compare_entries",
            "hardly_schema",
            "hardly_graphql",
            "hardly_sql",
            "hardly_curl",
            "hardly_probe",
        ],
    },
    {
        "id": "export",
        "title": "Export",
        "when": "Write docs / collections to disk",
        "tools": [
            "hardly_export_md",
            "hardly_export_openapi",
            "hardly_export_postman",
            "hardly_export_brief",
            "hardly_stub",
        ],
    },
    {
        "id": "capture",
        "title": "Live capture",
        "when": "Headless discover or interactive record (prefer channel=chrome)",
        "tools": [
            "hardly_discover",
            "hardly_capture_start",
            "hardly_capture_stop",
            "hardly_capture_goto",
            "hardly_capture_elements",
            "hardly_capture_click",
            "hardly_capture_fill",
            "hardly_capture_press",
            "hardly_capture_url",
            "hardly_capture_aria",
            "hardly_capture_screenshot",
            "hardly_capture_doctor",
            "hardly_capture_recipe",
            "hardly_capture_list",
            "hardly_capture_status",
            "hardly_capture_once",
            "hardly_recipe_plan",
        ],
    },
    {
        "id": "guide",
        "title": "Guidance",
        "when": "Not sure which tool to call",
        "tools": [
            "hardly_modes",
            "hardly_mode",
            "hardly_help",
            "hardly_recommend",
            "hardly_capabilities",
        ],
    },
)

_WORKFLOWS: tuple[dict[str, str], ...] = (
    {
        "name": "archive",
        "steps": (
            "hardly_mode(mode=archive, har_path=…) -> hardly_open -> "
            "hardly_brief / endpoints -> correlate / schema / export"
        ),
    },
    {
        "name": "headless",
        "steps": (
            "hardly_mode(mode=headless, url=…) -> hardly_discover(url) "
            "(or capture_start headed=false + aria/recipe) -> brief"
        ),
    },
    {
        "name": "interactive",
        "steps": (
            "hardly_mode(mode=interactive, url=…) -> "
            "capture_start(headed=true, channel=chrome) -> ASK PERSON -> "
            "capture_stop -> brief"
        ),
    },
    {
        "name": "guest_portal",
        "steps": (
            "hardly_open -> hardly_brief (includes credentials summary) -> "
            "hardly_credentials / hardly_wall -> "
            "hardly_correlate / hardly_trace -> hardly_stub or hardly_recipe_plan"
        ),
    },
    {
        "name": "login_session",
        "steps": (
            "hardly_open -> hardly_credentials -> "
            "hardly_trace / hardly_cookies -> hardly_compare_entries pre/post login"
        ),
    },
    {
        "name": "json_api",
        "steps": (
            "hardly_open -> hardly_endpoints -> hardly_auth -> "
            "hardly_schema -> hardly_export_openapi"
        ),
    },
)


def tool_help(topic: str | None = None) -> dict[str, Any]:
    """Return categorized tools, optionally filtered by topic/category/name."""
    text = (topic or "").strip().lower()
    cats = list(_CATEGORIES)
    playbook: dict[str, Any] | None = None
    if text in {"archive", "headless", "interactive", "file", "har", "offline"}:
        from hardly.core.modes import mode_playbook

        playbook = mode_playbook(text)
        # Prefer the modes + capture/session categories for mode topics.
        want = {"modes", "session", "capture", "portal", "guide"}
        cats = [c for c in cats if c["id"] in want] or cats
    elif text:
        filtered = []
        for cat in cats:
            if text in cat["id"] or text in cat["title"].lower() or text in cat["when"].lower():
                filtered.append(cat)
                continue
            tools = [t for t in cat["tools"] if text in t.lower()]
            if tools:
                filtered.append({**cat, "tools": tools})
        cats = filtered or cats

    known = set(TOOLS) | {"hardly_help", "hardly_list_sessions", "hardly_close"}
    out: dict[str, Any] = {
        "version": __version__,
        "topic": topic,
        "categories": cats,
        "workflows": list(_WORKFLOWS),
        "tool_count": len(TOOLS),
        "next": (
            "Pass topic like 'modes', 'archive', 'headless', 'interactive', "
            "'portal', 'tokens', 'capture', or a tool name. "
            "Or hardly_modes / hardly_recommend(\"guest portal csrf\")."
        ),
        "note": (
            None
            if all(
                t in known
                for cat in _CATEGORIES
                for t in cat["tools"]
            )
            else "catalog may list aliases"
        ),
    }
    if playbook:
        out["playbook"] = playbook
    return out
