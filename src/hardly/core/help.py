"""Categorized tool catalog so agents can navigate 50+ tools."""

from __future__ import annotations

from typing import Any

from hardly import __version__
from hardly.capabilities import TOOLS

_CATEGORIES: tuple[dict[str, Any], ...] = (
    {
        "id": "session",
        "title": "Session",
        "when": "Open / reattach a HAR; check version after MCP restart",
        "tools": [
            "hardly_capabilities",
            "hardly_open",
            "hardly_reopen",
            "hardly_list_sessions",
            "hardly_close",
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
        "when": "County / ASP.NET / search-grid UIs",
        "tools": [
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
        "when": "Record with Playwright (prefer channel=chrome)",
        "tools": [
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
        "tools": ["hardly_help", "hardly_recommend", "hardly_capabilities"],
    },
)

_WORKFLOWS: tuple[dict[str, str], ...] = (
    {
        "name": "guest_portal",
        "steps": (
            "hardly_open -> hardly_brief -> hardly_wall -> "
            "hardly_correlate / hardly_trace -> hardly_stub or hardly_recipe_plan"
        ),
    },
    {
        "name": "json_api",
        "steps": (
            "hardly_open -> hardly_endpoints -> hardly_auth -> "
            "hardly_schema -> hardly_export_openapi"
        ),
    },
    {
        "name": "record_then_analyze",
        "steps": (
            "hardly_capture_start(channel=chrome) -> elements/click/fill "
            "or recipe -> stop -> brief"
        ),
    },
)


def tool_help(topic: str | None = None) -> dict[str, Any]:
    """Return categorized tools, optionally filtered by topic/category/name."""
    text = (topic or "").strip().lower()
    cats = list(_CATEGORIES)
    if text:
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
    return {
        "version": __version__,
        "topic": topic,
        "categories": cats,
        "workflows": list(_WORKFLOWS),
        "tool_count": len(TOOLS),
        "next": (
            "Pass topic like 'portal', 'tokens', 'capture', or a tool name. "
            "Or hardly_recommend(\"guest portal csrf\")."
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
