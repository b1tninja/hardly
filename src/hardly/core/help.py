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
            "hardly_guide_task_plan",
            "hardly_guide_mode",
            "hardly_server_status",
            "hardly_guide_help",
        ],
    },
    {
        "id": "session",
        "title": "Session",
        "when": "Open / reattach a HAR; check version after MCP restart",
        "tools": [
            "hardly_server_status",
            "hardly_session_open",
            "hardly_session_list",
            "hardly_session_close",
            "hardly_write_session_copy",
            "hardly_session_overview",
            "hardly_session_traffic_stats",
            "hardly_session_body_coverage",
        ],
    },
    {
        "id": "discover",
        "title": "Discovery",
        "when": "Map hosts, endpoints, search, pages",
        "tools": [
            "hardly_endpoint_list",
            "hardly_entry_search",
            "hardly_page_list",
            "hardly_session_timeline",
            "hardly_session_duplicates",
            "hardly_session_slow_requests",
        ],
    },
    {
        "id": "portal",
        "title": "HTML guest portals",
        "when": "Server-rendered HTML portals: ASP.NET WebForms, search grids, detail pages",
        "tools": [
            "hardly_session_report",
            "hardly_session_site_brief",
            "hardly_session_story",
            "hardly_page_forms",
            "hardly_page_ui",
            "hardly_entry_outline",
            "hardly_page_embedded_routes",
            "hardly_entry_around",
            "hardly_entry_initiators",
            "hardly_session_plan_steps",
            "hardly_client_build",
        ],
    },
    {
        "id": "tokens",
        "title": "Tokens & secrets",
        "when": "CSRF, ViewState, cookies, credentials",
        "tools": [
            "hardly_auth_report",
            "hardly_session_trace_value",
            "hardly_endpoint_schema",
        ],
    },
    {
        "id": "quality",
        "title": "Capture quality & walls",
        "when": "Empty bodies, 403/Akamai, redirects, errors",
        "tools": [
            "hardly_gate_bot_protection",
            "hardly_session_issues",
            "hardly_session_body_coverage",
            "hardly_session_redirect_history",
            "hardly_session_compare",
            "hardly_har_file_check",
        ],
    },
    {
        "id": "api",
        "title": "API detail",
        "when": "JSON APIs, GraphQL, schemas, technology",
        "tools": [
            "hardly_entry_get",
            "hardly_entry_body_query",
            "hardly_session_traffic_stats",
            "hardly_entry_compare",
            "hardly_entry_dependencies",
            "hardly_endpoint_schema",
            "hardly_endpoint_graphql",
            "hardly_endpoint_streams",
            "hardly_endpoint_pagination",
            "hardly_endpoint_arcgis",
            "hardly_tech_stack",
            "hardly_page_tables",
            "hardly_spec_contract_check",
            "hardly_session_sql",
            "hardly_entry_build_curl",
        ],
    },
    {
        "id": "live",
        "title": "Live requests (send_*, confirm-gated)",
        "when": "Send real requests only after the person agrees; without confirm=true they return a plan",
        "tools": [
            "hardly_send_entry",
            "hardly_send_entry_ablation",
            "hardly_send_entry_series",
            "hardly_send_site_crawl",
            "hardly_send_arcgis_explore",
            "hardly_send_redirect_walk",
            "hardly_send_catalog_verify",
        ],
    },
    {
        "id": "export",
        "title": "Write files (write_*)",
        "when": "Write docs / collections / HAR copies to disk; existing files need overwrite=true",
        "tools": [
            "hardly_write_export",
            "hardly_write_session_copy",
            "hardly_write_har_pruned",
            "hardly_write_har_scrubbed",
            "hardly_write_har_split",
            "hardly_write_har_merged",
            "hardly_write_screenshot",
            "hardly_write_catalog_record",
        ],
    },
    {
        "id": "capture",
        "title": "Browser capture",
        "when": "Headless discovery or interactive record (prefer channel=chrome)",
        "tools": [
            "hardly_browser_capture_discover",
            "hardly_browser_start",
            "hardly_browser_stop",
            "hardly_browser_interact",
            "hardly_browser_inspect",
            "hardly_browser_run_steps",
            "hardly_write_screenshot",
            "hardly_capture_list",
            "hardly_server_status",
            "hardly_session_plan_steps",
        ],
    },
    {
        "id": "catalog",
        "title": "Target catalog",
        "when": "A project-defined list of endpoints to track",
        "tools": [
            "hardly_catalog_list",
            "hardly_write_catalog_record",
            "hardly_send_catalog_verify",
        ],
    },
    {
        "id": "guide",
        "title": "Guidance",
        "when": "Not sure which tool to call",
        "tools": [
            "hardly_guide_task_plan",
            "hardly_guide_mode",
            "hardly_guide_help",
            "hardly_server_status",
        ],
    },
)

_WORKFLOWS: tuple[dict[str, str], ...] = (
    {
        "name": "archive",
        "steps": (
            "hardly_guide_mode(mode=archive, har_path=…) -> hardly_session_open -> "
            "hardly_session_site_brief / hardly_endpoint_list -> hardly_session_trace_value / "
            "hardly_endpoint_schema / hardly_write_export"
        ),
    },
    {
        "name": "headless",
        "steps": (
            "hardly_guide_mode(mode=headless, url=…) -> "
            "hardly_browser_capture_discover(url, analyze=true, confirm=true) "
            "(or hardly_browser_start headed=false + hardly_browser_inspect/hardly_browser_run_steps) "
            "-> hardly_session_site_brief"
        ),
    },
    {
        "name": "interactive",
        "steps": (
            "hardly_guide_mode(mode=interactive, url=…) -> "
            "hardly_browser_start(headed=true, channel=chrome) -> ASK PERSON -> "
            "hardly_browser_stop -> hardly_session_site_brief"
        ),
    },
    {
        "name": "guest_portal",
        "steps": (
            "hardly_session_open -> hardly_session_site_brief (includes credentials summary) -> "
            "hardly_auth_report / hardly_gate_bot_protection -> "
            "hardly_session_trace_value -> hardly_client_build or hardly_session_plan_steps"
        ),
    },
    {
        "name": "login_session",
        "steps": (
            "hardly_session_open -> hardly_auth_report(sections=['credentials']) -> "
            "hardly_session_trace_value / hardly_auth_report(sections=['cookies']) -> "
            "hardly_entry_compare pre/post login"
        ),
    },
    {
        "name": "json_api",
        "steps": (
            "hardly_session_open -> hardly_endpoint_list -> hardly_auth_report -> "
            "hardly_endpoint_schema -> hardly_write_export(format=openapi)"
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

    known = set(TOOLS)
    out: dict[str, Any] = {
        "version": __version__,
        "topic": topic,
        "categories": cats,
        "workflows": list(_WORKFLOWS),
        "tool_count": len(TOOLS),
        "next": (
            "Pass topic like 'modes', 'archive', 'headless', 'interactive', "
            "'portal', 'tokens', 'capture', or a tool name. "
            "Or hardly_guide_mode / hardly_guide_task_plan(goal=\"guest portal csrf\")."
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
