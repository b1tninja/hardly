"""Advertise version and feature flags so agents detect a stale MCP server."""

from __future__ import annotations

from typing import Any

from hardly import __version__

# Bump when tools/features change in a way agents must notice.
FEATURES = (
    "forms",
    "ui",
    "labels",
    "routes",
    "around",
    "brief",
    "story",
    "stub",
    "correlate",
    "trace",
    "cookies",
    "secrets",
    "diff",
    "recipe_plan",
    "redirects",
    "issues",
    "recommend",
    "tree",
    "params",
    "graphql",
    "content_classify",
    "outline",
    "capture_aria",
    "capture_aria_ref",
    "capture_screenshot",
    "capture_trace",
    "capture_doctor",
    "duplicates",
    "slow",
    "wall",
    "pages",
    "stats",
    "reopen",
    "webforms",
    "help",
    "openapi_security",
    "cli_parity",
    "preferred_host",
    "related_hosts",
    "export_postman",
    "export_brief",
    "coverage",
    "body_backfill",
    "truncated_token",
    "capture_elements",
    "capture_click",
    "capture_fill",
    "capture_press",
    "capture_url",
    "capture_recipe",
    "offline_xpath",
)

TOOLS = (
    "hardly_capabilities",
    "hardly_help",
    "hardly_open",
    "hardly_reopen",
    "hardly_list_sessions",
    "hardly_close",
    "hardly_summary",
    "hardly_stats",
    "hardly_coverage",
    "hardly_hosts",
    "hardly_endpoints",
    "hardly_search",
    "hardly_entry",
    "hardly_forms",
    "hardly_ui",
    "hardly_routes",
    "hardly_around",
    "hardly_brief",
    "hardly_story",
    "hardly_stub",
    "hardly_correlate",
    "hardly_trace",
    "hardly_cookies",
    "hardly_secrets",
    "hardly_diff",
    "hardly_recipe_plan",
    "hardly_redirects",
    "hardly_issues",
    "hardly_recommend",
    "hardly_tree",
    "hardly_params",
    "hardly_graphql",
    "hardly_content",
    "hardly_outline",
    "hardly_duplicates",
    "hardly_slow",
    "hardly_wall",
    "hardly_pages",
    "hardly_compare_entries",
    "hardly_auth",
    "hardly_flow",
    "hardly_schema",
    "hardly_sql",
    "hardly_export_md",
    "hardly_export_openapi",
    "hardly_export_postman",
    "hardly_export_brief",
    "hardly_curl",
    "hardly_probe",
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
    "hardly_capture_recipe",
    "hardly_capture_list",
    "hardly_capture_status",
    "hardly_capture_once",
    "hardly_capture_doctor",
)


def capabilities() -> dict[str, Any]:
    capture_ok = False
    playwright: dict[str, Any] = {"package": False, "ready": False}
    try:
        from hardly.capture import playwright_status

        playwright = playwright_status()
        capture_ok = bool(playwright.get("ready"))
    except Exception as exc:  # noqa: BLE001
        playwright = {"package": False, "ready": False, "error": str(exc)}
    return {
        "name": "hardly",
        "version": __version__,
        "features": list(FEATURES),
        "tools": list(TOOLS),
        "tool_count": len(TOOLS),
        "capture_available": capture_ok,
        "playwright": playwright,
        "next": (
            "If this tool list is missing expected names (e.g. hardly_brief, "
            "hardly_trace, hardly_export_postman), restart the hardly MCP "
            "server / Cursor MCP entry so it loads the current package. "
            "If capture_available is false, see playwright.hint / "
            "hardly_capture_doctor."
        ),
    }
