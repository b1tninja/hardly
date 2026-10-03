"""Advertise version and feature flags so agents detect a stale MCP server."""

from __future__ import annotations

from typing import Any

from hardly import __version__

# Bump when tools/features change in a way agents must notice.
FEATURES = (
    "page_forms",
    "page_ui",
    "labels",
    "embedded_routes",
    "entry_around",
    "site_brief",
    "session_story",
    "session_timeline",
    "client_build",
    "trace_value",
    "cookies",
    "secrets",
    "credentials",
    "cookie_flags",
    "identity_fields",
    "oauth_signals",
    "value_shapes_index",
    "credentials_diff",
    "recipe_login_seed",
    "html_autocomplete",
    "oauth_flow",
    "entry_shapes",
    "session_compare",
    "plan_steps",
    "search_links",
    "grids",
    "recipe_policy",
    "gate_detect",
    "session_report",
    "page_tables",
    "tech_stack",
    "streams",
    "entry_body_query",
    "spec_contract_check",
    "entry_dependencies",
    "send_entry_series",
    "har_file_check",
    "har_tools",
    "pagination",
    "auth_patterns",
    "send_entry_ablation",
    "crawl_robots",
    "send_site_crawl",
    "send_redirect_walk",
    "dismiss_consent",
    "live_find_click",
    "send_arcgis_explore",
    "endpoint_arcgis",
    "data_attrs",
    "http_challenges",
    "redirect_history",
    "session_issues",
    "guide_task_plan",
    "guide_mode",
    "browser_capture_discover",
    "entry_initiators",
    "param_roles",
    "graphql",
    "content_classify",
    "entry_outline",
    "browser_inspect_aria",
    "aria_ref",
    "write_screenshot",
    "capture_trace",
    "server_status",
    "duplicates",
    "slow_requests",
    "bot_protection",
    "page_list",
    "traffic_stats",
    "webforms",
    "guide_help",
    "openapi_security",
    "cli_parity",
    "preferred_host",
    "preferred_host_cdn_skip",
    "related_hosts",
    "write_export",
    "body_coverage",
    "body_backfill",
    "truncated_token",
    "browser_interact",
    "offline_xpath",
    "catalog",
    "prompts",
    "resources",
    "skill",
    "sections",
    "confirm_gate",
    "write_overwrite_guard",
    "api_surface_v1",
)

# Grouped by family; the first token after ``hardly_`` is the effect marker where there is one:
# ``send_`` sends network requests (confirm-gated), ``write_`` writes a file (refuses to overwrite
# unless overwrite=true), ``browser_`` drives or reads a real browser.
TOOLS = (
    # guide and server
    "hardly_server_status",
    "hardly_guide_help",
    "hardly_guide_mode",
    "hardly_guide_task_plan",
    # sessions, HAR files, catalog
    "hardly_session_open",
    "hardly_session_close",
    "hardly_session_list",
    "hardly_write_session_copy",
    "hardly_har_file_check",
    "hardly_write_har_pruned",
    "hardly_write_har_scrubbed",
    "hardly_write_har_split",
    "hardly_write_har_merged",
    "hardly_catalog_list",
    "hardly_write_catalog_record",
    "hardly_send_catalog_verify",
    # browser
    "hardly_browser_start",
    "hardly_browser_stop",
    "hardly_capture_list",
    "hardly_browser_capture_discover",
    "hardly_browser_interact",
    "hardly_browser_inspect",
    "hardly_browser_run_steps",
    "hardly_write_screenshot",
    "hardly_session_plan_steps",
    # capture orientation
    "hardly_session_overview",
    "hardly_session_traffic_stats",
    "hardly_session_body_coverage",
    "hardly_session_issues",
    "hardly_session_duplicates",
    "hardly_session_slow_requests",
    "hardly_session_report",
    "hardly_session_site_brief",
    "hardly_session_story",
    "hardly_session_timeline",
    "hardly_session_redirect_history",
    # capture lookup
    "hardly_session_trace_value",
    "hardly_session_sql",
    "hardly_session_compare",
    "hardly_entry_search",
    "hardly_entry_get",
    "hardly_entry_around",
    "hardly_entry_initiators",
    "hardly_entry_compare",
    "hardly_entry_build_curl",
    "hardly_entry_body_query",
    "hardly_entry_outline",
    "hardly_entry_dependencies",
    # API shape, technology, pages, auth, gates
    "hardly_endpoint_list",
    "hardly_endpoint_schema",
    "hardly_spec_contract_check",
    "hardly_tech_stack",
    "hardly_endpoint_graphql",
    "hardly_endpoint_streams",
    "hardly_endpoint_pagination",
    "hardly_endpoint_arcgis",
    "hardly_page_list",
    "hardly_page_forms",
    "hardly_page_ui",
    "hardly_page_embedded_routes",
    "hardly_page_tables",
    "hardly_auth_report",
    "hardly_gate_bot_protection",
    # live (network) and generators
    "hardly_send_entry",
    "hardly_send_entry_ablation",
    "hardly_send_entry_series",
    "hardly_send_site_crawl",
    "hardly_send_arcgis_explore",
    "hardly_send_redirect_walk",
    "hardly_write_export",
    "hardly_client_build",
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
    from hardly.core.modes import list_modes

    return {
        "name": "hardly",
        "version": __version__,
        "features": list(FEATURES),
        "tools": list(TOOLS),
        "tool_count": len(TOOLS),
        "modes": list_modes()["modes"],
        "capture_available": capture_ok,
        "browser_available": capture_ok,
        "playwright": playwright,
        "next": (
            "Pick a mode with hardly_guide_mode. "
            "If this tool list is missing expected names (e.g. hardly_guide_mode, "
            "hardly_browser_capture_discover), restart the hardly MCP server. "
            "If capture_available is false, see playwright.hint / "
            "hardly_server_status(sections=['browser_setup'])."
        ),
    }
