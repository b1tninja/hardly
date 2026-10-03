"""Capabilities / version ping."""

import re

from hardly import server
from hardly.capabilities import FEATURES, TOOLS, capabilities


def test_capabilities_lists_current_tools():
    caps = capabilities()
    assert caps["version"]
    for name in (
        "hardly_server_status",
        "hardly_guide_help",
        "hardly_guide_mode",
        "hardly_guide_task_plan",
        "hardly_session_open",
        "hardly_session_close",
        "hardly_session_list",
        "hardly_write_session_copy",
        "hardly_write_export",
        "hardly_session_overview",
        "hardly_session_traffic_stats",
        "hardly_session_site_brief",
        "hardly_session_trace_value",
        "hardly_session_issues",
        "hardly_session_duplicates",
        "hardly_session_slow_requests",
        "hardly_session_redirect_history",
        "hardly_session_compare",
        "hardly_session_plan_steps",
        "hardly_browser_capture_discover",
        "hardly_browser_run_steps",
        "hardly_entry_initiators",
        "hardly_endpoint_schema",
        "hardly_endpoint_graphql",
        "hardly_page_forms",
        "hardly_page_ui",
        "hardly_page_list",
        "hardly_auth_report",
        "hardly_gate_bot_protection",
    ):
        assert name in caps["tools"], name
    assert "hardly_page_forms_ui" not in caps["tools"]
    assert "modes" in caps and len(caps["modes"]) == 3
    for feat in ("guide_mode", "credentials", "labels", "webforms", "guide_help", "openapi_security", "sections", "api_surface_v1"):
        assert feat in caps["features"], feat
    assert "playwright" in caps and "ready" in caps["playwright"]
    assert len(caps["tools"]) == len(TOOLS)
    assert set(FEATURES).issubset(set(caps["features"]))


def test_capabilities_match_registered_tools():
    live = {n for n, f in vars(server).items() if n.startswith("hardly_") and callable(f)}
    assert live == set(TOOLS)
    assert all(re.fullmatch(r"hardly_[a-z]+(_[a-z]+){0,2}", n) for n in TOOLS)
