"""Capabilities / version ping."""

from hardly.capabilities import FEATURES, TOOLS, capabilities


def test_capabilities_lists_current_tools():
    caps = capabilities()
    assert caps["version"]
    assert "hardly_capabilities" in caps["tools"]
    assert "hardly_ui" in caps["tools"]
    assert "hardly_capture_recipe" in caps["tools"]
    assert "hardly_help" in caps["tools"]
    assert "hardly_reopen" in caps["tools"]
    assert "hardly_stats" in caps["tools"]
    assert "hardly_brief" in caps["tools"]
    assert "hardly_list_sessions" in caps["tools"]
    assert "hardly_close" in caps["tools"]
    assert "hardly_correlate" in caps["tools"]
    assert "hardly_trace" in caps["tools"]
    assert "hardly_secrets" in caps["tools"]
    assert "hardly_recommend" in caps["tools"]
    assert "hardly_modes" in caps["tools"]
    assert "hardly_mode" in caps["tools"]
    assert "hardly_discover" in caps["tools"]
    assert "hardly_credentials" in caps["tools"]
    assert "credentials" in caps["features"]
    assert "modes" in caps
    assert len(caps["modes"]) == 3
    assert "hardly_export_postman" in caps["tools"]
    assert "modes" in caps["features"]
    assert "discover" in caps["features"]
    assert "hardly_export_brief" in caps["tools"]
    assert "hardly_tree" in caps["tools"]
    assert "hardly_params" in caps["tools"]
    assert "hardly_graphql" in caps["tools"]
    assert "hardly_duplicates" in caps["tools"]
    assert "hardly_slow" in caps["tools"]
    assert "hardly_wall" in caps["tools"]
    assert "hardly_pages" in caps["tools"]
    assert "hardly_diff" in caps["tools"]
    assert "hardly_recipe_plan" in caps["tools"]
    assert "hardly_issues" in caps["tools"]
    assert "hardly_redirects" in caps["tools"]
    assert "labels" in caps["features"]
    assert "brief" in caps["features"]
    assert "correlate" in caps["features"]
    assert "trace" in caps["features"]
    assert "tree" in caps["features"]
    assert "graphql" in caps["features"]
    assert "wall" in caps["features"]
    assert "pages" in caps["features"]
    assert "reopen" in caps["features"]
    assert "webforms" in caps["features"]
    assert "help" in caps["features"]
    assert "openapi_security" in caps["features"]
    assert "issues" in caps["features"]
    assert "capture_recipe" in caps["features"]
    assert "hardly_capture_doctor" in caps["tools"]
    assert "playwright" in caps
    assert "ready" in caps["playwright"]
    assert len(caps["tools"]) == len(TOOLS)
    assert set(FEATURES).issubset(set(caps["features"]))
