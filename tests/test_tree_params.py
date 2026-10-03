"""Initiator trees, param variance, GraphQL, export brief."""

from pathlib import Path

from hardly import session as sess
from hardly.core.export_brief import export_brief_md
from hardly.core.graphql import detect_graphql
from hardly.core.params import param_variance
from hardly.core.tree import entry_tree

FIX = Path(__file__).parent / "fixtures" / "sample.har"


def test_tree_js_children(tmp_path, monkeypatch):
    monkeypatch.setenv("HARDLY_RUNTIME_DIR", str(tmp_path))
    info = sess.open_har(str(FIX), force=True)
    conn = sess.require_conn(info["session_id"])
    # the search-pages .js script is entry 8
    tree = entry_tree(conn, 8)
    assert tree["initiator_type"] == "parser"
    assert tree["parent"] and tree["parent"]["entry_id"] == 7
    paths = {c["path"] for c in tree["children"]}
    assert "/Search/GridResults" in paths
    assert any("documentdetails" in p for p in paths)


def test_params_dynamic_page(tmp_path, monkeypatch):
    monkeypatch.setenv("HARDLY_RUNTIME_DIR", str(tmp_path))
    info = sess.open_har(str(FIX), force=True)
    conn = sess.require_conn(info["session_id"])
    result = param_variance(
        conn,
        method="GET",
        host="api.example.com",
        path_template="/organizations/{id}/transactions",
    )
    assert result["sample_count"] >= 2
    names = {p["name"] for p in result["query"]["dynamic"]}
    assert "page" in names


def test_graphql_detect(tmp_path, monkeypatch):
    monkeypatch.setenv("HARDLY_RUNTIME_DIR", str(tmp_path))
    info = sess.open_har(str(FIX), force=True)
    conn = sess.require_conn(info["session_id"])
    result = detect_graphql(conn, host="api.example.com")
    assert result["operation_count"] >= 1
    assert "GetOrg" in result["by_name"]


def test_export_brief_md(tmp_path, monkeypatch):
    monkeypatch.setenv("HARDLY_RUNTIME_DIR", str(tmp_path))
    info = sess.open_har(str(FIX), force=True)
    conn = sess.require_conn(info["session_id"])
    out = tmp_path / "brief.md"
    result = export_brief_md(
        conn,
        out,
        har_path=sess.get_har_path(info["session_id"]),
        host="portal.example.com",
    )
    assert result.get("output_path")
    text = out.read_text(encoding="utf-8")
    assert "Portal brief" in text
    assert "Story" in text
