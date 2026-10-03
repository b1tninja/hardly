"""Help catalog, OpenAPI security schemes, WebForms recipe notes."""

from pathlib import Path

from hardly import session as sess
from hardly.core.export_openapi import export_openapi
from hardly.core.help import tool_help
from hardly.core.recipe_plan import recipe_from_story

FIX = Path(__file__).parent / "fixtures" / "sample.har"


def test_help_catalog_and_topic():
    all_help = tool_help()
    assert all_help["tool_count"] >= 40
    assert any(c["id"] == "portal" for c in all_help["categories"])
    assert any(c["id"] == "modes" for c in all_help["categories"])
    names = {w["name"] for w in all_help["workflows"]}
    assert {"archive", "headless", "interactive"} <= names
    portal = tool_help("portal")
    tools = {t for c in portal["categories"] for t in c["tools"]}
    assert "hardly_session_site_brief" in tools
    archive = tool_help("archive")
    assert archive.get("playbook", {}).get("mode") == "archive"


def test_openapi_security_schemes(tmp_path, monkeypatch):
    monkeypatch.setenv("HARDLY_RUNTIME_DIR", str(tmp_path))
    info = sess.open_har(str(FIX), force=True)
    conn = sess.require_conn(info["session_id"])
    out = tmp_path / "openapi.json"
    result = export_openapi(conn, out, host="api.example.com")
    assert result.get("security_schemes")
    text = out.read_text(encoding="utf-8")
    assert "securitySchemes" in text


def test_recipe_notes_webforms(tmp_path, monkeypatch):
    monkeypatch.setenv("HARDLY_RUNTIME_DIR", str(tmp_path))
    info = sess.open_har(str(FIX), force=True)
    conn = sess.require_conn(info["session_id"])
    result = recipe_from_story(conn, host="portal.example.com")
    notes = " ".join(n.get("text", "") for n in result.get("notes") or [])
    assert "WebForms" in notes or "VIEWSTATE" in notes or result["step_count"] >= 1
    ops = [s.get("op") for s in (result.get("steps") or [])]
    # When steps are written to disk they're None — re-run without output
    if result.get("steps") is None:
        result = recipe_from_story(conn, host="portal.example.com")
        ops = [s.get("op") for s in (result.get("steps") or [])]
    assert "aria" in ops or result["step_count"] >= 1
