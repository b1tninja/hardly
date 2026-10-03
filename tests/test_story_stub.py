"""Portal story stitching and urllib stub generation."""

from pathlib import Path

from hardly import session as sess
from hardly.core.story import portal_story
from hardly.core.stub import client_stub

FIX = Path(__file__).parent / "fixtures" / "sample.har"


def test_portal_story_annotates_sample(tmp_path, monkeypatch):
    monkeypatch.setenv("HARDLY_RUNTIME_DIR", str(tmp_path))
    info = sess.open_har(str(FIX), force=True)
    conn = sess.require_conn(info["session_id"])
    story = portal_story(conn, host="portal.example.com", limit=20)
    assert story["host"] == "portal.example.com"
    assert story["step_count"] >= 1
    paths = [s["path"] for s in story["steps"]]
    assert any("search" in p.lower() or "GridResults" in p for p in paths)
    # HTML search page should carry form / handler hints when present
    html_steps = [s for s in story["steps"] if s.get("forms") or s.get("handler_functions")]
    assert html_steps
    assert isinstance(story.get("correlations"), list)
    assert "api.example.com" in (story.get("related_hosts") or [])
    hosts_seen = {s.get("host") for s in story["steps"]}
    assert "portal.example.com" in hosts_seen
    assert "api.example.com" in hosts_seen


def test_portal_story_no_related(tmp_path, monkeypatch):
    monkeypatch.setenv("HARDLY_RUNTIME_DIR", str(tmp_path))
    info = sess.open_har(str(FIX), force=True)
    conn = sess.require_conn(info["session_id"])
    story = portal_story(
        conn, host="portal.example.com", limit=20, include_related=False
    )
    assert not story.get("related_hosts")
    assert all(s.get("host") == "portal.example.com" for s in story["steps"])


def test_client_stub_writes_file(tmp_path, monkeypatch):
    monkeypatch.setenv("HARDLY_RUNTIME_DIR", str(tmp_path))
    info = sess.open_har(str(FIX), force=True)
    conn = sess.require_conn(info["session_id"])
    out = tmp_path / "portal_client.py"
    result = client_stub(
        conn,
        host="portal.example.com",
        output_path=out,
        class_name="ExamplePortal",
    )
    assert result.get("output_path")
    assert out.is_file()
    text = out.read_text(encoding="utf-8")
    assert "class ExamplePortal" in text
    assert "CookieJar" in text
    compile(text, str(out), "exec")  # generated sketch must be valid Python
    assert "PLACEHOLDER" in text
    # ASP.NET / CSRF fields must not be hard-coded from the recording
    assert "longtoken" not in text
    assert "csrf-token-xyz-7788" not in text


def test_client_stub_compiles_with_json_steps(tmp_path, monkeypatch):
    monkeypatch.setenv("HARDLY_RUNTIME_DIR", str(tmp_path))
    info = sess.open_har(str(FIX), force=True)
    conn = sess.require_conn(info["session_id"])
    result = client_stub(conn, host=None, output_path=tmp_path / "all.py")
    text = (tmp_path / "all.py").read_text(encoding="utf-8")
    assert "import json" in text
    compile(text, "all.py", "exec")
    assert result["entry_ids"]
