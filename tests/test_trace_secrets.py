"""Trace, secrets locate, recommend, Postman export."""

from pathlib import Path

from hardly import session as sess
from hardly.core.export_postman import export_postman
from hardly.core.recommend import recommend_tools
from hardly.core.secrets import locate_secrets
from hardly.core.trace import trace_field

FIX = Path(__file__).parent / "fixtures" / "sample.har"


def test_trace_viewstate(tmp_path, monkeypatch):
    monkeypatch.setenv("HARDLY_RUNTIME_DIR", str(tmp_path))
    info = sess.open_har(str(FIX), force=True)
    conn = sess.require_conn(info["session_id"])
    result = trace_field(
        conn,
        name="__VIEWSTATE",
        har_path=sess.get_har_path(info["session_id"]),
        host="portal.example.com",
    )
    assert result["hit_count"] >= 1
    sides = {h["side"] for h in result["hits"]}
    assert "response" in sides or "request" in sides
    assert "longtoken" not in str(result)


def test_trace_session_cookie_value(tmp_path, monkeypatch):
    monkeypatch.setenv("HARDLY_RUNTIME_DIR", str(tmp_path))
    info = sess.open_har(str(FIX), force=True)
    conn = sess.require_conn(info["session_id"])
    result = trace_field(
        conn,
        value="abc123sessionvalue99",
        har_path=sess.get_har_path(info["session_id"]),
        host="portal.example.com",
    )
    assert result["hit_count"] >= 2
    assert "abc123sessionvalue99" not in str(result)


def test_locate_secrets(tmp_path, monkeypatch):
    monkeypatch.setenv("HARDLY_RUNTIME_DIR", str(tmp_path))
    info = sess.open_har(str(FIX), force=True)
    conn = sess.require_conn(info["session_id"])
    result = locate_secrets(conn)
    assert result["hit_count"] >= 1
    names_l = {n.lower() for n in result["names"]}
    assert "password" in names_l or "cookie" in names_l or "authorization" in names_l


def test_recommend_portal():
    result = recommend_tools("guest portal csrf tokens")
    tools = {t for s in result["suggestions"] for t in s["tools"]}
    assert "hardly_correlate" in tools or "hardly_brief" in tools


def test_export_postman(tmp_path, monkeypatch):
    monkeypatch.setenv("HARDLY_RUNTIME_DIR", str(tmp_path))
    info = sess.open_har(str(FIX), force=True)
    conn = sess.require_conn(info["session_id"])
    out = tmp_path / "collection.json"
    result = export_postman(conn, out, host="portal.example.com")
    assert result["item_count"] >= 1
    assert out.is_file()
    text = out.read_text(encoding="utf-8")
    assert "item" in text
    assert "schema.getpostman.com" in text
