"""Duplicates, slow, wall, pages."""

from pathlib import Path

from hardly import session as sess
from hardly.core.duplicates import find_duplicates
from hardly.core.pages import list_pages
from hardly.core.slow import slowest_entries
from hardly.core.wall import detect_walls

FIX = Path(__file__).parent / "fixtures" / "sample.har"


def test_duplicates_login(tmp_path, monkeypatch):
    monkeypatch.setenv("HARDLY_RUNTIME_DIR", str(tmp_path))
    info = sess.open_har(str(FIX), force=True)
    conn = sess.require_conn(info["session_id"])
    result = find_duplicates(conn, host="api.example.com", min_count=2)
    templates = {g["path_template"] for g in result["groups"]}
    assert "/login" in templates


def test_slowest(tmp_path, monkeypatch):
    monkeypatch.setenv("HARDLY_RUNTIME_DIR", str(tmp_path))
    info = sess.open_har(str(FIX), force=True)
    conn = sess.require_conn(info["session_id"])
    result = slowest_entries(conn, limit=5)
    assert result["count"] >= 1
    assert result["entries"][0]["time_ms"] >= result["entries"][-1]["time_ms"]


def test_wall_akamai(tmp_path, monkeypatch):
    monkeypatch.setenv("HARDLY_RUNTIME_DIR", str(tmp_path))
    info = sess.open_har(str(FIX), force=True)
    conn = sess.require_conn(info["session_id"])
    result = detect_walls(conn, host="portal.example.com")
    assert result["hit_count"] >= 1
    kinds = {k for h in result["hits"] for k in h["kinds"]}
    assert "akamai" in kinds or "http_block" in kinds or "access_denied" in kinds


def test_pages_portal(tmp_path, monkeypatch):
    monkeypatch.setenv("HARDLY_RUNTIME_DIR", str(tmp_path))
    info = sess.open_har(str(FIX), force=True)
    conn = sess.require_conn(info["session_id"])
    result = list_pages(conn)
    prefs = {p["pageref"] for p in result["pages"]}
    assert "page_portal" in prefs
