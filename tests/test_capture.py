"""Browser HAR capture — unit tests; optional live Playwright smoke."""

import json

import pytest

from hardly.capture import (
    CaptureError,
    _persist_payload,
    active_dir,
    default_har_path,
    get_capture,
    latest_running_id,
    list_captures,
    playwright_available,
    start_capture,
    stop_capture,
)


def test_default_har_path_under_cache(tmp_path, monkeypatch):
    monkeypatch.setenv("HARDLY_CACHE_DIR", str(tmp_path))
    path = default_har_path("arcc-acclaim.sdcounty.ca.gov")
    assert path.parent == tmp_path / "captures"
    assert "arcc-acclaim" in path.name
    assert path.suffix == ".har"


def test_start_without_playwright_raises(monkeypatch):
    monkeypatch.setattr(
        "hardly.capture.playwright_status",
        lambda: {
            "package": False,
            "ready": False,
            "hint": "Playwright package missing. Run: pip install -e \".[capture]\"",
        },
    )
    with pytest.raises(CaptureError, match="Playwright"):
        start_capture("https://example.com")


def test_playwright_status_shape():
    from hardly.capture import playwright_status

    status = playwright_status()
    assert "package" in status
    assert "ready" in status
    assert "install" in status
    assert "features" in status
    assert "record_har" in status["features"]


def test_stop_latest_and_list(tmp_path, monkeypatch):
    monkeypatch.setenv("HARDLY_CACHE_DIR", str(tmp_path))
    har = tmp_path / "fake.har"
    har.write_text(
        '{"log":{"version":"1.2","creator":{"name":"t","version":"0"},"entries":[]}}',
        encoding="utf-8",
    )
    _persist_payload(
        "abc123",
        {
            "capture_id": "abc123",
            "har_path": str(har),
            "url": "https://example.com",
            "headed": True,
            "status": "running",
            "pid": 0,  # not alive → orphan finalize
            "started_at": 1.0,
            "stopped_at": None,
            "error": None,
            "entry_count_hint": None,
        },
    )

    assert latest_running_id() == "abc123"
    result = stop_capture(None, open_session=False)
    assert result["capture_id"] == "abc123"
    assert result["status"] == "stopped"
    assert result["har_exists"] is True
    assert "next" in result
    assert any(c["capture_id"] == "abc123" for c in list_captures())
    # Sidecar rewritten under the temp cache.
    sidecar = active_dir() / "abc123.json"
    assert sidecar.is_file()
    assert json.loads(sidecar.read_text(encoding="utf-8"))["status"] == "stopped"


def test_unknown_capture_id():
    with pytest.raises(CaptureError, match="unknown"):
        get_capture("does-not-exist")


def test_capture_rpc_requires_running(tmp_path, monkeypatch):
    monkeypatch.setenv("HARDLY_CACHE_DIR", str(tmp_path))
    from hardly.capture import capture_rpc

    with pytest.raises(CaptureError, match="no running capture"):
        capture_rpc(None, "elements")


@pytest.mark.skipif(not playwright_available(), reason="playwright not installed")
@pytest.mark.skipif(
    not __import__("os").environ.get("HARDLY_LIVE_CAPTURE"),
    reason="set HARDLY_LIVE_CAPTURE=1 to run live Playwright tests",
)
def test_headless_capture_elements(tmp_path, monkeypatch):
    monkeypatch.setenv("HARDLY_CACHE_DIR", str(tmp_path))
    har = tmp_path / "example-els.har"
    from hardly.capture import active_dir, list_capture_elements, start_capture

    info = start_capture("https://example.com", har, headed=False)
    try:
        els = list_capture_elements(info["capture_id"], limit=20)
        assert els.get("url", "").startswith("https://example.com")
        assert els.get("count", 0) >= 1
        first = (els.get("elements") or [{}])[0]
        assert first.get("xpath")
        assert first.get("css")
    finally:
        # Signal stop without waiting on HAR flush (can hang under pytest).
        (active_dir() / f"{info['capture_id']}.stop").write_text("stop\n", encoding="utf-8")


@pytest.mark.skipif(not playwright_available(), reason="playwright not installed")
@pytest.mark.skipif(
    not __import__("os").environ.get("HARDLY_LIVE_CAPTURE"),
    reason="set HARDLY_LIVE_CAPTURE=1 to run live Playwright tests",
)
def test_headless_capture_example(tmp_path):
    har = tmp_path / "example.har"
    from hardly.capture import capture_for

    result = capture_for(
        "https://example.com",
        har,
        wait_seconds=2,
        headed=False,
        open_session=False,
    )
    assert result["status"] == "stopped"
    assert har.is_file()
    assert har.stat().st_size > 100
    assert (result.get("entry_count_hint") or 0) >= 1
