"""Live headless soak against public tech demos (opt-in).

Default CI stays offline. Enable with::

    set HARDLY_LIVE_CAPTURE=1
    pytest tests/test_live_soak.py -q

Or run the full catalog::

    python -m hardly.soak_live
"""

from __future__ import annotations

import os

import pytest

from hardly.capture import playwright_available, playwright_status
from hardly.live_targets import TARGETS, catalog_summary, list_targets, target_by_id


def test_live_target_catalog_shape():
    assert len(TARGETS) >= 5
    ids = {t.id for t in TARGETS}
    assert "wyobiz" in ids
    assert "example" in ids
    rows = catalog_summary()
    assert all("url" in r and "tech" in r for r in rows)
    assert target_by_id("wyobiz") is not None
    assert list_targets(ids=["example"])[0].id == "example"


def test_live_target_ids_unique():
    ids = [t.id for t in TARGETS]
    assert len(ids) == len(set(ids))


@pytest.mark.skipif(not playwright_available(), reason="playwright not installed")
@pytest.mark.skipif(
    not os.environ.get("HARDLY_LIVE_CAPTURE"),
    reason="set HARDLY_LIVE_CAPTURE=1 to run live Playwright soak",
)
def test_live_soak_example_and_aspnet(tmp_path, monkeypatch):
    monkeypatch.setenv("HARDLY_CACHE_DIR", str(tmp_path))
    status = playwright_status()
    if not status.get("ready"):
        pytest.skip(status.get("hint") or "Playwright browsers missing")

    from hardly.soak_live import run_soak

    summary = run_soak(ids=["example", "wyobiz", "httpbin-form", "the-internet-login"])
    by_id = {r["id"]: r for r in summary["results"]}
    assert by_id["example"]["ok"], by_id["example"]
    assert by_id["wyobiz"]["ok"], by_id["wyobiz"]
    assert by_id["wyobiz"]["aspnet_pages"] >= 1
    assert by_id["httpbin-form"]["ok"], by_id["httpbin-form"]
    assert by_id["the-internet-login"]["ok"], by_id["the-internet-login"]
    assert by_id["the-internet-login"]["password_fields"] >= 1


@pytest.mark.skipif(not playwright_available(), reason="playwright not installed")
@pytest.mark.skipif(
    not os.environ.get("HARDLY_LIVE_CAPTURE"),
    reason="set HARDLY_LIVE_CAPTURE=1 to run live Playwright soak",
)
def test_capture_headless_writes_har(tmp_path, monkeypatch):
    monkeypatch.setenv("HARDLY_CACHE_DIR", str(tmp_path))
    if not playwright_status().get("ready"):
        pytest.skip("Playwright browsers missing")

    from hardly.capture import capture_headless

    har = tmp_path / "example.har"
    out = capture_headless(
        "https://example.com/",
        har,
        wait_seconds=1.5,
        open_session=False,
    )
    assert out["status"] == "stopped"
    assert har.is_file()
    assert har.stat().st_size > 100
    assert (out.get("entry_count_hint") or 0) >= 1
