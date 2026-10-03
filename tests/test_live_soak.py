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
    assert len(TARGETS) >= 8
    ids = {t.id for t in TARGETS}
    assert "local-webforms" in ids
    assert "example" in ids
    assert "countries-gql" in ids
    assert "jsonplaceholder" in ids
    assert "petstore-openapi" in ids
    rows = catalog_summary()
    assert all("url" in r and "tech" in r for r in rows)
    assert target_by_id("local-webforms") is not None
    assert list_targets(ids=["example"])[0].id == "example"
    gql = target_by_id("countries-gql")
    assert gql and any(s.get("op") == "fetch" for s in gql.recipe)


def test_live_target_ids_unique():
    ids = [t.id for t in TARGETS]
    assert len(ids) == len(set(ids))


@pytest.mark.browser
@pytest.mark.skipif(not playwright_available(), reason="playwright not installed")
@pytest.mark.skipif(
    not os.environ.get("HARDLY_LIVE_CAPTURE"),
    reason="set HARDLY_LIVE_CAPTURE=1 to run live Playwright soak",
)
def test_live_soak_example_and_aspnet(tmp_path, monkeypatch):
    monkeypatch.setenv("HARDLY_RUNTIME_DIR", str(tmp_path))
    status = playwright_status()
    if not status.get("ready"):
        pytest.skip(status.get("hint") or "Playwright browsers missing")

    from hardly.soak_live import run_soak

    summary = run_soak(
        ids=[
            "example",
            "local-webforms",
            "httpbin-form",
            "the-internet-login",
            "countries-gql",
            "jsonplaceholder",
        ],
        fixture_dir=tmp_path / "fixtures",
    )
    by_id = {r["id"]: r for r in summary["results"]}
    assert by_id["example"]["ok"], by_id["example"]
    assert by_id["local-webforms"]["ok"], by_id["local-webforms"]
    assert by_id["local-webforms"]["aspnet_pages"] >= 1
    assert by_id["httpbin-form"]["ok"], by_id["httpbin-form"]
    assert by_id["the-internet-login"]["ok"], by_id["the-internet-login"]
    assert by_id["the-internet-login"]["password_fields"] >= 1
    assert by_id["countries-gql"]["ok"], by_id["countries-gql"]
    assert by_id["countries-gql"]["graphql_ops"] >= 1
    assert by_id["jsonplaceholder"]["ok"], by_id["jsonplaceholder"]
    assert by_id["jsonplaceholder"]["json_entries"] >= 1
    assert summary.get("fixtures")
    assert (tmp_path / "fixtures" / "manifest.json").is_file()


@pytest.mark.browser
@pytest.mark.skipif(not playwright_available(), reason="playwright not installed")
@pytest.mark.skipif(
    not os.environ.get("HARDLY_LIVE_CAPTURE"),
    reason="set HARDLY_LIVE_CAPTURE=1 to run live Playwright soak",
)
def test_capture_headless_writes_har(tmp_path, monkeypatch):
    monkeypatch.setenv("HARDLY_RUNTIME_DIR", str(tmp_path))
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


@pytest.mark.browser
@pytest.mark.skipif(not playwright_available(), reason="playwright not installed")
def test_local_synthetic_soak(tmp_path, monkeypatch):
    """Loopback targets need a browser but no network."""
    monkeypatch.setenv("HARDLY_RUNTIME_DIR", str(tmp_path))
    if not playwright_status().get("ready"):
        pytest.skip("Playwright browser not ready")

    from hardly.soak_live import run_soak

    summary = run_soak(ids=["local-webforms", "local-token-login"])
    by_id = {r["id"]: r for r in summary["results"]}
    assert by_id["local-webforms"]["ok"], by_id["local-webforms"]
    assert by_id["local-webforms"]["aspnet_pages"] >= 1
    assert by_id["local-token-login"]["ok"], by_id["local-token-login"]
    assert by_id["local-token-login"]["password_fields"] >= 1


@pytest.mark.browser
@pytest.mark.skipif(not playwright_available(), reason="playwright not installed")
def test_local_challenges_captured(tmp_path, monkeypatch):
    """Capture the synthetic challenge pages in a real browser, then detect."""
    monkeypatch.setenv("HARDLY_RUNTIME_DIR", str(tmp_path))
    if not playwright_status().get("ready"):
        pytest.skip("Playwright browser not ready")

    from hardly import session as sess
    from hardly.capture import capture_headless
    from hardly.core.challenges import detect_challenges
    from hardly.local_site import serve

    with serve() as base:
        recipe = [
            {"op": "goto", "url": f"{base}/private"},
            {"op": "goto", "url": f"{base}/limited"},
            {"op": "goto", "url": f"{base}/captcha"},
        ]
        cap = capture_headless(
            f"{base}/", wait_seconds=0.5, recipe=recipe, open_session=True, brief=False
        )
    out = detect_challenges(sess.require_conn(cap["session_id"]))
    assert any(
        s["scheme"] == "Basic" for c in out["auth_challenges"] for s in c["schemes"]
    )
    assert any(t["status"] == 429 for t in out["throttling"])
    assert {"turnstile", "hcaptcha"} <= {c["name"] for c in out["captcha_widgets"]}


@pytest.mark.browser
@pytest.mark.skipif(not playwright_available(), reason="playwright not installed")
def test_find_click_navigates_to_search_form(tmp_path, monkeypatch):
    """Landing -> services (link) -> lookup (JS button) -> real search form."""
    monkeypatch.setenv("HARDLY_RUNTIME_DIR", str(tmp_path))
    if not playwright_status().get("ready"):
        pytest.skip("Playwright browser not ready")

    from hardly.capture import capture_headless
    from hardly.local_site import serve

    with serve() as base:
        recipe = [
            {"op": "goto", "url": f"{base}/portal"},
            {"op": "find_click", "keywords": ["widget"], "max_hops": 4},
        ]
        cap = capture_headless(
            f"{base}/portal", wait_seconds=0.3, recipe=recipe, open_session=False, brief=False
        )
    steps = cap["discover"]["recipe"]["steps"]
    result = next(s for s in steps if s["op"] == "find_click")["result"]
    assert result["reached"], result
    assert result["url"].endswith("/portal/lookup")
    assert [h["clicked"] for h in result["hops"]] == ["Online services", "Widget lookup"]
    assert set(result["form"]["fields"]) == {"name", "category"}


@pytest.mark.browser
@pytest.mark.skipif(not playwright_available(), reason="playwright not installed")
def test_find_click_survives_real_world_traps(tmp_path, monkeypatch):
    """Utility forms are not the goal; hidden and new-tab links fall back to href."""
    monkeypatch.setenv("HARDLY_RUNTIME_DIR", str(tmp_path))
    if not playwright_status().get("ready"):
        pytest.skip("Playwright browser not ready")

    from hardly.capture import capture_headless
    from hardly.local_site import serve

    with serve() as base:
        recipe = [
            {"op": "goto", "url": f"{base}/portal/traps"},
            {"op": "find_click", "keywords": ["entity", "lookup"], "max_hops": 3},
        ]
        cap = capture_headless(
            f"{base}/portal/traps", wait_seconds=0.3, recipe=recipe, open_session=False, brief=False
        )
    result = next(
        s for s in cap["discover"]["recipe"]["steps"] if s["op"] == "find_click"
    )["result"]
    assert result["reached"], result
    assert result["url"].endswith("/portal/lookup")
    assert result["hops"], "the traps page has no search form of its own"
    assert result["hops"][0]["via"] == "goto"  # hidden / new-tab link navigated by href
    assert "mobile-trigger-search" not in str(result["hops"])


@pytest.mark.browser
@pytest.mark.skipif(not playwright_available(), reason="playwright not installed")
def test_find_click_recovers_from_error_page_and_skips_feedback(tmp_path, monkeypatch):
    monkeypatch.setenv("HARDLY_RUNTIME_DIR", str(tmp_path))
    if not playwright_status().get("ready"):
        pytest.skip("Playwright browser not ready")

    from hardly.capture import capture_headless
    from hardly.local_site import serve

    with serve() as base:
        recipe = [
            {"op": "goto", "url": f"{base}/portal/broken"},
            {"op": "find_click", "keywords": ["records", "entity"], "max_hops": 3},
        ]
        cap = capture_headless(
            f"{base}/portal/broken", wait_seconds=0.3, recipe=recipe, open_session=False, brief=False
        )
    result = next(s for s in cap["discover"]["recipe"]["steps"] if s["op"] == "find_click")["result"]
    assert result["reached"], result
    assert result["url"].endswith("/portal/lookup")
    errors = [h for h in result["hops"] if h.get("error")]
    assert errors and "browser error page" in errors[0]["error"]      # stepped back from the dead link
    assert not any("Did you find" in str(h.get("clicked")) for h in result["hops"])


def _find_click_on(tmp_path, monkeypatch, start_path, keywords, max_hops=4):
    monkeypatch.setenv("HARDLY_RUNTIME_DIR", str(tmp_path))
    from hardly.capture import capture_headless
    from hardly.local_site import serve

    with serve() as base:
        recipe = [
            {"op": "goto", "url": f"{base}{start_path}"},
            {"op": "find_click", "keywords": keywords, "max_hops": max_hops},
        ]
        cap = capture_headless(
            f"{base}{start_path}", wait_seconds=0.3, recipe=recipe, open_session=False, brief=False
        )
    return next(s for s in cap["discover"]["recipe"]["steps"] if s["op"] == "find_click")["result"]


@pytest.mark.browser
@pytest.mark.skipif(not playwright_available(), reason="playwright not installed")
def test_find_click_after_first_hop_requires_a_search_term_and_keyword(tmp_path, monkeypatch):
    if not playwright_status().get("ready"):
        pytest.skip("Playwright browser not ready")
    ok = _find_click_on(tmp_path, monkeypatch, "/portal/w1", ["permit"])
    assert ok["reached"], ok
    assert [h["clicked"] for h in ok["hops"]] == ["Permit services", "Permit search"]
    dead = _find_click_on(tmp_path, monkeypatch, "/portal/dead", ["permit"])
    assert not dead["reached"]
    assert [h["clicked"] for h in dead["hops"]] == ["Permit services"]   # stopped; did not wander to guides/forms


@pytest.mark.browser
@pytest.mark.skipif(not playwright_available(), reason="playwright not installed")
def test_header_login_box_does_not_stop_navigation(tmp_path, monkeypatch):
    if not playwright_status().get("ready"):
        pytest.skip("Playwright browser not ready")
    res = _find_click_on(tmp_path, monkeypatch, "/portal/hl", ["widget"])
    assert "blocked" not in res, res
    assert res["reached"] and res["url"].endswith("/portal/lookup")


@pytest.mark.browser
@pytest.mark.skipif(not playwright_available(), reason="playwright not installed")
def test_find_click_waits_for_a_client_rendered_form(tmp_path, monkeypatch):
    if not playwright_status().get("ready"):
        pytest.skip("Playwright browser not ready")
    res = _find_click_on(tmp_path, monkeypatch, "/portal/spahome", ["inventory"])
    assert res["reached"], res
    assert set(res["form"]["fields"]) == {"holder_name", "item_number"}
