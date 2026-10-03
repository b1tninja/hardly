"""Headless navigation v2: iframes, shadow DOM, hover menus, consent, per-step waits.

Real-browser tests run against the loopback ``/nav2/`` routes (no network) and
skip when no browser is available.
"""

from __future__ import annotations

import time

import pytest

from hardly.capture import playwright_available, playwright_status
from hardly.core.page_nav import (
    classify_consent_label,
    consent_refusal,
    pick_consent_control,
    same_origin_frame,
)
from hardly.core.search_nav import page_candidates, search_form_reached

# --- offline -----------------------------------------------------------------


def test_consent_label_classes():
    assert classify_consent_label("Reject all") == "reject"
    assert classify_consent_label("Only necessary cookies") == "reject"
    assert classify_consent_label("No thanks") == "reject"
    assert classify_consent_label("Accept all") == "accept"
    assert classify_consent_label("I agree") == "accept"
    assert classify_consent_label("Got it") == "accept"
    assert classify_consent_label("Manage preferences") == "other"
    assert classify_consent_label("Cookie settings") == "other"
    assert classify_consent_label("Sign in") == "other"


def test_pick_consent_control_is_reject_first():
    ctrls = [{"label": "Accept all"}, {"label": "Reject all"}]
    assert pick_consent_control(ctrls)[1] == "reject"
    assert pick_consent_control(ctrls, "accept")[1] == "accept"
    assert pick_consent_control([{"label": "Accept all"}])[1] == "accept"
    assert pick_consent_control([{"label": "Manage"}]) == (None, "")


def test_consent_refusal_leaves_gates_alone():
    ok = {"text": "We use cookies to improve the site.", "has_fields": 0}
    assert consent_refusal(ok) == ""
    assert consent_refusal({**ok, "has_password": True}) == "login"
    assert consent_refusal({**ok, "has_captcha": True}) == "captcha"
    terms = {"text": "Terms of use: you give consent and agree to no automated access.", "has_fields": 0}
    assert consent_refusal(terms) == "terms_gate"
    assert consent_refusal({"text": "Welcome back, pick a plan", "has_fields": 0}) == "not_consent"
    assert consent_refusal({"text": "Cookies. Sign in with your username", "has_fields": 1}) == "login"


def test_same_origin_frame():
    assert same_origin_frame("http://127.0.0.1:5/a", "http://127.0.0.1:5/b")
    assert not same_origin_frame("http://127.0.0.1:6/a", "http://127.0.0.1:5/b")
    assert same_origin_frame("about:blank", "http://127.0.0.1:5/b")


def test_page_candidates_merges_extra_links_and_forms():
    extra_links = [
        {"text": "Widget lookup", "href": "http://h/nav2/lookup", "kind": "link", "css": 'a:has-text("Widget lookup")',
         "frame": 1, "idx": 7, "shadow": False}
    ]
    extra_forms = [
        {"action": "http://h/r", "method": "GET", "frame": "http://h/inner",
         "fields": [{"name": "a", "type": "text", "kind": "input"}, {"name": "b", "type": "text", "kind": "input"}]}
    ]
    cands, structure = page_candidates(
        "<html><body>nothing</body></html>", base_url="http://h/", extra_links=extra_links, extra_forms=extra_forms
    )
    assert cands and cands[0]["frame"] == 1 and cands[0]["idx"] == 7
    hit = search_form_reached(structure)
    assert hit and hit["frame"] == "http://h/inner"


def test_step_options_are_validated():
    from hardly.capture import CaptureError, _step_timeout, _step_wait_until, _unsupported_step_keys

    assert _step_wait_until({"wait_until": "LOAD"}) == "load"
    with pytest.raises(CaptureError):
        _step_wait_until({"wait_until": "soon"})
    assert _step_timeout({"timeout_ms": 5}) == 100
    assert _step_timeout({}, 7) == 7
    assert _unsupported_step_keys("goto", {"url": "x", "timeout_ms": 5, "wait_until": "load"}, inprocess=True) == ""
    assert _unsupported_step_keys("dismiss_consent", {"prefer": "accept"}, inprocess=True) == ""
    assert _unsupported_step_keys("find_click", {"hover": False}, inprocess=False) == ""


def test_live_runner_knows_new_ops():
    from hardly.capture import _RECIPE_OPS, _RPC_OPS

    assert {"find_click", "dismiss_consent"} <= _RECIPE_OPS
    assert {"find_click", "dismiss_consent", "goto"} <= _RPC_OPS


# --- real browser ------------------------------------------------------------

_skip_no_browser = pytest.mark.skipif(not playwright_available(), reason="playwright not installed")


def needs_browser(fn):
    return pytest.mark.browser(_skip_no_browser(fn))


def _run(tmp_path, monkeypatch, path, recipe):
    monkeypatch.setenv("HARDLY_RUNTIME_DIR", str(tmp_path))
    if not playwright_status().get("ready"):
        pytest.skip("Playwright browser not ready")
    from hardly.capture import capture_headless
    from hardly.local_site import serve

    with serve() as base:
        steps = [{"op": "goto", "url": f"{base}{path}"}] + recipe
        cap = capture_headless(f"{base}{path}", wait_seconds=0.2, recipe=steps, open_session=False, brief=False)
    return cap["discover"]["recipe"]["steps"]


@needs_browser
def test_find_click_sees_same_origin_iframe(tmp_path, monkeypatch):
    steps = _run(tmp_path, monkeypatch, "/nav2/frame", [{"op": "find_click", "keywords": ["widget"]}])
    res = steps[-1]["result"]
    assert res["reached"], res
    assert res["hops"][0]["where"] == "iframe"
    assert set(res["form"]["fields"]) == {"name", "serial"}
    assert res["form"]["frame"].endswith("/nav2/lookup")


@needs_browser
def test_find_click_sees_open_shadow_dom(tmp_path, monkeypatch):
    steps = _run(tmp_path, monkeypatch, "/nav2/shadow", [{"op": "find_click", "keywords": ["widget"]}])
    res = steps[-1]["result"]
    assert res["reached"], res
    assert res["hops"][0]["where"] == "shadow"
    assert res["url"].endswith("/nav2/lookup")


@needs_browser
def test_find_click_hovers_menu_to_reveal_links(tmp_path, monkeypatch):
    steps = _run(tmp_path, monkeypatch, "/nav2/hover", [{"op": "find_click", "keywords": ["widget"]}])
    res = steps[-1]["result"]
    assert res["reached"], res
    hop = res["hops"][0]
    assert hop["via"] == "hover+click" and hop["hover"] == "Services"
    assert res["url"].endswith("/nav2/lookup")


@needs_browser
def test_find_click_hover_can_be_disabled(tmp_path, monkeypatch):
    steps = _run(tmp_path, monkeypatch, "/nav2/hover", [{"op": "find_click", "keywords": ["widget"], "hover": False}])
    res = steps[-1]["result"]
    assert res["hops"][0]["via"] == "goto"  # old behaviour: hidden link, navigate to href


@needs_browser
def test_dismiss_consent_prefers_reject(tmp_path, monkeypatch):
    steps = _run(
        tmp_path, monkeypatch, "/nav2/consent",
        [{"op": "dismiss_consent"}, {"op": "evaluate", "js": "window.__choice"}],
    )
    res = steps[1]["result"]
    assert res["dismissed"] and res["action"] == "reject" and res["gone"], res
    assert steps[2]["result"]["value"] == "reject"


@needs_browser
def test_dismiss_consent_accept_when_only_option_and_when_asked(tmp_path, monkeypatch):
    steps = _run(
        tmp_path, monkeypatch, "/nav2/consent-accept",
        [{"op": "dismiss_consent"}, {"op": "evaluate", "js": "window.__choice"}],
    )
    assert steps[1]["result"]["action"] == "accept"
    assert steps[2]["result"]["value"] == "accept"
    steps = _run(
        tmp_path, monkeypatch, "/nav2/consent",
        [{"op": "dismiss_consent", "prefer": "accept"}, {"op": "evaluate", "js": "window.__choice"}],
    )
    assert steps[2]["result"]["value"] == "accept"


@needs_browser
@pytest.mark.parametrize(
    ("path", "reason"),
    [("/nav2/terms", "terms_gate"), ("/nav2/login-dialog", "login"), ("/nav2/captcha-dialog", "captcha")],
)
def test_dismiss_consent_never_touches_gates(tmp_path, monkeypatch, path, reason):
    steps = _run(
        tmp_path, monkeypatch, path,
        [{"op": "dismiss_consent"}, {"op": "evaluate", "js": "window.__choice"}],
    )
    res = steps[1]["result"]
    assert not res["dismissed"]
    assert reason in {r["reason"] for r in res["refused"]}
    assert steps[2]["result"]["value"] == ""


@needs_browser
def test_goto_wait_until_and_timeout(tmp_path, monkeypatch):
    t0 = time.monotonic()
    monkeypatch.setenv("HARDLY_RUNTIME_DIR", str(tmp_path))
    if not playwright_status().get("ready"):
        pytest.skip("Playwright browser not ready")
    from hardly.capture import capture_headless
    from hardly.local_site import serve

    with serve() as base:
        slow = f"{base}/nav2/slow"
        recipe = [
            {"op": "goto", "url": slow, "wait_until": "domcontentloaded", "timeout_ms": 1500},
            {"op": "goto", "url": slow, "wait_until": "load", "timeout_ms": 400},
            {"op": "goto", "url": slow, "wait_until": "sometime"},
        ]
        cap = capture_headless(f"{base}/nav2/lookup", wait_seconds=0.1, recipe=recipe, open_session=False, brief=False)
    steps = cap["discover"]["recipe"]["steps"]
    assert steps[0]["ok"], steps[0]
    assert not steps[1]["ok"] and "imeout" in steps[1]["error"]
    assert not steps[2]["ok"] and "wait_until" in steps[2]["error"]
    assert time.monotonic() - t0 < 60


@needs_browser
def test_click_wait_until(tmp_path, monkeypatch):
    steps = _run(
        tmp_path, monkeypatch, "/nav2/hover",
        [{"op": "click", "css": 'a:has-text("About")', "wait_until": "load", "timeout_ms": 3000}],
    )
    assert steps[-1]["ok"], steps[-1]
    assert steps[-1]["result"]["url"].endswith("/nav2/about")


@needs_browser
def test_find_click_and_consent_in_live_session(tmp_path, monkeypatch):
    """The live-session runner (worker process) supports find_click / dismiss_consent / goto waits."""
    monkeypatch.setenv("HARDLY_RUNTIME_DIR", str(tmp_path))
    if not playwright_status().get("ready"):
        pytest.skip("Playwright browser not ready")
    from hardly import capture as cap
    from hardly.local_site import serve

    with serve() as base:
        started = cap.start_capture(f"{base}/nav2/consent", tmp_path / "live.har", headed=False)
        cid = started["id"] if "id" in started else started["capture_id"]
        try:
            out = cap.run_capture_recipe(
                [
                    {"op": "dismiss_consent"},
                    {"op": "goto", "url": f"{base}/nav2/hover", "wait_until": "load", "timeout_ms": 5000},
                    {"op": "find_click", "keywords": ["widget"]},
                ],
                capture_id=cid,
            )
        finally:
            cap.stop_capture(cid)
    steps = out["steps"]
    assert out["stopped_on_error"] is False, out
    assert steps[0]["result"]["dismissed"] and steps[0]["result"]["action"] == "reject"
    assert steps[1]["result"]["url"].endswith("/nav2/hover")
    assert steps[2]["result"]["reached"], steps[2]
    assert steps[2]["result"]["hops"][0]["via"] == "hover+click"
