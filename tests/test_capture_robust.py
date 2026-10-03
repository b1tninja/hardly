"""Executable autodetect, doctor keys, budget, noise blocking, HAR-missing."""

import time

import pytest

from hardly import capture
from hardly.core import browser_detect
from hardly.core.noise_hosts import NoiseBlocker, block_reason


def _fake_browsers(root, build="1194"):
    d = root / f"chromium-{build}" / "chrome-linux"
    d.mkdir(parents=True)
    exe = d / "chrome"
    exe.write_text("#!/bin/sh\n")
    exe.chmod(0o755)
    return exe


def test_autodetect_from_env_dir(tmp_path, monkeypatch):
    exe = _fake_browsers(tmp_path)
    monkeypatch.delenv("HARDLY_BROWSER_EXECUTABLE", raising=False)
    monkeypatch.delenv("HARDLY_BROWSER_CHANNEL", raising=False)
    monkeypatch.setenv("PLAYWRIGHT_BROWSERS_PATH", str(tmp_path))
    missing = str(tmp_path / "missing")
    info = capture.resolve_browser_executable(playwright_path=missing)
    assert info["source"] == "autodetect" and info["executable"] == str(exe)
    assert capture.default_executable(playwright_path=missing) == str(exe)
    # Playwright's own browser present -> no override
    assert capture.resolve_browser_executable(playwright_path=str(exe))["source"] == "playwright"


def test_env_executable_wins_and_channel(tmp_path, monkeypatch):
    exe = _fake_browsers(tmp_path)
    monkeypatch.setenv("HARDLY_BROWSER_EXECUTABLE", str(exe))
    assert capture.resolve_browser_executable(playwright_path="")["source"] == "env"
    monkeypatch.delenv("HARDLY_BROWSER_EXECUTABLE")
    info = capture.resolve_browser_executable(channel="chrome", playwright_path="")
    assert info["source"] == "channel"


def test_scan_prefers_full_chromium_and_pin_hint(tmp_path):
    _fake_browsers(tmp_path, "1194")
    shell = tmp_path / "chromium_headless_shell-1200" / "chrome-linux"
    shell.mkdir(parents=True)
    (shell / "headless_shell").write_text("x")
    (shell / "headless_shell").chmod(0o755)
    builds = browser_detect.scan_chromium_builds([tmp_path])
    assert builds[0]["kind"] == "chromium"
    assert {b["build"] for b in builds} == {"1194", "1200"}
    assert browser_detect.pick_executable(builds)["build"] == "1194"
    assert "1.56" in browser_detect.pin_hint(builds[:1], "1243")
    assert "unknown" in browser_detect.pin_hint(builds[1:], "1243")


def test_doctor_keys():
    st = capture.playwright_status()
    for key in (
        "installed_builds",
        "expected_build",
        "mismatch",
        "suggested_executable",
        "browser_executable_source",
        "pin_hint",
    ):
        assert key in st
    assert isinstance(st["mismatch"], bool)


class FakePage:
    def __init__(self):
        self.url = "about:blank"

    def wait_for_timeout(self, ms):
        time.sleep(ms / 1000.0)

    def goto(self, url, **kw):
        if "bad" in url:
            raise RuntimeError("net::ERR_NAME_NOT_RESOLVED at " + url)
        self.url = url


def test_recipe_budget_skips_remaining_steps():
    steps = [{"op": "wait", "ms": 200}] * 5
    out = capture._run_inprocess_recipe(
        FakePage(), steps, deadline=time.monotonic() + 0.3
    )
    assert out["step_count"] < 5
    assert out["skipped_steps"] == 5 - out["step_count"]
    assert out["skipped_steps"] > 0
    assert out["ok"] is False


def test_recipe_goto_error_classified():
    out = capture._run_inprocess_recipe(FakePage(), [{"op": "goto", "url": "http://bad/"}])
    step = out["steps"][0]
    assert step["ok"] is False and step["error_class"] == "dns" and step["error_advice"]


def test_resolve_budget(monkeypatch):
    monkeypatch.delenv("HARDLY_CAPTURE_BUDGET", raising=False)
    assert capture.resolve_budget(None) == 0
    monkeypatch.setenv("HARDLY_CAPTURE_BUDGET", "12")
    assert capture.resolve_budget(None) == 12
    assert capture.resolve_budget(3) == 3


class FakeReq:
    def __init__(self, url, rtype):
        self.url, self.resource_type = url, rtype


class FakeRoute:
    def __init__(self, url, rtype="xhr"):
        self.request = FakeReq(url, rtype)
        self.action = None

    def abort(self):
        self.action = "abort"

    def continue_(self):
        self.action = "continue"


def test_noise_blocker_routes():
    b = NoiseBlocker()
    cases = {
        "https://www.google-analytics.com/collect": ("script", "abort"),
        "https://fonts.gstatic.com/s/x.woff2": ("font", "abort"),
        "https://cdn.example.org/a.mp4": ("media", "abort"),
        "https://tile.openstreetmap.org/5/10/12.png": ("image", "abort"),
        "https://api.example.org/v1/items": ("xhr", "continue"),
        "https://js.stripe.com/v3/": ("script", "continue"),
        "https://www.google-analytics.com/": ("document", "continue"),
    }
    for url, (rtype, expect) in cases.items():
        r = FakeRoute(url, rtype)
        b.handle(r)
        assert r.action == expect, url
    s = b.summary()
    assert s["blocked_requests"] == 4
    assert "www.google-analytics.com" in s["blocked_hosts"]
    assert block_reason("data:image/png;base64,xx", "image") is None


def test_install_registers_route():
    calls = []

    class Ctx:
        def route(self, pat, fn):
            calls.append(pat)

    NoiseBlocker().install(Ctx())
    assert calls == ["**/*"]


def test_no_har_written_is_error(tmp_path, monkeypatch):
    monkeypatch.setenv("HARDLY_CACHE_DIR", str(tmp_path))
    monkeypatch.setenv("HARDLY_CAPTURE_BUDGET", "30")
    monkeypatch.setattr(capture, "require_playwright", lambda **kw: {})
    monkeypatch.setattr(
        capture,
        "resolve_browser_executable",
        lambda **kw: {"executable": None, "source": "playwright"},
    )

    class Ctx:
        def new_page(self):
            return FakePage()

        def add_init_script(self, *_):
            pass

        def route(self, *_):
            pass

        def on(self, *_):
            pass

        def close(self):
            pass  # never writes the HAR

    class Browser:
        def new_context(self, **kw):
            return Ctx()

        def close(self):
            pass

    class PW:
        class chromium:  # noqa: N801
            executable_path = "/nonexistent"

            @staticmethod
            def launch(**kw):
                return Browser()

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(capture, "_sync_playwright", lambda: PW())
    out = capture.capture_headless(
        "about:blank",
        har_path=tmp_path / "x.har",
        wait_seconds=0,
        open_session=False,
        omit_content=True,
        block_noise=True,
    )
    assert out["status"] == "error" and out["har_exists"] is False
    assert out["error"] and out["error_class"] == "unknown"
    assert "waited_s" in out["slot"]
    assert out["budget"]["limit_s"] == 30 and out["budget"]["exceeded"] is False
    assert out["blocked_requests"] == 0


def test_stop_capture_stopped_without_har_is_error(tmp_path, monkeypatch):
    monkeypatch.setenv("HARDLY_CACHE_DIR", str(tmp_path))
    capture._persist_payload(
        "abc",
        {"capture_id": "abc", "status": "stopped", "har_path": str(tmp_path / "no.har")},
    )
    out = capture.stop_capture("abc", open_session=False)
    assert out["status"] == "error" and out["har_exists"] is False and out["error"]


@pytest.mark.skipif(not capture.playwright_available(), reason="playwright not installed")
def test_live_budget_and_noise(tmp_path, monkeypatch):
    monkeypatch.setenv("HARDLY_CACHE_DIR", str(tmp_path))
    if not capture.playwright_status().get("ready"):
        pytest.skip("Playwright browser not ready")
    from hardly.local_site import serve

    with serve() as base:
        out = capture.capture_headless(
            f"{base}/",
            wait_seconds=0,
            open_session=False,
            omit_content=True,
            budget_seconds=1.5,
            block_noise=True,
            recipe=[{"op": "wait", "ms": 1200}] * 3,
        )
    assert out["status"] == "stopped" and out["har_exists"]
    assert out["budget"]["exceeded"] is True and out["budget"]["skipped_steps"] >= 1
    assert "blocked_requests" in out and "waited_s" in out["slot"]
