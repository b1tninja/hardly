"""Capture hardening: slot timeout passthrough, -o precheck, 5xx warning, noise/budget, slots race."""

import os
import threading

import pytest

from hardly import capture
from hardly.core import redirect_diag, slots
from hardly.core.capture_errors import classify_capture_error
from hardly.core.noise_hosts import NoiseBlocker


class _Resp:
    def __init__(self, status=200, headers=None):
        self.status = status
        self.headers = headers or {}


def _fake_pw(monkeypatch, tmp_path, goto):
    monkeypatch.setenv("HARDLY_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setattr(capture, "require_playwright", lambda **kw: {})
    monkeypatch.setattr(
        capture, "resolve_browser_executable", lambda **kw: {"executable": None, "source": "playwright"}
    )
    har_holder = {}

    class Page:
        url = "about:blank"

        def goto(self, url, **kw):
            return goto(url)

        def wait_for_timeout(self, ms):
            pass

    class Ctx:
        def new_page(self):
            return Page()

        def add_init_script(self, *_):
            pass

        def route(self, *_):
            pass

        def on(self, *_):
            pass

        def close(self):
            with open(har_holder["path"], "w") as fh:
                fh.write('{"log":{"entries":[]}}')

    class Browser:
        def new_context(self, **kw):
            har_holder["path"] = kw["record_har_path"]
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


def test_main_document_502_warns(tmp_path, monkeypatch):
    _fake_pw(monkeypatch, tmp_path, lambda url: _Resp(502))
    out = capture.capture_headless(
        "https://example.invalid/", har_path=tmp_path / "a.har", wait_seconds=0,
        open_session=False, omit_content=True,
    )
    assert out["status"] == "stopped"
    assert out["main_status"] == 502 and out["main_document_ok"] is False
    assert any("502" in w and "proxy" in w for w in out["warnings"])


def test_main_document_200_no_warning(tmp_path, monkeypatch):
    _fake_pw(monkeypatch, tmp_path, lambda url: _Resp(200))
    out = capture.capture_headless(
        "https://example.invalid/", har_path=tmp_path / "a.har", wait_seconds=0,
        open_session=False, omit_content=True, block_noise=True,
    )
    assert "warnings" not in out and out["block_noise"] is True
    assert out["blocked_requests"] == 0 and out["blocked_hosts"] == []


def test_deny_reason_header_warns():
    msg = capture._main_document_warning(403, {"x-deny-reason": "host_not_allowed"}, None)
    assert "host_not_allowed" in msg


def _loop(url):
    raise RuntimeError("net::ERR_TOO_MANY_REDIRECTS at " + url)


def test_redirect_diagnosis_opt_in(tmp_path, monkeypatch):
    _fake_pw(monkeypatch, tmp_path, _loop)
    calls = []
    monkeypatch.setattr(
        redirect_diag, "diagnose_redirects", lambda url, **kw: calls.append((url, kw)) or {"outcome": "loop"}
    )
    kw = dict(har_path=tmp_path / "a.har", wait_seconds=0, open_session=False, omit_content=True)
    with pytest.raises(capture.CaptureError) as ei:
        capture.capture_headless("https://x.invalid/", **kw)
    assert calls == [] and ei.value.redirect_diagnosis is None
    assert "redirect_diagnosis" not in ei.value.to_dict()
    with pytest.raises(capture.CaptureError) as ei:
        capture.capture_headless("https://x.invalid/", diagnose_redirects=True, **kw)
    assert len(calls) == 1 and calls[0][1]["max_hops"] <= 8
    assert ei.value.to_dict()["redirect_diagnosis"] == {"outcome": "loop"}
    assert ei.value.to_dict()["error_class"] == "redirect_loop"


def test_redirect_diagnosis_not_for_other_errors(tmp_path, monkeypatch):
    def boom(url):
        raise RuntimeError("net::ERR_NAME_NOT_RESOLVED")

    _fake_pw(monkeypatch, tmp_path, boom)
    monkeypatch.setattr(redirect_diag, "diagnose_redirects", lambda *a, **k: pytest.fail("called"))
    with pytest.raises(capture.CaptureError):
        capture.capture_headless(
            "https://x.invalid/", har_path=tmp_path / "a.har", wait_seconds=0,
            open_session=False, diagnose_redirects=True,
        )


def test_bad_output_paths(tmp_path, monkeypatch):
    monkeypatch.setattr(capture, "require_playwright", lambda **kw: pytest.fail("precheck first"))
    d = tmp_path / "adir"
    d.mkdir()
    f = tmp_path / "afile"
    f.write_text("x")
    for bad, frag in [(d, "directory"), (f / "sub" / "x.har", "not a directory"), ("a\x00b.har", "NUL")]:
        with pytest.raises(capture.CaptureError, match=frag):
            capture.capture_headless("http://127.0.0.1:1/", bad)
        with pytest.raises(capture.CaptureError, match=frag):
            capture.start_capture("http://127.0.0.1:1/", bad)


def test_cli_bad_output_no_traceback(tmp_path, capsys, monkeypatch):
    from hardly import cli

    monkeypatch.setattr(capture, "require_playwright", lambda **kw: {})
    d = tmp_path / "adir"
    d.mkdir()
    with pytest.raises(SystemExit) as ei:
        cli.main(["capture", "discover", "http://127.0.0.1:1/", "-o", str(d)])
    out = capsys.readouterr().out
    assert ei.value.code == 1 and "directory" in out and "output_path" in out


def test_slot_timeout_passthrough(monkeypatch):
    seen = []
    monkeypatch.setattr(capture, "require_playwright", lambda **kw: {})

    def fake_start(*a, **kw):
        seen.append(kw.get("slot_timeout_s"))
        raise capture.CaptureError("stop here")

    monkeypatch.setattr(capture, "start_capture", fake_start)
    monkeypatch.setenv("HARDLY_CAPTURE_SUBPROCESS", "1")
    for fn, kw in [
        (capture.discover_apis, {}),
        (capture.capture_for, {"headed": True}),
        (capture.capture_interactive, {}),
    ]:
        with pytest.raises(capture.CaptureError):
            fn("http://127.0.0.1:1/", slot_timeout_s=7.5, **kw)
    assert seen == [7.5, 7.5, 7.5]


def test_slot_timeout_error_class(tmp_path, monkeypatch):
    if slots.fcntl is None:
        pytest.skip("no fcntl")
    monkeypatch.setenv("HARDLY_CACHE_DIR", str(tmp_path))
    monkeypatch.setenv("HARDLY_CAPTURE_SLOTS", "1")
    held = slots.acquire_slot(0)
    try:
        with pytest.raises(slots.SlotTimeoutError) as ei:
            slots.acquire_slot(0.05)
        assert ei.value.error_class == "slot_timeout"
        assert ei.value.to_dict()["error_class"] == "slot_timeout"
        monkeypatch.setattr(capture, "require_playwright", lambda **kw: {})
        with pytest.raises(capture.CaptureError) as ce:
            capture.capture_headless("http://127.0.0.1:1/", slot_timeout_s=0.05)
        assert ce.value.to_dict()["error_class"] == "slot_timeout"
        assert "slot_timeout" in str(ce.value)
    finally:
        held.release()
    assert classify_capture_error("waited 1s for a capture slot")["retryable"] is True


def test_queue_depth_sees_concurrent_waiter(tmp_path, monkeypatch):
    if slots.fcntl is None:
        pytest.skip("no fcntl")
    monkeypatch.setenv("HARDLY_CACHE_DIR", str(tmp_path))
    monkeypatch.setenv("HARDLY_CAPTURE_SLOTS", "1")
    held = slots.acquire_slot(0)
    results = {}

    def waiter(name):
        try:
            slots.acquire_slot(0.6)
        except slots.SlotTimeoutError as exc:
            results[name] = str(exc)

    ts = [threading.Thread(target=waiter, args=(n,)) for n in "ab"]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    held.release()
    assert len(results) == 2
    assert all("1 others waiting" in m for m in results.values()), results


def test_fresh_empty_marker_not_pruned(tmp_path):
    m = tmp_path / "wait-1-abc.marker"
    m.write_text("")
    assert slots._live_markers(tmp_path) == [m] and m.exists()
    old = os.stat(m).st_mtime - 60
    os.utime(m, (old, old))
    assert slots._live_markers(tmp_path) == [] and not m.exists()


def test_noise_blocker_summary_consistent():
    class Req:
        def __init__(self, url, rt=""):
            self.url, self.resource_type = url, rt

    class Route:
        def __init__(self, req):
            self.request, self.aborted = req, False

        def abort(self):
            self.aborted = True

        def continue_(self):
            pass

    b = NoiseBlocker()
    assert b.summary()["blocked_requests"] == 0
    r = Route(Req("https://fonts.gstatic.com/x.woff2", "font"))
    b.handle(r)
    s = b.summary()
    assert r.aborted and s["blocked_requests"] == 1 and s["block_noise"] is True
    assert s["blocked_reasons"] == {"type:font": 1}


def test_worker_capture_notes_ignored_options():
    out = {"status": "stopped"}
    capture._note_unsupported_options(out, block_noise=True, budget_seconds=5)
    assert out["block_noise"] is False and len(out["warnings"]) == 2


def test_budget_exhausted_warns(tmp_path, monkeypatch):
    _fake_pw(monkeypatch, tmp_path, lambda url: _Resp(200))
    out = capture.capture_headless(
        "https://example.invalid/", har_path=tmp_path / "a.har", wait_seconds=0, open_session=False,
        omit_content=True, budget_seconds=0.0001,
        recipe=[{"op": "wait", "ms": 10}, {"op": "wait", "ms": 10}],
    )
    assert out["budget"]["exceeded"] is True
    assert any("budget" in w for w in out["warnings"])


class _P:
    def wait_for_timeout(self, ms):
        pass


def test_unsupported_step_keys_inprocess():
    r = capture._run_inprocess_recipe(
        _P(), [{"op": "click", "text": "Login"}, {"op": "wait", "ms": 1}, {"css": "a"}]
    )
    s = r["steps"]
    assert s[0]["ok"] is False and "unsupported key(s) ['text']" in s[0]["error"]
    assert "find_click" in s[0]["error"]
    assert s[1]["ok"] is True
    assert "no 'op'" in s[2]["error"]


def test_unsupported_step_keys_worker_allows_text():
    assert capture._unsupported_step_keys("click", {"op": "click", "text": "x"}, inprocess=False) == ""
    assert "bogus" in capture._unsupported_step_keys("click", {"op": "click", "bogus": 1}, inprocess=False)
