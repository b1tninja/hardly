"""Small fixes from live testing: CDN seeds, wait seconds, SIGPIPE, captcha fields."""

import json
import subprocess
import sys
from pathlib import Path

from hardly import session as sess
from hardly.capture import _wait_ms
from hardly.core.challenges import detect_challenges

FIX = Path(__file__).parent / "fixtures" / "sample.har"


def _entry(i, url, body="", ct="text/html", status=200):
    return {
        "startedDateTime": f"2026-01-01T00:00:{i:02d}.000Z", "time": 5,
        "request": {"method": "GET", "url": url, "httpVersion": "HTTP/1.1", "headers": [],
                    "queryString": [], "cookies": [], "headersSize": -1, "bodySize": 0},
        "response": {"status": status, "statusText": "x", "httpVersion": "HTTP/1.1",
                     "headers": [{"name": "Content-Type", "value": ct}], "cookies": [],
                     "redirectURL": "", "headersSize": -1, "bodySize": len(body),
                     "content": {"size": len(body), "mimeType": ct, "text": body}},
    }


def test_preferred_host_skips_beacon_cdns(tmp_path, monkeypatch):
    entries = [_entry(1, "https://shop.example.com/login", "<form></form>")]
    entries += [_entry(i + 2, f"https://static.cloudflareinsights.com/beacon.min.js?{i}", "x", "text/javascript") for i in range(4)]
    entries += [_entry(i + 8, f"https://298279967.log.optimizely.com/event?{i}", "{}", "application/json") for i in range(4)]
    entries += [
        _entry(i + 20, f"https://events.backtrace.io/api/submit?{i}", "{}", "application/json")
        for i in range(6)
    ]
    path = tmp_path / "p.har"
    path.write_text(json.dumps({"log": {"version": "1.2", "creator": {"name": "t", "version": "1"}, "entries": entries}}))
    monkeypatch.setenv("HARDLY_RUNTIME_DIR", str(tmp_path / "cache"))
    info = sess.open_har(str(path), force=True)
    from hardly.index import query as q

    assert q.preferred_host(sess.require_conn(info["session_id"])) == "shop.example.com"


def test_wait_accepts_seconds_or_ms():
    assert _wait_ms({"ms": 250}, 1000) == 250
    assert _wait_ms({"seconds": 1.5}, 1000) == 1500
    assert _wait_ms({}, 700) == 700


def test_cli_survives_closed_pipe():
    code = (
        "from hardly.cli import main; import sys;"
        f"main(['endpoint', 'list', r'{FIX}'])"
    )
    proc = subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert proc.stdout is not None
    proc.stdout.read(10)
    proc.stdout.close()
    _, err = proc.communicate(timeout=60)
    assert b"BrokenPipeError" not in err and b"Traceback" not in err


def test_captcha_response_fields_are_submitted_names_only(tmp_path, monkeypatch):
    html = (
        '<form id="captcha-demo-form"><div class="g-recaptcha" data-sitekey="K"></div>'
        '<div id="captcha-error"></div><textarea name="g-recaptcha-response"></textarea></form>'
    )
    path = tmp_path / "c.har"
    path.write_text(json.dumps({"log": {"version": "1.2", "creator": {"name": "t", "version": "1"},
                                        "entries": [_entry(1, "https://a.example.com/", html)]}}))
    monkeypatch.setenv("HARDLY_RUNTIME_DIR", str(tmp_path / "cache"))
    info = sess.open_har(str(path), force=True)
    out = detect_challenges(sess.require_conn(info["session_id"]))
    assert out["captcha_widgets"][0]["response_fields"] == ["g-recaptcha-response"]
