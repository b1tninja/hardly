"""Stub token hygiene and replay_check hardening (MockTransport / no network)."""

import json
import sys
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).parent))
from test_replay_check import _client, _entry, _open  # noqa: E402

from hardly.core.replay_check import replay_check
from hardly.core.stub import _auth_scheme, client_stub

TOKEN = "e3ce9a7b41d05f26c8aa"
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.c2lnbmF0dXJlLXZhbHVl"


def test_stub_unquoted_hidden_carried_and_no_token_literal(tmp_path, monkeypatch):
    page = f"<form><input type=hidden name=nxt value={TOKEN}><input name=q></form>"
    entries = [
        _entry("GET", "/form", mime="text/html", resp_text=page),
        _entry(
            "POST", "/submit", mime="text/html",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            post={
                "mimeType": "application/x-www-form-urlencoded",
                "text": f"nxt={TOKEN}&q=hello&opaque=Zk9x83Lm2Pq7Rt5Vw1Ab",
            },
        ),
    ]
    conn = _open(tmp_path, monkeypatch, entries)
    code = client_stub(conn, entry_ids=[0, 1])["code"]
    assert TOKEN not in code
    assert "Zk9x83Lm2Pq7Rt5Vw1Ab" not in code
    assert "_hidden(self.resp[0], 'nxt')" in code
    assert "inp['opaque']" in code


def test_stub_authorization_scheme_from_shape(tmp_path, monkeypatch):
    entries = [
        _entry("GET", "/a", headers={"Authorization": f"Bearer {JWT}"}),
        _entry("GET", "/b", headers={"Authorization": "Basic dXNlcjpwYXNzd29yZA=="}),
    ]
    conn = _open(tmp_path, monkeypatch, entries)
    assert _auth_scheme(conn, 0) == "Bearer "
    assert _auth_scheme(conn, 1) == "Basic "


def _login_page(request):
    return httpx.Response(
        200,
        headers={"content-type": "text/html"},
        text='<html><form action="/login"><input type="text" name="user">'
        '<input type="password" name="password"></form> Sign in</html>',
    )


def test_login_gate_class_reported_and_opt_in(tmp_path, monkeypatch):
    conn = _open(tmp_path, monkeypatch, [_entry("GET", "/login", mime="text/html", resp_text="<html/>")])
    res = replay_check(conn, [0], delay_s=0, client=_client(_login_page))
    assert res["halted"]["gate_class"] == "login"
    assert res["halted"]["reason"] == "gate:login"
    res2 = replay_check(conn, [0], delay_s=0, client=_client(_login_page), allow_gates=["login"])
    assert res2["baseline"]["status"] == 200


def test_body_fingerprint_registers_value_carrying_piece(tmp_path, monkeypatch):
    entries = [_entry("GET", "/list", query=[("firstname", "Sally"), ("junk", "z")])]
    conn = _open(tmp_path, monkeypatch, entries)

    def srv(request):
        fn = request.url.params.get("firstname")
        return httpx.Response(200, json=[{"n": 1}] if fn else [{"n": 1}, {"n": 2}, {"n": 3}])

    res = replay_check(conn, [0], delay_s=0, client=_client(srv))
    assert "firstname" in res["required"]["query"]
    assert "junk" in res["optional"]["query"]


def test_captured_vs_baseline_and_sec_group_fold(tmp_path, monkeypatch):
    hdrs = {
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
        "sec-ch-ua": '"X";v="1"',
        "sec-ch-ua-mobile": "?0",
        "X-Requested-With": "XMLHttpRequest",
    }
    conn = _open(tmp_path, monkeypatch, [_entry("GET", "/d", headers=hdrs)])

    res = replay_check(conn, [0], delay_s=0, client=_client(lambda r: httpx.Response(200, json={"ok": True})))
    assert res["baseline_matches_captured"] is True
    for h in ("Sec-Fetch-Mode", "Sec-Fetch-Site", "sec-ch-ua", "sec-ch-ua-mobile"):
        assert h in res["optional"]["headers"]
    assert res["requests_used"] == 3  # baseline + X-Requested-With + one folded group

    res = replay_check(conn, [0], delay_s=0, client=_client(lambda r: httpx.Response(500, text="x")))
    assert res["baseline_matches_captured"] is False
    assert any("differs from the captured" in f for f in res["findings"])


def test_joint_credential_ablation_and_cookie_itemised(tmp_path, monkeypatch):
    hdrs = {"Authorization": "Bearer x", "Cookie": "sid=0123456789abcdef0123456789abcdef; theme=dark"}
    conn = _open(tmp_path, monkeypatch, [_entry("GET", "/me", headers=hdrs)])

    res = replay_check(conn, [0], delay_s=0, client=_client(lambda r: httpx.Response(200, json={})))
    assert "sid" in res["needs_override"]["cookies"]
    assert "Cookie" not in res["needs_override"].get("headers", [])

    def srv(request):
        ok = request.headers.get("authorization") == "auth-ok" or "sid=s1" in request.headers.get("cookie", "")
        return httpx.Response(200, json={"me": 1}) if ok else httpx.Response(401, json={"e": 1})

    ov = {"headers": {"Authorization": "auth-ok", "Cookie": "sid=s1"}}
    res = replay_check(conn, [0], overrides=ov, delay_s=0, client=_client(srv))
    assert res["baseline"]["status"] == 200
    assert "sid" in res["optional"]["cookies"]
    assert "Authorization" in res["optional"]["headers"]
    assert res["required_any_of"] == [["Authorization", "sid"]]


def test_bad_overrides_json_cli(tmp_path, monkeypatch, capsys):
    from hardly import cli

    har = tmp_path / "t.har"
    har.write_text(
        json.dumps({"log": {"version": "1.2", "creator": {"name": "t", "version": "1"}, "entries": [_entry("GET", "/x")]}})
    )
    monkeypatch.setenv("HARDLY_RUNTIME_DIR", str(tmp_path / "cache"))
    with pytest.raises(SystemExit) as exc:
        cli.main(["replay-check", str(har), "0", "--yes", "--overrides-json", str(tmp_path / "o.json")])
    out = capsys.readouterr().out
    assert exc.value.code == 1
    assert "inline JSON" in out
