"""Base64 text bodies are decoded; body shapes no longer fire on whole documents."""

import base64
import json

from hardly import session as sess
from hardly.core.redact import classify_value_shape


def _entry(i, url, body, ct, *, encoding=None):
    content = {"size": len(body), "mimeType": ct, "text": body}
    if encoding:
        content["encoding"] = encoding
    return {
        "startedDateTime": f"2026-01-01T00:00:0{i}.000Z", "time": 5,
        "request": {"method": "GET", "url": url, "httpVersion": "HTTP/1.1", "headers": [],
                    "queryString": [], "cookies": [], "headersSize": -1, "bodySize": 0},
        "response": {"status": 200, "statusText": "OK", "httpVersion": "HTTP/1.1",
                     "headers": [{"name": "Content-Type", "value": ct},
                                 {"name": "Referrer-Policy", "value": "strict-origin-when-cross-origin"}],
                     "cookies": [], "redirectURL": "", "headersSize": -1, "bodySize": len(body),
                     "content": content},
    }


def _open(tmp_path, monkeypatch, entries):
    path = tmp_path / "b.har"
    path.write_text(json.dumps({"log": {"version": "1.2", "creator": {"name": "t", "version": "1"}, "entries": entries}}))
    monkeypatch.setenv("HARDLY_RUNTIME_DIR", str(tmp_path / "cache"))
    info = sess.open_har(str(path), force=True)
    return sess.require_conn(info["session_id"])


def test_base64_json_body_is_decoded(tmp_path, monkeypatch):
    payload = json.dumps({"@odata.context": "m", "@odata.count": 2, "value": [{"id": 1}]})
    b64 = base64.b64encode(payload.encode()).decode()
    conn = _open(tmp_path, monkeypatch, [
        _entry(1, "https://api.example.com/odata/People?$top=2", b64, "application/json; charset=utf-8", encoding="base64"),
        _entry(2, "https://api.example.com/logo.png", base64.b64encode(b"\x89PNG\r\n").decode(), "image/png", encoding="base64"),
    ])
    rows = {r["entry_id"]: r["preview_text"] for r in conn.execute(
        "SELECT entry_id, preview_text FROM bodies WHERE side='response'")}
    assert "@odata.count" in rows[0] or "@odata.count" in rows[1]
    assert any(v and v.startswith("(binary base64") for v in rows.values())
    from hardly.core.grids import detect_grids

    envs = {g["name"] for g in detect_grids(conn)["json_envelopes"]}
    assert "odata-v4" in envs


def test_body_shapes_only_for_token_values(tmp_path, monkeypatch):
    html = "<html><body><a href='/assets/bundle-8f3a9c1d2b7e4a6f0c5d9e8b7a6f5e4d3c2b1a09.js'>x</a></body></html>"
    login = json.dumps({"access_token": "Zk9vQmFyQmF6S2V5MTIzNDU2Nzg5MEFCQ0Q=", "name": "A very long display name for the user"})
    conn = _open(tmp_path, monkeypatch, [
        _entry(1, "https://app.example.com/", html, "text/html"),
        _entry(2, "https://app.example.com/login", login, "application/json"),
    ])
    shapes = [(r["entry_id"], r["where_kind"], r["name"], r["shape"]) for r in conn.execute(
        "SELECT entry_id, where_kind, name, shape FROM value_shapes WHERE where_kind='body'")]
    assert all(s[0] != 0 for s in shapes), shapes  # the HTML page contributes nothing
    assert any(s[2] == "access_token" and s[3] == "base64" for s in shapes), shapes
    assert not any(s[2] == "name" for s in shapes)
    header_shapes = [r["shape"] for r in conn.execute(
        "SELECT shape FROM value_shapes WHERE where_kind='header' AND name='Referrer-Policy'")]
    assert header_shapes == []


def test_classify_value_shape_still_finds_tokens():
    assert classify_value_shape("Zk9vQmFyQmF6S2V5MTIzNDU2Nzg5MEFCQ0Q=") == "base64"
    assert classify_value_shape("z" * 40) is None  # a plain word run is not a token
    assert classify_value_shape("strict-origin-when-cross-origin") is None
    assert classify_value_shape("0123456789abcdef0123456789abcdef") == "hex"
