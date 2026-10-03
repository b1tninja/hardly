"""HTML data-* attribute interpretation (MDN dataset model)."""

import json

from hardly.core.data_attrs import classify_value, dataset_key, extract_data_attributes, scan_session

HTML = (
    '<table data-toggle="table" data-url="/api/rows?token=SECRET" data-page-size="25">'
    '<tr data-id="42" data-row-key="a1b2c3d4-0000-4000-8000-000000000000"><td data-sort="name">x</td></tr>'
    '<tr data-id="43"><td data-sort="date">y</td></tr></table>'
    '<button data-bs-toggle="modal" data-bs-target="#m" data-controller="hello" '
    'data-hello-name-value="World">go</button>'
    '<div data-config=\'{"apiBase":"/v2","debug":true}\' data-gtm-event="click" '
    'data-email="a@b.co" data-note="Some private free text here"></div>'
)


def test_dataset_key_follows_mdn_rule():
    assert dataset_key("data-date-of-birth") == "dateOfBirth"
    assert dataset_key("data-id") == "id"
    assert dataset_key("data-bs-toggle") == "bsToggle"


def test_value_kinds():
    assert classify_value("") == "empty"
    assert classify_value("TRUE") == "boolean"
    assert classify_value("42") == "integer"
    assert classify_value("1.5") == "number"
    assert classify_value("a1b2c3d4-0000-4000-8000-000000000000") == "uuid"
    assert classify_value('{"a":1}') == "json"
    assert classify_value("{broken") == "text"
    assert classify_value("/api/x") == "url"
    assert classify_value("2026-01-02T03:04") == "datetime"
    assert classify_value("x" * 40) == "opaque_token"


def test_extract_summary_and_privacy():
    out = extract_data_attributes(HTML, base_url="https://x.example/p")
    attrs = {a["name"]: a for a in out["attributes"]}
    assert attrs["data-page-size"]["dataset_key"] == "pageSize"
    assert attrs["data-id"]["count"] == 2 and attrs["data-id"]["value_kinds"] == {"integer": 2}
    assert attrs["data-sort"]["values"] == ["name", "date"]
    assert out["endpoints"] == [
        {"attr": "data-url", "tag": "table", "url": "https://x.example/api/rows?token="}
    ]
    assert out["embedded_json"][0]["keys"] == ["apiBase", "debug"]
    fw = {f["id"]: f["attributes"] for f in out["frameworks"]}
    assert "data-bs-toggle" in fw["bootstrap"]
    assert "data-controller" in fw["stimulus"] and "data-bs-target" not in fw["stimulus"]
    assert "data-gtm-event" in fw["tracking"]
    assert {"attr": "data-id", "elements": 2} in out["ids"]
    blob = json.dumps(out)
    assert "SECRET" not in blob and "Some private free text" not in blob and "a@b.co" not in blob


def test_no_data_attributes():
    assert extract_data_attributes("<p>hello</p>")["elements"] == 0
    assert extract_data_attributes("")["attributes"] == []


def test_scan_session_over_har(tmp_path, monkeypatch):
    from hardly import session as sess
    from hardly.core.data_attrs import scan_session

    body = HTML
    entry = {
        "startedDateTime": "2026-01-01T00:00:01.000Z", "time": 5,
        "request": {"method": "GET", "url": "https://app.example.com/list", "httpVersion": "HTTP/1.1",
                    "headers": [], "queryString": [], "cookies": [], "headersSize": -1, "bodySize": 0},
        "response": {"status": 200, "statusText": "OK", "httpVersion": "HTTP/1.1",
                     "headers": [{"name": "Content-Type", "value": "text/html"}], "cookies": [],
                     "redirectURL": "", "headersSize": -1, "bodySize": len(body),
                     "content": {"size": len(body), "mimeType": "text/html", "text": body}},
    }
    path = tmp_path / "d.har"
    path.write_text(json.dumps({"log": {"version": "1.2", "creator": {"name": "t", "version": "1"}, "entries": [entry]}}))
    monkeypatch.setenv("HARDLY_RUNTIME_DIR", str(tmp_path / "cache"))
    info = sess.open_har(str(path), force=True)
    out = scan_session(sess.require_conn(info["session_id"]))
    assert out["pages_with_data_attributes"] == 1
    assert out["endpoints"][0]["url"] == "https://app.example.com/api/rows?token="
    assert out["endpoints"][0]["entry_id"] is not None
    assert any(a["name"] == "data-id" for a in out["attributes"])
    assert "Some private free text" not in json.dumps(out)


def test_single_sitekey_gives_captcha_hint_without_echoing_value():
    out = extract_data_attributes('<div class="w" data-sitekey="PUBLICKEY1234567890abcdef"></div>')
    fw = [f for f in out["frameworks"] if f["id"] == "captcha-widget"]
    assert fw and "person" in fw[0]["hint"]
    assert "PUBLICKEY" not in json.dumps(out["frameworks"])


def test_scan_session_warns_on_truncated_html_preview():
    import sqlite3

    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    c.executescript(
        "CREATE TABLE entries (entry_id INTEGER, scheme TEXT, host TEXT, path TEXT);"
        "CREATE TABLE bodies (entry_id INTEGER, side TEXT, content_type TEXT, preview_text TEXT, size INTEGER);"
    )
    body = '<div data-x="1"></div>'
    c.execute("INSERT INTO entries VALUES (1,'https','a.test','/p')")
    c.execute("INSERT INTO bodies VALUES (1,'response','text/html',?,?)", (body, 500000))
    out = scan_session(c)
    assert out["truncated_previews"] == 1 and "truncated" in out["warnings"][0]
