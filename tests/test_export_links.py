"""Built-in export endpoint detection (synthetic HAR)."""

import json

from hardly import session as sess
from hardly.core.export_links import _inspect, export_links
from hardly.core.grids import detect_grids


def _entry(i, method, url, body, ct):
    return {
        "startedDateTime": f"2026-01-01T00:00:{i:02d}.000Z", "time": 1,
        "request": {"method": method, "url": url, "httpVersion": "HTTP/1.1",
                    "headers": [], "cookies": [], "headersSize": -1, "bodySize": 0,
                    "queryString": []},
        "response": {"status": 200, "statusText": "OK", "httpVersion": "HTTP/1.1",
                     "headers": [{"name": "Content-Type", "value": ct}], "cookies": [],
                     "redirectURL": "", "headersSize": -1, "bodySize": len(body),
                     "content": {"size": len(body), "mimeType": ct, "text": body}},
    }


def test_inspect_rules():
    assert _inspect("/List/ExportCsv?id=5&q=secret") == ("/List/ExportCsv", [])
    assert _inspect("/data?format=xlsx&id=1") == ("/data", ["xlsx"])
    assert _inspect("/files/rows.csv")[1] == ["csv"]
    assert _inspect("/api/items?type=pdf")[1] == ["pdf"]
    assert _inspect("/api/items?type=person") is None
    assert _inspect("/report")  is None  # bare generic word, no format
    assert _inspect("/report?output=csv")[1] == ["csv"]
    assert _inspect("javascript:void(0)") is None
    assert _inspect("/search/results") is None


def test_export_links_session_and_grids(tmp_path, monkeypatch):
    page = (
        '<table id="GridView1"><tr><th>A</th></tr></table>'
        '<a href="/Records/Download?format=csv&id=abc123">Export</a>'
        '<form method="post" action="/Records/ExportExcel"><input name="x"></form>'
        '<a href="/about">About</a>'
    )
    entries = [
        _entry(1, "GET", "https://app.example.com/Records", page, "text/html"),
        _entry(2, "GET", "https://app.example.com/api/rows?output=json&page=1", "{}", "application/json"),
        _entry(3, "GET", "https://app.example.com/dl/sheet.xlsx", "x", "application/octet-stream"),
    ]
    p = tmp_path / "e.har"
    p.write_text(json.dumps({"log": {"version": "1.2", "creator": {"name": "t", "version": "1"}, "entries": entries}}))
    monkeypatch.setenv("HARDLY_CACHE_DIR", str(tmp_path / "cache"))
    info = sess.open_har(str(p), force=True)
    conn = sess.require_conn(info["session_id"])

    links = export_links(conn)
    by_path = {(x["path"], x["source"]): x for x in links}
    assert by_path[("/Records/Download", "link")]["formats"] == ["csv"]
    assert by_path[("/Records/ExportExcel", "link")]["method"] == "POST"
    assert by_path[("/dl/sheet.xlsx", "request")]["formats"] == ["xlsx"]
    assert ("/about", "link") not in by_path
    assert all({"path", "formats", "method", "entry_id", "source"} <= set(x) for x in links)
    assert "abc123" not in json.dumps(links)  # query values dropped

    out = detect_grids(conn)
    assert out["export_links"]
    assert "paging" in out["export_note"]
