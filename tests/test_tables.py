"""HTML table extraction: headers + masked first row, never cell values."""

import json

from hardly import session as sess
from hardly.core.tables import column_kind, extract_tables, mask_value, scan_session

THEAD = """
<table><caption>Results list</caption>
<thead><tr><th>Ref</th><th>Filed</th><th colspan="2">Amount</th></tr></thead>
<tbody>
<tr><td>AB-1234</td><td>01/02/2020</td><td>$1,200.00</td><td>x</td></tr>
<tr><td>CD-77</td><td>12/31/2019</td><td>$5.50</td><td></td></tr>
</tbody></table>
"""

GRIDVIEW = """
<table id="ctl00_Main_GridView1" class="grid" cellspacing="0">
<tr><th scope="col">Name</th><th scope="col">Count</th></tr>
<tr><td>Zebra Quux</td><td>12</td></tr>
<tr><td>Other Name</td><td>1,034</td></tr>
<tr><td colspan="2"><table><tr><td><span>1</span></td>
<td><a href="javascript:__doPostBack('ctl00$Main$GridView1','Page$2')">2</a></td>
<td><a href="javascript:__doPostBack('ctl00$Main$GridView1','Page$3')">3</a></td>
</tr></table></td></tr>
</table>
"""

BOLD_HEADER = """
<table><tr><td><b>Col One</b></td><td><strong>Col Two</strong></td></tr>
<tr><td>alpha</td><td>7</td></tr></table>
"""

LABEL_VALUE = """
<table>
<tr><th>Holder Name</th><td>Secret Person</td></tr>
<tr><th>Item</th><td>000-111</td></tr>
<tr><th>Status</th><td>Active</td></tr>
</table>
"""

NESTED = """
<table class="layout"><tr><td>
  <table><tr><th>Left</th><th>Right</th></tr><tr><td>1</td><td>2</td></tr></table>
</td><td>sidebar text</td></tr></table>
"""


def test_mask_value_shapes():
    assert mask_value("AB-1234") == "AA-9999"
    assert mask_value("Hello World 5") == "Aaaaa Aaaaa 9"
    assert mask_value("x" * 40) == "a" * 24 + "…"


def test_column_kinds():
    assert column_kind(["1", "22", "1,000"]) == "integer"
    assert column_kind(["01/02/2020", "2020-01-05"]) == "date"
    assert column_kind(["$5.00", "$1,200.00", ""]) == "money"
    assert column_kind(["", " "]) == "empty"
    assert column_kind(["abc", "12"]) == "text"


def test_thead_table_with_colspan():
    (t,) = extract_tables(THEAD)
    assert t["kind"] == "data"
    assert t["caption"] == "Results list"
    assert t["headers"] == ["Ref", "Filed", "Amount", "Amount"]
    assert t["column_count"] == 4
    assert t["row_count"] == 2
    assert t["first_row_masked"] == ["AA-9999", "99/99/9999", "$9,999.99", "a"]
    assert t["column_kinds"][:3] == ["text", "date", "money"]
    assert "AB-1234" not in json.dumps(t)


def test_gridview_with_pager():
    tables = extract_tables(GRIDVIEW)
    assert len(tables) == 1  # nested pager table is not a data table
    t = tables[0]
    assert t["headers"] == ["Name", "Count"]
    assert t["row_count"] == 2  # pager row excluded
    assert t["column_kinds"] == ["text", "integer"]
    assert t["has_pager_hint"] is True
    assert "Zebra" not in json.dumps(t)


def test_bold_first_row_headers():
    (t,) = extract_tables(BOLD_HEADER)
    assert t["headers"] == ["Col One", "Col Two"]
    assert t["row_count"] == 1
    assert t["first_row_masked"] == ["aaaaa", "9"]


def test_label_value_table_reports_labels_only():
    (t,) = extract_tables(LABEL_VALUE)
    assert t["kind"] == "label_value"
    assert t["labels"] == ["Holder Name", "Item", "Status"]
    blob = json.dumps(t)
    assert "Secret Person" not in blob and "000-111" not in blob


def test_nested_layout_table():
    tables = extract_tables(NESTED)
    assert [t["headers"] for t in tables] == [["Left", "Right"]]


def test_not_a_table_and_max_tables():
    assert extract_tables("<p>hi</p>") == []
    assert extract_tables("") == []
    assert len(extract_tables(THEAD * 5, max_tables=2)) == 2


def test_scan_session(tmp_path, monkeypatch):
    def entry(i, url, body):
        return {
            "startedDateTime": f"2026-01-01T00:00:0{i}.000Z", "time": 1,
            "request": {"method": "GET", "url": url, "httpVersion": "HTTP/1.1",
                        "headers": [], "cookies": [], "headersSize": -1,
                        "bodySize": 0, "queryString": []},
            "response": {"status": 200, "statusText": "OK", "httpVersion": "HTTP/1.1",
                         "headers": [], "cookies": [], "redirectURL": "",
                         "headersSize": -1, "bodySize": len(body),
                         "content": {"size": len(body), "mimeType": "text/html", "text": body}},
        }

    har = {"log": {"version": "1.2", "creator": {"name": "t", "version": "1"},
                   "entries": [entry(1, "https://t.example.com/a", "<html>" + GRIDVIEW + "</html>"),
                               entry(2, "https://t.example.com/b", "<html>" + LABEL_VALUE + "</html>")]}}
    p = tmp_path / "t.har"
    p.write_text(json.dumps(har))
    monkeypatch.setenv("HARDLY_RUNTIME_DIR", str(tmp_path / "cache"))
    info = sess.open_har(str(p), force=True)
    conn = sess.require_conn(info["session_id"])

    out = scan_session(conn, host="t.example.com")
    assert out["table_count"] == 2
    assert {t["entry_id"] for t in out["tables"]} == {0, 1}
    assert scan_session(conn, entry_id=1)["tables"][0]["kind"] == "label_value"
    blob = json.dumps(out)
    for secret in ("Zebra", "Secret Person", "000-111"):
        assert secret not in blob
