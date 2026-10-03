"""HTML form / input inventory for portal reverse-engineering."""

from pathlib import Path

from hardly.core.html_forms import extract_html_structure
from hardly.core.redact import REDACTED
from hardly.index import query as q
from hardly import session as sess

FIX = Path(__file__).parent / "fixtures" / "sample.har"

SAMPLE = """
<html><body>
<form id="search" method="post" action="/Search/SearchTypePreName"
      onsubmit="return validateSearch(this);">
  <input type="hidden" name="NameList" value="" />
  <input type="text" name="SearchOnName" id="SearchOnName" value="EXAMPLE" />
  <input type="password" name="password" value="s3cret" />
  <input type="checkbox" name="Both" value="Both" checked />
  <select name="DateRangeList">
    <option value="Today" selected>Today</option>
    <option value="Custom">Custom</option>
  </select>
  <button type="submit">Done</button>
</form>
<a href="/search/SearchTypeDocType">Doc Type</a>
<a href="javascript:OpenDetailsPopup('DOC1');">Open</a>
<tr class="k-master-row" onclick="onGridItmClick(event)"
    data-documentid="DOC1111S2222" data-href="/Web/document/DOC1111S2222">
  <td>x</td>
</tr>
<input type="text" name="field_Loose" value="out" />
</body></html>
"""


def test_extract_forms_fields_and_signals():
    out = extract_html_structure(SAMPLE, base_url="https://portal.example.com/search")
    assert out["form_count"] == 1
    form = out["forms"][0]
    assert form["action"] == "https://portal.example.com/Search/SearchTypePreName"
    assert form["method"] == "POST"
    assert "validateSearch" in (form.get("onsubmit_functions") or [])
    assert form.get("xpath") == '//*[@id="search"]'
    names = form["field_names"]
    assert "SearchOnName" in names
    assert "password" in names
    assert "DateRangeList" in names
    by_name = {f["name"]: f for f in form["fields"]}
    assert by_name["password"]["value"] == REDACTED
    assert by_name["SearchOnName"]["value"] == "EXAMPLE"
    assert by_name["SearchOnName"].get("xpath") == '//*[@id="SearchOnName"]'
    assert by_name["Both"].get("checked") is True
    assert by_name["DateRangeList"]["options"][0]["selected"] is True
    assert "data-documentid" in out["signals"]
    assert out["signals"]["data-documentid"]["samples"]
    assert any(f["name"] == "field_Loose" for f in out["loose_inputs"])
    assert out["link_count"] >= 1
    assert any("SearchTypeDocType" in (link.get("href") or "") for link in out["links"])
    assert any(link.get("xpath") for link in out["links"])
    assert out["handler_count"] >= 2
    assert any(h.get("xpath") for h in out["handlers"])
    fnames = {f["name"] for f in out["handler_functions"]}
    assert "onGridItmClick" in fnames
    assert "OpenDetailsPopup" in fnames


def test_extract_labeled_fields_detail_page():
    html = """
    <div class="docDetailRow">
      <div class="detailLabel">Record Date:</div>
      <div class="formInput">10/1/2026</div>
    </div>
    <div class="docDetailRow">
      <div class="detailLabel">Grantor:</div>
      <div class="listDocDetails"><span>EXAMPLE PARTY</span></div>
    </div>
    <table><tr><th>Doc Type</th><td>003 - RECONVEYANCE</td></tr></table>
    """
    out = extract_html_structure(html)
    labels = {row["label"]: row["value"] for row in out["labels"]}
    assert labels.get("Record Date") == "10/1/2026"
    assert "EXAMPLE PARTY" in (labels.get("Grantor") or "")
    assert "RECONVEYANCE" in (labels.get("Doc Type") or "")
    assert out["label_count"] >= 3


def test_extract_labeled_fields_mptsweb_and_kofile():
    mpts = """
    <table>
      <tr><td class="font-weight-bolder">Assessment Number</td>
          <td>328-060-025-000</td></tr>
      <tr><td class="font-weight-bolder">Current Document Number</td>
          <td>2023R0014772</td></tr>
      <tr><td class="font-weight-bolder">Bedrooms</td><td>4</td></tr>
    </table>
    """
    out = extract_html_structure(mpts)
    labels = {row["label"]: row["value"] for row in out["labels"]}
    assert labels.get("Assessment Number") == "328-060-025-000"
    assert labels.get("Current Document Number") == "2023R0014772"
    assert labels.get("Bedrooms") == "4"
    assert all(row["source"] == "td/bolder" for row in out["labels"])

    kofile = """
    <table>
    <tr>
      <td align="right"><span id="fc1span" class="base">Document Number:</span></td>
      <td width="50%" style="padding-left: 5px">2023-0014772</td>
    </tr>
    <tr>
      <td align="right"><span id="fc2span" class="base">Document Type:</span></td>
      <td>DEED</td>
    </tr>
    </table>
    """
    out = extract_html_structure(kofile)
    labels = {row["label"]: row["value"] for row in out["labels"]}
    assert labels.get("Document Number") == "2023-0014772"
    assert labels.get("Document Type") == "DEED"
    assert all(row["source"] == "td/span.base" for row in out["labels"])


def test_forms_query_on_sample_har(tmp_path, monkeypatch):
    monkeypatch.setenv("HARDLY_CACHE_DIR", str(tmp_path))
    info = sess.open_har(str(FIX), force=True)
    conn = sess.require_conn(info["session_id"])
    listed = q.list_forms(conn, host="portal.example.com")
    assert listed["count"] >= 1
    entry_id = listed["entries"][0]["entry_id"]
    brief = listed["entries"][0]
    assert brief.get("handler_count", 0) >= 1
    assert any(f["name"] == "onGridItmClick" for f in brief.get("handler_functions") or [])
    detail = q.forms_for_entry(conn, entry_id)
    assert detail["form_count"] == 1
    assert "field_BothNamesID" in detail["forms"][0]["field_names"]
    assert detail["signals"].get("data-documentid")
    assert detail["links"]
    assert detail["handlers"]
    assert detail["forms"][0].get("xpath")


def test_named_token_pair_anti_forgery():
    html = """<form action="/login.action" method="post">
    <input type="hidden" name="struts.token.name" value="token">
    <input type="hidden" name="token" value="ABCDEF123456">
    <input type="text" name="username"><input type="submit" value="Go"></form>
    <form action="/other"><input type="hidden" name="a" value="b">
    <input type="hidden" name="b" value="c"></form>"""
    out = extract_html_structure(html)
    first, second = out["forms"]
    assert first["anti_forgery"] == {
        "scheme": "named_token",
        "name_field": "struts.token.name",
        "token_field": "token",
    }
    assert "anti_forgery" not in second  # indirection without "token" is not flagged
