"""Offline HTML/XML outlines."""

from pathlib import Path

from hardly import session as sess
from hardly.core.outline import outline_entry, outline_markup
from hardly.index import query as q

FIX = Path(__file__).parent / "fixtures" / "sample.har"

HTML = """
<!doctype html>
<html><body>
<main>
  <h1>Search</h1>
  <form method="post" action="/Search/GridResults">
    <label>Name</label>
    <input type="text" name="field_BothNamesID" />
    <button type="submit">Go</button>
  </form>
  <table class="dataTable">
    <thead><tr><th>Doc #</th><th>Party</th></tr></thead>
    <tbody>
      <tr data-documentid="99"><td>2024-1</td><td>SMITH</td></tr>
      <tr><td>2024-2</td><td>JONES</td></tr>
    </tbody>
  </table>
  <nav aria-label="Pager"><a href="/p/2">Next</a></nav>
</main>
</body></html>
"""

XML = """<?xml version="1.0"?>
<response>
  <status>ok</status>
  <items>
    <item id="1"><name>Alpha</name></item>
    <item id="2"><name>Beta</name></item>
  </items>
</response>
"""


def test_outline_html_markdown_and_aria():
    out = outline_markup(HTML, format="all", max_depth=10)
    assert out["markup_kind"] == "html"
    md = out["markdown"]
    assert "# Search" in md or "## Search" in md or "Search" in md
    assert "Doc #" in md and "SMITH" in md
    assert "Form POST" in md or "form" in md.lower()
    tree = "\n".join(out["tree"])
    assert "table" in tree and "form" in tree
    assert "heading" in out["aria"] or "form" in out["aria"]


def test_outline_xml():
    out = outline_markup(XML, mime="application/xml", format="tree")
    assert out["markup_kind"] == "xml"
    joined = "\n".join(out["tree"])
    assert "response" in joined and "item" in joined


def test_outline_entry_from_sample(tmp_path, monkeypatch):
    monkeypatch.setenv("HARDLY_CACHE_DIR", str(tmp_path))
    info = sess.open_har(str(FIX), force=True)
    conn = sess.require_conn(info["session_id"])
    row = conn.execute(
        "SELECT entry_id FROM entries WHERE path LIKE '%/search/results%' LIMIT 1"
    ).fetchone()
    assert row
    out = outline_entry(conn, row["entry_id"], format="markdown")
    assert "error" not in out
    assert "Doc" in out["markdown"] or "table" in out["markdown"].lower()


def test_get_entry_still_works_with_html_table(tmp_path, monkeypatch):
    monkeypatch.setenv("HARDLY_CACHE_DIR", str(tmp_path))
    info = sess.open_har(str(FIX), force=True)
    conn = sess.require_conn(info["session_id"])
    row = conn.execute(
        "SELECT entry_id FROM entries WHERE path LIKE '%/search/results%' LIMIT 1"
    ).fetchone()
    entry = q.get_entry(conn, row["entry_id"])
    assert entry["content"]["kind"] == "html_table"
