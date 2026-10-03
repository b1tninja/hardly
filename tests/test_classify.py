"""Response content classification."""

from pathlib import Path

from hardly import session as sess
from hardly.core.classify import classify_response, summarize_content
from hardly.index import query as q

FIX = Path(__file__).parent / "fixtures" / "sample.har"


def test_classify_json_flavors():
    assert classify_response(mime="application/json", body='{"a":1}')["kind"] == "json"
    jsonl = classify_response(
        mime="application/x-ndjson",
        body='{"id":1}\n{"id":2}\n',
    )
    assert jsonl["kind"] == "jsonl"
    assert jsonl["line_count"] == 2
    jsonp = classify_response(
        mime="application/javascript",
        body='searchDone({"rows":[1]});',
    )
    assert jsonp["kind"] == "jsonp"
    assert jsonp["callback"] == "searchDone"


def test_classify_csv_and_table():
    csv = classify_response(
        mime="text/csv",
        path="/export.csv",
        body="a,b\n1,2\n",
    )
    assert csv["kind"] == "csv"
    assert "a" in (csv.get("columns") or [])
    html = classify_response(
        mime="text/html",
        body=(
            '<table class="dataTable"><tr><th>Doc</th><th>Name</th></tr>'
            '<tr data-documentid="1"><td>x</td><td>y</td></tr></table>'
        ),
    )
    assert html["kind"] == "html_table"
    assert "Doc" in (html.get("table_headers") or [])
    assert any("data-documentid" in h or h == "attr:data-documentid" for h in html.get("hints") or [])


def test_classify_media_docs():
    assert classify_response(mime="application/pdf", path="/x.pdf", size=100)["kind"] == "pdf"
    assert classify_response(mime="image/png", path="/x.png", size=10)["kind"] == "image"
    assert classify_response(mime="text/css", path="/a.css", body="body{}")["kind"] == "css"
    doc = classify_response(
        mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        path="/a.docx",
        size=500,
    )
    assert doc["kind"] == "document"


def test_sample_har_content_summary(tmp_path, monkeypatch):
    monkeypatch.setenv("HARDLY_RUNTIME_DIR", str(tmp_path))
    info = sess.open_har(str(FIX), force=True)
    conn = sess.require_conn(info["session_id"])
    summary = summarize_content(conn, exclude_noise=False, limit=200)
    kinds = summary["by_kind"]
    assert kinds.get("csv", 0) >= 1
    assert kinds.get("jsonl", 0) >= 1
    assert kinds.get("jsonp", 0) >= 1
    assert kinds.get("html_table", 0) >= 1
    assert kinds.get("pdf", 0) >= 1
    assert kinds.get("image", 0) >= 1

    # Entry content field
    rows = conn.execute(
        "SELECT entry_id FROM entries WHERE path LIKE '%.csv' LIMIT 1"
    ).fetchone()
    entry = q.get_entry(conn, rows["entry_id"])
    assert entry["content"]["kind"] == "csv"


def test_search_by_content_kind(tmp_path, monkeypatch):
    monkeypatch.setenv("HARDLY_RUNTIME_DIR", str(tmp_path))
    info = sess.open_har(str(FIX), force=True)
    conn = sess.require_conn(info["session_id"])
    csv_hits = q.search_entries(conn, content_kind="csv", exclude_noise=False)
    assert csv_hits["total"] >= 1
    assert all(e["content_kind"] == "csv" for e in csv_hits["entries"])
    tables = q.search_entries(conn, content_kind="table", exclude_noise=False)
    assert tables["total"] >= 1
    assert all(e["content_kind"] == "html_table" for e in tables["entries"])


def test_pdf_magic_bytes():
    hit = classify_response(
        mime="application/octet-stream",
        path="/download",
        body="%PDF-1.4 binary-looking",
        size=99,
    )
    assert hit["kind"] == "pdf"


def test_stats_includes_content_kinds(tmp_path, monkeypatch):
    from hardly.core.stats import traffic_stats

    monkeypatch.setenv("HARDLY_RUNTIME_DIR", str(tmp_path))
    info = sess.open_har(str(FIX), force=True)
    conn = sess.require_conn(info["session_id"])
    stats = traffic_stats(conn, exclude_noise=False)
    assert isinstance(stats.get("content_kinds"), dict)
    assert stats["content_kinds"]
