"""Session reopen, stats, header search, WebForms markers."""

from pathlib import Path

from hardly import session as sess
from hardly.core.html_forms import detect_webforms, extract_html_structure
from hardly.core.stats import traffic_stats
from hardly.index import query as q

FIX = Path(__file__).parent / "fixtures" / "sample.har"


def test_reopen_after_close(tmp_path, monkeypatch):
    monkeypatch.setenv("HARDLY_CACHE_DIR", str(tmp_path))
    info = sess.open_har(str(FIX), force=True)
    sid = info["session_id"]
    sess.close_session(sid)
    assert sess.get_conn(sid) is None
    # require_conn auto-reopens
    conn = sess.require_conn(sid)
    assert conn is not None
    summary = q.summary(conn)
    assert summary["entries"] >= 10
    # explicit reopen is idempotent
    again = sess.reopen_session(sid)
    assert again["session_id"] == sid
    assert "error" not in again


def test_search_header_name(tmp_path, monkeypatch):
    monkeypatch.setenv("HARDLY_CACHE_DIR", str(tmp_path))
    info = sess.open_har(str(FIX), force=True)
    conn = sess.require_conn(info["session_id"])
    result = q.search_entries(
        conn, host="portal.example.com", header_name="set-cookie"
    )
    assert result["total"] >= 1


def test_stats(tmp_path, monkeypatch):
    monkeypatch.setenv("HARDLY_CACHE_DIR", str(tmp_path))
    info = sess.open_har(str(FIX), force=True)
    conn = sess.require_conn(info["session_id"])
    result = traffic_stats(conn, host="portal.example.com")
    assert result["status_classes"]["2xx"] >= 1
    assert result["mimes"]


def test_webforms_dopostback():
    html = """
    <form id="aspnetForm">
      <input type="hidden" name="__VIEWSTATE" value="x" />
      <input type="hidden" name="__EVENTVALIDATION" value="y" />
      <a href="javascript:__doPostBack('ctl00$btn','arg1')">Go</a>
    </form>
    """
    wf = detect_webforms(html)
    assert wf["aspnet"] is True
    assert "__VIEWSTATE" in wf["hidden_fields"]
    assert wf["dopostback"][0]["target"] == "ctl00$btn"
    out = extract_html_structure(html)
    assert out["webforms"]["aspnet"] is True
