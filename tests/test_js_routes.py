"""JS route mining and chronological neighbors."""

from pathlib import Path

from hardly.core.js_routes import extract_js_routes
from hardly.index import query as q
from hardly import session as sess

FIX = Path(__file__).parent / "fixtures" / "sample.har"

SAMPLE_JS = """
function onGridItmClick(e) {
  popWindow({ windowURL: '/Details/', docId: data["TransactionItemId"] });
}
$('.searchGridDiv').load('/Search/PartialGrid', function () {});
var u = '/details/documentdetails/' + id + '/1/1/50';
$.post("/Search/GridResults", {page:1});
var skip = '/Content/Images/logo.png';
"""


def test_extract_js_routes_ranks_portal_paths():
    routes = extract_js_routes(SAMPLE_JS, base_url="https://portal.example.com/Scripts/x.js")
    paths = [r["path"] for r in routes]
    assert "/Details/" in paths or "/Details" in paths
    assert "/Search/PartialGrid" in paths
    assert "/Search/GridResults" in paths
    assert "/details/documentdetails/" in paths
    assert not any(p.endswith(".png") for p in paths)
    assert routes[0]["score"] >= routes[-1]["score"]


def test_list_js_routes_and_around(tmp_path, monkeypatch):
    monkeypatch.setenv("HARDLY_CACHE_DIR", str(tmp_path))
    info = sess.open_har(str(FIX), force=True)
    conn = sess.require_conn(info["session_id"])

    routes = q.list_js_routes(conn, host="portal.example.com")
    assert routes["sources_scanned"] >= 1
    paths = [r["path"] for r in routes["routes"]]
    assert any("Details" in p for p in paths)
    assert any("GridResults" in p for p in paths)

    # Center on the HTML search page; GridResults should follow.
    listed = q.list_forms(conn, host="portal.example.com")
    center_id = listed["entries"][0]["entry_id"]
    around = q.entries_around(conn, center_id, before=2, after=10)
    assert around["center_entry_id"] == center_id
    assert any(e["is_center"] for e in around["entries"])
    assert any("GridResults" in (e["path"] or "") for e in around["entries"])
