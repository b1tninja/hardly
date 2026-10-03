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


MINIFIED = (
    'a.save=function(e){return $http.post("/api/Orders/Save",{orderId:e.id,qty:n,'
    '"ship-to":t,note:"hello, world: x"}).then(function(r){return r.data.secretKey})};'
    'fetch("/api/Items/Search",{method:"POST",headers:{"Content-Type":"application/json"},'
    'body:JSON.stringify({term:q,page:1,sortBy:s})}).then(function(r){return {leak:1}});'
    'axios.put("/api/Users/Update",{id:u,email:m}).then(f);'
    '$.ajax({url:"/Grid/Fetch",type:"POST",data:{start:0,length:25},'
    'success:function(d){var z={notAKey:1}}});'
    'var x=new XMLHttpRequest;x.open("POST","/svc/Legacy.ashx");x.setRequestHeader("a","b");'
    'x.send(JSON.stringify({Name:a,Code:b}));'
    'var base="/api/Plain/List";var o={unrelated:1};'
)


def _by_path(routes):
    return {r["path"]: r for r in routes}


def test_body_keys_names_only_and_methods():
    routes = _by_path(extract_js_routes(MINIFIED))
    save = routes["/api/Orders/Save"]
    assert save["method"] == "POST"
    assert save["body_keys"] == ["orderId", "qty", "ship-to", "note"]

    search = routes["/api/Items/Search"]
    assert search["method"] == "POST"
    assert search["body_keys"] == ["term", "page", "sortBy"]  # no header names/callback keys

    assert routes["/api/Users/Update"]["method"] == "PUT"
    assert routes["/api/Users/Update"]["body_keys"] == ["id", "email"]

    grid = routes["/Grid/Fetch"]
    assert grid["method"] == "POST"
    assert grid["body_keys"] == ["start", "length"]

    legacy = routes["/svc/Legacy.ashx"]
    assert legacy["method"] == "POST"
    assert legacy["body_keys"] == ["Name", "Code"]

    assert routes["/api/Plain/List"]["body_keys"] == []  # not in a call


def test_body_keys_never_include_values_and_are_capped():
    keys = ",".join(f"k{i}:v{i}" for i in range(30))
    js = f'$http.post("/api/Big/Post",{{{keys},tok:"VALUE-123"}});'
    (r,) = extract_js_routes(js)
    assert len(r["body_keys"]) == 12
    assert "VALUE-123" not in " ".join(r["body_keys"])
    assert "v1" not in r["body_keys"]


def test_list_js_routes_includes_body_keys(tmp_path, monkeypatch):
    monkeypatch.setenv("HARDLY_CACHE_DIR", str(tmp_path))
    info = sess.open_har(str(FIX), force=True)
    conn = sess.require_conn(info["session_id"])
    routes = q.list_js_routes(conn, host="portal.example.com")["routes"]
    for r in routes:
        assert "body_keys" in r and "method" in r
    posted = [r for r in routes if r["path"] == "/Search/GridResults"]
    assert posted and posted[0]["method"] == "POST"
