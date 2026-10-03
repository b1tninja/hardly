"""Grid framework, envelope and paging-convention detection (synthetic HAR)."""

import json

from hardly import session as sess
from hardly.core.grids import detect_grids


def _entry(i, url, body, ct, *, post=None):
    req = {
        "method": "POST" if post else "GET", "url": url, "httpVersion": "HTTP/1.1",
        "headers": [], "cookies": [], "headersSize": -1, "bodySize": 0,
        "queryString": [],
    }
    if post:
        req["postData"] = {"mimeType": "application/x-www-form-urlencoded", "text": post}
    return {
        "startedDateTime": f"2026-01-01T00:00:{i:02d}.000Z", "time": 5,
        "request": req,
        "response": {
            "status": 200, "statusText": "OK", "httpVersion": "HTTP/1.1",
            "headers": [{"name": "Content-Type", "value": ct}], "cookies": [],
            "redirectURL": "", "headersSize": -1, "bodySize": len(body),
            "content": {"size": len(body), "mimeType": ct, "text": body},
        },
    }


def test_detect_grids(tmp_path, monkeypatch):
    html = (
        '<div class="dataTables_wrapper"><table id="ctl00_GridView1" data-toggle="table" '
        'data-row-id="7"><tr><td><a href="javascript:__doPostBack(\'ctl00$GridView1\',\'Page$2\')">2</a>'
        '</td></tr></table><div class="ag-root"></div></div>'
    )
    entries = [
        _entry(1, "https://app.example.com/list", html, "text/html"),
        _entry(2, "https://app.example.com/api/rows?draw=1&start=0&length=25&order[0][column]=1",
               json.dumps({"draw": 1, "recordsTotal": 90, "recordsFiltered": 90, "data": [["a"]]}),
               "application/json"),
        _entry(3, "https://app.example.com/odata/Items?$top=10&$skip=20&$filter=x",
               json.dumps({"@odata.context": "m", "@odata.count": 5, "value": [{"id": 1}]}),
               "application/json"),
        _entry(4, "https://app.example.com/rest/q?f=json&where=1%3D1&resultOffset=0",
               json.dumps({"objectIdFieldName": "OBJECTID", "features": [{"attributes": {"a": 1}}]}),
               "application/json"),
        _entry(5, "https://app.example.com/api/items", json.dumps(
            {"count": 3, "next": None, "previous": None, "results": [{"id": 1}]}),
            "application/json"),
        _entry(6, "https://app.example.com/grid", json.dumps(
            {"page": 1, "total": 4, "records": 40, "rows": [{"id": 1}]}),
            "application/json", post="_search=false&nd=1&rows=10&page=1&sidx=id&sord=asc"),
    ]
    path = tmp_path / "g.har"
    path.write_text(json.dumps({"log": {"version": "1.2", "creator": {"name": "t", "version": "1"}, "entries": entries}}))
    monkeypatch.setenv("HARDLY_RUNTIME_DIR", str(tmp_path / "cache"))
    info = sess.open_har(str(path), force=True)
    out = detect_grids(sess.require_conn(info["session_id"]))

    grids = {g["name"] for g in out["html_grids"]}
    assert {"datatables", "ag-grid", "aspnet-gridview", "bootstrap-table"} <= grids
    envs = {g["name"] for g in out["json_envelopes"]}
    assert {"datatables-server", "odata-v4", "arcgis-rest", "drf-pagination", "jqgrid"} <= envs
    styles = {s["style"] for s in out["request_param_styles"]}
    assert {"datatables-server", "odata", "arcgis", "jqgrid"} <= styles
    assert out["webforms_pager_commands"] == {"Page$N": 1}
    assert {"data-toggle", "data-row-id"} <= {a["name"] for a in out["data_attributes"]}
    assert '"a"' not in json.dumps(out)  # row data never echoed


def test_grid_signature_fixes_from_live_testing(tmp_path, monkeypatch):
    # JSON served as text/html (DataTables server_processing.php behaviour)
    dt_json = json.dumps({"draw": 1, "recordsTotal": 57, "recordsFiltered": 57, "data": [["x"]]})
    # DevExtreme page: the host name devexpress.com must not count as DevExpress ASPx
    devextreme = '<link rel="canonical" href="https://js.devexpress.com/x"><script>$("#g").dxDataGrid({});</script>'
    # RadGrid: id RadGrid1, pager classes, entity-quoted postback with empty argument
    radgrid = (
        '<div id="ctl00_RadGrid1" class="RadGrid"><table class="rgMasterTable"></table>'
        '<div class="rgPager"></div><a href="javascript:__doPostBack(&#39;ctl00$C$RadGrid1$ctl00$ctl03$ctl01$ctl05&#39;,&#39;&#39;)">2</a>'
        '<a href="javascript:__doPostBack(&#39;ctl00$C$RadGrid1&#39;,&#39;Sort$Name&#39;)">Name</a></div>'
    )
    # Kendo marker placed beyond the stored 64k preview: found via ingest-time signals
    kendo = "<html><body>" + ("<p>filler</p>" * 6000) + '<script>$("#g").kendoGrid({});</script></body></html>'
    entries = [
        _entry(1, "https://app.example.com/dt.php?draw=1&start=0&length=10", dt_json, "text/html"),
        _entry(2, "https://app.example.com/dx", devextreme, "text/html"),
        _entry(3, "https://app.example.com/rad", radgrid, "text/html"),
        _entry(4, "https://app.example.com/kendo", kendo, "text/html"),
        _entry(5, "https://app.example.com/static/jquery.dataTables.min.js", "var a=1", "application/javascript"),
    ]
    path = tmp_path / "g2.har"
    path.write_text(json.dumps({"log": {"version": "1.2", "creator": {"name": "t", "version": "1"}, "entries": entries}}))
    monkeypatch.setenv("HARDLY_RUNTIME_DIR", str(tmp_path / "cache"))
    info = sess.open_har(str(path), force=True)
    out = detect_grids(sess.require_conn(info["session_id"]))

    envs = {g["name"] for g in out["json_envelopes"]}
    assert "datatables-server" in envs
    grids = {g["name"]: g for g in out["html_grids"]}
    assert "devextreme" in grids and "devexpress-aspx" not in grids
    assert "telerik-radgrid" in grids
    assert "kendo-grid" in grids and 3 in grids["kendo-grid"]["entry_ids"]
    assert "datatables" in grids  # via the script URL
    cmds = out["webforms_pager_commands"]
    assert cmds.get("Sort$Name") == 1 and cmds.get("control-id pager (empty argument)") == 1
