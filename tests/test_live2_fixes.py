"""Fixes from the second round of live testing (ArcGIS group layers, PII tokens,
route sample leaks, header-only tables, export false positives, bare data envelope)."""

import json

import httpx

from hardly.core import arcgis
from hardly.core.js_routes import extract_js_routes
from hardly.core.tables import extract_tables


def _explore(handler):
    calls = []

    def wrapped(req):
        calls.append(req)
        return handler(req)

    client = httpx.Client(transport=httpx.MockTransport(wrapped))
    return arcgis.explore("https://h/a/MapServer", confirm=True, client=client, delay=0), calls


def test_group_layers_do_not_waste_the_cap_or_the_sample():
    def handler(req):
        path = req.url.path
        if path.endswith("/MapServer"):
            groups = [{"id": 0, "name": "G0", "subLayerIds": [2, 3]}, {"id": 1, "name": "G1", "subLayerIds": [4]}]
            leaves = [{"id": i, "name": f"L{i}"} for i in range(2, 9)]
            return httpx.Response(200, json={"layers": groups + leaves})
        lid = int(path.rsplit("/", 1)[-1]) if path.rsplit("/", 1)[-1].isdigit() else None
        if path.endswith("/query"):
            return httpx.Response(200, json={"fields": [{"name": "OBJECTID"}], "features": [{"attributes": {"OBJECTID": 7}}]})
        if lid in (0, 1):
            return httpx.Response(200, json={"id": lid, "name": "group", "type": "Group Layer", "subLayerIds": [2], "capabilities": "Map,Query", "fields": []})
        return httpx.Response(200, json={"id": lid, "name": f"L{lid}", "capabilities": "Map,Query", "fields": [{"name": "OBJECTID", "type": "esriFieldTypeOID"}]})

    r, calls = _explore(handler)
    fetched = [c.url.path for c in calls]
    assert not any(p.endswith("/MapServer/0") or p.endswith("/MapServer/1") for p in fetched)  # groups never fetched
    assert all(layer["id"] >= 2 for layer in r["layers"])
    assert "group layer" in r["note"] and "cap" in r["note"]
    assert r["sample"]["layer_url"].endswith("/2")                       # sample came from a leaf
    assert "paging_note" not in r["sample"] and "exceededTransferLimit" not in r["sample"]
    assert r["caps"]["layer_docs"] == 5


def test_group_layer_is_not_queryable():
    parsed = arcgis.parse_layer({"id": 0, "type": "Group Layer", "subLayerIds": [1], "capabilities": "Map,Query"})
    assert parsed["group_layer"] is True and parsed["queryable"] is False


def test_personal_data_flags_use_tokens_not_substrings():
    flag = lambda n: "personal_data_like" in arcgis.flag_field(n, "esriFieldTypeString")
    for yes in ("OWNER", "owner_name", "OwnerName", "PHONE", "email", "SITUS_ADDRESS", "CREATED_USER", "last_edited_user", "FIRST_NAME", "dob"):
        assert flag(yes), yes
    for no in ("CITY_NAME", "STATE_NAME", "NAME", "OWNER_OCC", "county_name", "ADDRESS_TYPE_ID_X" if False else "SHAPE_Length"):
        assert not flag(no), no


def test_explore_error_message_is_not_just_json():
    def handler(req):
        if req.url.path.endswith("/MapServer"):
            return httpx.Response(200, json={"layers": [{"id": 99, "name": "x"}]})
        return httpx.Response(200, json={"error": {"code": 500, "message": "json"}})

    r, _ = _explore(handler)
    stop = r.get("stop") or r.get("sample_stop") or {}
    assert "ArcGIS error 500" in json.dumps(r)


def test_route_samples_never_contain_payload_values():
    js = (
        "var note='top secret note'; "
        "$http.post('/api/orders/create',{customerId:id,note:'hunter2 value',token:\"abcDEF123\"}); "
        "$.post('/api/orders/update',{secretval:'xyzzy-secret'});"
    )
    routes = {r["path"]: r for r in extract_js_routes(js)}
    blob = json.dumps(list(routes.values()))
    for secret in ("top secret", "hunter2", "abcDEF123", "xyzzy-secret"):
        assert secret not in blob, secret
    assert routes["/api/orders/create"]["body_keys"][:2] == ["customerId", "note"]
    assert "'/api/orders/create'" in routes["/api/orders/create"]["samples"][0]   # the route literal itself stays


def test_header_only_tables_are_reported():
    html = "<table><thead><tr><th>Name</th><th>Position</th><th>Salary</th></tr></thead><tbody></tbody></table>"
    tables = extract_tables(html)
    assert len(tables) == 1
    t = tables[0]
    assert t["headers"] == ["Name", "Position", "Salary"] and t["row_count"] == 0 and t["header_only"] is True


def test_download_nav_link_is_not_an_export():
    from hardly.core.export_links import _inspect

    assert _inspect("/download/") is None
    assert _inspect("/reports/export?format=csv")[1] == ["csv"]
    assert _inspect("/data/all.xlsx")[1] == ["xlsx"]
    assert _inspect("/export") is not None                                  # an explicit export word without a format is kept


def test_bare_data_envelope_detected_but_yields_to_specific_ones(tmp_path, monkeypatch):
    from hardly import session as sess
    from hardly.core.grids import detect_grids

    def entry(i, url, body):
        return {
            "startedDateTime": f"2026-01-01T00:00:0{i}.000Z", "time": 1,
            "request": {"method": "GET", "url": url, "httpVersion": "HTTP/1.1", "headers": [], "queryString": [], "cookies": [], "headersSize": -1, "bodySize": 0},
            "response": {"status": 200, "statusText": "OK", "httpVersion": "HTTP/1.1",
                         "headers": [{"name": "Content-Type", "value": "application/json"}], "cookies": [],
                         "redirectURL": "", "headersSize": -1, "bodySize": len(body),
                         "content": {"size": len(body), "mimeType": "application/json", "text": body}},
        }

    har = {"log": {"version": "1.2", "creator": {"name": "t", "version": "1"}, "entries": [
        entry(1, "https://a.example/arrays.txt", json.dumps({"data": [["a", "b"], ["c", "d"]]})),
        entry(2, "https://a.example/api/x", json.dumps({"data": [{"id": 1}], "links": {"self": "/x"}, "included": []})),
    ]}}
    path = tmp_path / "e.har"
    path.write_text(json.dumps(har))
    monkeypatch.setenv("HARDLY_CACHE_DIR", str(tmp_path / "cache"))
    info = sess.open_har(str(path), force=True)
    envs = {e["name"]: e["entry_ids"] for e in detect_grids(sess.require_conn(info["session_id"]))["json_envelopes"]}
    assert envs.get("data-list") == [0]            # only the bare shape
    assert envs.get("json-api") == [1]             # the specific shape is not also called data-list
