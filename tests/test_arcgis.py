"""ArcGIS REST explorer: offline parsers and mocked live exploration."""

import json
import sqlite3

import httpx

from hardly.core import arcgis
from hardly.index.schema import init_db

SERVICE = {
    "capabilities": "Map,Query,Data",
    "spatialReference": {"wkid": 102100, "latestWkid": 3857},
    "maxRecordCount": 1000,
    "layers": [{"id": i, "name": f"Layer{i}", "parentLayerId": -1} for i in range(7)],
    "tables": [{"id": 9, "name": "Tbl"}],
}
LAYER = {
    "id": 0,
    "name": "Parcels",
    "type": "Feature Layer",
    "geometryType": "esriGeometryPolygon",
    "displayField": "SITUS",
    "objectIdField": "OBJECTID",
    "maxRecordCount": 2000,
    "capabilities": "Map,Query,Data",
    "supportedQueryFormats": "JSON, geoJSON, PBF",
    "advancedQueryCapabilities": {"supportsPagination": True},
    "fields": [
        {"name": "OBJECTID", "alias": "OBJECTID", "type": "esriFieldTypeOID"},
        {"name": "OWNER_NAME", "alias": "Owner", "type": "esriFieldTypeString", "length": 80},
        {"name": "APN", "alias": "APN", "type": "esriFieldTypeString", "length": 12},
        {
            "name": "USE_CODE",
            "alias": "Use",
            "type": "esriFieldTypeString",
            "length": 4,
            "domain": {"type": "codedValue", "name": "Use", "codedValues": [{"name": "Res", "code": "R"}]},
        },
    ],
}
QUERY = {
    "geometryType": "esriGeometryPolygon",
    "exceededTransferLimit": True,
    "fields": [{"name": "OBJECTID"}, {"name": "OWNER_NAME"}],
    "features": [
        {"attributes": {"OBJECTID": 1234, "OWNER_NAME": "Zelda Quimby", "APN": "123-45-678"}, "geometry": {"rings": []}}
    ],
}
TOKEN = {"error": {"code": 499, "message": "Token Required", "details": []}}


def test_parse_service_and_layer():
    s = arcgis.parse_service(SERVICE)
    assert len(s["layers"]) == 7 and s["tables"][0]["id"] == 9
    assert s["capabilities"] == ["Map", "Query", "Data"]
    assert s["spatialReference"]["wkid"] == 102100 and s["maxRecordCount"] == 1000
    lay = arcgis.parse_layer(LAYER)
    assert lay["queryable"] and lay["supportsPagination"] is True
    assert lay["supportedQueryFormats"] == ["JSON", "geoJSON", "PBF"]
    by = {f["name"]: f for f in lay["fields"]}
    assert "personal_data_like" in by["OWNER_NAME"]["flags"]
    assert "id_or_key" in by["OBJECTID"]["flags"] and "id_or_key" in by["APN"]["flags"]
    assert by["USE_CODE"]["domain"]["coded_value_count"] == 1
    assert lay["personal_data_fields"] == ["OWNER_NAME"]


def test_not_queryable_and_token_gate():
    assert arcgis.parse_layer({**LAYER, "capabilities": "Map"})["queryable"] is False
    assert arcgis.parse_layer(TOKEN)["gate"] == "token_required"
    assert arcgis.summarise_query_response(TOKEN)["code"] == 499


def test_summarise_query_masks_values():
    out = arcgis.summarise_query_response(QUERY)
    text = json.dumps(out)
    assert out["first_row_shapes"]["OBJECTID"] == "9999"
    assert out["first_row_shapes"]["OWNER_NAME"] == "aaaaa aaaaaa"
    assert out["first_row_shapes"]["APN"] == "999-99-999"
    assert out["geometry_present"] and out["exceededTransferLimit"] and "paging_note" in out
    assert "Zelda" not in text and "Quimby" not in text and "1234" not in text and "123-45" not in text
    assert "personal_data_like" in out["flags"]["OWNER_NAME"]
    assert arcgis.summarise_query_response({"count": 42})["count_only"]


def test_query_templates():
    t = arcgis.query_templates("https://h/x/MapServer/0?f=json", arcgis.parse_layer(LAYER))
    assert t["templates"]["attribute_query"]["params"]["where"] == "<WHERE>"
    assert t["templates"]["count_only"]["params"]["returnCountOnly"] == "true"
    assert t["templates"]["distinct_values"]["params"]["returnDistinctValues"] == "true"
    assert t["recommended"] == "attribute_query"
    nop = arcgis.query_templates("https://h/x/MapServer/0", {**arcgis.parse_layer(LAYER), "supportsPagination": False})
    assert nop["recommended"] == "objectid_paging_fallback"
    assert "OBJECTID > <LAST_OBJECTID>" in nop["templates"]["objectid_paging_fallback"]["params"]["where"]


def test_find_service_urls_experience_builder():
    item = "a" * 32
    cfg = json.dumps(
        {
            "dataSources": {
                "ds1": {"type": "FEATURE_LAYER", "url": "https://gis.example.org/arcgis/rest/services/Land/Parcels/FeatureServer/0", "itemId": item},
                "ds2": {"type": "WEB_MAP", "itemId": "b" * 32, "portalUrl": "https://www.arcgis.com"},
            },
            "widgets": {},
        }
    ).replace("/", "\\/")
    r = arcgis.find_service_urls(cfg)
    assert r["kind"] == "experience_builder_config"
    assert r["urls"] == ["https://gis.example.org/arcgis/rest/services/Land/Parcels/FeatureServer/0"]
    assert item in r["item_ids"] and "b" * 32 in r["item_ids"]
    assert "sharing/rest/content/items/<item_id>/data?f=json" in r["item_data_url_template"]


def test_find_service_urls_wab_and_html():
    wab = '{"map":{"itemId":"%s"},"operationalLayers":[{"url":"https://maps.example.com/server/rest/services/A/MapServer/3"}]}' % ("c" * 32)
    r = arcgis.find_service_urls(wab)
    assert r["kind"] == "web_app_builder_config"
    assert r["urls"] == ["https://maps.example.com/server/rest/services/A/MapServer/3"]
    html = '<script>var u="https://portal.example.com/portal/sharing/rest/content/items/%s/data";fetch("https://x.org/a/ImageServer?f=json")</script>' % ("d" * 32)
    r2 = arcgis.find_service_urls(html)
    assert r2["portal_hosts"] == ["portal.example.com"]
    assert r2["item_data_urls"][0].startswith("https://portal.example.com/sharing/rest/content/items/dddd")
    assert r2["urls"] == ["https://x.org/a/ImageServer"]
    assert arcgis.find_service_urls("nothing here")["kind"] == "none"


def _session():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    init_db(conn)
    ins = "INSERT INTO entries(entry_id,method,host,path,path_template,query_json,status) VALUES(?,?,?,?,?,?,?)"
    base = "/arcgis/rest/services/Land/Parcels/MapServer"
    conn.execute(ins, (1, "GET", "gis.example.org", base, base, json.dumps({"f": "json"}), 200))
    conn.execute(ins, (2, "GET", "gis.example.org", base + "/0/query", base, json.dumps({"where": "1=1", "outFields": "*", "resultOffset": "0", "resultRecordCount": "100", "f": "json"}), 200))
    conn.execute(ins, (3, "GET", "other.example.org", "/index.html", "/index.html", None, 200))
    conn.execute("INSERT INTO bodies(entry_id,side,size,preview_text) VALUES(2,'response',10,?)", ('{"exceededTransferLimit": true, "features": []}',))
    conn.commit()
    return conn


def test_summarize_session():
    out = arcgis.summarize_session(_session())
    assert out["service_count"] == 1
    s = out["services"][0]
    assert s["service_root"] == "gis.example.org/arcgis/rest/services/Land/Parcels/MapServer"
    assert s["layers_queried"] == [0] and s["layer_ids_seen"] == [0]
    assert "where" in s["param_names"] and "resultOffset" in s["paging_evidence"]
    assert s["exceededTransferLimit_seen"] is True
    assert arcgis.summarize_session(_session(), host="nope")["service_count"] == 0


def _client(handler, calls):
    def wrapped(req: httpx.Request):
        calls.append(req)
        return handler(req)

    return httpx.Client(transport=httpx.MockTransport(wrapped))


def _ok_handler(req: httpx.Request):
    p = req.url.path
    if p.endswith("/query"):
        return httpx.Response(200, json=QUERY)
    if p.endswith("/MapServer") or p.endswith("/FeatureServer"):
        return httpx.Response(200, json=SERVICE)
    return httpx.Response(200, json={**LAYER, "id": int(p.rsplit("/", 1)[1])})


def test_explore_gates_and_refuses():
    calls: list = []
    c = _client(_ok_handler, calls)
    assert "confirm" in arcgis.explore("https://h/a/MapServer", client=c)["error"]
    assert "ArcGIS" in arcgis.explore("https://h/page.html", confirm=True, client=c)["error"]
    assert not calls


def test_explore_caps_and_no_values():
    calls: list = []
    r = arcgis.explore("https://h/a/MapServer", confirm=True, client=_client(_ok_handler, calls), delay=0)
    assert len(calls) == 1 + 5 + 1  # service + 5 layers + 1 sample
    assert all(c.method == "GET" for c in calls)
    q = [c for c in calls if c.url.path.endswith("/query")]
    assert len(q) == 1 and q[0].url.params["resultRecordCount"] == "1"
    assert len(r["layers"]) == 5 and "cap" in r["note"]
    text = json.dumps(r)
    assert "Zelda" not in text and "Quimby" not in text
    assert r["sample"]["first_row_shapes"]["OBJECTID"] == "9999"
    assert r["layers"][0]["templates"]["recommended"] == "attribute_query"


def test_explore_layer_url_and_token_gate():
    calls: list = []
    r = arcgis.explore("https://h/a/FeatureServer/2", confirm=True, client=_client(_ok_handler, calls), delay=0)
    assert len(calls) == 2 and r["layers"][0]["id"] == 2
    calls = []
    r = arcgis.explore("https://h/a/MapServer", confirm=True, client=_client(lambda q: httpx.Response(200, json=TOKEN), calls), delay=0)
    assert r["stop"]["gate"] == "token_required" and r["stop"]["code"] == 499
    assert len(calls) == 1


def test_explore_stops_on_429():
    calls: list = []
    r = arcgis.explore(
        "https://h/a/MapServer", confirm=True, delay=0,
        client=_client(lambda q: httpx.Response(429, headers={"Retry-After": "30"}), calls),
    )
    assert r["stop"]["stopped"] == "rate_limited" and r["stop"]["retry_after"] == "30"
    assert len(calls) == 1


def test_explore_non_queryable_skips_sample():
    def h(req):
        if req.url.path.endswith("/MapServer"):
            return httpx.Response(200, json={"layers": [{"id": 0, "name": "x"}]})
        return httpx.Response(200, json={**LAYER, "capabilities": "Map"})

    calls: list = []
    r = arcgis.explore("https://h/a/MapServer", confirm=True, client=_client(h, calls), delay=0)
    assert len(calls) == 2 and "sample" not in r
