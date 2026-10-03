"""Schema inference richness and contract drift, on synthetic HARs."""

import json

from hardly.core.contract import check_contract
from hardly.core.export_openapi import build_openapi
from hardly.core.schema_infer import infer_schema
from hardly.index.ingest import ingest_har
from hardly.index.schema import connect

HOST = "api.example.test"


def _entry(method, path, status, resp=None, req=None, headers=None):
    return {
        "startedDateTime": "2024-01-01T00:00:00.000Z",
        "time": 5,
        "request": {
            "method": method,
            "url": f"https://{HOST}{path}",
            "httpVersion": "HTTP/1.1",
            "headers": headers or [],
            "queryString": [],
            "cookies": [],
            "headersSize": -1,
            "bodySize": -1,
            **(
                {"postData": {"mimeType": "application/json", "text": json.dumps(req)}}
                if req is not None
                else {}
            ),
        },
        "response": {
            "status": status,
            "statusText": "",
            "httpVersion": "HTTP/1.1",
            "headers": [],
            "cookies": [],
            "content": {
                "size": 10,
                "mimeType": "application/json",
                "text": json.dumps(resp) if resp is not None else "",
            },
            "redirectURL": "",
            "headersSize": -1,
            "bodySize": -1,
        },
        "cache": {},
        "timings": {"send": 0, "wait": 1, "receive": 1},
    }


def _conn(tmp_path, name, entries):
    har = tmp_path / f"{name}.har"
    har.write_text(json.dumps({"log": {"version": "1.2", "entries": entries}}))
    ingest_har(har, tmp_path / f"{name}.db")
    return connect(str(tmp_path / f"{name}.db")), har


def _items(extra=None, price="9.99"):
    return [
        {
            "id": i,
            "uuid": f"123e4567-e89b-12d3-a456-42661417400{i}",
            "status": "active" if i % 2 else "closed",
            "price": 10 + i,
            "created": "2024-01-0%dT10:00:00Z" % i,
            "email": f"u{i}@example.test",
            "note": None if i == 1 else "x",
            "token": "supersecretvalue%d" % i,
            **({"opt": 1} if i == 1 else {}),
            **(extra or {}),
        }
        for i in range(1, 5)
    ]


def test_infer_rich_schema():
    s = infer_schema(_items())
    p = s["properties"]
    assert s["count"] == 4 and "id" in s["required"] and p["opt"]["optional"] is True
    assert p["id"]["format"] == "id"
    assert p["uuid"]["format"] == "uuid"
    assert p["created"]["format"] == "date-time"
    assert p["email"]["format"] == "email"
    assert p["price"]["format"] == "money"
    assert p["status"]["enum"] == ["active", "closed"]
    assert p["note"]["nullable"] is True
    assert p["token"]["secret_shape"] == "opaque"
    assert "supersecretvalue" not in json.dumps(s)
    assert "enum" not in p["email"] and "enum" not in p["token"]


def test_infer_oneof_and_personal_not_enumerated():
    s = infer_schema([{"items": [{"a": 1}, {"zz": "x", "yy": 2}, 5]}] * 3)
    assert len(s["properties"]["items"]["items"]["oneOf"]) == 3
    names = infer_schema([{"first_name": "Bob"}] * 4)
    assert "enum" not in names["properties"]["first_name"]
    assert infer_schema([1, "a"])["type"] == "integer|string"


def test_openapi_uses_all_samples_and_per_status(tmp_path):
    conn, _ = _conn(
        tmp_path,
        "a",
        [_entry("GET", "/items", 200, {"list": _items()[:2]}), _entry("GET", "/items", 200, {"list": _items()[2:]}),
         _entry("GET", "/items", 404, {"error": "nope"})],
    )
    doc = build_openapi(conn, host=HOST)
    op = doc["paths"]["/items"]["get"]
    ok = op["responses"]["200"]["content"]["application/json"]["schema"]
    assert ok["x-sample-count"] == 2
    assert ok["properties"]["list"]["items"]["x-sample-count"] == 4
    assert "error" in op["responses"]["404"]["content"]["application/json"]["schema"]["properties"]
    assert "supersecretvalue" not in json.dumps(doc)


def _baseline(tmp_path):
    conn, _ = _conn(
        tmp_path,
        "base",
        [
            _entry("GET", "/items", 200, {"id": 1, "name": "a", "old": True, "count": 3}),
            _entry("POST", "/items", 201, {"id": 2}, req={"title": "t"}),
            _entry("GET", "/gone", 200, {"x": 1}),
            _entry("GET", "/items", 200, {"id": 2, "name": "b", "old": False, "count": 4},
                   headers=[{"name": "Authorization", "value": "Bearer abc.def"}]),
        ],
    )
    spec = tmp_path / "spec.json"
    spec.write_text(json.dumps(build_openapi(conn, host=HOST)))
    return spec


def test_contract_no_drift(tmp_path):
    spec = _baseline(tmp_path)
    conn, _ = _conn(
        tmp_path,
        "same",
        [
            _entry("GET", "/items", 200, {"id": 1, "name": "a", "old": True, "count": 3}),
            _entry("POST", "/items", 201, {"id": 2}, req={"title": "t"}),
            _entry("GET", "/gone", 200, {"x": 1}),
            _entry("GET", "/items", 200, {"id": 2, "name": "b", "old": False, "count": 4},
                   headers=[{"name": "Authorization", "value": "Bearer abc.def"}]),
        ],
    )
    r = check_contract(conn, str(spec), host=HOST)
    assert r["drift"] is False, r


def test_contract_drift(tmp_path):
    spec = _baseline(tmp_path)
    _, har = _conn(
        tmp_path,
        "new",
        [
            _entry("GET", "/items", 200, {"id": "s1", "name": "a", "extra": 1, "count": 3}),
            _entry("GET", "/items", 200, {"id": "s2", "name": "b", "extra": 2, "count": 4}),
            _entry("GET", "/items", 500, {"error": "boom"}),
            _entry("POST", "/items", 201, {"id": 2}, req={"title": "t", "kind": "k"}),
            _entry("GET", "/fresh", 200, {"y": 1}),
        ],
    )
    r = check_contract(str(har), json.loads(spec.read_text()), host=HOST)
    assert r["drift"]
    assert r["new_endpoints"] == ["GET /fresh"]
    assert r["removed_endpoints"] == ["GET /gone"]
    assert {"endpoint": "GET /items", "added": ["500"], "removed": []} in r["status_changes"]
    kinds = {(c["where"], c["kind"]) for c in r["field_changes"] if c["endpoint"] == "GET /items"}
    assert ("$.id", "retyped") in kinds
    assert ("$.old", "removed") in kinds
    assert ("$.extra", "added") in kinds
    assert any(c["kind"] == "added" and c["where"] == "$.kind" and c["side"] == "request" for c in r["field_changes"])
    assert any(a["scope"] == "GET /items" and a["removed"] == ["bearerAuth"] for a in r["auth_changes"])
    assert r["summary"]["potentially_breaking"] >= 3
    assert "abc.def" not in json.dumps(r)


def test_contract_newly_required(tmp_path):
    base, _ = _conn(
        tmp_path, "b2",
        [_entry("POST", "/x", 200, {"a": 1}, req={"p": 1}), _entry("POST", "/x", 200, {"a": 1}, req={"p": 1, "q": 2})],
    )
    spec = build_openapi(base, host=HOST)
    fresh, _ = _conn(
        tmp_path, "f2",
        [_entry("POST", "/x", 200, {"a": 1}, req={"p": 1, "q": 2}), _entry("POST", "/x", 200, {"a": 1}, req={"p": 3, "q": 4})],
    )
    r = check_contract(fresh, spec, host=HOST)
    assert any(c["kind"] == "newly_required" and c["where"] == "$.q" for c in r["field_changes"])
