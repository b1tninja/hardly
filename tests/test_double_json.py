"""Double-encoded JSON: a JSON string whose content is JSON (synthetic)."""

import json

from hardly import session as sess
from hardly.core.classify import classify_response
from hardly.core.json_unwrap import unwrap_json_string
from hardly.index import query as q
from hardly.index.ingest import INDEX_VERSION

INNER = {"Table": {"Rows": [{"Id": 1, "Label": "zz-secret-zz"}], "Count": 1}}
WIRE = json.dumps(json.dumps(INNER))


def test_unwrap_json_string_layers():
    assert unwrap_json_string(json.dumps(INNER)) == (INNER, 0)
    assert unwrap_json_string(WIRE) == (INNER, 1)
    assert unwrap_json_string(json.dumps(WIRE)) == (INNER, 2)
    # three wrappers (the documented max) fully unwrap
    assert unwrap_json_string(json.dumps(json.dumps(WIRE))) == (INNER, 3)
    # four wrappers exceed the default cap: the remaining string comes back
    value, layers = unwrap_json_string(json.dumps(json.dumps(json.dumps(WIRE))))
    assert layers == 3 and isinstance(value, str)
    # depth cap: stops peeling, returns the remaining string
    value, layers = unwrap_json_string(json.dumps(json.dumps(WIRE)), max_depth=1)
    assert layers == 1 and isinstance(value, str)
    # a plain string is not an object
    assert unwrap_json_string('"hello"')[0] == "hello"
    assert unwrap_json_string("not json") == ("not json", 0)


def test_classify_reports_double_encoded():
    info = classify_response(mime="application/json", path="/svc/Get", body=WIRE)
    assert info["kind"] == "json"
    assert "double_encoded_json" in info["hints"]
    assert info["json_keys"] == ["Table"]
    # also when mime lies
    info = classify_response(mime="text/plain", path="/svc/Get", body=WIRE)
    assert info["kind"] == "json" and "double_encoded_json" in info["hints"]
    # an ordinary JSON string is not flagged
    plain = classify_response(mime="application/json", path="/x", body='"hello"')
    assert "double_encoded_json" not in (plain.get("hints") or [])


def _har(tmp_path):
    def entry(i, url, body):
        return {
            "startedDateTime": f"2026-01-01T00:00:0{i}.000Z", "time": 1,
            "request": {"method": "POST", "url": url, "httpVersion": "HTTP/1.1",
                        "headers": [], "cookies": [], "headersSize": -1,
                        "bodySize": 0, "queryString": []},
            "response": {"status": 200, "statusText": "OK", "httpVersion": "HTTP/1.1",
                         "headers": [], "cookies": [], "redirectURL": "",
                         "headersSize": -1, "bodySize": len(body),
                         "content": {"size": len(body), "mimeType": "application/json",
                                     "text": body}},
        }

    har = {"log": {"version": "1.2", "creator": {"name": "t", "version": "1"},
                   "entries": [entry(1, "https://svc.example.com/api/Get", WIRE),
                               entry(2, "https://svc.example.com/api/Plain", json.dumps(INNER))]}}
    p = tmp_path / "d.har"
    p.write_text(json.dumps(har))
    return p


def test_ingest_unwraps_and_schema(tmp_path, monkeypatch):
    assert INDEX_VERSION >= 4
    monkeypatch.setenv("HARDLY_CACHE_DIR", str(tmp_path / "cache"))
    info = sess.open_har(str(_har(tmp_path)), force=True)
    conn = sess.require_conn(info["session_id"])

    preview = conn.execute(
        "SELECT preview_text FROM bodies WHERE entry_id = 0 AND side = 'response'"
    ).fetchone()[0]
    assert isinstance(json.loads(preview), dict)
    sig = conn.execute(
        "SELECT entry_id, kind, name FROM body_signals WHERE kind = 'encoding'"
    ).fetchall()
    assert [(r["entry_id"], r["name"]) for r in sig] == [(0, "double-encoded-json")]

    entry = q.get_entry(conn, 0) if hasattr(q, "get_entry") else None
    if entry:
        assert "double_encoded_json" in entry["content"]["hints"]

    schema = q.endpoint_schema(
        conn, method="POST", host="svc.example.com", path_template="/api/Get"
    )
    assert schema["response_schema"]["type"] == "object"
    assert "Table" in json.dumps(schema["response_schema"])
