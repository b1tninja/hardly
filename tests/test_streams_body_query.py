"""Stream encoding detectors, summarize_streams, and body_query (synthetic data)."""

import base64
import json
import struct

import pytest

from hardly import session as sess
from hardly.core.body_query import BodyQueryError, parse_jsonpath, query_body
from hardly.core.classify import classify_response, summarize_content
from hardly.core.encodings import parse_msgpack, parse_protobuf, summarize_csv, summarize_sse
from hardly.core.streams import analyze_websocket, summarize_streams
from hardly.index.ingest import INDEX_VERSION

SECRET = "sup3r-s3cret-value-XYZ"


def _varint(n):
    out = b""
    while True:
        b = n & 0x7F
        n >>= 7
        out += bytes([b | (0x80 if n else 0)])
        if not n:
            return out


def pb_msg():
    inner = b"\x08" + _varint(7)  # field1 varint
    return (
        b"\x08" + _varint(150)  # f1 varint
        + b"\x12" + _varint(5) + b"hello"  # f2 string
        + b"\x1a" + _varint(len(inner)) + inner  # f3 message
    )


def grpc_frames():
    msg = pb_msg()
    data = b"\x00" + struct.pack(">I", len(msg)) + msg
    trailer = b"grpc-status: 0\r\ngrpc-message: ok\r\n"
    return data + b"\x80" + struct.pack(">I", len(trailer)) + trailer


def mp_map():
    # {"id": 1, "name": "x", "items": [1, 2]}
    return (
        b"\x83" + b"\xa2id" + b"\x01" + b"\xa4name" + b"\xa1x"
        + b"\xa5items" + b"\x92\x01\x02"
    )


def _entry(url, mime, text=None, b64=None, req=None, ws=None, method="POST"):
    content = {"mimeType": mime, "size": 10}
    if b64 is not None:
        content.update(text=base64.b64encode(b64).decode(), encoding="base64")
    elif text is not None:
        content["text"] = text
    e = {
        "startedDateTime": "2024-01-01T00:00:00Z",
        "time": 5,
        "request": {"method": method, "url": url, "headers": [], "queryString": []},
        "response": {"status": 200, "headers": [], "content": content},
    }
    if req:
        e["request"]["postData"] = req
    if ws:
        e["_webSocketMessages"] = ws
    return e


@pytest.fixture
def har(tmp_path, monkeypatch):
    monkeypatch.setenv("HARDLY_CACHE_DIR", str(tmp_path / "cache"))
    big = {
        "user": {"name": "n", "password": SECRET, "token": "a" * 40},
        "rows": [{"id": i, "label": f"row-{i}", "api_key": SECRET} for i in range(100)],
    }
    entries = [
        _entry("https://x.test/api/Svc/Call", "application/grpc-web+proto", b64=grpc_frames()),
        _entry("https://x.test/pb", "application/x-protobuf", b64=pb_msg()),
        _entry("https://x.test/mp", "application/msgpack", b64=mp_map()),
        _entry("https://x.test/export.csv", "text/csv", text="id,name,amount\n1,a,2\n2,b,3\n3,c,4\n"),
        _entry("https://x.test/export.tsv", "text/tab-separated-values", text="a\tb\n1\t2\n"),
        _entry(
            "https://x.test/events",
            "text/event-stream",
            text='event: tick\ndata: {"n": 1}\n\nevent: tick\ndata: {"n": 2}\n\nevent: done\ndata: bye\n\n',
        ),
        _entry("https://x.test/big", "application/json", text=json.dumps(big)),
        _entry(
            "https://x.test/ws",
            "text/plain",
            text="",
            ws=[
                {"type": "send", "time": 1.0, "opcode": 1, "data": json.dumps({"op": "sub", "token": SECRET})},
                {"type": "receive", "time": 2.5, "opcode": 1, "data": json.dumps({"op": "msg", "d": [1, 2]})},
                {"type": "receive", "time": 3.0, "opcode": 1, "data": "ping"},
                {"type": "receive", "time": 3.5, "opcode": 2, "data": base64.b64encode(pb_msg()).decode()},
            ],
        ),
    ]
    p = tmp_path / "t.har"
    p.write_text(json.dumps({"log": {"version": "1.2", "entries": entries}}))
    return p


def test_index_version_bumped():
    assert INDEX_VERSION >= 5


def test_protobuf_and_msgpack_units():
    pb = parse_protobuf(pb_msg())
    assert pb["fields"]["1"]["wire"] == "varint"
    assert pb["fields"]["2"]["as"] == "string"
    assert pb["fields"]["3"]["as"] == "message" and "1" in pb["fields"]["3"]["sub"]
    assert parse_protobuf(b"\xff\xff\xff") is None
    mp = parse_msgpack(mp_map())
    assert mp["top_level"] == "object" and mp["keys"] == ["id", "name", "items"]
    assert parse_msgpack(mp_map() + b"\x00") is None


def test_csv_sse_units():
    c = summarize_csv("a;b;c\n1;2;3\n4;5;6\n")
    assert c["delimiter"] == "semicolon" and c["header"] == ["a", "b", "c"] and c["rows"] == 2
    s = summarize_sse("event: a\ndata: {\"k\": \"v\"}\n\ndata: plain\n\n: hb\n")
    assert s["events"] == 2 and s["event_names"] == {"a": 1, "message": 1}


def test_websocket_summary_redacts():
    s = analyze_websocket(
        [
            {"type": "send", "opcode": 1, "data": json.dumps({"password": SECRET, "n": 1})},
            {"type": "receive", "opcode": 1, "data": "hello"},
        ]
    )
    assert s["directions"] == {"send": 1, "receive": 1}
    assert s["json_frames"] == 1
    assert SECRET not in json.dumps(s)


def test_classify_mime_hints():
    assert classify_response(mime="application/grpc-web+proto", size=9)["kind"] == "grpc-web"
    assert classify_response(mime="application/x-protobuf", size=9)["kind"] == "protobuf"
    assert classify_response(mime="text/event-stream", body="data: x\n\n")["kind"] == "sse"
    assert classify_response(body="event: a\ndata: 1\n\n")["kind"] == "sse"


def test_ingest_and_summarize_streams(har):
    info = sess.open_har(str(har), force=True)
    conn = sess.require_conn(info["session_id"])
    out = summarize_streams(conn, exclude_noise=False)
    kinds = out["by_kind"]
    for k in ("grpc-web", "protobuf", "msgpack", "csv", "sse", "websocket"):
        assert kinds.get(k, 0) >= 1, kinds
    assert kinds["csv"] == 2
    g = next(s for s in out["streams"] if s["kind"] == "grpc-web")["summary"]
    assert g["frames"] == 2 and g["grpc_status"] == 0
    assert g["message"]["fields"]["2"]["as"] == "string"
    sse = next(s for s in out["streams"] if s["kind"] == "sse")["summary"]
    assert sse["events"] == 3 and sse["event_names"]["tick"] == 2
    ws = next(s for s in out["streams"] if s["kind"] == "websocket")["summary"]
    assert ws["messages"] == 4 and ws["opcodes"] == {"text": 3, "binary": 1}
    assert ws["binary_kinds"] == {"protobuf": 1}
    assert out["websocket_totals"]["sent"] == 1
    assert SECRET not in json.dumps(out)
    assert "hello" not in json.dumps(out)  # payload strings never echoed
    # classify hints surface via summarize_content
    sc = summarize_content(conn, exclude_noise=False, limit=50)
    assert "grpc-web" in sc["by_kind"] and "sse" in sc["by_kind"]
    only = summarize_streams(conn, kind="csv", exclude_noise=False)
    assert only["total"] == 2


def test_jsonpath_parse():
    assert parse_jsonpath("$.a[0]..b[*]['c d'][1:3]") == [
        ("key", "a"), ("idx", 0), ("rec", "b"), ("wild", None), ("key", "c d"), ("slice", (1, 3)),
    ]
    with pytest.raises(BodyQueryError):
        parse_jsonpath("$.a[?(@.x)]")


def test_body_query_jsonpath_paging_redaction(har):
    info = sess.open_har(str(har), force=True)
    conn = sess.require_conn(info["session_id"])
    r = query_body(conn, 6, jsonpath="$.rows[*].label", limit=10)
    assert r["total"] == 100 and len(r["matches"]) == 10 and r["has_more"]
    assert r["matches"][0]["value"] == "row-0"
    r2 = query_body(str(har), 6, jsonpath="$.rows[*].label", offset=r["next_offset"], limit=100)
    assert r2["matches"][0]["value"] == "row-10" and not r2["has_more"]
    red = query_body(conn, 6, jsonpath="$.user.password")
    assert red["matches"][0]["redacted"] is True and SECRET not in json.dumps(red)
    red = query_body(conn, 6, jsonpath="$..api_key", limit=3)
    assert all(m.get("redacted") for m in red["matches"]) and SECRET not in json.dumps(red)
    tok = query_body(conn, 6, jsonpath="$.user")  # container with sensitive children
    assert SECRET not in json.dumps(tok) and "a" * 40 not in json.dumps(tok)
    assert query_body(conn, 6, jsonpath="$.rows[-1].id")["matches"][0]["value"] == 99
    assert query_body(conn, 6, jsonpath="$.rows[2:4].id")["total"] == 2


def test_body_query_regex_and_window(har):
    r = query_body(str(har), 6, regex=r'"password":\s*"[^"]+"')
    assert r["total"] == 1 and SECRET not in json.dumps(r)
    r = query_body(str(har), 6, regex=r"row-\d+", limit=5, offset=2)
    assert [m["at"] for m in r["matches"]] == sorted(m["at"] for m in r["matches"])
    assert r["total"] == 100 and r["next_offset"] == 7
    w = query_body(str(har), 6, limit=5)
    assert w["length"] == 500 and w["has_more"] and SECRET not in w["window"]
    with pytest.raises(BodyQueryError):
        query_body(str(har), 6, regex="(", limit=5)
    with pytest.raises(BodyQueryError):
        query_body(str(har), 99, jsonpath="$")


def test_body_query_binary_returns_shape(har):
    r = query_body(str(har), 0)
    assert r["binary"] and r["stream"]["kind"] == "grpc-web"
