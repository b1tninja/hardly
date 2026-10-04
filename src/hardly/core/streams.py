"""Stream / wire-encoding summaries: gRPC-web, protobuf, MessagePack, CSV/TSV,
SSE and WebSocket frames. Shapes and counts only, never payload values.

Ingest calls :func:`analyze_body` / :func:`analyze_websocket` and persists the
result via :func:`store_stream` into ``stream_info``; :func:`summarize_streams`
and :func:`attach_stream_hints` read it back.
"""

from __future__ import annotations

import base64
import binascii
import json
import sqlite3
from typing import Any

from hardly.core.encodings import (
    decode_grpc_text,
    json_shape,
    looks_like_sse,
    parse_msgpack,
    parse_protobuf,
    sniff_binary,
    summarize_csv,
    summarize_grpc,
    summarize_sse,
)
from hardly.core.safe_json import safe_loads

STREAM_KINDS = ("grpc-web", "grpc", "protobuf", "msgpack", "csv", "sse", "websocket")
_MAX_WS = 5000


def analyze_body(
    mime: str | None,
    path: str | None,
    text: str | None,
    raw: bytes | None = None,
) -> tuple[str, dict[str, Any]] | None:
    """Return (kind, summary) for a recognised stream encoding, else None."""
    m = (mime or "").lower().split(";")[0].strip()
    p = (path or "").lower().split("?", 1)[0]
    if m.startswith("application/grpc-web-text") or m.startswith("application/grpc-web+text"):
        src = decode_grpc_text(text or "") if text else (raw and decode_grpc_text(raw.decode("ascii", "ignore")))
        if src:
            s = summarize_grpc(src)
            if s:
                return "grpc-web", s
        return None
    if raw:
        hit = sniff_binary(raw, m)
        if hit:
            return hit
    if text:
        if m == "text/event-stream" or (not m.startswith(("text/html", "application/json")) and looks_like_sse(text)):
            s = summarize_sse(text)
            if s:
                return "sse", s
        if m in {"text/csv", "application/csv", "text/tab-separated-values"} or p.endswith((".csv", ".tsv")):
            s = summarize_csv(text, m, p)
            if s:
                return "csv", s
        # Binary protocols delivered as latin-1/utf-8 text are not recoverable.
    return None


def analyze_websocket(messages: list[dict[str, Any]] | None) -> dict[str, Any] | None:
    """Summarise Chrome ``_webSocketMessages`` (direction, opcode, JSON shapes)."""
    if not messages:
        return None
    directions: dict[str, int] = {}
    opcodes: dict[str, int] = {}
    shapes: dict[str, int] = {}
    binary_kinds: dict[str, int] = {}
    text_frames = json_frames = 0
    bytes_total = 0
    times: list[float] = []
    for msg in messages[:_MAX_WS]:
        if not isinstance(msg, dict):
            continue
        d = str(msg.get("type") or "unknown")
        directions[d] = directions.get(d, 0) + 1
        try:
            op = int(msg.get("opcode")) if msg.get("opcode") is not None else None
        except (TypeError, ValueError):
            op = None
        data = msg.get("data")
        if op is None:
            op = 1 if isinstance(data, str) else 2
        opname = {1: "text", 2: "binary", 8: "close", 9: "ping", 10: "pong", 0: "continuation"}.get(
            op, f"op{op}"
        )
        opcodes[opname] = opcodes.get(opname, 0) + 1
        t = msg.get("time")
        try:
            if t is not None:
                times.append(float(t))
        except (TypeError, ValueError):
            pass
        if not isinstance(data, str):
            continue
        bytes_total += len(data)
        if op == 1:
            text_frames += 1
            s = data.lstrip()
            if s[:1] in "{[":
                try:
                    sh = json.dumps(json_shape(safe_loads(s), max_depth=3), sort_keys=True)
                except ValueError:
                    sh = "text"
                else:
                    json_frames += 1
            else:
                sh = "text"
            if sh not in shapes and len(shapes) >= 8:
                sh = "(other)"
            shapes[sh] = shapes.get(sh, 0) + 1
        elif op == 2:
            try:
                raw = base64.b64decode(data, validate=False)
            except (binascii.Error, ValueError):
                continue
            hit = sniff_binary(raw, "")
            k = hit[0] if hit else "opaque"
            binary_kinds[k] = binary_kinds.get(k, 0) + 1
    out: dict[str, Any] = {
        "messages": len(messages),
        "directions": directions,
        "opcodes": opcodes,
        "text_frames": text_frames,
        "json_frames": json_frames,
        "json_shapes": dict(sorted(shapes.items(), key=lambda kv: -kv[1])),
        "payload_chars": bytes_total,
    }
    if binary_kinds:
        out["binary_kinds"] = binary_kinds
    if len(times) >= 2:
        out["duration_s"] = round(max(times) - min(times), 3)
    if len(messages) > _MAX_WS:
        out["truncated_at"] = _MAX_WS
    return out


def store_stream(
    conn: sqlite3.Connection, entry_id: int, side: str, kind: str, summary: dict[str, Any]
) -> None:
    conn.execute(
        "INSERT INTO stream_info (entry_id, side, kind, summary_json) VALUES (?, ?, ?, ?)",
        (entry_id, side, kind, json.dumps(summary, default=str)),
    )


def _hint(kind: str, s: dict[str, Any]) -> list[str]:
    h = [f"stream:{kind}"]
    if kind in ("grpc-web", "grpc"):
        h.append(f"frames:{s.get('frames')}")
        if "grpc_status" in s:
            h.append(f"grpc-status:{s['grpc_status']}")
        fields = (s.get("message") or {}).get("fields")
        if fields:
            h.append("pb_fields:" + ",".join(list(fields)[:8]))
    elif kind == "protobuf":
        h.append("pb_fields:" + ",".join(list(s.get("fields", {}))[:8]))
    elif kind == "msgpack":
        h.append(f"msgpack:{s.get('top_level')}")
    elif kind == "csv":
        h.append(f"delimiter:{s.get('delimiter')}")
        h.append(f"rows:{s.get('rows')}")
    elif kind == "sse":
        h.append(f"events:{s.get('events')}")
        h.extend(f"event:{n}" for n in list(s.get("event_names", {}))[:4])
    elif kind == "websocket":
        h.append(f"messages:{s.get('messages')}")
    return h


def attach_stream_hints(conn: sqlite3.Connection, entry_id: int, info: dict[str, Any]) -> None:
    """Merge stream_info rows for an entry into a classify_response dict (in place)."""
    try:
        rows = conn.execute(
            "SELECT side, kind, summary_json FROM stream_info WHERE entry_id = ? ORDER BY id",
            (entry_id,),
        ).fetchall()
    except sqlite3.Error:
        return
    if not rows:
        return
    streams = []
    hints = list(info.get("hints") or [])
    for r in rows:
        try:
            s = safe_loads(r["summary_json"])
        except ValueError:
            continue
        streams.append({"side": r["side"], "kind": r["kind"], "summary": s})
        if r["side"] in ("response", "messages"):
            hints.extend(h for h in _hint(r["kind"], s) if h not in hints)
            if info.get("kind") in {"binary", "empty", "omitted", "text", None} and r["kind"] != "websocket":
                info["kind"] = r["kind"]
                info["confidence"] = "high"
    info["streams"] = streams
    info["hints"] = hints[:12]


def summarize_streams(
    conn: sqlite3.Connection,
    *,
    host: str | None = None,
    kind: str | None = None,
    exclude_noise: bool = True,
    limit: int = 40,
) -> dict[str, Any]:
    """Histogram of stream encodings with per-entry shape summaries."""
    clauses = ["1=1"]
    params: list[Any] = []
    if host:
        clauses.append("e.host = ?")
        params.append(host.lower())
    if kind:
        clauses.append("s.kind = ?")
        params.append(kind)
    if exclude_noise:
        clauses.append("e.is_noise = 0")
    try:
        rows = conn.execute(
            f"""
            SELECT s.entry_id, s.side, s.kind, s.summary_json,
                   e.method, e.host, e.path, e.status
            FROM stream_info s JOIN entries e ON e.entry_id = s.entry_id
            WHERE {" AND ".join(clauses)}
            ORDER BY s.entry_id, s.id
            """,
            params,
        ).fetchall()
    except sqlite3.Error:
        rows = []
    by_kind: dict[str, int] = {}
    items: list[dict[str, Any]] = []
    ws = {"connections": 0, "messages": 0, "sent": 0, "received": 0}
    for r in rows:
        by_kind[r["kind"]] = by_kind.get(r["kind"], 0) + 1
        try:
            summary = safe_loads(r["summary_json"])
        except ValueError:
            summary = {}
        if r["kind"] == "websocket":
            ws["connections"] += 1
            ws["messages"] += int(summary.get("messages") or 0)
            ws["sent"] += int((summary.get("directions") or {}).get("send", 0))
            ws["received"] += int((summary.get("directions") or {}).get("receive", 0))
        if len(items) < max(1, min(limit, 200)):
            items.append(
                {
                    "entry_id": r["entry_id"],
                    "side": r["side"],
                    "kind": r["kind"],
                    "method": r["method"],
                    "host": r["host"],
                    "path": r["path"],
                    "status": r["status"],
                    "summary": summary,
                }
            )
    out: dict[str, Any] = {
        "host": host,
        "total": len(rows),
        "by_kind": dict(sorted(by_kind.items(), key=lambda kv: (-kv[1], kv[0]))),
        "streams": items,
    }
    if ws["connections"]:
        out["websocket_totals"] = ws
    out["next"] = (
        "Shapes only (field numbers, columns, event names, JSON key types). "
        "Drill into a body with core.body_query.query_body(...)."
    )
    return out


__all__ = [
    "STREAM_KINDS",
    "analyze_body",
    "analyze_websocket",
    "attach_stream_hints",
    "parse_msgpack",
    "parse_protobuf",
    "store_stream",
    "summarize_streams",
]
