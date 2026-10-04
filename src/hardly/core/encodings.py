"""Shape-only detectors for non-JSON wire encodings.

Everything here returns *structure* (field numbers, wire types, delimiters,
column names, event names, counts) and never payload values.
"""

from __future__ import annotations

import base64
import binascii
import csv
import io
import json
import re
from typing import Any

from hardly.core.redact import classify_value_shape, is_sensitive_key
from hardly.core.safe_json import safe_loads

MAX_SCAN_BYTES = 2_000_000
_WIRE = {0: "varint", 1: "fixed64", 2: "len", 5: "fixed32"}


# ---------------------------------------------------------------- JSON shape
def type_name(v: Any) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "boolean"
    if isinstance(v, (int, float)):
        return "number"
    if isinstance(v, str):
        return "string"
    if isinstance(v, (bytes, bytearray)):
        return "bytes"
    if isinstance(v, list):
        return "array"
    return "object"


def json_shape(obj: Any, *, depth: int = 0, max_depth: int = 4) -> Any:
    """Type-only shape of a JSON value. Sensitive-key values show their shape label."""
    if depth >= max_depth:
        return "..."
    if isinstance(obj, dict):
        out: dict[str, Any] = {}
        for k, v in list(obj.items())[:25]:
            if is_sensitive_key(str(k)):
                label = classify_value_shape(v) if isinstance(v, str) else None
                out[str(k)] = f"<redacted:{label or type_name(v)}>"
            else:
                out[str(k)] = json_shape(v, depth=depth + 1, max_depth=max_depth)
        if len(obj) > 25:
            out["..."] = f"+{len(obj) - 25} keys"
        return out
    if isinstance(obj, list):
        if not obj:
            return []
        return [json_shape(obj[0], depth=depth + 1, max_depth=max_depth)]
    return type_name(obj)


# ------------------------------------------------------------------ protobuf
def _varint(buf: bytes, i: int) -> tuple[int, int] | None:
    shift = 0
    val = 0
    for n in range(10):
        if i + n >= len(buf):
            return None
        b = buf[i + n]
        val |= (b & 0x7F) << shift
        if not b & 0x80:
            return val, i + n + 1
        shift += 7
    return None


def parse_protobuf(buf: bytes, *, depth: int = 0) -> dict[str, Any] | None:
    """Parse as schemaless protobuf. None when it is not a clean full parse."""
    if not buf or len(buf) > MAX_SCAN_BYTES:
        return None
    i = 0
    fields: dict[int, dict[str, Any]] = {}
    total = 0
    while i < len(buf):
        tag = _varint(buf, i)
        if tag is None:
            return None
        key, i = tag
        num, wt = key >> 3, key & 7
        if num < 1 or num > 536870911 or wt not in _WIRE:
            return None
        info = fields.setdefault(num, {"wire": _WIRE[wt], "count": 0})
        if info["wire"] != _WIRE[wt]:
            info["wire"] = "mixed"
        info["count"] += 1
        total += 1
        if wt == 0:
            v = _varint(buf, i)
            if v is None:
                return None
            i = v[1]
        elif wt == 1:
            i += 8
        elif wt == 5:
            i += 4
        else:
            ln = _varint(buf, i)
            if ln is None:
                return None
            n, i = ln
            if i + n > len(buf):
                return None
            chunk = buf[i : i + n]
            i += n
            if "sub" not in info and "as" not in info:
                kind = _len_kind(chunk, depth)
                if isinstance(kind, dict):
                    info["as"] = "message"
                    info["sub"] = kind["fields"]
                else:
                    info["as"] = kind
        if i > len(buf):
            return None
        if total > 5000:
            break
    return {
        "fields": {str(k): fields[k] for k in sorted(fields)[:40]},
        "field_count": len(fields),
        "total_fields": total,
    }


def _len_kind(chunk: bytes, depth: int) -> Any:
    if not chunk:
        return "empty"
    try:
        s = chunk.decode("utf-8")
        if all(c.isprintable() or c in "\r\n\t" for c in s):
            return "string"
    except UnicodeDecodeError:
        pass
    if depth < 2:
        sub = parse_protobuf(chunk, depth=depth + 1)
        if sub and sub["field_count"]:
            return sub
    return "bytes"


def split_grpc_frames(raw: bytes) -> list[tuple[int, bytes]] | None:
    """Split length-prefixed gRPC(-web) frames: 1 flag byte + 4 byte BE length."""
    frames: list[tuple[int, bytes]] = []
    i = 0
    while i < len(raw):
        if i + 5 > len(raw):
            return None
        flag = raw[i]
        if flag & 0x7E:  # only compressed(1) and trailer(0x80) bits are valid
            return None
        n = int.from_bytes(raw[i + 1 : i + 5], "big")
        if i + 5 + n > len(raw):
            return None
        frames.append((flag, raw[i + 5 : i + 5 + n]))
        i += 5 + n
        if len(frames) > 2000:
            break
    return frames or None


def summarize_grpc(raw: bytes) -> dict[str, Any] | None:
    frames = split_grpc_frames(raw[:MAX_SCAN_BYTES])
    if not frames:
        return None
    data = [f for f in frames if not f[0] & 0x80]
    trailers = [f for f in frames if f[0] & 0x80]
    out: dict[str, Any] = {
        "frames": len(frames),
        "data_frames": len(data),
        "compressed_frames": sum(1 for f in frames if f[0] & 1),
        "frame_sizes": [len(f[1]) for f in frames[:10]],
    }
    for flag, payload in data:
        if flag & 1:
            continue
        pb = parse_protobuf(payload)
        if pb:
            out["message"] = pb
            break
    if trailers:
        names: list[str] = []
        status = None
        for _, payload in trailers:
            for line in payload.decode("latin-1").splitlines():
                name, _, val = line.partition(":")
                name = name.strip().lower()
                if name:
                    names.append(name)
                if name == "grpc-status" and val.strip().isdigit():
                    status = int(val.strip())
        out["trailers"] = names[:10]
        if status is not None:
            out["grpc_status"] = status
    return out


def decode_grpc_text(text: str) -> bytes | None:
    """application/grpc-web-text bodies are base64 (possibly several chunks)."""
    try:
        s = re.sub(r"\s+", "", text)
        out = b""
        for part in re.findall(r"[A-Za-z0-9+/]+={0,2}", s):
            out += base64.b64decode(part + "=" * (-len(part) % 4))
        return out or None
    except (binascii.Error, ValueError):
        return None


# ----------------------------------------------------------------- msgpack
class _MP(Exception):
    pass


def _mp_read(b: bytes, i: int, depth: int, budget: list[int]) -> tuple[Any, int]:
    budget[0] -= 1
    if budget[0] < 0 or depth > 12 or i >= len(b):
        raise _MP
    c = b[i]
    i += 1

    def take(n: int) -> bytes:
        nonlocal i
        if i + n > len(b):
            raise _MP
        d = b[i : i + n]
        i += n
        return d

    def arr(n: int):
        nonlocal i
        out = []
        for _ in range(n):
            v, i = _mp_read(b, i, depth + 1, budget)
            out.append(v)
        return out

    def mp(n: int):
        nonlocal i
        out = {}
        for _ in range(n):
            k, i = _mp_read(b, i, depth + 1, budget)
            v, i = _mp_read(b, i, depth + 1, budget)
            out[k if isinstance(k, (str, int)) else repr(k)] = v
        return out

    def text(n: int) -> str:
        try:
            return take(n).decode("utf-8")
        except UnicodeDecodeError:
            raise _MP

    if c <= 0x7F:
        return c, i
    if c >= 0xE0:
        return c - 256, i
    if 0x80 <= c <= 0x8F:
        return mp(c & 0x0F), i
    if 0x90 <= c <= 0x9F:
        return arr(c & 0x0F), i
    if 0xA0 <= c <= 0xBF:
        return text(c & 0x1F), i
    if c == 0xC0:
        return None, i
    if c in (0xC2, 0xC3):
        return c == 0xC3, i
    sizes = {0xCC: 1, 0xCD: 2, 0xCE: 4, 0xCF: 8, 0xD0: 1, 0xD1: 2, 0xD2: 4, 0xD3: 8}
    if c in sizes:
        return int.from_bytes(take(sizes[c]), "big", signed=c >= 0xD0), i
    if c == 0xCA:
        take(4)
        return 0.0, i
    if c == 0xCB:
        take(8)
        return 0.0, i
    if c in (0xC4, 0xC5, 0xC6):
        n = int.from_bytes(take({0xC4: 1, 0xC5: 2, 0xC6: 4}[c]), "big")
        return bytes(take(n)), i
    if c in (0xD9, 0xDA, 0xDB):
        n = int.from_bytes(take({0xD9: 1, 0xDA: 2, 0xDB: 4}[c]), "big")
        return text(n), i
    if c in (0xDC, 0xDD):
        return arr(int.from_bytes(take(2 if c == 0xDC else 4), "big")), i
    if c in (0xDE, 0xDF):
        return mp(int.from_bytes(take(2 if c == 0xDE else 4), "big")), i
    if c in (0xD4, 0xD5, 0xD6, 0xD7, 0xD8):
        take(1 + {0xD4: 1, 0xD5: 2, 0xD6: 4, 0xD7: 8, 0xD8: 16}[c])
        return b"", i
    if c in (0xC7, 0xC8, 0xC9):
        n = int.from_bytes(take({0xC7: 1, 0xC8: 2, 0xC9: 4}[c]), "big")
        take(1 + n)
        return b"", i
    raise _MP


def parse_msgpack(raw: bytes) -> dict[str, Any] | None:
    """Fully decode one MessagePack value; return its shape (not values)."""
    if not raw or len(raw) > MAX_SCAN_BYTES:
        return None
    try:
        val, end = _mp_read(raw, 0, 0, [20000])
    except (_MP, RecursionError):
        return None
    if end != len(raw):
        return None
    out: dict[str, Any] = {"top_level": type_name(val), "shape": json_shape(val, max_depth=3)}
    if isinstance(val, dict):
        out["keys"] = [str(k) for k in list(val)[:25]]
    elif isinstance(val, list):
        out["length"] = len(val)
    return out


# --------------------------------------------------------------------- CSV
def summarize_csv(text: str, mime: str = "", path: str = "") -> dict[str, Any] | None:
    if not text or "\n" not in text.strip():
        return None
    first = (text[:8000].splitlines() or [""])[0]
    counts = {d: first.count(d) for d in (",", "\t", ";", "|")}
    delim = max(counts, key=lambda d: counts[d])
    if "tab-separated" in mime or path.endswith(".tsv"):
        delim = "\t"
    if counts[delim] == 0:
        return None
    try:
        rows = [r for r in csv.reader(io.StringIO(text), delimiter=delim) if r]
    except csv.Error:
        return None
    if not rows:
        return None
    header = [c.strip() for c in rows[0]]
    headerish = sum(1 for c in header if c and not re.fullmatch(r"-?[\d.,]+", c)) >= max(
        1, len(header) // 2
    )
    return {
        "delimiter": {",": "comma", "\t": "tab", ";": "semicolon", "|": "pipe"}[delim],
        "columns": len(header),
        "header": [h[:60] for h in header[:40]] if headerish else None,
        "rows": len(rows) - (1 if headerish else 0),
    }


# --------------------------------------------------------------------- SSE
def looks_like_sse(text: str) -> bool:
    lines = [ln for ln in text[:4000].splitlines() if ln.strip()]
    if not lines:
        return False
    return all(re.match(r"^(event|data|id|retry):|^:", ln) for ln in lines[:10]) and any(
        ln.startswith(("data:", "event:")) for ln in lines[:10]
    )


def summarize_sse(text: str) -> dict[str, Any] | None:
    if not text.strip():
        return None
    names: dict[str, int] = {}
    shapes: dict[str, int] = {}
    state: dict[str, Any] = {"count": 0, "event": None, "data": []}
    comments = 0

    def flush() -> None:
        if state["event"] is None and not state["data"]:
            return
        state["count"] += 1
        n = state["event"] or "message"
        names[n] = names.get(n, 0) + 1
        if state["data"]:
            body = "\n".join(state["data"])
            try:
                sh = json.dumps(json_shape(safe_loads(body), max_depth=3), sort_keys=True)
            except ValueError:
                sh = "text"
            if sh not in shapes and len(shapes) >= 5:
                sh = "(other)"
            shapes[sh] = shapes.get(sh, 0) + 1
        state["event"], state["data"] = None, []

    for line in text.splitlines():
        if not line:
            flush()
        elif line.startswith(":"):
            comments += 1
        elif line.startswith("event:"):
            state["event"] = line[6:].strip()[:60]
        elif line.startswith("data:"):
            state["data"].append(line[5:].lstrip(" "))
    flush()
    if state["count"] == 0:
        return None
    out: dict[str, Any] = {
        "events": state["count"],
        "event_names": dict(sorted(names.items(), key=lambda kv: -kv[1])[:15]),
        "data_shapes": dict(sorted(shapes.items(), key=lambda kv: -kv[1])),
    }
    if comments:
        out["comments"] = comments
    return out


# ----------------------------------------------------------- dispatch (bytes)
def sniff_binary(raw: bytes, mime: str) -> tuple[str, dict[str, Any]] | None:
    """Detect protobuf / grpc-web / msgpack in raw bytes, hinted by content-type."""
    m = (mime or "").lower().split(";")[0].strip()
    if not raw:
        return None
    if m.startswith("application/grpc"):
        s = summarize_grpc(raw)
        if s:
            return ("grpc-web" if "web" in m else "grpc"), s
    if "protobuf" in m or m.endswith("+proto"):
        pb = parse_protobuf(raw)
        if pb:
            return "protobuf", pb
    if "msgpack" in m or "messagepack" in m:
        mp = parse_msgpack(raw)
        if mp:
            return "msgpack", mp
    if m in ("", "application/octet-stream", "binary/octet-stream", "application/x-binary"):
        try:
            if all(c.isprintable() or c in "\r\n\t" for c in raw[:512].decode("utf-8")):
                return None  # plain text, not a binary encoding
        except UnicodeDecodeError:
            pass
        g = summarize_grpc(raw)
        if g and raw[0] in (0, 0x80):
            return "grpc-web", g
        pb = parse_protobuf(raw)
        if pb and pb["field_count"] >= 1:
            return "protobuf", pb
        mp = parse_msgpack(raw)
        if mp and mp["top_level"] in ("object", "array") and (
            mp.get("keys") or mp.get("length", 0) >= 2
        ):
            return "msgpack", mp
    return None
