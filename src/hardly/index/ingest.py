"""Stream-ingest HAR files into SQLite."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from decimal import Decimal
from pathlib import Path
from typing import Any

from hardly.core.filters import is_noise
from hardly.core.har_io import ijson_items
from hardly.core.redact import (
    JWT_RE,
    classify_value_shape,
    is_sensitive_header,
    is_sensitive_key,
    redact_body_text,
    redact_header_value,
    redact_query_dict,
    redact_query_string,
    redact_url,
)
from hardly.core.safe_json import safe_loads
from hardly.core.urls import parse_url, path_template
from hardly.index.atomic import persist_connection, remove_quietly, tmp_path_for
from hardly.index.schema import connect_ingest, connect_memory, init_db


def _num(value: Any) -> float | int | None:
    """Coerce ijson Decimals / numbers to SQLite-friendly types.

    Booleans, NaN and infinities are not numbers a HAR field can usefully be.
    A non-finite Decimal used to raise when later coerced with ``int()`` and
    abort the whole import.
    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, Decimal):
        if not value.is_finite():
            return None
        if value == value.to_integral_value():
            try:
                return int(value)
            except (OverflowError, ValueError):
                return None
        return float(value)
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            return None
        return value
    if isinstance(value, int):
        return value
    try:
        return float(value)
    except (TypeError, ValueError, OverflowError):
        return None


def _sqlite_int(value: Any, default: int | None = 0, *, lo: int | None = None, hi: int | None = None) -> int | None:
    """An integer SQLite can store, or ``default`` when the HAR value is nonsense."""
    n = _num(value)
    if n is None:
        return default
    try:
        i = int(n)
    except (OverflowError, ValueError, ArithmeticError):
        return default
    if i > 2**62 or i < -(2**62):
        return default
    if lo is not None and i < lo:
        return default
    if hi is not None and i > hi:
        return default
    return i


PREVIEW_CHARS = 8000
# Bump when ingest output changes meaning (redaction, shapes, signals) so cached
# indexes built by older versions are rebuilt instead of reused.
INDEX_VERSION = 9
# HTML portals often bury forms after scripts/CSS; keep more for hardly_page_forms.
HTML_PREVIEW_CHARS = 64_000


def _header_list(headers: list | None) -> list[dict]:
    if not isinstance(headers, list):
        return []
    out = []
    for h in headers:
        if not isinstance(h, dict):
            continue
        name = h.get("name", "")
        value = h.get("value", "")
        out.append({
            "name": name if isinstance(name, str) else str(name or ""),
            "value": value if isinstance(value, str) else ("" if value is None else str(value)),
        })
    return out


def _header_present(headers: Any, name: str) -> bool:
    if not isinstance(headers, list):
        return False
    want = name.lower()
    return any(
        isinstance(h, dict) and str(h.get("name") or "").lower() == want for h in headers
    )


def _cookie_pairs(cookies: Any) -> list[tuple[str, str]]:
    """Name/value pairs from a HAR ``cookies`` array. Values stay in memory for shape classification only."""
    if not isinstance(cookies, list):
        return []
    out: list[tuple[str, str]] = []
    for item in cookies:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        if not isinstance(name, str) or not name.strip():
            continue
        value = item.get("value")
        out.append((name.strip(), "" if value is None else str(value)))
        if len(out) >= 200:
            break
    return out


def _note_cookies(conn, entry_id: int, side: str, pairs: list[tuple[str, str]]) -> None:
    """Record cookie names (and value shapes) when the HAR had no Cookie / Set-Cookie header."""
    for name, value in pairs:
        _record_shape(conn, entry_id, side, "cookie", classify_value_shape(value) or "cookie", name)


def _initiator(entry: dict) -> tuple[str | None, str | None]:
    """Extract Chrome-style _initiator type + URL (stack frame fallback)."""
    init = entry.get("_initiator") or entry.get("initiator") or {}
    if not isinstance(init, dict):
        return None, None
    init_type = init.get("type")
    url = init.get("url")
    if not url:
        stack = init.get("stack") or {}
        frames = stack.get("callFrames") or []
        if frames and isinstance(frames[0], dict):
            url = frames[0].get("url")
        parent = stack.get("parent") or {}
        if not url and isinstance(parent, dict):
            pframes = parent.get("callFrames") or []
            if pframes and isinstance(pframes[0], dict):
                url = pframes[0].get("url")
    if url and len(str(url)) > 2000:
        url = str(url)[:2000]
    return (
        str(init_type) if init_type else None,
        redact_url(str(url)) if url else None,  # a stored URL never carries a secret value
    )


def _is_textual_mime(mime: str | None) -> bool:
    m = (mime or "").split(";", 1)[0].strip().lower()
    return (
        m.startswith("text/")
        or m in {"application/json", "application/xml", "application/javascript",
                 "application/x-www-form-urlencoded", "application/graphql", "application/xhtml+xml"}
        or m.endswith(("+json", "+xml"))
    )


def _decode_base64_text(text: str | None) -> str | None:
    import base64
    import binascii

    if not text:
        return None
    try:
        raw = base64.b64decode(text, validate=False)
    except (binascii.Error, ValueError):
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("utf-8", "replace")


def _body_text(content: dict | None) -> tuple[str | None, str | None, int]:
    """Return (text, mime, size) from HAR content/postData."""
    if not isinstance(content, dict):
        return None, None, 0
    mime_v = content.get("mimeType") or content.get("mime_type")
    mime = mime_v if isinstance(mime_v, str) else None
    text = content.get("text")
    if text is not None and not isinstance(text, str):
        text = json.dumps(text, default=str) if not isinstance(text, (bytes, bytearray)) else None
    size = _sqlite_int(content.get("size"), default=None, lo=-(2**62), hi=2**62)
    if text is None:
        # multipart params — summarize
        params = content.get("params")
        if isinstance(params, list) and params:
            summary = []
            for p in params:
                if not isinstance(p, dict):
                    continue
                name = p.get("name", "")
                if p.get("fileName"):
                    summary.append(
                        {
                            "name": name,
                            "fileName": p.get("fileName"),
                            "contentType": p.get("contentType"),
                            "value": "(binary)",
                        }
                    )
                else:
                    summary.append({"name": name, "value": p.get("value", "")})
            text = json.dumps(summary)
            size = size or len(text)
        else:
            return None, mime, int(size or 0)
    if size is None:
        size = len(text)
    encoding = content.get("encoding")
    if encoding == "base64":
        if _is_textual_mime(mime):
            # Textual bodies are sometimes stored base64-encoded (proxies,
            # some exporters): decode so every analysis sees the real text.
            decoded = _decode_base64_text(text)
            if decoded is not None:
                return decoded, mime, int(size or len(decoded))
        elif mime:
            return f"(binary base64, {size} bytes)", mime, int(size)
    return text, mime, int(size)


def _raw_bytes(content: dict | None, mime: str | None) -> bytes | None:
    """Raw bytes of a base64-encoded non-textual HAR body (capped), else None."""
    import base64
    import binascii

    if not content or content.get("encoding") != "base64" or _is_textual_mime(mime):
        return None
    text = content.get("text")
    if not isinstance(text, str) or not text or len(text) > 4_000_000:
        return None
    try:
        return base64.b64decode(text, validate=False)
    except (binascii.Error, ValueError):
        return None


def _detect_streams(
    conn, entry_id: int, side: str, mime: str | None, path: str,
    text: str | None, content: dict | None,
) -> None:
    from hardly.core.streams import analyze_body, store_stream

    raw = _raw_bytes(content, mime)
    if raw is None and (text is None or text.startswith("(binary base64")):
        return
    try:
        hit = analyze_body(mime, path, None if raw is not None else text, raw)
    except Exception:  # detectors must never break ingest
        return
    if hit:
        store_stream(conn, entry_id, side, hit[0], hit[1])


def _store_websocket(conn, entry_id: int, entry: dict) -> None:
    from hardly.core.streams import analyze_websocket, store_stream

    msgs = entry.get("_webSocketMessages")
    if not isinstance(msgs, list) or not msgs:
        return
    clean = [
        {k: (_num(v) if k in ("time", "opcode") else v) for k, v in m.items()}
        for m in msgs[:5001]
        if isinstance(m, dict)
    ]
    summary = analyze_websocket(clean)
    if summary:
        summary["messages"] = len(msgs)
        store_stream(conn, entry_id, "messages", "websocket", summary)


def _store_body(
    conn,
    entry_id: int,
    side: str,
    text: str | None,
    mime: str | None,
    size: int,
) -> None:
    if text is None and size == 0:
        return
    preview = None
    sha = None
    double_encoded = False
    if text is not None:
        from hardly.core.json_unwrap import unwrap_double_encoded

        inner = unwrap_double_encoded(text)
        if inner is not None:
            # Hash the wire bytes; preview/shapes use the unwrapped JSON.
            sha = hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()
            text = json.dumps(inner, ensure_ascii=False)
            double_encoded = True
    if text is not None:
        limit = (
            HTML_PREVIEW_CHARS
            if mime and "html" in str(mime).lower()
            else PREVIEW_CHARS
        )
        redacted = redact_body_text(text, max_chars=limit, markup=False)
        preview = redacted["text"]
        if sha is None:
            sha = hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()
        size = redacted["size"] or size
    if double_encoded:
        conn.execute(
            "INSERT INTO body_signals (entry_id, kind, name) "
            "VALUES (?, 'encoding', 'double-encoded-json')",
            (entry_id,),
        )
    if text is not None and side == "response" and mime and "html" in str(mime).lower() and len(text) > HTML_PREVIEW_CHARS:
        from hardly.core.grids import html_grid_signals

        for name in html_grid_signals(text):
            conn.execute(
                "INSERT INTO body_signals (entry_id, kind, name) VALUES (?, 'grid', ?)",
                (entry_id, name),
            )
    conn.execute(
        """
        INSERT OR REPLACE INTO bodies (entry_id, side, content_type, size, preview_text, sha256)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (entry_id, side, mime, size, preview, sha),
    )
    if preview:
        conn.execute(
            "INSERT INTO bodies_fts (entry_id, side, preview_text) VALUES (?, ?, ?)",
            (entry_id, side, preview),
        )


def _store_headers(conn, entry_id: int, side: str, headers: list[dict]) -> None:
    for h in headers:
        name = h.get("name", "")
        value = str(h.get("value", ""))
        redacted = redact_header_value(name, value)
        raw = None if is_sensitive_header(name) else value
        conn.execute(
            """
            INSERT INTO headers (entry_id, side, name, value_redacted, value_raw)
            VALUES (?, ?, ?, ?, ?)
            """,
            (entry_id, side, name, redacted, raw),
        )
        _record_header_shapes(conn, entry_id, side, name, value)


def _record_shape(
    conn,
    entry_id: int,
    side: str,
    where_kind: str,
    shape: str,
    name: str | None = None,
) -> None:
    conn.execute(
        """
        INSERT INTO value_shapes (entry_id, side, where_kind, name, shape)
        VALUES (?, ?, ?, ?, ?)
        """,
        (entry_id, side, where_kind, name, shape),
    )


def _record_header_shapes(
    conn, entry_id: int, side: str, name: str, value: str
) -> None:
    low = name.lower()
    if low in {"cookie", "set-cookie"}:
        # First name=value only for Set-Cookie; Cookie may have several.
        parts = value.split(";")
        pairs = []
        if low == "set-cookie":
            if parts and "=" in parts[0]:
                n, _, v = parts[0].partition("=")
                pairs.append((n.strip(), v.strip()))
        else:
            for part in parts:
                part = part.strip()
                if "=" not in part:
                    continue
                n, _, v = part.partition("=")
                n = n.strip()
                if n.lower() in {
                    "path",
                    "domain",
                    "expires",
                    "max-age",
                    "secure",
                    "httponly",
                    "samesite",
                }:
                    continue
                pairs.append((n, v.strip()))
        for n, v in pairs:
            shape = classify_value_shape(v)
            if shape:
                _record_shape(conn, entry_id, side, "cookie", shape, n)
        return
    shape = classify_value_shape(value)
    if shape:
        _record_shape(conn, entry_id, side, "header", shape, name or None)


def _record_query_shapes(conn, entry_id: int, query: dict[str, Any] | None) -> None:
    if not query:
        return
    for name, value in query.items():
        candidates = value if isinstance(value, list) else [value]
        for item in candidates:
            if not isinstance(item, str):
                continue
            shape = classify_value_shape(item)
            if shape:
                _record_shape(conn, entry_id, "request", "query", shape, str(name))


def _record_body_shapes(
    conn, entry_id: int, side: str, text: str | None
) -> None:
    if not text or len(text) > 200_000:
        return
    if JWT_RE.search(text):
        _record_shape(conn, entry_id, side, "body", "jwt", None)
    stripped = text.strip()
    # A bare token body (no markup, no spaces) is itself a value.
    if len(stripped) <= 4096 and " " not in stripped and "<" not in stripped and not stripped.startswith(("{", "[")):
        shape = classify_value_shape(stripped)
        if shape and shape != "jwt":
            _record_shape(conn, entry_id, side, "body", shape, None)
        return
    # Structured bodies: judge string *values* under token-like keys, never the
    # whole document (any long path/hash/class name would otherwise match).
    if stripped.startswith(("{", "[")):
        try:
            data = safe_loads(stripped)
        except ValueError:
            return
        seen: set[tuple[str, str]] = set()

        def walk(obj: Any, key: str | None, depth: int) -> None:
            if depth > 6 or len(seen) > 40:
                return
            if isinstance(obj, dict):
                for k, v in list(obj.items())[:60]:
                    walk(v, str(k), depth + 1)
            elif isinstance(obj, list):
                for item in obj[:30]:
                    walk(item, key, depth + 1)
            elif isinstance(obj, str) and key and is_sensitive_key(key):
                shape = classify_value_shape(obj)
                if shape and shape != "jwt" and (key, shape) not in seen:
                    seen.add((key, shape))
                    _record_shape(conn, entry_id, side, "body", shape, key)

        walk(data, None, 0)


def _fill_query(parsed: dict[str, Any], req: dict) -> dict[str, Any]:
    """Use ``request.queryString`` when the URL itself has no query.

    Some exporters leave the query only in the array. When the URL already has
    one, that is the wire form and wins.
    """
    if parsed.get("query_raw"):
        return parsed
    items = req.get("queryString")
    if not isinstance(items, list) or not items:
        return parsed
    flat: dict[str, Any] = {}
    pieces: list[str] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        if not isinstance(name, str) or name == "":
            continue
        value = item.get("value")
        text = "" if value is None else str(value)
        prev = flat.get(name)
        if prev is None:
            flat[name] = text
        elif isinstance(prev, list):
            prev.append(text)
        else:
            flat[name] = [prev, text]
        pieces.append(f"{name}={text}")
        if len(pieces) >= 2000:
            break
    if not pieces:
        return parsed
    out = dict(parsed)
    out["query"] = flat
    out["query_raw"] = "&".join(pieces)
    return out


def ingest_into(har_path: str | Path, conn: sqlite3.Connection) -> dict[str, Any]:
    """Parse HAR at har_path into an empty database behind ``conn``. Leaves ``conn`` open."""
    har_path = Path(har_path).resolve()
    init_db(conn)

    stat = har_path.stat()
    conn.execute(
        "INSERT INTO meta (key, value) VALUES (?, ?)",
        ("har_path", str(har_path)),
    )
    conn.execute(
        "INSERT INTO meta (key, value) VALUES (?, ?)",
        ("har_size", str(stat.st_size)),
    )
    conn.execute(
        "INSERT INTO meta (key, value) VALUES (?, ?)",
        ("har_mtime", str(stat.st_mtime)),
    )
    conn.execute(
        "INSERT INTO meta (key, value) VALUES (?, ?)",
        ("index_version", str(INDEX_VERSION)),
    )

    counts = {
        "entries": 0,
        "skipped": 0,
        "noise": 0,
        "api": 0,
        "hosts": {},
        "methods": {},
        "statuses": {},
    }

    with har_path.open("rb") as f:
        for entry_id, entry in enumerate(ijson_items(f, "log.entries.item")):
            if not isinstance(entry, dict):
                counts["skipped"] += 1
                continue
            req = entry.get("request") if isinstance(entry.get("request"), dict) else {}
            resp = entry.get("response") if isinstance(entry.get("response"), dict) else {}
            raw_method = req.get("method")
            method = raw_method.strip().upper() if isinstance(raw_method, str) and raw_method.strip() else "GET"
            method = method[:40]
            raw_url = req.get("url")
            url = raw_url if isinstance(raw_url, str) else ""
            parsed = _fill_query(parse_url(url), req)
            status = _sqlite_int(resp.get("status"), default=None, lo=-1, hi=9999)
            content = resp.get("content") if isinstance(resp.get("content"), dict) else {}
            mime = content.get("mimeType") if isinstance(content.get("mimeType"), str) else None
            post = req.get("postData") if isinstance(req.get("postData"), dict) else None

            noise = is_noise(method=method, url=url, status=status, mime=mime)

            req_text, req_mime, req_size = _body_text(post)
            resp_text, resp_mime, resp_size = _body_text(content)
            mime = mime or resp_mime
            time_ms = _num(entry.get("time"))
            init_type, init_url = _initiator(entry)

            conn.execute(
                """
                INSERT INTO entries (
                    entry_id, method, scheme, host, path, path_template,
                    query_json, query_raw, status, mime, started_datetime, time_ms,
                    is_noise, has_req_body, has_resp_body,
                    pageref, initiator_type, initiator_url
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    entry_id,
                    method,
                    parsed["scheme"],
                    parsed["host"],
                    parsed["path"],
                    path_template(parsed["path"]),
                    # Secret-bearing values never reach the index (shapes are recorded
                    # from the original below); entry/curl/stub/params read these.
                    json.dumps(redact_query_dict(parsed["query"])) if parsed["query"] else None,
                    redact_query_string(parsed["query_raw"]) or None,
                    status,
                    mime,
                    entry.get("startedDateTime") if isinstance(entry.get("startedDateTime"), str) else None,
                    time_ms,
                    1 if noise else 0,
                    1 if req_text else 0,
                    1 if resp_text else 0,
                    entry.get("pageref") if isinstance(entry.get("pageref"), str) else None,
                    init_type,
                    init_url,
                ),
            )

            _store_headers(conn, entry_id, "request", _header_list(req.get("headers")))
            _store_headers(conn, entry_id, "response", _header_list(resp.get("headers")))
            if parsed.get("userinfo"):
                _record_shape(conn, entry_id, "request", "url", "basic_auth", "userinfo")
            for item in parsed.get("path_params") or []:
                _record_shape(conn, entry_id, "request", "path", item["shape"], item["name"])
            if not _header_present(req.get("headers"), "cookie"):
                _note_cookies(conn, entry_id, "request", _cookie_pairs(req.get("cookies")))
            if not _header_present(resp.get("headers"), "set-cookie"):
                _note_cookies(conn, entry_id, "response", _cookie_pairs(resp.get("cookies")))
            _store_body(
                conn, entry_id, "request", req_text,
                req_mime or (post.get("mimeType") if isinstance(post, dict) else None),
                req_size,
            )
            _store_body(conn, entry_id, "response", resp_text, mime, resp_size)
            _detect_streams(
                conn, entry_id, "request",
                req_mime or (post.get("mimeType") if isinstance(post, dict) else None),
                parsed["path"], req_text, post,
            )
            _detect_streams(conn, entry_id, "response", mime, parsed["path"], resp_text, content)
            _store_websocket(conn, entry_id, entry)
            _record_query_shapes(conn, entry_id, parsed.get("query"))
            _record_body_shapes(conn, entry_id, "request", req_text)
            _record_body_shapes(conn, entry_id, "response", resp_text)

            counts["entries"] += 1
            if noise:
                counts["noise"] += 1
            else:
                counts["api"] += 1
            counts["hosts"][parsed["host"]] = counts["hosts"].get(parsed["host"], 0) + 1
            counts["methods"][method] = counts["methods"].get(method, 0) + 1
            sk = str(status) if status is not None else "none"
            counts["statuses"][sk] = counts["statuses"].get(sk, 0) + 1

            if entry_id % 200 == 0:
                conn.commit()

    conn.execute(
        "INSERT INTO meta (key, value) VALUES (?, ?)",
        ("entry_count", str(counts["entries"])),
    )
    conn.execute(
        "INSERT INTO meta (key, value) VALUES (?, ?)",
        ("skipped_entries", str(counts["skipped"])),
    )
    conn.commit()

    return {
        "har_path": str(har_path),
        "entries": counts["entries"],
        "skipped": counts["skipped"],
        "noise": counts["noise"],
        "api": counts["api"],
        "hosts": dict(sorted(counts["hosts"].items(), key=lambda x: -x[1])),
        "methods": counts["methods"],
        "statuses": counts["statuses"],
        "har_size": stat.st_size,
        "har_mtime": stat.st_mtime,
        "index_version": INDEX_VERSION,
    }


def ingest_memory(har_path: str | Path) -> tuple[dict[str, Any], sqlite3.Connection]:
    """Ingest into a private ``:memory:`` database; returns (stats, live connection).

    Nothing is written to disk. The caller owns the connection (single-connection use only:
    a memory database is invisible to any other connection).
    """
    conn = connect_memory()
    try:
        stats = ingest_into(har_path, conn)
    except BaseException:
        conn.close()
        raise
    stats["db_path"] = ":memory:"
    return stats, conn


def ingest_har(har_path: str | Path, db_path: str | Path) -> dict[str, Any]:
    """Parse HAR at har_path into SQLite at db_path (atomic). Returns summary stats.

    Builds in a temp file, writes a compact WAL-free copy with VACUUM INTO and renames it
    over db_path, so a crash or error never leaves a partial database at db_path.
    """
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    work = tmp_path_for(db_path, "ingest")
    conn = connect_ingest(str(work))
    try:
        stats = ingest_into(har_path, conn)
        persist_connection(conn, db_path)
    finally:
        conn.close()
        remove_quietly(work)
    stats["db_path"] = str(db_path.resolve())
    return stats
