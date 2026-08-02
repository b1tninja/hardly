"""Stream-ingest HAR files into SQLite."""

from __future__ import annotations

import hashlib
import json
from decimal import Decimal
from pathlib import Path
from typing import Any

import ijson


def _num(value: Any) -> float | int | None:
    """Coerce ijson Decimals / numbers to SQLite-friendly types."""
    if value is None:
        return None
    if isinstance(value, Decimal):
        if value == value.to_integral_value():
            return int(value)
        return float(value)
    if isinstance(value, (int, float)):
        return value
    try:
        return float(value)
    except (TypeError, ValueError):
        return None

from hardly.core.filters import is_noise
from hardly.core.redact import redact_body_text, redact_header_value, is_sensitive_header
from hardly.core.urls import parse_url, path_template
from hardly.index.schema import connect, init_db

PREVIEW_CHARS = 8000


def _header_list(headers: list | None) -> list[dict]:
    if not headers:
        return []
    return [{"name": h.get("name", ""), "value": h.get("value", "")} for h in headers]


def _body_text(content: dict | None) -> tuple[str | None, str | None, int]:
    """Return (text, mime, size) from HAR content/postData."""
    if not content:
        return None, None, 0
    mime = content.get("mimeType") or content.get("mime_type")
    text = content.get("text")
    size = _num(content.get("size"))
    if text is None:
        # multipart params — summarize
        params = content.get("params")
        if params:
            summary = []
            for p in params:
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
    # Skip base64 binary previews
    encoding = content.get("encoding")
    if encoding == "base64" and mime and not str(mime).startswith(
        ("application/json", "text/", "application/xml", "application/javascript")
    ):
        return f"(binary base64, {size} bytes)", mime, int(size)
    return text, mime, int(size)


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
    if text is not None:
        redacted = redact_body_text(text, max_chars=PREVIEW_CHARS)
        preview = redacted["text"]
        sha = hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()
        size = redacted["size"] or size
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


def ingest_har(har_path: str | Path, db_path: str | Path) -> dict[str, Any]:
    """Parse HAR at har_path into SQLite at db_path. Returns summary stats."""
    har_path = Path(har_path).resolve()
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    if db_path.exists():
        db_path.unlink()

    conn = connect(str(db_path))
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

    counts = {
        "entries": 0,
        "noise": 0,
        "api": 0,
        "hosts": {},
        "methods": {},
        "statuses": {},
    }

    with har_path.open("rb") as f:
        for entry_id, entry in enumerate(ijson.items(f, "log.entries.item")):
            req = entry.get("request") or {}
            resp = entry.get("response") or {}
            method = (req.get("method") or "GET").upper()
            url = req.get("url") or ""
            parsed = parse_url(url)
            status = _num(resp.get("status"))
            if status is not None:
                status = int(status)
            content = resp.get("content") or {}
            mime = content.get("mimeType")
            post = req.get("postData")

            noise = is_noise(method=method, url=url, status=status, mime=mime)

            req_text, req_mime, req_size = _body_text(post)
            resp_text, resp_mime, resp_size = _body_text(content)
            mime = mime or resp_mime
            time_ms = _num(entry.get("time"))

            conn.execute(
                """
                INSERT INTO entries (
                    entry_id, method, scheme, host, path, path_template,
                    query_json, query_raw, status, mime, started_datetime, time_ms,
                    is_noise, has_req_body, has_resp_body
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    entry_id,
                    method,
                    parsed["scheme"],
                    parsed["host"],
                    parsed["path"],
                    path_template(parsed["path"]),
                    json.dumps(parsed["query"]) if parsed["query"] else None,
                    parsed["query_raw"] or None,
                    status,
                    mime,
                    entry.get("startedDateTime"),
                    time_ms,
                    1 if noise else 0,
                    1 if req_text else 0,
                    1 if resp_text else 0,
                ),
            )

            _store_headers(conn, entry_id, "request", _header_list(req.get("headers")))
            _store_headers(conn, entry_id, "response", _header_list(resp.get("headers")))
            _store_body(conn, entry_id, "request", req_text, req_mime or (post or {}).get("mimeType"), req_size)
            _store_body(conn, entry_id, "response", resp_text, mime, resp_size)

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
    conn.commit()
    conn.close()

    return {
        "har_path": str(har_path),
        "db_path": str(db_path.resolve()),
        "entries": counts["entries"],
        "noise": counts["noise"],
        "api": counts["api"],
        "hosts": dict(sorted(counts["hosts"].items(), key=lambda x: -x[1])),
        "methods": counts["methods"],
        "statuses": counts["statuses"],
        "har_size": stat.st_size,
        "har_mtime": stat.st_mtime,
    }
