"""Live request replay (gated)."""

from __future__ import annotations

import json
import sqlite3
from typing import Any

import httpx

from hardly.core.redact import is_sensitive_header, redact_body_text


def probe_entry(
    conn: sqlite3.Connection,
    entry_id: int,
    *,
    confirm: bool = False,
    header_overrides: dict[str, str] | None = None,
    body_override: str | None = None,
    timeout: float = 30.0,
) -> dict:
    """
    Replay a captured request.

    Requires confirm=True. Sensitive headers from the HAR are NOT sent unless
    explicitly provided in header_overrides.
    """
    if not confirm:
        return {
            "error": "probe requires confirm=true",
            "hint": "Pass confirm=true and supply secrets via header_overrides / body_override.",
        }

    row = conn.execute(
        "SELECT * FROM entries WHERE entry_id = ?", (entry_id,)
    ).fetchone()
    if not row:
        return {"error": f"entry_id {entry_id} not found"}

    headers_rows = conn.execute(
        "SELECT name, value_raw, value_redacted FROM headers WHERE entry_id = ? AND side = 'request'",
        (entry_id,),
    ).fetchall()

    headers: dict[str, str] = {}
    skipped_sensitive: list[str] = []
    for h in headers_rows:
        name = h["name"]
        # Skip hop-by-hop / auto headers
        if name.lower() in {
            "content-length",
            "host",
            "connection",
            "transfer-encoding",
            "accept-encoding",
        }:
            continue
        if is_sensitive_header(name):
            skipped_sensitive.append(name)
            continue
        val = h["value_raw"] if h["value_raw"] is not None else h["value_redacted"]
        if val is not None:
            headers[name] = str(val)

    overrides = header_overrides or {}
    headers.update(overrides)

    body_row = conn.execute(
        "SELECT preview_text, size FROM bodies WHERE entry_id = ? AND side = 'request'",
        (entry_id,),
    ).fetchone()

    content: str | bytes | None = body_override
    if content is None and body_row and body_row["preview_text"]:
        # Only use body if it doesn't look fully redacted-only secrets
        content = body_row["preview_text"]

    url = f"{row['scheme']}://{row['host']}{row['path']}"
    if row["query_raw"]:
        url = f"{url}?{row['query_raw']}"

    try:
        with httpx.Client(timeout=timeout, follow_redirects=False) as client:
            resp = client.request(
                row["method"],
                url,
                headers=headers,
                content=content,
            )
    except httpx.HTTPError as exc:
        return {
            "entry_id": entry_id,
            "error": str(exc),
            "url": url,
            "method": row["method"],
            "skipped_sensitive_headers": skipped_sensitive,
        }

    resp_preview = redact_body_text(resp.text, max_chars=4000)
    return {
        "entry_id": entry_id,
        "url": url,
        "method": row["method"],
        "status_code": resp.status_code,
        "response_headers": {
            k: v for k, v in resp.headers.items() if k.lower() not in {"set-cookie"}
        },
        "response_body": resp_preview,
        "skipped_sensitive_headers": skipped_sensitive,
        "applied_overrides": list(overrides.keys()),
    }
