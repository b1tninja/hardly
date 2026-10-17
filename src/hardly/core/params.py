"""Static vs dynamic parameters across samples of one endpoint."""

from __future__ import annotations

import json
import sqlite3
from collections import defaultdict
from typing import Any
from urllib.parse import parse_qsl

from hardly.core.redact import is_sensitive_key
from hardly.core.safe_json import safe_loads


def param_variance(
    conn: sqlite3.Connection,
    *,
    method: str,
    host: str,
    path_template: str,
    limit: int = 30,
) -> dict[str, Any]:
    """Classify query/body field names as static, dynamic, or sensitive."""
    rows = conn.execute(
        """
        SELECT e.entry_id, e.query_raw,
               b.preview_text AS req_body, b.content_type
        FROM entries e
        LEFT JOIN bodies b ON b.entry_id = e.entry_id AND b.side = 'request'
        WHERE e.method = ? AND e.host = ? AND e.path_template = ?
        ORDER BY e.entry_id ASC
        LIMIT ?
        """,
        (method.upper(), host.lower(), path_template, min(limit, 80)),
    ).fetchall()
    if not rows:
        return {
            "error": "no samples",
            "method": method,
            "host": host,
            "path_template": path_template,
        }

    query_vals: dict[str, set[str]] = defaultdict(set)
    body_vals: dict[str, set[str]] = defaultdict(set)
    for row in rows:
        if row["query_raw"]:
            for k, v in parse_qsl(row["query_raw"], keep_blank_values=True):
                query_vals[k].add(_shape(v))
        text = row["req_body"] or ""
        ct = (row["content_type"] or "").lower()
        if not text:
            continue
        if "json" in ct or text.lstrip().startswith(("{", "[")):
            try:
                data = safe_loads(text)
            except (json.JSONDecodeError, TypeError):
                data = None
            if isinstance(data, dict):
                for k, v in list(data.items())[:40]:
                    body_vals[str(k)].add(_shape(v))
        elif "=" in text:
            for k, v in parse_qsl(text, keep_blank_values=True):
                body_vals[k].add(_shape(v))

    return {
        "method": method.upper(),
        "host": host.lower(),
        "path_template": path_template,
        "sample_count": len(rows),
        "sample_entry_ids": [r["entry_id"] for r in rows[:20]],
        "query": _classify(query_vals),
        "body": _classify(body_vals),
        "next": (
            "dynamic fields need live extraction (hardly_session_trace_value / hardly_session_trace_value). "
            "static fields can be hard-coded in a client."
        ),
    }


def _shape(value: Any) -> str:
    if value is None:
        return "null"
    text = str(value)
    if len(text) > 120:
        return f"len:{len(text)}"
    return text


def _classify(vals: dict[str, set[str]]) -> dict[str, list[dict[str, Any]]]:
    static: list[dict[str, Any]] = []
    dynamic: list[dict[str, Any]] = []
    sensitive: list[dict[str, Any]] = []
    for name, shapes in sorted(vals.items()):
        item = {
            "name": name,
            "distinct": len(shapes),
            "sample_shapes": sorted(shapes)[:5],
        }
        if is_sensitive_key(name) or name.upper().startswith("__VIEWSTATE"):
            sensitive.append(item)
        elif len(shapes) <= 1:
            static.append(item)
        else:
            dynamic.append(item)
    return {"static": static, "dynamic": dynamic, "sensitive": sensitive}
