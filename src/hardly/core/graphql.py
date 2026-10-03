"""Detect GraphQL operations in request bodies."""

from __future__ import annotations

import json
import re
import sqlite3
from typing import Any

_OP_NAME = re.compile(
    r"\b(query|mutation|subscription)\s+([A-Za-z_][A-Za-z0-9_]*)",
    re.I,
)
_ANON = re.compile(r"^\s*(query|mutation|subscription)\b", re.I)


def detect_graphql(
    conn: sqlite3.Connection,
    *,
    host: str | None = None,
    limit: int = 40,
) -> dict[str, Any]:
    """Find GraphQL-looking POSTs and summarize operation names."""
    clauses = [
        "e.is_noise = 0",
        "e.method IN ('POST', 'GET')",
        "b.side = 'request'",
        "b.preview_text IS NOT NULL",
    ]
    params: list[Any] = []
    if host:
        clauses.append("e.host = ?")
        params.append(host.lower())
    where = " AND ".join(clauses)
    rows = conn.execute(
        f"""
        SELECT e.entry_id, e.method, e.host, e.path, e.path_template, e.status,
               b.preview_text, b.content_type
        FROM entries e
        JOIN bodies b ON b.entry_id = e.entry_id
        WHERE {where}
        ORDER BY e.entry_id ASC
        """,
        params,
    ).fetchall()

    ops: list[dict[str, Any]] = []
    by_name: dict[str, int] = {}
    for row in rows:
        parsed = _parse_graphql(row["preview_text"], row["content_type"])
        if not parsed:
            # Path heuristic
            path = (row["path"] or "").lower()
            if "graphql" not in path and "gql" not in path:
                continue
            parsed = {"operation_type": "unknown", "operation_name": None, "has_variables": False}
        name = parsed.get("operation_name") or "(anonymous)"
        by_name[name] = by_name.get(name, 0) + 1
        ops.append(
            {
                "entry_id": row["entry_id"],
                "method": row["method"],
                "host": row["host"],
                "path": row["path"],
                "status": row["status"],
                **parsed,
            }
        )
        if len(ops) >= min(limit, 80):
            break

    return {
        "host": host,
        "operation_count": len(ops),
        "by_name": dict(sorted(by_name.items(), key=lambda x: -x[1])),
        "operations": ops,
        "next": (
            "Use hardly_entry / hardly_schema on entry_ids. "
            "Variables are redacted when sensitive."
        ),
    }


def _parse_graphql(
    text: str, content_type: str | None
) -> dict[str, Any] | None:
    ct = (content_type or "").lower()
    stripped = text.lstrip()
    data = None
    if "json" in ct or stripped.startswith(("{", "[")):
        try:
            data = json.loads(text)
        except (json.JSONDecodeError, TypeError):
            return None
    if not isinstance(data, dict):
        return None
    query = data.get("query")
    if not isinstance(query, str):
        # Apollo batch
        return None
    op_type = None
    op_name = data.get("operationName")
    m = _OP_NAME.search(query)
    if m:
        op_type = m.group(1).lower()
        if not op_name:
            op_name = m.group(2)
    else:
        m2 = _ANON.search(query)
        if m2:
            op_type = m2.group(1).lower()
        elif "graphql" in ct or data.get("variables") is not None:
            op_type = "unknown"
        else:
            return None
    var_keys = []
    variables = data.get("variables")
    if isinstance(variables, dict):
        var_keys = sorted(str(k) for k in list(variables.keys())[:30])
    return {
        "operation_type": op_type or "unknown",
        "operation_name": op_name,
        "has_variables": bool(var_keys),
        "variable_keys": var_keys,
    }
