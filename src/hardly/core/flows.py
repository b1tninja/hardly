"""Chronological request flows."""

from __future__ import annotations

import sqlite3
from typing import Any


def get_flow(
    conn: sqlite3.Connection,
    *,
    host: str | None = None,
    path_prefix: str | None = None,
    exclude_options: bool = True,
    exclude_noise: bool = True,
    limit: int = 100,
    offset: int = 0,
) -> dict:
    """Return chronological entries for reconstructing auth/business flows."""
    clauses = ["1=1"]
    params: list[Any] = []
    if host:
        clauses.append("e.host = ?")
        params.append(host.lower())
    if path_prefix:
        clauses.append("e.path LIKE ?")
        params.append(path_prefix + "%")
    if exclude_noise:
        clauses.append("e.is_noise = 0")
    if exclude_options:
        clauses.append("e.method != 'OPTIONS'")

    where = " AND ".join(clauses)
    total = conn.execute(
        f"SELECT COUNT(*) AS c FROM entries e WHERE {where}", params
    ).fetchone()["c"]

    rows = conn.execute(
        f"""
        SELECT e.entry_id, e.method, e.host, e.path, e.path_template,
               e.status, e.started_datetime, e.time_ms, e.query_json
        FROM entries e
        WHERE {where}
        ORDER BY e.started_datetime ASC, e.entry_id ASC
        LIMIT ? OFFSET ?
        """,
        params + [limit, offset],
    ).fetchall()

    steps = [
        {
            "entry_id": r["entry_id"],
            "method": r["method"],
            "host": r["host"],
            "path": r["path"],
            "path_template": r["path_template"],
            "status": r["status"],
            "started_datetime": r["started_datetime"],
            "time_ms": r["time_ms"],
        }
        for r in rows
    ]
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "steps": steps,
    }
