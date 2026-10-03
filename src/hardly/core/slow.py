"""Slowest requests by HAR time_ms."""

from __future__ import annotations

import sqlite3
from typing import Any


def slowest_entries(
    conn: sqlite3.Connection,
    *,
    host: str | None = None,
    exclude_noise: bool = True,
    limit: int = 20,
    min_ms: float = 0,
) -> dict[str, Any]:
    """Return the slowest non-OPTIONS entries."""
    clauses = ["method != 'OPTIONS'", "time_ms IS NOT NULL"]
    params: list[Any] = []
    if exclude_noise:
        clauses.append("is_noise = 0")
    if host:
        clauses.append("host = ?")
        params.append(host.lower())
    if min_ms > 0:
        clauses.append("time_ms >= ?")
        params.append(min_ms)
    where = " AND ".join(clauses)
    rows = conn.execute(
        f"""
        SELECT entry_id, method, host, path, path_template, status, time_ms, mime
        FROM entries
        WHERE {where}
        ORDER BY time_ms DESC, entry_id ASC
        LIMIT ?
        """,
        [*params, min(limit, 50)],
    ).fetchall()
    entries = [
        {
            "entry_id": r["entry_id"],
            "method": r["method"],
            "host": r["host"],
            "path": r["path"],
            "path_template": r["path_template"],
            "status": r["status"],
            "time_ms": r["time_ms"],
            "mime": r["mime"],
        }
        for r in rows
    ]
    total = sum(e["time_ms"] or 0 for e in entries)
    return {
        "host": host,
        "count": len(entries),
        "sum_time_ms": round(total, 1),
        "entries": entries,
        "next": "Inspect with hardly_entry_get; pair slow HTML with hardly_page_forms / hardly_entry_initiators.",
    }
