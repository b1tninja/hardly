"""Find repeated requests that may be polling or wasted traffic."""

from __future__ import annotations

import sqlite3
from typing import Any


def find_duplicates(
    conn: sqlite3.Connection,
    *,
    host: str | None = None,
    exclude_noise: bool = True,
    min_count: int = 2,
    limit: int = 30,
) -> dict[str, Any]:
    """Group by method + path_template (+ host); report repeats."""
    clauses = ["method != 'OPTIONS'"]
    params: list[Any] = []
    if exclude_noise:
        clauses.append("is_noise = 0")
    if host:
        clauses.append("host = ?")
        params.append(host.lower())
    where = " AND ".join(clauses)
    rows = conn.execute(
        f"""
        SELECT method, host, path_template, COUNT(*) AS cnt,
               GROUP_CONCAT(entry_id) AS ids,
               GROUP_CONCAT(DISTINCT status) AS statuses
        FROM entries
        WHERE {where}
        GROUP BY method, host, path_template
        HAVING COUNT(*) >= ?
        ORDER BY cnt DESC, host, path_template
        LIMIT ?
        """,
        [*params, max(min_count, 2), min(limit, 80)],
    ).fetchall()

    groups = []
    for row in rows:
        ids = [int(x) for x in (row["ids"] or "").split(",") if x][:20]
        groups.append(
            {
                "method": row["method"],
                "host": row["host"],
                "path_template": row["path_template"],
                "count": row["cnt"],
                "statuses": row["statuses"],
                "entry_ids": ids,
            }
        )
    return {
        "host": host,
        "min_count": min_count,
        "group_count": len(groups),
        "groups": groups,
        "next": (
            "High counts may be polling or retries — use hardly_params / "
            "hardly_compare_entries on sample entry_ids."
        ),
    }
