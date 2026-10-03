"""Compare endpoint coverage between two HAR sessions."""

from __future__ import annotations

import sqlite3
from typing import Any


def diff_sessions(
    conn_a: sqlite3.Connection,
    conn_b: sqlite3.Connection,
    *,
    host: str | None = None,
    exclude_noise: bool = True,
) -> dict[str, Any]:
    """Diff path templates between two indexed sessions."""
    set_a = _endpoint_set(conn_a, host=host, exclude_noise=exclude_noise)
    set_b = _endpoint_set(conn_b, host=host, exclude_noise=exclude_noise)
    only_a = sorted(set_a - set_b)
    only_b = sorted(set_b - set_a)
    both = sorted(set_a & set_b)
    return {
        "host": host,
        "a_count": len(set_a),
        "b_count": len(set_b),
        "shared_count": len(both),
        "only_in_a": [
            {"method": m, "host": h, "path_template": p} for m, h, p in only_a[:80]
        ],
        "only_in_b": [
            {"method": m, "host": h, "path_template": p} for m, h, p in only_b[:80]
        ],
        "shared_sample": [
            {"method": m, "host": h, "path_template": p} for m, h, p in both[:20]
        ],
        "next": (
            "only_in_b are new since capture A — useful after a second "
            "recording that reached detail/search the first missed."
        ),
    }


def _endpoint_set(
    conn: sqlite3.Connection,
    *,
    host: str | None,
    exclude_noise: bool,
) -> set[tuple[str, str, str]]:
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
        SELECT DISTINCT method, host, path_template
        FROM entries
        WHERE {where}
        """,
        params,
    ).fetchall()
    return {(r["method"], r["host"], r["path_template"]) for r in rows}
