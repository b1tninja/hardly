"""Compact traffic stats beyond summary hosts/methods."""

from __future__ import annotations

import sqlite3
from typing import Any


def traffic_stats(
    conn: sqlite3.Connection,
    *,
    host: str | None = None,
    exclude_noise: bool = True,
) -> dict[str, Any]:
    """MIME mix, body sizes, status classes, initiator types."""
    clauses = ["1=1"]
    params: list[Any] = []
    if host:
        clauses.append("e.host = ?")
        params.append(host.lower())
    if exclude_noise:
        clauses.append("e.is_noise = 0")
    where = " AND ".join(clauses)

    mime_rows = conn.execute(
        f"""
        SELECT COALESCE(mime, '(none)') AS mime, COUNT(*) AS cnt
        FROM entries e
        WHERE {where}
        GROUP BY mime
        ORDER BY cnt DESC
        LIMIT 20
        """,
        params,
    ).fetchall()

    status_class = conn.execute(
        f"""
        SELECT
          SUM(CASE WHEN status BETWEEN 200 AND 299 THEN 1 ELSE 0 END) AS ok,
          SUM(CASE WHEN status BETWEEN 300 AND 399 THEN 1 ELSE 0 END) AS redirect,
          SUM(CASE WHEN status BETWEEN 400 AND 499 THEN 1 ELSE 0 END) AS client_err,
          SUM(CASE WHEN status BETWEEN 500 AND 599 THEN 1 ELSE 0 END) AS server_err,
          SUM(CASE WHEN status IS NULL OR status < 100 THEN 1 ELSE 0 END) AS other
        FROM entries e
        WHERE {where}
        """,
        params,
    ).fetchone()

    sizes = conn.execute(
        f"""
        SELECT
          COUNT(*) AS bodies,
          SUM(CASE WHEN b.size > 0 THEN b.size ELSE 0 END) AS bytes_sum,
          MAX(b.size) AS bytes_max,
          AVG(CASE WHEN b.size > 0 THEN b.size END) AS bytes_avg
        FROM entries e
        JOIN bodies b ON b.entry_id = e.entry_id AND b.side = 'response'
        WHERE {where}
        """,
        params,
    ).fetchone()

    init_rows = conn.execute(
        f"""
        SELECT COALESCE(initiator_type, '(none)') AS initiator_type, COUNT(*) AS cnt
        FROM entries e
        WHERE {where}
        GROUP BY initiator_type
        ORDER BY cnt DESC
        """,
        params,
    ).fetchall()

    timing = conn.execute(
        f"""
        SELECT
          AVG(time_ms) AS avg_ms,
          MAX(time_ms) AS max_ms,
          SUM(CASE WHEN time_ms >= 1000 THEN 1 ELSE 0 END) AS slow_1s
        FROM entries e
        WHERE {where} AND time_ms IS NOT NULL
        """,
        params,
    ).fetchone()

    from hardly.core.classify import summarize_content

    content = summarize_content(
        conn, host=host, exclude_noise=exclude_noise, limit=300
    )

    return {
        "host": host,
        "mimes": [{"mime": r["mime"], "count": r["cnt"]} for r in mime_rows],
        "content_kinds": content.get("by_kind") or {},
        "status_classes": {
            "2xx": int(status_class["ok"] or 0),
            "3xx": int(status_class["redirect"] or 0),
            "4xx": int(status_class["client_err"] or 0),
            "5xx": int(status_class["server_err"] or 0),
            "other": int(status_class["other"] or 0),
        },
        "response_bodies": {
            "count": int(sizes["bodies"] or 0),
            "bytes_sum": int(sizes["bytes_sum"] or 0),
            "bytes_max": int(sizes["bytes_max"] or 0),
            "bytes_avg": round(float(sizes["bytes_avg"] or 0), 1),
        },
        "initiators": [
            {"type": r["initiator_type"], "count": r["cnt"]} for r in init_rows
        ],
        "timing": {
            "avg_ms": round(float(timing["avg_ms"] or 0), 1),
            "max_ms": float(timing["max_ms"] or 0),
            "slow_ge_1s": int(timing["slow_1s"] or 0),
        },
        "next": (
            "hardly_session_traffic_stats to drill kinds; hardly_session_slow_requests for outliers; "
            "hardly_gate_bot_protection if 4xx cluster; hardly_session_body_coverage if bodies look empty."
        ),
    }
