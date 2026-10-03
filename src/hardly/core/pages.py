"""Group entries by HAR pageref (browser page load)."""

from __future__ import annotations

import sqlite3
from typing import Any


def list_pages(
    conn: sqlite3.Connection,
    *,
    host: str | None = None,
    exclude_noise: bool = True,
    limit: int = 40,
) -> dict[str, Any]:
    """Summarize pageref groups with document/API counts."""
    clauses = ["pageref IS NOT NULL", "pageref != ''"]
    params: list[Any] = []
    if host:
        clauses.append("host = ?")
        params.append(host.lower())
    if exclude_noise:
        # Still count noise separately; filter later in aggregates
        pass
    where = " AND ".join(clauses)
    rows = conn.execute(
        f"""
        SELECT pageref,
               COUNT(*) AS entries,
               SUM(CASE WHEN is_noise = 0 THEN 1 ELSE 0 END) AS apiish,
               SUM(CASE WHEN is_noise = 1 THEN 1 ELSE 0 END) AS noise,
               MIN(entry_id) AS first_entry_id,
               MAX(entry_id) AS last_entry_id,
               MIN(started_datetime) AS started,
               GROUP_CONCAT(DISTINCT host) AS hosts
        FROM entries
        WHERE {where}
        GROUP BY pageref
        ORDER BY first_entry_id ASC
        LIMIT ?
        """,
        [*params, min(limit, 80)],
    ).fetchall()

    pages = []
    for row in rows:
        doc = conn.execute(
            """
            SELECT entry_id, method, path, status, mime
            FROM entries
            WHERE pageref = ?
              AND (mime LIKE '%html%' OR path LIKE '%.aspx' OR path LIKE '%.html'
                   OR initiator_type = 'other' OR initiator_type IS NULL)
            ORDER BY entry_id ASC
            LIMIT 1
            """,
            (row["pageref"],),
        ).fetchone()
        pages.append(
            {
                "pageref": row["pageref"],
                "entries": row["entries"],
                "apiish": row["apiish"],
                "noise": row["noise"],
                "first_entry_id": row["first_entry_id"],
                "last_entry_id": row["last_entry_id"],
                "started": row["started"],
                "hosts": (row["hosts"] or "").split(",")[:8],
                "document": (
                    {
                        "entry_id": doc["entry_id"],
                        "method": doc["method"],
                        "path": doc["path"],
                        "status": doc["status"],
                    }
                    if doc
                    else None
                ),
            }
        )

    unpaged = conn.execute(
        """
        SELECT COUNT(*) AS c FROM entries
        WHERE pageref IS NULL OR pageref = ''
        """
    ).fetchone()["c"]

    synthetic = False
    if not pages:
        # Some SPA / export HARs omit pageref entirely — group by HTML documents.
        syn_clauses = [
            "is_noise = 0",
            "method = 'GET'",
            "status BETWEEN 200 AND 399",
            "lower(IFNULL(mime, '')) LIKE '%html%'",
        ]
        syn_params: list[Any] = []
        if host:
            syn_clauses.append("host = ?")
            syn_params.append(host.lower())
        syn_where = " AND ".join(syn_clauses)
        syn_rows = conn.execute(
            f"""
            SELECT entry_id, method, path, status, mime, host, started_datetime
            FROM entries
            WHERE {syn_where}
            ORDER BY entry_id ASC
            LIMIT ?
            """,
            [*syn_params, min(limit, 40)],
        ).fetchall()
        for row in syn_rows:
            pages.append(
                {
                    "pageref": f"synthetic:{row['entry_id']}",
                    "entries": 1,
                    "apiish": 1,
                    "noise": 0,
                    "first_entry_id": row["entry_id"],
                    "last_entry_id": row["entry_id"],
                    "started": row["started_datetime"],
                    "hosts": [row["host"]],
                    "document": {
                        "entry_id": row["entry_id"],
                        "method": row["method"],
                        "path": row["path"],
                        "status": row["status"],
                    },
                    "synthetic": True,
                }
            )
        synthetic = bool(pages)

    note = (
        "Use first_entry_id with hardly_tree / hardly_around. "
        "Playwright/DevTools HARs usually set pageref; some exports omit it."
    )
    if synthetic:
        note = (
            "No pageref in HAR; pages are synthetic HTML document navigations. "
            + note
        )

    return {
        "host": host,
        "page_count": len(pages),
        "unpaged_entries": unpaged,
        "synthetic": synthetic,
        "pages": pages,
        "next": note,
    }
