"""Follow HTTP redirect chains in a HAR session."""

from __future__ import annotations

import sqlite3
from typing import Any
from urllib.parse import urljoin, urlparse

from hardly.core.explain import finish
from hardly.core.redact import redact_url


def _redirect_chains(
    conn: sqlite3.Connection,
    *,
    host: str | None = None,
    limit: int = 30,
) -> dict[str, Any]:
    """List 3xx responses and where Location points (matched when possible)."""
    clauses = ["e.status BETWEEN 300 AND 399"]
    params: list[Any] = []
    if host:
        clauses.append("e.host = ?")
        params.append(host.lower())
    where = " AND ".join(clauses)
    rows = conn.execute(
        f"""
        SELECT e.entry_id, e.method, e.scheme, e.host, e.path, e.status,
               e.started_datetime
        FROM entries e
        WHERE {where}
        ORDER BY e.entry_id ASC
        LIMIT ?
        """,
        [*params, min(limit, 80)],
    ).fetchall()

    chains: list[dict[str, Any]] = []
    for row in rows:
        location = _location_header(conn, row["entry_id"])
        target = None
        hop_entry = None
        if location:
            base = f"{row['scheme']}://{row['host']}{row['path']}"
            abs_url = urljoin(base, location)
            parsed = urlparse(abs_url)
            hop_entry = _match_follow(
                conn,
                host=parsed.netloc.lower(),
                path=parsed.path or "/",
                after_id=row["entry_id"],
            )
            target = {
                "url": redact_url(abs_url),
                "host": parsed.netloc.lower(),
                "path": parsed.path or "/",
                "follow_entry_id": hop_entry,
            }
        chains.append(
            {
                "entry_id": row["entry_id"],
                "method": row["method"],
                "status": row["status"],
                "path": row["path"],
                "location": redact_url(location) if location else location,
                "target": target,
                "started_datetime": row["started_datetime"],
            }
        )

    return {
        "host": host,
        "chain_count": len(chains),
        "chains": chains,
        "next": (
            "Use follow_entry_id with hardly_entry / hardly_around. "
            "Guest portals often 302 through disclaimer → search."
        ),
    }


def redirect_chains(
    conn: sqlite3.Connection,
    *,
    host: str | None = None,
    limit: int = 30,
    explain: bool = False,
) -> dict[str, Any]:
    """``redirect_chains``; canned prose (next) only with ``explain=True``."""
    return finish(_redirect_chains(conn, host=host, limit=limit), explain, 'next')



def _location_header(conn: sqlite3.Connection, entry_id: int) -> str | None:
    row = conn.execute(
        """
        SELECT value_raw, value_redacted FROM headers
        WHERE entry_id = ? AND side = 'response' AND lower(name) = 'location'
        LIMIT 1
        """,
        (entry_id,),
    ).fetchone()
    if not row:
        return None
    return row["value_raw"] or row["value_redacted"]


def _match_follow(
    conn: sqlite3.Connection,
    *,
    host: str,
    path: str,
    after_id: int,
) -> int | None:
    row = conn.execute(
        """
        SELECT entry_id FROM entries
        WHERE host = ? AND path = ? AND entry_id > ?
        ORDER BY entry_id ASC LIMIT 1
        """,
        (host, path, after_id),
    ).fetchone()
    return int(row["entry_id"]) if row else None
