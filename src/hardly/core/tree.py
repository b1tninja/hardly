"""Request initiator trees from HAR _initiator / pageref."""

from __future__ import annotations

import sqlite3
from typing import Any
from urllib.parse import urlparse

from hardly.core.redact import redact_url


def entry_tree(
    conn: sqlite3.Connection,
    entry_id: int,
    *,
    exclude_noise: bool = True,
    child_limit: int = 40,
) -> dict[str, Any]:
    """Parent (initiator) and children of an entry."""
    row = conn.execute(
        "SELECT * FROM entries WHERE entry_id = ?", (entry_id,)
    ).fetchone()
    if not row:
        return {"error": f"unknown entry_id {entry_id}"}

    self_urls = _urls_for_row(row)
    parent = _find_parent(conn, row)
    children = _find_children(
        conn, self_urls, exclude_noise=exclude_noise, limit=child_limit
    )
    siblings = []
    if row["pageref"]:
        siblings = _pageref_peers(
            conn,
            row["pageref"],
            entry_id,
            exclude_noise=exclude_noise,
            limit=12,
        )

    return {
        "entry_id": entry_id,
        "method": row["method"],
        "path": row["path"],
        "pageref": row["pageref"],
        "initiator_type": row["initiator_type"],
        "initiator_url": row["initiator_url"],
        "parent": parent,
        "child_count": len(children),
        "children": children,
        "pageref_peers": siblings,
        "next": (
            "Children are requests whose _initiator points at this URL. "
            "Use hardly_entry_around for time-neighbors when initiator is missing."
        ),
    }


def _urls_for_row(row: sqlite3.Row) -> list[str]:
    base = f"{row['scheme']}://{row['host']}{row['path']}"
    urls = [base]
    if row["query_raw"]:
        urls.append(f"{base}?{row['query_raw']}")
    return urls


def _find_parent(conn: sqlite3.Connection, row: sqlite3.Row) -> dict[str, Any] | None:
    init_url = row["initiator_url"]
    if not init_url:
        # Referer fallback
        ref = conn.execute(
            """
            SELECT value_raw, value_redacted FROM headers
            WHERE entry_id = ? AND side = 'request' AND lower(name) = 'referer'
            LIMIT 1
            """,
            (row["entry_id"],),
        ).fetchone()
        init_url = redact_url(ref["value_raw"] or ref["value_redacted"]) if ref else None
        if not init_url or init_url == "***REDACTED***":
            return None
        source = "referer"
    else:
        source = "initiator"

    parent = _match_url(conn, init_url, before_id=row["entry_id"])
    if not parent:
        parsed = urlparse(init_url)
        return {
            "source": source,
            "url": init_url,
            "entry_id": None,
            "path": parsed.path or "/",
            "note": "no matching entry in this capture",
        }
    return {
        "source": source,
        "entry_id": parent["entry_id"],
        "method": parent["method"],
        "path": parent["path"],
        "status": parent["status"],
        "url": init_url,
    }


def _find_children(
    conn: sqlite3.Connection,
    parent_urls: list[str],
    *,
    exclude_noise: bool,
    limit: int,
) -> list[dict[str, Any]]:
    if not parent_urls:
        return []
    placeholders = ",".join("?" * len(parent_urls))
    noise = "AND is_noise = 0" if exclude_noise else ""
    rows = conn.execute(
        f"""
        SELECT entry_id, method, path, status, initiator_type, mime, started_datetime
        FROM entries
        WHERE initiator_url IN ({placeholders})
          AND method != 'OPTIONS'
          {noise}
        ORDER BY entry_id ASC
        LIMIT ?
        """,
        [*parent_urls, min(limit, 80)],
    ).fetchall()
    return [
        {
            "entry_id": r["entry_id"],
            "method": r["method"],
            "path": r["path"],
            "status": r["status"],
            "initiator_type": r["initiator_type"],
            "mime": r["mime"],
        }
        for r in rows
    ]


def _match_url(
    conn: sqlite3.Connection, url: str, *, before_id: int
) -> sqlite3.Row | None:
    parsed = urlparse(url)
    host = (parsed.netloc or "").lower()
    path = parsed.path or "/"
    query = parsed.query or None
    if query:
        from hardly.core.redact import redact_query_string

        query = redact_query_string(query)  # stored query strings are redacted
        row = conn.execute(
            """
            SELECT * FROM entries
            WHERE host = ? AND path = ? AND query_raw = ? AND entry_id < ?
            ORDER BY entry_id DESC LIMIT 1
            """,
            (host, path, query, before_id),
        ).fetchone()
        if row:
            return row
    return conn.execute(
        """
        SELECT * FROM entries
        WHERE host = ? AND path = ? AND entry_id < ?
        ORDER BY entry_id DESC LIMIT 1
        """,
        (host, path, before_id),
    ).fetchone()


def _pageref_peers(
    conn: sqlite3.Connection,
    pageref: str,
    entry_id: int,
    *,
    exclude_noise: bool,
    limit: int,
) -> list[dict[str, Any]]:
    noise = "AND is_noise = 0" if exclude_noise else ""
    rows = conn.execute(
        f"""
        SELECT entry_id, method, path, status
        FROM entries
        WHERE pageref = ? AND entry_id != ? AND method != 'OPTIONS' {noise}
        ORDER BY entry_id ASC
        LIMIT ?
        """,
        (pageref, entry_id, min(limit, 30)),
    ).fetchall()
    return [
        {
            "entry_id": r["entry_id"],
            "method": r["method"],
            "path": r["path"],
            "status": r["status"],
        }
        for r in rows
    ]
