"""Detect bot walls / challenge pages that block plain HTTP clients."""

from __future__ import annotations

import re
import sqlite3
from typing import Any

_SIGNALS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("akamai", re.compile(r"akamai|edgesuite|_abck|ak_bmsc|bm_sz", re.I)),
    ("cloudflare", re.compile(r"cloudflare|cf-ray|cf_clearance|attention required", re.I)),
    ("imperva", re.compile(r"imperva|incapsula|_incap_ses|visid_incap", re.I)),
    ("datadome", re.compile(r"datadome|dd_cookie", re.I)),
    ("perimeterx", re.compile(r"perimeterx|_px\d|px-captcha", re.I)),
    ("recaptcha", re.compile(r"recaptcha|g-recaptcha|hcaptcha", re.I)),
    ("access_denied", re.compile(r"access denied|request blocked|bot detection", re.I)),
    ("captcha", re.compile(r"\bcaptcha\b|challenge-platform", re.I)),
)


def detect_walls(
    conn: sqlite3.Connection,
    *,
    host: str | None = None,
    limit: int = 30,
) -> dict[str, Any]:
    """Scan statuses, headers, and body previews for bot-wall signals."""
    clauses = ["e.is_noise = 0"]
    params: list[Any] = []
    if host:
        clauses.append("e.host = ?")
        params.append(host.lower())
    where = " AND ".join(clauses)

    hits: list[dict[str, Any]] = []
    seen: set[int] = set()

    # Status-based: 403/429 often walls
    for row in conn.execute(
        f"""
        SELECT entry_id, method, host, path, status, mime
        FROM entries e
        WHERE {where} AND status IN (403, 429, 503)
        ORDER BY entry_id ASC
        LIMIT 40
        """,
        params,
    ):
        _add(
            hits,
            seen,
            row,
            kinds=["http_block"],
            detail=f"status {row['status']}",
        )

    # Header names / values (redacted still has names; set-cookie names lost —
    # scan value_redacted for non-cookie headers and header names)
    for row in conn.execute(
        f"""
        SELECT e.entry_id, e.method, e.host, e.path, e.status, e.mime,
               h.name AS header_name, h.value_redacted
        FROM entries e
        JOIN headers h ON h.entry_id = e.entry_id
        WHERE {where}
        ORDER BY e.entry_id ASC
        LIMIT 2000
        """,
        params,
    ):
        blob = f"{row['header_name']} {row['value_redacted'] or ''}"
        kinds = _match_kinds(blob)
        if kinds:
            _add(hits, seen, row, kinds=kinds, detail=f"header {row['header_name']}")

    # Body previews
    for row in conn.execute(
        f"""
        SELECT e.entry_id, e.method, e.host, e.path, e.status, e.mime,
               b.preview_text
        FROM entries e
        JOIN bodies b ON b.entry_id = e.entry_id AND b.side = 'response'
        WHERE {where} AND b.preview_text IS NOT NULL
        ORDER BY e.entry_id ASC
        LIMIT 400
        """,
        params,
    ):
        text = row["preview_text"] or ""
        # Keep scan cheap — first 4k already previewed
        kinds = _match_kinds(text[:4000])
        if kinds:
            _add(hits, seen, row, kinds=kinds, detail="response body")

    hits = hits[: min(limit, 60)]
    by_kind: dict[str, int] = {}
    for h in hits:
        for k in h.get("kinds") or []:
            by_kind[k] = by_kind.get(k, 0) + 1

    return {
        "host": host,
        "hit_count": len(hits),
        "by_kind": by_kind,
        "hits": hits,
        "next": (
            "Bot walls need headed Chrome capture (channel=chrome), not urllib. "
            "Use hardly_capture_start; for CA counties prefer asspy.sample."
        ),
    }


def _match_kinds(text: str) -> list[str]:
    found = []
    for name, pattern in _SIGNALS:
        if pattern.search(text):
            found.append(name)
    return found


def _add(
    hits: list[dict[str, Any]],
    seen: set[int],
    row: sqlite3.Row,
    *,
    kinds: list[str],
    detail: str,
) -> None:
    eid = int(row["entry_id"])
    if eid in seen:
        # Merge kinds onto existing
        for h in hits:
            if h["entry_id"] == eid:
                for k in kinds:
                    if k not in h["kinds"]:
                        h["kinds"].append(k)
                if detail not in h.get("details", []):
                    h.setdefault("details", []).append(detail)
                return
        return
    seen.add(eid)
    hits.append(
        {
            "entry_id": eid,
            "method": row["method"],
            "host": row["host"],
            "path": row["path"],
            "status": row["status"],
            "mime": row["mime"],
            "kinds": list(kinds),
            "details": [detail],
        }
    )
