"""Cheap capture-quality and protocol issues for agents."""

from __future__ import annotations

import sqlite3
from typing import Any
from urllib.parse import parse_qsl

# Common exporter caps that chop ASP.NET ViewState / CSRF blobs.
_SUSPECT_CAPS = frozenset({256, 500, 512, 1000, 1024, 2000, 2048, 4096})
_TOKEN_FIELD = (
    "viewstate",
    "eventvalidation",
    "requestverification",
    "csrf",
    "xsrf",
    "nonce",
    "authenticity",
)


def find_issues(
    conn: sqlite3.Connection,
    *,
    host: str | None = None,
    limit: int = 40,
) -> dict[str, Any]:
    """Surface empty bodies, error statuses, and odd redirects."""
    clauses: list[str] = []
    params: list[Any] = []
    if host:
        clauses.append("e.host = ?")
        params.append(host.lower())
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""

    issues: list[dict[str, Any]] = []

    # 4xx / 5xx (non-noise)
    for row in conn.execute(
        f"""
        SELECT e.entry_id, e.method, e.path, e.status, e.host
        FROM entries e
        {where}{" AND " if where else "WHERE "}e.is_noise = 0
          AND e.status >= 400
        ORDER BY e.status DESC, e.entry_id ASC
        LIMIT 20
        """,
        params,
    ):
        issues.append(
            {
                "kind": "http_error",
                "entry_id": row["entry_id"],
                "status": row["status"],
                "method": row["method"],
                "host": row["host"],
                "path": row["path"],
            }
        )

    # Expected body missing (HTML/JSON mime, size 0 / null preview)
    for row in conn.execute(
        f"""
        SELECT e.entry_id, e.method, e.path, e.mime, e.status, b.size, b.preview_text
        FROM entries e
        LEFT JOIN bodies b ON b.entry_id = e.entry_id AND b.side = 'response'
        {where}{" AND " if where else "WHERE "}e.is_noise = 0
          AND e.status BETWEEN 200 AND 299
          AND e.mime IS NOT NULL
          AND (
            lower(e.mime) LIKE '%json%'
            OR lower(e.mime) LIKE '%html%'
            OR lower(e.mime) LIKE '%javascript%'
          )
          AND (b.preview_text IS NULL OR b.preview_text = '' OR b.size = 0 OR b.size = -1)
        ORDER BY e.entry_id ASC
        LIMIT 20
        """,
        params,
    ):
        size = row["size"]
        if size == -1:
            hint = "Body omitted in HAR (size=-1); re-capture without omit-content or use body backfill"
        elif size == 0:
            hint = "Zero-length body; server returned empty or capture stripped it"
        else:
            hint = "Expected body missing from preview; re-capture with body backfill"
        issues.append(
            {
                "kind": "empty_body",
                "entry_id": row["entry_id"],
                "method": row["method"],
                "path": row["path"],
                "mime": row["mime"],
                "body_size": size,
                "hint": hint,
            }
        )

    # 3xx without Location
    for row in conn.execute(
        f"""
        SELECT e.entry_id, e.method, e.path, e.status
        FROM entries e
        {where}{" AND " if where else "WHERE "}e.status BETWEEN 300 AND 399
          AND NOT EXISTS (
            SELECT 1 FROM headers h
            WHERE h.entry_id = e.entry_id AND h.side = 'response'
              AND lower(h.name) = 'location'
          )
        ORDER BY e.entry_id ASC
        LIMIT 10
        """,
        params,
    ):
        issues.append(
            {
                "kind": "redirect_missing_location",
                "entry_id": row["entry_id"],
                "status": row["status"],
                "method": row["method"],
                "path": row["path"],
            }
        )

    # Truncated token fields (HAR exporters often cap at 500 chars)
    for row in conn.execute(
        f"""
        SELECT e.entry_id, e.method, e.path, b.preview_text
        FROM entries e
        JOIN bodies b ON b.entry_id = e.entry_id AND b.side = 'request'
        {where}{" AND " if where else "WHERE "}e.is_noise = 0
          AND e.method IN ('POST', 'PUT', 'PATCH')
          AND b.preview_text IS NOT NULL
          AND (
            b.preview_text LIKE '%VIEWSTATE%'
            OR b.preview_text LIKE '%RequestVerification%'
            OR b.preview_text LIKE '%csrf%'
            OR b.preview_text LIKE '%__RequestVerificationToken%'
          )
        ORDER BY e.entry_id ASC
        LIMIT 15
        """,
        params,
    ):
        text = row["preview_text"] or ""
        for name, val in parse_qsl(text, keep_blank_values=True):
            lname = (name or "").lower()
            if not any(tok in lname for tok in _TOKEN_FIELD):
                continue
            if len(val) in _SUSPECT_CAPS:
                issues.append(
                    {
                        "kind": "truncated_token",
                        "entry_id": row["entry_id"],
                        "method": row["method"],
                        "path": row["path"],
                        "field": name,
                        "value_length": len(val),
                        "hint": (
                            "Token field looks exporter-truncated; "
                            "re-capture with full bodies / body backfill "
                            "or correlate will miss ViewState reuse"
                        ),
                    }
                )
                break

    issues = issues[: min(limit, 60)]
    by_kind: dict[str, int] = {}
    for issue in issues:
        by_kind[issue["kind"]] = by_kind.get(issue["kind"], 0) + 1

    return {
        "host": host,
        "issue_count": len(issues),
        "by_kind": by_kind,
        "issues": issues,
        "next": (
            "empty_body / truncated_token → hardly_session_body_coverage / re-capture; "
            "http_error → hardly_entry_get; redirects → hardly_session_redirect_history."
        ),
    }
