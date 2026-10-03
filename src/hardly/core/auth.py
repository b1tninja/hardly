"""Auth pattern detection from indexed entries."""

from __future__ import annotations

import json
import re
import sqlite3
from typing import Any

AUTH_PATH_RE = re.compile(
    r"(login|log-in|signin|sign-in|auth|oauth|token|2fa|mfa|otp|sso|session|logout)",
    re.I,
)

TOKEN_KEYS = frozenset(
    {
        "token",
        "access_token",
        "refresh_token",
        "id_token",
        "verificationkey",
        "verification_key",
        "twofactorkey",
        "two_factor_key",
        "sessiontoken",
        "jwt",
    }
)

AUTH_HEADER_NAMES = frozenset(
    {
        "authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "x-auth-token",
        "x-access-token",
        "x-csrf-token",
        "x-xsrf-token",
        "x-legfi-site-id",
    }
)


def _json_keys(text: str | None) -> set[str]:
    if not text:
        return set()
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return set()
    keys: set[str] = set()

    def walk(obj: Any, depth: int = 0) -> None:
        if depth > 6:
            return
        if isinstance(obj, dict):
            for k, v in obj.items():
                keys.add(str(k).lower())
                walk(v, depth + 1)
        elif isinstance(obj, list):
            for item in obj[:10]:
                walk(item, depth + 1)

    walk(data)
    return keys


def detect_auth(conn: sqlite3.Connection, *, host: str | None = None) -> dict:
    """Scan session for auth-related signals."""
    params: list[Any] = []
    host_clause = ""
    if host:
        host_clause = "AND e.host = ?"
        params.append(host.lower())

    # Path-based candidates
    rows = conn.execute(
        f"""
        SELECT e.entry_id, e.method, e.host, e.path, e.status, e.path_template,
               rb.preview_text AS req_body, sb.preview_text AS resp_body
        FROM entries e
        LEFT JOIN bodies rb ON rb.entry_id = e.entry_id AND rb.side = 'request'
        LEFT JOIN bodies sb ON sb.entry_id = e.entry_id AND sb.side = 'response'
        WHERE e.is_noise = 0 {host_clause}
        ORDER BY e.entry_id
        """,
        params,
    ).fetchall()

    path_hits = []
    token_responses = []
    interesting_headers: dict[str, int] = {}

    for row in rows:
        path = row["path"] or ""
        if AUTH_PATH_RE.search(path):
            path_hits.append(
                {
                    "entry_id": row["entry_id"],
                    "method": row["method"],
                    "host": row["host"],
                    "path": path,
                    "path_template": row["path_template"],
                    "status": row["status"],
                }
            )
        resp_keys = _json_keys(row["resp_body"])
        token_found = sorted(k for k in resp_keys if k.replace("_", "") in {
            t.replace("_", "") for t in TOKEN_KEYS
        } or k in TOKEN_KEYS)
        if token_found:
            token_responses.append(
                {
                    "entry_id": row["entry_id"],
                    "method": row["method"],
                    "path": path,
                    "status": row["status"],
                    "token_keys": token_found,
                }
            )

    header_rows = conn.execute(
        f"""
        SELECT h.name, COUNT(*) AS cnt
        FROM headers h
        JOIN entries e ON e.entry_id = h.entry_id
        WHERE e.is_noise = 0 {host_clause}
          AND LOWER(h.name) IN ({",".join("?" * len(AUTH_HEADER_NAMES))})
        GROUP BY LOWER(h.name)
        ORDER BY cnt DESC
        """,
        params + [n.lower() for n in AUTH_HEADER_NAMES],
    ).fetchall()
    for hr in header_rows:
        interesting_headers[hr["name"].lower()] = hr["cnt"]

    # Custom site / tenant headers often matter for APIs
    custom = conn.execute(
        f"""
        SELECT LOWER(h.name) AS name, COUNT(*) AS cnt
        FROM headers h
        JOIN entries e ON e.entry_id = h.entry_id
        WHERE e.is_noise = 0 {host_clause}
          AND h.side = 'request'
          AND (
            LOWER(h.name) LIKE 'x-%site%'
            OR LOWER(h.name) LIKE 'x-%auth%'
            OR LOWER(h.name) LIKE 'x-%csrf%'
            OR LOWER(h.name) LIKE 'x-%xsrf%'
            OR LOWER(h.name) LIKE 'x-%api%'
            OR LOWER(h.name) LIKE 'x-%legfi%'
            OR LOWER(h.name) IN ('api_key', 'api-key', 'apikey', 'auth-token', 'auth_token', 'access-token',
                                 'access_token', 'token', 'secret', 'session-id', 'session_id', 'sessiontoken')
          )
        GROUP BY LOWER(h.name)
        ORDER BY cnt DESC
        LIMIT 20
        """,
        params,
    ).fetchall()
    custom_headers = {r["name"]: r["cnt"] for r in custom}

    return {
        "auth_path_entries": path_hits[:50],
        "auth_path_count": len(path_hits),
        "token_response_entries": token_responses[:50],
        "token_response_count": len(token_responses),
        "auth_related_headers": interesting_headers,
        "custom_auth_headers": custom_headers,
        "notes": [
            "Chrome HAR exports may strip Authorization and Cookie headers.",
            "Look for tokens in response bodies (token, verificationKey, etc.).",
            "Write headers like X-XSRF-TOKEN may still appear on mutating requests.",
        ],
    }
