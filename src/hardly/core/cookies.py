"""Cookie name timeline from Cookie / Set-Cookie headers."""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path
from typing import Any

import ijson

from hardly.core.filters import is_noise
from hardly.core.urls import parse_url

_COOKIE_PAIR = re.compile(r"([^=;\s]+)\s*=\s*([^;]*)")


def cookie_timeline(
    conn: sqlite3.Connection,
    *,
    har_path: str | Path | None = None,
    host: str | None = None,
    limit: int = 60,
) -> dict[str, Any]:
    """List cookie *names* set and sent over time (values never returned)."""
    path = Path(har_path) if har_path else _har_path(conn)
    if path and path.is_file():
        events = _from_har(path, host=host)
        source = "har"
    else:
        events = _from_db(conn, host=host)
        source = "index"

    events = events[: min(limit, 120)]
    names_set = sorted({e["name"] for e in events if e.get("event") == "set"})
    names_sent = sorted({e["name"] for e in events if e.get("event") == "send"})
    return {
        "host": host,
        "source": source,
        "event_count": len(events),
        "names_set": names_set,
        "names_sent": names_sent,
        "events": events,
        "next": (
            "Names only — pair with hardly_correlate to see which session "
            "cookies flow into later requests."
        ),
    }


def _har_path(conn: sqlite3.Connection) -> Path | None:
    row = conn.execute(
        "SELECT value FROM meta WHERE key = 'har_path'"
    ).fetchone()
    if not row:
        return None
    path = Path(row["value"] if isinstance(row, sqlite3.Row) else row[0])
    return path if path.is_file() else None


def _from_har(har_path: Path, *, host: str | None) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    with har_path.open("rb") as f:
        for entry_id, entry in enumerate(ijson.items(f, "log.entries.item")):
            req = entry.get("request") or {}
            resp = entry.get("response") or {}
            url = req.get("url") or ""
            parsed = parse_url(url)
            if host and parsed["host"].lower() != host.lower():
                continue
            method = (req.get("method") or "GET").upper()
            mime = (resp.get("content") or {}).get("mimeType")
            if is_noise(
                method=method, url=url, status=resp.get("status"), mime=mime
            ):
                continue
            for h in req.get("headers") or []:
                if (h.get("name") or "").lower() != "cookie":
                    continue
                for name in _cookie_names(str(h.get("value") or "")):
                    events.append(
                        {
                            "entry_id": entry_id,
                            "event": "send",
                            "name": name,
                            "path": parsed["path"],
                            "method": method,
                        }
                    )
            for h in resp.get("headers") or []:
                if (h.get("name") or "").lower() != "set-cookie":
                    continue
                names = _cookie_names(str(h.get("value") or "").split(";", 1)[0])
                for name in names:
                    events.append(
                        {
                            "entry_id": entry_id,
                            "event": "set",
                            "name": name,
                            "path": parsed["path"],
                            "status": resp.get("status"),
                        }
                    )
    return events


def _from_db(conn: sqlite3.Connection, *, host: str | None) -> list[dict[str, Any]]:
    """Index fallback: Cookie/Set-Cookie values are redacted — names unavailable."""
    clauses = ["e.is_noise = 0"]
    params: list[Any] = []
    if host:
        clauses.append("e.host = ?")
        params.append(host.lower())
    where = " AND ".join(clauses)
    rows = conn.execute(
        f"""
        SELECT e.entry_id, e.method, e.path, e.status, h.side, h.name
        FROM entries e
        JOIN headers h ON h.entry_id = e.entry_id
        WHERE {where}
          AND lower(h.name) IN ('cookie', 'set-cookie')
        ORDER BY e.entry_id ASC
        """,
        params,
    ).fetchall()
    events: list[dict[str, Any]] = []
    for row in rows:
        events.append(
            {
                "entry_id": row["entry_id"],
                "event": "set" if row["side"] == "response" else "send",
                "name": "(redacted — reopen with HAR on disk)",
                "path": row["path"],
                "method": row["method"],
                "status": row["status"],
            }
        )
    return events


def _cookie_names(header_value: str) -> list[str]:
    names: list[str] = []
    for match in _COOKIE_PAIR.finditer(header_value):
        name = match.group(1).strip()
        if name.lower() in {"path", "domain", "expires", "max-age", "samesite", "secure", "httponly"}:
            continue
        if name and name not in names:
            names.append(name)
    return names
