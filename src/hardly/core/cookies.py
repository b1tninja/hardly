"""Cookie name timeline from Cookie / Set-Cookie headers."""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path
from typing import Any

from hardly.core.filters import is_noise
from hardly.core.har_io import ijson_items
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
    flags = _cookie_flags_from_har(path, host=host, limit=min(limit, 80)) if (
        path and path.is_file()
    ) else []
    by_flag: dict[str, list[str]] = {
        "httponly": [],
        "secure": [],
        "samesite_lax": [],
        "samesite_strict": [],
        "samesite_none": [],
    }
    for row in flags:
        if row.get("httponly"):
            by_flag["httponly"].append(row["name"])
        if row.get("secure"):
            by_flag["secure"].append(row["name"])
        ss = (row.get("samesite") or "").lower()
        if ss == "lax":
            by_flag["samesite_lax"].append(row["name"])
        elif ss == "strict":
            by_flag["samesite_strict"].append(row["name"])
        elif ss == "none":
            by_flag["samesite_none"].append(row["name"])
    for key in by_flag:
        by_flag[key] = sorted(set(by_flag[key]), key=str.lower)

    return {
        "host": host,
        "source": source,
        "event_count": len(events),
        "names_set": names_set,
        "names_sent": names_sent,
        "flags": flags,
        "by_flag": by_flag,
        "events": events,
        "next": (
            "Names and Set-Cookie flags only — pair with hardly_session_trace_value / "
            "hardly_auth_report. Values are never returned."
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
        for entry_id, entry in enumerate(ijson_items(f, "log.entries.item")):
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


def _cookie_flags_from_har(
    har_path: Path,
    *,
    host: str | None,
    limit: int,
) -> list[dict[str, Any]]:
    """Set-Cookie attribute map (HttpOnly/Secure/SameSite/Path) — no values."""
    out: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    with har_path.open("rb") as f:
        for entry_id, entry in enumerate(ijson_items(f, "log.entries.item")):
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
            for h in resp.get("headers") or []:
                if (h.get("name") or "").lower() != "set-cookie":
                    continue
                parsed_flags = _parse_set_cookie_flags(str(h.get("value") or ""))
                if not parsed_flags.get("name"):
                    continue
                key = (entry_id, parsed_flags["name"].lower())
                if key in seen:
                    continue
                seen.add(key)
                out.append(
                    {
                        "entry_id": entry_id,
                        "name": parsed_flags["name"],
                        "path_attr": parsed_flags.get("path"),
                        "domain": parsed_flags.get("domain"),
                        "httponly": bool(parsed_flags.get("httponly")),
                        "secure": bool(parsed_flags.get("secure")),
                        "samesite": parsed_flags.get("samesite"),
                        "max_age": parsed_flags.get("max_age"),
                        "status": resp.get("status"),
                        "request_path": parsed["path"],
                    }
                )
                if len(out) >= limit:
                    return out
    return out


def _parse_set_cookie_flags(header_value: str) -> dict[str, Any]:
    parts = [p.strip() for p in header_value.split(";") if p.strip()]
    if not parts or "=" not in parts[0]:
        return {}
    name, _, _val = parts[0].partition("=")
    name = name.strip()
    if not name:
        return {}
    out: dict[str, Any] = {
        "name": name,
        "httponly": False,
        "secure": False,
        "samesite": None,
        "path": None,
        "domain": None,
        "max_age": None,
    }
    for part in parts[1:]:
        key, sep, val = part.partition("=")
        key_l = key.strip().lower()
        val = val.strip() if sep else ""
        if key_l == "httponly":
            out["httponly"] = True
        elif key_l == "secure":
            out["secure"] = True
        elif key_l == "samesite":
            out["samesite"] = val or None
        elif key_l == "path":
            out["path"] = val or None
        elif key_l == "domain":
            out["domain"] = val or None
        elif key_l == "max-age":
            out["max_age"] = val or None
    return out
