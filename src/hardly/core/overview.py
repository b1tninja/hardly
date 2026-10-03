"""Headline counts of a capture: requests per server, method and status."""

from __future__ import annotations

import sqlite3
from typing import Any

from hardly.index import query as q


def _where(host: str | None, exclude_noise: bool) -> tuple[str, list[Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    if exclude_noise:
        clauses.append("is_noise = 0")
    if host:
        clauses.append("host = ?")
        params.append(host.lower())
    return (" WHERE " + " AND ".join(clauses)) if clauses else "", params


def session_overview(
    conn: sqlite3.Connection,
    *,
    host: str | None = None,
    exclude_noise: bool = True,
    limit: int = 50,
) -> dict[str, Any]:
    """COUNTS only: requests per host, method and status, plus the main (app) host."""
    where, params = _where(host, exclude_noise)
    total = conn.execute(f"SELECT COUNT(*) FROM entries{where}", params).fetchone()[0]
    all_entries, noise = conn.execute("SELECT COUNT(*), COALESCE(SUM(is_noise), 0) FROM entries").fetchone()
    rows = conn.execute(
        f"SELECT host, method, status, COUNT(*) AS n FROM entries{where} GROUP BY host, method, status",
        params,
    ).fetchall()
    hosts: dict[str, dict[str, Any]] = {}
    methods: dict[str, int] = {}
    statuses: dict[str, int] = {}
    for r in rows:
        h = hosts.setdefault(r["host"], {"host": r["host"], "count": 0, "methods": {}, "statuses": {}})
        n = int(r["n"])
        h["count"] += n
        h["methods"][r["method"]] = h["methods"].get(r["method"], 0) + n
        st = str(r["status"])
        h["statuses"][st] = h["statuses"].get(st, 0) + n
        methods[r["method"]] = methods.get(r["method"], 0) + n
        statuses[st] = statuses.get(st, 0) + n
    ordered = sorted(hosts.values(), key=lambda h: (-h["count"], h["host"]))
    cap = max(1, int(limit))
    meta = {r["key"]: r["value"] for r in conn.execute("SELECT key, value FROM meta").fetchall()}
    return {
        "requests": int(total),
        "entries_in_capture": int(all_entries),
        "noise_entries": int(noise or 0),
        "exclude_noise": bool(exclude_noise),
        "main_host": q.preferred_host(conn),
        "host_count": len(ordered),
        "hosts": ordered[:cap],
        "methods": dict(sorted(methods.items(), key=lambda kv: -kv[1])),
        "statuses": dict(sorted(statuses.items(), key=lambda kv: -kv[1])),
        "har_path": meta.get("har_path"),
        "next": (
            "Pass main_host as host= to later tools. hardly_session_traffic_stats gives distributions, "
            "hardly_session_report findings, hardly_session_site_brief a digest of a server-rendered site."
        ),
    }
