"""Query helpers over an indexed HAR session."""

from __future__ import annotations

import json
import re
import sqlite3
from typing import Any

from hardly.core.redact import redact_body_text
from hardly.core.schema_infer import infer_schema

_SELECT_ONLY = re.compile(r"^\s*SELECT\b", re.I)
_FORBIDDEN = re.compile(
    r"\b(INSERT|UPDATE|DELETE|DROP|ALTER|ATTACH|DETACH|PRAGMA|REPLACE|CREATE|VACUUM)\b",
    re.I,
)


def summary(conn: sqlite3.Connection) -> dict:
    meta = {
        r["key"]: r["value"]
        for r in conn.execute("SELECT key, value FROM meta").fetchall()
    }
    hosts = conn.execute(
        """
        SELECT host, COUNT(*) AS cnt,
               SUM(CASE WHEN is_noise = 0 THEN 1 ELSE 0 END) AS api_cnt
        FROM entries GROUP BY host ORDER BY cnt DESC
        """
    ).fetchall()
    methods = conn.execute(
        "SELECT method, COUNT(*) AS cnt FROM entries GROUP BY method ORDER BY cnt DESC"
    ).fetchall()
    statuses = conn.execute(
        "SELECT status, COUNT(*) AS cnt FROM entries GROUP BY status ORDER BY cnt DESC"
    ).fetchall()
    noise = conn.execute(
        "SELECT SUM(is_noise) AS noise, COUNT(*) - SUM(is_noise) AS api FROM entries"
    ).fetchone()
    return {
        "har_path": meta.get("har_path"),
        "entries": int(meta.get("entry_count", 0)),
        "noise": noise["noise"] or 0,
        "api": noise["api"] or 0,
        "hosts": [{"host": r["host"], "count": r["cnt"], "api": r["api_cnt"]} for r in hosts],
        "methods": {r["method"]: r["cnt"] for r in methods},
        "statuses": {str(r["status"]): r["cnt"] for r in statuses},
    }


def list_hosts(conn: sqlite3.Connection, *, exclude_noise: bool = False) -> list[dict]:
    clause = "WHERE is_noise = 0" if exclude_noise else ""
    rows = conn.execute(
        f"""
        SELECT host, COUNT(*) AS count
        FROM entries {clause}
        GROUP BY host ORDER BY count DESC
        """
    ).fetchall()
    return [{"host": r["host"], "count": r["count"]} for r in rows]


def list_endpoints(
    conn: sqlite3.Connection,
    *,
    host: str | None = None,
    exclude_noise: bool = True,
    limit: int = 100,
    offset: int = 0,
) -> dict:
    clauses = ["1=1"]
    params: list[Any] = []
    if host:
        clauses.append("host = ?")
        params.append(host.lower())
    if exclude_noise:
        clauses.append("is_noise = 0")
    where = " AND ".join(clauses)
    total = conn.execute(
        f"""
        SELECT COUNT(*) AS c FROM (
            SELECT 1 FROM entries WHERE {where}
            GROUP BY method, host, path_template
        )
        """,
        params,
    ).fetchone()["c"]
    rows = conn.execute(
        f"""
        SELECT method, host, path_template,
               COUNT(*) AS count,
               GROUP_CONCAT(DISTINCT status) AS statuses,
               MIN(entry_id) AS sample_entry_id
        FROM entries
        WHERE {where}
        GROUP BY method, host, path_template
        ORDER BY count DESC, host, path_template
        LIMIT ? OFFSET ?
        """,
        params + [limit, offset],
    ).fetchall()
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "endpoints": [
            {
                "method": r["method"],
                "host": r["host"],
                "path_template": r["path_template"],
                "count": r["count"],
                "statuses": r["statuses"],
                "sample_entry_id": r["sample_entry_id"],
            }
            for r in rows
        ],
    }


def search_entries(
    conn: sqlite3.Connection,
    *,
    host: str | None = None,
    path_contains: str | None = None,
    method: str | None = None,
    status: int | None = None,
    body_contains: str | None = None,
    exclude_noise: bool = True,
    exclude_options: bool = True,
    limit: int = 50,
    offset: int = 0,
) -> dict:
    clauses = ["1=1"]
    params: list[Any] = []
    if host:
        clauses.append("e.host = ?")
        params.append(host.lower())
    if path_contains:
        clauses.append("e.path LIKE ?")
        params.append(f"%{path_contains}%")
    if method:
        clauses.append("e.method = ?")
        params.append(method.upper())
    if status is not None:
        clauses.append("e.status = ?")
        params.append(status)
    if exclude_noise:
        clauses.append("e.is_noise = 0")
    if exclude_options:
        clauses.append("e.method != 'OPTIONS'")

    join = ""
    if body_contains:
        join = "JOIN bodies b ON b.entry_id = e.entry_id"
        clauses.append("b.preview_text LIKE ?")
        params.append(f"%{body_contains}%")

    where = " AND ".join(clauses)
    total = conn.execute(
        f"SELECT COUNT(DISTINCT e.entry_id) AS c FROM entries e {join} WHERE {where}",
        params,
    ).fetchone()["c"]
    rows = conn.execute(
        f"""
        SELECT DISTINCT e.entry_id, e.method, e.host, e.path, e.path_template,
               e.status, e.started_datetime, e.time_ms
        FROM entries e {join}
        WHERE {where}
        ORDER BY e.entry_id
        LIMIT ? OFFSET ?
        """,
        params + [limit, offset],
    ).fetchall()

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "entries": [
            {
                "entry_id": r["entry_id"],
                "method": r["method"],
                "host": r["host"],
                "path": r["path"],
                "path_template": r["path_template"],
                "status": r["status"],
                "started_datetime": r["started_datetime"],
                "time_ms": r["time_ms"],
            }
            for r in rows
        ],
    }


def get_entry(
    conn: sqlite3.Connection,
    entry_id: int,
    *,
    body_chars: int = 4000,
) -> dict:
    row = conn.execute(
        "SELECT * FROM entries WHERE entry_id = ?", (entry_id,)
    ).fetchone()
    if not row:
        return {"error": f"entry_id {entry_id} not found"}

    headers = {"request": [], "response": []}
    for h in conn.execute(
        "SELECT side, name, value_redacted FROM headers WHERE entry_id = ? ORDER BY id",
        (entry_id,),
    ):
        headers[h["side"]].append({"name": h["name"], "value": h["value_redacted"]})

    bodies = {}
    for b in conn.execute(
        "SELECT side, content_type, size, preview_text FROM bodies WHERE entry_id = ?",
        (entry_id,),
    ):
        preview = redact_body_text(b["preview_text"], max_chars=body_chars)
        bodies[b["side"]] = {
            "content_type": b["content_type"],
            "size": b["size"],
            **preview,
        }

    return {
        "entry_id": row["entry_id"],
        "method": row["method"],
        "url": f"{row['scheme']}://{row['host']}{row['path']}"
        + (f"?{row['query_raw']}" if row["query_raw"] else ""),
        "host": row["host"],
        "path": row["path"],
        "path_template": row["path_template"],
        "query": json.loads(row["query_json"]) if row["query_json"] else {},
        "status": row["status"],
        "mime": row["mime"],
        "started_datetime": row["started_datetime"],
        "time_ms": row["time_ms"],
        "is_noise": bool(row["is_noise"]),
        "headers": headers,
        "bodies": bodies,
    }


def compare_entries(conn: sqlite3.Connection, a_id: int, b_id: int) -> dict:
    a = get_entry(conn, a_id)
    b = get_entry(conn, b_id)
    if "error" in a or "error" in b:
        return {"error": a.get("error") or b.get("error")}

    def header_map(entry: dict, side: str) -> dict[str, str]:
        return {h["name"].lower(): h["value"] for h in entry["headers"].get(side, [])}

    def body_keys(entry: dict, side: str) -> list[str]:
        body = entry["bodies"].get(side, {})
        text = body.get("text")
        if not text:
            return []
        try:
            data = json.loads(text)
        except (json.JSONDecodeError, TypeError):
            return []
        if isinstance(data, dict):
            return sorted(data.keys())
        return []

    result = {
        "a": {"entry_id": a_id, "method": a["method"], "path": a["path"], "status": a["status"]},
        "b": {"entry_id": b_id, "method": b["method"], "path": b["path"], "status": b["status"]},
        "request_headers": {
            "only_a": sorted(set(header_map(a, "request")) - set(header_map(b, "request"))),
            "only_b": sorted(set(header_map(b, "request")) - set(header_map(a, "request"))),
            "changed": sorted(
                k
                for k in set(header_map(a, "request")) & set(header_map(b, "request"))
                if header_map(a, "request")[k] != header_map(b, "request")[k]
            ),
        },
        "request_body_keys": {
            "only_a": sorted(set(body_keys(a, "request")) - set(body_keys(b, "request"))),
            "only_b": sorted(set(body_keys(b, "request")) - set(body_keys(a, "request"))),
            "shared": sorted(set(body_keys(a, "request")) & set(body_keys(b, "request"))),
        },
        "response_body_keys": {
            "only_a": sorted(set(body_keys(a, "response")) - set(body_keys(b, "response"))),
            "only_b": sorted(set(body_keys(b, "response")) - set(body_keys(a, "response"))),
            "shared": sorted(set(body_keys(a, "response")) & set(body_keys(b, "response"))),
        },
    }
    return result


def endpoint_schema(
    conn: sqlite3.Connection,
    *,
    method: str,
    host: str,
    path_template: str,
    limit: int = 20,
) -> dict:
    rows = conn.execute(
        """
        SELECT entry_id FROM entries
        WHERE method = ? AND host = ? AND path_template = ?
        LIMIT ?
        """,
        (method.upper(), host.lower(), path_template, limit),
    ).fetchall()
    req_samples = []
    resp_samples = []
    for r in rows:
        for side, bucket in (("request", req_samples), ("response", resp_samples)):
            b = conn.execute(
                "SELECT preview_text FROM bodies WHERE entry_id = ? AND side = ?",
                (r["entry_id"], side),
            ).fetchone()
            if b and b["preview_text"]:
                try:
                    bucket.append(json.loads(b["preview_text"]))
                except (json.JSONDecodeError, TypeError):
                    pass
    return {
        "method": method.upper(),
        "host": host.lower(),
        "path_template": path_template,
        "sample_count": len(rows),
        "request_schema": infer_schema(req_samples) if req_samples else None,
        "response_schema": infer_schema(resp_samples) if resp_samples else None,
    }


def run_sql(
    conn: sqlite3.Connection,
    sql: str,
    *,
    limit: int = 100,
) -> dict:
    sql_stripped = sql.strip().rstrip(";")
    if not _SELECT_ONLY.match(sql_stripped):
        return {"error": "Only SELECT statements are allowed"}
    if _FORBIDDEN.search(sql_stripped):
        return {"error": "Forbidden keyword in SQL"}
    # Enforce limit
    upper = sql_stripped.upper()
    if "LIMIT" not in upper:
        sql_stripped = f"{sql_stripped} LIMIT {limit}"
    try:
        cur = conn.execute(sql_stripped)
        cols = [d[0] for d in cur.description] if cur.description else []
        rows = cur.fetchmany(limit)
    except sqlite3.Error as exc:
        return {"error": str(exc)}
    return {
        "columns": cols,
        "rows": [dict(zip(cols, row)) for row in rows],
        "row_count": len(rows),
        "limit": limit,
    }
