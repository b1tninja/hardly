"""Generic next-link / cursor / Link-header pagination recognition.

Shapes only: ``detect_pagination`` reports which key or header carries the
continuation (and the request parameter it usually maps to), never its value.
``find_next`` and ``iter_follow`` are dependency-free so generated stubs embed
their source and follow the continuation at run time.
"""

from __future__ import annotations

import sqlite3
from typing import Any


def find_next(headers, body):
    """Continuation of a response, or None on the last page.

    Returns {"kind": "link-header"|"next-link"|"cursor", "name": ..., "value":
    ..., "param": request parameter or None}.
    """
    import json
    import re

    link = None
    for k, v in (headers or {}).items():
        if str(k).lower() == "link":
            link = v
    if link:
        for m in re.finditer(r"<([^>]*)>([^<]*)", str(link)):
            rel = re.search(r'rel\s*=\s*"?([^";,]*)"?', m.group(2), re.I)
            if rel and "next" in rel.group(1).lower().split():
                return {"kind": "link-header", "name": "Link rel=next",
                        "value": m.group(1), "param": None}
    try:
        data = json.loads(body or "")
    except (TypeError, ValueError):
        return None
    if isinstance(data, dict) and isinstance(data.get("d"), str):
        try:
            data = json.loads(data["d"])
        except ValueError:
            pass
    if not isinstance(data, dict):
        return None
    wrappers = ("meta", "pagination", "paging", "page", "links", "_links",
                "pageInfo", "page_info", "d", "data", "response")
    scopes = [("", data)]
    for w in wrappers:
        sub = data.get(w)
        if isinstance(sub, dict):
            scopes.append((w + ".", sub))
            for w2 in ("pageInfo", "page_info", "pagination", "links", "_links"):
                if isinstance(sub.get(w2), dict):
                    scopes.append((w + "." + w2 + ".", sub[w2]))
    url_keys = ("next", "nextLink", "next_link", "nextUrl", "next_url",
                "nextHref", "@odata.nextLink", "__next", "next_page_url",
                "nextPageUrl")
    cursor_keys = (
        ("endCursor", "after"), ("next_cursor", "cursor"), ("nextCursor", "cursor"),
        ("nextPageToken", "pageToken"), ("next_page_token", "page_token"),
        ("nextToken", "nextToken"), ("next_token", "next_token"),
        ("continuation", "continuation"), ("continuationToken", "continuationToken"),
        ("next_page", "page"), ("nextPage", "page"),
    )
    for prefix, scope in scopes:
        flags = [scope.get(f) for f in ("hasNextPage", "has_next", "hasMore", "has_more")
                 if f in scope]
        if flags and not any(flags):
            return None
        for key in url_keys:
            val = scope.get(key)
            if isinstance(val, dict):
                val = val.get("href") or val.get("url")
            if isinstance(val, str) and val and re.match(r"^(https?:)?//|^[/?]", val):
                return {"kind": "next-link", "name": prefix + key,
                        "value": val, "param": None}
        for key, param in cursor_keys:
            val = scope.get(key)
            if isinstance(val, (str, int)) and not isinstance(val, bool) and val != "":
                return {"kind": "cursor", "name": prefix + key,
                        "value": str(val), "param": param}
        val = scope.get("next")
        if isinstance(val, str) and val:
            return {"kind": "cursor", "name": prefix + "next",
                    "value": val, "param": "cursor"}
    return None


def iter_follow(fetch, max_pages=200):
    """Yield page bodies, following find_next() until the last page.

    ``fetch(ref)`` takes None (first page) or a find_next() dict and returns
    (headers, body).
    """
    ref = None
    seen = set()
    for _ in range(max_pages):
        headers, body = fetch(ref)
        yield body
        ref = find_next(headers, body)
        if not ref or ref["value"] in seen:
            return
        seen.add(ref["value"])


def detect_pagination(
    conn: sqlite3.Connection, *, host: str | None = None, limit: int = 20
) -> dict[str, Any]:
    """Which continuation conventions the capture's responses use (no values)."""
    where, params = "e.is_noise = 0", []
    if host:
        where += " AND e.host = ?"
        params.append(host.lower())
    rows = conn.execute(
        "SELECT e.entry_id, sb.preview_text AS resp FROM entries e "
        "LEFT JOIN bodies sb ON sb.entry_id = e.entry_id AND sb.side = 'response' "
        f"WHERE {where} ORDER BY e.entry_id LIMIT 2000",
        params,
    ).fetchall()
    found: dict[tuple, list[int]] = {}
    for row in rows:
        eid = int(row["entry_id"])
        hdrs = {
            h["name"]: h["value_redacted"]
            for h in conn.execute(
                "SELECT name, value_redacted FROM headers "
                "WHERE entry_id = ? AND side = 'response' AND lower(name) = 'link'",
                (eid,),
            )
        }
        ref = find_next(hdrs, row["resp"] or "")
        if ref:
            found.setdefault((ref["kind"], ref["name"], ref["param"]), []).append(eid)
    shapes = [
        {"kind": k, "name": n, "param": p, "entries": len(ids),
         "entry_ids": ids[:8]}
        for (k, n, p), ids in sorted(found.items(), key=lambda kv: -len(kv[1]))
    ][:limit]
    return {"host": host, "entries_scanned": len(rows), "pagination": shapes}
