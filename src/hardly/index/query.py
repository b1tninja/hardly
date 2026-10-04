"""Query helpers over an indexed HAR session."""

from __future__ import annotations

import json
import re
import sqlite3
from typing import Any

from hardly.core.html_forms import extract_html_structure
from hardly.core.js_routes import extract_js_routes
from hardly.core.redact import (
    REDACTED,
    classify_value_shape,
    is_sensitive_key,
    redact_body_text,
)
from hardly.core.safe_json import safe_loads
from hardly.core.schema_infer import infer_schema

_SELECT_ONLY = re.compile(r"^\s*SELECT\b", re.I)
_FORBIDDEN = re.compile(
    r"\b(INSERT|UPDATE|DELETE|DROP|ALTER|ATTACH|DETACH|PRAGMA|REPLACE|CREATE|VACUUM)\b",
    re.I,
)


def _flag_double_encoded(conn: sqlite3.Connection, entry_id: int, content: dict) -> None:
    """Add the double_encoded_json hint when ingest unwrapped this body."""
    if content.get("kind") != "json":
        return
    hints = content.get("hints") or []
    if "double_encoded_json" in hints:
        return
    try:
        hit = conn.execute(
            "SELECT 1 FROM body_signals WHERE entry_id = ? AND kind = 'encoding' "
            "AND name = 'double-encoded-json' LIMIT 1",
            (entry_id,),
        ).fetchone()
    except sqlite3.Error:
        return
    if hit:
        content["hints"] = ["double_encoded_json", *hints][:12]


def body_coverage(
    conn: sqlite3.Connection,
    *,
    host: str | None = None,
    exclude_noise: bool = True,
    limit: int = 20,
) -> dict:
    """Report how many entries have usable body previews vs empty / truncated."""
    clauses = ["1=1"]
    params: list[Any] = []
    if host:
        clauses.append("e.host = ?")
        params.append(host.lower())
    if exclude_noise:
        clauses.append("e.is_noise = 0")
    where = " AND ".join(clauses)
    row = conn.execute(
        f"""
        SELECT
          COUNT(*) AS entries,
          SUM(CASE WHEN b.preview_text IS NOT NULL AND length(b.preview_text) > 0
                   THEN 1 ELSE 0 END) AS with_preview,
          SUM(CASE WHEN b.size IS NOT NULL AND b.size < 0 THEN 1 ELSE 0 END)
              AS size_negative,
          SUM(CASE WHEN b.size IS NOT NULL AND b.preview_text IS NOT NULL
                    AND b.size > length(b.preview_text) + 100 THEN 1 ELSE 0 END)
              AS truncated,
          SUM(CASE WHEN e.has_resp_body = 0 THEN 1 ELSE 0 END) AS no_resp_body
        FROM entries e
        LEFT JOIN bodies b ON b.entry_id = e.entry_id AND b.side = 'response'
        WHERE {where}
        """,
        params,
    ).fetchone()
    entries = int(row["entries"] or 0)
    with_preview = int(row["with_preview"] or 0)
    missing = [
        {
            "entry_id": r["entry_id"],
            "method": r["method"],
            "path": r["path"],
            "status": r["status"],
            "mime": r["mime"],
            "size": r["size"],
            "preview_len": len(r["preview_text"] or "") if r["preview_text"] else 0,
        }
        for r in conn.execute(
            f"""
            SELECT e.entry_id, e.method, e.path, e.status, e.mime,
                   b.size, b.preview_text
            FROM entries e
            LEFT JOIN bodies b ON b.entry_id = e.entry_id AND b.side = 'response'
            WHERE {where}
              AND (b.preview_text IS NULL OR length(b.preview_text) = 0)
              AND e.method != 'OPTIONS'
            ORDER BY e.entry_id
            LIMIT ?
            """,
            [*params, min(limit, 50)],
        ).fetchall()
    ]
    return {
        "entries": entries,
        "with_preview": with_preview,
        "without_preview": max(0, entries - with_preview),
        "size_negative": int(row["size_negative"] or 0),
        "truncated": int(row["truncated"] or 0),
        "no_resp_body_flag": int(row["no_resp_body"] or 0),
        "preview_ratio": round(with_preview / entries, 3) if entries else 0.0,
        "missing_sample": missing,
        "next": (
            "Low preview_ratio on XHR-heavy portals usually means the capture "
            "predated body backfill — re-capture with current hardly, or use "
            "hardly_send_entry / live clients for those paths."
        ),
    }


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


def _host_apex(host: str) -> str:
    """Cheap registrable-domain guess (last two labels)."""
    parts = (host or "").lower().split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return (host or "").lower()


# Tile / analytics / payment / captcha CDNs — never seed preferred_host from these.
_CDN_SEED_RE = re.compile(
    r"(?i)(^|\.)("
    r"arcgis\w*|googleapis|gstatic|ggpht|stripe\w*|"
    r"cloudflare\w*|akamai\w*|edgekey|edgesuite|fastly\w*|walkme|clarity\.ms|linkedin|facebook|fbcdn|"
    r"googletagmanager|google-analytics|googlesyndication|siteimproveanalytics|"
    r"doubleclick|hotjar|segment\.|sentry\.|newrelic|nr-data|"
    r"optimizely|onetrust|cookielaw|cookiebot|trustarc|truste|tiqcdn|adobedtm|demdex|omtrdc|"
    r"qualtrics|intercom\w*|hubspot\w*|hs-\w+|fullstory|mouseflow|crazyegg|datadoghq|"
    r"bing\.com|twimg|ytimg|youtube|vimeocdn|typekit|gravatar|"
    r"fontawesome|bootstrapcdn|jsdelivr|unpkg|cdnjs|jquery\.com|"
    r"hcaptcha|recaptcha|px-cloud|px-cdn|perimeterx|captcha-delivery|datadome|"
    r"google\.com|gstatic\.com"
    r")(\.|$)"
)


def preferred_host(conn: sqlite3.Connection) -> str | None:
    """Pick the host that best represents the guest portal, not a payment iframe.

    Seed from the busiest non-CDN host (API volume), then stay on that apex.
    Prefer an HTML document host on that apex over a pure API sibling and over
    third-party HTML (Stripe / Google Pay / captcha).
    """
    candidates = conn.execute(
        """
        SELECT host, COUNT(*) AS c FROM entries
        WHERE is_noise = 0
        GROUP BY host
        ORDER BY c DESC
        """
    ).fetchall()
    if not candidates:
        return None

    seed = None
    for row in candidates:
        if _CDN_SEED_RE.search(row["host"] or ""):
            continue
        seed = row
        break
    if seed is None:
        seed = candidates[0]

    apex = _host_apex(seed["host"])
    rows = conn.execute(
        """
        SELECT host,
               COUNT(*) AS api_cnt,
               SUM(
                 CASE
                   WHEN lower(IFNULL(mime, '')) LIKE '%html%'
                        AND method = 'GET'
                        AND status BETWEEN 200 AND 399
                   THEN 1 ELSE 0
                 END
               ) AS html_cnt,
               SUM(
                 CASE
                   WHEN method IN ('POST', 'PUT', 'PATCH')
                        AND (
                          lower(IFNULL(mime, '')) LIKE '%html%'
                          OR path LIKE '%.aspx%'
                          OR path LIKE '%/login%'
                          OR path LIKE '%/signin%'
                        )
                   THEN 1 ELSE 0
                 END
               ) AS formish_cnt
        FROM entries
        WHERE is_noise = 0
          AND (host = ? OR host LIKE ?)
        GROUP BY host
        """,
        (apex, f"%.{apex}"),
    ).fetchall()
    if not rows:
        return seed["host"]

    def score(row: sqlite3.Row) -> tuple:
        # Prefer real HTML shells; never let a CDN sibling win via api_cnt alone.
        cdn_penalty = 0 if not _CDN_SEED_RE.search(row["host"] or "") else -1000
        return (
            cdn_penalty + (row["html_cnt"] or 0),
            row["formish_cnt"] or 0,
            row["api_cnt"] or 0,
        )

    with_html = [
        r
        for r in rows
        if (r["html_cnt"] or 0) > 0 and not _CDN_SEED_RE.search(r["host"] or "")
    ]
    pick = max(with_html or [r for r in rows if not _CDN_SEED_RE.search(r["host"] or "")] or rows, key=score)
    return pick["host"]


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
    header_name: str | None = None,
    header_contains: str | None = None,
    mime_contains: str | None = None,
    content_kind: str | None = None,
    exclude_noise: bool = True,
    exclude_options: bool = True,
    limit: int = 50,
    offset: int = 0,
) -> dict:
    from hardly.core.classify import classify_response

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
    if mime_contains:
        clauses.append("e.mime LIKE ?")
        params.append(f"%{mime_contains}%")
    if exclude_noise:
        clauses.append("e.is_noise = 0")
    if exclude_options:
        clauses.append("e.method != 'OPTIONS'")

    joins: list[str] = []
    # Always left-join response body so we can classify the result page cheaply.
    joins.append(
        "LEFT JOIN bodies b ON b.entry_id = e.entry_id AND b.side = 'response'"
    )
    if body_contains:
        clauses.append("b.preview_text LIKE ?")
        params.append(f"%{body_contains}%")
    if header_name or header_contains:
        joins.append("JOIN headers h ON h.entry_id = e.entry_id")
        if header_name:
            clauses.append("lower(h.name) = ?")
            params.append(header_name.lower())
        if header_contains:
            clauses.append(
                "h.value_redacted LIKE ?"
            )
            params.append(f"%{header_contains}%")  # redacted text only: no raw-value oracle

    join = " ".join(joins)
    where = " AND ".join(clauses)
    want_kind = (content_kind or "").strip().lower() or None

    # When filtering by content kind, scan a wider window then paginate in Python.
    scan_limit = min(max(limit + offset, limit) * (8 if want_kind else 1), 2000)
    rows = conn.execute(
        f"""
        SELECT DISTINCT e.entry_id, e.method, e.host, e.path, e.path_template,
               e.status, e.started_datetime, e.time_ms, e.mime,
               b.preview_text, b.size AS body_size, b.content_type
        FROM entries e {join}
        WHERE {where}
        ORDER BY e.entry_id
        LIMIT ?
        """,
        params + [scan_limit],
    ).fetchall()

    entries: list[dict] = []
    for r in rows:
        content = classify_response(
            mime=r["content_type"] or r["mime"],
            path=r["path"],
            body=r["preview_text"],
            size=r["body_size"],
        )
        _flag_double_encoded(conn, r["entry_id"], content)
        from hardly.core.streams import attach_stream_hints

        attach_stream_hints(conn, r["entry_id"], content)
        kind = (content.get("kind") or "").lower()
        subtype = (content.get("subtype") or "").lower()
        if want_kind and want_kind not in {kind, subtype}:
            # Also allow html_table match via kind=table
            if not (want_kind == "table" and kind == "html_table"):
                continue
        entries.append(
            {
                "entry_id": r["entry_id"],
                "method": r["method"],
                "host": r["host"],
                "path": r["path"],
                "path_template": r["path_template"],
                "status": r["status"],
                "mime": r["mime"],
                "content_kind": content.get("kind"),
                "content_subtype": content.get("subtype"),
                "content_hints": (content.get("hints") or [])[:6],
                "started_datetime": r["started_datetime"],
                "time_ms": r["time_ms"],
            }
        )

    total = len(entries)
    page = entries[offset : offset + limit]
    # Without kind filter, approximate total via SQL when we didn't exhaust the scan.
    if not want_kind:
        total = conn.execute(
            f"SELECT COUNT(DISTINCT e.entry_id) AS c FROM entries e {join} WHERE {where}",
            params,
        ).fetchone()["c"]

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "content_kind": want_kind,
        "entries": page,
        "note": (
            "content_kind filter scans up to 2000 candidates then classifies; "
            "total is match count within that window."
            if want_kind
            else None
        ),
    }


def forms_for_entry(
    conn: sqlite3.Connection,
    entry_id: int,
    *,
    side: str = "response",
) -> dict:
    """Extract forms/inputs/signals from one entry body (redacted)."""
    row = conn.execute(
        "SELECT * FROM entries WHERE entry_id = ?", (entry_id,)
    ).fetchone()
    if not row:
        return {"error": f"entry_id {entry_id} not found"}
    body = conn.execute(
        "SELECT content_type, size, preview_text FROM bodies "
        "WHERE entry_id = ? AND side = ?",
        (entry_id, side),
    ).fetchone()
    if not body or not body["preview_text"]:
        return {
            "entry_id": entry_id,
            "side": side,
            "url": _entry_url(row),
            "forms": [],
            "loose_inputs": [],
            "signals": {},
            "form_count": 0,
            "note": f"no {side} body preview stored",
        }
    url = _entry_url(row)
    structure = extract_html_structure(body["preview_text"], base_url=url)
    preview_len = len(body["preview_text"] or "")
    size = int(body["size"] or 0)
    note = None
    if size > preview_len + 100:
        note = (
            f"parsed stored preview ({preview_len} chars); "
            f"original body size={size} — forms near the end may be missing"
        )
    return {
        "entry_id": entry_id,
        "side": side,
        "url": url,
        "method": row["method"],
        "status": row["status"],
        "content_type": body["content_type"],
        "note": note,
        **structure,
    }


def list_forms(
    conn: sqlite3.Connection,
    *,
    host: str | None = None,
    side: str = "response",
    exclude_noise: bool = False,
    limit: int = 30,
    offset: int = 0,
) -> dict:
    """Scan HTML-ish bodies for forms; return compact per-entry summaries."""
    clauses = [
        "b.side = ?",
        "(b.content_type LIKE '%html%' OR b.preview_text LIKE '%<form%' "
        "OR b.preview_text LIKE '%<input%' OR b.preview_text LIKE '%<a %' "
        "OR b.preview_text LIKE '%onclick%' OR b.preview_text LIKE '%onsubmit%' "
        "OR b.preview_text LIKE '%detailLabel%' OR b.preview_text LIKE '%<th%' "
        "OR b.preview_text LIKE '%font-weight-bolder%' "
        "OR b.preview_text LIKE '%fc%span%' OR b.preview_text LIKE '%class=\"base\"%')",
        "b.preview_text IS NOT NULL",
    ]
    params: list[Any] = [side]
    if host:
        clauses.append("e.host = ?")
        params.append(host.lower())
    if exclude_noise:
        clauses.append("e.is_noise = 0")
    where = " AND ".join(clauses)
    # Oversample then rank by label_count so detail pages (label-rich) beat early login/search shells within the first page.
    scan = min(150, max(min(limit, 100) * 5, min(limit, 100) + offset + 10))
    rows = conn.execute(
        f"""
        SELECT e.entry_id, e.method, e.scheme, e.host, e.path, e.query_raw,
               e.status, e.mime, b.content_type, b.size, b.preview_text
        FROM entries e
        JOIN bodies b ON b.entry_id = e.entry_id
        WHERE {where}
        ORDER BY
          CASE
            WHEN b.preview_text LIKE '%detailLabel%' THEN 0
            WHEN b.preview_text LIKE '%font-weight-bolder%' THEN 0
            WHEN b.preview_text LIKE '%fc%span%' THEN 0
            WHEN b.preview_text LIKE '%Document Number:%' THEN 0
            WHEN b.preview_text LIKE '%<th%' OR b.preview_text LIKE '%<dt%' THEN 1
            ELSE 2
          END,
          e.entry_id
        LIMIT ?
        """,
        [*params, scan],
    ).fetchall()
    entries: list[dict] = []
    for row in rows:
        url = _entry_url(row)
        structure = extract_html_structure(row["preview_text"] or "", base_url=url)
        wf = structure.get("webforms") or {}
        if (
            structure["form_count"] == 0
            and not structure.get("loose_inputs")
            and not structure.get("signals")
            and not structure.get("links")
            and not structure.get("handlers")
            and not structure.get("labels")
            and not wf.get("aspnet")
        ):
            continue
        forms_brief = [
            {
                "action": f.get("action"),
                "method": f.get("method"),
                "id": f.get("id") or None,
                "xpath": f.get("xpath"),
                "field_count": f.get("field_count"),
                "field_names": f.get("field_names"),
                "onsubmit": f.get("onsubmit"),
                "onsubmit_functions": f.get("onsubmit_functions"),
            }
            for f in structure.get("forms") or []
        ]
        entries.append(
            {
                "entry_id": row["entry_id"],
                "method": row["method"],
                "url": url,
                "status": row["status"],
                "form_count": structure["form_count"],
                "field_count": structure.get("field_count"),
                "link_count": structure.get("link_count"),
                "handler_count": structure.get("handler_count"),
                "label_count": structure.get("label_count"),
                "forms": forms_brief,
                "links": [
                    {
                        "href": link.get("href"),
                        "text": link.get("text"),
                        "target": link.get("target") or None,
                        "xpath": link.get("xpath") or None,
                    }
                    for link in (structure.get("links") or [])[:12]
                ],
                "labels": (structure.get("labels") or [])[:20],
                "handler_functions": structure.get("handler_functions") or [],
                "signals": structure.get("signals") or {},
                "webforms": {
                    "aspnet": bool(wf.get("aspnet")),
                    "hidden_fields": (wf.get("hidden_fields") or [])[:12],
                    "dopostback_count": wf.get("dopostback_count") or 0,
                },
                "loose_input_names": [
                    f.get("name")
                    for f in structure.get("loose_inputs") or []
                    if f.get("name")
                ][:40],
            }
        )
    entries.sort(
        key=lambda e: (-int(e.get("label_count") or 0), int(e.get("entry_id") or 0))
    )
    page = entries[offset : offset + min(limit, 100)]
    return {
        "side": side,
        "count": len(page),
        "scanned": len(entries),
        "limit": limit,
        "offset": offset,
        "entries": page,
        "next": (
            "Call hardly_page_forms or hardly_page_ui with entry_id for full field / "
            "link / handler lists (values redacted / truncated). Cross-check "
            "handler_functions against hardly_page_embedded_routes. Entries with labels "
            "are sorted first."
        ),
    }


def ui_for_entry(
    conn: sqlite3.Connection,
    entry_id: int,
    *,
    side: str = "response",
) -> dict:
    """Alias of forms_for_entry focused on UI surfaces (same payload)."""
    return forms_for_entry(conn, entry_id, side=side)


def _entry_url(row: sqlite3.Row) -> str:
    scheme = row["scheme"] or "https"
    host = row["host"]
    path = row["path"]
    query = row["query_raw"] or ""
    url = f"{scheme}://{host}{path}"
    if query:
        url += f"?{query}"
    return url


def list_js_routes(
    conn: sqlite3.Connection,
    *,
    host: str | None = None,
    limit: int = 40,
    offset: int = 0,
) -> dict:
    """Mine path literals from JavaScript response bodies."""
    clauses = [
        "b.side = 'response'",
        "b.preview_text IS NOT NULL",
        "("
        "b.content_type LIKE '%javascript%' OR b.content_type LIKE '%ecmascript%' "
        "OR e.path LIKE '%.js' OR e.mime LIKE '%javascript%'"
        ")",
    ]
    params: list[Any] = []
    if host:
        clauses.append("e.host = ?")
        params.append(host.lower())
    where = " AND ".join(clauses)
    rows = conn.execute(
        f"""
        SELECT e.entry_id, e.host, e.path, e.scheme, e.query_raw, b.preview_text
        FROM entries e
        JOIN bodies b ON b.entry_id = e.entry_id
        WHERE {where}
        ORDER BY e.entry_id
        """,
        params,
    ).fetchall()

    by_path: dict[str, dict[str, Any]] = {}
    sources_scanned = 0
    for row in rows:
        text = row["preview_text"] or ""
        if len(text) < 40 or "function" not in text and "/" not in text:
            # Still try short files that only hold URL constants.
            if "'" not in text and '"' not in text:
                continue
        sources_scanned += 1
        base = f"{row['scheme']}://{row['host']}{row['path']}"
        for route in extract_js_routes(text, base_url=base):
            path = route["path"]
            agg = by_path.setdefault(
                path,
                {
                    "path": path,
                    "count": 0,
                    "score": route["score"],
                    "samples": [],
                    "source_entry_ids": [],
                    "body_keys": [],
                    "method": None,
                },
            )
            agg["count"] += route["count"]
            agg["score"] = max(agg["score"], route["score"])
            for k in route.get("body_keys") or []:
                if k not in agg["body_keys"] and len(agg["body_keys"]) < 12:
                    agg["body_keys"].append(k)
            if route.get("method") and not agg["method"]:
                agg["method"] = route["method"]
            if row["entry_id"] not in agg["source_entry_ids"]:
                if len(agg["source_entry_ids"]) < 8:
                    agg["source_entry_ids"].append(row["entry_id"])
            for sample in route.get("samples") or []:
                if sample not in agg["samples"] and len(agg["samples"]) < 3:
                    agg["samples"].append(sample)

    ranked = sorted(
        by_path.values(),
        key=lambda r: (-r["score"], -r["count"], r["path"]),
    )
    page = ranked[offset : offset + min(limit, 100)]
    return {
        "sources_scanned": sources_scanned,
        "route_count": len(ranked),
        "limit": limit,
        "offset": offset,
        "routes": page,
        "next": (
            "Paths are string literals from JS — confirm against hardly_endpoint_list "
            "/ hardly_entry_around after a click that should hit them."
        ),
    }


def entries_around(
    conn: sqlite3.Connection,
    entry_id: int,
    *,
    before: int = 5,
    after: int = 15,
    exclude_noise: bool = True,
    host: str | None = None,
) -> dict:
    """Return neighbors of an entry in chronological order (click → XHR)."""
    center = conn.execute(
        "SELECT * FROM entries WHERE entry_id = ?", (entry_id,)
    ).fetchone()
    if not center:
        return {"error": f"entry_id {entry_id} not found"}

    clauses = ["1=1"]
    params: list[Any] = []
    if exclude_noise:
        clauses.append("is_noise = 0")
    if host:
        clauses.append("host = ?")
        params.append(host.lower())
    elif center["host"]:
        # Default: same host as the center entry (portal XHRs).
        clauses.append("host = ?")
        params.append(center["host"])
    where = " AND ".join(clauses)
    rows = conn.execute(
        f"""
        SELECT entry_id, method, scheme, host, path, query_raw, status, mime,
               started_datetime, time_ms, is_noise, has_resp_body
        FROM entries
        WHERE {where}
        ORDER BY started_datetime ASC, entry_id ASC
        """,
        params,
    ).fetchall()

    ids = [r["entry_id"] for r in rows]
    try:
        idx = ids.index(entry_id)
    except ValueError:
        # Center filtered out (noise / host); include it explicitly.
        rows = list(rows)
        # Re-fetch full ordered list without exclude for positioning
        all_rows = conn.execute(
            """
            SELECT entry_id, method, scheme, host, path, query_raw, status, mime,
                   started_datetime, time_ms, is_noise, has_resp_body
            FROM entries
            WHERE host = ?
            ORDER BY started_datetime ASC, entry_id ASC
            """,
            (center["host"],),
        ).fetchall()
        ids = [r["entry_id"] for r in all_rows]
        if entry_id not in ids:
            return {"error": f"entry_id {entry_id} not in host timeline"}
        idx = ids.index(entry_id)
        rows = all_rows

    start = max(0, idx - max(0, before))
    end = min(len(rows), idx + max(0, after) + 1)
    window = rows[start:end]
    center_started = center["started_datetime"] or ""

    def delta_ms(started: str | None) -> float | None:
        if not started or not center_started:
            return None
        try:
            # HAR timestamps are ISO-ish; compare via datetime when possible.
            from datetime import datetime

            def parse(ts: str) -> datetime:
                return datetime.fromisoformat(ts.replace("Z", "+00:00"))

            return (parse(started) - parse(center_started)).total_seconds() * 1000.0
        except ValueError:
            return None

    entries = []
    for row in window:
        entries.append(
            {
                "entry_id": row["entry_id"],
                "method": row["method"],
                "url": _entry_url(row),
                "path": row["path"],
                "status": row["status"],
                "mime": row["mime"],
                "started_datetime": row["started_datetime"],
                "delta_ms": delta_ms(row["started_datetime"]),
                "is_center": row["entry_id"] == entry_id,
                "has_resp_body": bool(row["has_resp_body"]),
                "is_noise": bool(row["is_noise"]),
            }
        )
    return {
        "center_entry_id": entry_id,
        "host": center["host"],
        "before": before,
        "after": after,
        "count": len(entries),
        "entries": entries,
        "next": (
            "Use hardly_entry_get / hardly_page_forms on XHRs after the center "
            "(positive delta_ms) to map the click handler."
        ),
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
    resp_preview = None
    resp_size = None
    resp_ct = None
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
        if b["side"] == "response":
            resp_preview = b["preview_text"]
            resp_size = b["size"]
            resp_ct = b["content_type"]

    from hardly.core.classify import classify_response

    content = classify_response(
        mime=resp_ct or row["mime"],
        path=row["path"],
        body=resp_preview,
        size=resp_size,
    )
    _flag_double_encoded(conn, entry_id, content)
    from hardly.core.streams import attach_stream_hints

    attach_stream_hints(conn, entry_id, content)

    shapes: list[dict[str, Any]] = []
    try:
        for s in conn.execute(
            """
            SELECT side, where_kind, name, shape
            FROM value_shapes
            WHERE entry_id = ?
            ORDER BY id ASC
            LIMIT 40
            """,
            (entry_id,),
        ):
            shapes.append(
                {
                    "side": s["side"],
                    "where": s["where_kind"],
                    "name": s["name"],
                    "shape": s["shape"],
                }
            )
    except sqlite3.Error:
        shapes = []

    return {
        "entry_id": row["entry_id"],
        "method": row["method"],
        "url": f"{row['scheme']}://{row['host']}{row['path']}"
        + (f"?{row['query_raw']}" if row["query_raw"] else ""),
        "host": row["host"],
        "path": row["path"],
        "path_template": row["path_template"],
        "query": _redact_query(row["query_json"]),
        "status": row["status"],
        "mime": row["mime"],
        "content": content,
        "shapes": shapes,
        "started_datetime": row["started_datetime"],
        "time_ms": row["time_ms"],
        "is_noise": bool(row["is_noise"]),
        "pageref": row["pageref"] if "pageref" in row.keys() else None,
        "initiator_type": (
            row["initiator_type"] if "initiator_type" in row.keys() else None
        ),
        "initiator_url": (
            row["initiator_url"] if "initiator_url" in row.keys() else None
        ),
        "headers": headers,
        "bodies": bodies,
    }


def _redact_query(query_json: str | None) -> dict[str, Any]:
    """Return query params with sensitive / shaped values redacted."""
    if not query_json:
        return {}
    try:
        query = safe_loads(query_json)
    except (json.JSONDecodeError, TypeError):
        return {}
    if not isinstance(query, dict):
        return {}
    out: dict[str, Any] = {}
    for key, value in query.items():
        if is_sensitive_key(str(key)):
            out[key] = REDACTED
            continue
        if isinstance(value, list):
            out[key] = [
                REDACTED
                if isinstance(v, str) and classify_value_shape(v)
                else v
                for v in value
            ]
        elif isinstance(value, str) and classify_value_shape(value):
            out[key] = REDACTED
        else:
            out[key] = value
    return out


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
            data = safe_loads(text)
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
    limit: int = 500,
) -> dict:
    """Merged request/response schema over all samples (up to ``limit``) of an endpoint."""
    from hardly.core.schema_infer import endpoint_samples

    rows = endpoint_samples(
        conn, method=method, host=host, path_template=path_template, limit=limit
    )
    req_samples = [r["request"] for r in rows if r["request"] is not None]
    resp_samples = [r["response"] for r in rows if r["response"] is not None]
    by_status: dict[str, list] = {}
    for r in rows:
        if r["response"] is not None:
            by_status.setdefault(str(r["status"] or 0), []).append(r["response"])
    out = {
        "method": method.upper(),
        "host": host.lower(),
        "path_template": path_template,
        "sample_count": len(rows),
        "request_sample_count": len(req_samples),
        "response_sample_count": len(resp_samples),
        "request_schema": infer_schema(req_samples) if req_samples else None,
        "response_schema": infer_schema(resp_samples) if resp_samples else None,
    }
    if len(by_status) > 1:
        out["response_schema_by_status"] = {k: infer_schema(v) for k, v in sorted(by_status.items())}
    return out


#: Columns that keep un-redacted values for the analysis code; ad-hoc SQL reads them as NULL.
_RAW_COLUMNS = {("headers", "value_raw")}


def _hide_raw_columns(action, arg1, arg2, _db, _source):
    if action == sqlite3.SQLITE_READ and (arg1, arg2) in _RAW_COLUMNS:
        return sqlite3.SQLITE_IGNORE
    return sqlite3.SQLITE_OK


def _allow_all(*_args):
    return sqlite3.SQLITE_OK


def _clean_cell(value: Any) -> Any:
    """Stored text previews keep markup values for the detectors; ad-hoc SQL shows them redacted."""
    if isinstance(value, str) and len(value) > 16:
        from hardly.core.redact import redact_form, redact_markup_text, redact_string

        return redact_form(redact_markup_text(redact_string(value)))
    return value


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
    conn.set_authorizer(_hide_raw_columns)
    try:
        cur = conn.execute(sql_stripped)
        cols = [d[0] for d in cur.description] if cur.description else []
        rows = cur.fetchmany(limit)
    except sqlite3.Error as exc:
        return {"error": str(exc)}
    finally:
        # Python < 3.11 rejects None here (every later statement would be denied).
        conn.set_authorizer(_allow_all)
    return {
        "columns": cols,
        "rows": [dict(zip(cols, (_clean_cell(v) for v in row))) for row in rows],
        "row_count": len(rows),
        "limit": limit,
    }
