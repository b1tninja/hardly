"""Stitch a portal session into an annotated chronological story."""

from __future__ import annotations

import json
import re
import sqlite3
from typing import Any
from urllib.parse import parse_qsl

from hardly.core.classify import classify_response
from hardly.core.html_forms import extract_html_structure

_ROLE_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("disclaimer", re.compile(r"disclaimer", re.I)),
    ("search", re.compile(r"search(type|post|criteria)?|gridresults|partialgrid", re.I)),
    ("detail", re.compile(r"detail|documentdetails|/document/|/details/", re.I)),
    ("image", re.compile(r"/image/|showpostingboard", re.I)),
    ("auth", re.compile(r"login|signin|oauth|token|auth", re.I)),
    ("static", re.compile(r"\.(js|css|png|jpg|gif|woff2?)($|\?)", re.I)),
)


def portal_story(
    conn: sqlite3.Connection,
    *,
    host: str | None = None,
    limit: int = 40,
    exclude_noise: bool = True,
    include_related: bool = True,
) -> dict[str, Any]:
    """Build an annotated step list for reverse-engineering a guest portal.

    When ``include_related`` is true (default), also include non-noise traffic
    from sibling hosts on the same apex (e.g. ``api.app.com`` beside
    ``app.app.com``) so SPA captures tell a full story.
    """
    from hardly.index import query as q

    if not host:
        host = q.preferred_host(conn)
    if not host:
        return {"host": None, "steps": [], "note": "no entries"}

    hosts = [host.lower()]
    related: list[str] = []
    if include_related:
        apex = q._host_apex(host)
        for item in q.list_hosts(conn, exclude_noise=True):
            h = (item.get("host") or "").lower()
            if not h or h == host.lower():
                continue
            if h == apex or h.endswith(f".{apex}"):
                related.append(h)
            if len(related) >= 4:
                break
        hosts.extend(related)

    placeholders = ", ".join("?" for _ in hosts)
    clauses = [f"e.host IN ({placeholders})", "e.method != 'OPTIONS'"]
    params: list[Any] = list(hosts)
    if exclude_noise:
        clauses.append("e.is_noise = 0")
    where = " AND ".join(clauses)

    rows = conn.execute(
        f"""
        SELECT e.entry_id, e.method, e.scheme, e.host, e.path, e.path_template,
               e.query_raw, e.status, e.mime, e.started_datetime, e.time_ms,
               rb.preview_text AS req_body, rb.content_type AS req_ct,
               sb.preview_text AS resp_body, sb.content_type AS resp_ct, sb.size AS resp_size
        FROM entries e
        LEFT JOIN bodies rb ON rb.entry_id = e.entry_id AND rb.side = 'request'
        LEFT JOIN bodies sb ON sb.entry_id = e.entry_id AND sb.side = 'response'
        WHERE {where}
        ORDER BY e.started_datetime ASC, e.entry_id ASC
        """,
        params,
    ).fetchall()

    steps: list[dict[str, Any]] = []
    prev_key: tuple[str, str, str] | None = None
    for row in rows:
        role = _role(row["path"] or "", row["mime"] or "")
        if role == "static":
            continue
        key = (row["host"], row["method"], row["path_template"] or row["path"])
        # Collapse consecutive duplicates (polling, repeated assets mislabeled).
        if key == prev_key and steps:
            steps[-1]["repeat"] = int(steps[-1].get("repeat") or 1) + 1
            continue
        prev_key = key

        step: dict[str, Any] = {
            "entry_id": row["entry_id"],
            "host": row["host"],
            "method": row["method"],
            "path": row["path"],
            "path_template": row["path_template"],
            "status": row["status"],
            "role": role,
            "mime": row["mime"],
            "started_datetime": row["started_datetime"],
        }
        req_keys = _body_keys(row["req_body"], row["req_ct"])
        if req_keys:
            step["request_fields"] = req_keys
        content = classify_response(
            mime=row["resp_ct"] or row["mime"],
            path=row["path"],
            body=row["resp_body"],
            size=row["resp_size"],
        )
        step["content"] = {
            "kind": content.get("kind"),
            "subtype": content.get("subtype"),
            "hints": (content.get("hints") or [])[:8],
            "table_headers": content.get("table_headers"),
            "json_keys": content.get("json_keys"),
            "columns": content.get("columns"),
        }
        # Back-compat for older agents / tests
        step["response_kind"] = content.get("kind")
        kind = content.get("kind") or ""
        if kind in {"html", "html_table"} and row["resp_body"]:
            structure = extract_html_structure(
                row["resp_body"],
                base_url=f"{row['scheme']}://{row['host']}{row['path']}",
            )
            if structure.get("form_count"):
                step["forms"] = [
                    {
                        "action": f.get("action"),
                        "method": f.get("method"),
                        "field_names": f.get("field_names"),
                        "onsubmit_functions": f.get("onsubmit_functions"),
                    }
                    for f in (structure.get("forms") or [])[:3]
                ]
            if structure.get("handler_functions"):
                step["handler_functions"] = [
                    f["name"] for f in structure["handler_functions"][:12]
                ]
            wf = structure.get("webforms") or {}
            if wf.get("aspnet"):
                step["webforms"] = {
                    "hidden_fields": wf.get("hidden_fields")[:12],
                    "dopostback": wf.get("dopostback")[:6],
                    "dopostback_count": wf.get("dopostback_count"),
                }
            if structure.get("labels"):
                step["labels"] = [
                    {"label": x["label"], "value": x["value"]}
                    for x in structure["labels"][:12]
                ]
            if structure.get("links"):
                step["link_hrefs"] = [
                    link.get("href")
                    for link in structure["links"][:8]
                    if link.get("href")
                ]
        elif kind in {"json", "jsonl", "jsonp"} and content.get("json_keys"):
            step["response_keys"] = content["json_keys"]

        steps.append(step)
        if len(steps) >= min(limit, 80):
            break

    correlations: list[dict[str, Any]] = []
    try:
        from hardly.core.correlate import correlate_tokens

        # Prefer primary host; fall back to whole capture when related hosts joined.
        corr = correlate_tokens(conn, host=host, limit=12)
        if not corr.get("correlations") and related:
            corr = correlate_tokens(conn, host=None, limit=12)
        correlations = [
            {
                "from_entry_id": c["from_entry_id"],
                "to_entry_id": c["to_entry_id"],
                "name_hint": c.get("name_hint"),
                "to_where": c.get("to_where"),
            }
            for c in (corr.get("correlations") or [])[:12]
        ]
    except Exception:  # noqa: BLE001
        correlations = []

    return {
        "host": host,
        "related_hosts": related,
        "hosts": hosts,
        "step_count": len(steps),
        "steps": steps,
        "correlations": correlations,
        "next": (
            "Use entry_ids with hardly_entry_get / hardly_client_build. "
            "Cross-check handler_functions against hardly_page_embedded_routes; "
            "hardly_session_trace_value for full token reuse detail."
            + (
                " related_hosts were merged for SPA API coverage."
                if related
                else ""
            )
        ),
    }


def _role(path: str, mime: str) -> str:
    for name, pattern in _ROLE_RULES:
        if pattern.search(path) or (name == "static" and pattern.search(mime or "")):
            return name
    if "json" in (mime or "").lower():
        return "api"
    if "html" in (mime or "").lower():
        return "page"
    return "other"


def _body_keys(body: str | None, content_type: str | None) -> list[str]:
    if not body:
        return []
    ct = (content_type or "").lower()
    text = body.strip()
    if "json" in ct or text.startswith(("{", "[")):
        return _json_top_keys(text)
    if "urlencoded" in ct or "=" in text and "&" in text:
        keys: list[str] = []
        for name, _ in parse_qsl(text, keep_blank_values=True):
            if name and name not in keys:
                keys.append(name)
            if len(keys) >= 40:
                break
        return keys
    return []


def _json_top_keys(text: str) -> list[str]:
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return []
    if isinstance(data, dict):
        return sorted(str(k) for k in list(data.keys())[:40])
    if isinstance(data, list) and data and isinstance(data[0], dict):
        return sorted(str(k) for k in list(data[0].keys())[:40])
    return []
