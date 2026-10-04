"""Trace a field name or opaque value across a HAR session."""

from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, unquote_plus, urlparse

from hardly.core.filters import is_noise
from hardly.core.har_io import ijson_items
from hardly.core.safe_json import safe_loads
from hardly.core.urls import parse_url

_MAX_HITS = 50
_HIDDEN = re.compile(
    r"""<input\b[^<>]*\btype\s*=\s*['"]hidden['"][^<>]*>""",
    re.I,
)
_ATTR = re.compile(
    r"""\b(name|value|id)\s*=\s*['"]([^'"]*)['"]""",
    re.I,
)


def trace_field(
    conn: sqlite3.Connection,
    *,
    name: str | None = None,
    value: str | None = None,
    har_path: str | Path | None = None,
    host: str | None = None,
    limit: int = 40,
) -> dict[str, Any]:
    """Find where a field *name* or exact *value* appears.

    Value matches never echo the raw value — only length/kind and locations.
    Prefers the on-disk HAR so Cookie/Set-Cookie values can be matched.
    """
    if not name and not value:
        return {"error": "pass name and/or value"}
    path = Path(har_path) if har_path else _har_path(conn)
    if path and path.is_file():
        hits = _from_har(path, name=name, value=value, host=host)
        source = "har"
    else:
        hits = _from_db(conn, name=name, value=value, host=host)
        source = "index"

    hits = hits[: min(limit, _MAX_HITS)]
    return {
        "name": name,
        "value_length": len(value) if value else None,
        "source": source,
        "hit_count": len(hits),
        "hits": hits,
        "next": (
            "Pair with hardly_session_trace_value for auto-discovered reuse, or "
            "hardly_entry_get on hit entry_ids."
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


def _from_har(
    har_path: Path,
    *,
    name: str | None,
    value: str | None,
    host: str | None,
) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    name_l = name.lower() if name else None
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
            for hit in _scan_request(req, url, name_l=name_l, value=value):
                hits.append(
                    {
                        "entry_id": entry_id,
                        "side": "request",
                        "method": method,
                        "path": parsed["path"],
                        **hit,
                    }
                )
            for hit in _scan_response(resp, name_l=name_l, value=value):
                hits.append(
                    {
                        "entry_id": entry_id,
                        "side": "response",
                        "method": method,
                        "path": parsed["path"],
                        "status": resp.get("status"),
                        **hit,
                    }
                )
            if len(hits) >= _MAX_HITS:
                break
    return hits


def _from_db(
    conn: sqlite3.Connection,
    *,
    name: str | None,
    value: str | None,
    host: str | None,
) -> list[dict[str, Any]]:
    clauses = ["e.is_noise = 0", "e.method != 'OPTIONS'"]
    params: list[Any] = []
    if host:
        clauses.append("e.host = ?")
        params.append(host.lower())
    where = " AND ".join(clauses)
    rows = conn.execute(
        f"""
        SELECT e.entry_id, e.method, e.path, e.status, e.query_raw,
               rb.preview_text AS req_body, sb.preview_text AS resp_body
        FROM entries e
        LEFT JOIN bodies rb ON rb.entry_id = e.entry_id AND rb.side = 'request'
        LEFT JOIN bodies sb ON sb.entry_id = e.entry_id AND sb.side = 'response'
        WHERE {where}
        ORDER BY e.entry_id ASC
        """,
        params,
    ).fetchall()
    name_l = name.lower() if name else None
    hits: list[dict[str, Any]] = []
    for row in rows:
        fake_req = {
            "headers": _db_headers(conn, row["entry_id"], "request"),
            "postData": {"text": row["req_body"] or ""},
            "queryString": [],
        }
        fake_resp = {
            "headers": _db_headers(conn, row["entry_id"], "response"),
            "content": {"text": row["resp_body"] or "", "mimeType": "text/html"},
        }
        url = f"https://x{row['path']}"
        if row["query_raw"]:
            url = f"{url}?{row['query_raw']}"
        for hit in _scan_request(fake_req, url, name_l=name_l, value=value):
            hits.append(
                {
                    "entry_id": row["entry_id"],
                    "side": "request",
                    "method": row["method"],
                    "path": row["path"],
                    **hit,
                }
            )
        for hit in _scan_response(fake_resp, name_l=name_l, value=value):
            hits.append(
                {
                    "entry_id": row["entry_id"],
                    "side": "response",
                    "method": row["method"],
                    "path": row["path"],
                    "status": row["status"],
                    **hit,
                }
            )
        if len(hits) >= _MAX_HITS:
            break
    return hits


def _db_headers(
    conn: sqlite3.Connection, entry_id: int, side: str
) -> list[dict[str, str]]:
    out = []
    for h in conn.execute(
        "SELECT name, value_raw, value_redacted FROM headers "
        "WHERE entry_id = ? AND side = ?",
        (entry_id, side),
    ):
        val = h["value_raw"] or h["value_redacted"]
        if val and val != "***REDACTED***":
            out.append({"name": h["name"], "value": val})
    return out


def _scan_request(
    req: dict,
    url: str,
    *,
    name_l: str | None,
    value: str | None,
) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    parsed = urlparse(url)
    for key, val in parse_qsl(parsed.query, keep_blank_values=True):
        if _match(name_l, value, key, unquote_plus(val)):
            hits.append(_hit("query", key, val))
    for seg in parsed.path.strip("/").split("/"):
        if value and seg == value:
            hits.append(_hit("path", None, seg))
    for h in req.get("headers") or []:
        hname = h.get("name") or ""
        hval = str(h.get("value") or "")
        if hname.lower() == "cookie":
            for part in hval.split(";"):
                if "=" not in part:
                    continue
                cname, cval = part.split("=", 1)
                if _match(name_l, value, cname.strip(), cval.strip()):
                    hits.append(_hit("cookie", cname.strip(), cval.strip()))
        elif _match(name_l, value, hname, hval):
            hits.append(_hit("header", hname, hval))
    post = req.get("postData") or {}
    text = post.get("text") or ""
    if text:
        hits.extend(_scan_body(text, name_l=name_l, value=value, where="request.body"))
    return hits


def _scan_response(
    resp: dict,
    *,
    name_l: str | None,
    value: str | None,
) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    for h in resp.get("headers") or []:
        hname = h.get("name") or ""
        hval = str(h.get("value") or "")
        if hname.lower() == "set-cookie" and "=" in hval:
            cname, cval = hval.split(";", 1)[0].split("=", 1)
            if _match(name_l, value, cname.strip(), cval.strip()):
                hits.append(_hit("set-cookie", cname.strip(), cval.strip()))
        elif _match(name_l, value, hname, hval):
            hits.append(_hit("header", hname, hval))
    content = resp.get("content") or {}
    text = content.get("text") or ""
    if text:
        hits.extend(_scan_body(text, name_l=name_l, value=value, where="response.body"))
        for tag in _HIDDEN.findall(text):
            attrs = {m.group(1).lower(): m.group(2) for m in _ATTR.finditer(tag)}
            fname = attrs.get("name") or attrs.get("id") or ""
            fval = attrs.get("value") or ""
            if _match(name_l, value, fname, fval):
                hits.append(_hit("html.hidden", fname, fval))
    return hits


def _scan_body(
    text: str,
    *,
    name_l: str | None,
    value: str | None,
    where: str,
) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    stripped = text.lstrip()
    if stripped.startswith(("{", "[")):
        try:
            data = safe_loads(text)
        except (json.JSONDecodeError, TypeError):
            data = None
        if data is not None:
            for key, val in _walk_json(data):
                if _match(name_l, value, key, str(val) if val is not None else ""):
                    hits.append(_hit(where + ".json", key, str(val)))
            return hits
    if "=" in text and ("&" in text or text.count("=") == 1) and "<" not in text[:40]:
        for key, val in parse_qsl(text, keep_blank_values=True):
            if _match(name_l, value, key, val):
                hits.append(_hit(where + ".form", key, val))
    elif name_l and name_l in text.lower():
        hits.append({"where": where, "name": name_l, "note": "name substring in body"})
    elif value and value in text:
        hits.append(_hit(where, None, value))
    return hits


def _walk_json(obj: Any, prefix: str = "") -> list[tuple[str, Any]]:
    out: list[tuple[str, Any]] = []
    if isinstance(obj, dict):
        for k, v in list(obj.items())[:60]:
            key = f"{prefix}.{k}" if prefix else str(k)
            out.append((str(k), v))
            if isinstance(v, (dict, list)):
                out.extend(_walk_json(v, key))
    elif isinstance(obj, list):
        for i, item in enumerate(obj[:30]):
            out.extend(_walk_json(item, f"{prefix}[{i}]"))
    return out


def _match(
    name_l: str | None, value: str | None, key: str | None, val: str
) -> bool:
    if name_l and (key or "").lower() == name_l:
        return True
    if name_l and name_l in (key or "").lower() and len(name_l) >= 4:
        return True
    if value and val == value:
        return True
    return False


def _hit(where: str, key: str | None, val: str) -> dict[str, Any]:
    out: dict[str, Any] = {"where": where}
    if key:
        out["name"] = key
    if val:
        out["value_length"] = len(val)
        out["value_kind"] = _kind(val)
    return out


def _kind(value: str) -> str:
    if re.fullmatch(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        value,
        re.I,
    ):
        return "uuid"
    if value.isdigit():
        return "digits"
    if value.startswith("eyJ"):
        return "jwtish"
    return "opaque"
