"""Find dynamic values reused from earlier responses into later requests."""

from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, unquote, unquote_plus, urlparse

import ijson

from hardly.core.filters import is_noise
from hardly.core.urls import parse_url

# Values shorter than this are usually noise ("1", "true", "GET").
_MIN_VALUE_LEN = 8
_MAX_CANDIDATES = 400
_MAX_HITS = 40

_HIDDEN_INPUT = re.compile(
    r"""<input\b[^>]*\btype\s*=\s*['"]hidden['"][^>]*>""",
    re.I,
)
_ATTR = re.compile(
    r"""\b(name|value|id)\s*=\s*['"]([^'"]*)['"]""",
    re.I,
)
_TOKENISH_NAME = re.compile(
    r"(token|csrf|xsrf|nonce|viewstate|eventvalidation|requestverification|"
    r"session|state|challenge|authenticity|key|ticket|secret|password|passwd)",
    re.I,
)
# Request headers that are protocol plumbing, not replayed server-issued values.
_PLUMBING_HEADER = re.compile(
    r"^(:|accept|user-agent|host|referer|origin|content-|sec-|cache-control|"
    r"connection|upgrade-insecure|pragma|dnt|te$|if-|range|cookie|authorization|"
    r"x-requested-with|priority|via|forwarded|x-forwarded|x-real-ip|"
    r"traceparent|tracestate|x-datadog|x-b3)",
    re.I,
)
_UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.I,
)


def correlate_tokens(
    conn: sqlite3.Connection,
    *,
    har_path: str | Path | None = None,
    host: str | None = None,
    limit: int = 40,
) -> dict[str, Any]:
    """Report values that appear in a response and later in a request.

    Never returns the raw value — only length, kind, name hints, and entry ids.
    Prefers streaming the original HAR so Set-Cookie / unredacted bodies work.
    """
    path = Path(har_path) if har_path else _har_path_from_meta(conn)
    if path and path.is_file():
        timeline = _timeline_from_har(path, host=host)
        source = "har"
    else:
        timeline = _timeline_from_db(conn, host=host)
        source = "index"

    if not timeline:
        return {
            "host": host,
            "source": source,
            "correlations": [],
            "note": "no entries to correlate",
        }

    # value -> first producer
    producers: dict[str, dict[str, Any]] = {}
    hits: list[dict[str, Any]] = []

    for item in timeline:
        # Match against later request surfaces first (consume), then publish.
        for loc, value, name_hint in item["consume"]:
            if value not in producers:
                continue
            prod = producers[value]
            if prod["entry_id"] >= item["entry_id"]:
                continue
            hits.append(
                {
                    "from_entry_id": prod["entry_id"],
                    "from_path": prod["path"],
                    "from_where": prod["where"],
                    "to_entry_id": item["entry_id"],
                    "to_method": item["method"],
                    "to_path": item["path"],
                    "to_where": loc,
                    "name_hint": name_hint or prod.get("name_hint"),
                    "from_name_hint": prod.get("name_hint"),
                    "to_name_hint": name_hint,
                    "value_kind": _value_kind(value),
                    "value_length": len(value),
                }
            )
            if len(hits) >= min(limit, _MAX_HITS):
                break
        if len(hits) >= min(limit, _MAX_HITS):
            break

        for where, value, name_hint in item["produce"]:
            if value in producers:
                continue
            if len(producers) >= _MAX_CANDIDATES:
                continue
            producers[value] = {
                "entry_id": item["entry_id"],
                "path": item["path"],
                "where": where,
                "name_hint": name_hint,
            }

    # Prefer tokenish / named correlations first.
    hits.sort(
        key=lambda h: (
            0 if h.get("name_hint") and _TOKENISH_NAME.search(str(h["name_hint"])) else 1,
            h["from_entry_id"],
            h["to_entry_id"],
        )
    )
    hits = hits[: min(limit, _MAX_HITS)]

    return {
        "host": host,
        "source": source,
        "correlation_count": len(hits),
        "correlations": hits,
        "candidate_count": len(producers),
        "next": (
            "Wire these into clients: extract from from_entry response "
            "(hardly_forms / hardly_entry) and inject into to_entry request. "
            "Values are omitted on purpose — re-read live or from the HAR."
        ),
    }


def _har_path_from_meta(conn: sqlite3.Connection) -> Path | None:
    row = conn.execute(
        "SELECT value FROM meta WHERE key = 'har_path'"
    ).fetchone()
    if not row:
        return None
    path = Path(row["value"] if isinstance(row, sqlite3.Row) else row[0])
    return path if path.is_file() else None


def _timeline_from_har(
    har_path: Path, *, host: str | None
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    with har_path.open("rb") as f:
        for entry_id, entry in enumerate(ijson.items(f, "log.entries.item")):
            req = entry.get("request") or {}
            resp = entry.get("response") or {}
            method = (req.get("method") or "GET").upper()
            url = req.get("url") or ""
            parsed = parse_url(url)
            if host and parsed["host"].lower() != host.lower():
                continue
            mime = (resp.get("content") or {}).get("mimeType")
            status = resp.get("status")
            if is_noise(method=method, url=url, status=status, mime=mime):
                continue
            if method == "OPTIONS":
                continue
            produce = _extract_produce(resp)
            consume = _extract_consume(req, url)
            out.append(
                {
                    "entry_id": entry_id,
                    "method": method,
                    "path": parsed["path"],
                    "produce": produce,
                    "consume": consume,
                }
            )
    return out


def _timeline_from_db(
    conn: sqlite3.Connection, *, host: str | None
) -> list[dict[str, Any]]:
    clauses = ["e.is_noise = 0", "e.method != 'OPTIONS'"]
    params: list[Any] = []
    if host:
        clauses.append("e.host = ?")
        params.append(host.lower())
    where = " AND ".join(clauses)
    rows = conn.execute(
        f"""
        SELECT e.entry_id, e.method, e.path,
               rb.preview_text AS req_body, sb.preview_text AS resp_body
        FROM entries e
        LEFT JOIN bodies rb ON rb.entry_id = e.entry_id AND rb.side = 'request'
        LEFT JOIN bodies sb ON sb.entry_id = e.entry_id AND sb.side = 'response'
        WHERE {where}
        ORDER BY e.entry_id ASC
        """,
        params,
    ).fetchall()
    out: list[dict[str, Any]] = []
    for row in rows:
        fake_resp = {
            "headers": [],
            "content": {"text": row["resp_body"] or "", "mimeType": "text/html"},
        }
        # Pull non-sensitive headers from index (Cookie/Set-Cookie are redacted).
        for h in conn.execute(
            "SELECT name, value_raw, value_redacted FROM headers "
            "WHERE entry_id = ? AND side = 'response'",
            (row["entry_id"],),
        ):
            val = h["value_raw"] or h["value_redacted"]
            if val and val != "***REDACTED***":
                fake_resp["headers"].append({"name": h["name"], "value": val})
        fake_req = {
            "headers": [],
            "postData": {"text": row["req_body"] or ""},
            "queryString": [],
        }
        for h in conn.execute(
            "SELECT name, value_raw, value_redacted FROM headers "
            "WHERE entry_id = ? AND side = 'request'",
            (row["entry_id"],),
        ):
            val = h["value_raw"] or h["value_redacted"]
            if val and val != "***REDACTED***":
                fake_req["headers"].append({"name": h["name"], "value": val})
        url = f"https://x{row['path']}"
        out.append(
            {
                "entry_id": row["entry_id"],
                "method": row["method"],
                "path": row["path"],
                "produce": _extract_produce(fake_resp),
                "consume": _extract_consume(fake_req, url),
            }
        )
    return out


def _extract_produce(resp: dict) -> list[tuple[str, str, str | None]]:
    found: list[tuple[str, str, str | None]] = []
    for h in resp.get("headers") or []:
        name = (h.get("name") or "").lower()
        value = str(h.get("value") or "")
        if name == "set-cookie" and "=" in value:
            cookie_name, cookie_val = value.split(";", 1)[0].split("=", 1)
            if _keep_value(cookie_val):
                found.append(("set-cookie", cookie_val, cookie_name.strip()))
            decoded = unquote(cookie_val)
            if decoded != cookie_val and _keep_value(decoded):
                found.append(("set-cookie", decoded, cookie_name.strip()))
        elif name == "location" and value:
            # path ids in redirects
            for part in urlparse(value).path.strip("/").split("/"):
                if _keep_value(part) and not part.isalpha():
                    found.append(("location", part, None))
    content = resp.get("content") or {}
    text = content.get("text") or ""
    mime = (content.get("mimeType") or "").lower()
    if text:
        if "html" in mime or "<" in text[:64]:
            found.extend(_hidden_fields(text))
        if "json" in mime or text.lstrip().startswith(("{", "[")):
            found.extend(_json_values(text, where="response.json"))
        # Also scan form-looking bodies
        if "=" in text and "&" in text and "<" not in text[:32]:
            for key, val in parse_qsl(text, keep_blank_values=True):
                if _keep_value(val):
                    found.append(("response.form", val, key))
    return _dedupe_triples(found)


def _extract_consume(
    req: dict, url: str
) -> list[tuple[str, str, str | None]]:
    found: list[tuple[str, str, str | None]] = []
    parsed = urlparse(url)
    for key, val in parse_qsl(parsed.query, keep_blank_values=True):
        if _keep_value(val):
            found.append(("query", unquote_plus(val), key))
    for seg in parsed.path.strip("/").split("/"):
        if _keep_value(seg) and any(ch.isdigit() for ch in seg):
            found.append(("path", seg, None))
    for h in req.get("headers") or []:
        name = (h.get("name") or "").lower()
        value = str(h.get("value") or "")
        if name == "cookie":
            for part in value.split(";"):
                if "=" not in part:
                    continue
                cname, cval = part.split("=", 1)
                if _keep_value(cval.strip()):
                    found.append(("cookie", cval.strip(), cname.strip()))
        elif name in {"x-csrf-token", "x-xsrf-token", "x-request-verification-token"}:
            if _keep_value(value):
                found.append(("header", value, name))
        elif not _PLUMBING_HEADER.match(name) and _keep_value(value):
            # Custom header carrying a value issued earlier (session key,
            # API key handshake, per-page nonce).
            found.append(("header", value, name))
        elif name == "authorization" and _keep_value(value):
            # Skip — always sensitive; still note reuse by length only if Bearer
            token = value.split(None, 1)[-1] if " " in value else value
            if _keep_value(token):
                found.append(("authorization", token, "authorization"))
    post = req.get("postData") or {}
    text = post.get("text") or ""
    if text:
        if text.lstrip().startswith(("{", "[")):
            found.extend(_json_values(text, where="request.json"))
        else:
            for key, val in parse_qsl(text, keep_blank_values=True):
                if _keep_value(val):
                    found.append(("request.form", val, key))
            # HAR params array
            for p in post.get("params") or []:
                val = p.get("value") or ""
                if _keep_value(str(val)):
                    found.append(("request.form", str(val), p.get("name")))
    return _dedupe_triples(found)


def _hidden_fields(html: str) -> list[tuple[str, str, str | None]]:
    out: list[tuple[str, str, str | None]] = []
    for tag in _HIDDEN_INPUT.findall(html):
        attrs = {m.group(1).lower(): m.group(2) for m in _ATTR.finditer(tag)}
        name = attrs.get("name") or attrs.get("id")
        value = attrs.get("value") or ""
        if _keep_value(value):
            out.append(("html.hidden", value, name))
    return out


def _json_values(
    text: str, *, where: str
) -> list[tuple[str, str, str | None]]:
    try:
        data = json.loads(text)
        # Double-encoded JSON: keep parsing while the result is a JSON string.
        while isinstance(data, str) and data.lstrip()[:1] in ("{", "["):
            data = json.loads(data)
    except (json.JSONDecodeError, TypeError):
        return []
    out: list[tuple[str, str, str | None]] = []

    def walk(obj: Any, key: str | None, depth: int) -> None:
        if depth > 6 or len(out) > 80:
            return
        if isinstance(obj, dict):
            for k, v in list(obj.items())[:40]:
                walk(v, str(k), depth + 1)
        elif isinstance(obj, list):
            for item in obj[:20]:
                walk(item, key, depth + 1)
        elif isinstance(obj, str) and _keep_value(obj):
            # Prefer named tokenish keys; still keep long opaque strings.
            if key and (_TOKENISH_NAME.search(key) or len(obj) >= 16):
                out.append((where, obj, key))
            elif len(obj) >= 24:
                out.append((where, obj, key))

    walk(data, None, 0)
    return out


def _keep_value(value: str) -> bool:
    if not value or len(value) < _MIN_VALUE_LEN:
        return False
    if value in {"true", "false", "null", "undefined", "***REDACTED***"}:
        return False
    if value.isdigit() and len(value) < 6:
        return False
    # Skip pure words / UI labels
    if value.isalpha() and len(value) < 16:
        return False
    if " " in value and len(value) < 20:
        return False
    return True


def _value_kind(value: str) -> str:
    if _UUID.match(value):
        return "uuid"
    if re.fullmatch(r"[0-9a-fA-F]{16,}", value):
        return "hex"
    if value.startswith("eyJ"):
        return "jwtish"
    if value.isdigit():
        return "digits"
    if re.search(r"[^A-Za-z0-9._\-]", value):
        return "opaque"
    return "alnum"


def _dedupe_triples(
    items: list[tuple[str, str, str | None]],
) -> list[tuple[str, str, str | None]]:
    seen: set[str] = set()
    out: list[tuple[str, str, str | None]] = []
    for where, value, name in items:
        if value in seen:
            continue
        seen.add(value)
        out.append((where, value, name))
    return out
