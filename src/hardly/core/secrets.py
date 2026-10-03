"""Locate sensitive field/header *names* without returning values."""

from __future__ import annotations

import json
import sqlite3
from typing import Any
from urllib.parse import parse_qsl

from hardly.core.redact import is_sensitive_header, is_sensitive_key

_MAX = 60


def locate_secrets(
    conn: sqlite3.Connection,
    *,
    host: str | None = None,
    limit: int = 40,
) -> dict[str, Any]:
    """Report where sensitive names appear (never values)."""
    clauses = ["e.is_noise = 0"]
    params: list[Any] = []
    if host:
        clauses.append("e.host = ?")
        params.append(host.lower())
    where = " AND ".join(clauses)

    hits: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()

    for row in conn.execute(
        f"""
        SELECT e.entry_id, e.method, e.path, h.side, h.name
        FROM entries e
        JOIN headers h ON h.entry_id = e.entry_id
        WHERE {where}
        ORDER BY e.entry_id ASC
        """,
        params,
    ):
        if is_sensitive_header(row["name"]) or is_sensitive_key(row["name"]):
            key = (row["entry_id"], row["side"], "header", row["name"].lower())
            if key in seen:
                continue
            seen.add(key)
            hits.append(
                {
                    "entry_id": row["entry_id"],
                    "method": row["method"],
                    "path": row["path"],
                    "side": row["side"],
                    "kind": "header",
                    "name": row["name"],
                }
            )
            if len(hits) >= _MAX:
                break

    if len(hits) < _MAX:
        for row in conn.execute(
            f"""
            SELECT e.entry_id, e.method, e.path, b.side, b.preview_text, b.content_type
            FROM entries e
            JOIN bodies b ON b.entry_id = e.entry_id
            WHERE {where} AND b.preview_text IS NOT NULL
            ORDER BY e.entry_id ASC
            """,
            params,
        ):
            for name, kind in _body_sensitive_names(
                row["preview_text"], row["content_type"]
            ):
                key = (row["entry_id"], row["side"], kind, name.lower())
                if key in seen:
                    continue
                seen.add(key)
                hits.append(
                    {
                        "entry_id": row["entry_id"],
                        "method": row["method"],
                        "path": row["path"],
                        "side": row["side"],
                        "kind": kind,
                        "name": name,
                    }
                )
                if len(hits) >= _MAX:
                    break
            if len(hits) >= _MAX:
                break

    hits = hits[: min(limit, _MAX)]
    by_name: dict[str, int] = {}
    for h in hits:
        by_name[h["name"]] = by_name.get(h["name"], 0) + 1

    return {
        "host": host,
        "hit_count": len(hits),
        "names": sorted(by_name, key=lambda n: (-by_name[n], n.lower())),
        "hits": hits,
        "next": (
            "Names only — values are redacted in the index. "
            "Rotate credentials if a HAR was shared; use hardly_trace(name=...)."
        ),
    }


def _body_sensitive_names(
    text: str, content_type: str | None
) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    ct = (content_type or "").lower()
    stripped = text.lstrip()
    if "json" in ct or stripped.startswith(("{", "[")):
        try:
            data = json.loads(text)
        except (json.JSONDecodeError, TypeError):
            data = None
        if data is not None:
            for key in _json_keys(data):
                if is_sensitive_key(key):
                    out.append((key, "json_key"))
            return out
    if "=" in text and "&" in text and "<" not in text[:40]:
        for key, _ in parse_qsl(text, keep_blank_values=True):
            if key and is_sensitive_key(key):
                out.append((key, "form_field"))
    # HTML password inputs
    if "<" in text[:200] or "html" in ct:
        import re

        for m in re.finditer(
            r"""<(?:input|textarea)\b[^>]*\bname\s*=\s*['"]([^'"]+)['"]""",
            text,
            re.I,
        ):
            if is_sensitive_key(m.group(1)):
                out.append((m.group(1), "html_field"))
        for m in re.finditer(
            r"""type\s*=\s*['"]password['"][^>]*\bname\s*=\s*['"]([^'"]+)['"]"""
            r"""|\bname\s*=\s*['"]([^'"]+)['"][^>]*type\s*=\s*['"]password['"]""",
            text,
            re.I,
        ):
            name = m.group(1) or m.group(2)
            if name:
                out.append((name, "html_password"))
    return out


def _json_keys(obj: Any, depth: int = 0) -> list[str]:
    if depth > 6:
        return []
    keys: list[str] = []
    if isinstance(obj, dict):
        for k, v in list(obj.items())[:40]:
            keys.append(str(k))
            keys.extend(_json_keys(v, depth + 1))
    elif isinstance(obj, list):
        for item in obj[:20]:
            keys.extend(_json_keys(item, depth + 1))
    return keys
