"""Detect built-in export endpoints (CSV/XLSX/... downloads) from links, forms
and request paths. Technology-level: path words, format query parameters and
file extensions. Query VALUES are never reported (only the format token that
selected the export, which is a keyword, not data).
"""

from __future__ import annotations

import html
import re
import sqlite3
from typing import Any
from urllib.parse import parse_qsl, urlsplit

_PATH_WORD = re.compile(r"(?<![a-z])(export|download|csv|xlsx|report)s?(?![a-z])", re.I)
_PATH_WORD_LOOSE = re.compile(r"(export|download|xlsx|csv)", re.I)
_FMT_PARAM = {"format", "output", "type", "fmt"}
_FORMATS = {"csv", "xlsx", "xls", "json", "xml", "pdf", "tsv"}
_EXT = re.compile(r"\.(csv|xlsx|xls|tsv)$", re.I)
_ATTR = re.compile(
    r"<(a|form|area|link)\b[^>]*?\b(href|action)\s*=\s*(\"([^\"]*)\"|'([^']*)')[^>]*>",
    re.I | re.S,
)
_METHOD = re.compile(r"\bmethod\s*=\s*[\"']?(\w+)", re.I)


def _inspect(url: str) -> tuple[str, list[str]] | None:
    """Return (path, formats) when ``url`` looks like an export, else None."""
    url = html.unescape(url).strip()
    if not url or url.startswith(("#", "javascript:", "mailto:", "data:")):
        return None
    parts = urlsplit(url)
    path = parts.path or ""
    if not path:
        return None
    formats: list[str] = []
    m = _EXT.search(path)
    if m:
        formats.append(m.group(1).lower())
    for k, v in parse_qsl(parts.query, keep_blank_values=True):
        if k.lower() in _FMT_PARAM and v.lower() in _FORMATS:
            formats.append(v.lower())
    word = bool(_PATH_WORD.search(path) or _PATH_WORD_LOOSE.search(path.rsplit("/", 1)[-1]))
    if not formats and not word:
        return None
    # A bare path word with no format is only kept for export/download/csv/xlsx;
    # "report" alone is too generic unless a format also shows up.
    if not formats:
        last = path.lower()
        if not re.search(r"export|csv|xlsx", last):
            return None
    return path, sorted(set(formats))


def export_links(conn: sqlite3.Connection, host: str | None = None) -> list[dict[str, Any]]:
    """List export-style links/forms in HTML pages and in observed requests."""
    found: dict[tuple[str, str], dict[str, Any]] = {}

    def add(path: str, fmts: list[str], method: str, eid: int, source: str) -> None:
        key = (method, path)
        row = found.setdefault(
            key,
            {"path": path, "formats": [], "method": method, "entry_id": eid, "source": source},
        )
        for f in fmts:
            if f not in row["formats"]:
                row["formats"].append(f)
        if source == "request":
            row["source"] = "request"

    clauses = []
    params: list[Any] = []
    if host:
        clauses.append("e.host = ?")
        params.append(host.lower())
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    for r in conn.execute(
        f"SELECT e.entry_id, e.method, e.path, e.query_raw FROM entries e {where} LIMIT 5000",
        params,
    ):
        url = (r["path"] or "") + (("?" + r["query_raw"]) if r["query_raw"] else "")
        hit = _inspect(url)
        if hit:
            add(hit[0], hit[1], (r["method"] or "GET").upper(), int(r["entry_id"]), "request")

    hclauses = ["b.side = 'response'", "b.preview_text IS NOT NULL", "e.is_noise = 0"]
    if host:
        hclauses.append("e.host = ?")
    for r in conn.execute(
        f"""
        SELECT e.entry_id, b.preview_text, b.content_type, e.mime
        FROM entries e JOIN bodies b ON b.entry_id = e.entry_id
        WHERE {' AND '.join(hclauses)} ORDER BY e.entry_id LIMIT 2000
        """,
        params,
    ):
        ct = (r["content_type"] or r["mime"] or "").lower()
        body = r["preview_text"] or ""
        if "html" not in ct and "<" not in body[:200]:
            continue
        for m in _ATTR.finditer(body):
            url = m.group(4) if m.group(4) is not None else m.group(5)
            hit = _inspect(url or "")
            if not hit:
                continue
            method = "GET"
            if m.group(1).lower() == "form":
                mm = _METHOD.search(m.group(0))
                method = (mm.group(1) if mm else "GET").upper()
            add(hit[0], hit[1], method, int(r["entry_id"]), "link")
    return list(found.values())[:50]
