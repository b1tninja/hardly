"""Detect built-in export endpoints (CSV/XLSX/... downloads) from links, forms
and request paths. Technology-level: path words, format query parameters and
file extensions. Query VALUES are never reported (only the format token that
selected the export, which is a keyword, not data).

Each row carries a ``source`` label: ``request`` (seen as a request in the
capture), ``link`` (an ``<a href>``/``<area>``/``<link>`` in HTML), ``form``
(a ``<form action>``) or ``form_field`` (a hidden/submit field inside a form
that selects the export format).
"""

from __future__ import annotations

import html
import re
import sqlite3
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from hardly.core.previews import is_truncated, preview_warnings

# Query parameters whose value names an export format (OGC ``outputFormat`` included).
_FMT_PARAM = {
    "format", "output", "type", "fmt", "export", "download", "outputformat",
    "exportformat", "export_format", "output_format", "exporttype", "export_type",
    "file_format", "fileformat", "dl", "as",
}
_FORMATS = {"csv", "xlsx", "xls", "json", "xml", "pdf", "tsv"}
_MIME_FORMAT = {
    "text/csv": "csv", "application/json": "json", "application/xml": "xml", "text/xml": "xml",
    "application/pdf": "pdf", "text/tab-separated-values": "tsv",
    "application/vnd.ms-excel": "xls",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": "xlsx",
    "excel": "xlsx", "csv": "csv",
}
# Extensions that count for any URL vs. only for links/forms in HTML (a request
# for ``/manifest.json`` is routine traffic, a *link* to ``rows.json`` is a download).
_EXT_ANY = re.compile(r"\.(csv|xlsx|xls|tsv|pdf)$", re.I)
_EXT_LINK = re.compile(r"\.(csv|xlsx|xls|tsv|pdf|json|xml)$", re.I)
# A bare path (no format) is an export only when its LAST segment is an export action.
_ACTION_SEG = re.compile(
    r"^(?:exports?|csv|xlsx|excel"  # bare "download" is usually navigation
    r"|(?:export|download)[-_]?(?:to[-_]?)?(?:csv|xlsx|xls|excel|data|all|results?|report|file|list|table|grid|records?)"
    r"|(?:csv|xlsx|excel)[-_]?(?:export|download)"
    r"|(?:get|to|as)[-_]?(?:csv|xlsx|excel))$",
    re.I,
)
_DOC_SEGMENTS = frozenset(
    {"about", "help", "docs", "doc", "documentation", "faq", "guide", "guides", "blog", "news",
     "support", "learn", "kb", "wiki", "policy", "terms", "privacy", "tutorial", "tutorials"}
)
_ATTR = re.compile(
    r"<(a|area|link)\b[^<>]*?\b(href)\s*=\s*(\"([^\"]*)\"|'([^']*)')[^<>]*>",
    re.I | re.S,
)
_FORM = re.compile(r"<form\b([^<>]*)>(.*?)(?:</form>|(?=<form\b)|\Z)", re.I | re.S)
_FORM_ACTION = re.compile(r"\baction\s*=\s*(?:\"([^\"]*)\"|'([^']*)')", re.I)
_METHOD = re.compile(r"\bmethod\s*=\s*[\"']?(\w+)", re.I)
_INPUT = re.compile(r"<(?:input|button)\b[^<>]*>", re.I | re.S)
_ATTR_KV = re.compile(r"""(?<![\w:-])([\w:-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))""")
_SOURCE_RANK = {"request": 0, "form": 1, "form_field": 2, "link": 3}


def _norm_format(value: str) -> str | None:
    v = html.unescape(value or "").strip().lower()
    if not v:
        return None
    v = v.split(";")[0].strip()
    if v in _FORMATS:
        return v
    return _MIME_FORMAT.get(v)


def _inspect(url: str, *, from_html: bool = False) -> tuple[str, list[str]] | None:
    """Return (path, formats) when ``url`` looks like an export, else None."""
    url = html.unescape(url).strip()
    if not url or url.startswith(("#", "javascript:", "mailto:", "data:")):
        return None
    parts = urlsplit(url)
    path = parts.path or ""
    if not path:
        return None
    formats: list[str] = []
    m = (_EXT_LINK if from_html else _EXT_ANY).search(path)
    if m:
        formats.append(m.group(1).lower())
    for k, v in parse_qsl(parts.query, keep_blank_values=True):
        if k.lower() in _FMT_PARAM:
            f = _norm_format(v)
            if f:
                formats.append(f)
    if formats:
        return path, sorted(set(formats))
    segs = [s for s in path.split("/") if s]
    if not segs or any(s.lower() in _DOC_SEGMENTS for s in segs[:-1]):
        return None
    last = segs[-1]
    if _ACTION_SEG.match(last) or _ACTION_SEG.match(re.sub(r"(?<=[a-z])(?=[A-Z])", "-", last)) \
            or re.fullmatch(r"(?i)(?:export|download)(?:to)?(?:csv|xlsx|excel)\w{0,6}", last) \
            or re.fullmatch(r"(?i)export\w{0,8}", last):
        return path, []
    return None


def _form_field_formats(inner: str) -> list[str]:
    """Format tokens carried by hidden/submit fields (``<input name=format value=csv>``)."""
    out: list[str] = []
    for tag in _INPUT.findall(inner):
        attrs = {
            a.group(1).lower(): (a.group(2) or a.group(3) or a.group(4) or "")
            for a in _ATTR_KV.finditer(tag)
        }
        name = attrs.get("name", "").lower()
        typ = attrs.get("type", "text").lower()
        if name in _FMT_PARAM and typ in {"hidden", "submit", "button", "radio", "image"}:
            f = _norm_format(attrs.get("value", ""))
            if f and f not in out:
                out.append(f)
    return out


def _collect(conn: sqlite3.Connection, host: str | None) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    found: dict[tuple[str, str], dict[str, Any]] = {}
    truncated: list[dict[str, Any]] = []

    def add(path: str, fmts: list[str], method: str, eid: int, source: str) -> None:
        key = (method, path)
        row = found.setdefault(
            key,
            {"path": path, "formats": [], "method": method, "entry_id": eid, "source": source},
        )
        for f in fmts:
            if f not in row["formats"]:
                row["formats"].append(f)
        if _SOURCE_RANK[source] < _SOURCE_RANK[row["source"]]:
            row["source"] = source
            row["entry_id"] = eid

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
        SELECT e.entry_id, b.preview_text, b.content_type, e.mime, b.size
        FROM entries e JOIN bodies b ON b.entry_id = e.entry_id
        WHERE {' AND '.join(hclauses)} ORDER BY e.entry_id LIMIT 2000
        """,
        params,
    ):
        ct = (r["content_type"] or r["mime"] or "").lower()
        body = r["preview_text"] or ""
        if "html" not in ct and "<" not in body[:200]:
            continue
        eid = int(r["entry_id"])
        if is_truncated(r["size"], body):
            truncated.append({"entry_id": eid, "size": int(r["size"]), "preview_chars": len(body)})
        for m in _ATTR.finditer(body):
            url = m.group(4) if m.group(4) is not None else m.group(5)
            hit = _inspect(url or "", from_html=True)
            if hit:
                add(hit[0], hit[1], "GET", eid, "link")
        for fm in _FORM.finditer(body):
            am = _FORM_ACTION.search(fm.group(1))
            action = html.unescape((am.group(1) if am and am.group(1) is not None else (am.group(2) if am else "")) or "")
            mm = _METHOD.search(fm.group(1))
            method = (mm.group(1) if mm else "GET").upper()
            field_fmts = _form_field_formats(fm.group(2))
            hit = _inspect(action, from_html=True) if action else None
            if hit:
                add(hit[0], sorted(set(hit[1]) | set(field_fmts)), method, eid, "form")
            elif field_fmts and action and not action.startswith(("#", "javascript:")):
                path = urlsplit(action).path
                if path:
                    add(path, field_fmts, method, eid, "form_field")
    return list(found.values())[:50], truncated


def export_links(conn: sqlite3.Connection, host: str | None = None) -> list[dict[str, Any]]:
    """List export-style links/forms in HTML pages and in observed requests."""
    return _collect(conn, host)[0]


def export_links_report(conn: sqlite3.Connection, host: str | None = None) -> dict[str, Any]:
    """``export_links`` plus a warning when HTML previews were truncated (links may be missed)."""
    rows, truncated = _collect(conn, host)
    out: dict[str, Any] = {"export_links": rows}
    warnings = preview_warnings(truncated)
    if warnings:
        out["warnings"] = warnings
        out["truncated_previews"] = len(truncated)
    return out
