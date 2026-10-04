"""Extract data-table structure from HTML bodies, without leaking row data.

Technology-level only. For every table that looks like a data grid we report
the HEADER names (page wording), column count, row count, a *masked* first row
(each value replaced by a shape: digits -> ``9``, letters -> ``a``/``A``,
punctuation kept, at most 24 chars), and a guessed kind per column. Two-column
label/value tables (definition style) report their labels only. Cell contents
are never returned.
"""

from __future__ import annotations

import re
import sqlite3
from html.parser import HTMLParser
from typing import Any

from hardly.core.htmlsafe import defuse_html
from hardly.core.previews import is_truncated, preview_warnings

_MASK_MAX = 24
_HEADER_MAX = 60
_MAX_COLSPAN = 20
_LABEL_MAX = 30

_PAGER_DOC = re.compile(
    r"Page\$\d|Page\$(Next|Prev|First|Last)|\brgPager\b|\bpagination\b|\bpager\b|"
    r"dataTables_paginate|\bui-pg-|Page\s+\d+\s+of\s+\d+|\bpaginate_button\b|"
    r"GridPager|\bgridpager\b",
    re.I,
)
_PAGER_TEXT = re.compile(
    r"(?:\s|\d+|\.\.\.|…|<+|>+|&lt;|&gt;|prev\w*|next|first|last|page|of)*",
    re.I,
)
_PAGER_TOKEN = re.compile(
    r"\d+|\.\.\.|…|<+|>+|prev\w*|next|first|last|«|»|‹|›",
    re.I,
)

_INT = re.compile(r"^[-+]?\d{1,3}(,\d{3})+$|^[-+]?\d+$")
_MONEY = re.compile(
    r"^[(\-+]?\s*[$€£¥]\s*[\d,]+(\.\d+)?\s*\)?$"
    r"|^[(\-]?\d{1,3}(,\d{3})*\.\d{2}\)?$|^[(\-]?\d+\.\d{2}\)?$"
)
_MONTHS = (
    r"(?:jan|feb|mar|apr|may|jun|jul|aug|sep|sept|oct|nov|dec)[a-z]*\.?"
)
_DATE = re.compile(
    r"^\d{1,2}[/.-]\d{1,2}[/.-]\d{2,4}(\s+\d{1,2}:\d{2}(:\d{2})?\s*([ap]m)?)?$"
    r"|^\d{4}[/.-]\d{1,2}[/.-]\d{1,2}([T\s]\d{1,2}:\d{2}(:\d{2})?.*)?$"
    rf"|^{_MONTHS}\s+\d{{1,2}},?\s+\d{{2,4}}$"
    rf"|^\d{{1,2}}\s+{_MONTHS}\s+\d{{2,4}}$",
    re.I,
)


def mask_value(value: str | None) -> str:
    """Replace a cell value by its shape (digits 9, letters a/A, punctuation kept)."""
    text = re.sub(r"\s+", " ", value or "").strip()
    out = []
    for ch in text[:_MASK_MAX]:
        if ch.isdigit():
            out.append("9")
        elif ch.isalpha():
            out.append("A" if ch.isupper() else "a")
        else:
            out.append(ch)
    masked = "".join(out)
    if len(text) > _MASK_MAX:
        masked += "…"
    return masked


def _value_kind(value: str) -> str:
    v = value.strip()
    if _MONEY.match(v):
        return "money"
    if _INT.match(v):
        return "integer"
    if _DATE.match(v):
        return "date"
    return "text"


def column_kind(values: list[str]) -> str:
    """Guess integer|date|money|text|empty from every value in a column."""
    vals = [v for v in values if v and v.strip()]
    if not vals:
        return "empty"
    counts: dict[str, int] = {}
    for v in vals:
        k = _value_kind(v)
        counts[k] = counts.get(k, 0) + 1
    best, n = max(counts.items(), key=lambda kv: kv[1])
    if n / len(vals) >= 0.8:
        return best
    if set(counts) <= {"integer", "money"}:
        return "money" if "money" in counts else "integer"
    return "text"


class _Cell:
    __slots__ = ("parts", "th", "colspan", "bold", "chars", "nested", "linked", "pagelink")

    def __init__(self, th: bool, colspan: int) -> None:
        self.parts: list[str] = []
        self.th = th
        self.colspan = colspan
        self.bold = 0
        self.chars = 0
        self.nested = False
        self.linked = False
        self.pagelink = False

    @property
    def text(self) -> str:
        return re.sub(r"\s+", " ", "".join(self.parts)).strip()

    @property
    def is_bold(self) -> bool:
        return self.chars > 0 and self.bold >= 0.8 * self.chars


class _Table:
    def __init__(self, idx: int) -> None:
        self.idx = idx
        self.rows: list[tuple[str, list[_Cell]]] = []
        self.row: list[_Cell] | None = None
        self.cell: _Cell | None = None
        self.caption: list[str] | None = None
        self.in_caption = False
        self.section = "tbody"
        self.bold_depth = 0
        self.attr_text = ""

    def close_cell(self) -> None:
        if self.cell is not None and self.row is not None:
            self.row.append(self.cell)
        self.cell = None

    def close_row(self) -> None:
        self.close_cell()
        if self.row:
            self.rows.append((self.section, self.row))
        self.row = None


class _Parser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.stack: list[_Table] = []
        self.done: list[_Table] = []
        self.count = 0
        self.skip = 0

    # -- helpers
    def _top(self) -> _Table | None:
        return self.stack[-1] if self.stack else None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag in {"script", "style"}:
            self.skip += 1
            return
        if tag == "table":
            t = _Table(self.count)
            self.count += 1
            t.attr_text = f"{a.get('class', '')} {a.get('id', '')}"
            outer = self._top()
            if outer is not None and outer.cell is not None:
                outer.cell.nested = True
            self.stack.append(t)
            return
        t = self._top()
        if t is None:
            return
        if tag == "caption":
            t.caption = []
            t.in_caption = True
        elif tag in {"thead", "tbody", "tfoot"}:
            t.close_row()
            t.section = tag
        elif tag == "tr":
            t.close_row()
            t.row = []
        elif tag in {"td", "th"}:
            t.close_cell()
            if t.row is None:
                t.row = []
            try:
                span = int(re.sub(r"\D", "", a.get("colspan", "") or "1") or 1)
            except ValueError:
                span = 1
            t.cell = _Cell(tag == "th", max(1, min(span, _MAX_COLSPAN)))
            t.bold_depth = 0
        elif tag in {"b", "strong"}:
            t.bold_depth += 1
        elif tag == "a" and t.cell is not None:
            t.cell.linked = True
            if re.search(r"Page\$|[?&]page=|pager", a.get("href", "") + a.get("onclick", ""), re.I):
                t.cell.pagelink = True
        elif tag == "br" and t.cell is not None:
            t.cell.parts.append(" ")

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style"}:
            self.skip = max(0, self.skip - 1)
            return
        t = self._top()
        if t is None:
            return
        if tag == "table":
            t.close_row()
            self.stack.pop()
            self.done.append(t)
        elif tag == "caption":
            t.in_caption = False
        elif tag in {"td", "th"}:
            t.close_cell()
        elif tag == "tr":
            t.close_row()
        elif tag in {"thead", "tbody", "tfoot"}:
            t.close_row()
            t.section = "tbody"
        elif tag in {"b", "strong"}:
            t.bold_depth = max(0, t.bold_depth - 1)

    def handle_data(self, data: str) -> None:
        if self.skip:
            return
        t = self._top()
        if t is None:
            return
        if t.in_caption and t.caption is not None:
            t.caption.append(data)
        elif t.cell is not None:
            t.cell.parts.append(data)
            n = len(data.strip())
            t.cell.chars += n
            if t.bold_depth:
                t.cell.bold += n

    def finish(self) -> list[_Table]:
        while self.stack:
            t = self.stack.pop()
            t.close_row()
            self.done.append(t)
        return sorted(self.done, key=lambda t: t.idx)


def _is_pager_row(cells: list[_Cell]) -> bool:
    nonempty = [c for c in cells if c.text]
    if not nonempty:
        return any(c.nested for c in cells) and len(cells) == 1
    if any(c.pagelink for c in cells) and all(_PAGER_TEXT.fullmatch(c.text) for c in nonempty):
        return True
    if len(cells) == 1:
        c = cells[0]
        return (c.nested or c.colspan >= 2) and bool(_PAGER_TEXT.fullmatch(c.text))
    return (
        all(_PAGER_TOKEN.fullmatch(c.text) for c in nonempty)
        and any(c.linked for c in nonempty)
    )


def _expand(cells: list[_Cell], width: int | None = None) -> list[str | None]:
    out: list[str | None] = []
    for c in cells:
        out.append(c.text)
        out.extend([None] * (c.colspan - 1))
    if width is not None and len(out) < width:
        out.extend([None] * (width - len(out)))
    return out


def _header_row(rows: list[tuple[str, list[_Cell]]]) -> int | None:
    """Index of the header row, or None."""
    best: int | None = None
    for i, (section, cells) in enumerate(rows):
        if section == "thead" and cells and not _is_pager_row(cells):
            if best is None or len(cells) > len(rows[best][1]):
                best = i
    if best is not None:
        return best
    for i, (section, cells) in enumerate(rows):
        if section == "tfoot" or _is_pager_row(cells):
            continue
        if all(c.th for c in cells) and sum(c.colspan for c in cells) >= 2:
            return i
        nonempty = [c for c in cells if c.text]
        if (
            len(nonempty) >= 2
            and not any(c.th for c in cells)
            and all(c.is_bold for c in nonempty)
        ):
            return i
        break
    return None


def _analyze(t: _Table, doc_pager: bool) -> dict[str, Any] | None:
    rows = t.rows
    if not rows:
        return None
    caption = None
    if t.caption:
        caption = re.sub(r"\s+", " ", "".join(t.caption)).strip()[:_HEADER_MAX] or None
    pager_rows = [i for i, (_, cells) in enumerate(rows) if _is_pager_row(cells)]
    hdr = _header_row(rows)

    if hdr is None:
        return _label_value(t, rows, pager_rows, caption, doc_pager)

    hdr_cells = rows[hdr][1]
    headers: list[str] = []
    for c in hdr_cells:
        headers.extend([c.text[:_HEADER_MAX]] * c.colspan)
    data: list[list[str | None]] = []
    for i, (section, cells) in enumerate(rows):
        if i == hdr or i in pager_rows or section == "tfoot":
            continue
        if section == "thead" or all(c.th for c in cells):
            continue
        data.append(_expand(cells))
    width = max([len(headers), *[len(r) for r in data]] or [0])
    if width < 2:
        return None  # header-only tables (JS-filled grids) are still useful: headers are the schema
    headers += [""] * (width - len(headers))
    cols = [[(r[j] if j < len(r) else None) or "" for r in data] for j in range(width)]
    first = [mask_value(v) for v in ((data[0] + [None] * width)[:width])] if data else []
    return {
        "kind": "data",
        "caption": caption,
        "headers": headers,
        "column_count": width,
        "row_count": len(data),
        "header_only": not data,
        "first_row_masked": first,
        "column_kinds": [column_kind(c) for c in cols],
        "has_pager_hint": bool(pager_rows) or doc_pager
        or bool(re.search(r"pager|paginat", t.attr_text, re.I)),
        "entry_id": None,
    }


def _label_value(
    t: _Table,
    rows: list[tuple[str, list[_Cell]]],
    pager_rows: list[int],
    caption: str | None,
    doc_pager: bool,
) -> dict[str, Any] | None:
    body = [cells for i, (_, cells) in enumerate(rows) if i not in pager_rows]
    pairs = [cells for cells in body if len(cells) == 2 or (len(cells) == 1 and False)]
    if len(pairs) < 2 or len(pairs) < 0.8 * len(body):
        return None
    labelish = sum(
        1
        for c in pairs
        if c[0].text and (c[0].th or c[0].is_bold or c[0].text.endswith(":"))
    )
    if labelish < 0.8 * len(pairs):
        return None
    labels = []
    for c in pairs:
        text = c[0].text.rstrip(":").strip()[:_HEADER_MAX]
        if text and text not in labels:
            labels.append(text)
    return {
        "kind": "label_value",
        "caption": caption,
        "labels": labels[:_LABEL_MAX],
        "column_count": 2,
        "row_count": len(pairs),
        "has_pager_hint": False,
        "entry_id": None,
    }


def extract_tables(html: str | None, *, max_tables: int = 8) -> list[dict[str, Any]]:
    """Return data-table summaries (headers + masked first row) for an HTML page."""
    if not html or "<table" not in html.lower():
        return []
    parser = _Parser()
    try:
        parser.feed(defuse_html(html))
        parser.close()
    except Exception:  # noqa: BLE001 - malformed markup must never raise
        pass
    doc_pager = bool(_PAGER_DOC.search(html))
    out: list[dict[str, Any]] = []
    for t in parser.finish():
        info = _analyze(t, doc_pager)
        if info:
            out.append(info)
        if len(out) >= max_tables:
            break
    return out


def scan_session(
    conn: sqlite3.Connection,
    host: str | None = None,
    entry_id: int | None = None,
    *,
    max_tables: int = 8,
    limit: int = 400,
) -> dict[str, Any]:
    """Scan stored HTML response previews for data tables."""
    clauses = ["b.side = 'response'", "b.preview_text IS NOT NULL"]
    params: list[Any] = []
    if entry_id is not None:
        clauses.append("e.entry_id = ?")
        params.append(int(entry_id))
    else:
        clauses.append("e.is_noise = 0")
        if host:
            clauses.append("e.host = ?")
            params.append(host.lower())
    rows = conn.execute(
        f"""
        SELECT e.entry_id, e.method, e.path, e.mime, b.content_type, b.preview_text, b.size
        FROM entries e JOIN bodies b ON b.entry_id = e.entry_id
        WHERE {' AND '.join(clauses)}
        ORDER BY e.entry_id LIMIT ?
        """,
        [*params, limit],
    ).fetchall()
    tables: list[dict[str, Any]] = []
    truncated: list[dict[str, Any]] = []
    scanned = 0
    for r in rows:
        body = r["preview_text"] or ""
        ct = (r["content_type"] or r["mime"] or "").lower()
        if "html" not in ct and not body.lstrip()[:20].lower().startswith(("<!doctype", "<html", "<table", "<div")):
            continue
        scanned += 1
        if is_truncated(r["size"], body):
            truncated.append({"entry_id": int(r["entry_id"])})
        for info in extract_tables(body, max_tables=max_tables):
            info["entry_id"] = int(r["entry_id"])
            info["path"] = r["path"]
            tables.append(info)
    warnings = preview_warnings(truncated, "tables")
    return {
        **({"warnings": warnings, "truncated_previews": len(truncated)} if warnings else {}),
        "host": host,
        "entry_id": entry_id,
        "entries_scanned": scanned,
        "table_count": len(tables),
        "tables": tables[:60],
        "note": (
            "Headers are the page's own wording; first_row_masked shows value "
            "shapes only (9 digit, a/A letter). Cell values are never returned. "
            "kind=label_value lists labels of definition-style tables."
        ),
    }
