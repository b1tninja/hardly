"""Classify HAR response payloads for agents (JSON flavors, tables, docs, media)."""

from __future__ import annotations

import csv
import io
import json
import re
import sqlite3
from html.parser import HTMLParser
from typing import Any

_JSONP = re.compile(
    r"^\s*(?:/\*.*?\*/\s*|//[^\n]*\n\s*)*"
    r"([A-Za-z_$][\w$.]*)\s*\(\s*([\s\S]*)\)\s*;?\s*$",
    re.DOTALL,
)
_BOM = "\ufeff"

# Path suffixes used when Content-Type is missing or wrong.
_EXT_KIND: tuple[tuple[str, str], ...] = (
    (".jsonl", "jsonl"),
    (".ndjson", "jsonl"),
    (".json", "json"),
    (".csv", "csv"),
    (".tsv", "csv"),
    (".pdf", "pdf"),
    (".docx", "document"),
    (".doc", "document"),
    (".xlsx", "spreadsheet"),
    (".xls", "spreadsheet"),
    (".pptx", "document"),
    (".odt", "document"),
    (".rtf", "document"),
    (".css", "css"),
    (".js", "javascript"),
    (".mjs", "javascript"),
    (".map", "sourcemap"),
    (".png", "image"),
    (".jpg", "image"),
    (".jpeg", "image"),
    (".gif", "image"),
    (".webp", "image"),
    (".svg", "image"),
    (".ico", "image"),
    (".bmp", "image"),
    (".mp4", "video"),
    (".webm", "video"),
    (".mp3", "audio"),
    (".wav", "audio"),
    (".woff2", "font"),
    (".woff", "font"),
    (".ttf", "font"),
    (".eot", "font"),
    (".zip", "archive"),
    (".gz", "archive"),
)


def classify_response(
    *,
    mime: str | None = None,
    path: str | None = None,
    body: str | None = None,
    size: int | None = None,
) -> dict[str, Any]:
    """Return a compact content classification for one response.

    Keys: ``kind``, ``subtype`` (optional), ``hints`` (list of short strings),
    ``confidence`` (high|medium|low), plus kind-specific fields.
    """
    mime_l = (mime or "").lower().split(";")[0].strip()
    path_l = (path or "").lower().split("?", 1)[0]
    text = body if isinstance(body, str) else None
    if text and text.startswith(_BOM):
        text = text.lstrip(_BOM)
    stripped = (text or "").lstrip()
    size_i = int(size) if size is not None else (len(text) if text else 0)

    # --- MIME / extension first pass (no body needed) ---
    kind_from_mime = _kind_from_mime(mime_l)
    kind_from_ext = _kind_from_ext(path_l)

    # Magic-byte / prefix sniff before trusting empty media MIME.
    if stripped.startswith("%PDF") or (text or "").startswith("%PDF"):
        return _pack(
            "pdf",
            confidence="high",
            mime=mime_l or None,
            path=path,
            size=size_i,
            hints=["magic:%PDF", *_media_hints("pdf", mime_l, path_l, size_i)],
        )

    if kind_from_mime in {
        "image",
        "audio",
        "video",
        "font",
        "css",
        "pdf",
        "document",
        "spreadsheet",
        "archive",
    }:
        return _pack(
            kind_from_mime,
            confidence="high",
            mime=mime_l or None,
            path=path,
            size=size_i,
            hints=_media_hints(kind_from_mime, mime_l, path_l, size_i),
        )

    stream_kind = _stream_kind_from_mime(mime_l)
    if stream_kind:
        return _pack(
            stream_kind,
            confidence="high",
            mime=mime_l or None,
            path=path,
            size=size_i,
            hints=[f"stream:{stream_kind}", "see:hardly.core.streams.summarize_streams"],
        )

    if not stripped:
        # Empty / binary omitted — fall back to mime/ext.
        if kind_from_mime:
            return _pack(
                kind_from_mime,
                confidence="medium",
                mime=mime_l or None,
                path=path,
                size=size_i,
                hints=["empty_or_omitted_body"],
            )
        if kind_from_ext:
            return _pack(
                kind_from_ext,
                confidence="low",
                mime=mime_l or None,
                path=path,
                size=size_i,
                hints=["empty_or_omitted_body", "inferred_from_extension"],
            )
        if size_i and size_i < 0:
            return _pack(
                "omitted",
                confidence="high",
                mime=mime_l or None,
                path=path,
                size=size_i,
                hints=["har_size_negative"],
            )
        if size_i == 0:
            return _pack(
                "empty",
                confidence="high",
                mime=mime_l or None,
                path=path,
                size=0,
            )
        return _pack(
            "binary",
            confidence="low",
            mime=mime_l or None,
            path=path,
            size=size_i,
            hints=["no_text_preview"],
        )

    # --- Body sniff (wins over wrong MIME for JSON flavors / CSV) ---
    jsonp = _try_jsonp(stripped)
    if jsonp:
        return jsonp

    jsonl = _try_jsonl(stripped, mime_l)
    if jsonl:
        return jsonl

    wrapped = _try_double_json(stripped)
    if wrapped:
        return wrapped

    as_json = _try_json(stripped, mime_l)
    if as_json:
        return as_json

    if "html" in mime_l or stripped[:32].lower().startswith(
        ("<!doctype", "<html", "<head", "<body", "<div", "<form", "<table")
    ):
        return _classify_html(stripped, mime_l=mime_l, path=path, size=size_i)

    csv_hit = _try_csv(stripped, mime_l, path_l)
    if csv_hit:
        return csv_hit

    from hardly.core.encodings import looks_like_sse

    if looks_like_sse(stripped):
        return _pack(
            "sse",
            confidence="medium",
            mime=mime_l or None,
            path=path,
            size=size_i,
            hints=["stream:sse", "sniffed_event_stream"],
        )

    if kind_from_mime == "javascript" or path_l.endswith((".js", ".mjs")):
        # JSONP already handled; plain JS
        return _pack(
            "javascript",
            confidence="high" if "javascript" in mime_l else "medium",
            mime=mime_l or None,
            path=path,
            size=size_i,
            hints=_js_hints(stripped),
        )

    if kind_from_mime == "css" or path_l.endswith(".css"):
        return _pack(
            "css",
            confidence="high",
            mime=mime_l or None,
            path=path,
            size=size_i,
        )

    if "xml" in mime_l or stripped.startswith(("<?xml", "<")):
        return _pack(
            "xml",
            confidence="high" if "xml" in mime_l else "medium",
            mime=mime_l or None,
            path=path,
            size=size_i,
            hints=_xml_hints(stripped),
        )

    if kind_from_mime:
        return _pack(
            kind_from_mime,
            confidence="medium",
            mime=mime_l or None,
            path=path,
            size=size_i,
        )
    if kind_from_ext:
        return _pack(
            kind_from_ext,
            confidence="low",
            mime=mime_l or None,
            path=path,
            size=size_i,
            hints=["inferred_from_extension"],
        )

    return _pack(
        "text",
        confidence="low",
        mime=mime_l or None,
        path=path,
        size=size_i,
        hints=["untyped_text"],
    )


def summarize_content(
    conn: sqlite3.Connection,
    *,
    host: str | None = None,
    exclude_noise: bool = True,
    limit: int = 80,
    kind: str | None = None,
) -> dict[str, Any]:
    """Histogram of response kinds plus sample entry ids per kind."""
    clauses = ["1=1"]
    params: list[Any] = []
    if host:
        clauses.append("e.host = ?")
        params.append(host.lower())
    if exclude_noise:
        clauses.append("e.is_noise = 0")
    where = " AND ".join(clauses)
    rows = conn.execute(
        f"""
        SELECT e.entry_id, e.method, e.host, e.path, e.mime, e.status,
               b.preview_text, b.size, b.content_type
        FROM entries e
        LEFT JOIN bodies b ON b.entry_id = e.entry_id AND b.side = 'response'
        WHERE {where}
        ORDER BY e.entry_id ASC
        LIMIT ?
        """,
        [*params, min(max(limit, 1), 400)],
    ).fetchall()

    by_kind: dict[str, int] = {}
    samples: dict[str, list[dict[str, Any]]] = {}
    tables = 0
    classified = 0
    for row in rows:
        info = classify_response(
            mime=row["content_type"] or row["mime"],
            path=row["path"],
            body=row["preview_text"],
            size=row["size"],
        )
        if info["kind"] == "json":
            from hardly.index.query import _flag_double_encoded

            _flag_double_encoded(conn, row["entry_id"], info)
        from hardly.core.streams import attach_stream_hints

        attach_stream_hints(conn, row["entry_id"], info)
        k = info["kind"]
        if kind and k != kind and info.get("subtype") != kind:
            continue
        classified += 1
        by_kind[k] = by_kind.get(k, 0) + 1
        if info.get("table_count"):
            tables += int(info["table_count"] or 0)
        bucket = samples.setdefault(k, [])
        if len(bucket) < 5:
            bucket.append(
                {
                    "entry_id": row["entry_id"],
                    "method": row["method"],
                    "path": row["path"],
                    "status": row["status"],
                    "subtype": info.get("subtype"),
                    "hints": (info.get("hints") or [])[:6],
                    "table_headers": info.get("table_headers"),
                }
            )

    return {
        "host": host,
        "scanned": len(rows),
        "classified": classified,
        "by_kind": dict(sorted(by_kind.items(), key=lambda kv: (-kv[1], kv[0]))),
        "html_tables_seen": tables,
        "samples": samples,
        "next": (
            "Filter with kind=json|jsonl|jsonp|csv|html|html_table|pdf|image|… "
            "Drill samples via hardly_entry_get (includes content classification)."
        ),
    }


def _pack(
    kind: str,
    *,
    confidence: str,
    mime: str | None,
    path: str | None,
    size: int,
    hints: list[str] | None = None,
    subtype: str | None = None,
    **extra: Any,
) -> dict[str, Any]:
    out: dict[str, Any] = {
        "kind": kind,
        "confidence": confidence,
        "mime": mime,
        "size": size,
    }
    if subtype:
        out["subtype"] = subtype
    if path:
        out["path_suffix"] = path.lower().rsplit(".", 1)[-1] if "." in (path or "") else None
    if hints:
        out["hints"] = hints[:12]
    out.update(extra)
    return out


def _stream_kind_from_mime(mime: str) -> str | None:
    if mime.startswith("application/grpc-web"):
        return "grpc-web"
    if mime.startswith("application/grpc"):
        return "grpc"
    if "protobuf" in mime or mime.endswith("+proto"):
        return "protobuf"
    if "msgpack" in mime or "messagepack" in mime:
        return "msgpack"
    if mime == "text/event-stream":
        return "sse"
    return None


def _kind_from_mime(mime: str) -> str | None:
    if not mime:
        return None
    if mime in {"application/json", "text/json"} or mime.endswith("+json"):
        return "json"
    if mime in {"application/x-ndjson", "application/jsonl", "text/jsonl"}:
        return "jsonl"
    if mime in {"text/csv", "application/csv", "text/tab-separated-values"}:
        return "csv"
    if "html" in mime:
        return "html"
    if mime.startswith("image/"):
        return "image"
    if mime.startswith("audio/"):
        return "audio"
    if mime.startswith("video/"):
        return "video"
    if mime.startswith("font/") or "font-" in mime or mime in {
        "application/font-woff",
        "application/font-woff2",
        "application/vnd.ms-fontobject",
    }:
        return "font"
    if mime == "text/css":
        return "css"
    if mime in {
        "application/javascript",
        "text/javascript",
        "application/x-javascript",
        "text/ecmascript",
    }:
        return "javascript"
    if mime == "application/pdf" or mime == "application/x-pdf":
        return "pdf"
    if mime in {
        "application/msword",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/vnd.oasis.opendocument.text",
        "application/rtf",
        "text/rtf",
    }:
        return "document"
    if mime in {
        "application/vnd.ms-excel",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/vnd.oasis.opendocument.spreadsheet",
    }:
        return "spreadsheet"
    if mime in {
        "application/zip",
        "application/x-zip-compressed",
        "application/gzip",
        "application/x-gzip",
    }:
        return "archive"
    if mime.startswith("text/"):
        return "text"
    if mime in {"application/octet-stream", "binary/octet-stream"}:
        return "binary"
    if "xml" in mime:
        return "xml"
    return None


def _kind_from_ext(path: str) -> str | None:
    for ext, kind in _EXT_KIND:
        if path.endswith(ext):
            return kind
    return None


def _media_hints(kind: str, mime: str, path: str, size: int) -> list[str]:
    hints = []
    if mime:
        hints.append(f"mime:{mime}")
    if size:
        hints.append(f"bytes:{size}")
    if kind == "image" and path.endswith(".svg"):
        hints.append("vector_svg")
    return hints


def _try_jsonp(text: str) -> dict[str, Any] | None:
    # Avoid treating plain function-looking HTML/JS as JSONP unless it wraps JSON.
    m = _JSONP.match(text[: min(len(text), 200_000)])
    if not m:
        return None
    callback, inner = m.group(1), m.group(2).strip()
    if callback.lower() in {"if", "while", "for", "function", "switch"}:
        return None
    try:
        data = json.loads(inner)
    except (json.JSONDecodeError, TypeError):
        return None
    return _pack(
        "jsonp",
        confidence="high",
        mime=None,
        path=None,
        size=len(text),
        subtype="jsonp",
        hints=[f"callback:{callback}", *_json_shape_hints(data)],
        callback=callback,
        json_keys=_json_top_keys(data),
    )


def _try_jsonl(text: str, mime: str) -> dict[str, Any] | None:
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    if len(lines) < 2 and "jsonl" not in mime and "ndjson" not in mime:
        return None
    if len(lines) < 1:
        return None
    # Require majority of non-empty lines to be JSON objects/arrays
    ok = 0
    keys: list[str] = []
    for ln in lines[:40]:
        try:
            obj = json.loads(ln)
        except (json.JSONDecodeError, TypeError):
            continue
        if isinstance(obj, (dict, list)):
            ok += 1
            if not keys and isinstance(obj, dict):
                keys = sorted(str(k) for k in list(obj.keys())[:20])
    need = 2 if "jsonl" not in mime and "ndjson" not in mime else 1
    if ok < need or ok < max(1, int(0.7 * min(len(lines), 40))):
        return None
    return _pack(
        "jsonl",
        confidence="high" if ok >= 2 else "medium",
        mime=mime or None,
        path=None,
        size=len(text),
        hints=[f"lines:{len(lines)}", f"parsed:{ok}"],
        line_count=len(lines),
        json_keys=keys,
    )


def _try_json(text: str, mime: str) -> dict[str, Any] | None:
    if not (
        text.startswith(("{", "["))
        or "json" in mime
        or mime.endswith("+json")
    ):
        return None
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        # Partial / truncated JSON preview
        if text.startswith(("{", "[")) or "json" in mime:
            return _pack(
                "json",
                confidence="low",
                mime=mime or None,
                path=None,
                size=len(text),
                hints=["truncated_or_invalid_json"],
                subtype="truncated",
            )
        return None
    shape = "array" if isinstance(data, list) else "object" if isinstance(data, dict) else "scalar"
    return _pack(
        "json",
        confidence="high",
        mime=mime or None,
        path=None,
        size=len(text),
        subtype=shape,
        hints=_json_shape_hints(data),
        json_keys=_json_top_keys(data),
    )


def _try_double_json(text: str) -> dict[str, Any] | None:
    """A JSON string whose content is itself a JSON object/array."""
    if not text.startswith('"'):
        return None
    from hardly.core.json_unwrap import unwrap_double_encoded

    data = unwrap_double_encoded(text)
    if data is None:
        return None
    shape = "array" if isinstance(data, list) else "object"
    return _pack(
        "json",
        confidence="high",
        mime=None,
        path=None,
        size=len(text),
        subtype=shape,
        hints=["double_encoded_json", *_json_shape_hints(data)],
        json_keys=_json_top_keys(data),
    )


def _json_top_keys(data: Any) -> list[str]:
    if isinstance(data, dict):
        return sorted(str(k) for k in list(data.keys())[:40])
    if isinstance(data, list) and data and isinstance(data[0], dict):
        return sorted(str(k) for k in list(data[0].keys())[:40])
    return []


def _json_shape_hints(data: Any) -> list[str]:
    hints: list[str] = []
    if isinstance(data, list):
        hints.append(f"array_len:{len(data)}")
        if data and isinstance(data[0], dict):
            hints.append("array_of_objects")
    elif isinstance(data, dict):
        hints.append(f"keys:{len(data)}")
        for key in ("data", "results", "items", "rows", "records", "value"):
            if key in data and isinstance(data[key], list):
                hints.append(f"nested_list:{key}:{len(data[key])}")
                break
    return hints


def _try_csv(text: str, mime: str, path: str) -> dict[str, Any] | None:
    looks_csv = (
        "csv" in mime
        or "tab-separated" in mime
        or path.endswith((".csv", ".tsv"))
    )
    sample = text[:8000]
    if not looks_csv:
        # Heuristic: 2+ lines, consistent delimiter
        lines = [ln for ln in sample.splitlines() if ln.strip()]
        if len(lines) < 2:
            return None
        if not ("," in lines[0] or "\t" in lines[0] or ";" in lines[0]):
            return None
        # Reject if looks like HTML/JSON/code
        if lines[0].lstrip().startswith(("<", "{", "[", "function", "var ", "const ")):
            return None

    dialect_name = "excel"
    delim = ","
    if "\t" in sample.splitlines()[0] if sample.splitlines() else "":
        delim = "\t"
        dialect_name = "excel-tab"
    elif sample.count(";") > sample.count(",") and ";" in (sample.splitlines()[0] if sample else ""):
        delim = ";"

    try:
        reader = csv.reader(io.StringIO(sample), delimiter=delim)
        rows = [r for r in reader if any(cell.strip() for cell in r)]
    except csv.Error:
        return None
    if len(rows) < 1:
        return None
    if not looks_csv and len(rows) < 2:
        return None
    header = [c.strip() for c in rows[0]][:20]
    # Header-ish: mostly non-numeric short cells
    headerish = sum(1 for c in header if c and not c.replace(".", "").isdigit()) >= max(
        1, len(header) // 2
    )
    return _pack(
        "csv",
        confidence="high" if looks_csv or headerish else "medium",
        mime=mime or None,
        path=path or None,
        size=len(text),
        subtype="tsv" if delim == "\t" else "csv",
        hints=[
            f"delimiter:{delim!r}",
            f"rows_preview:{len(rows)}",
            f"cols:{len(header)}",
            *(["headerish"] if headerish else []),
        ],
        columns=header if headerish else None,
        row_count_preview=len(rows),
    )


class _TableScanner(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tables = 0
        self._in_table = 0
        self._in_th = False
        self._in_td = False
        self._in_caption = False
        self._buf: list[str] = []
        self.headers: list[str] = []
        self.captions: list[str] = []
        self.data_attrs: list[str] = []
        self.row_hints = 0
        self.grid_hints: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        ad = {k.lower(): (v or "") for k, v in attrs}
        t = tag.lower()
        if t == "table":
            self.tables += 1
            self._in_table += 1
            for key, val in ad.items():
                if key.startswith("data-") and key not in self.data_attrs:
                    self.data_attrs.append(key)
                if key == "class" and val:
                    low = val.lower()
                    for token in (
                        "datatable",
                        "grid",
                        "table",
                        "results",
                        "ag-grid",
                        "ui-grid",
                    ):
                        if token in low and token not in self.grid_hints:
                            self.grid_hints.append(token)
        elif t == "th" and self._in_table:
            self._in_th = True
            self._buf = []
        elif t == "td" and self._in_table:
            self._in_td = True
            self.row_hints += 1
        elif t == "caption" and self._in_table:
            self._in_caption = True
            self._buf = []
        elif t in {"div", "span", "tr"}:
            for key, val in ad.items():
                if key.startswith("data-") and any(
                    x in key for x in ("id", "document", "row", "key", "href", "url")
                ):
                    if key not in self.data_attrs:
                        self.data_attrs.append(key)
                if key == "class" and val:
                    low = val.lower()
                    for token in ("detailLabel", "documentrow", "result-row", "ag-row"):
                        if token.lower() in low and token.lower() not in self.grid_hints:
                            self.grid_hints.append(token.lower())

    def handle_endtag(self, tag: str) -> None:
        t = tag.lower()
        if t == "table" and self._in_table:
            self._in_table -= 1
        elif t == "th" and self._in_th:
            text = re.sub(r"\s+", " ", "".join(self._buf)).strip()
            # Skip templating leftovers (Angular/Handlebars) as header hints.
            if (
                text
                and "{{" not in text
                and "{%" not in text
                and text not in self.headers
                and len(self.headers) < 24
            ):
                self.headers.append(text[:80])
            self._in_th = False
            self._buf = []
        elif t == "td":
            self._in_td = False
        elif t == "caption" and self._in_caption:
            text = re.sub(r"\s+", " ", "".join(self._buf)).strip()
            if text and len(self.captions) < 4:
                self.captions.append(text[:100])
            self._in_caption = False
            self._buf = []

    def handle_data(self, data: str) -> None:
        if self._in_th or self._in_caption:
            self._buf.append(data)


def _classify_html(
    text: str, *, mime_l: str, path: str | None, size: int
) -> dict[str, Any]:
    scanner = _TableScanner()
    try:
        scanner.feed(text[:120_000])
        scanner.close()
    except Exception:  # noqa: BLE001
        pass

    hints: list[str] = []
    subtype = None
    kind = "html"
    if scanner.tables:
        kind = "html_table"
        subtype = "table"
        hints.append(f"tables:{scanner.tables}")
        hints.append(f"td_cells_preview:{scanner.row_hints}")
        for g in scanner.grid_hints[:6]:
            hints.append(f"grid:{g}")
        for a in scanner.data_attrs[:8]:
            hints.append(f"attr:{a}")
    else:
        # Partial table markup / grid without <table>
        if scanner.grid_hints or scanner.data_attrs:
            hints.extend(f"grid:{g}" for g in scanner.grid_hints[:6])
            hints.extend(f"attr:{a}" for a in scanner.data_attrs[:6])
            if scanner.grid_hints:
                subtype = "gridish"

    low = text[:4000].lower()
    if "__viewstate" in low:
        hints.append("aspnet_viewstate")
    if "application/json" in low or "datatables" in low:
        hints.append("embedded_ajax_hints")

    return _pack(
        kind,
        confidence="high" if "html" in mime_l else "medium",
        mime=mime_l or None,
        path=path,
        size=size,
        subtype=subtype,
        hints=hints,
        table_count=scanner.tables,
        table_headers=scanner.headers[:16] or None,
        table_captions=scanner.captions or None,
        data_attrs=scanner.data_attrs[:12] or None,
    )


def _js_hints(text: str) -> list[str]:
    hints = []
    if "webpack" in text[:2000] or "__NEXT_DATA__" in text[:4000]:
        hints.append("bundled_app")
    if text.lstrip().startswith(("!", "(function", "define(", "require(")):
        hints.append("module_or_bundle")
    return hints


def _xml_hints(text: str) -> list[str]:
    hints = []
    if text.lstrip().startswith("<?xml"):
        hints.append("xml_decl")
    if "<soap" in text[:500].lower():
        hints.append("soap")
    return hints
