"""Detect common data-grid frameworks and data/paging conventions.

Technology-level only: UI grid libraries (HTML signatures), response envelope
conventions (JSON key sets), and request paging parameters. Nothing here knows
about any particular website or subject matter. Output is names and counts —
never row data or parameter values.
"""

from __future__ import annotations

import html
import json
import re
import sqlite3
from collections import Counter
from typing import Any
from urllib.parse import parse_qsl

# --- HTML grid libraries: (name, regex on markup/scripts) -------------------
_HTML_GRIDS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("datatables", re.compile(r"dataTables_wrapper|jquery\.dataTables|\bnew\s+DataTable\s*\(|\.DataTable\s*\(|cdn\.datatables\.net|dataTables(\.[\w-]+)*\.(min\.)?(js|css)|class=\"[^\"]*\bdataTable\b|\bdt-(container|layout-row|paging|search)\b", re.I)),
    ("jqgrid", re.compile(r"ui-jqgrid|jqGrid\s*\(|\bjqgrow\b", re.I)),
    ("ag-grid", re.compile(r"\bag-root\b|ag-grid|ag-theme-", re.I)),
    ("kendo-grid", re.compile(r"\bk-grid\b|kendoGrid\s*\(|kendo\.(all|web)(\.min)?\.js", re.I)),
    ("telerik-radgrid", re.compile(r"\bRadGrid\d*\b|rgMasterTable|\brgRow\b|\brgPager\b|\brgCurrentPage\b|\brgNumPart\b|Telerik\.Web\.UI|RadAjaxPanel", re.I)),
    ("devextreme", re.compile(r"\bdxDataGrid\b|dx-data-?grid|DevExpress\.ui\.dxDataGrid|\bdx\.all\b", re.I)),
    # case-sensitive on purpose: the host name js.devexpress.com must not match
    ("devexpress-aspx", re.compile(r"\bdxgvControl|\bdxgvTable|ASPxGridView")),
    ("syncfusion", re.compile(r"\be-grid\b|\bejGrid\b", re.I)),
    ("aspnet-gridview", re.compile(r"id=\"[^\"]*GridView[^\"]*\"|__doPostBack\(\s*'[^']*GridView[^']*'", re.I)),
    ("tabulator", re.compile(r"\btabulator\b", re.I)),
    ("handsontable", re.compile(r"handsontable|\bht_master\b", re.I)),
    ("bootstrap-table", re.compile(r"bootstrap-table|data-toggle=\"table\"|data-bs-toggle=\"table\"", re.I)),
    ("extjs-grid", re.compile(r"\bx-grid\b|Ext\.grid", re.I)),
    ("primefaces-datatable", re.compile(r"ui-datatable", re.I)),
    ("primeng-table", re.compile(r"<p-table\b|\bp-datatable\b", re.I)),
    ("mui-datagrid", re.compile(r"MuiDataGrid", re.I)),
    ("ant-table", re.compile(r"\bant-table\b", re.I)),
    ("angular-material-table", re.compile(r"\bmat-(mdc-)?table\b", re.I)),
    ("vaadin-grid", re.compile(r"vaadin-grid", re.I)),
    ("slickgrid", re.compile(r"\bslick-viewport\b|SlickGrid", re.I)),
    ("webix", re.compile(r"webix_dtable", re.I)),
    ("w2ui", re.compile(r"w2ui-grid", re.I)),
    ("gridjs", re.compile(r"\bgridjs-", re.I)),
    ("tanstack-table", re.compile(r"@tanstack/(react-)?table|react-table", re.I)),
)
# WebForms pager/sort commands travel inside __doPostBack arguments.
_POSTBACK_CMD = re.compile(r"__doPostBack\(\s*'[^']*'\s*,\s*'(Page\$[^']*|Sort\$[^']*|Select\$\d+|Edit\$\d+)'", re.I)
# Telerik/Infragistics-style pagers: the grid control id is the target and the
# argument is empty.
_POSTBACK_CONTROL_PAGER = re.compile(r"__doPostBack\(\s*'[^']*\$ctl\d+\$ctl\d+\$ctl\d+[^']*'\s*,\s*''", re.I)
# Library script/stylesheet names seen as request paths.
_URL_LIBS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("datatables", re.compile(r"dataTables(\.[\w-]+)*\.(min\.)?(js|css)|datatables\.net", re.I)),
    ("jqgrid", re.compile(r"jquery\.jqGrid|jqgrid", re.I)),
    ("ag-grid", re.compile(r"ag-grid", re.I)),
    ("kendo-grid", re.compile(r"kendo\.(all|web|grid)", re.I)),
    ("telerik-radgrid", re.compile(r"Telerik\.Web\.UI\.WebResource|RadGrid", re.I)),
    ("devextreme", re.compile(r"/dx\.all|devextreme", re.I)),
    ("tabulator", re.compile(r"tabulator", re.I)),
    ("handsontable", re.compile(r"handsontable", re.I)),
    ("bootstrap-table", re.compile(r"bootstrap-table", re.I)),
    ("syncfusion", re.compile(r"syncfusion|ej2", re.I)),
)

# --- JSON envelope conventions: (name, required top-level keys, any-of) ------
_JSON_ENVELOPES: tuple[tuple[str, frozenset[str], frozenset[str]], ...] = (
    ("datatables-server", frozenset({"recordsTotal", "recordsFiltered"}), frozenset()),
    ("jqgrid", frozenset({"records", "rows"}), frozenset({"page", "total"})),
    ("odata-v4", frozenset(), frozenset({"@odata.context", "@odata.count", "@odata.nextLink"})),
    ("odata-v2", frozenset({"d"}), frozenset({"results", "__count", "__next"})),
    ("aspnet-d-wrapper", frozenset({"d"}), frozenset()),
    ("json-api", frozenset({"data"}), frozenset({"included", "jsonapi", "links"})),
    ("hal", frozenset(), frozenset({"_links", "_embedded"})),
    ("spring-page", frozenset({"content", "totalElements"}), frozenset({"totalPages", "pageable", "number"})),
    ("drf-pagination", frozenset({"count", "results"}), frozenset({"next", "previous"})),
    ("relay-connection", frozenset({"edges", "pageInfo"}), frozenset()),
    ("elasticsearch-hits", frozenset({"hits"}), frozenset({"took", "timed_out", "_shards"})),
    ("arcgis-rest", frozenset({"features"}), frozenset({"fields", "objectIdFieldName", "exceededTransferLimit", "geometryType"})),
    ("geojson", frozenset({"type", "features"}), frozenset()),
    ("kendo-datasource", frozenset({"Data", "Total"}), frozenset()),
    ("generic-paged-list", frozenset(), frozenset({"totalCount", "total_count", "totalRecords", "totalItems", "nextPageToken", "next_cursor", "hasMore", "has_more"})),
)

# --- request paging/sort/filter parameter conventions ------------------------
_PARAM_STYLES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("datatables-server", re.compile(r"^(draw|start|length|search\[value\]|order\[\d+\]\[column\]|columns\[\d+\]\[data\])$")),
    ("jqgrid", re.compile(r"^(_search|nd|sidx|sord)$")),
    ("kendo", re.compile(r"^(take|skip|sort\[\d+\]\[field\]|filter\[.*\]|group)$")),
    ("odata", re.compile(r"^\$(top|skip|filter|orderby|count|select|expand|inlinecount|search)$")),
    ("offset-limit", re.compile(r"^(offset|limit)$")),
    ("page-number", re.compile(r"^(page|pageNumber|page_number|pageIndex|per_page|perPage|pageSize|page_size|size)$", re.I)),
    ("cursor", re.compile(r"^(cursor|after|before|first|last|pageToken|page_token|next_cursor)$")),
    ("solr-es", re.compile(r"^(rows|from|q\.op|fq|wt)$")),
    ("arcgis", re.compile(r"^(resultOffset|resultRecordCount|outFields|where|returnGeometry|f|orderByFields|objectIds)$")),
    ("sort", re.compile(r"^(sort|sortBy|sort_by|orderBy|order_by|order|dir|sortOrder)$", re.I)),
)

_DATA_ATTR = re.compile(r"\sdata-([a-z][a-z0-9-]{1,40})\s*=", re.I)
_JSON_KEY = re.compile(r'"((?:[^"\\]|\\.){1,60})"\s*:')


def detect_grids(
    conn: sqlite3.Connection, *, host: str | None = None, limit: int = 20
) -> dict[str, Any]:
    """Summarise grid frameworks, envelope conventions and paging parameters."""
    where = "e.is_noise = 0"
    params: list[Any] = []
    if host:
        where += " AND e.host = ?"
        params.append(host.lower())
    rows = conn.execute(
        f"""
        SELECT e.entry_id, e.method, e.path_template, e.path, e.query_raw,
               e.mime, sb.preview_text AS resp, sb.content_type AS resp_ct,
               rb.preview_text AS req
        FROM entries e
        LEFT JOIN bodies sb ON sb.entry_id = e.entry_id AND sb.side = 'response'
        LEFT JOIN bodies rb ON rb.entry_id = e.entry_id AND rb.side = 'request'
        WHERE {where}
        ORDER BY e.entry_id LIMIT 2000
        """,
        params,
    ).fetchall()

    html_hits: dict[str, list[int]] = {}
    json_hits: dict[str, list[int]] = {}
    param_hits: dict[str, Counter[str]] = {}
    param_entries: dict[str, list[int]] = {}
    postback_cmds: Counter[str] = Counter()
    data_attrs: Counter[str] = Counter()

    for row in rows:
        eid = int(row["entry_id"])
        body = row["resp"] or ""
        ct = (row["resp_ct"] or row["mime"] or "").lower()
        json_like = body.lstrip().startswith(("{", "[")) if body else False
        if body and not json_like and ("html" in ct or body.lstrip().startswith("<")):
            body = html.unescape(body)
            for name, pat in _HTML_GRIDS:
                if pat.search(body):
                    html_hits.setdefault(name, []).append(eid)
            for m in _POSTBACK_CMD.finditer(body):
                postback_cmds[re.sub(r"\d+", "N", m.group(1))] += 1
            n_ctrl = len(_POSTBACK_CONTROL_PAGER.findall(body))
            if n_ctrl:
                postback_cmds["control-id pager (empty argument)"] += n_ctrl
            for m in _DATA_ATTR.finditer(body):
                data_attrs[m.group(1).lower()] += 1
        elif body and (json_like or "json" in ct):
            keys = _top_keys(body)
            for name, name_req, any_of in _JSON_ENVELOPES:
                if name_req <= keys and (not any_of or keys & any_of):
                    json_hits.setdefault(name, []).append(eid)
        # request parameters (names only)
        names = [k for k, _ in parse_qsl(row["query_raw"] or "", keep_blank_values=True)]
        req = row["req"] or ""
        if req and not req.lstrip().startswith(("{", "[", "<")):
            names += [k for k, _ in parse_qsl(req, keep_blank_values=True)]
        elif req.lstrip().startswith("{"):
            names += list(_top_keys(req))
        for n in names:
            for style, pat in _PARAM_STYLES:
                if pat.match(n):
                    param_hits.setdefault(style, Counter())[n] += 1
                    param_entries.setdefault(style, []).append(eid)

    # Libraries named in request URLs (scripts are separate HAR entries).
    for row in rows:
        target = f"{row['path']}"
        for name, pat in _URL_LIBS:
            if pat.search(target):
                html_hits.setdefault(name, []).append(int(row["entry_id"]))
    # Signals computed at ingest on the full body (markers often sit beyond
    # the stored preview). Absent in sessions indexed by older versions.
    try:
        for r in conn.execute("SELECT entry_id, name FROM body_signals WHERE kind = 'grid'"):
            html_hits.setdefault(r["name"], []).append(int(r["entry_id"]))
    except sqlite3.Error:
        pass

    def pack(hits: dict[str, list[int]]) -> list[dict[str, Any]]:
        return [
            {"name": n, "entries": len(ids), "entry_ids": sorted(set(ids))[:8]}
            for n, ids in sorted(hits.items(), key=lambda kv: -len(kv[1]))
        ][:limit]

    param_styles = [
        {
            "style": style,
            "params": [n for n, _ in names.most_common(8)],
            "entries": len(set(param_entries[style])),
            "entry_ids": sorted(set(param_entries[style]))[:8],
        }
        for style, names in sorted(param_hits.items(), key=lambda kv: -sum(kv[1].values()))
    ][:limit]
    return {
        "host": host,
        "entries_scanned": len(rows),
        "html_grids": pack(html_hits),
        "json_envelopes": pack(json_hits),
        "request_param_styles": param_styles,
        "webforms_pager_commands": dict(postback_cmds.most_common(8)),
        "data_attributes": [
            {"name": f"data-{n}", "count": c} for n, c in data_attrs.most_common(limit)
        ],
        "next": (
            "Use hardly_entry / hardly_outline on entry_ids; server-side grids "
            "need the param style replayed (e.g. start/length or page/pageSize)."
        ),
    }


def html_grid_signals(text: str) -> list[str]:
    """Grid library names found anywhere in a (possibly very large) HTML body."""
    text = html.unescape(text)
    return [name for name, pat in _HTML_GRIDS if pat.search(text)]


def _top_keys(text: str) -> frozenset[str]:
    """Top-level-ish JSON keys from a possibly truncated preview."""
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        # Truncated preview: take keys seen in the first level of text.
        return frozenset(m.group(1) for m in _JSON_KEY.finditer(text[:4000]))
    if isinstance(data, dict):
        keys = set(data)
        d = data.get("d")
        if isinstance(d, dict):
            keys |= set(d)
        return frozenset(keys)
    if isinstance(data, list) and data and isinstance(data[0], dict):
        return frozenset({"__list__"})
    return frozenset()
