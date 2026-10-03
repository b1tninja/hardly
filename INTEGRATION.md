# Integration notes (tables, double-encoded JSON, export links, JS body keys)

Files NOT edited here (apply by hand): `server.py`, `cli.py`, `capabilities.py`,
`docs/technologies.md`, `docs/tools.md`, README/AGENTS.

## 1. MCP tool (`src/hardly/server.py`)

```python
@mcp.tool
def hardly_tables(
    session_id: str,
    entry_id: int | None = None,
    host: str | None = None,
) -> str:
    """List HTML data tables: headers, row/column counts, masked first row.

    For each table that looks like a data grid (th / thead / bold first row,
    >=2 columns, >=1 data row; handles nested tables, colspan and ASP.NET
    GridView pagers) returns caption, headers, column_count, row_count,
    first_row_masked (values replaced by shapes: 9 digit, a/A letter),
    column_kinds (integer|date|money|text|empty over ALL rows),
    has_pager_hint and entry_id. Two-column definition-style tables come back
    as kind=label_value with their labels only. Cell values are never returned.
    """
    try:
        conn = sess.require_conn(session_id)
    except KeyError as exc:
        return _err(exc)
    from hardly.core.tables import scan_session

    return _ok(scan_session(conn, host=host, entry_id=entry_id))
```

## 2. CLI (`src/hardly/cli.py`)

```python
def cmd_tables(args: argparse.Namespace) -> int:
    from hardly.core.tables import scan_session

    result = sess.open_har(args.har)
    if "error" in result:
        _print(result)
        return 1
    conn = sess.require_conn(result["session_id"])
    _print(scan_session(conn, host=args.host, entry_id=args.entry_id))
    return 0
```

Parser (next to `grids_p`):

```python
    tables_p = sub.add_parser(
        "tables",
        help="HTML data tables: headers, counts, masked first row (no values)",
    )
    tables_p.add_argument("har")
    tables_p.add_argument("--host")
    tables_p.add_argument("--entry-id", type=int, dest="entry_id")
    tables_p.set_defaults(func=cmd_tables)
```

## 3. Capabilities (`src/hardly/capabilities.py`)

Add `"tables"` to the feature list (after `"grids"`) and `"hardly_tables"` to the
tool list (after `"hardly_grids"`). `tests/test_capabilities.py` /
`test_mcp_sync.py` may require the tool to appear in docs/tools.md and the
tool count to match; regenerate with `scripts/gen_tool_docs.py`.
Optionally mention in the `hardly_grids` docstring that results now include
`export_links` (+ `export_note`).

## 4. docs/technologies.md paragraphs

Under the HTML section (or beside the grid section):

> ### Data tables
> `hardly_tables` finds HTML data tables by structure: a header row from `<th>`,
> `<thead>` or an all-bold first row, at least two columns and one data row.
> Nested layout tables, `colspan` and ASP.NET GridView pager rows (a row of page
> links, often a nested table) are handled; the pager sets `has_pager_hint`.
> Output is header names, column/row counts, a first row **masked to shapes**
> (digits `9`, letters `a`/`A`, punctuation kept, 24 chars max) and a per-column
> kind guessed from all rows (integer, date, money, text, empty). Two-column
> label/value (definition-style) tables are reported as `kind: label_value`
> with their labels. Cell contents are never returned.

Under JSON / content classification:

> ### Double-encoded JSON
> Some servers return a JSON *string* whose content is JSON
> (`"{\"Table\":{...}}"`). At ingest the string is peeled (up to 3 layers), the
> stored preview becomes the unwrapped JSON, and a `body_signals` row
> `kind='encoding' name='double-encoded-json'` is recorded. `hardly_content` /
> `hardly_entry` report `kind: json` with hint `double_encoded_json`, and
> `hardly_schema` infers on the unwrapped value. `INDEX_VERSION` is 4.

Under grids:

> ### Built-in exports
> `hardly_grids` lists `export_links`: links, forms and observed requests whose
> path contains export/download/csv/xlsx/report words, whose query has
> `format|output|type|fmt` = `csv|xlsx|xls|json|xml|pdf|tsv`, or whose path ends
> in `.csv/.xlsx/.xls/.tsv`. Each has `path` (query values dropped), `formats`,
> `method`, `entry_id` and `source` (`link` or `request`). An export returns the
> whole result set in one response, so prefer it to paging the grid.

Under JS route mining (`hardly_routes`):

> Each route also lists `method` (when visible) and up to 12 `body_keys`: the
> object-literal key names found within ~400 characters after the call
> (`$http.post`, `axios.*`, `fetch(url, {body: JSON.stringify({...})})`,
> `$.ajax({url, data})`, `xhr.open` + `.send(JSON.stringify({...}))`). Names
> only, never values; option keys (method, headers, data, success…) and
> callback bodies are skipped.
