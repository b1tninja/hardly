# hardly

HAR analysis MCP server — index, query, document, and probe APIs **without** loading giant HAR files into the model context.

You *hardly* need the whole file.

## Why

Browser HAR captures are often tens of megabytes. Agents that `Read` them burn tokens and still miss structure. **hardly** streams a HAR into SQLite once, then exposes small, redacted, paginated tools over MCP (and a CLI for the same helpers).

## Install (local venv)

```bash
cd D:\code\hardly
python -m venv .venv
.venv\Scripts\activate
pip install -e ".[dev]"
```

## Docker (recommended for Cursor)

Build and register:

```powershell
powershell -File scripts\deploy-docker.ps1
```

### Cursor MCP config (stdio via Docker)

Add to `~/.cursor/mcp.json` (or Cursor *Settings → MCP*):

```json
{
  "mcpServers": {
    "hardly": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "-v", "D:/code:/workspace",
        "-e", "HARDLY_CACHE_DIR=/workspace/.hardly-cache",
        "-e", "HARDLY_WORKSPACE=/workspace",
        "hardly-mcp:latest"
      ]
    }
  }
}
```

The image is **self-describing** (`io.docker.server.metadata` label) so it can also be added to a Docker MCP Toolkit profile:

```bash
docker mcp profile server add ai_coding --server docker://hardly-mcp:latest
```

That surfaces hardly through the existing `MCP_DOCKER` gateway (`docker mcp gateway run --profile ai_coding`). The direct `hardly` entry in `mcp.json` is usually simpler (tools appear as `hardly_*` without going through the gateway).

`D:/code` is mounted at `/workspace`. Host paths like `D:\code\payhoa\app.payhoa.com.har` are auto-mapped; you can also pass `/workspace/payhoa/app.payhoa.com.har`.

Exports (e.g. `API.md`) written under `D:\code\...` land on the host via the same mount.

### Local venv (no Docker)

```json
{
  "mcpServers": {
    "hardly": {
      "command": "D:\\code\\hardly\\.venv\\Scripts\\python.exe",
      "args": ["-m", "hardly"]
    }
  }
}
```

```bash
python -m hardly
# or
hardly serve
```

## Agent workflow

1. `hardly_open("D:/code/payhoa/app.payhoa.com.har")` → `session_id` + counts  
2. `hardly_endpoints(session_id, host="core.payhoa.com", exclude_noise=true)`  
3. `hardly_auth(session_id, host="core.payhoa.com")` / `hardly_flow(...)`  
4. `hardly_entry(session_id, entry_id)` / `hardly_schema(...)` for details  
5. `hardly_export_md(session_id, output_path="...", host="core.payhoa.com")`

Prompts `document_api` and `find_auth_flow` are registered for guided workflows.

## MCP tools

| Tool | Purpose |
|------|---------|
| `hardly_open` | Index HAR (cached by path+size+mtime) |
| `hardly_list_sessions` / `hardly_close` | Session management |
| `hardly_summary` / `hardly_hosts` / `hardly_endpoints` | Cheap discovery |
| `hardly_search` / `hardly_entry` / `hardly_compare_entries` | Drill-down |
| `hardly_auth` / `hardly_flow` / `hardly_schema` | Analysis |
| `hardly_sql` | Read-only `SELECT` on the index |
| `hardly_export_md` / `hardly_export_openapi` | Write docs to disk |
| `hardly_curl` | curl with redacted secrets / env placeholders |
| `hardly_probe` | Live replay (`confirm=true`; secrets only via overrides) |

**Token rules:** bodies truncated, secrets redacted (`password`, tokens, `Authorization`, cookies, JWTs), lists paginated. Never returns the full HAR.

## CLI

```bash
hardly summary path/to/capture.har
hardly endpoints path/to/capture.har --host api.example.com
hardly auth path/to/capture.har --host api.example.com
hardly export-md path/to/capture.har -o API.md --host api.example.com
hardly export-openapi path/to/capture.har -o openapi.json --host api.example.com
hardly serve
```

Cache lives in `~/.cache/hardly/`.

## Library

```python
from hardly.session import open_har, require_conn
from hardly.index import query as q

info = open_har("capture.har")
conn = require_conn(info["session_id"])
print(q.list_endpoints(conn, host="api.example.com"))
```

## Features

- Stream ingest (`ijson`) for large HARs  
- Noise filter (static assets, trackers, `OPTIONS`, non-API MIME)  
- Path templating (`/users/42` → `/users/{id}`)  
- Auth heuristics (login/2fa paths, token response keys, custom headers)  
- Schema inference from JSON samples  
- OpenAPI + Markdown export  
- Gated live probe via `httpx`

## Tests

```bash
pytest
```

## Security

HAR files often contain live passwords and session tokens. hardly redacts by default, but treat captures as secrets: do not commit them, and rotate credentials if a HAR was shared.
