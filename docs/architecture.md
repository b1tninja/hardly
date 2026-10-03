# Architecture

> Purpose: How data flows through hardly, from a HAR or live capture to redacted query tools and generated artefacts, and the design rules that keep it safe.

## Data flow

```mermaid
flowchart LR
    subgraph Sources
        HAR[HAR file]
        CAP[Playwright capture<br/>headless / interactive]
        CRAWL[curl-first crawl]
    end
    CAP -->|writes| HAR
    HAR -->|ijson stream| ING[index/ingest.py<br/>redact + classify + body_signals]
    ING --> DB[(SQLite index<br/>per session)]
    DB --> Q[index/query.py]
    Q --> CORE[core/* detectors<br/>redacted, paginated]
    CORE --> MCP[server.py<br/>MCP tools]
    CORE --> CLI[cli.py]
    CORE --> OUT[reports, stubs,<br/>OpenAPI, Postman, briefs]
    CRAWL -.confirm-gated.-> LIVE[(network)]
    PROBE[probe / replay / verify] -.confirm-gated.-> LIVE
```

1. **Ingest** (`index/ingest.py`): ijson streams entries so large HARs never load whole. Each entry is
   filtered for noise, its URL templated (`/users/42` to `/users/{id}`), secret query values redacted,
   text bodies decoded, and per-body signals (`body_signals`: content kind, value shapes, framework
   hints, double-encoded JSON, ...) computed once.
2. **Index**: one SQLite database per HAR, held according to the storage mode (below).
   `session.py` maps `session_id` to the connection; disk sessions reattach from the cache after an
   MCP restart.
3. **Query**: `index/query.py` and `core/*` modules read the index and return small dictionaries.
   Detectors return evidence (names, shapes, counts, entry ids); prose advice appears only with
   `explain=true`. Output is paginated and bodies are truncated.
4. **Outputs**: `hardly_report` (one-pass evidence index), client stubs, OpenAPI, Postman, Markdown
   briefs and recipe plans are built from the same index.

## Capture paths

- **In-process headless** (`capture.py`, `capture_headless`): one-shot discovery and recipes.
- **Durable worker** (`capture_worker.py`): a subprocess that keeps a browser alive across calls
  (start / aria / click / stop), with disk sidecars so stop works across processes. Opt in for
  one-shots with `HARDLY_CAPTURE_SUBPROCESS=1`.
- **Interactive**: headed browser, a person drives; the agent only starts and stops.
- Capture slots bound concurrency (`HARDLY_CAPTURE_SLOTS`, `HARDLY_CAPTURE_SLOT_TIMEOUT`), budgets
  bound recipe time, and failures are classified (`error_class`). After stop, the HAR is opened as a
  normal archive session.

## Live-tool gating

Anything that sends traffic (`probe`, `crawl`, `redirect_diag`, `arcgis_explore`, `replay_check`,
`replay_flow`, `catalog_verify`) requires `confirm=true` (CLI `--yes`). Without it the tool returns a
plan or an error and sends nothing. Live tools stop at gates (bot walls, challenges, rate limits,
environment blocks) per [gate-policy.md](gate-policy.md) and never evade them; crawl honours
robots.txt and per-host delays. Secrets for probes come only from explicit overrides.

## Redaction model

- Redaction happens at **ingest** (secret query values) and again at **output** (`core/redact.py`),
  so nothing downstream can echo a raw credential.
- Credential tools report **names and shapes** (jwt, hex, base64, lengths), cookie flags and
  roles, never values.
- Generated stubs use placeholders and carry server-issued tokens forward at runtime from earlier
  responses rather than embedding literals.
- The raw HAR is never returned by any tool.

## Storage modes

`HARDLY_INDEX` (or `hardly_open(storage=...)` / `hardly open --storage`) selects where the index lives:

| Mode | Behaviour |
|------|-----------|
| `disk` (default) | Cached in `HARDLY_CACHE_DIR` (default `~/.cache/hardly`) as `<session_id>.db` plus `<session_id>.json`; survives MCP restarts (`hardly_reopen`). |
| `memory` | Ingested into `:memory:`; no cache file or metadata is written, so no derived data (redacted previews, headers, shapes) is left on disk. The session is gone after a restart; reopen the HAR. Use for sensitive captures. |
| `auto` | `memory` when the HAR is at most `HARDLY_INDEX_MEMORY_MAX_MB` (default 25), else `disk`. Opt-in because it drops restart reattach for small HARs. |

Results report `storage: memory|disk` (`hardly_open`, `hardly_list_sessions`, `hardly_summary`).
`hardly_persist(session_id, path=None, overwrite=False)` (CLI `hardly persist HAR`) saves a session as
a compact SQLite file with `VACUUM INTO`; it never writes in place and refuses to replace an
existing file unless `overwrite=true`. Without `path` it writes into the cache dir so the session
reattaches like a disk one. Memory is not much faster than disk (ingest is parse-bound), so choose
it for privacy, not speed.

**Atomic cache.** A disk ingest builds in a temp file, writes a compact, WAL-free copy with
`VACUUM INTO` to `.hardly-db-*.tmp` in the cache dir and `os.replace`s it onto `<sid>.db`; the
metadata JSON is written last the same way. A crash leaves the old cache or none, never a partial
one. Stray `.hardly-*.tmp` files older than 15 minutes are removed on open. Caches built by older
versions in WAL mode are rebuilt.

**Read-only open.** Cached indexes open with `file:<path>?mode=ro` (no write locks, no `-wal`/`-shm`
sidecars, works from a read-only cache dir); memory sessions are sealed with `PRAGMA query_only`.
Query code never writes; temp tables stay allowed and use `temp_store=MEMORY`. A memory database is
private to its single connection, which hardly keeps (`check_same_thread=False`); never open a second
connection to one.

## INDEX_VERSION rule

`INDEX_VERSION` (in `index/ingest.py`) is stored in each session's metadata. On open, a cached index
with a different version is rebuilt from the HAR. Bump it whenever ingest changes what it stores or
what a stored value means (new `body_signals`, changed redaction, changed templating). Pure query-side
changes do not need a bump.

## Extension points

A new detector is a `core/` module plus a test, wired into `server.py`, `cli.py`, `capabilities.py`
and `scripts/gen_tool_docs.py` (see [AGENTS.md](../AGENTS.md)). Downstream vocabularies and target
collections plug in through arguments and the neutral `TargetAdapter` / catalog ([catalog.md](catalog.md)),
never through site-specific code in hardly. See [scope.md](scope.md).
