# Using hardly from another project

> Purpose: How to use hardly from another project via MCP, CLI or Python, plus fixtures and soak testing.

hardly is meant to sit *under* SDKs and adapters: it explores a site and
documents its wire behaviour; your project turns that into a library. Keep the
boundary clean:

| hardly (generic) | Your project (specific) |
|------------------|-------------------------|
| Capture, index, query, redact | Which sites you target and why |
| Technology detectors, content kinds | Record types, parsers, vocabularies |
| Client sketches and specs | The maintained client and its tests |
| Synthetic fixtures | Your own redacted fixtures and capture recipes |

Dependencies point one way: your project may use hardly while developing; hardly
never imports or names downstream projects.

## Three ways in

**MCP (agents).** Run `hardly serve` (stdio). Configure in your editor; see the
[README](../README.md#mcp-setup-cursor-and-others). Agents start with `hardly_guide_task_plan`, then
`hardly_session_open`. Prompts: `analyze_har`, `discover_apis`, `capture_portal`.
Tools: [tools.md](tools.md).

**CLI (scripts, CI).** Every analysis tool is a command with the same name (`hardly_session_open`
is `hardly session open`) and prints JSON; see [cli.md](cli.md):

```bash
hardly endpoint list a.har --host api.site.example | jq '.endpoints[] | .path_template'
hardly auth report a.har --host site.example --sections credentials
hardly write export a.har --format openapi -o openapi.json
```

**Python.** The public API is `hardly.open_session` and the error classes (see
[api-stability.md](api-stability.md)). The session gives you a read-only SQLite connection to the
index, so any question the tools do not answer is a SELECT:

```python
from hardly import open_session

with open_session("a.har") as s:
    rows = s.conn.execute("SELECT host, COUNT(*) FROM entries GROUP BY host").fetchall()
```

For analysis results, call the CLI or MCP tool and parse the JSON; that is the stable contract.
`hardly.core.*` and `hardly.index.*` (detectors, `query` helpers) are internal: you may import them,
but pin the hardly version because they can change in any release.

## Recommended loop for an SDK project

1. Capture the flow (interactive when walled, headless otherwise) and keep the
   HAR **outside** your repo.
2. Run the [SDK workflow](sdk-workflow.md): endpoints → content → forms →
   credentials → client/OpenAPI.
3. Write the client in your project. Replace the stub's placeholders with real
   inputs supplied at runtime; never commit captured values.
4. Save **small, hand-redacted snippets** of key responses (HTML fragments,
   JSON bodies) as unit-test fixtures; point the client's HTTP layer at them so
   tests run offline. `hardly soak live --write-fixtures DIR` can write such
   snippets for hardly's own public test targets.
5. Keep your capture steps (`hardly write export HAR --format plan_steps -o steps.json`) with the
   project so the capture can be refreshed.
6. After a site change, re-capture and `hardly session compare old.har new.har` to see
   which endpoints, fields or auth behaviours moved.
7. Mark live smoke tests so they are opt-in; default CI stays offline.

## Many targets: the catalog

To track many targets with several discovered URLs each, keep them in a
`hardly.core.catalog` file and subclass `TargetAdapter` for your own discovery;
`CatalogRunner` verifies politely and stops at gates. hardly stays
content-neutral - your project defines tags, group keys and roles. See
[catalog.md](catalog.md).

## Testing hardly itself

```bash
pip install -e ".[dev]"
pytest                                  # offline; fixtures are synthetic
HARDLY_LIVE_CAPTURE=1 pytest            # + live Playwright tests
hardly soak live --list                 # public technology demos
hardly soak live                        # headless soak against them
python scripts/soak.py "~/captures/*.har"       # archive soak on your own HARs (globs)
```

`scripts/soak.py` takes globs (`~` and `**` work) as arguments, or
`HARDLY_SOAK_GLOB` (patterns separated by the OS path separator). With neither
it runs the synthetic fixtures. Soak output is checked for leaked secrets.
Private captures are inputs to this script, not fixtures: keep them outside
the repo.
The checked-in `tests/fixtures/sample.har` is synthetic.

## Contributing a detector

1. Add logic under `hardly/core/` that keys on **technology signatures**, not
   a site or subject.
2. Surface it in an existing tool where possible (a section of `hardly_auth_report`, a finding of
   `hardly_session_report`) rather than adding a new one.
3. Add a synthetic fixture and a test.
4. If you add or change an MCP tool, update `capabilities.TOOLS`, the snapshots and run
   `python scripts/gen_tool_docs.py` (tests fail if `docs/tools.md` or `tests/api_surface.json` is stale;
   see [api-stability.md](api-stability.md)).

## Python API for downstream projects

**Give an output path to save; otherwise nothing is written.**

```python
from hardly import open_session

# In memory: nothing is written to disk.
with open_session("capture.har") as s:
    n = s.conn.execute("SELECT COUNT(*) FROM entries").fetchone()[0]

# Also save the index (atomic; refused if the file exists unless overwrite=True) ...
with open_session("capture.har", output_path="work/capture.idx") as s:
    print(s.session_id, s.info["entries"], s.saved_to)

# ... and reopen it later without re-ingesting.
with open_session("work/capture.idx") as s:
    ...
```

`open_session(har_or_index, output_path=None, overwrite=False)` is idempotent (same input path = same
session id and live session, no re-ingest), reference counted, and `s.close()` is safe to call twice;
`contextlib.ExitStack` works. `s.conn` is read-only. Errors carry a stable `code`: `unknown_session`,
`output_exists`, `output_error`, `index_outdated`, `har_not_found` (all subclasses of `SessionError`,
exported from `hardly`).
