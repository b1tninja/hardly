# Using hardly from another project

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
[README](../README.md#cursor-mcp). Agents start with `hardly_modes`, then
`hardly_open`. Prompts: `analyze_har`, `discover_apis`, `capture_portal`.
Tools: [tools.md](tools.md).

**CLI (scripts, CI).** Every analysis tool is a subcommand and prints JSON:

```bash
hardly endpoints a.har --host api.site.example | jq '.endpoints[] | .path_template'
hardly credentials a.har --host site.example
hardly export-openapi a.har -o openapi.json
```

**Python.**

```python
from hardly.session import open_har, require_conn
from hardly.index import query as q
from hardly.core.credentials import map_credentials
from hardly.core.search_nav import find_search_entry

info = open_har("a.har")
conn = require_conn(info["session_id"])
q.list_endpoints(conn, host="api.site.example")
map_credentials(conn, host="site.example")          # names + shapes only
find_search_entry(conn, keywords=["your", "terms"])  # generic + your vocabulary
```

Core functions take a SQLite connection and return plain dicts, so they are
easy to call from tests and notebooks. Check `hardly capabilities` (or
`hardly_capabilities`) for the feature list when you depend on a newer tool.

## Recommended loop for an SDK project

1. Capture the flow (interactive when walled, headless otherwise) and keep the
   HAR **outside** your repo.
2. Run the [SDK workflow](sdk-workflow.md): endpoints → content → forms →
   credentials → stub/OpenAPI.
3. Write the client in your project. Replace the stub's placeholders with real
   inputs supplied at runtime; never commit captured values.
4. Save **small, hand-redacted snippets** of key responses (HTML fragments,
   JSON bodies) as unit-test fixtures; point the client's HTTP layer at them so
   tests run offline. `hardly soak-live --write-fixtures DIR` can write such
   snippets for hardly's own public test targets.
5. Keep your capture recipe (`hardly recipe-plan -o steps.json`) with the
   project so the capture can be refreshed.
6. After a site change, re-capture and `hardly diff old.har new.har` to see
   which endpoints, fields or auth behaviours moved.
7. Mark live smoke tests so they are opt-in; default CI stays offline.

## Testing hardly itself

```bash
pip install -e ".[dev]"
pytest                                  # offline; fixtures are synthetic
HARDLY_LIVE_CAPTURE=1 pytest            # + live Playwright tests
hardly soak-live --list                 # public technology demos
hardly soak-live                        # headless soak against them
HARDLY_SOAK_HARS="a.har=host:b.har" python scripts/soak.py   # archive soak on your own HARs
```

`HARDLY_SOAK_HARS` holds `path[=host_substring]` entries separated by the OS
path separator (`:` on POSIX, `;` on Windows); the optional host asserts which
host hardly picks as `preferred_host`. Soak output is checked for leaked
secrets. The checked-in `tests/fixtures/sample.har` is synthetic.

## Contributing a detector

1. Add logic under `hardly/core/` that keys on **technology signatures**, not
   a site or subject.
2. Surface it in an existing tool where possible (for example `forms` or
   `credentials`) rather than adding a new one.
3. Add a synthetic fixture and a test.
4. If you add or change an MCP tool, update `capabilities.TOOLS` and run
   `python scripts/gen_tool_docs.py` (a test fails if `docs/tools.md` is stale).
