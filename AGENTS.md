# hardly: contributor and agent guide

hardly is a generic, content-neutral HAR analysis CLI and FastMCP server: index a capture into
SQLite once, then query it with small, redacted, paginated tools. What is in and out of scope is
defined in [docs/scope.md](docs/scope.md); `tests/test_neutrality.py` enforces it (no site, domain
or organisation terms in `src`, `docs`, `skills`, `tests`, `scripts`). Read the scope doc first.

Human setup: [README.md](README.md). Docs index: [docs/README.md](docs/README.md).
Design overview: [docs/architecture.md](docs/architecture.md). What is public and frozen:
[docs/api-stability.md](docs/api-stability.md).

## Repo map

| Path | What lives there |
|------|------------------|
| `src/hardly/server.py` | FastMCP server: `hardly_*` tools, prompts, resources, instructions |
| `src/hardly/cli.py` | argparse CLI: `hardly <group> <command>` mirrors the tool names ([docs/cli.md](docs/cli.md)) |
| `src/hardly/core/` | Pure detectors and builders (one concern per module: `credentials`, `botwalls`, `grids`, `stub`, `report`, ...). Internal |
| `src/hardly/index/` | `ingest.py` (ijson stream to SQLite, `INDEX_VERSION`), `schema.py`, `query.py`. Internal (the saved index file is public) |
| `src/hardly/session.py` | Session implementation; `open_session`, `Session` and the errors are re-exported from `hardly` (public) |
| `src/hardly/capture*.py` | Playwright capture (in-process and durable worker), recipes, aria refs. Internal |
| `src/hardly/local_site.py` | Loopback synthetic site used by tests and soak |
| `src/hardly/capabilities.py`, `resources.py` | Capability report; docs/skill bundled as MCP resources |
| `docs/` | Human docs; `tools.md` and `cli.md` are generated |
| `skills/hardly/` | Agent Skill; `references/*.md` are generated copies of `docs/` |
| `scripts/` | `gen_tool_docs.py` (also writes `docs/cli.md`), `dump_api_surface.py`, `dump_cli_surface.py`, soak scripts, image build |
| `tests/` | pytest suite; `tests/fixtures/sample.har` is synthetic; `api_surface.json` and `cli_surface.json` are the frozen surface |

## Commands

```bash
python -m venv .venv && source .venv/bin/activate    # Windows: .venv\Scripts\activate
pip install -e ".[dev]"                              # add ".[capture]" + `playwright install chromium` for capture
pytest -q                                            # offline; live Playwright tests need HARDLY_LIVE_CAPTURE=1
ruff check .                                         # lint (config in pyproject.toml)
python scripts/gen_tool_docs.py                      # regenerate docs/tools.md, docs/cli.md, skills/hardly/references
python scripts/gen_tool_docs.py --check              # exit 1 if stale
python scripts/dump_api_surface.py                   # rewrite tests/api_surface.json (deliberate change only)
python scripts/dump_cli_surface.py                   # rewrite tests/cli_surface.json (deliberate change only)
```

In a git worktree the editable install may point at another checkout. Run
`PYTHONPATH=src python -m pytest -q` so the tests import your worktree's code.
`test_queue_depth_sees_concurrent_waiter` is occasionally flaky; rerun before investigating.

## Naming rules (v1, permanent)

Rationale and evidence: [docs/api-decisions.md](docs/api-decisions.md).

- **Effect markers.** `hardly_send_*` sends requests (takes `confirm`, returns a plan without it),
  `hardly_write_*` writes a file (takes `output_path`/`output_dir` + `overwrite`, default false),
  `hardly_browser_*` drives a browser. No marker means read-only.
- **Grammar.** `hardly_<object>_<view>`, at most three words; the last word names the output, never
  a container. Verbs come from the closed set in `docs/api-decisions.md`; a new verb or marker needs
  that document to change first.
- **Sections rule.** Merge into a `sections` list only when the tool name already names the common
  subject, all sections take the same selectors and none crosses the effect boundary. A different
  output kind or question is a separate tool.
- **Parameter vocabulary.** `session_id`, `entry_id`, `host`, `limit`/`offset`, `har_path`,
  `output_path`, `overwrite`, `confirm`, `exclude_noise`, `*_seconds` for durations; omit or `null`
  for unset (never `""`/`0`); native JSON lists and objects (no `*_json`).
- **CLI mirrors tools.** `hardly <first word> <rest with hyphens>`; flags are the parameter names
  with hyphens; live commands take `--confirm`.
- **Adding or changing a tool or command** requires: the code and docstring, `capabilities.TOOLS`,
  the CLI command, the `GROUPS` table in `scripts/gen_tool_docs.py`, regenerated snapshots
  (`dump_api_surface.py`, `dump_cli_surface.py`), regenerated docs (`gen_tool_docs.py`), tests and a
  CHANGELOG entry. Renames and removals of released names are breaking
  ([docs/api-stability.md](docs/api-stability.md)).

## Public and internal

Public: MCP tool names, parameters and documented result keys, error codes, CLI paths and flags,
`hardly.open_session` / `Session` / the error classes, the saved index format. Internal:
`hardly.core.*`, `hardly.index.*`, `hardly.capture*`, anything starting with an underscore. Do not
import internal modules from docs or examples as if they were API.

## Conventions

- **New detector** = a `core/<name>.py` module + a test + wiring in `server.py` (a tool or a section
  of one, with a docstring), `cli.py`, `capabilities.py` and the `GROUPS` table in
  `scripts/gen_tool_docs.py`, then regenerate docs. Prefer extending an existing tool or a
  `hardly_session_report` / `hardly_auth_report` section over adding a tool.
- **Names and shapes, never secret values.** Output may include header/cookie/field names, value
  shapes (jwt, hex, base64) and lengths; never values. Redact URLs with `core/redact.py`.
- **Live tools are confirm-gated.** Anything that sends traffic needs `confirm=true` (CLI
  `--confirm`) and returns only a plan without it. Mark them `LIVE` in the docstring.
- **Evidence by default, prose behind `explain=true`.** Report facts read from the HAR or a probe.
- **Tool docstrings are prompts**: first sentence is the point (<=160 chars), say when to use it and
  which sibling to prefer, include an `Example:` call. `tests/test_agent_onboarding.py` lints this;
  `tests/test_docs_tool_names.py` checks every `hardly_*` name, call and CLI example in the docs.
- **Index changes**: if ingest stores something new or changes meaning, bump `INDEX_VERSION` in
  `index/ingest.py` so stale index files rebuild.
- **Tests** use synthetic fixtures with neutral names (`example.com`) and the loopback
  `hardly.local_site`. No private HARs, no network, no real credentials.
- Docs: each file in `docs/` starts with a `> Purpose:` line. Relative links are checked by
  `tests/test_docs_links.py`.

## Safety rules

- Do not build or document evasion of captchas, bot walls, rate limits or access controls. Gates are
  classified and reported (`docs/gate-policy.md`); the answer is to stop, ask the person, or re-run
  from another environment.
- Only probe, crawl or capture targets the user is authorised to access. Crawl is robots-aware and polite.
- Capture and HAR files contain live secrets: never print bodies wholesale, never commit them.

## Do not

- Add site-, organisation- or region-specific logic, vocabulary, URLs or recipes (callers pass
  keywords as arguments; downstream projects keep their own adapters).
- Commit HAR files (`*.har` is gitignored; only `tests/fixtures/sample.har` is tracked).
- Write scratch files, captures or reports in the repo root; use `$TMPDIR`.
- Hand-edit `docs/tools.md`, `docs/cli.md`, `skills/hardly/references/*` or the two snapshots (edit
  `docs/*`, docstrings or the parser, regenerate).
- Rename or remove a public name without the process in `docs/api-stability.md`.
- Load a raw HAR into a model's context; use `hardly_session_open`, `hardly_session_site_brief`,
  `hardly_endpoint_list`.

## Agent workflow in brief

`hardly_guide_task_plan(goal, har_path, url)` returns an ordered plan. Pick a mode
(`hardly_guide_mode`): HAR path means **archive**; scriptable URL means **headless**
(`hardly_browser_capture_discover(url, analyze=true, confirm=true)`); a person, wall or MFA means
**interactive** (ask the person, do not claim to see their screen). After any capture stop, continue
in archive mode on the new `session_id`. If tools look missing, `hardly_server_status` and restart
the MCP server; after a restart sessions are gone: repeat `hardly_session_open`. Full guidance:
`hardly://cheatsheet`, `docs/cheatsheet.md`, `skills/hardly/SKILL.md` (`hardly skill install`).

## Subagent and worktree work

Each subagent works in its own worktree on its own branch and owns a disjoint set of files. Before
handing back: full suite green (with `PYTHONPATH=src`), `ruff check .`, `gen_tool_docs.py` run if
tools, commands or docstrings changed, neutrality test green, one commit per coherent change. The
integrator merges branches one at a time, reruns the suite after each merge, and resolves
`docs/tools.md`, `docs/cli.md`, the two snapshots and `skills/hardly/references/` conflicts by
regenerating them, never by hand. Worktrees live under `.claude/worktrees/` (gitignored).
