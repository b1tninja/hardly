# hardly: contributor and agent guide

hardly is a generic, content-neutral HAR analysis CLI and FastMCP server: index a capture into
SQLite once, then query it with small, redacted, paginated tools. What is in and out of scope is
defined in [docs/scope.md](docs/scope.md); `tests/test_neutrality.py` enforces it (no site, domain
or organisation terms in `src`, `docs`, `skills`, `tests`, `scripts`). Read the scope doc first.

Human setup: [README.md](README.md). Docs index: [docs/README.md](docs/README.md).
Design overview: [docs/architecture.md](docs/architecture.md).

## Repo map

| Path | What lives there |
|------|------------------|
| `src/hardly/server.py` | FastMCP server: `hardly_*` tools, prompts, resources, instructions |
| `src/hardly/cli.py` | argparse CLI (`hardly <command>`), mirrors most tools |
| `src/hardly/core/` | Pure detectors and builders (one concern per module: `credentials`, `botwalls`, `grids`, `stub`, `report`, ...) |
| `src/hardly/index/` | `ingest.py` (ijson stream to SQLite, `INDEX_VERSION`), `schema.py`, `query.py` |
| `src/hardly/session.py` | Public session API (`open_session`), dict layer for MCP/CLI |
| `src/hardly/capture*.py` | Playwright capture (in-process and durable worker), recipes, aria refs |
| `src/hardly/local_site.py` | Loopback synthetic site used by tests and soak |
| `src/hardly/capabilities.py`, `resources.py` | Capability report; docs/skill bundled as MCP resources |
| `docs/` | Human docs; `tools.md` is generated |
| `skills/hardly/` | Agent Skill; `references/*.md` are generated copies of `docs/` |
| `scripts/` | `gen_tool_docs.py`, soak scripts, image build |
| `tests/` | pytest suite; `tests/fixtures/sample.har` is synthetic |

## Commands

```bash
python -m venv .venv && source .venv/bin/activate    # Windows: .venv\Scripts\activate
pip install -e ".[dev]"                              # add ".[capture]" + `playwright install chromium` for capture
pytest -q                                            # offline; live Playwright tests need HARDLY_LIVE_CAPTURE=1
ruff check .                                         # lint (config in pyproject.toml)
python scripts/gen_tool_docs.py                      # regenerate docs/tools.md + skills/hardly/references
python scripts/gen_tool_docs.py --check              # exit 1 if stale
```

In a git worktree the editable install may point at another checkout. Run
`PYTHONPATH=src python -m pytest -q` so the tests import your worktree's code.
`test_queue_depth_sees_concurrent_waiter` is occasionally flaky; rerun before investigating.

## Conventions

- **New detector** = a `core/<name>.py` module + a test + wiring in `server.py` (tool with a
  docstring), `cli.py`, `capabilities.py` and the `GROUPS` table in `scripts/gen_tool_docs.py`,
  then regenerate docs. Prefer extending an existing tool or a `hardly_report` section over adding
  a tool.
- **Names and shapes, never secret values.** Output may include header/cookie/field names, value
  shapes (jwt, hex, base64) and lengths; never values. Redact URLs with `core/redact.py`.
- **Live tools are confirm-gated.** Anything that sends traffic needs `confirm=true` (CLI `--yes`)
  and returns only a plan without it. Mark them `LIVE` in the docstring.
- **Evidence by default, prose behind `explain=true`.** Report facts read from the HAR or a probe.
- **Tool docstrings are prompts**: first sentence is the point (<=160 chars), say when to use it and
  which sibling to prefer, include an `Example:` call. `tests/test_agent_onboarding.py` lints this.
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
- Hand-edit `docs/tools.md` or `skills/hardly/references/*` (edit `docs/*` or docstrings, regenerate).
- Load a raw HAR into a model's context; use `hardly_open`, `hardly_brief`, `hardly_endpoints`.

## Agent workflow in brief

`hardly_start(goal, har_path, url)` returns an ordered plan. Pick a mode (`hardly_modes`): HAR path
means **archive**; scriptable URL means **headless** (`hardly_discover`); a person, wall or MFA means
**interactive** (ask the person, do not claim to see their screen). After any capture stop, continue
in archive mode on the new `session_id`. If tools look missing, `hardly_capabilities` and restart the
MCP server; after a restart sessions are gone: repeat `hardly_open`. Full guidance: `hardly://cheatsheet`,
`docs/cheatsheet.md`, `skills/hardly/SKILL.md` (`hardly skill install`).

## Subagent and worktree work

Each subagent works in its own worktree on its own branch and owns a disjoint set of files. Before
handing back: full suite green (with `PYTHONPATH=src`), `ruff check .`, `gen_tool_docs.py` run if
tools or docstrings changed, neutrality test green, one commit per coherent change. The integrator
merges branches one at a time, reruns the suite after each merge, and resolves `docs/tools.md` and
`skills/hardly/references/` conflicts by regenerating them, never by hand. Worktrees live under
`.claude/worktrees/` (gitignored).
