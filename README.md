# hardly

<!-- mcp-name: io.github.b1tninja/hardly -->

A generic, content-neutral CLI and MCP server for **reading and capturing HAR files** and turning
them into what a client SDK needs: endpoints, forms and labels, data and media kinds, and how
credentials and authentication work.

## Why

Browser HAR captures are often tens of megabytes. Agents that read them burn tokens and still miss
structure. hardly streams a HAR into SQLite once, then exposes small, redacted, paginated tools over
MCP (and a matching CLI). Bodies are truncated, secrets are redacted, lists are paginated: you
*hardly* need the whole file.

hardly knows technologies (HTML forms, ASP.NET WebForms, GraphQL, OAuth/OIDC, cookies/CSRF, bot
walls, ArcGIS REST...) and resource kinds (JSON, CSV, HTML tables, PDF, images...), not any
particular site. Downstream SDKs keep their own recipes and vocabularies. See
[docs/scope.md](docs/scope.md).

## Install

```bash
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pip install -e ".[capture]" && playwright install chromium   # optional: record HARs
```

Python 3.10+. **Give an output path to save; otherwise nothing is written.** Everything lives in
memory unless you pass `output_path` (`hardly session open HAR -o index.db`). Python:
`with open_session(har) as s: ...` ([integrating.md](docs/integrating.md)).

## 60-second quick start

```bash
hardly guide mode                             # which of the three modes fits
hardly session overview path/to/capture.har   # counts per server, method and status
hardly session site-brief path/to/capture.har # one-screen digest of a server-rendered site
hardly endpoint list path/to/capture.har --host api.example.com
hardly session report path/to/capture.har     # one-pass findings with severity
hardly write export path/to/capture.har --format openapi -o api.yaml
hardly write export path/to/capture.har --format client_python --host api.example.com -o client.py
```

For agents, start with `hardly_guide_task_plan(goal, har_path, url)` (CLI:
`hardly guide task-plan --goal ...`): it returns an ordered plan with example calls and the current
environment state.

## Names tell the effect

The CLI and the MCP server share one vocabulary: the command is the tool name without `hardly_`
(`hardly_session_open` is `hardly session open HAR`, `hardly_send_entry` is `hardly send entry HAR 12 --confirm`).

| First word | Meaning |
|------------|---------|
| `send` | sends requests to a real server; needs `confirm=true` (CLI `--confirm`), otherwise returns only a plan |
| `write` | writes a file; refuses to replace one unless `overwrite=true` (`--overwrite`) |
| `browser` | drives or reads a real browser |
| anything else | only reads loaded data |

Merged tools take a `sections` list, for example `hardly_auth_report(sections=['credentials',
'cookies'])`. Reference: [docs/tools.md](docs/tools.md) (71 tools), [docs/cli.md](docs/cli.md)
(commands); stability promise: [docs/api-stability.md](docs/api-stability.md).

## Three modes

| Mode | When | Entry |
|------|------|-------|
| **archive** | A HAR file already exists | `hardly_session_open(har_path)` then `hardly_session_site_brief` / `hardly_endpoint_list` |
| **headless** | Only a URL; an agent can drive the page | `hardly_browser_capture_discover(url, analyze=true, confirm=true)` (CLI `hardly browser capture-discover URL --analyze --confirm`) |
| **interactive** | Bot wall, captcha, MFA, complex UI | `hardly_browser_start(headed=true)`, **ask the person**, then `hardly_browser_stop` |

After any capture, continue in archive mode on the returned `session_id`. hardly never evades
captchas or bot walls: it identifies them and tells you to stop, ask a person, or re-run elsewhere
([docs/gate-policy.md](docs/gate-policy.md)). Details: [docs/capture.md](docs/capture.md).

## Install and run without cloning

```bash
uvx hardly serve                              # MCP server over stdio (archive mode)
uvx --from 'hardly[capture]' hardly browser --help   # with the Playwright capture extra
pipx install 'hardly[capture]'                # or install the CLI permanently
hardly skill install                          # copy the Agent Skill into ~/.claude/skills/hardly
```

MCP client config for the published package:

```json
{ "mcpServers": { "hardly": { "command": "uvx", "args": ["hardly", "serve"] } } }
```

Browser capture needs a local install (`[capture]` extra, then `python -m playwright install chromium`;
headed capture needs a display). The container image `ghcr.io/b1tninja/hardly` (multi-arch, built on each
release) is for archive/headless analysis only; mount your working directory at `/workspace`.
Release and verification details: [docs/releasing.md](docs/releasing.md).

## MCP setup (Cursor and others)

Local venv (recommended; headed capture needs a display):

```json
{
  "mcpServers": {
    "hardly": {
      "command": "/path/to/hardly/.venv/bin/python",
      "args": ["-m", "hardly"]
    }
  }
}
```

On Windows use `...\\.venv\\Scripts\\python.exe`. `hardly serve` starts the same server.

Docker (offline analysis only; mount your working directory):

```bash
python scripts/build_image.py       # builds hardly-mcp:latest (Windows: scripts\deploy-docker.ps1)
```

```json
{
  "mcpServers": {
    "hardly": {
      "command": "docker",
      "args": ["run", "--rm", "-i",
               "-v", "/home/me/work:/workspace",
               "-e", "HARDLY_WORKSPACE=/workspace",
               "hardly-mcp:latest"]
    }
  }
}
```

Host paths under the mount map to `/workspace/...`. To skip building locally, use the published
image `ghcr.io/b1tninja/hardly:latest` in place of `hardly-mcp:latest`.

## Agent onboarding

- `hardly_guide_task_plan`, `hardly_guide_mode`, `hardly_server_status` (stale MCP? restart the server),
  `hardly_guide_help(topic)`.
- MCP prompts: `analyze_har`, `discover_apis`, `capture_portal`, `document_api`, `find_auth_flow`,
  `reverse_engineer_api`, `build_client_sdk`, `diagnose_blocked_capture`, `verify_client`.
- MCP resources: `hardly://cheatsheet` and `hardly://docs/<name>` for the bundled docs.
- Agent Skill: `hardly skill install [--dest DIR]` (default `~/.claude/skills/hardly`), or
  `hardly skill print`. Source: [skills/hardly](skills/hardly/SKILL.md).

## Documentation

| Doc | Contents |
|-----|----------|
| [docs/README.md](docs/README.md) | Index of all docs |
| [docs/scope.md](docs/scope.md) | What is in and out of scope; change checklist |
| [docs/cheatsheet.md](docs/cheatsheet.md) | One-page quick reference |
| [docs/concepts.md](docs/concepts.md) | Sessions, index, redaction, modes |
| [docs/sdk-workflow.md](docs/sdk-workflow.md) | Capture to client SDK, step by step |
| [docs/reporting.md](docs/reporting.md) | `hardly_session_report` findings |
| [docs/catalog.md](docs/catalog.md) | Target catalog, `TargetAdapter`, batch verify |
| [docs/capture.md](docs/capture.md) | Headless and interactive capture, recipes, env vars |
| [docs/technologies.md](docs/technologies.md) | What is detected, per technology |
| [docs/architecture.md](docs/architecture.md) | Data flow and design rules |
| [docs/troubleshooting.md](docs/troubleshooting.md) | Common first-use problems |
| [docs/tools.md](docs/tools.md) | Generated reference for every MCP tool |
| [docs/cli.md](docs/cli.md) | CLI grammar and every command (generated) |
| [docs/api-stability.md](docs/api-stability.md) | What is public and the v1 compatibility policy |
| [docs/api-decisions.md](docs/api-decisions.md) | How the v1 names were chosen; old to new names |

## Library use

```python
from hardly import open_session

with open_session("capture.har") as s:      # in memory; pass output_path= to save the index
    print(s.conn.execute("select count(*) from entries").fetchone()[0])
```

## Development and tests

```bash
pytest -q                 # offline; HARDLY_LIVE_CAPTURE=1 enables live Playwright tests
ruff check .
```

Live soak against public demo sites (no private HARs): `hardly soak live --list`, then
`hardly soak live` (or `--ids datatables-ajax,quotes-login,…`). Catalog covers loopback
WebForms/token login, HTML/AJAX tables, form logins, GraphQL, and JSON/OpenAPI — see
`hardly.live_targets` and [docs/test-targets.md](docs/test-targets.md).
[CONTRIBUTING.md](CONTRIBUTING.md), [AGENTS.md](AGENTS.md); release notes in
[CHANGELOG.md](CHANGELOG.md).

## Security

HAR files often contain live passwords and session tokens. hardly redacts by default, but treat
captures as secrets: do not commit or share them, and rotate credentials if one leaked. Use hardly
only on targets you are authorised to access. See [SECURITY.md](SECURITY.md).

## License

MPL-2.0. Generated output (stubs, OpenAPI, reports) is not covered; see [NOTICE.md](NOTICE.md).
