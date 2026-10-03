# hardly

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

Python 3.10+. Cache lives in `~/.cache/hardly/` (override with `HARDLY_CACHE_DIR`).

## 60-second quick start

```bash
hardly modes                                  # which of the three modes fits
hardly brief path/to/capture.har              # one-screen overview of a HAR
hardly endpoints path/to/capture.har --host api.example.com
hardly report path/to/capture.har             # one-pass evidence index
hardly stub path/to/capture.har --host api.example.com -o client.py
```

For agents, start with `hardly_start(goal, har_path, url)` (CLI: `hardly start --goal ...`): it
returns an ordered plan with example calls and the current environment state.

## Three modes

| Mode | When | Entry |
|------|------|-------|
| **archive** | A HAR file already exists | `hardly_open(path)` then `hardly_brief` / `hardly_endpoints` |
| **headless** | Only a URL; an agent can drive the page | `hardly_discover(url)` (CLI `hardly capture discover URL`) |
| **interactive** | Bot wall, captcha, MFA, complex UI | `hardly_capture_start(headed=true)`, **ask the person**, then `hardly_capture_stop` |

After any capture, continue in archive mode on the returned `session_id`. hardly never evades
captchas or bot walls: it identifies them and tells you to stop, ask a person, or re-run elsewhere
([docs/gate-policy.md](docs/gate-policy.md)). Details: [docs/capture.md](docs/capture.md).

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
               "-e", "HARDLY_CACHE_DIR=/workspace/.hardly-cache",
               "-e", "HARDLY_WORKSPACE=/workspace",
               "hardly-mcp:latest"]
    }
  }
}
```

Host paths under the mount map to `/workspace/...`.

## Agent onboarding

- `hardly_start`, `hardly_modes`, `hardly_capabilities` (stale MCP? restart the server),
  `hardly_help(topic)`, `hardly_recommend("...")`.
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
| [docs/reporting.md](docs/reporting.md) | `hardly_report` evidence index |
| [docs/catalog.md](docs/catalog.md) | Target catalog, `TargetAdapter`, batch verify |
| [docs/capture.md](docs/capture.md) | Headless and interactive capture, recipes, env vars |
| [docs/technologies.md](docs/technologies.md) | What is detected, per technology |
| [docs/architecture.md](docs/architecture.md) | Data flow and design rules |
| [docs/troubleshooting.md](docs/troubleshooting.md) | Common first-use problems |
| [docs/tools.md](docs/tools.md) | Generated reference for every MCP tool |

## Library use

```python
from hardly.session import open_har, require_conn
from hardly.index import query as q

info = open_har("capture.har")
conn = require_conn(info["session_id"])
print(q.list_endpoints(conn, host="api.example.com"))
```

## Development and tests

```bash
pytest -q                 # offline; HARDLY_LIVE_CAPTURE=1 enables live Playwright tests
ruff check .
```

Live soak against public demo sites (no private HARs): `hardly soak-live --list`, then
`hardly soak-live`. See [CONTRIBUTING.md](CONTRIBUTING.md) and [AGENTS.md](AGENTS.md); release notes
in [CHANGELOG.md](CHANGELOG.md).

## Security

HAR files often contain live passwords and session tokens. hardly redacts by default, but treat
captures as secrets: do not commit or share them, and rotate credentials if one leaked. Use hardly
only on targets you are authorised to access. See [SECURITY.md](SECURITY.md).
