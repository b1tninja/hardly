# hardly documentation

hardly is a **generic helper and MCP server for reading and capturing HAR files**
and turning them into what you need to write a client SDK: endpoints, forms and
labels, data and media kinds, and how credentials and authentication work. It
knows technologies (HTML forms, ASP.NET WebForms, GraphQL, OAuth, cookies/CSRF,
bot walls) and resource kinds (JSON, CSV, HTML tables, PDF, images…). It knows
nothing about any particular website or subject matter — that belongs in the
SDK you build with it.

| Read this | When |
|-----------|------|
| [concepts.md](concepts.md) | First. Sessions, the index, redaction, pagination, the three modes |
| [sdk-workflow.md](sdk-workflow.md) | You want to build a client SDK from a capture, step by step |
| [capture.md](capture.md) | Recording HARs: headless, interactive, recipes, env vars, containers |
| [technologies.md](technologies.md) | What hardly detects, per technology, and what it does not |
| [integrating.md](integrating.md) | Using hardly from another project (MCP, CLI, Python), fixtures, soak |
| [gate-policy.md](gate-policy.md) | What to do at each kind of gate: accept, stop, or re-run elsewhere |
| [crawl-handoff.md](crawl-handoff.md) | Crawl strategy, budgets, and a catalogue of traps hit during live testing |
| [tools.md](tools.md) | Generated reference for every MCP tool |

Setup (venv, Docker, Cursor MCP) lives in the top-level [README](../README.md);
agent rules live in [AGENTS.md](../AGENTS.md).

## Scope rule

hardly ships **technology helpers** and **generic resource classifications**.
It does not ship site recipes, vendor/site names in logic, subject-specific
vocabularies, or record schemas. Downstream projects (SDKs, adapters) pass
their own vocabulary in as arguments (for example `hardly_find_search`
`keywords`) and keep their own captures, fixtures and recipes.
