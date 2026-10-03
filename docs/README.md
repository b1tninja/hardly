# hardly documentation

> Purpose: Index of the hardly docs and which one to read for a given need.

hardly is a **generic helper and MCP server for reading and capturing HAR files** and turning them
into what you need to write a client SDK: endpoints, forms and labels, data and media kinds, and how
credentials and authentication work. It knows technologies and resource kinds, and nothing about any
particular website or subject matter; that belongs in the SDK you build with it.

## Start here

| Read this | When |
|-----------|------|
| [scope.md](scope.md) | Before changing anything: what is in scope, what is not, and the change checklist |
| [cheatsheet.md](cheatsheet.md) | One-page quick reference (also MCP resource `hardly://cheatsheet`) |
| [concepts.md](concepts.md) | Sessions, the index, redaction, pagination, the three modes |
| [architecture.md](architecture.md) | Data flow, capture paths, live-tool gating, redaction, `INDEX_VERSION` |

## Workflows

| Read this | When |
|-----------|------|
| [sdk-workflow.md](sdk-workflow.md) | Building a client SDK from a capture, step by step |
| [capture.md](capture.md) | Recording HARs: headless, interactive, recipes, env vars, containers |
| [reporting.md](reporting.md) | One-pass evidence index: sections, severity, detail levels, `explain` |
| [catalog.md](catalog.md) | Tracking many targets with several endpoints each; `TargetAdapter`; polite batch verify |
| [integrating.md](integrating.md) | Using hardly from another project (MCP, CLI, Python), fixtures, soak |

## Reference

| Read this | When |
|-----------|------|
| [tools.md](tools.md) | Generated reference for every MCP tool |
| [technologies.md](technologies.md) | What hardly detects per technology, and what it does not |
| [gate-policy.md](gate-policy.md) | What to do at each kind of gate: accept, stop, or re-run elsewhere |
| [crawl-handoff.md](crawl-handoff.md) | Crawl strategy, budgets, and traps hit during live testing |
| [troubleshooting.md](troubleshooting.md) | Common first-use problems and fixes |
| [test-targets.md](test-targets.md) | Research notes for growing the soak catalog |

Setup (venv, Docker, MCP config) is in the top-level [README](../README.md); contributor and agent
rules are in [AGENTS.md](../AGENTS.md) and [CONTRIBUTING.md](../CONTRIBUTING.md). Maintainers: see
[releasing.md](releasing.md) for publishing, verification and the distribution matrix.

## Scope rule

hardly ships **technology helpers** and **generic resource classifications**. It does not ship site
recipes, vendor/site names in logic, subject-specific vocabularies, or record schemas. Downstream
projects pass their own vocabulary in as arguments (for example `hardly_page_ui` `keywords`) and
keep their own captures, fixtures and recipes. Details: [scope.md](scope.md).
