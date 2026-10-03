# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/) (pre-1.0: minor versions may change behaviour).

## [Unreleased]

### Added
- Repository documentation and tooling: `CONTRIBUTING.md`, `SECURITY.md`, this changelog,
  `docs/architecture.md`, `docs/troubleshooting.md`, a docs link-check test, ruff configuration,
  pre-commit config, GitHub Actions CI and PR/issue templates.
- Package metadata: keywords, classifiers and project URLs.

### Changed
- `AGENTS.md` and `README.md` rewritten to be concise; every doc now opens with a purpose line.
- Lint auto-fixes (import order, unused imports, deprecated typing forms); no behaviour change.

## [0.2.x]

### Added
- **Core analysis**: streaming ijson ingest into a SQLite index; hosts, endpoints, path templating,
  content kinds, search, entry/compare, pages, stats, coverage, issues, duplicates and slow traffic.
- **HTML and portal reading**: brief, story, forms and labels, UI, outlines, routes, params, tables,
  data-attribute interpretation, grid-library and pagination detection, GraphQL.
- **Credentials and auth**: credential map (names and shapes only), login flow, cookies, correlate and
  trace, redirects, challenges, generic auth-pattern detectors (bearer/refresh, OIDC/PKCE, SAML,
  double-submit CSRF, signed requests), technology fingerprinting (`stack`), ArcGIS REST explorer.
- **Gates and bot walls**: bot-protection catalog, gate taxonomy with written policy
  (`docs/gate-policy.md`), redirect-loop diagnosis, recipe guard. Detection and reporting only.
- **Capture**: Playwright capture in three modes (archive, headless, interactive), aria refs, recipes
  with `find_click`, iframe/shadow-DOM/hover/consent handling, per-step options, body backfill, retry of
  transient errors, slot/budget/noise controls, browser autodetection, classified capture errors.
- **Client output**: urllib stubs with token carry-forward, AJAX deltas, pagination iterators and
  retry/backoff; OpenAPI with security schemes and contract-drift check; Postman; Markdown briefs;
  recipe planning; replay minimisation (`replay_check`); flow graph and confirm-gated flow replay.
- **Streams and hygiene**: gRPC-web, protobuf, msgpack, SSE and WebSocket detection, body queries,
  double-encoded JSON unwrapping, HAR doctor, and prune/split/merge/scrub tools.
- **Reporting and catalog**: one-pass evidence-index report (prose behind `explain=true`);
  content-neutral target catalog with `TargetAdapter` and a polite batch verifier; curl-first
  robots-aware crawl.
- **Agent onboarding**: `hardly_start`, rewritten tool docstrings, MCP prompts and resources, bundled
  Agent Skill with `hardly skill install`, generated `docs/tools.md`.
- **Neutrality guard**: `docs/scope.md` and `tests/test_neutrality.py` keep the codebase free of
  site-specific terms.

### Security
- Secrets are redacted at ingest and in every reported URL; stale cached indexes rebuild via
  `INDEX_VERSION`.
