# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/) (pre-1.0: minor versions may change behaviour).

## [Unreleased]

### Added
- One persistence rule: **give an output path to save; otherwise nothing is written.**
  `hardly_open(har_path, output_path=None, overwrite=False)` / `hardly open HAR -o OUT` /
  Python `open_session(har_or_index, output_path=None, overwrite=False)`. The index is written
  atomically (`VACUUM INTO` a temp file in the same directory, then `os.replace`; never in place) and
  an existing file is refused unless `overwrite`. Results report `saved_to`.
- `open` accepts a HAR or a previously saved index (SQLite header + embedded `meta`: source HAR
  path/size/mtime, index version; no sidecar files), skipping re-ingest. An index from another build
  returns `index_outdated` with the exact re-open call.
- Python API: `open_session(...)` returns a `Session` (context manager; `.session_id`, `.conn`
  read-only, `.info`, idempotent `.close()`), exported from `hardly`.
- Idempotent: the session id is a pure function of the resolved input path; opening it again returns the
  same live session without re-ingesting (reference counted); open again with `output_path` just saves
  it. Unknown ids give a deterministic `unknown_session` error whose hint is the `hardly_open` call to
  repeat. Ingest output is deterministic.
- `hardly_export_har` / `hardly export-har HAR -o OUT`: atomic copy of a live session's source HAR.
- Captures without an output path are ephemeral: private temp file in the OS temp dir, ingested into a
  memory session and deleted at once (`har_path: null, ephemeral: true`); pass `har_path` / `-o`, or
  `export_path` to `hardly_capture_stop`, to keep the HAR.
- Release engineering: tag-driven `release.yml` (build once, PyPI trusted publishing with attestations,
  GitHub Release with checksums and CycloneDX SBOM, multi-arch GHCR image, MCP Registry via
  `server.json`), nightly real-browser workflow, CodeQL, Dependabot, pip-audit and workflow lint,
  `docs/releasing.md`, `browser`/`live` pytest markers, `tests/test_packaging.py`.
- Repository documentation and tooling: `CONTRIBUTING.md`, `SECURITY.md`, this changelog,
  `docs/architecture.md`, `docs/troubleshooting.md`, a docs link-check test, ruff configuration,
  pre-commit config, GitHub Actions CI and PR/issue templates.
- Package metadata: keywords, classifiers and project URLs.

### Changed
- No cache: the per-HAR cache directory (`~/.cache/hardly`, `HARDLY_CACHE_DIR`, `<sid>.db` + `<sid>.json`),
  `hardly_reopen`, storage modes (`HARDLY_INDEX`, `auto`) were removed before any release. Files left
  by earlier development versions under `~/.cache/hardly` can simply be deleted.
- `HARDLY_RUNTIME_DIR` (optional) overrides the private scratch dir for capture state, slot locks and
  ephemeral HARs; it defaults to `<tempdir>/hardly-<uid>`, never the home directory.
- Contract checks ingest into memory instead of a temp file (fixes Windows file locks).
- Dockerfile copies `docs/` and `skills/` (required by the wheel build).
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
