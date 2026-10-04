# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/) (pre-1.0: minor versions may change behaviour).

## [Unreleased]

### Security hardening (no tool, parameter or command was renamed or removed)
- **Outbound URL guard.** Every live tool (`hardly_send_*`, catalog verify, crawl, replay, redirect and
  ArcGIS walks) and the initial URL of the browser tools refuse non-http(s) URLs, credentials in the URL
  and hosts that are or resolve to loopback, private, link-local (cloud metadata), CGNAT, multicast or
  reserved addresses, `localhost`, `*.local` and `*.internal`. Every redirect hop is re-validated and the
  connection goes to the validated address. Error code `host_not_allowed`; dry-run plans report it too.
  Opt-out for local testing: `HARDLY_ALLOW_PRIVATE_HOSTS=1` or the new global CLI flag
  `--allow-private-hosts` (before the group; the per-command CLI snapshot is unchanged).
- **Write-path guard.** All writes (`hardly_write_*`, session `output_path`, `har_output_path`, capture
  export path, screenshots, catalog and plan outputs, browser `profile`, CLI `-o`) must resolve inside the
  current directory, the OS temp directory, `/workspace` or `HARDLY_WRITE_DIRS`; special files and
  credential / shell-startup locations (`~/.ssh`, `~/.bashrc`, `.git`, ...) are never writable. Error code
  `path_not_allowed`. **Behaviour change**: a path outside those directories that used to work now needs
  `HARDLY_WRITE_DIRS`.
- **Secret canary test and the leaks it found.** `tests/test_secret_canary.py` plants canary secrets in a
  synthetic HAR and checks every tool, the CLI and the shareable writers. Fixed generically in
  `core/redact.py`: secret query/fragment values inside `Location` / `Referer` / `Link` headers and URLs in
  text, `user:pass@` URL credentials, headers named like secrets (`X-Session-Token`), double-encoded JSON,
  JSON strings holding HTML, `{"name": ..., "value": ...}` pairs, sensitive HTML attributes and script
  assignments (`csrf`, `xsrf`, `nonce` and `authenticity` keys count as secrets), `hardly_write_har_scrubbed`
  (now shares these helpers and also scrubs WebSocket messages), `hardly_session_sql` (raw header values
  hidden, text cells redacted), `hardly_entry_body_query` (regex and windows run on the redacted text),
  `hardly_entry_build_curl` form bodies, stored initiator URLs. `hardly_entry_search(header_contains=...)`
  matches redacted values only. A saved index no longer keeps raw header values or page-text values that
  are redacted on display.
- **Robustness.** HARs are read with a 4 MiB buffer (one 50 MB body: 112 s to 2.6 s), grid-signal
  scanning samples very large HTML, untrusted JSON is parsed with a nesting cap (`input_too_deep` instead
  of a crash), `hardly_entry_body_query` readable prefix is 2 MB of the redacted body
  (`readable_prefix_chars`), pathological-input tests with time budgets for the detectors and redaction.
- Docs: threat model in [SECURITY.md](SECURITY.md), troubleshooting entries for `host_not_allowed` and
  `path_not_allowed`.

### Changed: the v1 API surface (nothing was published before this, so there are no aliases)
- **MCP tools: 97 renamed or merged into 71.** The first word is the effect: `hardly_send_*` sends
  requests (confirm-gated), `hardly_write_*` writes a file (`overwrite=false` by default),
  `hardly_browser_*` drives a browser; everything else only reads. 43 old tools are folded into 17
  (for example `hardly_auth_report(sections=[...])`, `hardly_gate_bot_protection`, `hardly_page_ui`,
  `hardly_write_export(format=...)`, `hardly_browser_interact(action=...)`). Every old name and its new
  name: [docs/api-decisions.md](docs/api-decisions.md).
- **Parameters unified**: `har_path`, `output_path`/`output_dir` + `overwrite`, `entry_id`/`entry_ids`,
  `other_entry_id`/`other_session_id`, `limit`/`offset`, `confirm` (replaces `dry_run`), durations in
  `*_seconds`, native JSON lists and objects instead of `*_json` strings, `null` for unset.
- **CLI mirrors the tools**: `hardly <group> <command>`, where the command is the tool name without
  `hardly_` (`hardly session open HAR`, `hardly entry get HAR 12`, `hardly send entry HAR 12 --confirm`,
  `hardly write export HAR --format openapi -o api.yaml`, `hardly browser capture-discover URL`).
  Flags are the parameter names with hyphens; live commands take `--confirm` (no more `--yes`,
  `--allow-gate`); booleans that default to true are `--x` / `--no-x`; lists are comma separated.
  Every old command name was removed. Reference (generated): [docs/cli.md](docs/cli.md).
- Merged commands print the tool's result (sections), so `session overview`, `auth report`,
  `gate bot-protection`, `endpoint schema`, `tech stack` and friends differ in shape from the old
  one-purpose commands. `send` commands print a plan (exit 0) without `--confirm` instead of an
  error; `send catalog-verify` saves statuses only with `--write-back`; `session report` no longer
  writes (use `write export --format report`); `client build` prints and `write export --format
  client_python` writes.

### Added
- **Frozen surface**: `tests/api_surface.json` (tools, parameters, defaults, effect markers) and
  `tests/cli_surface.json` (commands, positionals, flags), each with a dump script and a test that
  fails on any unreviewed change ("v1 names are permanent"), plus `tests/test_docs_tool_names.py`
  (every tool name, tool call and CLI example in the docs exists and parses).
- `docs/api-stability.md` (public surface, semver rules, deprecation process, index-version rules),
  `docs/api-decisions.md` (how the names were chosen) and the generated `docs/cli.md`.
- `hardly session sql HAR "SELECT ..."` and `hardly browser start --foreground` (record until the
  window is closed).
- One persistence rule: **give an output path to save; otherwise nothing is written.**
  `hardly_write_session_copy(session_id, output_path, format='index')` / `hardly session open HAR -o OUT` /
  Python `open_session(har_or_index, output_path=None, overwrite=False)`. The index is written
  atomically (`VACUUM INTO` a temp file in the same directory, then `os.replace`; never in place) and
  an existing file is refused unless `overwrite`. Results report `saved_to`.
- `hardly_session_open` accepts a HAR or a previously saved index (SQLite header + embedded `meta`: source HAR
  path/size/mtime, index version; no sidecar files), skipping re-ingest. An index from another build
  returns `index_outdated` with the exact re-open call.
- Python API: `open_session(...)` returns a `Session` (context manager; `.session_id`, `.conn`
  read-only, `.info`, idempotent `.close()`), exported from `hardly`.
- Idempotent: the session id is a pure function of the resolved input path; opening it again returns the
  same live session without re-ingesting (reference counted); open again with `output_path` just saves
  it. Unknown ids give a deterministic `unknown_session` error whose hint is the `hardly_session_open` call to
  repeat. Ingest output is deterministic.
- `hardly_write_session_copy` / `hardly write session-copy HAR -o OUT`: atomic copy of a live session's source HAR (or index).
- Captures without an output path are ephemeral: private temp file in the OS temp dir, ingested into a
  memory session and deleted at once (`har_path: null, ephemeral: true`); pass `har_output_path` / `-o` to keep the HAR.
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
  the reopen tool, storage modes (`HARDLY_INDEX`, `auto`) were removed before any release. Files left
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
- **Agent onboarding**: `hardly_guide_task_plan`, rewritten tool docstrings, MCP prompts and resources, bundled
  Agent Skill with `hardly skill install`, generated `docs/tools.md`.
- **Neutrality guard**: `docs/scope.md` and `tests/test_neutrality.py` keep the codebase free of
  site-specific terms.

### Security
- Secrets are redacted at ingest and in every reported URL; stale cached indexes rebuild via
  `INDEX_VERSION`.
