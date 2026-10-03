# Concepts

> Purpose: The mental model: sessions, the SQLite index, redaction, pagination and the three modes.

## Why an index

A browser HAR is often tens of megabytes. Reading it into a model wastes
tokens and still misses structure. hardly streams the file once into SQLite
(`ijson`, constant memory), then answers small questions against the index.

- **Session** — one indexed HAR, identified by `session_id`. `hardly_session_open`
  creates it, in memory by default (nothing on disk). After a restart or
  `hardly_session_close` the id is gone: repeat `hardly_session_open`.
- **Entry** — one request/response pair, addressed by `entry_id`.
- **Noise filter** — static assets, trackers, `OPTIONS` and non-API MIME types
  are flagged `is_noise` and hidden by default from endpoint/story views.
- **Path templating** — `/users/42` and `/users/97` collapse to
  `/users/{id}` so endpoint lists show routes, not instances.
- **Main host** — `hardly_session_overview` returns `main_host`, the apex HTML
  host, chosen to skip CDN/payment/analytics hosts. Related same-apex API hosts
  are merged into stories.
- **Value shapes** — at ingest, hardly records what a value *looks like*
  (JWT, hex, base64, UUID…) so credentials can be described without storing or
  returning secrets.

## Token rules

Every tool is built so output stays small and safe:

- bodies are truncated, with full detail only via `hardly_entry_get` / `hardly_entry_outline`;
- secrets (passwords, tokens, cookies, auth headers) are redacted; credential
  tools return **names and shapes, never values**;
- lists are paginated (`limit`, `offset`);
- the raw HAR is never returned. Don't `Read` it either.

HARs are still secrets on disk: they contain live cookies, passwords and
bodies. They are git-ignored; do not commit them.

## Three modes

Pick one first (`hardly_guide_mode`, or `hardly guide mode` on the command line):

| Mode | Use when | Entry point |
|------|----------|-------------|
| **archive** | A HAR file already exists | `hardly_session_open` → `hardly_session_site_brief` / `hardly_endpoint_list` |
| **headless** | A URL is scriptable by an agent | `hardly_browser_capture_discover(url, analyze=true, confirm=true)` with optional `steps` |
| **interactive** | Bot wall, CAPTCHA, MFA, complex UI | `hardly_browser_start(headed=true, channel="chrome")` → **ask the person** → stop |

After any capture stops, continue in **archive** mode on the new `session_id`.
In interactive mode, ask the person to click — never claim to see their screen.

## What the tools tell you

| Question | Tools |
|----------|-------|
| What hosts and routes exist? | `hardly_session_overview`, `hardly_endpoint_list`, `hardly_page_embedded_routes`, `hardly_session_timeline`, `hardly_page_list` |
| What does each response contain? (data, media, documents) | `hardly_session_traffic_stats`, `hardly_endpoint_schema`, `hardly_entry_outline` |
| What can I submit? What are the fields called? | `hardly_page_forms`, `hardly_page_ui`, `hardly_session_story`, `hardly_endpoint_schema(session_id, method, path_template, sections=['param_roles'])`, `hardly_endpoint_graphql` |
| How do I log in and stay logged in? | `hardly_auth_report` (sections quick, patterns, credentials, secret_names, cookies), `hardly_session_trace_value`, `hardly_session_redirect_history` |
| Why is the capture incomplete or blocked? | `hardly_session_body_coverage`, `hardly_session_issues`, `hardly_gate_bot_protection`, `hardly_session_duplicates`, `hardly_session_slow_requests` |
| What changed between two captures? | `hardly_session_compare` |
| Give me code or a spec | `hardly_client_build`, `hardly_write_export` (openapi, postman, api_markdown, site_brief), `hardly_entry_build_curl` |

Full signatures: [tools.md](tools.md).
