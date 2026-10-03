# Concepts

> Purpose: The mental model: sessions, the SQLite index, redaction, pagination and the three modes.

## Why an index

A browser HAR is often tens of megabytes. Reading it into a model wastes
tokens and still misses structure. hardly streams the file once into SQLite
(`ijson`, constant memory), then answers small questions against the index.

- **Session** — one indexed HAR, identified by `session_id`. `hardly_open`
  creates it, in memory by default (nothing on disk). After a restart or
  `hardly_close` the id is gone: repeat `hardly_open`.
- **Entry** — one request/response pair, addressed by `entry_id`.
- **Noise filter** — static assets, trackers, `OPTIONS` and non-API MIME types
  are flagged `is_noise` and hidden by default from endpoint/story views.
- **Path templating** — `/users/42` and `/users/97` collapse to
  `/users/{id}` so endpoint lists show routes, not instances.
- **Preferred host** — `hardly_hosts` returns `preferred_host`, the apex HTML
  host, chosen to skip CDN/payment/analytics hosts. Related same-apex API hosts
  are merged into stories.
- **Value shapes** — at ingest, hardly records what a value *looks like*
  (JWT, hex, base64, UUID…) so credentials can be described without storing or
  returning secrets.

## Token rules

Every tool is built so output stays small and safe:

- bodies are truncated, with full detail only via `entry` / `outline`;
- secrets (passwords, tokens, cookies, auth headers) are redacted; credential
  tools return **names and shapes, never values**;
- lists are paginated (`limit`, `offset`);
- the raw HAR is never returned. Don't `Read` it either.

HARs are still secrets on disk: they contain live cookies, passwords and
bodies. They are git-ignored; do not commit them.

## Three modes

Pick one first (`hardly_modes`, `hardly_mode`, or `hardly modes`):

| Mode | Use when | Entry point |
|------|----------|-------------|
| **archive** | A HAR file already exists | `hardly_open` → `hardly_brief` / `hardly_endpoints` |
| **headless** | A URL is scriptable by an agent | `hardly_discover(url)` or a capture recipe |
| **interactive** | Bot wall, CAPTCHA, MFA, complex UI | `hardly_capture_start(headed=true, channel="chrome")` → **ask the person** → stop |

After any capture stops, continue in **archive** mode on the new `session_id`.
In interactive mode, ask the person to click — never claim to see their screen.

## What the tools tell you

| Question | Tools |
|----------|-------|
| What hosts and routes exist? | `hosts`, `endpoints`, `routes`, `flow`, `pages` |
| What does each response contain? (data, media, documents) | `content`, `schema`, `outline`, `stats` |
| What can I submit? What are the fields called? | `forms`, `ui`, `story`, `params`, `graphql` |
| How do I log in and stay logged in? | `credentials`, `auth`, `correlate`, `trace`, `cookies`, `secrets`, `redirects` |
| Why is the capture incomplete or blocked? | `coverage`, `issues`, `wall`, `duplicates`, `slow` |
| What changed between two captures? | `diff` |
| Give me code or a spec | `stub`, `export_openapi`, `export_postman`, `export_md`, `curl` |

Full signatures: [tools.md](tools.md).
