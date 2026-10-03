# From capture to client SDK

> Purpose: A repeatable path from a captured session to a client SDK, step by step.

A repeatable path from "I can drive the site in a browser" to "I have a client
library". Commands are shown as CLI; every step is also an MCP tool: the command is the tool name
without `hardly_` (`hardly session overview` is `hardly_session_overview`, see [cli.md](cli.md)).
Replace placeholders with your own host and paths.

## 1. Get a HAR

```bash
hardly guide mode                               # pick archive / headless / interactive
hardly browser start https://site.example -o a.har --foreground   # interactive: a person clicks; needs [capture]
hardly browser capture-discover https://site.example --analyze --confirm   # headless; optional --steps steps.json, see capture.md
```

## 2. Orient

```bash
hardly session overview a.har        # counts per server, method and status; main_host = the host to model first
hardly gate bot-protection a.har --sections bot_protection   # bot-wall / challenge evidence (Akamai, Cloudflare, captcha, 403/429)
hardly session body-coverage a.har   # empty / truncated bodies: recapture if important ones are empty
```

## 3. Map the API surface

```bash
hardly endpoint list a.har --host api.site.example   # templated routes, methods, status, kinds
hardly session traffic-stats a.har --host site.example   # MIME mix, sizes, timing, payload_kinds: json / jsonl / csv / html_table / pdf / image
hardly endpoint schema a.har GET /items/{id} --host api.site.example   # inferred JSON schema
hardly endpoint graphql a.har                        # operations: type, name, variable keys
hardly tech stack a.har                              # frameworks and, under data_grids, grid libraries, JSON envelopes, paging params
hardly page embedded-routes a.har                    # URLs referenced in JS and data-* attributes but never fetched
```

`payload_kinds` tells you which responses are structured data, which are HTML you
must parse, and which are media/documents to download. For HTML tables and
detail pages, hardly gives header/column names and label/value rows so you do
not scrape from raw bodies.

## 4. Understand the pages (HTML UIs)

```bash
hardly session site-brief a.har    # one-shot digest: story + forms + correlation + credentials summary
hardly session story a.har         # ordered steps, annotated by role (page/search/detail/auth/...)
hardly page forms a.har --entry-id 12   # fields, hidden inputs, handlers, label/value rows
hardly entry outline a.har 12 --format markdown
hardly endpoint schema a.har POST /search --host site.example --sections param_roles   # which parameters vary across calls to one route
```

`hardly browser capture-discover URL --analyze --steps FILE` can do the clicking for you with the
`find_click` step (see [capture.md](capture.md#recipes)). If you have only a landing page,
`hardly page ui a.har --sections search_links --keywords term` ranks links, buttons and postback
targets likely to lead to a search/lookup UI and returns a ready `click` step. You supply the domain
vocabulary; hardly supplies generic signals only.

## 5. Work out authentication

```bash
hardly auth report a.har --sections credentials   # password/identity fields, session cookies + flags, CSRF, OAuth params,
                                                  # value shapes, hypothesised login_flow: names and shapes only
hardly session trace-value a.har                  # which value from response N is replayed in request M
hardly session trace-value a.har --name csrf_token   # follow one field across requests
hardly auth report a.har --sections cookies       # cookie name timeline (values omitted)
hardly session redirect-history a.har             # 3xx chains
```

Typical findings that drive SDK design: which cookie is the session, whether a
CSRF/verification token must be scraped from a prior page, whether auth is a
form post, a token endpoint, or an OAuth redirect dance, and which hidden
fields must be echoed back (see `docs/technologies.md`).

## 6. Generate a starting point

```bash
hardly write export a.har --format client_python --host site.example -o client.py   # stdlib urllib sketch, cookies + placeholders
hardly write export a.har --format openapi -o openapi.json                          # with securitySchemes
hardly write export a.har --format postman -o collection.json
hardly write export a.har --format api_markdown -o API.md --host api.site.example
hardly write export a.har --format plan_steps -o steps.json                         # browser steps to refresh the capture later
```

`hardly client build a.har --host site.example` prints the same client without writing a file (MCP
`hardly_client_build`). The client is runnable and **carries tokens forward**: values
issued by an earlier response are extracted at run time: all hidden form fields
are carried forward (`_hidden_fields`, covering ASP.NET VIEWSTATE/EVENTVALIDATION
and antiforgery fields), cookies are echoed into headers (`_cookie`, URL-decoded,
e.g. XSRF-TOKEN to X-XSRF-TOKEN), and JSON keys (including double-encoded bodies)
are read with `_json_path`. Previous bodies are kept in `self.resp[entry_id]`.
User-supplied values (passwords, search terms) stay `PLACEHOLDER_*` defaults,
overridable as `run(txtpassword="...")`.

The client is a **sketch**: secrets are `PLACEHOLDER_*`, steps follow capture
order, correlation notes show where tokens come from. Treat it as scaffolding
and move the real logic into your SDK.

## 6b. Trim the client with an ablation run

Once a request works, run `hardly send entry-ablation a.har 12 --confirm` (MCP
`hardly_send_entry_ablation`) with your own `--overrides` for secrets (cookies, auth headers,
CSRF/hidden fields as inline JSON; the index never holds their values, and `needs_override` lists the
names you must supply). Encode only the `required` headers, cookies, parameters,
fields and prior steps in the SDK; treat `optional` as safe to omit. Default is
GET/HEAD only; keep `--max-requests` small. Output contains names and findings,
never bodies or values.

## 7. Verify and keep current

- `hardly send entry a.har 12 --confirm` replays an entry live. It needs explicit confirmation, and
  secrets only via overrides, never from the HAR.
- Re-capture periodically and run `hardly session compare old.har new.har` to see changed
  endpoints and credentials behaviour.
- Keep small, hand-redacted response snippets as unit-test fixtures; do not
  commit HARs. See `docs/integrating.md`.

## Client helpers

Generated clients retry 429/5xx with backoff and `Retry-After` (`HARDLY_STUB_RETRIES`, `HARDLY_STUB_BACKOFF`), expose `client.pages(entry_id)` (grid paging parameters) and `client.follow(entry_id)` (cursor / next-link / `Link` header), and carry refreshed hidden fields from ASP.NET AJAX partial responses. `hardly endpoint pagination a.har` shows the detected paging shapes.

## Verifying a client

- `hardly entry dependencies a.har 12` shows the ordered steps and which earlier response supplied each header, cookie, hidden field or value, plus the inputs you must supply (credentials, tokens).
- `hardly send entry-series a.har --entry-id 12 --confirm` replays that flow live (a plan without `--confirm`) and names the first step whose status, content type or body shape diverges. Secrets come from `HARDLY_INPUT_<NAME>` env vars or `--env '{"NAME":"value"}'`; values are never printed.
- `hardly spec contract-check a.har openapi.json` compares a fresh capture with an exported OpenAPI file and lists drift. "Removed" means not observed, which may only be a coverage gap.
- `hardly entry body-query a.har 12 --jsonpath '$.items'` searches inside very large bodies (JSONPath-lite or regex, paged); `hardly endpoint streams a.har` summarises gRPC/protobuf/MessagePack/CSV/SSE/WebSocket traffic.
- `hardly har file-check a.har` checks the HAR itself (truncated bodies, sanitised cookies, clock skew, noise); `hardly write har-pruned|har-split|har-merged|har-scrubbed` produce cleaned copies and never edit in place.
