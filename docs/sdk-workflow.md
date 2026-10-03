# From capture to client SDK

A repeatable path from "I can drive the site in a browser" to "I have a client
library". Commands are shown as CLI; every step is also an MCP tool
(`hardly_<name>`). Replace placeholders with your own host and paths.

## 1. Get a HAR

```bash
hardly modes                                    # pick archive / headless / interactive
hardly capture https://site.example -o a.har    # interactive: a person clicks; needs [capture]
hardly capture discover https://site.example --headless   # optional --recipe steps.json — see capture.md
```

## 2. Orient

```bash
hardly summary a.har        # counts, hosts, status mix
hardly hosts a.har          # preferred_host = the host to model first
hardly wall a.har           # bot-wall / challenge evidence (Akamai, Cloudflare, captcha, 403/429)
hardly coverage a.har       # empty / truncated bodies — recapture if important ones are empty
```

## 3. Map the API surface

```bash
hardly endpoints a.har --host api.site.example   # templated routes, methods, status, kinds
hardly content a.har --host site.example         # json / jsonl / csv / html_table / pdf / image …
hardly schema a.har GET api.site.example /items/{id}   # inferred JSON schema (method host path_template)
hardly graphql a.har                             # operations: type, name, variable keys
hardly grids a.har                               # grid libraries, JSON envelopes, paging params, data-* attrs
hardly routes a.har                              # URLs referenced in JS but never fetched
```

`content` tells you which responses are structured data, which are HTML you
must parse, and which are media/documents to download. For HTML tables and
detail pages, hardly gives header/column names and label/value rows so you do
not scrape from raw bodies.

## 4. Understand the pages (HTML UIs)

```bash
hardly brief a.har        # one-shot: story + forms + correlation + credentials summary
hardly story a.har        # ordered steps, annotated by role (page/search/detail/auth/…)
hardly forms a.har --entry-id 12   # fields, hidden inputs, handlers, label/value rows
hardly outline a.har 12 --format markdown
hardly params a.har POST site.example /search   # which parameters vary across calls to one route
```

`hardly capture discover … --recipe` can do the clicking for you with the
`find_click` recipe step (see [capture.md](capture.md#recipes)). If you have only a landing page, `hardly find-search a.har --keyword <term>`
ranks links, buttons and postback targets likely to lead to a search/lookup
UI and returns a ready `click` step. You supply the domain vocabulary; hardly
supplies generic signals only.

## 5. Work out authentication

```bash
hardly credentials a.har   # password/identity fields, session cookies + flags, CSRF, OAuth params,
                           # value shapes, hypothesised login_flow — names and shapes only
hardly correlate a.har     # which value from response N is replayed in request M
hardly trace a.har --name <field>   # follow one field across requests
hardly cookies a.har       # cookie name timeline (values omitted)
hardly redirects a.har     # 3xx chains
```

Typical findings that drive SDK design: which cookie is the session, whether a
CSRF/verification token must be scraped from a prior page, whether auth is a
form post, a token endpoint, or an OAuth redirect dance, and which hidden
fields must be echoed back (see [technologies.md](technologies.md)).

## 6. Generate a starting point

```bash
hardly stub a.har --host site.example -o client.py   # stdlib urllib sketch, cookies + placeholders
hardly export-openapi a.har -o openapi.json          # with securitySchemes
hardly export-postman a.har -o collection.json
hardly export-md a.har -o API.md --host api.site.example
hardly recipe-plan a.har -o steps.json               # capture recipe to refresh the capture later
```

The stub is a **sketch**: secrets are `PLACEHOLDER_*`, steps follow capture
order, correlation notes show where tokens come from. Treat it as scaffolding
and move the real logic into your SDK.

## 7. Verify and keep current

- `hardly probe` replays an entry live. It needs explicit confirmation, and
  secrets only via overrides — never from the HAR.
- Re-capture periodically and run `hardly diff old.har new.har` to see changed
  endpoints and credentials behaviour.
- Keep small, hand-redacted response snippets as unit-test fixtures; do not
  commit HARs. See [integrating.md](integrating.md).
