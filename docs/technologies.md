# Technology support

hardly recognises technologies by their wire-level signatures, not by site.
This page lists what it detects and what it deliberately does not do.

## HTML forms and pages

`hardly_forms` / `hardly_ui` / `hardly_outline` parse HTML offline:

- forms (action, method, enctype), every input with type, name, id, value shape,
  select options, textareas, and xpath;
- links, buttons, `formaction`, `javascript:` and `onclick` handlers, and
  click targets (`actions`: JS links, postback links, buttons);
- inline-handler function names (`handler_functions`) and URL-like strings in
  JS (`hardly_routes`) to reveal endpoints never fetched during capture;
- **label/value rows** for detail pages in common layouts: label div beside
  value div, `th`/`td`, `dt`/`dd`, bold-label cells, and `span` label cells —
  so field names come from the page's own wording;
- HTML tables (`html_table` content kind) with header names;
- autocomplete hints for identity/password fields.

## ASP.NET WebForms

Detected from `__VIEWSTATE`, `__VIEWSTATEGENERATOR`, `__EVENTVALIDATION`,
`__EVENTTARGET`/`__EVENTARGUMENT` and `__doPostBack(target, arg)` calls.
`forms` reports the hidden fields and postback targets. `correlate` shows
which response a state field came from; `stub` marks them `PLACEHOLDER_*`
with a correlation note. SDK consequence: GET the page, scrape the hidden
fields, echo them in the POST, repeat per step.

## CSRF and anti-forgery tokens

Field/header names containing `csrf`, `xsrf` or `requestverification`
(including `__RequestVerificationToken`), plus value-based reuse are found by `credentials` and `correlate`; `trace`
follows any named field or exact value across requests without printing it.

### Token-name indirection

Some frameworks send two hidden fields: one whose *value* is the *name* of the
second, which holds the token (for example `x.token.name = token` plus
`token = …`). A client must read the first to learn which parameter carries the
token. `hardly_forms` marks such forms with `anti_forgery`
(`scheme: named_token`, `name_field`, `token_field`) and `hardly_credentials`
lists them under `anti_forgery_forms` (action, method, field names — never
token values).

### Server-issued keys replayed in headers

When a response hands out a key/ticket/secret (JSON field or hidden input) and
a later request sends it back in a custom header, query or body, `hardly_correlate`
reports the hop (`from_where` → `to_where`, header name, value kind and length;
never the value). Plumbing headers (`Accept`, `User-Agent`, `Content-*`, `Sec-*`,
`Referer`…) are ignored.

## Sessions and cookies

`hardly_cookies` gives a timeline of cookie names set and sent, with values
omitted. `hardly_credentials` adds `HttpOnly`, `Secure` and `SameSite` flags,
identifies likely session cookies by name.

## Authentication flows

`hardly_credentials` and `hardly_auth` map:

- password fields paired with their username/email fields;
- login endpoints and a hypothesised `login_flow`
  (credentials submit → token response → auth material);
- custom auth headers and bearer usage;
- OAuth/OIDC parameters (`client_id`, `redirect_uri`, `state`, `code`,
  `code_challenge`/`code_verifier`) with the authorize → callback → token sequence stitched from the
  capture;
- value **shapes** (JWT, hex, base64, UUID) so you know what kind of token a
  response issues without seeing it.

Values are never returned; probes take secrets only through overrides.

## GraphQL

`hardly_graphql` lists the operations seen in the capture — entry, endpoint,
operation type and name, and variable keys (values redacted when sensitive) —
so a client can be written without schema introspection.

## Data and media kinds

`hardly_content` classifies every response: `json`, `jsonl`, `jsonp`, `csv`,
`html`, `html_table`, `xml`, `pdf`, `image`, and others, with hints (table
headers, JSON keys, columns). `hardly_schema` infers a JSON schema for an
endpoint; `hardly_export_openapi` embeds schemas and `securitySchemes`.

## Bot walls and capture quality

`hardly_wall` detects Akamai, Cloudflare, Imperva/Incapsula, DataDome,
PerimeterX, reCAPTCHA/hCaptcha and generic access-denied/captcha pages
(challenge cookies, scripts, 403/429). `hardly_coverage` / `hardly_issues`
report empty or truncated bodies, errors and redirects. Respect the site's
terms; a wall means switch to interactive capture with a person, not to
evasion.

## Not done (by design)

- No per-site or per-vendor logic, recipes, or field mappings.
- No subject-specific vocabulary baked in; pass your own (for example
  `keywords` to `hardly_find_search`).
- No secret values in output, ever.
- No claim that a stub works — it is a sketch to verify against the live site.

Missing a technology (another anti-forgery scheme, a framework's hidden-field
convention, a token protocol)? Add a detector in `hardly.core` with a synthetic
fixture and a test; keep it technology-level.
