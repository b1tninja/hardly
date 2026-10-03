# Technology support

> Purpose: What hardly detects per technology (by wire-level signature, not by site) and what it does not.

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

Login steps carry a role and, for credential POSTs, an **outcome**: a GET that
merely contains a password input is `login_page`; a POST ends in `redirect`
(with the target path), `rejected` (401/403/422/429), `ok_json`, or
`page_returned` (a 200 HTML page after a credential POST is often a failed
login redisplayed — compare with a redirect). Session cookies are the
name-matched ones **plus** HttpOnly cookies first set by or after the credential
POST; CSRF cookies (`csrftoken`) and token-ish fields sent with the credentials
(`_token`) are reported under `csrf_names`, not as the session. OAuth/OIDC
stitching follows `Location` headers: a 3xx whose target carries `code` or
`id_token` is the callback hop, and token requests contribute their body field
names (`grant_type`, `code_verifier`…). WebAuthn/passkey ceremonies appear under
`webauthn` (option fetch with `challenge`/`rp`/`pubKeyCredParams`, verify with
`clientDataJSON`/`attestationObject`) and as `webauthn_*` login steps. Pages
that are empty client-rendered shells set `spa_login_suspected`, because their
password inputs only exist after JavaScript runs; entries with no response
(status -1/0) are counted in `aborted_entries`.

## ArcGIS REST

`hardly_arcgis` lists ArcGIS REST endpoints (`MapServer`, `FeatureServer`,
`ImageServer`, `GeocodeServer`) in an indexed capture: service roots, layer ids,
which layers were queried, parameter names used, paging evidence
(`resultOffset` / `resultRecordCount`) and whether `exceededTransferLimit` was
seen. `hardly_arcgis_explore(url, confirm=true)` makes at most one service
document, five layer documents and one one-row sample query, and reports layers,
fields (name, alias, type, domain), request templates (attribute, count-only,
distinct values, objectId paging fallback) and the sample as field names plus
masked shapes (digits 9, letters a) — never row values. Fields whose names look
like personal data (name, owner, phone, email, address, ssn, dob, birth) are
flagged, not hidden. A 498/499 response is a token-required gate: stop.
`find_service_urls` (library) extracts service URLs and item ids from
Experience Builder / Web AppBuilder configs and page text and shows the item
data URL pattern without fetching it.

## Minimal replay

Server frameworks often answer with a generic error (HTTP 500 or an error page)
when an implicit precondition is missing: an Ajax marker header
(`X-Requested-With`), a cookie set by an earlier page load, a paging parameter,
or a per-form hidden token. Do not guess which matters. `hardly_replay_check`
(CLI `hardly replay-check <har> <entry_id…> --yes`) replays the entry, or an
ordered flow of entry ids, with a cookie jar, removes one header, cookie, query
parameter, body field or prior step at a time, and compares a coarse outcome
signature (status class, content kind, JSON top-level keys or an HTML size band
and form presence). Pieces whose removal changes the signature are `required`;
the rest are `optional`. Secrets are supplied only through overrides
(`needs_override` lists the names). It defaults to GET/HEAD, never sends or
tests captcha/challenge token fields, and halts on 429, `Retry-After` or a gate
stop. Output is names and findings only.

## Technology fingerprint (`hardly_stack`)

`hardly stack` / `hardly_stack` scores framework tells from cookie *names*,
header names, URL paths and HTML/JS previews, and attaches a one-line SDK
implication to each: server frameworks (ASP.NET WebForms and antiforgery,
Blazor Server/WASM, Laravel, Django, Rails, Express, Spring/servlet, PHP, JSF),
front ends (Next.js, Nuxt, React, Vue, AngularJS, Angular, Inertia, Salesforce
Aura), CMS and site builders (AEM, WordPress, Drupal, SharePoint, Wix,
Squarespace, Webflow, GoDaddy), UI toolkits (Telerik/Kendo, DevExpress), GIS
(ArcGIS REST and web apps, Leaflet, OpenLayers, Mapbox/MapLibre GL, OGC WMS/WFS,
slippy tiles), API docs (Swagger/OpenAPI), and data conventions (double-encoded
JSON). Confidence is high/medium/low from weighted evidence; evidence lists
marker labels only, never cookie or token values. CDN/WAF products are reported
by `hardly_wall`.

## Data tables, double-encoded JSON, exports and route body keys

`hardly_tables` finds HTML data tables by structure (header row from `<th>`,
`<thead>` or an all-bold first row; at least two columns and one data row).
Nested layout tables, `colspan` and ASP.NET GridView pager rows are handled; a
pager sets `has_pager_hint`. Output is header names, column/row counts, a first
row **masked to shapes** (digits `9`, letters `a`/`A`, 24 chars max) and a
per-column kind guessed from all rows. Two-column label/value tables are
`kind: label_value` with their labels. Cell contents are never returned.

Some servers return a JSON *string* whose content is JSON. At ingest the string
is peeled (up to 3 layers), the stored preview is the unwrapped JSON, and a
`body_signals` row (`encoding` / `double-encoded-json`) is recorded;
`hardly_content` / `hardly_entry` report `kind: json` with hint
`double_encoded_json` and `hardly_schema` infers on the unwrapped value.

`hardly_grids` also lists `export_links`: links, forms and requests whose path
or query indicates a built-in export (`csv|xlsx|xls|json|xml|pdf|tsv`). An export
returns the whole result set in one response, so prefer it to paging.

`hardly_routes` lists, per route, the `method` (when visible) and up to 12
`body_keys` — object-literal key names found near the call (`$http.post`,
`axios.*`, `fetch`, `$.ajax`, `xhr.send`). Names only, never values.

## HTML data attributes

`hardly_data_attrs` (CLI `hardly data-attrs`) applies the MDN
[data attributes](https://developer.mozilla.org/en-US/docs/Web/HTML/How_to/Use_data_attributes)
model to captured HTML: `data-date-of-birth` is read by scripts as
`element.dataset.dateOfBirth`, and every value is a string. It reports:

- each attribute with its `dataset_key`, count, tags and **value kinds**
  (`integer`, `uuid`, `url`, `json`, `boolean`, `datetime`, `opaque_token`,
  `email`, `text`); short enum-like values (`toggle="modal"`) are listed because
  they are conventions, free text is not;
- **endpoints** carried in attributes (`data-url`, `data-href`, `data-api`…),
  resolved against the page URL, query *values* dropped;
- **embedded JSON** config (`data-config='{"apiBase":…}'`) with its top-level
  keys;
- **identifier attributes** (`data-id`, `data-row-key`) that tell you what a row
  or widget is keyed by;
- **framework hints**: Bootstrap (`data-bs-*`), Stimulus
  (`data-controller`, `data-*-target`), Turbo/Rails UJS (`data-remote`,
  `data-method`, `data-turbo-*`), htmx, Angular/Vue/React markers, test hooks
  (`data-testid`, `data-cy`), tracking (`data-gtm-*`), captcha widgets
  (`data-sitekey`), grid/table hints (`data-sort`, `data-page-size`).

SDK consequence: attribute-carried URLs and JSON are often the real API
configuration (base URLs, page sizes, feature flags) that never shows up in a
form or a network request until a script uses it.

### Gate taxonomy and policy

`hardly_gates` (and the `gates` list in `hardly_wall`, a summary in
`hardly_brief`) classifies each gate: `environment_blocked`, `bot_wall`,
`captcha`, `proof_of_work`, `waiting_room`, `click_through_terms`, `login`,
`paywall`, `rate_limit`, with an action `stop`, `accept_click_through` or
`unknown_rerun`. An `x-deny-reason` header (or a proxy-style 403/502 with no
site-WAF fingerprint) means *our* sandbox refused the request: it is reported as
"unknown — re-run from another network", never as a site wall. The catalog also
covers Azure Front Door (`x-azure-ref` alone is informational; the 403 "request
is blocked" page is a block), F5 (TSPD, `volt-adc`, "Request Rejected"), AWS WAF
challenges returned as HTTP 202, Imperva blocks returned as 503, and an
application-level `app-rate-limit` entry. `hardly_challenges` captcha widgets add
public `sitekeys` (max 3, truncated) and `token_endpoints` (requests whose field
names include a captcha token field; values never shown). Written policy:
[gate-policy.md](gate-policy.md). Headless recipes are guarded by
`hardly.core.recipe_policy.check_step`, and `find_click` stops on a gated page.

## HTTP auth challenges, throttling and captchas

`hardly_challenges` (CLI `hardly challenges`) reports:

- **Challenges:** `WWW-Authenticate` / `Proxy-Authenticate` schemes (Basic,
  Bearer, Digest, Negotiate, NTLM, Hawk…), parameter names, and safe values
  (`realm`, `error`, `scope`, `qop`, `algorithm`). Nonces and opaque values are
  never returned. For each challenge it notes whether the same request was
  retried with an `Authorization` header and the resulting status. SDK
  consequence: you need a challenge/response loop, not a pre-set header.
- **Throttling:** 429/423 responses, `Retry-After`, `X-RateLimit-*` /
  `RateLimit-*` headers (including quotas advertised on successful responses),
  and lockout wording ("too many attempts", "account locked"…). SDK
  consequence: back off and honour `Retry-After`.
- **Captcha widgets:** reCAPTCHA, hCaptcha, Cloudflare Turnstile, Arkose,
  GeeTest, Friendly Captcha and image captchas, with the response field names
  a form would submit. hardly never solves captchas; switch to interactive
  mode with a person.

## GraphQL

`hardly_graphql` lists the operations seen in the capture — entry, endpoint,
operation type and name, and variable keys (values redacted when sensitive) —
so a client can be written without schema introspection.

## Data grids and data conventions

`hardly_grids` (CLI `hardly grids`) reports, by name and count only (never row
data or parameter values):

- **HTML grid libraries:** DataTables, jqGrid, AG Grid, Kendo, Telerik RadGrid,
  DevExpress, Syncfusion, ASP.NET GridView, Tabulator, Handsontable,
  Bootstrap Table, Ext JS, PrimeFaces/PrimeNG, MUI DataGrid, Ant Design,
  Angular Material, Vaadin, SlickGrid, Webix, w2ui, Grid.js, TanStack Table.
  WebForms pager/sort commands (`Page$N`, `Sort$`, `Select$N`) are extracted
  from `__doPostBack` arguments.
- **JSON envelope conventions:** DataTables server-side
  (`recordsTotal`/`recordsFiltered`), jqGrid (`page`/`total`/`records`/`rows`),
  OData v2 and v4, the ASP.NET `d` wrapper, JSON:API, HAL, Spring Data pages,
  Django REST pagination, Relay connections (`edges`/`pageInfo`), Elasticsearch
  hits, ArcGIS REST feature sets, GeoJSON, Kendo `Data`/`Total`, and generic
  `totalCount`/`nextPageToken` style lists.
- **Request paging/sort/filter styles:** `draw/start/length`, jqGrid
  `_search/nd/sidx/sord`, Kendo `take/skip`, OData `$top/$skip/$filter`,
  `offset/limit`, `page/pageSize`, cursor/`after`/`pageToken`, Solr/Elastic
  `rows/from`, ArcGIS `resultOffset/where/outFields`, and sort parameters.
- **`data-*` attributes** ranked by frequency (`data-toggle`, `data-row-id`,
  `data-field`…), which usually reveal the grid's row and column identifiers.

SDK consequence: the paging style tells you how to enumerate all rows (and
whether the server pages at all); the envelope tells you where rows and totals
live; the grid library tells you whether the HTML is a rendered table or the
data arrives separately as JSON.

## Data and media kinds

`hardly_content` classifies every response: `json`, `jsonl`, `jsonp`, `csv`,
`html`, `html_table`, `xml`, `pdf`, `image`, and others, with hints (table
headers, JSON keys, columns). `hardly_schema` infers a JSON schema for an
endpoint; `hardly_export_openapi` embeds schemas and `securitySchemes`.

## Bot walls, WAFs and captchas

`hardly_wall` (CLI `hardly wall`) identifies the bot-protection product(s) in
use from wire-level evidence — cookie *names*, response headers, request URLs
and script sources, and challenge-page wording — and reports a **state** for
each: `blocked`, `challenged`, `clearance_seen` (a clearance cookie such as
`cf_clearance` was issued), or `present` (fingerprints only). The catalog
(`hardly.core.botwalls`) covers:

- **CDN/WAF:** Cloudflare, Imperva/Incapsula, AWS WAF, Sucuri, Vercel Security
  Checkpoint, Reblaze, DDoS-Guard, Fastly Signal Sciences.
- **Bot managers:** Akamai, DataDome, HUMAN/PerimeterX, Kasada, F5/Shape,
  Radware/ShieldSquare, Netacea.
- **Captcha / proof of work:** reCAPTCHA, hCaptcha, Cloudflare Turnstile, Arkose
  Labs, GeeTest, Friendly Captcha, MTCaptcha, Anubis.
- **Other:** Queue-it waiting rooms, Google's "unusual traffic" page, and a
  generic "unidentified block page" fallback (suppressed when a named product
  already explains the block).

A CDN or WAF header on an ordinary 200 response is *protection present*, not a
wall: it appears under `protection` and creates no `hit`. Plain 403/429 without
corroboration are listed as `status_only` (usually auth or rate errors).
Cookie values and tokens are never reported. hardly does not solve or evade
any of these; a block means re-capturing interactively with a person.

`hardly_coverage` / `hardly_issues` report empty or truncated bodies, errors
and redirects. Respect the site's terms.

## Not done (by design)

- No per-site or per-vendor logic, recipes, or field mappings.
- No subject-specific vocabulary baked in; pass your own (for example
  `keywords` to `hardly_find_search`).
- No secret values in output, ever.
- No claim that a stub works — it is a sketch to verify against the live site.

Missing a technology (another anti-forgery scheme, a framework's hidden-field
convention, a token protocol)? Add a detector in `hardly.core` with a synthetic
fixture and a test; keep it technology-level.
