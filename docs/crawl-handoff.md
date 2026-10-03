# Crawl strategies and pitfalls — handoff

For anyone (human or agent) using hardly to explore a site and build a client
SDK. It records the strategies that worked and the traps that cost us time
during live testing on 2026-10-03 (about 40 public sites: practice logins, test
APIs, OIDC/passkey demos, grid-library demos, and 21 public-sector portal
landing pages).

**How to read the status tags.** *Fixed* = hardly was changed and has a test.
*Mitigated* = hardly reduces it but you must still watch for it. *Open* = known
and not handled. *Untested* = expected from how the technology works but not
yet observed by us; verify before relying on it.

hardly is content-neutral. Nothing here is specific to a site or subject; pass
your own vocabulary as `keywords`.

---

## 1. The loop

```
capture ─▶ index ─▶ analyse ─▶ decide next click/request ─▶ capture ─▶ …
 (HAR)    (SQLite)  (tools)         (find_click / recipe)
```

1. **Pick a mode** (`hardly modes`): a HAR already exists → *archive*; a URL an
   agent can drive → *headless*; a bot wall, CAPTCHA, MFA or complex UI →
   *interactive* (ask a person; never claim to see their screen).
2. **Capture the landing page**, then run `hardly brief`, `hardly wall`,
   `hardly challenges`. Decide the mode from what they say before doing more.
3. **Navigate toward the data** with `find_click` (see §3) until a real form,
   grid or API appears.
4. **Characterise it**: `forms`, `grids`, `data-attrs`, `endpoints`, `content`,
   `credentials`, `correlate`.
5. **Write the client** in your own repo from `stub` / `export-openapi` plus
   hand-redacted fixtures. Keep the recipe (`recipe-plan -o`) so the capture can
   be repeated, and `hardly diff` old vs new when the site changes.

## 2. Ground rules (read before crawling anything)

- **Be polite and bounded.** Keep to a handful of requests per site per run,
  set explicit hop/page budgets, never loop on failures, and stop when you hit a
  wall or a rate limit. Respect the site's terms and robots rules.
- **Practice only where invited.** For logins use sites meant for testing and
  only the demo credentials they publish. Never guess passwords, never repeat
  failing logins (lockouts are real), never register accounts on someone else's
  service for a test.
- **Do not evade protection.** A bot wall or CAPTCHA means switching to an
  interactive capture with a person, not rotating agents or spoofing.
- **HARs are secrets.** They hold cookies, passwords and bodies. Keep them out
  of git; commit only small hand-redacted snippets.
- **Do not read the raw HAR into a model.** Use the tools; they are paginated
  and redacted.

## 3. Navigation strategy (`find_click`)

Recipe step: `{"op":"find_click","keywords":[…],"max_hops":4}` (headless
one-shots; see `capture.md`).

What it does each hop: read the settled page, rank links / buttons / postback
targets, stop if a *real* search form is present, otherwise follow the best
candidate. Ranking = your keywords (strong) + generic search words (medium) +
low-weight gateway words ("online services", "records", "portal") taken from
link text only.

Practical guidance:

- Give **domain nouns** as keywords (what the thing you want is *called*), not
  generic words. Generic words ("search", "records") are discounted on purpose
  because they match every site-search box.
- Keep `max_hops` small (3–4). If it has not reached a form by then, inspect
  the hops it took; more hops mostly means more drift.
- Expect landing pages to need **two to three** hops (home → department/service
  → tool), and expect the last one to leave the original host (a separate
  search subdomain is common).
- When a hop's `via` is `goto`, hardly navigated to the link's `href` because
  the element was hidden, covered or opens a new tab. That is normal.
- A result with `reached: true` still deserves a look at `form.fields`: the
  field *names* tell you whether it is the lookup you wanted.

## 4. Traps and pitfalls

### 4.1 Deciding you have arrived (goal detection)

| Trap | Symptom | Status |
|------|---------|--------|
| The site-wide search box counts as "the search form" | `reached` at hop 0 with a field called `q`, `keys`, `search_term`, `cdsSearchText` | **Fixed**: such names are skipped unless a field *name/id* mentions your domain keyword |
| Utility forms count | newsletter (`email`), language selector (`<select>`), translate widget (`sl`,`tl`,`gtrans`), feedback / "report a problem" (honeypot field + textarea) | **Fixed** (email-only, select-only and utility actions are skipped) |
| Nameless inputs satisfy "two fields" | header search with two unnamed `<input>`s | **Fixed** (nameless inputs are not counted) |
| Keyword appears in the form *action* URL | `/search/permits` makes a one-box site search look specific | **Fixed** (only field names/ids vouch) |
| Your keyword is a generic word | keyword `"search"` blesses every search box | **Fixed** (generic keywords are ignored for acceptance) |
| Login forms | password field present | **Fixed** (skipped) |
| Search UI exists only after JavaScript runs | SPA shell, `spa_login_suspected`, 0 forms | **Open**: use `hardly_capture_aria` or an `evaluate` step after load |

### 4.2 Clicking things that are not there

| Trap | Symptom | Status |
|------|---------|--------|
| Hidden mobile / off-canvas trigger ranks first | 8 s click timeout on `#mobile-trigger-search` | **Fixed** (such ids are not candidates; clicks wait 1.5 s for visibility) |
| Link text also exists in a hidden mega-menu | `.first` picks the invisible copy | **Mitigated** (`:visible` match, then `href` fallback) |
| Link in an inactive carousel slide / collapsed menu | click timeout | **Mitigated** (`href` fallback) |
| `target=_blank` opens a tab the crawler is not tracking | page does not change, hop looks wasted | **Mitigated** (navigates to `href` instead) |
| Hover-only menus, iframes, shadow DOM | no candidates on a page that visibly has links | **Open / untested** — not shown to be the cause on any site yet |
| Cookie banner / consent or disclaimer gate covers the page | clicks time out; banner markup seen on several portals | **Open / untested** whether it blocked a click; dismiss it with an explicit recipe step if it does |
| Drift: following generic links after a good hop | "Did you find what you needed?", "Alerts", unrelated service pages | **Mitigated** in the unreleased patch (feedback wording is never a candidate; after hop 1 only links with real evidence qualify) — see §6 |
| Ending on a browser error page after a click | `chrome-error://` URL, zero candidates | **Mitigated** in the same patch (steps back and tries the next candidate) |

### 4.3 The network and the browser

| Trap | Symptom | Status |
|------|---------|--------|
| First navigation fails with `ERR_TOO_MANY_RETRIES` or "interrupted by another navigation" | capture reports a goto error, recipe starts on a blank page | **Fixed**: transient errors are retried (not proxy denials) |
| `ERR_TUNNEL_CONNECTION_FAILED` | host blocked by the environment's egress policy | Permanent: add the host to the allowlist; not retried |
| `ERR_CERT_AUTHORITY_INVALID` when driving Playwright by hand through a TLS-intercepting proxy | blank `chrome-error://` page that *looks* loaded | Use hardly's capture (it ignores TLS errors) or set `ignore_https_errors` yourself |
| `page.content()` during navigation raises "page is navigating and changing the content" | crash on data.gov, Sunbiz, EPO | **Fixed** (settled, retried read) |
| Heavy pages hit the 60 s goto timeout | Telerik / Kendo demo pages | **Open**: raise the timeout per step or capture with `wait_until="load"` selectively |
| Prebuilt Chromium does not match the Playwright version | `doctor` says the binary is missing | Set `HARDLY_BROWSER_EXECUTABLE` |
| Parallel captures share one cache dir | confusing sessions | Give each worker its own `HARDLY_CACHE_DIR` |

### 4.4 Bot protection and throttling

- **A CDN or WAF header is not a wall.** `Server: cloudflare` on a 200 page is
  protection *present*. `hardly wall` now reports `state: present` and creates no
  hit; only a block status / challenge wording / clearance flow is a wall.
  (Earlier versions flagged ordinary pages. **Fixed.**)
- **Plain 403/429 is often just auth or rate limiting.** hardly lists these
  under `status_only` until a named product corroborates.
- **Some sites 403 every automated visit** (we saw this on several large
  municipal and transit portals). Record it, move on, and use an interactive
  capture with a person if the data matters.
- **Captcha widgets** (reCAPTCHA, hCaptcha, Turnstile, Arkose…) are detected,
  never solved. Their official *test* keys on a page you host are the only
  reliable fixtures.
- **Honour `Retry-After` and `X-RateLimit-*`.** `hardly challenges` reports
  them. Back off; do not retry in a tight loop.
- **Digest auth needs the 401's nonce** before the retry; a pre-set header will
  not work. hardly shows the challenge and whether a retry followed, never the
  nonce.

### 4.5 Secrets leaking into your output

We found several real leaks during testing. All are **fixed**, but know where
secrets hide when you add a feature:

- OAuth `code`, `state`, `nonce`, `session_state` in `Location` headers and
  query strings.
- `;jsessionid=…` path parameters inside form actions and links.
- `api_key`, `sid`, `access_token` query parameters (now redacted **at ingest**,
  so `entry`, `curl`, `stub` and `params` never see them).
- Generic key matching: `authenticatorSelection`, `allowCredentials`,
  `Access-Control-Allow-Credentials` are *not* secrets (and were noise).
- Always grep new output for known fake secrets in a test before you ship it.

### 4.6 What a HAR can hide from you

| Trap | Symptom | Status |
|------|---------|--------|
| Bodies stored base64-encoded | `grids` / `content` / `schema` see gibberish | **Fixed** (textual types are decoded at ingest) |
| Previews are capped (HTML 64 KB, JSON 8 KB) | grid library marker sits at char 400 000 | **Mitigated** (grid signals are computed on the full body at ingest) |
| Whole-document "looks like base64/hex" | every page tagged as a token | **Fixed** (shapes come from token-like JSON keys and bare-token bodies) |
| Padded base64 (`…=`) never matched | real tokens missed | **Fixed** |
| Entries with status `-1`/`0` | aborted XHRs, capture stopped early, duplicates of finished requests | **Mitigated**: counted in `aborted_entries`; always `wait` before stopping a capture |
| Stale cache from an older hardly | old, less-redacted data keeps appearing | **Fixed** (`INDEX_VERSION` forces a rebuild) |
| `preferred_host` is a beacon / CDN | `brief` reports no credentials | **Fixed** for common beacon hosts; **still check** `hardly hosts` yourself |
| Entry ids are 0-based | off-by-one when pairing output with a viewer | Know it |

### 4.7 Logins and sessions

- A **GET page that contains a password input is the login *page***; only the
  POST is the submit. hardly labels them `login_page` / `login_submit`.
- **A 200 HTML response to a credential POST is often a failed login redisplayed.**
  A success is usually a 3xx to a different path. `outcome` shows which.
- **CSRF cookies are not the session.** `csrftoken` guards forms; the session is
  the HttpOnly cookie set by or after the credential POST.
- **Hidden-field tokens** can use *name indirection*
  (`x.token.name = token` + `token = …`); read the first field to learn the
  second's name.
- **Echo endpoints** (`/bearer`) return the token you sent; they are not token
  issuers.
- **Profile endpoints echo `password`** in their JSON; that is not a login.
- **SPA logins** (client-rendered, JSON POST, token in storage) have no `<form>`
  in the HTML — hardly says so (`spa_login_suspected`); capture after render.
- **OIDC:** the callback is a 3xx whose `Location` carries `code`; PKCE's
  `code_verifier` is in the token POST body, not the URL.
- **WebAuthn / passkeys** need a real or virtual authenticator; hardly only
  describes the ceremony (`webauthn`).

### 4.8 Grids, paging and data conventions

- A grid library on the page does not mean the data is in the HTML. Check
  `grids`: **server-side** styles (`draw/start/length`, `$top/$skip`,
  `page/pageSize`, `resultOffset`) mean you must replay the paging parameters.
- **JSON served as `text/html`** is common (DataTables `server_processing.php`);
  hardly now sniffs the body first.
- **ASP.NET WebForms:** every step must echo `__VIEWSTATE`,
  `__EVENTVALIDATION`, etc. from the previous response; pagers either use
  `Page$N` arguments or an empty argument with the control id as target
  (Telerik-style). **Untested:** partial (UpdatePanel/MicrosoftAjax) responses
  and delta-encoded view state.
- `data-*` attributes often carry the real config (endpoint URLs, page size,
  embedded JSON); use `data-attrs`, not only the network tab.
- OData / JSON:API / HAL / Spring / DRF / Relay / ArcGIS envelopes tell you where
  rows and totals live and how to get the next page.

### 4.9 Crawl-shape hazards (general)

Not all observed on our targets; these are the usual ways a crawl blows up, so
budget for them up front:

- **URL explosion:** faceted filters, calendars, "sort by", session ids in paths
  or queries. De-duplicate by `path_template`, strip session ids, cap pages per
  template.
- **Infinite or very deep pagination:** stop on a repeated page, an empty page,
  or a fixed ceiling; prefer asking for the total first.
- **POST-only search:** you cannot revisit by URL; keep the recipe, not a link.
- **Stateful flows:** disclaimer → search → results → detail often needs the
  same session; do not parallelise within one session.
- **Soft errors:** a 200 with an error message, or a redirect to the home page.
  Compare content kind and size, not just status.
- **Time-dependent tokens:** nonces and view state expire; a replayed stub fails
  after minutes.

## 5. Per-site checklist

Before: environment ready (`hardly capture doctor`), keywords chosen, budget set
(hops, pages), a per-run `HARDLY_CACHE_DIR`, and a place **outside the repo**
for the HAR.

During: `brief` → `wall` → navigate → `forms` / `grids` / `data-attrs` →
`credentials` → `correlate`. After every capture check `coverage` and
`aborted_entries`.

Exit criteria (any one): reached a form or API you can describe; a wall or
challenge appeared (switch to interactive or stop); budget spent; the same page
twice.

Record in your own repo: the recipe, the redacted fixtures, the endpoint and
auth notes, and the date you verified them.

## 6. Status of the navigation hardening

First live sweep (21 portal landing pages, before the fixes): 3 produced a
result, and none of those got there by navigating. Most "reached" results were
goal-detector false positives (site-search boxes, newsletter, translate and
feedback forms); the rest failed on hidden elements, navigation races, or bot
walls.

Re-sweep after the goal-detector, visibility and retry fixes (partial, 11 of
17 sites when this was written): Delaware reached its real entity-search form
(three named fields); the Library of Congress reached its catalog search; a
national patent and trademark office's trademark-search page was reached by link;
the others still
wandered after a good first hop or landed on browser error pages. The
follow-up patch (feedback wording never a candidate, evidence floor after hop 1,
step back from `chrome-error://`, keyword vouching by field name only) was
prepared but not yet measured. **Re-run the sweep before trusting these
numbers.**

## 7. Open items

- Hover menus, iframes, shadow DOM: add handling once a real site shows the need.
- Consent / cookie / disclaimer banner dismissal as an explicit recipe helper.
- A per-step timeout override and `wait_until="load"` for heavy pages.
- `find_click` in the live-session recipe runner (today: headless one-shots only).
- Partial-response ASP.NET AJAX handling in `stub`.
- Remaining minor: `field_count` counts unnamed submit buttons; xpaths on pages
  with two `<html>` elements show `/html[1]/html[1]`.
- Re-run the full navigation sweep and fold the numbers into §6.
