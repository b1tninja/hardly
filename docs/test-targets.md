# Candidate authentication test targets

> Purpose: Research notes on candidate public authentication test targets for the soak catalog.

Research notes for growing hardly's soak catalog (`hardly.live_targets`) and
unit-test fixtures. Everything here is a *generic technology demo*; hardly
never encodes site-specific logic for any of them.

> Before adding a target: (1) read the owner's stated testing policy,
> (2) run `hardly browser capture-discover <url> --analyze --confirm` (or
> `python -m hardly.soak_live --ids …`) and confirm the signals below,
> (3) keep it `soft=True` in the catalog until it has proven stable.
> Never script against a service that requires an account you don't own or
> that forbids automation. Demo credentials are not recorded here; use the
> owner's published ones from their page.

## Verified in catalog (`hardly.live_targets`)

These are live soak ids (hard unless noted). Signals are what the soak asserts.

| Id | Pattern | Asserts |
|----|---------|---------|
| `datatables-ajax` | DataTables AJAX grid + JSON | `expect_table`, `expect_json` |
| `internet-tables` | Static HTML data tables | `expect_table` |
| `scrape-forms` | Form search → results table | `expect_forms`, `expect_table`, recipe fill/click |
| `quotes-login` | Form login → session cookie | `expect_password`, `expect_session_cookie`, recipe |
| `practice-login` | Form login → redirect path | `expect_path_contains`, recipe |
| `dummyjson` | REST JSON catalog | `expect_json` |
| `datatables-objects` | DataTables object-row AJAX | `expect_table`, `expect_json` |
| `scrape-ajax` | jQuery AJAX → JSON → table | `expect_table`, `expect_json` |
| `reqres-login` | JSON login → token body | `expect_json`, recipe `fetch` |
| `escuela-auth` | JSON login → access + refresh | `expect_json`, recipe `fetch` |
| `saucedemo-login` | SPA login (JS-hydrated) | `soft=True` (preferred_host can drift to telemetry) |
| `the-internet-login` | Password form (no submit) | `expect_forms`, `expect_password` |
| `local-webforms` / `local-token-login` | Loopback VIEWSTATE / token | offline deterministic |

## Next candidates (fanout research, not yet catalogued)

Verified reachable (2026-10-10) but not yet soaked into `TARGETS`:

| Candidate | Pattern | Notes |
|-----------|---------|-------|
| DataTables `server_side/simple.html` | server-side XHR draws | Distinct from ajax/objects; start `soft=True` |
| Tabulator AJAX example | click → `/exampledata/ajax.json` | Needs button-click recipe |
| `spa1.scrape.center` | SPA REST movie grid | Paginate once for extra entries |
| `books.toscrape.com` product detail | `table.table-striped` | Scraping sandbox |
| ParaBank (`john`/`demo`) | form → `JSESSIONID` | Strong form_session next |
| Expand Testing `/login` | form → `/secure` | Soft until cookie jar confirmed |
| `restful-booker` `/auth` | opaque token (not JWT) | Host up; wire recipe carefully |
| `httpbingo.org` / `postman-echo.com` | JSON echo + auth challenges | Light hard GET soaks |
| `quotes.toscrape.com/search.aspx` | ASP.NET ViewState filter | Needs fill recipe; no table on bare load |
| Duende `demo.duendesoftware.com` | OIDC multi-hop | Soft; browser recipe required |
| `testaspnet.vulnweb.com` | ASP.NET WebForms | **HTTP only** (HTTPS times out) |

## Priority shortlist (still research)

| Target | Pattern it would exercise | What hardly should report |
|--------|---------------------------|---------------------------|
| `dummyjson.com` `/auth/login`, `/auth/me`, `/auth/refresh` | JSON login → JWT access + refresh in body, Bearer reuse | `token_responses`, JWT shape, `login_flow`, trace-value (response JSON → `Authorization`) |
| `httpbingo.org` / `httpbin.org` `/basic-auth`, `/bearer`, `/digest-auth`, `/cookies` | `WWW-Authenticate` Basic/Bearer/Digest challenges, Digest retry, cookie flags | challenge scheme per 401, `auth_headers`, cookie flags |
| `postman-echo.com` `/basic-auth`, `/digest-auth`, `/auth/hawk`, `/oauth1` | Signed-header schemes (OAuth1 HMAC, Hawk) | custom `Authorization` scheme names and parameter names (never values) |
| `api.escuelajs.co/api/v1` `/auth/login`, `/auth/refresh-token`, `/graphql` | Access/refresh pair, GraphQL beside REST auth | refresh hop, GraphQL operations on an authed endpoint |
| `restful-booker.herokuapp.com` `/auth` | JSON login → token replayed as a **cookie** and as Basic | token-in-cookie correlation; 403 (not 401) failures |
| `testaspnet.vulnweb.com` (policy: intentionally scannable, per its owner) | ASP.NET WebForms VIEWSTATE/EVENTVALIDATION login | webforms fields, session cookie flags |
| `testasp.vulnweb.com`, `testphp.vulnweb.com` | Classic ASP / PHP session cookies, forms without CSRF | `ASPSESSIONID*` / `PHPSESSID` flags, "no anti-forgery" negative case |
| `demo.duendesoftware.com` (OIDC) | Auth code + PKCE, antiforgery login form, JWT tokens | authorize→callback→token stitch, PKCE, state/nonce, token shapes |
| `samltest.id` | SAML Redirect/POST bindings | `SAMLRequest`/`SAMLResponse`/`RelayState` presence (not yet detected — see backlog) |
| Cloudflare Turnstile / reCAPTCHA / hCaptcha **official test keys** on a locally hosted page | Captcha widgets that always pass | widget and response-field detection (not yet detected) |

Form-login practice sites worth a look (each unverified): ParaBank (Java,
`JSESSIONID`, registration + reset link), the-internet.herokuapp.com
(`/login`, `/basic_auth`), OrangeHRM public demo (hidden CSRF token), a Rails
travel demo with `authenticity_token` + remember-me, automationexercise
(Django-style `csrfmiddlewaretoken`), SauceDemo (SPA login with no form POST —
a useful *negative* case for form detection), OpenCart demo (`customer_token`
in the query string).

## Do not use against production services

- OWASP Juice Shop's public instance (its README discourages using it),
  PortSwigger Academy labs (account-bound), and anything that needs a real
  Google/GitHub login or a real MFA device.
- Run DVWA, WebGoat, bWAPP, Juice Shop, Keycloak, Ory/Zitadel/Authentik and
  similar **locally in Docker** if you want those stacks; that is stable and
  needs no network allowlist entry.

## Gaps this research exposed (backlog)

Patterns no public target covers well, so they should be built as synthetic
pages in `hardly.local_site` (loopback, offline, deterministic):

1. `WWW-Authenticate` challenge parsing (Basic / Bearer / Digest / Negotiate)
   and the retry with an `Authorization` response.
2. Bearer JSON login with access + refresh tokens and an expiry hint.
3. OAuth/OIDC redirect chain with PKCE (a tiny fake IdP: authorize, token).
4. SAML POST binding (auto-submitting form with `SAMLResponse`/`RelayState`).
5. Captcha / Turnstile widget markup and response field names.
6. Double-submit CSRF for JSON APIs (`XSRF-TOKEN` cookie → `X-XSRF-TOKEN`
   header) and Django/Rails-style form tokens.
7. Login throttling / lockout messages (429 + `Retry-After`).
8. Signed-request headers (HMAC `Authorization` params, `Date` + signature).

Items 1, 5 and 7 now have detectors (`hardly_gate_bot_protection`) and loopback pages
(`/private`, `/captcha`, `/limited` in `hardly.local_site`). Items 2, 3, 4, 6 and
8 are still open.
