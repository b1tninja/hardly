"""Public websites for headless live soak / fixture generation.

These are intentional demos (or stable public portals) that exercise distinct
stacks — ASP.NET VIEWSTATE, HTML forms, login pages, SPAs, GraphQL, JSON APIs —
without committing private HAR captures. Live soak captures a HAR on the fly
with ``capture_headless``, then asserts analysis signals.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class LiveTarget:
    """One public URL and the analysis signals it should produce."""

    id: str
    url: str
    tech: tuple[str, ...]
    description: str
    wait_seconds: float = 3.0
    recipe: tuple[dict[str, Any], ...] = ()
    expect_host: str | None = None
    min_entries: int = 1
    expect_aspnet: bool = False
    expect_forms: bool = False
    expect_password: bool = False
    expect_graphql: bool = False
    expect_json: bool = False
    expect_table: bool = False
    # After a login recipe, at least one path should contain this substring.
    expect_path_contains: str | None = None
    # After login / session work, at least one session-ish cookie name.
    expect_session_cookie: bool = False
    soft: bool = False  # soft failures do not fail the soak exit code


# GraphQL POST fired in-page so the HAR records a real operation (no GraphiQL click).
_COUNTRIES_GQL = {
    "op": "fetch",
    "url": "https://countries.trevorblades.com/",
    "method": "POST",
    "headers": {"content-type": "application/json"},
    "body": {"query": '{ __typename country(code:"US"){ name continent { name } } }'},
}

_GQLZERO_GQL = {
    "op": "fetch",
    "url": "https://graphqlzero.almansi.me/api",
    "method": "POST",
    "headers": {"content-type": "application/json"},
    "body": {"query": "{ __typename }"},
}

_SAUCE_LOGIN = (
    {"op": "fill", "css": "#user-name", "value": "standard_user"},
    {"op": "fill", "css": "#password", "value": "secret_sauce", "allow_login": True},
    {"op": "click", "css": "#login-button"},
    {"op": "wait", "ms": 2000},
)

_PRACTICE_LOGIN = (
    {"op": "fill", "css": "#username", "value": "student"},
    {"op": "fill", "css": "#password", "value": "Password123", "allow_login": True},
    {"op": "click", "css": "#submit"},
    {"op": "wait", "ms": 2000},
)

_QUOTES_LOGIN = (
    {"op": "fill", "css": "#username", "value": "admin"},
    {"op": "fill", "css": "#password", "value": "admin", "allow_login": True},
    {"op": "click", "css": 'input[type="submit"]'},
    {"op": "wait", "ms": 1500},
)

_SCRAPE_TEAM_SEARCH = (
    {"op": "fill", "css": "#q", "value": "Boston"},
    {"op": "click", "css": 'input[type="submit"]'},
    {"op": "wait", "ms": 1500},
)

_REQRES_LOGIN = {
    "op": "fetch",
    "url": "https://reqres.in/api/login",
    "method": "POST",
    "headers": {"content-type": "application/json"},
    # Published demo credentials from https://reqres.in/
    "body": {"email": "eve.holt@reqres.in", "password": "cityslicka"},
}

_ESCUELA_LOGIN = {
    "op": "fetch",
    "url": "https://api.escuelajs.co/api/v1/auth/login",
    "method": "POST",
    "headers": {"content-type": "application/json"},
    # Published demo credentials from the Fake Store API docs.
    "body": {"email": "john@mail.com", "password": "changeme"},
}

_BOOKER_AUTH = {
    "op": "fetch",
    "url": "https://restful-booker.herokuapp.com/auth",
    "method": "POST",
    "headers": {"content-type": "application/json"},
    # Published demo credentials from restful-booker docs.
    "body": {"username": "admin", "password": "password123"},
}

_PARABANK_LOGIN = (
    {"op": "fill", "css": "input[name='username']", "value": "john"},
    {
        "op": "fill",
        "css": "input[name='password']",
        "value": "demo",
        "allow_login": True,
    },
    {"op": "click", "css": "input[type='submit']"},
    {"op": "wait", "ms": 2500},
)

_EXPAND_LOGIN = (
    {"op": "fill", "css": "#username", "value": "practice"},
    {
        "op": "fill",
        "css": "#password",
        "value": "SuperSecretPassword!",
        "allow_login": True,
    },
    # Generic ``button`` can miss the submit control; ``button.btn`` posts /authenticate.
    {"op": "click", "css": "button.btn"},
    {"op": "wait", "ms": 2000},
)

# Published Postman Echo demo Basic creds (postman:password).
_POSTMAN_BASIC = {
    "op": "fetch",
    "url": "https://postman-echo.com/basic-auth",
    "method": "GET",
    "headers": {"authorization": "Basic cG9zdG1hbjpwYXNzd29yZA=="},
}

_ORANGEHRM_LOGIN = (
    {"op": "fill", "css": "input[name='username']", "value": "Admin"},
    {
        "op": "fill",
        "css": "input[name='password']",
        "value": "admin123",
        "allow_login": True,
    },
    {"op": "click", "css": "button[type='submit']"},
    {"op": "wait", "ms": 4000},
)

_DUENDE_LOGIN = (
    {"op": "fill", "css": "#Input_Username", "value": "alice"},
    {
        "op": "fill",
        "css": "#Input_Password",
        "value": "alice",
        "allow_login": True,
    },
    {"op": "click", "css": "button.btn-primary"},
    {"op": "wait", "ms": 3000},
)


TARGETS: tuple[LiveTarget, ...] = (
    LiveTarget(
        id="example",
        url="https://example.com/",
        tech=("static", "html"),
        description="Minimal static HTML baseline",
        wait_seconds=1.5,
        expect_host="example.com",
        min_entries=1,
    ),
    # ``local:`` targets are served by hardly.local_site on loopback — synthetic
    # pages, no network, no real website.
    LiveTarget(
        id="local-webforms",
        url="local:/directory.aspx",
        tech=("aspnet", "viewstate", "webforms"),
        description="Synthetic ASP.NET WebForms page (VIEWSTATE, __doPostBack)",
        wait_seconds=1.0,
        expect_host="127.0.0.1",
        min_entries=1,
        expect_aspnet=True,
        expect_forms=True,
    ),
    LiveTarget(
        id="local-token-login",
        url="local:/login",
        tech=("html_form", "login", "named_token"),
        description="Synthetic login with token-name indirection and session cookie",
        wait_seconds=1.0,
        expect_host="127.0.0.1",
        min_entries=1,
        expect_forms=True,
        expect_password=True,
    ),
    LiveTarget(
        id="httpbin-form",
        url="https://httpbin.org/forms/post",
        tech=("html_form",),
        description="httpbin HTML form POST demo",
        wait_seconds=2.5,
        expect_host="httpbin",
        min_entries=1,
        expect_forms=True,
    ),
    LiveTarget(
        id="httpbin-json",
        url="https://httpbin.org/json",
        tech=("json", "rest"),
        description="httpbin JSON response body",
        wait_seconds=2.0,
        expect_host="httpbin",
        min_entries=1,
        expect_json=True,
    ),
    LiveTarget(
        id="jsonplaceholder",
        url="https://jsonplaceholder.typicode.com/users",
        tech=("json", "rest"),
        description="JSONPlaceholder REST users list",
        wait_seconds=2.0,
        expect_host="typicode",
        min_entries=1,
        expect_json=True,
    ),
    LiveTarget(
        id="dummyjson",
        url="https://dummyjson.com/products",
        tech=("json", "rest", "catalog"),
        description="DummyJSON products catalog API",
        wait_seconds=2.0,
        expect_host="dummyjson",
        min_entries=1,
        expect_json=True,
    ),
    LiveTarget(
        id="reqres-login",
        # API login via in-page fetch so the HAR records the token JSON.
        url="https://reqres.in/",
        tech=("login", "json", "token"),
        description="ReqRes JSON login (eve.holt@reqres.in) — recipe fetch POST",
        wait_seconds=1.5,
        recipe=(_REQRES_LOGIN, {"op": "wait", "ms": 500}),
        expect_host="reqres",
        min_entries=2,
        expect_json=True,
    ),
    LiveTarget(
        id="escuela-auth",
        # CORS-open Fake Store API; bootstrap from example.com like countries-gql.
        url="https://example.com/",
        tech=("login", "json", "jwt", "refresh"),
        description="EscuelaJS auth login — access + refresh tokens via recipe fetch",
        wait_seconds=1.5,
        recipe=(_ESCUELA_LOGIN, {"op": "wait", "ms": 500}),
        expect_host="example.com",
        min_entries=2,
        expect_json=True,
    ),
    LiveTarget(
        id="booker-auth",
        # Same-origin fetch (CORS blocks bootstrap-from-example.com).
        url="https://restful-booker.herokuapp.com/",
        tech=("login", "json", "token"),
        description="Restful Booker /auth — opaque token JSON via recipe fetch",
        wait_seconds=1.5,
        recipe=(_BOOKER_AUTH, {"op": "wait", "ms": 500}),
        expect_host="herokuapp",
        min_entries=2,
        expect_json=True,
    ),
    LiveTarget(
        id="parabank-login",
        url="https://parabank.parasoft.com/parabank/index.htm",
        tech=("login", "html_form", "password", "session"),
        description="ParaBank form login (john/demo) → overview + JSESSIONID",
        wait_seconds=2.0,
        recipe=_PARABANK_LOGIN,
        expect_host="parasoft",
        min_entries=2,
        expect_forms=True,
        expect_password=True,
        expect_path_contains="overview",
        expect_session_cookie=True,
    ),
    LiveTarget(
        id="datatables-ajax",
        url="https://datatables.net/examples/data_sources/ajax.html",
        tech=("datatables", "ajax", "table", "json"),
        description="DataTables AJAX-sourced grid (loads arrays.txt JSON)",
        wait_seconds=4.0,
        expect_host="datatables",
        min_entries=3,
        expect_table=True,
        expect_json=True,
    ),
    LiveTarget(
        id="datatables-objects",
        url="https://datatables.net/examples/ajax/objects.html",
        tech=("datatables", "ajax", "table", "json"),
        description="DataTables AJAX grid with object-shaped JSON rows",
        wait_seconds=4.0,
        expect_host="datatables",
        min_entries=3,
        expect_table=True,
        expect_json=True,
    ),
    LiveTarget(
        id="datatables-ssp",
        url="https://datatables.net/examples/server_side/simple.html",
        tech=("datatables", "ajax", "server_side", "table", "json"),
        description="DataTables server-side processing (draw/start/length XHR)",
        wait_seconds=4.0,
        expect_host="datatables",
        min_entries=3,
        expect_table=True,
        expect_json=True,
    ),
    LiveTarget(
        id="scrape-ajax",
        url="https://www.scrapethissite.com/pages/ajax-javascript/#2015",
        tech=("ajax", "table", "json"),
        description="Scrape This Site Oscar wins — jQuery AJAX year → JSON → table",
        wait_seconds=2.0,
        recipe=({"op": "wait", "ms": 2500},),
        expect_host="scrapethissite",
        min_entries=2,
        expect_table=True,
        expect_json=True,
    ),
    LiveTarget(
        id="books-detail",
        url="https://books.toscrape.com/catalogue/a-light-in-the-attic_1000/index.html",
        tech=("html_table",),
        description="books.toscrape product detail with striped HTML table",
        wait_seconds=2.5,
        expect_host="toscrape",
        min_entries=1,
        expect_table=True,
    ),
    LiveTarget(
        id="tabulator-ajax",
        # Div/canvas grid — expect_json only (not expect_table). Soft until the
        # AJAX click recipe stays stable across Tabulator example-page layout.
        url="https://www.tabulator.info/examples/6.x/#ajax",
        tech=("tabulator", "ajax", "json"),
        description="Tabulator AJAX data-loading example (JSON in HAR)",
        wait_seconds=2.5,
        recipe=(
            {"op": "wait", "ms": 1000},
            {
                "op": "click",
                "css": "button:has-text('Load Data via AJAX')",
            },
            {"op": "wait", "ms": 2000},
        ),
        expect_host="tabulator",
        min_entries=3,
        expect_json=True,
        soft=True,
    ),
    LiveTarget(
        id="kendo-remote-grid",
        # Kendo + OData JSON; no HTML <table> for expect_table.
        url="https://demos.telerik.com/kendo-ui/grid/remote-data-binding",
        tech=("kendo", "ajax", "json", "odata"),
        description="Kendo UI remote DataSource grid (JSON XHR; no static HTML table)",
        wait_seconds=4.0,
        expect_host="telerik",
        min_entries=3,
        expect_json=True,
        soft=True,
    ),
    LiveTarget(
        id="spa1-movies",
        url="https://spa1.scrape.center/",
        tech=("spa", "rest", "json"),
        description="spa1.scrape.center movie list SPA (/api/movie/ JSON)",
        wait_seconds=3.0,
        recipe=({"op": "wait", "ms": 2000},),
        expect_host="scrape.center",
        min_entries=2,
        expect_json=True,
        soft=True,
    ),
    LiveTarget(
        id="quotes-viewstate",
        url="https://quotes.toscrape.com/search.aspx",
        tech=("aspnet", "viewstate", "html_form"),
        description="quotes.toscrape ASP.NET ViewState search page",
        wait_seconds=2.5,
        expect_host="toscrape",
        min_entries=1,
        expect_aspnet=True,
        expect_forms=True,
    ),
    LiveTarget(
        id="testaspnet-webforms",
        # HTTPS times out; intentional vulnweb demo speaks HTTP.
        url="http://testaspnet.vulnweb.com/",
        tech=("aspnet", "viewstate", "html_table"),
        description="Acunetix testaspnet — live VIEWSTATE WebForms + HTML table",
        wait_seconds=3.0,
        expect_host="vulnweb",
        min_entries=1,
        expect_aspnet=True,
        expect_forms=True,
        expect_table=True,
    ),
    LiveTarget(
        id="httpbingo",
        url="https://httpbingo.org/get",
        tech=("json", "http"),
        description="httpbingo JSON echo GET",
        wait_seconds=2.0,
        expect_host="httpbingo",
        min_entries=1,
        expect_json=True,
    ),
    LiveTarget(
        # Bootstrap on /get (root redirects to postman.com SPA). Same-origin
        # fetch then hits /basic-auth with published demo Basic credentials.
        id="postman-echo",
        url="https://postman-echo.com/get",
        tech=("json", "http", "basic_auth"),
        description="Postman Echo JSON GET + recipe Basic-auth hop",
        wait_seconds=1.5,
        recipe=(_POSTMAN_BASIC, {"op": "wait", "ms": 500}),
        expect_host="postman-echo",
        min_entries=2,
        expect_json=True,
    ),
    LiveTarget(
        id="internet-tables",
        url="https://the-internet.herokuapp.com/tables",
        tech=("html_table",),
        description="the-internet sortable HTML data tables",
        wait_seconds=2.0,
        expect_host="herokuapp",
        min_entries=1,
        expect_table=True,
    ),
    LiveTarget(
        id="scrape-forms",
        url="https://www.scrapethissite.com/pages/forms/",
        tech=("lookup", "html_table", "form_search"),
        description="Scrape This Site hockey teams — search form + results table",
        wait_seconds=2.0,
        recipe=_SCRAPE_TEAM_SEARCH,
        expect_host="scrapethissite",
        min_entries=2,
        expect_forms=True,
        expect_table=True,
    ),
    LiveTarget(
        id="the-internet-login",
        url="https://the-internet.herokuapp.com/login",
        tech=("login", "html_form", "password"),
        description="Heroku the-internet login form (password field)",
        wait_seconds=2.5,
        expect_host="herokuapp",
        min_entries=1,
        expect_forms=True,
        expect_password=True,
    ),
    LiveTarget(
        id="quotes-login",
        url="https://quotes.toscrape.com/login",
        tech=("login", "html_form", "password", "session"),
        description="quotes.toscrape login (admin/admin) → session cookie",
        wait_seconds=1.5,
        recipe=_QUOTES_LOGIN,
        expect_host="toscrape",
        min_entries=2,
        expect_forms=True,
        expect_password=True,
        expect_session_cookie=True,
    ),
    LiveTarget(
        id="practice-login",
        url="https://practicetestautomation.com/practice-test-login/",
        tech=("login", "html_form", "redirect"),
        description="Practice Test Automation login (student/Password123)",
        wait_seconds=2.0,
        recipe=_PRACTICE_LOGIN,
        expect_host="practicetestautomation",
        min_entries=2,
        expect_path_contains="logged-in-successfully",
    ),
    LiveTarget(
        id="expand-login",
        url="https://practice.expandtesting.com/login",
        tech=("login", "html_form", "redirect", "session"),
        description="Expand Testing login (practice/…) → /secure",
        wait_seconds=2.0,
        recipe=_EXPAND_LOGIN,
        expect_host="expandtesting",
        min_entries=2,
        expect_password=True,
        expect_path_contains="secure",
        expect_session_cookie=True,
    ),
    LiveTarget(
        id="orangehrm-login",
        url="https://opensource-demo.orangehrmlive.com/web/index.php/auth/login",
        tech=("login", "spa", "json"),
        description="OrangeHRM demo login (Admin/admin123) → dashboard + API JSON",
        wait_seconds=2.0,
        recipe=_ORANGEHRM_LOGIN,
        expect_host="orangehrmlive",
        min_entries=3,
        expect_password=True,
        expect_path_contains="dashboard",
        expect_json=True,
        soft=True,
    ),
    LiveTarget(
        # Local account login only — not a full OIDC authorize→callback→token stitch.
        id="duende-account-login",
        url="https://demo.duendesoftware.com/Account/Login",
        tech=("login", "html_form", "oidc_idp"),
        description="Duende demo IdP account login (alice/alice); soft local-login soak",
        wait_seconds=2.0,
        recipe=_DUENDE_LOGIN,
        expect_host="duendesoftware",
        min_entries=2,
        expect_password=True,
        soft=True,
    ),
    LiveTarget(
        id="saucedemo-login",
        url="https://www.saucedemo.com/",
        tech=("login", "spa"),
        description="Sauce Demo SPA login recipe (standard_user/secret_sauce); JS-hydrated shell",
        wait_seconds=2.0,
        recipe=_SAUCE_LOGIN,
        expect_host="saucedemo",
        min_entries=2,
        soft=True,
    ),
    LiveTarget(
        id="quotes",
        url="https://quotes.toscrape.com/",
        tech=("html", "pagination"),
        description="quotes.toscrape scrape demo (links + pagination)",
        wait_seconds=2.5,
        expect_host="toscrape",
        min_entries=1,
    ),
    LiveTarget(
        id="todomvc",
        url="https://demo.playwright.dev/todomvc/",
        tech=("spa", "js"),
        description="Playwright TodoMVC SPA demo",
        wait_seconds=3.0,
        expect_host="playwright.dev",
        min_entries=1,
    ),
    LiveTarget(
        id="countries-gql",
        # API root returns 204 and aborts Playwright navigation; bootstrap
        # from example.com then POST via recipe fetch (CORS-open GraphQL).
        url="https://example.com/",
        tech=("graphql",),
        description="Trevorblades countries GraphQL — recipe fetch POST from example.com",
        wait_seconds=1.5,
        recipe=(_COUNTRIES_GQL, {"op": "wait", "ms": 500}),
        expect_host="example.com",
        min_entries=2,
        expect_graphql=True,
    ),
    LiveTarget(
        id="graphqlzero",
        url="https://graphqlzero.almansi.me/",
        tech=("graphql", "spa"),
        description="GraphQLZero — UI load + recipe POST to /api",
        wait_seconds=2.0,
        recipe=(_GQLZERO_GQL, {"op": "wait", "ms": 500}),
        expect_host="almansi",
        min_entries=1,
        expect_graphql=True,
    ),
    LiveTarget(
        id="petstore-openapi",
        url="https://petstore.swagger.io/v2/swagger.json",
        tech=("openapi", "json"),
        description="Swagger Petstore OpenAPI document (raw JSON)",
        wait_seconds=2.0,
        expect_host="swagger",
        min_entries=1,
        expect_json=True,
    ),
)


def list_targets(*, ids: list[str] | None = None) -> list[LiveTarget]:
    """Return catalog entries, optionally filtered by id."""
    if not ids:
        return list(TARGETS)
    wanted = {x.strip().lower() for x in ids if x and x.strip()}
    return [t for t in TARGETS if t.id in wanted]


def target_by_id(target_id: str) -> LiveTarget | None:
    key = (target_id or "").strip().lower()
    for t in TARGETS:
        if t.id == key:
            return t
    return None


def catalog_summary() -> list[dict[str, Any]]:
    """Compact catalog for CLI / MCP help."""
    return [
        {
            "id": t.id,
            "url": t.url,
            "tech": list(t.tech),
            "description": t.description,
            "expect_aspnet": t.expect_aspnet,
            "expect_forms": t.expect_forms,
            "expect_password": t.expect_password,
            "expect_graphql": t.expect_graphql,
            "expect_json": t.expect_json,
            "expect_table": t.expect_table,
            "expect_path_contains": t.expect_path_contains,
            "expect_session_cookie": t.expect_session_cookie,
            "soft": t.soft,
            "recipe_ops": [str(s.get("op")) for s in t.recipe if isinstance(s, dict)],
        }
        for t in TARGETS
    ]
