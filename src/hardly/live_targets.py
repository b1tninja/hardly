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
    LiveTarget(
        id="wyobiz",
        url="https://wyobiz.wy.gov/Business/FilingSearch.aspx",
        tech=("aspnet", "viewstate", "webforms"),
        description="Wyoming business search — classic ASP.NET WebForms VIEWSTATE",
        wait_seconds=4.0,
        expect_host="wyobiz",
        min_entries=2,
        expect_aspnet=True,
        expect_forms=True,
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
            "soft": t.soft,
            "recipe_ops": [str(s.get("op")) for s in t.recipe if isinstance(s, dict)],
        }
        for t in TARGETS
    ]
