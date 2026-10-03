"""Public websites for headless live soak / fixture generation.

These are intentional demos (or stable public portals) that exercise distinct
stacks — ASP.NET VIEWSTATE, HTML forms, login pages, SPAs, GraphQL UIs —
without committing private HAR captures. Live soak captures a HAR on the fly
with ``capture_headless`` / ``discover_apis``, then asserts analysis signals.
"""

from __future__ import annotations

from dataclasses import dataclass, field
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
    soft: bool = False  # soft failures do not fail the soak exit code


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
        id="graphqlzero",
        url="https://graphqlzero.almansi.me/",
        tech=("graphql", "spa"),
        description="GraphQLZero GraphiQL-style UI",
        wait_seconds=4.0,
        recipe=({"op": "wait", "ms": 1500},),
        expect_host="almansi",
        min_entries=1,
        expect_graphql=True,
        soft=True,  # UI may not issue GraphQL until the person runs a query
    ),
    LiveTarget(
        id="petstore",
        url="https://petstore.swagger.io/",
        tech=("openapi", "swagger"),
        description="Swagger Petstore UI (often loads OpenAPI JSON)",
        wait_seconds=4.0,
        recipe=({"op": "wait", "ms": 2000},),
        expect_host="swagger",
        min_entries=2,
        soft=True,
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
            "soft": t.soft,
        }
        for t in TARGETS
    ]
