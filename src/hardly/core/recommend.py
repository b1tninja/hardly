"""Suggest next hardly tools from a short goal string."""

from __future__ import annotations

from typing import Any

_RULES: tuple[tuple[tuple[str, ...], list[str], str], ...] = (
    (
        ("portal", "guest", "county", "acclaim", "recorder", "search form"),
        ["hardly_brief", "hardly_forms", "hardly_correlate", "hardly_stub"],
        "Start with a portal brief, then forms/CSRF, then a client sketch.",
    ),
    (
        ("csrf", "viewstate", "token", "nonce", "session cookie", "correlate"),
        ["hardly_correlate", "hardly_trace", "hardly_cookies", "hardly_stub"],
        "Find reused dynamic values, then stub with placeholders.",
    ),
    (
        ("cookie", "set-cookie", "jar"),
        ["hardly_cookies", "hardly_correlate", "hardly_auth"],
        "Cookie name timeline, then correlate session reuse.",
    ),
    (
        ("login", "auth", "mfa", "2fa", "oauth", "password"),
        ["hardly_auth", "hardly_flow", "hardly_secrets", "hardly_compare_entries"],
        "Auth heuristics, then flow and pre/post login compare.",
    ),
    (
        ("detail", "document", "xhr", "ajax", "click"),
        ["hardly_routes", "hardly_around", "hardly_tree", "hardly_ui"],
        "Mine JS routes, initiator children, then time-neighbors.",
    ),
    (
        ("initiator", "dependency", "tree", "children", "parent"),
        ["hardly_tree", "hardly_around", "hardly_story"],
        "Initiator parent/children from Chrome _initiator.",
    ),
    (
        ("graphql", "gql", "mutation", "apollo"),
        ["hardly_graphql", "hardly_schema", "hardly_entry"],
        "List GraphQL operations, then schema the variables/response.",
    ),
    (
        (
            "jsonl",
            "jsonp",
            "csv",
            "table",
            "html table",
            "pdf",
            "docx",
            "mime",
            "content type",
            "what format",
            "payload kind",
        ),
        ["hardly_content", "hardly_entry", "hardly_schema", "hardly_forms"],
        "Classify response kinds (json/jsonl/csv/tables/docs/media), then drill.",
    ),
    (
        (
            "dom",
            "outline",
            "markdown outline",
            "parse html",
            "parse xml",
            "accessibility",
            "aria snapshot",
            "document structure",
        ),
        ["hardly_outline", "hardly_capture_aria", "hardly_ui", "hardly_forms"],
        "Offline outline from HAR bodies; live ARIA YAML via capture_aria.",
    ),
    (
        ("static", "dynamic", "param", "which fields"),
        ["hardly_params", "hardly_correlate", "hardly_schema"],
        "Classify params across samples of one endpoint template.",
    ),
    (
        ("capture", "record", "playwright", "browser", "recipe", "aria ref"),
        [
            "hardly_capture_doctor",
            "hardly_capture_start",
            "hardly_capture_aria",
            "hardly_capture_click",
            "hardly_capture_recipe",
        ],
        "Doctor → start (channel=chrome) → aria → click/fill with ref → stop.",
    ),
    (
        ("akamai", "cloudflare", "bot wall", "captcha", "403", "blocked"),
        ["hardly_wall", "hardly_capture_start", "hardly_issues"],
        "Wall detected — use headed channel=chrome, not plain HTTP.",
    ),
    (
        ("slow", "latency", "timeout", "waterfall", "performance"),
        ["hardly_slow", "hardly_issues", "hardly_tree"],
        "List slowest requests, then inspect entry/tree.",
    ),
    (
        ("duplicate", "polling", "repeat", "retry"),
        ["hardly_duplicates", "hardly_params", "hardly_compare_entries"],
        "Find repeated templates, then compare samples.",
    ),
    (
        ("page load", "pageref", "pages"),
        ["hardly_pages", "hardly_tree", "hardly_story"],
        "Group by browser pageref, then tree the document.",
    ),
    (
        ("empty body", "missing body", "coverage", "size=-1", "truncated"),
        ["hardly_issues", "hardly_coverage", "hardly_capture_start"],
        "Check issues/coverage, then re-capture with body backfill.",
    ),
    (
        ("diff", "compare", "second capture", "new endpoint"),
        ["hardly_diff", "hardly_compare_entries", "hardly_endpoints"],
        "Diff two sessions, or two entries for the same call.",
    ),
    (
        ("openapi", "swagger", "postman", "export", "document"),
        [
            "hardly_export_openapi",
            "hardly_export_postman",
            "hardly_export_md",
            "hardly_endpoints",
        ],
        "Export a contract, then fill gaps with entry/schema.",
    ),
    (
        ("probe", "replay", "live"),
        ["hardly_curl", "hardly_probe", "hardly_correlate"],
        "curl first (redacted), probe only with confirm=true.",
    ),
    (
        ("secret", "credential", "leak", "password field"),
        ["hardly_secrets", "hardly_trace", "hardly_issues"],
        "Locate sensitive names; never commit the HAR.",
    ),
    (
        ("redirect", "302", "301", "location"),
        ["hardly_redirects", "hardly_around", "hardly_story"],
        "List 3xx hops, then follow matched entry ids.",
    ),
)


def recommend_tools(goal: str) -> dict[str, Any]:
    """Return ranked tool suggestions for a free-text goal."""
    text = (goal or "").strip().lower()
    if not text:
        return {
            "goal": goal,
            "suggestions": [
                {
                    "tools": [
                        "hardly_help",
                        "hardly_capabilities",
                        "hardly_open",
                        "hardly_brief",
                    ],
                    "reason": (
                        "Browse the catalog, open a HAR, then brief for portals "
                        "or endpoints for APIs."
                    ),
                }
            ],
        }

    scored: list[tuple[int, list[str], str]] = []
    for keywords, tools, reason in _RULES:
        score = sum(1 for kw in keywords if kw in text)
        if score:
            scored.append((score, tools, reason))
    scored.sort(key=lambda x: -x[0])

    if not scored:
        return {
            "goal": goal,
            "suggestions": [
                {
                    "tools": [
                        "hardly_summary",
                        "hardly_endpoints",
                        "hardly_brief",
                        "hardly_search",
                    ],
                    "reason": (
                        "No specific match — summarize, list endpoints, "
                        "or brief if it looks like an HTML portal."
                    ),
                }
            ],
            "next": "Pass a more specific goal (csrf, capture, detail url, export).",
        }

    return {
        "goal": goal,
        "suggestions": [
            {"tools": tools, "reason": reason, "score": score}
            for score, tools, reason in scored[:5]
        ],
        "next": "Call the first tool with the open session_id.",
    }
