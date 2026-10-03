"""Suggest next hardly tools from a short goal string."""

from __future__ import annotations

from typing import Any

_RULES: tuple[tuple[tuple[str, ...], list[str], str], ...] = (
    (
        (
            "mode",
            "archive",
            "headless",
            "interactive",
            "which mode",
            "how to start",
        ),
        ["hardly_guide_mode", "hardly_server_status"],
        "Pick archive (HAR file), headless (hardly_browser_capture_discover), or interactive.",
    ),
    (
        ("discover", "auto discover", "no har", "headless", "automate"),
        [
            "hardly_guide_mode",
            "hardly_browser_capture_discover",
            "hardly_server_status",
            "hardly_session_site_brief",
        ],
        "Headless: hardly_browser_capture_discover(url) or hardly_browser_start(headed=false).",
    ),
    (
        (
            "ask user",
            "ask the user",
            "interactive",
            "headed",
            "person click",
            "human",
        ),
        [
            "hardly_guide_mode",
            "hardly_browser_start",
            "hardly_browser_stop",
            "hardly_session_site_brief",
        ],
        "Interactive: start headed chrome, ask the person, then stop + brief.",
    ),
    (
        ("portal", "guest", "search form", "webforms", "viewstate"),
        ["hardly_session_site_brief", "hardly_page_forms", "hardly_session_trace_value", "hardly_client_build"],
        "Start with a portal brief, then forms/CSRF, then a client sketch.",
    ),
    (
        ("csrf", "viewstate", "token", "nonce", "session cookie", "correlate"),
        ["hardly_session_trace_value", "hardly_auth_report", "hardly_client_build"],
        "Find reused dynamic values, then stub with placeholders.",
    ),
    (
        ("cookie", "set-cookie", "jar"),
        ["hardly_auth_report", "hardly_session_trace_value"],
        "Cookie name timeline, then correlate session reuse.",
    ),
    (
        ("login", "auth", "mfa", "2fa", "oauth", "password"),
        [
            "hardly_auth_report",
            "hardly_session_timeline",
            "hardly_entry_compare",
        ],
        "Credential map (passwords/JWT/cookies), then flow and pre/post compare.",
    ),
    (
        (
            "jwt",
            "bearer",
            "base64",
            "hex token",
            "session cookie",
            "credential",
            "password field",
        ),
        [
            "hardly_auth_report",
            "hardly_session_trace_value",
        ],
        "Map shapes (jwt/hex/base64) and session cookie names — values never returned.",
    ),
    (
        ("detail", "document", "xhr", "ajax", "click"),
        ["hardly_page_embedded_routes", "hardly_entry_around", "hardly_entry_initiators", "hardly_page_ui"],
        "Mine JS routes, initiator children, then time-neighbors.",
    ),
    (
        ("initiator", "dependency", "tree", "children", "parent"),
        ["hardly_entry_initiators", "hardly_entry_around", "hardly_session_story"],
        "Initiator parent/children from Chrome _initiator.",
    ),
    (
        ("graphql", "gql", "mutation", "apollo"),
        ["hardly_endpoint_graphql", "hardly_endpoint_schema", "hardly_entry_get"],
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
        ["hardly_session_traffic_stats", "hardly_entry_get", "hardly_endpoint_schema", "hardly_page_forms"],
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
        ["hardly_entry_outline", "hardly_browser_inspect", "hardly_page_ui", "hardly_page_forms"],
        "Offline outline from HAR bodies; live ARIA YAML via hardly_browser_inspect(sections=['aria']).",
    ),
    (
        ("static", "dynamic", "param", "which fields"),
        ["hardly_endpoint_schema", "hardly_session_trace_value"],
        "Classify params across samples of one endpoint template.",
    ),
    (
        ("capture", "record", "playwright", "browser", "recipe", "aria ref"),
        [
            "hardly_guide_mode",
            "hardly_server_status",
            "hardly_browser_capture_discover",
            "hardly_browser_start",
            "hardly_browser_inspect",
        ],
        "Pick a mode first; headless=discover, interactive=ask person + start.",
    ),
    (
        ("akamai", "cloudflare", "bot wall", "captcha", "403", "blocked"),
        ["hardly_gate_bot_protection", "hardly_guide_mode", "hardly_browser_start", "hardly_session_issues"],
        "Wall — interactive headed channel=chrome; ask the person to click.",
    ),
    (
        ("slow", "latency", "timeout", "waterfall", "performance"),
        ["hardly_session_slow_requests", "hardly_session_issues", "hardly_entry_initiators"],
        "List slowest requests, then inspect entry/tree.",
    ),
    (
        ("duplicate", "polling", "repeat", "retry"),
        ["hardly_session_duplicates", "hardly_endpoint_schema", "hardly_entry_compare"],
        "Find repeated templates, then compare samples.",
    ),
    (
        ("page load", "pageref", "pages"),
        ["hardly_page_list", "hardly_entry_initiators", "hardly_session_story"],
        "Group by browser pageref, then tree the document.",
    ),
    (
        ("empty body", "missing body", "coverage", "size=-1", "truncated"),
        ["hardly_session_issues", "hardly_session_body_coverage", "hardly_browser_start"],
        "Check issues/coverage, then re-capture with body backfill.",
    ),
    (
        ("diff", "compare", "second capture", "new endpoint"),
        ["hardly_session_compare", "hardly_entry_compare", "hardly_endpoint_list"],
        "Diff two sessions, or two entries for the same call.",
    ),
    (
        ("openapi", "swagger", "postman", "export", "document"),
        [
            "hardly_write_export",
            "hardly_endpoint_list",
        ],
        "Export a contract, then fill gaps with entry/schema.",
    ),
    (
        ("probe", "replay", "live"),
        ["hardly_entry_build_curl", "hardly_send_entry", "hardly_session_trace_value"],
        "curl first (redacted), probe only with confirm=true.",
    ),
    (
        ("secret", "leak"),
        ["hardly_auth_report", "hardly_session_trace_value", "hardly_session_issues"],
        "Credential map + sensitive names; never commit the HAR.",
    ),
    (
        ("redirect", "302", "301", "location"),
        ["hardly_session_redirect_history", "hardly_entry_around", "hardly_session_story"],
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
                        "hardly_guide_mode",
                        "hardly_guide_help",
                        "hardly_session_open",
                        "hardly_browser_capture_discover",
                    ],
                    "reason": (
                        "Pick a mode: open a HAR (archive), "
                        "hardly_browser_capture_discover(url) (headless), or interactive capture."
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
                        "hardly_session_overview",
                        "hardly_endpoint_list",
                        "hardly_session_site_brief",
                        "hardly_entry_search",
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
