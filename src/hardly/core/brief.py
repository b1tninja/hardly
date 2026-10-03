"""One-shot portal reverse-engineering brief for agents."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from hardly.core.classify import summarize_content
from hardly.core.cookies import cookie_timeline
from hardly.core.correlate import correlate_tokens
from hardly.core.issues import find_issues
from hardly.core.story import portal_story
from hardly.core.wall import detect_walls
from hardly.index import query as q


def portal_brief(
    conn: sqlite3.Connection,
    *,
    har_path: str | Path | None = None,
    host: str | None = None,
) -> dict[str, Any]:
    """Compact RE brief: story, forms, routes, correlate, cookies, issues."""
    if not host:
        host = q.preferred_host(conn)
    if not host:
        return {"error": "no host", "host": None}

    story = portal_story(conn, host=host, limit=25)
    forms = q.list_forms(conn, host=host, exclude_noise=True, limit=8)
    routes = q.list_js_routes(conn, host=host, limit=15)
    corr = correlate_tokens(conn, har_path=har_path, host=host, limit=15)
    cookies = cookie_timeline(conn, har_path=har_path, host=host, limit=30)
    issues = find_issues(conn, host=host, limit=15)
    walls = detect_walls(conn, host=host, limit=10)
    coverage = q.body_coverage(conn, host=host)
    content = summarize_content(conn, host=host, exclude_noise=True, limit=120)

    from hardly.core.credentials import map_credentials

    cred = map_credentials(conn, har_path=har_path, host=host, limit=25)
    credentials = {
        "password_field_count": cred.get("password_field_count"),
        "identity_fields": [
            f.get("name") for f in (cred.get("identity_fields") or [])[:8]
        ],
        "session_cookies": (cred.get("session_cookies") or [])[:12],
        "csrf_names": (cred.get("csrf_names") or [])[:12],
        "shapes_by_kind": cred.get("shapes_by_kind") or {},
        "cookie_flags_by": cred.get("cookie_flags_by") or {},
        "oauth_likely": bool((cred.get("oauth") or {}).get("likely")),
        "oauth_flow": (cred.get("oauth") or {}).get("flow") or {},
        "login_flow": {
            "confidence": (cred.get("login_flow") or {}).get("confidence"),
            "step_count": (cred.get("login_flow") or {}).get("step_count"),
            "steps": ((cred.get("login_flow") or {}).get("steps") or [])[:8],
        },
    }

    form_pages = []
    for item in forms.get("entries") or []:
        field_names: list[str] = []
        for form in item.get("forms") or []:
            for name in form.get("field_names") or []:
                if name not in field_names:
                    field_names.append(name)
        form_pages.append(
            {
                "entry_id": item.get("entry_id"),
                "path": (item.get("url") or "").split("://", 1)[-1],
                "form_count": item.get("form_count"),
                "field_names": field_names[:30],
                "handler_functions": [
                    h.get("name") if isinstance(h, dict) else h
                    for h in (item.get("handler_functions") or [])[:10]
                ],
            }
        )

    roles: dict[str, int] = {}
    for step in story.get("steps") or []:
        role = step.get("role") or "other"
        roles[role] = roles.get(role, 0) + 1

    apex = q._host_apex(host)
    related = [
        h
        for h in q.list_hosts(conn, exclude_noise=True)
        if h["host"] != host
        and (h["host"] == apex or h["host"].endswith(f".{apex}"))
    ][:8]

    next_bits = [
        "Drill with hardly_entry / hardly_around / hardly_stub.",
        "Live: hardly_recipe_plan → capture_recipe.",
        "Do not Read the HAR file.",
    ]
    if related:
        next_bits.insert(
            0,
            f"SPA APIs often live on related_hosts (same apex {apex}); "
            "pass that host to hardly_endpoints / hardly_story.",
        )
    if (
        credentials.get("password_field_count")
        or credentials.get("shapes_by_kind")
        or credentials.get("session_cookies")
        or credentials.get("oauth_likely")
    ):
        next_bits.insert(
            0,
            "Credentials/login signals present — drill with hardly_credentials "
            "(names/shapes only).",
        )
    if (walls.get("hit_count") or 0) > 0:
        next_bits.insert(
            0,
            "Wall hits — prefer interactive capture (channel=chrome) over "
            "headless/urllib.",
        )

    return {
        "host": host,
        "apex": apex,
        "related_hosts": related,
        "roles": roles,
        "step_count": story.get("step_count"),
        "steps": story.get("steps"),
        "correlations": (corr.get("correlations") or [])[:12],
        "cookie_names_set": cookies.get("names_set"),
        "cookie_names_sent": cookies.get("names_sent"),
        "cookie_flags_by": cookies.get("by_flag") or {},
        "credentials": credentials,
        "form_pages": form_pages[:8],
        "js_routes": [
            {"path": r.get("path"), "score": r.get("score"), "count": r.get("count")}
            for r in (routes.get("routes") or [])[:15]
        ],
        "issues": {
            "issue_count": issues.get("issue_count"),
            "by_kind": issues.get("by_kind"),
            "sample": (issues.get("issues") or [])[:8],
        },
        "walls": {
            "hit_count": walls.get("hit_count"),
            "by_kind": walls.get("by_kind"),
            "sample": (walls.get("hits") or [])[:5],
        },
        "coverage": {
            "entries": coverage.get("entries"),
            "with_preview": coverage.get("with_preview"),
            "without_preview": coverage.get("without_preview"),
            "preview_ratio": coverage.get("preview_ratio"),
        },
        "content_kinds": content.get("by_kind"),
        "content_samples": {
            k: v[:2] for k, v in (content.get("samples") or {}).items()
        },
        "next": " ".join(next_bits),
    }
