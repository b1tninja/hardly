"""Rank links in captured HTML that likely lead to a search / lookup UI.

Content-neutral: built-in signals are generic (search, lookup, find, viewer...).
Domain vocabulary (e.g. "parcel", "docket", "inventory") comes from the caller
via ``keywords`` so no site category is baked into hardly.
"""

from __future__ import annotations

import re
import sqlite3
from typing import Any
from urllib.parse import urlparse

from hardly.core.html_forms import extract_html_structure

_GENERIC = re.compile(
    r"\b(search|lookup|look\s*up|find|query|inquiry|viewer|browse|directory|"
    r"advanced\s*search|index)\b",
    re.I,
)
_NEGATIVE = re.compile(
    r"log\s*in|sign\s*in|register|password|pay(ment)?\b|contact|faq|forms?\b|"
    r"news|careers?|facebook|twitter|linkedin|instagram|youtube|privacy|"
    r"accessib|sitemap|mailto|\.pdf|translate|subscribe|calendar|holiday",
    re.I,
)
# Low-weight "gateway" wording: pages that usually lead on to a search UI.
_GATEWAY = re.compile(
    r"\b(online|e-?services?|services|public (access|records?)|records?|research|"
    r"tools|resources|databases?|portal|applications?|apps|self[- ]service)\b",
    re.I,
)
_GATEWAY_WEIGHT = 2
_KEYWORD_WEIGHT = 10
_GENERIC_WEIGHT = 3


def score_link(
    text: str, href: str, keywords: tuple[str, ...] = ()
) -> tuple[int, list[str]]:
    """Return ``(score, matched_keywords)``; score <= 0 means not a candidate."""
    if _NEGATIVE.search(text or "") or _NEGATIVE.search(href or ""):
        return 0, []
    hay = f"{text} {urlparse(href).path.replace('-', ' ').replace('_', ' ')}"
    score = 0
    matched = [k for k in keywords if k and re.search(re.escape(k), hay, re.I)]
    score += _KEYWORD_WEIGHT * len(matched)
    if _GENERIC.search(hay):
        score += _GENERIC_WEIGHT
    if _GATEWAY.search(text or ""):
        score += _GATEWAY_WEIGHT
    # A keyword alone (no search-ish word) is only a weak lead.
    return score, matched


def rank_search_links(
    links: list[dict[str, Any]],
    *,
    keywords: tuple[str, ...] = (),
    limit: int = 15,
) -> list[dict[str, Any]]:
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for link in links:
        href = link.get("href") or link.get("href_raw") or ""
        text = (link.get("text") or "").strip()
        if not href or (href, text) in seen:
            continue
        seen.add((href, text))  # type: ignore[arg-type]
        score, matched = score_link(text, href, keywords)
        if score <= 0:
            continue
        css = (
            f"a:has-text({_q(text)})" if text and len(text) <= 80
            else f"a[href={_q(link.get('href_raw') or href)}]"
        )
        if link.get("css"):
            css = link["css"]
        out.append(
            {
                "kind": link.get("kind") or "link",
                "score": score,
                "matched_keywords": matched,
                "text": text,
                "href": href,
                "click": {"op": "click", "css": css},
            }
        )
    out.sort(key=lambda r: (-r["score"], r["href"]))
    return out[:limit]


def actions_as_links(actions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Adapt JS click targets (buttons, postback/js links) to link-shaped rows."""
    out = []
    for a in actions:
        sel = f"#{a['id']}" if a.get("id") and re.fullmatch(r"[A-Za-z][\w-]*", a["id"]) else None
        out.append(
            {
                "text": a.get("text") or "",
                "href": f"action:{a.get('kind')}:{a.get('id') or a.get('xpath')}",
                "kind": a.get("kind"),
                "css": sel or (f"{a['tag']}:has-text({_q(a['text'])})" if a.get("text") else None),
            }
        )
    return [o for o in out if o["css"]]


_SITE_SEARCH_NAME = re.compile(
    r"^(q|s|search|query|keyword|keywords|term|searchterm|site-search)$", re.I
)
_ENTRY_TYPES = frozenset(
    {"text", "search", "number", "date", "email", "tel", "select", "textarea", "datetime-local", "month"}
)


def search_form_reached(
    structure: dict[str, Any], *, min_fields: int = 2
) -> dict[str, Any] | None:
    """First form that looks like a real search/lookup form, else ``None``.

    Skips login forms (password field) and one-box site-search widgets, so a
    landing page's header search does not end navigation early.
    """
    for form in structure.get("forms") or []:
        fields = form.get("fields") or []
        if any((f.get("type") or "").lower() == "password" for f in fields):
            continue
        entry = [
            f for f in fields
            if (f.get("type") or f.get("kind") or "").lower() in _ENTRY_TYPES
            or f.get("kind") in {"select", "textarea"}
        ]
        if not entry:
            continue
        if len(entry) < min_fields and not (
            len(entry) == 1
            and not _SITE_SEARCH_NAME.match(str(entry[0].get("name") or entry[0].get("id") or ""))
        ):
            continue
        return {
            "action": form.get("action") or "",
            "method": form.get("method") or "",
            "fields": [f.get("name") or f.get("id") or "" for f in entry][:12],
        }
    return None


def page_candidates(
    html: str,
    *,
    base_url: str = "",
    keywords: tuple[str, ...] | list[str] = (),
    limit: int = 15,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Ranked click targets for one page plus its parsed structure."""
    structure = extract_html_structure(html, base_url=base_url)
    links = (structure.get("links") or []) + actions_as_links(structure.get("actions") or [])
    kw = tuple(k.strip() for k in keywords if k and k.strip())
    return rank_search_links(links, keywords=kw, limit=limit), structure


def _q(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def find_search_entry(
    conn: sqlite3.Connection,
    *,
    host: str | None = None,
    keywords: tuple[str, ...] | list[str] = (),
    limit: int = 15,
) -> dict[str, Any]:
    """Rank click targets across indexed HTML responses (landing pages first)."""
    from hardly.index import query as q

    kw = tuple(k.strip() for k in keywords if k and k.strip())
    host = host or q.preferred_host(conn)
    where, params = "e.is_noise = 0 AND sb.preview_text IS NOT NULL", []
    if host:
        where += " AND e.host = ?"
        params.append(host.lower())
    rows = conn.execute(
        f"""
        SELECT e.entry_id, e.scheme, e.host, e.path, sb.preview_text AS body
        FROM entries e
        JOIN bodies sb ON sb.entry_id = e.entry_id AND sb.side = 'response'
        WHERE {where} AND (e.mime LIKE '%html%' OR sb.content_type LIKE '%html%')
        ORDER BY e.started_datetime, e.entry_id
        """,
        params,
    ).fetchall()
    links: list[dict[str, Any]] = []
    for row in rows:
        s = extract_html_structure(
            row["body"], base_url=f"{row['scheme']}://{row['host']}{row['path']}"
        )
        for link in (s.get("links") or []) + actions_as_links(s.get("actions") or []):
            links.append({**link, "entry_id": row["entry_id"]})
    ranked = rank_search_links(links, keywords=kw, limit=limit)
    return {
        "host": host,
        "keywords": list(kw),
        "pages_scanned": len(rows),
        "candidates": ranked,
        "next_step": ranked[0]["click"] if ranked else None,
        "note": (
            "Click next_step, then re-capture and run hardly_forms/hardly_story "
            "on the result page; repeat until a form with input fields appears."
        ),
    }
