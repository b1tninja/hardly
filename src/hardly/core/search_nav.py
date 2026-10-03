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
_HIDDENISH = re.compile(r"mobile|offcanvas|off-canvas|sr-only|skip|hamburger|navbar-toggle", re.I)
# Feedback/survey/utility wording: never a route to a lookup.
_UTILITY_TEXT = re.compile(
    r"did you find|was this (page )?helpful|feedback|survey|rate (this|us)|take our|your opinion|"
    r"report a problem|give us|share your|how are we doing|cookie|accept all|manage preferences",
    re.I,
)
_KEYWORD_WEIGHT = 10
_GENERIC_WEIGHT = 3


def score_link(
    text: str, href: str, keywords: tuple[str, ...] = ()
) -> tuple[int, list[str]]:
    """Return ``(score, matched_keywords)``; score <= 0 means not a candidate."""
    if _NEGATIVE.search(text or "") or _NEGATIVE.search(href or "") or _UTILITY_TEXT.search(text or ""):
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
                "target": link.get("target") or "",
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
        # Hidden mobile/off-canvas triggers are never what a visitor uses.
        if _HIDDENISH.search(f"{a.get('id') or ''} {a.get('name') or ''}"):
            continue
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


_GENERIC_KEYWORDS = frozenset(
    {"search", "searches", "find", "lookup", "look up", "query", "records", "record", "online",
     "services", "service", "portal", "index", "public", "database", "directory", "viewer", "inquiry"}
)
_SITE_SEARCH_NAME = re.compile(
    r"^(q|s|search|query|keyword|keywords|term|searchterm|site-?search|keys|search[-_]?(term|text|box|input|query|field)|"
    r"cdssearchtext|searchtext|st|k|text)$",
    re.I,
)
# Forms that exist on almost every site and are never the lookup we want.
_UTILITY_ACTION = re.compile(
    r"translate|subscribe|newsletter|govdelivery|feedback|report[-_]?a?[-_]?problem|signup|sign-up|"
    r"register|login|signin|comment|contact|unsubscribe|/search/?$|/find/?$",
    re.I,
)
_ENTRY_TYPES = frozenset(
    {"text", "search", "number", "date", "tel", "select", "textarea", "datetime-local", "month"}
)


def has_search_term(text: str) -> bool:
    """True when link text itself names a search/lookup action."""
    return bool(_GENERIC.search(text or ""))


def search_form_reached(
    structure: dict[str, Any],
    *,
    min_fields: int = 2,
    keywords: tuple[str, ...] | list[str] = (),
    allow_site_search: bool = False,
) -> dict[str, Any] | None:
    """First form that looks like a real search/lookup form, else ``None``.

    Skips login forms, one-box site search, newsletter/feedback/translate
    widgets, email-only and select-only forms, and forms whose inputs have no
    names (nothing to submit). A one-field form counts only when its field name
    is specific and, if ``keywords`` are given, mentions one of them.
    """
    # Generic words ("search", "records"...) match every site-search box, so
    # only the caller's domain terms can vouch for a form.
    # ``allow_site_search``: we got here by deliberately following a link that
    # itself named a search (e.g. "Search Online Catalog"), so a one-box form on
    # THIS page is the search, not a site-wide header widget.
    kw = [k.lower() for k in keywords if k and k.lower().strip() not in _GENERIC_KEYWORDS]
    for form in structure.get("forms") or []:
        fields = form.get("fields") or []
        if any((f.get("type") or "").lower() == "password" for f in fields):
            continue
        if _UTILITY_ACTION.search(form.get("action") or "") and not any(
            k in (form.get("action") or "").lower() for k in kw
        ):
            continue
        entry = [
            f for f in fields
            if ((f.get("type") or f.get("kind") or "").lower() in _ENTRY_TYPES or f.get("kind") in {"select", "textarea"})
            and (f.get("name") or f.get("id"))
        ]
        if not entry or all((f.get("kind") == "select" or f.get("type") == "select") for f in entry):
            continue
        names = [str(f.get("name") or f.get("id") or "") for f in entry]
        # A site-search box with a scope selector (q + search_type/scope/site)
        # is still the site-wide widget, not a lookup form.
        free = [f for f in entry if (f.get("type") or f.get("kind") or "").lower() != "select" and f.get("kind") != "select"]
        if (
            len(free) == 1
            and len(entry) > 1
            and _SITE_SEARCH_NAME.match(str(free[0].get("name") or free[0].get("id") or ""))
            and not allow_site_search
            and not any(k in " ".join(names).lower() for k in kw)
        ):
            continue
        # A keyword vouches for a form only through its field names (or id),
        # never through the action URL: /search/permits is still a site search.
        blob = " ".join(names + [form.get("id") or ""]).lower()
        kw_hit = any(k in blob for k in kw)
        if len(entry) >= max(min_fields, 2):
            return _form_hit(form, entry)
        # single named field: needs a specific name (and a keyword when given)
        name = names[0]
        if _SITE_SEARCH_NAME.match(name) or "search" in name.lower():
            if not kw_hit and not allow_site_search:
                continue
        elif kw and not kw_hit:
            continue
        return _form_hit(form, entry)
    return None


def _form_hit(form: dict[str, Any], entry: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "action": form.get("action") or "",
        "method": form.get("method") or "",
        "fields": [f.get("name") or f.get("id") or "" for f in entry][:12],
    }


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
    if not host:
        # The page we navigate is the first HTML document, not whichever host
        # has the most hits (an embedded video host would win otherwise).
        first = conn.execute(
            "SELECT host FROM entries WHERE status = 200 AND mime LIKE '%html%' ORDER BY entry_id LIMIT 1"
        ).fetchone()
        host = first["host"] if first else q.preferred_host(conn)
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
