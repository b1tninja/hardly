"""Extract and interpret HTML ``data-*`` attributes.

Follows the MDN "Use data attributes" model: ``data-foo-bar`` is exposed to
script as ``element.dataset.fooBar`` and always holds a string. Pages use them
to carry row ids, endpoint URLs, embedded JSON config and framework hooks, so
they are a rich source of client-SDK facts that never appear in a form.

Technology-level only. Reports attribute names, their ``dataset`` keys, value
*kinds* and framework hints. Free-text values are never echoed; short
enum-like values (``toggle="modal"``) are listed because they are conventions,
not content.
"""

from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin, urlparse

from hardly.core.explain import finish
from hardly.core.previews import is_truncated, preview_warnings

_DATA = re.compile(r"^data-([a-z][a-z0-9\-_.:]*)$")
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_ISO_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}(:\d{2})?)?")
_URLISH = re.compile(r"^(https?://|//|/[^\s]*|\.{1,2}/[^\s]*)", re.I)
# Enum-like = one short token (a convention such as "modal"), never prose.
_ENUM_OK = re.compile(r"^[A-Za-z][A-Za-z0-9_\-:.]{0,23}$")
# Attribute names that usually carry user content: never list their values.
_CONTENT_NAMES = re.compile(
    r"(^|-)(name|first|last|full|title|description|desc|label|message|msg|text|comment|note|notes|"
    r"address|street|city|phone|tel|email|mail|user|username|owner|author|content|body|caption|"
    r"placeholder|tooltip|content)(-|$)",
    re.I,
)
_EMAIL = re.compile(r"[^@\s]+@[^@\s]+\.[a-z]{2,}", re.I)
_ENDPOINT_NAMES = re.compile(r"(^|-)(url|href|src|endpoint|action|api|path|link|route|source|ajax|remote|fetch)(-|$)", re.I)

# (framework id, regex on the attribute name after "data-")
_FRAMEWORKS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("bootstrap", re.compile(r"^bs-(toggle|target|dismiss|backdrop|placement|content|bs)|^(toggle|target|dismiss|slide|ride|spy|offset)$")),
    ("stimulus", re.compile(r"^(controller|action|(?!bs-)[\w-]+-target|[\w-]+-value|[\w-]+-class)$")),
    ("turbo-rails-ujs", re.compile(r"^(turbo[\w-]*|remote|method|confirm|disable-with|params|type)$")),
    ("htmx", re.compile(r"^hx-")),
    ("alpine-vue-react", re.compile(r"^(v-[0-9a-f]{6,}|reactroot|react-helmet|reactid|server-rendered)$")),
    ("angular", re.compile(r"^(ng-[\w-]+|ng-version)$")),
    ("jquery-mobile-ui", re.compile(r"^(role|theme|transition|rel|ajax|dialog|position-to|icon|inline|mini)$")),
    ("test-hooks", re.compile(r"^(testid|test|test-id|cy|qa|automation-id|e2e|pw)$")),
    ("tracking", re.compile(r"^(gtm[\w-]*|ga[\w-]*|analytics[\w-]*|track[\w-]*|pixel[\w-]*|fb[\w-]*|segment[\w-]*|event-(category|action|label))$")),
    ("captcha-widget", re.compile(r"^(sitekey|callback|expired-callback|theme|size|action|cdata)$")),
    ("payments", re.compile(r"^(stripe[\w-]*|paypal[\w-]*|braintree[\w-]*)$")),
    ("grid-table", re.compile(r"^(sort|order|field|column|row-id|row|page|total|page-size|filter|searchable|orderable|sortable|visible|priority|index|key)$")),
)
# Framework-name collisions: weaker match words only count with a second signal.
_AMBIGUOUS = {"jquery-mobile-ui", "captcha-widget"}


class _Collector(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base = base_url
        self.rows: list[tuple[str, dict[str, str], dict[str, str]]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        ad = {k.lower(): (v if v is not None else "") for k, v in attrs}
        data = {k: v for k, v in ad.items() if _DATA.match(k)}
        if data:
            self.rows.append((tag, data, ad))

    handle_startendtag = handle_starttag


def dataset_key(attr: str) -> str:
    """MDN rule: strip ``data-``, drop each ``-`` and upper-case the next letter."""
    name = attr[5:] if attr.startswith("data-") else attr
    return re.sub(r"-([a-z])", lambda m: m.group(1).upper(), name)


def classify_value(value: str) -> str:
    v = value.strip()
    if v == "":
        return "empty"
    low = v.lower()
    if low in {"true", "false"}:
        return "boolean"
    if re.fullmatch(r"-?\d+", v):
        return "integer"
    if re.fullmatch(r"-?\d+\.\d+", v):
        return "number"
    if _UUID.match(v):
        return "uuid"
    if v[0] in "{[" and v[-1] in "}]":
        try:
            json.loads(v)
            return "json"
        except ValueError:
            return "json_like"
    if _URLISH.match(v):
        return "url"
    if _ISO_DATE.match(v):
        return "datetime"
    if _EMAIL.search(v):
        return "email"
    if len(v) >= 24 and " " not in v and re.fullmatch(r"[A-Za-z0-9+/=_\-.~%]+", v):
        return "opaque_token"
    return "text"


def extract_data_attributes(html: str, *, base_url: str = "") -> dict[str, Any]:
    """Summarise ``data-*`` usage in one HTML document."""
    empty = {
        "elements": 0, "attribute_count": 0, "attributes": [], "endpoints": [],
        "embedded_json": [], "frameworks": [], "ids": [],
    }
    if not html or "data-" not in html:
        return empty
    col = _Collector(base_url)
    try:
        col.feed(html)
        col.close()
    except Exception:  # noqa: BLE001 — partial results beat none on broken HTML
        pass
    if not col.rows:
        return empty

    stats: dict[str, dict[str, Any]] = defaultdict(
        lambda: {"count": 0, "tags": Counter(), "kinds": Counter(), "enum": Counter()}
    )
    endpoints: list[dict[str, Any]] = []
    embedded: list[dict[str, Any]] = []
    id_attrs: Counter[str] = Counter()
    for tag, data, ad in col.rows:
        for attr, value in data.items():
            st = stats[attr]
            st["count"] += 1
            st["tags"][tag] += 1
            kind = classify_value(value)
            st["kinds"][kind] += 1
            if kind == "text" and _ENUM_OK.match(value.strip()) and not _CONTENT_NAMES.search(attr[5:]):
                st["enum"][value.strip()] += 1
            if kind == "url" or (kind == "text" and _ENDPOINT_NAMES.search(attr) and "/" in value):
                if len(endpoints) < 40:
                    resolved = urljoin(base_url, value) if base_url and not value.startswith(("http", "//")) else value
                    endpoints.append({"attr": attr, "tag": tag, "url": _strip_query_values(resolved)})
            elif kind in {"json", "json_like"} and len(embedded) < 20:
                keys: list[str] = []
                if kind == "json":
                    try:
                        parsed = json.loads(value)
                        keys = sorted(parsed)[:12] if isinstance(parsed, dict) else [f"[list:{len(parsed)}]"]
                    except ValueError:
                        pass
                embedded.append({"attr": attr, "key": dataset_key(attr), "tag": tag, "keys": keys, "bytes": len(value)})
            if kind in {"integer", "uuid"} and re.search(r"(^|-)(id|key|uuid|pk|ref)(-|$)", attr):
                id_attrs[attr] += 1

    attributes = []
    for attr, st in sorted(stats.items(), key=lambda kv: -kv[1]["count"]):
        enum = [v for v, _ in st["enum"].most_common(6)]
        distinct_ok = len(st["enum"]) <= 8 and sum(st["enum"].values()) >= 1
        attributes.append(
            {
                "name": attr,
                "dataset_key": dataset_key(attr),
                "count": st["count"],
                "tags": dict(st["tags"].most_common(4)),
                "value_kinds": dict(st["kinds"].most_common(4)),
                **({"values": enum} if enum and distinct_ok else {}),
            }
        )

    fw_hits: dict[str, list[str]] = defaultdict(list)
    for attr in stats:
        bare = attr[5:]
        for fid, pat in _FRAMEWORKS:
            if pat.search(bare):
                fw_hits[fid].append(attr)
    frameworks = [
        {"id": fid, "attributes": sorted(attrs)[:8]}
        for fid, attrs in fw_hits.items()
        if fid not in _AMBIGUOUS or len(attrs) >= 2
    ]
    # data-sitekey is specific to captcha widgets: one attribute is enough, and it matters
    # because the response token cannot be scripted.
    if "data-sitekey" in stats and not any(f["id"] == "captcha-widget" for f in frameworks):
        frameworks.append({"id": "captcha-widget", "attributes": sorted(fw_hits.get("captcha-widget", ["data-sitekey"]))[:8]})
    for f in frameworks:
        if f["id"] == "captcha-widget":
            f["hint"] = (
                "captcha widget (data-sitekey): the site expects a human-solved token; "
                "do not script around it - use an interactive capture with a person."
            )
    return {
        "elements": len(col.rows),
        "attribute_count": len(stats),
        "attributes": attributes[:40],
        "endpoints": endpoints,
        "embedded_json": embedded,
        "frameworks": sorted(frameworks, key=lambda f: -len(f["attributes"])),
        "ids": [{"attr": a, "elements": c} for a, c in id_attrs.most_common(8)],
    }


def _strip_query_values(url: str) -> str:
    """Keep path and query *names*; drop query values (may carry tokens)."""
    p = urlparse(url)
    if not p.query:
        return url
    names = sorted({q.split("=", 1)[0] for q in p.query.split("&") if q})
    return p._replace(query="&".join(f"{n}=" for n in names)).geturl()


def _scan_session(conn: Any, *, host: str | None = None, entry_id: int | None = None, limit: int = 20) -> dict[str, Any]:
    """Aggregate ``data-*`` usage across HTML responses in a session."""
    where = "(b.content_type LIKE '%html%' OR b.preview_text LIKE '<%') AND b.preview_text LIKE '%data-%'"
    params: list[Any] = []
    if entry_id is not None:
        where += " AND e.entry_id = ?"
        params.append(entry_id)
    elif host:
        where += " AND e.host = ?"
        params.append(host.lower())
    rows = conn.execute(
        f"""
        SELECT e.entry_id, e.scheme, e.host, e.path, b.preview_text, b.size
        FROM entries e JOIN bodies b ON b.entry_id = e.entry_id AND b.side = 'response'
        WHERE {where} ORDER BY e.entry_id LIMIT 200
        """,
        params,
    ).fetchall()
    merged: dict[str, dict[str, Any]] = {}
    endpoints: list[dict[str, Any]] = []
    embedded: list[dict[str, Any]] = []
    frameworks: dict[str, set[str]] = defaultdict(set)
    ids: Counter[str] = Counter()
    pages = 0
    truncated: list[dict[str, Any]] = []
    for row in rows:
        if is_truncated(row["size"], row["preview_text"]):
            truncated.append({"entry_id": row["entry_id"]})
        out = extract_data_attributes(row["preview_text"], base_url=f"{row['scheme']}://{row['host']}{row['path']}")
        if not out["elements"]:
            continue
        pages += 1
        for a in out["attributes"]:
            m = merged.setdefault(a["name"], {**a, "entry_ids": [], "count": 0, "value_kinds": Counter(), "tags": Counter()})
            m["count"] += a["count"]
            m["value_kinds"].update(a["value_kinds"])
            m["tags"].update(a["tags"])
            if a.get("values"):
                m["values"] = sorted(set(m.get("values", [])) | set(a["values"]))[:8]
            if len(m["entry_ids"]) < 5:
                m["entry_ids"].append(row["entry_id"])
        for ep in out["endpoints"]:
            if ep not in endpoints and len(endpoints) < 40:
                endpoints.append({**ep, "entry_id": row["entry_id"]})
        for ej in out["embedded_json"]:
            if len(embedded) < 20:
                embedded.append({**ej, "entry_id": row["entry_id"]})
        for fw in out["frameworks"]:
            frameworks[fw["id"]].update(fw["attributes"])
        for i in out["ids"]:
            ids[i["attr"]] += i["elements"]
    attributes = sorted(merged.values(), key=lambda a: -a["count"])
    for a in attributes:
        a["value_kinds"] = dict(a["value_kinds"].most_common(4))
        a["tags"] = dict(a["tags"].most_common(4))
    warnings = preview_warnings(truncated, "data-* attributes")
    return {
        **({"warnings": warnings, "truncated_previews": len(truncated)} if warnings else {}),
        "host": host,
        "pages_with_data_attributes": pages,
        "attribute_count": len(attributes),
        "attributes": attributes[:limit],
        "endpoints": endpoints,
        "embedded_json": embedded,
        "frameworks": [{"id": k, "attributes": sorted(v)[:8]} for k, v in frameworks.items()],
        "ids": [{"attr": a, "elements": c} for a, c in ids.most_common(8)],
        "next": (
            "dataset_key is what page scripts read (element.dataset.<key>); "
            "endpoints/embedded_json show config the page hands to JavaScript — "
            "use hardly_entry / hardly_outline on entry_id for context."
        ),
    }


def scan_session(conn: Any, *, host: str | None = None, entry_id: int | None = None, limit: int = 20,
    explain: bool = False,
) -> dict[str, Any]:
    """``scan_session``; canned prose (next) only with ``explain=True``."""
    return finish(_scan_session(conn, host=host, entry_id=entry_id, limit=limit), explain, 'next')

