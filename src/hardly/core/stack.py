"""Technology fingerprinting with SDK implications (stdlib only).

Technology-level only: web frameworks, front-end frameworks, CMS / site
builders, GIS stacks, UI toolkits, auth/CSRF conventions. Domain products and
site names are deliberately out of scope; CDN/WAF products live in botwalls.

Evidence is weighted like ``botwalls``: each distinct signal (by label) counts
once per technology; score >= 3 is ``high``, 2 ``medium``, 1 ``low``. Evidence
``match`` strings are fixed labels written in this catalog -- cookie values,
header values and tokens are matched but never echoed.
"""

from __future__ import annotations

import json
import re
import sqlite3
from typing import Any
from urllib.parse import urlsplit

from hardly.core.cookies import cookie_timeline
from hardly.core.explain import finish

_MAX_ENTRIES = 6000
_MAX_BODY_CHARS = 200_000
_MAX_ENTRY_IDS = 10
_SKIP_HEADERS = frozenset({"cookie", "set-cookie", "authorization", "proxy-authorization"})
_CONF_ORDER = {"high": 0, "medium": 1, "low": 2}


def _sig(kind: str, pattern: str, weight: int, label: str):
    return (kind, re.compile(pattern, re.I), weight, label)


def C(pattern: str, weight: int, label: str):
    """Cookie name (full match)."""
    return _sig("cookie", rf"^(?:{pattern})$", weight, label)


def H(pattern: str, weight: int, label: str):
    """Header line ``name: value`` (anchored at start)."""
    return _sig("header", rf"^(?:{pattern})", weight, label)


def U(pattern: str, weight: int, label: str):
    """URL fragment; also matched inside bodies (script/link references)."""
    return _sig("url", pattern, weight, label)


def R(pattern: str, weight: int, label: str):
    """Request-URL only: never matched inside bodies (outbound links would false-positive)."""
    return _sig("requrl", pattern, weight, label)


def B(pattern: str, weight: int, label: str):
    """Body-only marker."""
    return _sig("body", pattern, weight, label)


def _tech(tid, name, category, implication, *sigs, cap=None):
    return {
        "id": tid,
        "name": name,
        "category": category,
        "implication": implication,
        "signals": list(sigs),
        "cap": cap,
    }


_JS_BUNDLE = "The API path lives in the JS bundle; use hardly_routes to find it."

CATALOG: list[dict[str, Any]] = [
    _tech(
        "aspnet-webforms", "ASP.NET WebForms", "server_framework",
        "Carry ALL hidden fields (__VIEWSTATE, __EVENTVALIDATION, ...) forward on each postback step.",
        B(r"__VIEWSTATE\b", 3, "__VIEWSTATE"),
        B(r"__EVENTVALIDATION\b", 2, "__EVENTVALIDATION"),
        B(r"__doPostBack", 2, "__doPostBack"),
        B(r"__VIEWSTATEGENERATOR|__EVENTTARGET", 1, "__VIEWSTATEGENERATOR/__EVENTTARGET"),
        C(r"ASP\.NET_SessionId", 1, "cookie:ASP.NET_SessionId"),
        H(r"x-aspnet-version:", 1, "header:X-AspNet-Version"),
        R(r"\.aspx?(?:[?#]|$)", 1, "url:.aspx"),
    ),
    _tech(
        "aspnet-antiforgery", "ASP.NET MVC/Core antiforgery", "auth_stack",
        "Send the __RequestVerificationToken from the prior GET (field or header) on the POST, with its cookie.",
        B(r"__RequestVerificationToken", 3, "field:__RequestVerificationToken"),
        C(r"__RequestVerificationToken\w*", 3, "cookie:__RequestVerificationToken"),
        C(r"\.AspNetCore\.Antiforgery[\w.\-]*", 3, "cookie:.AspNetCore.Antiforgery"),
        H(r"requestverificationtoken:", 2, "header:RequestVerificationToken"),
    ),
    _tech(
        "blazor-server", "Blazor Server", "server_framework",
        "UI state travels over a SignalR WebSocket circuit, so HAR request replay will not work; drive a real browser.",
        U(r"/_blazor\b", 3, "/_blazor (negotiate/circuit)"),
        U(r"blazor\.server\.js", 3, "blazor.server.js"),
        U(r"_framework/blazor\.web\.js", 2, "blazor.web.js"),
        B(r"<!--\s*Blazor:", 2, "Blazor prerender marker"),
    ),
    _tech(
        "blazor-wasm", "Blazor WebAssembly", "frontend",
        "Client-side .NET app: data comes from separate API calls, so find them via hardly_routes rather than page HTML.",
        U(r"_framework/blazor\.webassembly\.js", 3, "blazor.webassembly.js"),
        U(r"blazor\.boot\.json", 3, "blazor.boot.json"),
        U(r"_framework/[\w.\-]+\.(?:wasm|dll)", 2, "_framework/*.wasm|dll"),
        U(r"\.wasm(?:[?\"'\s]|$)", 1, ".wasm"),
    ),
    _tech(
        "jsf", "JavaServer Faces", "server_framework",
        "Carry the faces ViewState (and form id) forward from each response into the next POST.",
        B(r"(?:javax|jakarta)\.faces\.ViewState", 3, "faces.ViewState"),
        U(r"/(?:javax|jakarta)\.faces\.resource/", 2, "faces.resource path"),
    ),
    _tech(
        "laravel", "Laravel", "server_framework",
        "Echo the XSRF-TOKEN cookie into the X-XSRF-TOKEN header (or send the _token field) on writes.",
        C(r"laravel_session", 3, "cookie:laravel_session"),
        C(r"XSRF-TOKEN", 2, "cookie:XSRF-TOKEN"),
        H(r"x-xsrf-token:", 1, "header:X-XSRF-TOKEN"),
        B(r"""name=["']_token["']""", 2, "field:_token"),
    ),
    _tech(
        "inertia", "Inertia.js", "frontend",
        "Send X-Inertia headers to get JSON page props, and echo the XSRF cookie into X-XSRF-TOKEN.",
        H(r"x-inertia(?:-version)?:", 3, "header:X-Inertia"),
        B(r"""\sdata-page=["']""", 2, "attr:data-page"),
    ),
    _tech(
        "django", "Django", "server_framework",
        "Send the csrftoken cookie value as csrfmiddlewaretoken (form) or X-CSRFToken (header) with a same-origin Referer.",
        B(r"csrfmiddlewaretoken", 3, "field:csrfmiddlewaretoken"),
        C(r"csrftoken", 2, "cookie:csrftoken"),
        H(r"x-csrftoken:", 2, "header:X-CSRFToken"),
    ),
    _tech(
        "rails", "Ruby on Rails", "server_framework",
        "Re-scrape authenticity_token (or csrf-token meta) from each GET; x-request-id is per-response noise, not state.",
        B(r"authenticity_token", 3, "field:authenticity_token"),
        B(r"""<meta[^>]+name=["']csrf-param["']""", 2, "meta:csrf-param"),
        C(r"_[\w\-]+_session", 2, "cookie:_<app>_session"),
        H(r"x-runtime:", 1, "header:X-Runtime"),
        H(r"x-csrf-token:", 1, "header:X-CSRF-Token"),
    ),
    _tech(
        "express", "Express / Connect", "server_framework",
        "connect.sid is a signed session cookie: keep a cookie jar and never rewrite its value.",
        C(r"connect\.sid", 3, "cookie:connect.sid"),
        H(r"x-powered-by:\s*express", 3, "header:X-Powered-By: Express"),
    ),
    _tech(
        "spring-servlet", "Spring / Java servlet", "server_framework",
        "Keep JSESSIONID in the cookie jar (or the ;jsessionid path param) and send the _csrf field from the prior GET.",
        C(r"JSESSIONID", 3, "cookie:JSESSIONID"),
        U(r";jsessionid=", 3, ";jsessionid path param"),
        B(r"""name=["']_csrf["']""", 2, "field:_csrf"),
        H(r"x-application-context:", 2, "header:X-Application-Context"),
    ),
    _tech(
        "php", "PHP", "server_framework",
        "Keep PHPSESSID in the cookie jar; flows are usually plain form posts replayable with cookie plus form fields.",
        C(r"PHPSESSID", 3, "cookie:PHPSESSID"),
        H(r"x-powered-by:\s*php", 3, "header:X-Powered-By: PHP"),
        R(r"\.php(?:[?#]|$)", 1, "url:.php"),
    ),
    _tech(
        "nextjs", "Next.js", "frontend",
        "Page data may sit in __NEXT_DATA__ or /_next/data JSON; other API paths live in the JS bundle (hardly_routes).",
        B(r"__NEXT_DATA__", 3, "__NEXT_DATA__"),
        U(r"/_next/", 3, "/_next/"),
        H(r"x-powered-by:\s*next\.js", 3, "header:X-Powered-By: Next.js"),
    ),
    _tech(
        "nuxt", "Nuxt", "frontend",
        "State may sit in window.__NUXT__ or /_nuxt payloads; the API path lives in the JS bundle (hardly_routes).",
        B(r"__NUXT__", 3, "__NUXT__"),
        U(r"/_nuxt/", 3, "/_nuxt/"),
    ),
    _tech(
        "react", "React", "frontend",
        _JS_BUNDLE,
        B(r"data-reactroot|_reactRootContainer", 2, "data-reactroot"),
        B(r"""<div[^>]+id=["']root["']""", 1, "root div"),
        U(r"react(?:-dom)?[.\-][\w.\-]*js", 1, "react bundle"),
        cap="low",
    ),
    _tech(
        "vue", "Vue", "frontend",
        _JS_BUNDLE,
        B(r"\sdata-v-[0-9a-f]{6,8}\b", 2, "attr:data-v-*"),
        B(r"data-server-rendered|__VUE__", 2, "vue SSR marker"),
        U(r"/vue(?:\.runtime)?(?:\.global)?(?:\.min)?\.js", 2, "vue.js"),
        B(r"""<div[^>]+id=["']app["']""", 1, "app div"),
        B(r"\sv-cloak\b", 1, "v-cloak"),
        cap="medium",
    ),
    _tech(
        "angularjs", "AngularJS", "frontend",
        _JS_BUNDLE,
        B(r"""\sng-app(?=[\s=>/])""", 3, "attr:ng-app"),
        U(r"/angular(?:\.min)?\.js", 3, "angular.js"),
        B(r"""\sng-(?:controller|repeat|model)\b""", 2, "ng-* directives"),
    ),
    _tech(
        "angular", "Angular", "frontend",
        _JS_BUNDLE,
        B(r"\sng-version=", 3, "attr:ng-version"),
        B(r"\b_ng(?:host|content)-", 3, "_nghost/_ngcontent"),
        B(r"<app-root\b", 2, "<app-root>"),
        B(r"\sng-reflect-", 2, "ng-reflect-*"),
    ),
    _tech(
        "salesforce-aura", "Salesforce Experience Cloud / Aura", "frontend",
        "Single Aura endpoint with large form-encoded payloads (aura.context); static bundles must load first.",
        U(r"/aura(?:\?|[\"'\s]|$)", 3, "/aura endpoint"),
        B(r"aura\.context", 3, "aura.context"),
        B(r"aura\.pageURI|aura\.token", 2, "aura.pageURI/token"),
        U(r"/s/sfsites/", 2, "/s/sfsites/"),
        B(r"\$A\.", 1, "$A"),
        U(r"\.force\.com|/lightning/|lightning:", 1, "lightning"),
    ),
    _tech(
        "aem", "Adobe Experience Manager", "cms",
        "Often just link directories; extract outbound links (page .model.json / .json selectors expose content).",
        U(r"/etc\.clientlibs/", 3, "/etc.clientlibs"),
        U(r"/content/dam/", 2, "/content/dam"),
        U(r"/libs/granite/|jcr:content", 2, "granite/jcr:content"),
        U(r"/bin/\w", 1, "/bin/ servlet"),
    ),
    _tech(
        "wordpress", "WordPress", "cms",
        "Often just link directories; /wp-json/wp/v2 lists pages and posts as JSON, else extract outbound links.",
        U(r"/wp-content/", 3, "/wp-content"),
        U(r"/wp-json\b", 3, "/wp-json"),
        U(r"/wp-includes/", 3, "/wp-includes"),
        H(r"link:.*api\.w\.org", 3, "header:Link api.w.org"),
        B(r"""<meta[^>]+generator[^>]+wordpress""", 3, "meta generator WordPress"),
    ),
    _tech(
        "drupal", "Drupal", "cms",
        "Often just link directories; extract outbound links and look for JSON:API under /jsonapi.",
        B(r"Drupal\.settings|drupalSettings", 3, "Drupal.settings"),
        H(r"x-generator:\s*drupal", 3, "header:X-Generator: Drupal"),
        H(r"x-drupal-(?:cache|dynamic-cache)", 3, "header:X-Drupal-Cache"),
        U(r"/sites/(?:default/files|all/)", 3, "/sites/default/files"),
        B(r"data-drupal-selector", 2, "data-drupal-selector"),
        C(r"S?SESS[0-9a-f]{32}", 2, "cookie:SESS<hash>"),
    ),
    _tech(
        "wix", "Wix", "site_builder",
        "Hosted site builder, often just link directories; extract outbound links from the rendered DOM.",
        U(r"static\.parastorage\.com|wixstatic\.com", 3, "wixstatic/parastorage"),
        H(r"x-wix-request-id:", 3, "header:X-Wix-Request-Id"),
    ),
    _tech(
        "squarespace", "Squarespace", "site_builder",
        "Hosted site builder, often just link directories; append ?format=json to pages or extract outbound links.",
        U(r"static1\.squarespace\.com|squarespace-cdn\.com|SQUARESPACE_CONTEXT", 3, "squarespace assets"),
        H(r"server:\s*squarespace", 3, "header:Server: Squarespace"),
    ),
    _tech(
        "webflow", "Webflow", "site_builder",
        "Hosted site builder, often just link directories; extract outbound links from the static HTML.",
        B(r"\sdata-wf-(?:page|site)=", 3, "attr:data-wf-*"),
        U(r"website-files\.com|webflow\.com", 3, "webflow assets"),
    ),
    _tech(
        "godaddy-builder", "GoDaddy Websites", "site_builder",
        "Hosted site builder, often just link directories; extract outbound links from the rendered DOM.",
        U(r"\bwsimg\.com", 3, "wsimg.com"),
    ),
    _tech(
        "sharepoint", "SharePoint", "cms",
        "Often just link directories; /_api/web/lists exposes list items as JSON, else extract outbound links.",
        U(r"/_layouts/|/_vti_bin/", 3, "/_layouts|/_vti_bin"),
        U(r"/_api/(?:web|site)\b", 3, "/_api/web"),
        H(r"(?:microsoftsharepointteamservices|sprequestguid|x-sharepointhealthscore)", 3, "header:SharePoint"),
        B(r"_spPageContextInfo", 3, "_spPageContextInfo"),
    ),
    _tech(
        "telerik-kendo", "Telerik / Kendo UI", "ui_toolkit",
        "Send each *_ClientState hidden JSON field back unchanged with the form; server controls validate it.",
        B(r"\w+_ClientState\b", 3, "*_ClientState field"),
        U(r"Telerik\.Web\.UI", 3, "Telerik.Web.UI"),
        U(r"kendo[.\w\-]*\.js", 2, "kendo.js"),
        B(r"\bk-(?:grid|widget|input)\b", 2, "k-* css classes"),
    ),
    _tech(
        "devexpress", "DevExpress web controls", "ui_toolkit",
        "Callbacks post control state back (__CALLBACKID/__CALLBACKPARAM); replay with the full form.",
        U(r"DXR\.axd", 3, "DXR.axd"),
        B(r"__CALLBACKID|__CALLBACKPARAM", 2, "__CALLBACKID"),
        B(r"\bdx(?:eEditor|cb|gv)\w*\b", 1, "dx* css classes"),
    ),
    _tech(
        "arcgis-rest", "ArcGIS REST services", "gis",
        "Query <layer>/query with where, outFields, f=json and resultOffset/resultRecordCount paging.",
        U(r"/arcgis/rest/services", 3, "/arcgis/rest/services"),
        U(r"/rest/services/", 2, "/rest/services/"),
        U(r"/(?:Map|Feature|Image|Geocode|Geometry|Geoprocessing|Scene)Server\b", 2, "MapServer/FeatureServer"),
        U(r"[?&]f=(?:p?json|pbf)\b", 1, "f=json"),
        B(r""""(?:serviceDescription|objectIdFieldName|spatialReference)"\s*:""", 2, "ArcGIS JSON keys"),
    ),
    _tech(
        "arcgis-apps", "ArcGIS web apps (Experience Builder / WebAppBuilder / Hub / Portal)", "gis",
        "App config JSON (item data) names the underlying REST services; fetch it and query those layers directly.",
        U(r"experience\.arcgis\.com|hub\.arcgis\.com", 3, "arcgis experience/hub host"),
        U(r"/apps/(?:webappviewer|experiencebuilder|dashboards|opsdashboard|instant|storymaps)", 3, "/apps/<arcgis app>"),
        U(r"/sharing/rest", 3, "/sharing/rest"),
        U(r"/portal/(?:home|apps|sharing)", 2, "/portal/*"),
    ),
    _tech(
        "leaflet", "Leaflet", "gis",
        "Map layers load client-side; find the data feed (GeoJSON/REST) behind the tiles, not the tile URLs.",
        U(r"leaflet[\w.\-]*\.(?:js|css)", 3, "leaflet asset"),
        B(r"\bleaflet-(?:container|pane|tile)\b", 3, "leaflet-* css classes"),
    ),
    _tech(
        "openlayers", "OpenLayers", "gis",
        "Map layers load client-side; find the data feed (WFS/GeoJSON/REST) behind the tiles.",
        U(r"openlayers|/ol(?:\.min)?\.(?:js|css)", 3, "openlayers asset"),
        B(r"\bol-(?:viewport|layer|overlaycontainer)\b", 3, "ol-* css classes"),
    ),
    _tech(
        "mapbox-gl", "Mapbox GL / MapLibre GL", "gis",
        "Vector tiles are the backdrop; find the GeoJSON/REST data source in the style JSON or bundle.",
        U(r"(?:mapbox|maplibre)-gl[\w.\-]*\.(?:js|css)", 3, "mapbox-gl asset"),
        B(r"\b(?:mapboxgl|maplibregl)-", 3, "mapboxgl-* css classes"),
        U(r"api\.mapbox\.com", 2, "api.mapbox.com"),
    ),
    _tech(
        "map-tiles", "Slippy-map tile requests", "gis",
        "Tiles are only the backdrop; look for the data layer (WFS/GeoJSON/REST query) beside them.",
        U(r"/\d{1,2}/\d{1,7}/\d{1,7}(?:@2x)?\.(?:png|jpe?g|webp|pbf|mvt)\b", 2, "z/x/y tile path"),
        cap="medium",
    ),
    _tech(
        "ogc-services", "OGC WMS/WFS services", "gis",
        "Use GetCapabilities, then GetFeature with outputFormat=application/json and startIndex/count paging.",
        U(r"[?&]service=(?:wms|wfs|wmts)\b", 3, "service=WMS|WFS"),
        U(r"[?&]request=(?:GetCapabilities|GetFeature|GetMap)\b", 2, "request=GetFeature"),
    ),
    _tech(
        "swagger-openapi", "Swagger UI / OpenAPI docs", "api_docs",
        "A machine-readable spec is published; fetch it for the full endpoint list instead of inferring routes.",
        B(r"swagger-ui", 3, "swagger-ui"),
        U(r"/(?:openapi|swagger)\.(?:json|ya?ml)\b|/v[23]/api-docs", 3, "openapi/swagger spec path"),
        B(r""""(?:openapi|swagger)"\s*:\s*"[23]""", 3, "openapi/swagger version key"),
        B(r"<redoc\b|redoc(?:\.standalone)?(?:\.min)?\.js|\bRedoc\.init\b", 1, "redoc"),
    ),
]

_META: dict[str, dict[str, Any]] = {t["id"]: t for t in CATALOG}
_META["double-encoded-json"] = {
    "id": "double-encoded-json",
    "name": "Double-encoded JSON",
    "category": "data_convention",
    "implication": "Response is a JSON string containing JSON: parse twice (json.loads of the decoded string).",
    "cap": None,
}
_META["named-token-form"] = {
    "id": "named-token-form",
    "name": "Name-indirection token form",
    "category": "auth_stack",
    "implication": "A hidden field's value names the sibling field that carries the token: read it each GET, then post that pair.",
    "cap": None,
}

_COOKIE_NAME = re.compile(r"^\s*([^=;\s]+)\s*=")
_INPUT_TAG = re.compile(r"<input\b[^>]*>", re.I)
_ATTR = re.compile(r"""([\w:-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))""")
_FIELD_NAME = re.compile(r"^[A-Za-z_][\w.\-:$]{2,79}$")


def _score_conf(score: int, cap: str | None) -> str:
    conf = "high" if score >= 3 else "medium" if score == 2 else "low"
    if cap and _CONF_ORDER[conf] < _CONF_ORDER[cap]:
        conf = cap
    return conf


def _named_token_pair(body: str) -> bool:
    """Hidden field whose value is the name of another hidden (token) field."""
    if "<input" not in body.lower():
        return False
    hidden: dict[str, str] = {}
    for tag in _INPUT_TAG.findall(body):
        attrs = {
            m.group(1).lower(): (m.group(2) or m.group(3) or m.group(4) or "")
            for m in _ATTR.finditer(tag)
        }
        if attrs.get("type", "").lower() == "hidden" and attrs.get("name"):
            hidden.setdefault(attrs["name"], attrs.get("value", ""))
    for name, value in hidden.items():
        if value == name or value not in hidden or not _FIELD_NAME.match(value):
            continue
        if "token" in f"{name} {value}".lower():
            return True
    return False


def _double_encoded(body: str) -> int:
    """Weight 3 for a parsed JSON-string-of-JSON, 2 for a truncated preview."""
    s = body.strip()
    if len(s) < 4 or s[0] != '"':
        return 0
    try:
        inner = json.loads(s)
    except ValueError:
        inner = None
    if isinstance(inner, str):
        t = inner.strip()
        if t[:1] in ("{", "["):
            try:
                json.loads(t)
                return 3
            except ValueError:
                return 2 if re.match(r'^[\[{]\s*[{"]', t) else 0
        return 0
    if re.match(r'^"\s*(?:\{\s*\\"|\[\s*\{\s*\\"|\[\s*\\")', s):
        return 2
    return 0


class _Acc:
    """Accumulates distinct signals and entry ids per technology."""

    def __init__(self) -> None:
        self.found: dict[str, dict[str, Any]] = {}

    def hit(self, tid: str, kind: str, label: str, weight: int, entry_id: int | None) -> None:
        rec = self.found.setdefault(tid, {"signals": {}, "entry_ids": []})
        key = (kind, label)
        rec["signals"][key] = max(weight, rec["signals"].get(key, 0))
        if entry_id is not None and entry_id not in rec["entry_ids"]:
            rec["entry_ids"].append(entry_id)

    def scan(
        self,
        *,
        entry_id: int | None,
        url: str,
        headers: list[tuple[str, str]],
        cookies: list[str],
        bodies: list[str],
        response_body: str = "",
    ) -> None:
        texts = [f"{n}: {v}" for n, v in headers if n.lower() not in _SKIP_HEADERS]
        bodies = [b[:_MAX_BODY_CHARS] for b in bodies if b]
        for tech in CATALOG:
            for kind, rx, weight, label in tech["signals"]:
                hit_kind = None
                if kind == "cookie":
                    if any(rx.search(c) for c in cookies):
                        hit_kind = "cookie"
                elif kind == "header":
                    if any(rx.search(t) for t in texts):
                        hit_kind = "header"
                elif kind == "requrl":
                    if url and rx.search(urlsplit(url).path + ("?" if "?" in url else "")):
                        hit_kind = "url"
                elif kind == "url":
                    if url and rx.search(url):
                        hit_kind = "url"
                    elif any(rx.search(b) for b in bodies):
                        hit_kind = "body"
                elif any(rx.search(b) for b in bodies):
                    hit_kind = "body"
                if hit_kind:
                    self.hit(tech["id"], hit_kind, label, weight, entry_id)
        for b in bodies:
            if _named_token_pair(b):
                self.hit("named-token-form", "body", "hidden field value names a sibling field", 3, entry_id)
                break
        w = _double_encoded(response_body[:_MAX_BODY_CHARS]) if response_body else 0
        if w:
            self.hit("double-encoded-json", "body", "JSON string containing JSON", w, entry_id)

    def result(self, *, limit: int | None = None) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for tid, rec in self.found.items():
            meta = _META[tid]
            score = sum(rec["signals"].values())
            out.append(
                {
                    "id": tid,
                    "name": meta["name"],
                    "category": meta["category"],
                    "confidence": _score_conf(score, meta.get("cap")),
                    "score": score,
                    "evidence": [{"kind": k, "match": m} for (k, m) in rec["signals"]],
                    "entry_ids": sorted(rec["entry_ids"])[:_MAX_ENTRY_IDS],
                    "implications": meta["implication"],
                }
            )
        out.sort(key=lambda t: (_CONF_ORDER[t["confidence"]], -t["score"], t["id"]))
        return out[:limit] if limit else out


def _set_cookie_names(value: Any) -> list[str]:
    values = value if isinstance(value, (list, tuple)) else str(value or "").split("\n")
    names: list[str] = []
    for v in values:
        m = _COOKIE_NAME.match(str(v))
        if m and m.group(1) not in names:
            names.append(m.group(1))
    return names


def fingerprint_response(
    status: int, headers: dict[str, Any], body: str, url: str = ""
) -> list[dict[str, Any]]:
    """Fingerprint one response (pure; no I/O). ``headers`` is name -> value."""
    hdrs: list[tuple[str, str]] = []
    cookies: list[str] = []
    for name, value in (headers or {}).items():
        if str(name).lower() == "set-cookie":
            cookies.extend(c for c in _set_cookie_names(value) if c not in cookies)
            continue
        vals = value if isinstance(value, (list, tuple)) else [value]
        hdrs.extend((str(name), str(v)) for v in vals)
    acc = _Acc()
    text = body or ""
    acc.scan(
        entry_id=None, url=url or "", headers=hdrs, cookies=cookies,
        bodies=[text], response_body=text,
    )
    return acc.result()


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    return bool(
        conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
        ).fetchone()
    )


def fingerprint(
    conn: sqlite3.Connection,
    host: str | None = None,
    limit: int = 30,
    explain: bool = False,
) -> dict[str, Any]:
    """Session-level technology fingerprint; SDK implications only with ``explain``."""
    where = "1=1"
    params: list[Any] = []
    if host:
        where = "e.host = ?"
        params.append(host.lower())
    rows = conn.execute(
        f"""
        SELECT e.entry_id, e.scheme, e.host, e.path, e.query_raw
        FROM entries e WHERE {where}
        ORDER BY e.entry_id ASC LIMIT {_MAX_ENTRIES}
        """,
        params,
    ).fetchall()
    ids = {int(r["entry_id"]) for r in rows}

    hdrs: dict[int, list[tuple[str, str]]] = {}
    for r in conn.execute(
        "SELECT entry_id, name, COALESCE(value_raw, value_redacted, '') AS v FROM headers"
    ):
        if r["entry_id"] in ids:
            hdrs.setdefault(int(r["entry_id"]), []).append((r["name"], r["v"]))

    resp_body: dict[int, str] = {}
    other_body: dict[int, list[str]] = {}
    for r in conn.execute(
        "SELECT entry_id, side, preview_text FROM bodies WHERE preview_text IS NOT NULL"
    ):
        eid = int(r["entry_id"])
        if eid not in ids:
            continue
        if r["side"] == "response":
            resp_body[eid] = r["preview_text"]
        else:
            other_body.setdefault(eid, []).append(r["preview_text"])
    double_encoded_ids: list[int] = []
    if _table_exists(conn, "body_signals"):
        try:
            for r in conn.execute("SELECT * FROM body_signals"):
                d = dict(r)
                eid = d.get("entry_id")
                if eid is None or int(eid) not in ids:
                    continue
                # Ingest unwraps double-encoded JSON, so the preview no longer shows it;
                # the ingest-time signal is the evidence.
                if d.get("kind") == "encoding" and d.get("name") == "double-encoded-json":
                    double_encoded_ids.append(int(eid))
                txt = " ".join(
                    str(v) for k, v in d.items() if k != "entry_id" and isinstance(v, str)
                )
                other_body.setdefault(int(eid), []).append(txt)
        except sqlite3.Error:
            pass

    cookies: dict[int, list[str]] = {}
    try:
        tl = cookie_timeline(conn, host=host, limit=120)
        for ev in tl.get("events") or []:
            n = ev.get("name") or ""
            if n and not n.startswith("("):
                cookies.setdefault(int(ev["entry_id"]), []).append(n)
    except Exception:  # noqa: BLE001 - cookie names are best-effort
        pass

    acc = _Acc()
    for eid in double_encoded_ids:
        acc.hit("double-encoded-json", "body", "JSON string containing JSON (ingest signal)", 3, eid)
    for r in rows:
        eid = int(r["entry_id"])
        q = f"?{r['query_raw']}" if r["query_raw"] else ""
        url = f"{r['scheme']}://{r['host']}{r['path']}{q}"
        rb = resp_body.get(eid, "")
        acc.scan(
            entry_id=eid,
            url=url,
            headers=hdrs.get(eid, []),
            cookies=cookies.get(eid, []),
            bodies=([rb] if rb else []) + other_body.get(eid, []),
            response_body=rb,
        )

    techs = acc.result(limit=max(1, min(limit, 60)))
    by_category: dict[str, list[str]] = {}
    notes: list[str] = []
    for t in techs:
        by_category.setdefault(t["category"], []).append(t["id"])
        if t["implications"] not in notes:
            notes.append(t["implications"])
    if not explain:
        for t in techs:
            t.pop("implications", None)
    out = {
        "host": host,
        "technology_count": len(techs),
        "technologies": techs,
        "by_category": by_category,
        "sdk_notes": notes,
        "next": (
            "Names, header names and path fragments only (no values). Use hardly_routes "
            "for JS-bundle APIs, hardly_forms for hidden fields, hardly_credentials for auth."
        ),
    }
    return finish(out, explain, "sdk_notes", "next")
