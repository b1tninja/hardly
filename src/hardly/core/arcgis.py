"""ArcGIS REST service explorer (technology-level, content-neutral).

Offline parsers for service / layer / query JSON, request-shape templates,
URL discovery from web-app configs, an indexed-session summary, and a
confirm-gated live explorer with hard request caps.

Row VALUES are never returned: query samples are reported as field names plus
masked shapes (digits -> 9, letters -> a). Personal-data-looking field names
are flagged, not hidden.
"""

from __future__ import annotations

import json
import re
import sqlite3
import time
from typing import Any
from urllib.parse import parse_qsl, urlsplit

import httpx

SERVER_KINDS = ("MapServer", "FeatureServer", "ImageServer", "GeocodeServer")

# Hard caps for live exploration.
MAX_SERVICE_DOCS = 1
MAX_LAYER_DOCS = 5
MAX_SAMPLE_QUERIES = 1

USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0 Safari/537.36"
)

_PII_RE = re.compile(
    r"(name|owner|phone|tel(?:ephone)?$|mobile|email|e_mail|address|addr|ssn|dob|birth)",
    re.I,
)
_ID_RE = re.compile(r"(^|_)(id|key|oid|fid|guid|uuid|objectid|pin|apn|parcel)$|^(id|oid|fid)(_|$)", re.I)

_SERVICE_URL_RE = re.compile(
    r"https?://[A-Za-z0-9.\-]+(?::\d+)?/[A-Za-z0-9_\-./%%~]*?/(?:%s)(?:/\d+)?(?=[/?#\"'\s\\<>)]|$)"
    % "|".join(SERVER_KINDS),
    re.I,
)
_ITEM_ID_RE = re.compile(r"/sharing/rest/content/items/([0-9a-f]{32})", re.I)
_ITEM_KEY_RE = re.compile(r'"(?:itemId|webmap|webMapId|appid|appId|id)"\s*:\s*"([0-9a-f]{32})"', re.I)
_PORTAL_RE = re.compile(r"https?://([A-Za-z0-9.\-]+)/(?:[A-Za-z0-9_\-]+/)?sharing/rest", re.I)
_HUB_ITEM_RE = re.compile(r"/(?:home|apps|maps|datasets|stories)/(?:item|view|webmap)\.html\?id=([0-9a-f]{32})", re.I)


# ---------------------------------------------------------------- shapes


def mask_value(value: Any) -> str:
    """Return a shape string: digits -> 9, letters -> a. Never the value."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, (int, float)):
        return re.sub(r"\d", "9", str(value))
    if isinstance(value, (dict, list)):
        return "object" if isinstance(value, dict) else "array"
    text = str(value)
    if len(text) > 40:
        text = text[:40] + "..."
    return re.sub(r"[A-Za-z]", "a", re.sub(r"\d", "9", text))


def flag_field(name: str, field_type: str | None = None) -> list[str]:
    flags: list[str] = []
    n = name or ""
    if _PII_RE.search(n):
        flags.append("personal_data_like")
    if _ID_RE.search(n) or (field_type or "") in {"esriFieldTypeOID", "esriFieldTypeGlobalID", "esriFieldTypeGUID"}:
        flags.append("id_or_key")
    return flags


def _json(obj: Any) -> dict:
    if isinstance(obj, (str, bytes)):
        try:
            obj = json.loads(obj)
        except (ValueError, TypeError):
            return {}
    return obj if isinstance(obj, dict) else {}


def token_gate(obj: Any) -> dict | None:
    """Detect ArcGIS error envelope requiring a token (498/499)."""
    err = _json(obj).get("error")
    if isinstance(err, dict):
        code = err.get("code")
        if code in (498, 499):
            return {
                "gate": "token_required",
                "code": code,
                "message": str(err.get("message", ""))[:120],
                "note": "Stop. Do not guess or brute-force tokens.",
            }
    return None


def error_info(obj: Any) -> dict | None:
    err = _json(obj).get("error")
    if isinstance(err, dict):
        return {"code": err.get("code"), "message": str(err.get("message", ""))[:160]}
    return None


# ---------------------------------------------------------------- parsers


def parse_service(data: Any) -> dict:
    d = _json(data)
    gate = token_gate(d)
    if gate:
        return gate
    sr = d.get("spatialReference") or {}
    return {
        "layers": [
            {"id": x.get("id"), "name": x.get("name"), "parentLayerId": x.get("parentLayerId")}
            for x in d.get("layers", []) or []
            if isinstance(x, dict)
        ],
        "tables": [
            {"id": x.get("id"), "name": x.get("name")}
            for x in d.get("tables", []) or []
            if isinstance(x, dict)
        ],
        "capabilities": [c.strip() for c in str(d.get("capabilities", "")).split(",") if c.strip()],
        "spatialReference": {
            k: sr.get(k) for k in ("wkid", "latestWkid") if sr.get(k) is not None
        },
        "maxRecordCount": d.get("maxRecordCount"),
        "serviceDescription_present": bool(d.get("serviceDescription")),
    }


def parse_layer(data: Any) -> dict:
    d = _json(data)
    gate = token_gate(d)
    if gate:
        return gate
    caps = [c.strip() for c in str(d.get("capabilities", "")).split(",") if c.strip()]
    fields = []
    for f in d.get("fields", []) or []:
        if not isinstance(f, dict):
            continue
        item: dict[str, Any] = {
            "name": f.get("name"),
            "alias": f.get("alias"),
            "type": f.get("type"),
            "length": f.get("length"),
        }
        dom = f.get("domain")
        if isinstance(dom, dict):
            coded = dom.get("codedValues")
            item["domain"] = {
                "type": dom.get("type"),
                "name": dom.get("name"),
                "coded_value_count": len(coded) if isinstance(coded, list) else None,
            }
        flags = flag_field(str(f.get("name") or ""), f.get("type"))
        if flags:
            item["flags"] = flags
        fields.append(item)
    formats = d.get("supportedQueryFormats")
    if isinstance(formats, str):
        formats = [x.strip() for x in formats.split(",") if x.strip()]
    adv = d.get("advancedQueryCapabilities") or {}
    oid = d.get("objectIdField") or next(
        (f["name"] for f in fields if f.get("type") == "esriFieldTypeOID"), None
    )
    return {
        "id": d.get("id"),
        "name": d.get("name"),
        "type": d.get("type"),
        "geometryType": d.get("geometryType"),
        "fields": fields,
        "objectIdField": oid,
        "displayField": d.get("displayField"),
        "maxRecordCount": d.get("maxRecordCount"),
        "supportsPagination": bool(adv.get("supportsPagination")) if adv else None,
        "supportedQueryFormats": formats,
        "capabilities": caps,
        "queryable": "Query" in caps,
        "personal_data_fields": [f["name"] for f in fields if "personal_data_like" in f.get("flags", [])],
    }


def summarise_query_response(data: Any) -> dict:
    d = _json(data)
    gate = token_gate(d)
    if gate:
        return gate
    err = error_info(d)
    if err:
        return {"error": err}
    feats = d.get("features")
    fields = d.get("fields") or []
    field_names = [f.get("name") for f in fields if isinstance(f, dict)]
    shapes: dict[str, str] = {}
    has_geom = False
    if isinstance(feats, list) and feats and isinstance(feats[0], dict):
        attrs = feats[0].get("attributes") or {}
        for k, v in attrs.items():
            shapes[str(k)] = mask_value(v)
        has_geom = feats[0].get("geometry") is not None
        if not field_names:
            field_names = list(attrs)
    out: dict[str, Any] = {
        "feature_count": len(feats) if isinstance(feats, list) else None,
        "field_names": field_names,
        "first_row_shapes": shapes,
        "geometry_present": has_geom,
        "geometryType": d.get("geometryType"),
        "flags": {
            n: flag_field(str(n))
            for n in field_names
            if n and flag_field(str(n))
        },
    }
    if "count" in d and "features" not in d:
        out["count_only"] = True
        out["count"] = d.get("count") if isinstance(d.get("count"), int) else None
    if d.get("exceededTransferLimit"):
        out["exceededTransferLimit"] = True
        out["paging_note"] = (
            "exceededTransferLimit=true: more rows exist than returned. Page with "
            "resultOffset/resultRecordCount (if supportsPagination) or by objectId ranges."
        )
    return out


# ---------------------------------------------------------------- templates


def query_templates(layer_url: str, layer: dict | None = None) -> dict:
    """Suggested request shapes. Names only; `<WHERE>` is the where placeholder."""
    layer = layer or {}
    base = layer_url.split("?")[0].rstrip("/")
    q = f"{base}/query"
    oid = layer.get("objectIdField") or "<OBJECTID_FIELD>"
    maxrc = layer.get("maxRecordCount")
    templates = {
        "attribute_query": {
            "method": "GET",
            "url": q,
            "params": {
                "where": "<WHERE>",
                "outFields": "*",
                "returnGeometry": "false",
                "f": "json",
                "resultOffset": "0",
                "resultRecordCount": str(maxrc or "<N <= maxRecordCount>"),
                "orderByFields": oid,
            },
        },
        "count_only": {
            "method": "GET",
            "url": q,
            "params": {"where": "<WHERE>", "returnCountOnly": "true", "f": "json"},
        },
        "distinct_values": {
            "method": "GET",
            "url": q,
            "params": {
                "where": "<WHERE>",
                "outFields": "<FIELD>",
                "returnDistinctValues": "true",
                "returnGeometry": "false",
                "f": "json",
            },
        },
        "objectid_paging_fallback": {
            "method": "GET",
            "url": q,
            "params": {
                "where": f"{oid} > <LAST_OBJECTID> AND (<WHERE>)",
                "outFields": "*",
                "returnGeometry": "false",
                "orderByFields": oid,
                "f": "json",
            },
            "use_when": "server lacks supportsPagination; repeat with last seen objectId",
        },
    }
    if layer.get("supportsPagination") is False:
        recommended = "objectid_paging_fallback"
    else:
        recommended = "attribute_query"
    return {
        "layer_url": base,
        "templates": templates,
        "recommended": recommended,
        "notes": [
            f"maxRecordCount={maxrc}: a page never returns more rows than this." if maxrc
            else "maxRecordCount unknown: read it from the layer document.",
            "If the response has exceededTransferLimit=true, more rows exist: keep paging.",
            "Use where=1=1 only with a small resultRecordCount; prefer returnCountOnly first.",
            "A 498/499 error means a token is required: stop.",
        ],
    }


# ---------------------------------------------------------------- discovery


def _classify_text(text: str, urls: list[str], item_ids: list[str]) -> str:
    low = text[:200000]
    if '"dataSources"' in low and ('"widgets"' in low or '"pages"' in low or '"layouts"' in low):
        return "experience_builder_config"
    if '"operationalLayers"' in low and ('"map"' in low or '"widgetPool"' in low or '"layers"' in low):
        return "web_app_builder_config"
    if '"operationalLayers"' in low:
        return "web_map_data"
    if _ITEM_ID_RE.search(low):
        return "portal_item_reference"
    if urls:
        return "service_urls"
    return "item_ids" if item_ids else "none"


def find_service_urls(text: str) -> dict:
    """Extract ArcGIS service/layer URLs and item ids from text. Fetches nothing."""
    text = (text or "").replace("\\/", "/")
    urls: list[str] = []
    for m in _SERVICE_URL_RE.finditer(text):
        u = m.group(0).rstrip("/")
        if u not in urls:
            urls.append(u)
    item_ids: list[str] = []
    for rx in (_ITEM_ID_RE, _ITEM_KEY_RE, _HUB_ITEM_RE):
        for m in rx.finditer(text):
            i = m.group(1).lower()
            if i not in item_ids:
                item_ids.append(i)
    portals: list[str] = []
    for m in _PORTAL_RE.finditer(text):
        h = m.group(1).lower()
        if h not in portals:
            portals.append(h)
    portal_hint = portals[0] if portals else "<portal-host>"
    return {
        "kind": _classify_text(text, urls, item_ids),
        "urls": urls,
        "item_ids": item_ids,
        "portal_hosts": portals,
        "item_data_url_template": f"https://{portal_hint}/sharing/rest/content/items/<item_id>/data?f=json",
        "item_data_urls": [
            f"https://{portal_hint}/sharing/rest/content/items/{i}/data?f=json" for i in item_ids
        ],
        "note": (
            "Nothing was fetched. Item ids resolve to config via the item data URL "
            "(web maps list operationalLayers[].url; Experience Builder lists "
            "dataSources[].url / itemId). Public items need no token."
        ),
    }


# ---------------------------------------------------------------- session


def _split_service(path: str) -> tuple[str, int | None, str] | None:
    m = re.match(
        r"^(?P<root>.*?/(?P<kind>%s))(?:/(?P<layer>\d+))?(?:/(?P<op>[A-Za-z]+))?/?$"
        % "|".join(SERVER_KINDS),
        path,
        re.I,
    )
    if not m:
        return None
    layer = int(m.group("layer")) if m.group("layer") else None
    return m.group("root"), layer, (m.group("op") or "").lower()


def summarize_session(conn: sqlite3.Connection, host: str | None = None) -> dict:
    sql = "SELECT entry_id, host, path, query_json, status FROM entries WHERE (path LIKE '%MapServer%' OR path LIKE '%FeatureServer%' OR path LIKE '%ImageServer%' OR path LIKE '%GeocodeServer%')"
    args: list[Any] = []
    if host:
        sql += " AND host = ?"
        args.append(host)
    rows = conn.execute(sql, args).fetchall()
    services: dict[str, dict] = {}
    for r in rows:
        sp = _split_service(r["path"])
        if not sp:
            continue
        root, layer, op = sp
        key = f"{r['host']}{root}"
        s = services.setdefault(
            key,
            {
                "service_root": key,
                "layer_ids_seen": set(),
                "layers_queried": set(),
                "param_names": set(),
                "paging_evidence": set(),
                "exceededTransferLimit_seen": False,
                "entry_ids": [],
                "statuses": set(),
            },
        )
        if layer is not None:
            s["layer_ids_seen"].add(layer)
        params: dict = {}
        try:
            params = json.loads(r["query_json"]) if r["query_json"] else {}
        except (ValueError, TypeError):
            pass
        names = {str(k) for k in params} if isinstance(params, dict) else set()
        body = conn.execute(
            "SELECT preview_text FROM bodies WHERE entry_id=? AND side='request'", (r["entry_id"],)
        ).fetchone()
        if body and body["preview_text"] and "=" in body["preview_text"][:2000] and not body["preview_text"].lstrip().startswith(("{", "[")):
            names |= {k for k, _ in parse_qsl(body["preview_text"][:2000], keep_blank_values=True)}
        if op == "query":
            if layer is not None:
                s["layers_queried"].add(layer)
            s["param_names"] |= names
            for p in ("resultOffset", "resultRecordCount", "orderByFields"):
                if p in names:
                    s["paging_evidence"].add(p)
            if "objectIds" in names:
                s["paging_evidence"].add("objectIds")
        if r["status"] is not None:
            s["statuses"].add(r["status"])
        if len(s["entry_ids"]) < 10:
            s["entry_ids"].append(r["entry_id"])
        resp = conn.execute(
            "SELECT preview_text FROM bodies WHERE entry_id=? AND side='response'", (r["entry_id"],)
        ).fetchone()
        if resp and resp["preview_text"] and "exceededTransferLimit" in resp["preview_text"]:
            if re.search(r'"exceededTransferLimit"\s*:\s*true', resp["preview_text"]):
                s["exceededTransferLimit_seen"] = True
    out = []
    for s in sorted(services.values(), key=lambda x: x["service_root"]):
        out.append(
            {
                **s,
                "layer_ids_seen": sorted(s["layer_ids_seen"]),
                "layers_queried": sorted(s["layers_queried"]),
                "param_names": sorted(s["param_names"]),
                "paging_evidence": sorted(s["paging_evidence"]),
                "statuses": sorted(s["statuses"]),
            }
        )
    return {"service_count": len(out), "services": out, "host_filter": host}


# ---------------------------------------------------------------- live


def looks_like_arcgis(url: str) -> bool:
    return bool(re.search(r"/(?:%s)(?:/\d+)?/?$" % "|".join(SERVER_KINDS), urlsplit(url).path, re.I)) and url.lower().startswith(("http://", "https://"))


def explore(
    url: str,
    confirm: bool = False,
    client: httpx.Client | None = None,
    *,
    delay: float = 0.5,
    timeout: float = 20.0,
) -> dict:
    """Confirm-gated, capped live exploration of an ArcGIS REST service or layer URL."""
    if not confirm:
        return {
            "error": "explore requires confirm=true",
            "hint": "Makes up to 1 service doc + 5 layer docs + 1 sample query (resultRecordCount=1) GET requests.",
        }
    url = (url or "").split("?")[0].split("#")[0].rstrip("/")
    if not looks_like_arcgis(url):
        return {
            "error": "URL does not look like an ArcGIS REST service",
            "hint": "Expected .../(MapServer|FeatureServer|ImageServer|GeocodeServer)[/<layerId>]",
        }
    sp = _split_service(urlsplit(url).path)
    if not sp or sp[2]:
        return {"error": "Pass the service root or a layer URL, not an operation URL"}
    own = client is None
    if own:
        client = httpx.Client(timeout=timeout, headers={"User-Agent": USER_AGENT}, follow_redirects=False)
    requests_made: list[str] = []
    result: dict[str, Any] = {"url": url, "requests": requests_made, "layers": []}

    def get(u: str, params: dict[str, str]) -> tuple[dict | None, dict | None]:
        """Returns (json, stop_info). stop_info set on 429/HTTP/network/token problems."""
        if requests_made:
            time.sleep(delay)
        requests_made.append(f"GET {u.split('://', 1)[-1].split('/', 1)[-1][:80]} params={sorted(params)}")
        try:
            resp = client.get(u, params=params, headers={"User-Agent": USER_AGENT})
        except httpx.HTTPError as exc:
            return None, {"stopped": "network_error", "detail": type(exc).__name__}
        if resp.status_code == 429:
            return None, {"stopped": "rate_limited", "retry_after": resp.headers.get("Retry-After")}
        if resp.status_code >= 400:
            return None, {"stopped": "http_error", "status": resp.status_code}
        try:
            data = resp.json()
        except ValueError:
            return None, {"stopped": "non_json_response", "status": resp.status_code}
        gate = token_gate(data)
        if gate:
            return None, gate
        err = error_info(data)
        if err:
            return None, {"stopped": "service_error", **err}
        return data, None

    try:
        layer_ids: list[int] = []
        service_info: dict | None = None
        if sp[1] is None:
            data, stop = get(url, {"f": "json"})
            if stop:
                result["stop"] = stop
                return result
            service_info = parse_service(data)
            result["service"] = service_info
            layer_ids = [x["id"] for x in service_info["layers"] if isinstance(x.get("id"), int)]
            layer_ids += [x["id"] for x in service_info["tables"] if isinstance(x.get("id"), int)]
            layer_ids = layer_ids[:MAX_LAYER_DOCS]
            if len(service_info["layers"]) + len(service_info["tables"]) > MAX_LAYER_DOCS:
                result["note"] = f"Only first {MAX_LAYER_DOCS} layer docs fetched (cap)."
            base = url
        else:
            layer_ids = [sp[1]]
            base = url.rsplit("/", 1)[0]
        sample_target: tuple[str, dict] | None = None
        for lid in layer_ids:
            lurl = f"{base}/{lid}"
            data, stop = get(lurl, {"f": "json"})
            if stop:
                result["stop"] = stop
                break
            parsed = parse_layer(data)
            parsed["templates"] = query_templates(lurl, parsed)
            result["layers"].append(parsed)
            if sample_target is None and parsed["queryable"]:
                sample_target = (lurl, parsed)
        if sample_target and "stop" not in result:
            lurl, parsed = sample_target
            data, stop = get(
                f"{lurl}/query",
                {
                    "where": "1=1",
                    "outFields": "*",
                    "returnGeometry": "false",
                    "resultRecordCount": "1",
                    "f": "json",
                },
            )
            if stop:
                result["sample_stop"] = stop
            else:
                result["sample"] = {"layer_url": lurl, **summarise_query_response(data)}
        result["caps"] = {
            "service_docs": MAX_SERVICE_DOCS,
            "layer_docs": MAX_LAYER_DOCS,
            "sample_queries": MAX_SAMPLE_QUERIES,
            "requests_made": len(requests_made),
        }
        return result
    finally:
        if own:
            client.close()
