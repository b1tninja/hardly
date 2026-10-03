"""Generic auth-pattern detectors (names and shapes only, never values).

Detects, from a HAR: bearer/refresh-token JSON logins, OIDC/PKCE
authorization-code flows, SAML POST binding, double-submit CSRF and
signed-request headers. Secret values are compared in memory only and are
never returned; output carries field/header/cookie names, shapes, lengths,
booleans and entry ids.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import zlib
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlparse

import ijson

from hardly.core.credentials import _cookie_pairs
from hardly.core.redact import classify_value_shape

KINDS = ("bearer_refresh", "oidc_pkce", "saml_post", "double_submit_csrf", "signed_requests")

_ACCESS_KEYS = ("access_token", "accesstoken", "token", "id_token", "idtoken", "jwt", "auth_token")
_REFRESH_KEYS = ("refresh_token", "refreshtoken")
_EXPIRY_KEYS = ("expires_in", "expiresin", "expires_at", "expiry")
_MAX_BODY = 2_000_000


# ---------------------------------------------------------------- loading

def _hdrs(items: list[dict] | None) -> list[tuple[str, str]]:
    return [(str(h.get("name") or ""), str(h.get("value") or "")) for h in items or []]


def _params_of(req: dict) -> tuple[dict[str, str], str]:
    """Body parameters (form or flat JSON) -> ({name: value}, kind)."""
    pd = req.get("postData") or {}
    mime = (pd.get("mimeType") or "").lower()
    if pd.get("params"):
        return {str(p.get("name")): str(p.get("value") or "") for p in pd["params"]}, "form"
    text = pd.get("text") or ""
    if not text or len(text) > _MAX_BODY:
        return {}, ""
    if "json" in mime or text.lstrip().startswith("{"):
        try:
            data = json.loads(text)
        except ValueError:
            return {}, ""
        if isinstance(data, dict):
            return {str(k): v if isinstance(v, str) else json.dumps(v)[:200] for k, v in data.items()}, "json"
        return {}, ""
    if "x-www-form-urlencoded" in mime or "=" in text:
        return dict(parse_qsl(text, keep_blank_values=True)), "form"
    return {}, ""


def _load(har_path: str | Path, host: str | None) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    with Path(har_path).open("rb") as f:
        for i, e in enumerate(ijson.items(f, "log.entries.item")):
            req, resp = e.get("request") or {}, e.get("response") or {}
            u = urlparse(req.get("url") or "")
            if host and u.netloc.lower() != host.lower():
                continue
            content = resp.get("content") or {}
            text = content.get("text") or ""
            if content.get("encoding") == "base64" and text:
                try:
                    text = base64.b64decode(text).decode("utf-8", "replace")
                except (binascii.Error, ValueError):
                    text = ""
            if len(text) > _MAX_BODY:
                text = ""
            rjson = None
            if text.lstrip()[:1] in ("{", "["):
                try:
                    rjson = json.loads(text)
                except ValueError:
                    pass
            body, bkind = _params_of(req)
            out.append(
                {
                    "id": i,
                    "method": (req.get("method") or "GET").upper(),
                    "url": req.get("url") or "",
                    "host": u.netloc.lower(),
                    "path": u.path or "/",
                    "query": dict(parse_qsl(u.query, keep_blank_values=True)),
                    "status": resp.get("status"),
                    "req_headers": _hdrs(req.get("headers")),
                    "resp_headers": _hdrs(resp.get("headers")),
                    "req_cookies": [(c.get("name", ""), str(c.get("value", ""))) for c in req.get("cookies") or []],
                    "body": body,
                    "body_kind": bkind,
                    "req_mime": ((req.get("postData") or {}).get("mimeType") or "").lower(),
                    "text": text,
                    "json": rjson,
                    "mime": (content.get("mimeType") or "").lower(),
                }
            )
    return out


def _h(e: dict, side: str, name: str) -> list[str]:
    return [v for n, v in e[f"{side}_headers"] if n.lower() == name]


def _where(e: dict) -> dict[str, Any]:
    return {"entry_id": e["id"], "method": e["method"], "host": e["host"], "path": e["path"]}


def _flat_json(obj: Any, depth: int = 0) -> dict[str, str]:
    """Flatten string leaves of nested JSON (depth<=3) to {lower_key: value}."""
    out: dict[str, str] = {}
    if depth > 3:
        return out
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, str):
                out.setdefault(str(k).lower(), v)
            elif isinstance(v, (dict, list)):
                for kk, vv in _flat_json(v, depth + 1).items():
                    out.setdefault(kk, vv)
    elif isinstance(obj, list):
        for v in obj[:5]:
            for kk, vv in _flat_json(v, depth + 1).items():
                out.setdefault(kk, vv)
    return out


def _shape(v: str) -> str:
    return classify_value_shape(v) or ("opaque" if v else "empty")


def _origin(u: str) -> str | None:
    p = urlparse(u)
    return f"{p.scheme}://{p.netloc}" if p.netloc else (p.scheme + ":" if p.scheme else None)


def _is_loopback(u: str) -> bool:
    return (urlparse(u).hostname or "").lower() in ("localhost", "127.0.0.1", "::1")


# ------------------------------------------------- 1. bearer / refresh JSON

def detect_bearer_refresh(entries: list[dict]) -> dict[str, Any]:
    issued: list[dict] = []  # internal only; holds values
    for e in entries:
        if e["method"] != "POST" or (e["status"] or 0) >= 300 or not isinstance(e["json"], (dict, list)):
            continue
        flat = _flat_json(e["json"])
        acc = next((k for k in _ACCESS_KEYS if flat.get(k)), None)
        ref = next((k for k in _REFRESH_KEYS if flat.get(k)), None)
        if acc or ref:
            issued.append({"e": e, "acc": acc, "ref": ref, "flat": flat})
    if not issued:
        return {"detected": False, "token_endpoints": [], "refresh_flows": []}

    endpoints: dict[tuple[str, str], dict[str, Any]] = {}
    for it in issued:
        e, flat = it["e"], it["flat"]
        ep = endpoints.setdefault(
            (e["host"], e["path"]),
            {
                "host": e["host"],
                "path": e["path"],
                "entry_ids": [],
                "access_field": it["acc"],
                "refresh_field": it["ref"],
                "access_shape": _shape(flat.get(it["acc"] or "", "")) if it["acc"] else None,
                "refresh_shape": _shape(flat.get(it["ref"] or "", "")) if it["ref"] else None,
                "expiry_fields": sorted(k for k in flat if k in _EXPIRY_KEYS),
                "request_fields": sorted(e["body"]),
                "uses": {},
            },
        )
        ep["entry_ids"].append(e["id"])
        if isinstance(e["json"], dict):
            for k in _EXPIRY_KEYS:
                if k in e["json"] and k not in ep["expiry_fields"]:
                    ep["expiry_fields"].append(k)

    for it in issued:
        if not it["acc"]:
            continue
        tok = it["flat"][it["acc"]]
        if len(tok) < 8:
            continue
        ep = endpoints[(it["e"]["host"], it["e"]["path"])]
        for e in entries:
            if e["id"] <= it["e"]["id"]:
                continue
            for n, v in e["req_headers"]:
                if tok in v:
                    use = ep["uses"].setdefault(
                        n.lower(),
                        {"header": n.lower(), "scheme": v.split(" ", 1)[0] if " " in v else None, "count": 0, "paths": []},
                    )
                    use["count"] += 1
                    if e["path"] not in use["paths"] and len(use["paths"]) < 10:
                        use["paths"].append(e["path"])
    for ep in endpoints.values():
        ep["uses"] = list(ep["uses"].values())

    flows: list[dict[str, Any]] = []
    issued_refresh = {it["flat"][it["ref"]]: it for it in issued if it["ref"]}
    for e in entries:
        grant = e["body"].get("grant_type")
        sent = next((k for k in e["body"] if k.lower() in _REFRESH_KEYS), None)
        sent_val = e["body"].get(sent) if sent else None
        if grant != "refresh_token" and not (sent_val and sent_val in issued_refresh):
            continue
        origin = issued_refresh.get(sent_val)
        new = next((it for it in issued if it["e"]["id"] == e["id"]), None)
        rotated = bool(new and new["ref"] and sent_val and new["flat"][new["ref"]] != sent_val)
        prev401 = [x for x in entries if x["id"] < e["id"] and x["status"] == 401]
        flows.append(
            {
                **_where(e),
                "grant_type": grant,
                "refresh_field": sent,
                "body_kind": e["body_kind"],
                "refresh_matches_issued": bool(origin),
                "issued_by_entry": origin["e"]["id"] if origin else None,
                "response_status": e["status"],
                "issues_new_access": bool(new and new["acc"]),
                "rotates_refresh": rotated,
                "follows_401": bool(prev401) and prev401[-1]["id"] >= e["id"] - 3,
            }
        )
    return {"detected": True, "token_endpoints": list(endpoints.values()), "refresh_flows": flows}


# ---------------------------------------------------------- 2. OIDC / PKCE

def _b64url_sha256(v: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).rstrip(b"=").decode()


def detect_oidc_pkce(entries: list[dict]) -> dict[str, Any]:
    auths, callbacks, exchanges = [], [], []
    for e in entries:
        q = e["query"]
        is_auth = bool(q.get("response_type") and q.get("client_id") and ("redirect_uri" in q or "scope" in q))
        if is_auth:
            auths.append(e)
        loc = next(iter(_h(e, "resp", "location")), "")
        if loc:
            lq = dict(parse_qsl(urlparse(loc).query, keep_blank_values=True))
            if "code" in lq and "state" in lq:
                callbacks.append((e, lq))
        if "code" in q and "state" in q and not is_auth:
            callbacks.append((e, q))
        if e["body"].get("grant_type") == "authorization_code":
            exchanges.append(e)
    if not auths and not exchanges:
        return {"detected": False, "flows": []}

    flows = []
    for a in auths:
        q = a["query"]
        scopes = q.get("scope", "").split()
        flow: dict[str, Any] = {
            **_where(a),
            "response_type": q.get("response_type"),
            "params_present": sorted(
                k
                for k in q
                if k in ("client_id", "redirect_uri", "scope", "state", "nonce", "code_challenge",
                         "code_challenge_method", "response_mode", "prompt", "login_hint")
            ),
            "oidc": "openid" in scopes or "nonce" in q,
            "scope_names": scopes[:12],
            "pkce": "code_challenge" in q,
            "pkce_method": q.get("code_challenge_method"),
            "state_shape": _shape(q["state"]) if "state" in q else None,
            "nonce_shape": _shape(q["nonce"]) if "nonce" in q else None,
            "redirect_uri_origin": _origin(q.get("redirect_uri", "")),
            "loopback_redirect": _is_loopback(q.get("redirect_uri", "")),
        }
        later = [(c, cq) for c, cq in callbacks if c["id"] >= a["id"]]
        flow["callback_entry"] = later[0][0]["id"] if later else None
        flow["state_roundtrip"] = bool(later and "state" in q and later[0][1].get("state") == q["state"])
        ex = next((x for x in exchanges if x["id"] >= a["id"]), None)
        if ex:
            b = ex["body"]
            ver = b.get("code_verifier")
            verified: bool | None = None
            if ver and "code_challenge" in q:
                if q.get("code_challenge_method", "plain") == "S256":
                    verified = _b64url_sha256(ver) == q["code_challenge"]
                else:
                    verified = ver == q["code_challenge"]
            flow["token_exchange"] = {
                **_where(ex),
                "fields": sorted(b),
                "has_code_verifier": bool(ver),
                "verifier_length": len(ver) if ver else None,
                "verifier_matches_challenge": verified,
                "code_matches_callback": bool(later and b.get("code") and b["code"] == later[0][1].get("code")),
                "client_auth": "client_secret_post" if "client_secret" in b else (
                    "client_secret_basic"
                    if any(v.lower().startswith("basic ") for v in _h(ex, "req", "authorization"))
                    else "none_or_public"
                ),
                "response_token_fields": sorted(
                    k for k in _flat_json(ex["json"])
                    if k in ("access_token", "refresh_token", "id_token", "expires_in", "token_type", "scope")
                ),
            }
        flows.append(flow)
    if not auths:
        for ex in exchanges:
            flows.append({**_where(ex), "authorize_leg_captured": False,
                          "token_exchange": {"fields": sorted(ex["body"]), "has_code_verifier": "code_verifier" in ex["body"]}})
    return {"detected": True, "flows": flows}


# ------------------------------------------------------------ 3. SAML POST

_FORM_RE = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.I | re.S)
_INPUT_RE = re.compile(r"<input\b[^>]*>", re.I)


def _saml_shape(v: str) -> dict[str, Any]:
    info: dict[str, Any] = {"length": len(v)}
    try:
        raw = base64.b64decode(v + "=" * (-len(v) % 4))
    except (binascii.Error, ValueError):
        return {**info, "encoding": "unknown"}
    candidates = [("base64", raw)]
    try:
        candidates.append(("base64+deflate", zlib.decompress(raw, -15)))
    except zlib.error:
        pass
    for enc, data in candidates:
        m = re.search(rb"<(?:\w+:)?(AuthnRequest|Response|LogoutRequest|LogoutResponse)\b", data)
        if m:
            return {**info, "encoding": enc, "root": m.group(1).decode(), "signed": b"Signature" in data,
                    "encrypted_assertion": b"EncryptedAssertion" in data}
    return {**info, "encoding": "unknown"}


def detect_saml_post(entries: list[dict]) -> dict[str, Any]:
    hits = []
    for e in entries:
        body = e["body"]
        if e["method"] == "POST" and ("SAMLRequest" in body or "SAMLResponse" in body):
            kind = "SAMLRequest" if "SAMLRequest" in body else "SAMLResponse"
            hits.append({
                **_where(e), "direction": "request_form_post", "message": kind, "fields": sorted(body),
                "relay_state": "RelayState" in body,
                "relay_state_shape": _shape(body["RelayState"]) if "RelayState" in body else None,
                "payload": _saml_shape(body[kind]), "response_status": e["status"],
                "redirect_after": bool(_h(e, "resp", "location")),
            })
        for k in ("SAMLRequest", "SAMLResponse"):
            if k in e["query"]:
                hits.append({**_where(e), "direction": "redirect_binding_query", "message": k,
                             "fields": sorted(e["query"]), "relay_state": "RelayState" in e["query"],
                             "payload": _saml_shape(e["query"][k]), "response_status": e["status"]})
        if "html" in e["mime"] and e["text"]:
            for m in _FORM_RE.finditer(e["text"]):
                inputs = "".join(_INPUT_RE.findall(m.group(2)))
                names = re.findall(r"""name\s*=\s*["']([^"']+)["']""", inputs, re.I)
                kind = "SAMLRequest" if "SAMLRequest" in names else ("SAMLResponse" if "SAMLResponse" in names else None)
                if not kind:
                    continue
                act = re.search(r"""action\s*=\s*["']([^"']*)["']""", m.group(1), re.I)
                val = re.search(r"""name\s*=\s*["']%s["'][^>]*value\s*=\s*["']([^"']*)["']""" % kind, inputs, re.I)
                hits.append({
                    **_where(e), "direction": "auto_post_form_in_html", "message": kind,
                    "fields": sorted(set(names)), "relay_state": "RelayState" in names,
                    "form_action_origin": _origin(act.group(1)) if act else None,
                    "form_action_path": urlparse(act.group(1)).path if act else None,
                    "payload": _saml_shape(val.group(1)) if val else None,
                })
    return {"detected": bool(hits), "messages": hits}


# -------------------------------------------------- 4. double-submit CSRF

_CSRF_NAME = re.compile(r"csrf|xsrf|anti-?forgery", re.I)
_SKIP_HDRS = {"cookie", "set-cookie", "authorization", "user-agent", "referer", "origin", "host", "accept"}


def _req_cookies(e: dict) -> dict[str, str]:
    ck: dict[str, str] = dict(e["req_cookies"])
    for ch in _h(e, "req", "cookie"):
        for part in ch.split(";"):
            n, _, v = part.strip().partition("=")
            if n:
                ck[n] = v
    return ck


def detect_double_submit_csrf(entries: list[dict]) -> dict[str, Any]:
    set_by: dict[str, dict] = {}
    for e in entries:
        for sc in _h(e, "resp", "set-cookie"):
            pairs = _cookie_pairs(sc)
            if pairs:
                ss = re.search(r"samesite=(\w+)", sc, re.I)
                set_by.setdefault(pairs[0][0], {
                    "entry_id": e["id"], "http_only": bool(re.search(r"httponly", sc, re.I)),
                    "samesite": ss.group(1) if ss else None})
    found: dict[tuple[str, str], dict[str, Any]] = {}
    for e in entries:
        ck = _req_cookies(e)
        if not ck:
            continue
        for hn, hv in e["req_headers"]:
            if hn.lower() in _SKIP_HDRS or hn.startswith(":") or len(hv) < 8:
                continue
            for cn, cv in ck.items():
                if cv and hv.strip('"') == cv.strip('"'):
                    meta = set_by.get(cn) or {}
                    rec = found.setdefault((cn, hn.lower()), {
                        "cookie": cn, "header": hn.lower(),
                        "name_looks_csrf": bool(_CSRF_NAME.search(cn + hn)),
                        "cookie_set_by_entry": meta.get("entry_id"),
                        "cookie_http_only": meta.get("http_only"),
                        "cookie_samesite": meta.get("samesite"),
                        "value_shape": _shape(cv), "value_length": len(cv),
                        "entry_ids": [], "methods": set(), "json_requests": 0})
                    rec["entry_ids"].append(e["id"])
                    rec["methods"].add(e["method"])
                    rec["json_requests"] += "json" in e["req_mime"]
    out = []
    for r in found.values():
        if not (r["name_looks_csrf"] or r["header"].startswith("x-")):
            continue
        r["methods"] = sorted(r["methods"])
        r["count"] = len(r["entry_ids"])
        r["entry_ids"] = r["entry_ids"][:20]
        out.append(r)
    return {"detected": bool(out), "pairs": out}


# ----------------------------------------------------- 5. signed requests

_SIG_NAME = re.compile(r"sig(nature)?|hmac|digest|(^|-)mac$", re.I)
_TS_NAME = re.compile(r"timestamp|(^|-)ts$|(^|-)time$", re.I)
_NONCE_NAME = re.compile(r"nonce|(^|-)jti$", re.I)
_SIG_SCHEMES = re.compile(r"^(HMAC[\w-]*|AWS4-HMAC-SHA\d+|Signature|Hawk|HS\d+)\b", re.I)


def _ts_shape(v: str) -> str | None:
    if re.fullmatch(r"\d{10}", v):
        return "epoch_s"
    if re.fullmatch(r"\d{13}", v):
        return "epoch_ms"
    if re.fullmatch(r"\d{4}-\d\d-\d\dT[\d:.]+Z?", v):
        return "iso8601"
    if re.fullmatch(r"\d{8}T\d{6}Z", v):
        return "iso8601_basic"
    return None


def _sig_shape(v: str) -> str:
    if re.fullmatch(r"(sha\d+=)?[0-9a-fA-F]{32,}", v):
        return f"hex{len(v.split('=')[-1])}"
    if re.fullmatch(r"[A-Za-z0-9+/_-]{20,}={0,2}", v):
        return f"base64_len{len(v)}"
    return _shape(v)


def detect_signed_requests(entries: list[dict]) -> dict[str, Any]:
    groups: dict[tuple, dict[str, Any]] = {}
    for e in entries:
        found: dict[str, tuple[str, str, str]] = {}  # role -> (location, name, value)
        for n, v in e["req_headers"]:
            ln = n.lower()
            if ln == "authorization":
                m = _SIG_SCHEMES.match(v)
                if m:
                    found["auth_scheme"] = ("header", ln, m.group(1).upper())
                    for key in ("Signature", "Timestamp", "Nonce"):
                        km = re.search(key + r"=([^,\s]+)", v, re.I)
                        if km:
                            found[key.lower()] = ("auth_param", key.lower(), km.group(1).strip('"'))
                continue
            if ln.startswith("sec-") or "-" not in ln:
                continue
            if _CSRF_NAME.search(ln):
                continue
            if _SIG_NAME.search(ln):
                found.setdefault("signature", ("header", ln, v))
            elif _TS_NAME.search(ln):
                found.setdefault("timestamp", ("header", ln, v))
            elif _NONCE_NAME.search(ln):
                found.setdefault("nonce", ("header", ln, v))
        for n, v in {**e["query"], **e["body"]}.items():
            ln = n.lower()
            if re.fullmatch(r"(x-amz-)?(signature|sig|hmac|sign)", ln):
                found.setdefault("signature", ("param", ln, v))
            elif re.fullmatch(r"(x-amz-)?(timestamp|ts)", ln) and _ts_shape(v):
                found.setdefault("timestamp", ("param", ln, v))
            elif ln == "nonce":
                found.setdefault("nonce", ("param", ln, v))
        if "signature" not in found and "auth_scheme" not in found:
            continue
        key = tuple(sorted((r, w[0], w[1]) for r, w in found.items()))
        g = groups.setdefault(key, {"fields": key, "ids": [], "paths": set(), "methods": set(),
                                    "sig": set(), "nonce": set(), "ts": set(), "sig_shape": None,
                                    "ts_shape": None, "scheme": None})
        g["ids"].append(e["id"])
        g["paths"].add(e["path"])
        g["methods"].add(e["method"])
        if "signature" in found:
            g["sig"].add(found["signature"][2])
            g["sig_shape"] = _sig_shape(found["signature"][2])
        if "nonce" in found:
            g["nonce"].add(found["nonce"][2])
        if "timestamp" in found:
            g["ts"].add(found["timestamp"][2])
            g["ts_shape"] = _ts_shape(found["timestamp"][2])
        if "auth_scheme" in found:
            g["scheme"] = found["auth_scheme"][2]
    out = []
    for g in groups.values():
        n = len(g["ids"])
        out.append({
            "fields": [{"role": r, "location": w, "name": nm} for r, w, nm in g["fields"]],
            "request_count": n,
            "entry_ids": g["ids"][:20],
            "paths": sorted(g["paths"])[:10],
            "methods": sorted(g["methods"]),
            "signature_shape": g["sig_shape"],
            "timestamp_shape": g["ts_shape"],
            "auth_scheme": g["scheme"],
            "signature_varies_per_request": (len(g["sig"]) > 1) if n > 1 else None,
            "nonce_unique_per_request": (len(g["nonce"]) == n) if g["nonce"] and n > 1 else None,
            "timestamp_varies": (len(g["ts"]) > 1) if g["ts"] and n > 1 else None,
            "replay_hint": "signature is bound to timestamp/nonce; recompute per request"
            if (g["ts"] or g["nonce"]) else "signature may be static or body-bound",
        })
    return {"detected": bool(out), "groups": out}


# ------------------------------------------------------------------ entry

_DETECTORS = {
    "bearer_refresh": detect_bearer_refresh,
    "oidc_pkce": detect_oidc_pkce,
    "saml_post": detect_saml_post,
    "double_submit_csrf": detect_double_submit_csrf,
    "signed_requests": detect_signed_requests,
}


def detect_auth_patterns(
    har_path: str | Path, *, host: str | None = None, kinds: list[str] | None = None
) -> dict[str, Any]:
    """Run the generic auth-pattern detectors over a HAR (names/shapes only)."""
    wanted = [k for k in (kinds or KINDS) if k in _DETECTORS]
    entries = _load(har_path, host)
    result: dict[str, Any] = {"host": host, "entry_count": len(entries)}
    for k in wanted:
        result[k] = _DETECTORS[k](entries)
    result["detected"] = [k for k in wanted if result[k].get("detected")]
    return result
