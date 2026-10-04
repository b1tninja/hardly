"""Gate taxonomy: what stands between a client and the content, and what to do.

A *gate* is anything that stops a plain client from reaching content without a
decision by a person. Classes:

``environment_blocked``  OUR sandbox/proxy refused the request - not the site.
                         Always "unknown - re-run from another network".
``bot_wall``             WAF / bot-manager block or challenge page.
``captcha``              captcha widget or captcha challenge.
``proof_of_work``        client-side proof-of-work interstitial.
``waiting_room``         virtual queue / waiting room.
``click_through_terms``  disclaimer / terms form with an accept submit.
``login``                password page or HTTP 401.
``paywall``              pricing wording or HTTP 402.
``rate_limit``           429 / Retry-After / lockout wording.

Technology-level signatures only. Only evidence *names* are reported (header
names, cookie names, wording markers) - never cookie values, tokens or nonces.
See ``docs/gate-policy.md`` for the written policy that ``POLICY`` encodes.
"""

from __future__ import annotations

import re
import sqlite3
from typing import Any

from hardly.core.explain import finish

GATE_CLASSES: tuple[str, ...] = (
    "environment_blocked",
    "bot_wall",
    "captcha",
    "proof_of_work",
    "waiting_room",
    "click_through_terms",
    "login",
    "paywall",
    "rate_limit",
)

ENV_MESSAGE = "unknown — re-run from another network"

POLICY: dict[str, Any] = {
    "version": 1,
    "doc": "docs/gate-policy.md",
    "click_through": {
        "accept": "ordinary form post only",
        "condition": "terms do not forbid automation",
        "action": "accept_click_through",
    },
    "stop_classes": [
        "bot_wall",
        "captcha",
        "proof_of_work",
        "waiting_room",
        "login",
        "paywall",
        "rate_limit",
    ],
    "unknown_classes": ["environment_blocked"],
    "rules": [
        "Click-through disclaimers may be accepted by an ordinary form post only if the terms do not forbid automation.",
        "Login, paywall, captcha, WAF/bot challenge, waiting room, rate limit and terms that forbid automation are stop signs.",
        "Never test whether a gate is enforced server-side.",
        "Never retry a challenged URL in a loop.",
        "An environment block is 'unknown', not 'walled': re-run from another network before concluding anything about the site.",
    ],
    "actions": {
        "stop": "Stop. Hand to a person (interactive mode) or drop the target.",
        "accept_click_through": "Submit the accept form once, as an ordinary form post.",
        "unknown_rerun": ENV_MESSAGE + ". Do not report as a site wall.",
    },
}


def action_for(gate_class: str, *, forbids_automation: bool = False) -> str:
    """Policy action for a gate class."""
    if gate_class == "environment_blocked":
        return "unknown_rerun"
    if gate_class == "click_through_terms" and not forbids_automation:
        return "accept_click_through"
    return "stop"


def severity_for_action(action: str) -> str:
    """Shared info|notice|blocker vocabulary: stop signs block, the rest need attention."""
    return "blocker" if action == "stop" else "notice"


# --------------------------------------------------------------------------
# single-response detectors
# --------------------------------------------------------------------------

_PROXY_BODY = re.compile(
    r"blocked by (the )?(proxy|egress|network policy|sandbox)|host (is )?not allowed|"
    r"not in (the )?allow-?list|egress (policy|filter)|proxy authentication required|"
    r"tunnel(ing)? (connection )?failed|connect tunnel|policy denied the request",
    re.I,
)
_PROXY_HEADER = re.compile(
    r"^(x-proxy-[a-z-]+|proxy-status|x-squid-error|x-envoy-[a-z-]+|x-egress-[a-z-]+|proxy-authenticate)$", re.I
)
# "HAProxy"/"reverse-proxy" are ordinary site infrastructure; only a bare proxy name counts.
_PROXY_VIA = re.compile(r"(?<![A-Za-z-])(?:squid|proxy|envoy|tinyproxy|privoxy|mitm)", re.I)
_NON_TEXT_MIME = re.compile(r"javascript|ecmascript|css|image/|font/|octet-stream|wasm|audio/|video/", re.I)

_TERMS_CONTEXT = re.compile(
    r"disclaimer|terms (of use|of service|and conditions|& conditions)|i (agree|accept)|"
    r"accept (the |these |all )?(terms|conditions)|conditions of use|user agreement",
    re.I,
)
_TERMS_PATH = re.compile(r"(?:^|[/_.-])(disclaimer|termaccept|accept-?terms|tos|terms-?accept)(?:$|[/_.?-])", re.I)
_ACCEPT_CONTROL = re.compile(
    r"<input[^<>]+type\s*=\s*['\"]?(?:submit|button|image)[^<>]*(?:value|name|id)\s*=\s*['\"][^'\"]*(?:accept|agree)[^'\"]*['\"]|"
    r"<input[^<>]+(?:value|name|id)\s*=\s*['\"][^'\"]*(?:accept|agree)[^'\"]*['\"][^<>]*type\s*=\s*['\"]?(?:submit|button|image)|"
    r"<button[^<>]*>[^<]{0,40}(?:i\s+)?(?:accept|agree)[^<]{0,40}</button>|"
    r"<input[^<>]+type\s*=\s*['\"]?checkbox[^<>]*(?:name|id)\s*=\s*['\"][^'\"]*(?:accept|agree|terms)[^'\"]*['\"]",
    re.I,
)
_AUTOMATION_WORDS = r"(?:automated|scrap\w*|crawl\w*|spider\w*|robots?|\bbots?\b|harvest\w*|data[- ]mining|screen[- ]scrap\w*)"
_FORBIDS_AUTOMATION = re.compile(
    r"(?:no|not|prohibit\w*|forbid\w*|may not|shall not|must not|without (?:prior )?(?:written )?permission|unauthori[sz]ed)[^.<]{0,100}"
    + _AUTOMATION_WORDS
    + r"|"
    + _AUTOMATION_WORDS
    + r"[^.<]{0,100}(?:prohibited|forbidden|not (?:permitted|allowed)|is strictly)",
    re.I,
)

_PASSWORD_FIELD = re.compile(r"<input[^<>]+type\s*=\s*['\"]?password", re.I)

_PRICE_STRONG = re.compile(
    r"\$\s?\d[\d,]*(?:\.\d{2})?\s*(?:/|a|an|per|each)\s*(?:day|week|month|year|page|document|copy|search|view|record|hour)\b|"
    r"purchase (?:a|an|your) (?:day |month |annual |one-?time )?pass|pay[- ]per[- ](?:view|page|document)|"
    r"\bpaywall\b|subscribe to (?:read|continue|access)",
    re.I,
)
_PRICE_WEAK = re.compile(r"\bsubscription\b|\bper page\b|\bper document\b", re.I)
_AMOUNT = re.compile(r"\$\s?\d")

_LOCKOUT = re.compile(
    r"too many (login |sign-?in |failed )?(attempts|requests)|account (is )?(temporarily )?(locked|disabled)|"
    r"rate limit(ed)?|exceeded .{0,30}(attempts|limit)|temporarily blocked|you have been rate.?limited|"
    r"try again (in|after) \d+",
    re.I,
)
_CHALLENGE_REDIRECT = re.compile(r"^(?:[a-z][a-z0-9+.-]*://[^/]+)?/challenge[\w-]*(?:/|\?|$)", re.I)

_VENDOR_CLASS = {
    "cdn_waf": "bot_wall",
    "bot_manager": "bot_wall",
    "generic": "bot_wall",
    "captcha": "captcha",
    "proof_of_work": "proof_of_work",
    "waiting_room": "waiting_room",
    "rate_limit": "rate_limit",
}


def _norm_headers(headers: dict[str, Any] | None) -> dict[str, str]:
    out: dict[str, str] = {}
    for k, v in (headers or {}).items():
        vals = v if isinstance(v, (list, tuple)) else [v]
        out[str(k).lower()] = "\n".join("" if x is None else str(x) for x in vals)
    return out


def _gate(cls: str, evidence: list[str], *, vendor: str | None = None, action: str | None = None) -> dict[str, Any]:
    g: dict[str, Any] = {"class": cls}
    if vendor:
        g["vendor"] = vendor
    g["evidence"] = list(dict.fromkeys(evidence))[:8]
    g["entry_ids"] = []
    g["action"] = action or action_for(cls)
    g["severity"] = severity_for_action(g["action"])
    return g


def _path_of(url: str) -> str:
    bare = re.sub(r"^[a-z][a-z0-9+.-]*://[^/]*", "", url or "", flags=re.I)
    return bare.split("?")[0] or "/"


def _environment(status: int, h: dict[str, str], body: str) -> dict[str, Any] | None:
    ev: list[str] = []
    if "x-deny-reason" in h:
        ev.append("header:x-deny-reason")
        reason = h["x-deny-reason"].strip().lower()
        if re.fullmatch(r"[a-z0-9_.-]{1,40}", reason):
            ev.append(f"reason:{reason}")
    if ev:
        return _gate("environment_blocked", ev)
    return None


def _proxy_style(status: int, h: dict[str, str], body: str) -> list[str]:
    if status not in (403, 407, 502):
        return []
    ev: list[str] = []
    for name in h:
        if _PROXY_HEADER.match(name):
            ev.append(f"header:{name}")
    if _PROXY_VIA.search(h.get("via", "")):
        ev.append("header:via")
    if _PROXY_VIA.search(h.get("server", "")):
        ev.append("header:server")
    if body and _PROXY_BODY.search(body[:4000]):
        ev.append("body:proxy-wording")
    return ev


def _merge(gates: dict[tuple[str, str | None], dict[str, Any]], g: dict[str, Any]) -> None:
    key = (g["class"], g.get("vendor"))
    cur = gates.get(key)
    if cur is None:
        gates[key] = g
        return
    cur["evidence"] = list(dict.fromkeys(cur["evidence"] + g["evidence"]))[:8]
    if g["action"] == "stop":
        cur["action"] = "stop"
        cur["severity"] = "blocker"


def classify_response(
    status: int,
    headers: dict[str, Any] | None,
    body: str = "",
    url: str = "",
) -> list[dict[str, Any]]:
    """Classify the gates a single response represents (pure; no I/O).

    ``headers`` maps response header names to a string or list of strings.
    Returns ``[{class, vendor?, evidence, entry_ids, action}]`` (``entry_ids``
    is empty here; the session-level ``classify_gates`` fills it). An
    environment block suppresses every site-gate verdict for the response.
    """
    from hardly.core.botwalls import classify_response_vendors

    status = int(status or 0)
    h = _norm_headers(headers)
    text = body or ""
    # Wording scans (lockout, password fields, pricing, terms) only make sense on
    # documents: a JS bundle that contains the phrase "too many attempts" is not a gate.
    if _NON_TEXT_MIME.search(h.get("content-type", "")):
        text_for_wording = ""
    else:
        text_for_wording = text

    env = _environment(status, h, text)
    if env:
        env["evidence"].append(f"status:{status}") if status else None
        return [env]

    vendors = classify_response_vendors(status, headers or {}, text, url)
    site_signal = any(v["id"] != "generic-block" and v["score"] >= 2 for v in vendors)
    proxy = _proxy_style(status, h, text)
    if proxy and not site_signal:
        return [_gate("environment_blocked", proxy + [f"status:{status}"])]

    gates: dict[tuple[str, str | None], dict[str, Any]] = {}

    for v in vendors:
        cls = _VENDOR_CLASS.get(v["category"])
        if not cls:
            continue
        names = [f"{e['kind']}:{e['match']}" for e in v["evidence"]]
        non_cookie = any(e["kind"] != "cookie" for e in v["evidence"])
        if cls == "bot_wall":
            if v["state"] not in {"blocked", "challenged"}:
                continue
        elif cls == "rate_limit":
            if v["state"] not in {"blocked", "challenged"}:
                continue
        elif cls == "captcha":
            if not non_cookie:
                continue
        elif cls in {"proof_of_work", "waiting_room"}:
            if v["state"] == "present" and not non_cookie:
                continue
        if v["state"] in {"blocked", "challenged"}:
            names.append(f"state:{v['state']}")
        _merge(gates, _gate(cls, names, vendor=v["id"]))

    # redirect into a challenge path
    loc = h.get("location", "")
    if 300 <= status < 400 and loc and _CHALLENGE_REDIRECT.match(loc.strip()):
        _merge(gates, _gate("bot_wall", ["redirect:challenge-path"]))
    elif _CHALLENGE_REDIRECT.match(_path_of(url)) and status in (200, 202, 403, 429):
        _merge(gates, _gate("bot_wall", ["path:challenge"]))

    # rate limit
    rl: list[str] = []
    if status == 429:
        rl.append("status:429")
    if "retry-after" in h and (status in (403, 423, 429, 503) or status >= 400):
        rl.append("header:retry-after")
    if text_for_wording and status != 200 or (text_for_wording and _LOCKOUT.search(text_for_wording[:6000]) and status in (200, 202)):
        if _LOCKOUT.search(text_for_wording[:6000]):
            rl.append("body:lockout-wording")
    if status == 423:
        rl.append("status:423")
    if rl:
        _merge(gates, _gate("rate_limit", rl))

    # login
    login: list[str] = []
    if status == 401:
        login.append("status:401")
        wa = h.get("www-authenticate", "")
        for m in re.finditer(r"(?:^|[\s,])(basic|bearer|digest|negotiate|ntlm)\b", wa, re.I):
            login.append(f"scheme:{m.group(1).lower()}")
    if text_for_wording and _PASSWORD_FIELD.search(text_for_wording):
        login.append("form:password-field")
    if login:
        _merge(gates, _gate("login", login))

    # paywall
    pay: list[str] = []
    if status == 402:
        pay.append("status:402")
    if text_for_wording:
        if _PRICE_STRONG.search(text_for_wording):
            pay.append("body:pricing-wording")
        elif _PRICE_WEAK.search(text_for_wording) and _AMOUNT.search(text_for_wording):
            pay.append("body:pricing-wording")
    if pay and status != 401:
        _merge(gates, _gate("paywall", pay))

    # click-through terms
    if text_for_wording and "<form" in text_for_wording.lower() and _ACCEPT_CONTROL.search(text_for_wording):
        path_hit = _TERMS_PATH.search(_path_of(url))
        if _TERMS_CONTEXT.search(text[:20000]) or path_hit:
            ev = ["form:accept-control"]
            if path_hit:
                ev.append(f"path:{path_hit.group(1).lower()}")
            if _TERMS_CONTEXT.search(text[:20000]):
                ev.append("body:terms-wording")
            forbids = bool(_FORBIDS_AUTOMATION.search(text[:40000]))
            if forbids:
                ev.append("terms:forbid-automation")
            _merge(gates, _gate("click_through_terms", ev, action=action_for("click_through_terms", forbids_automation=forbids)))

    # One rate_limit gate per response (status-based and vendor-based evidence merge).
    rls = [k for k in gates if k[0] == "rate_limit"]
    if len(rls) > 1:
        keep = gates[rls[0]]
        for k in rls[1:]:
            keep["evidence"] = list(dict.fromkeys(keep["evidence"] + gates.pop(k)["evidence"]))[:8]
            keep["action"] = "stop"
        keep["vendor"] = next((k[1] for k in rls if k[1]), None)
    # A terms page that says "no automation" is a click-through gate that stops;
    # the generic block-wording match on the same page is the same fact, not a bot wall.
    if any(k[0] == "click_through_terms" for k in gates):
        for k in [k for k in gates if k[0] == "bot_wall" and k[1] == "generic-block"]:
            gates.pop(k)

    return list(gates.values())


# --------------------------------------------------------------------------
# session level
# --------------------------------------------------------------------------


def classify_gates(
    conn: sqlite3.Connection, host: str | None = None, explain: bool = False
) -> dict[str, Any]:
    """Aggregate gate classes over a whole session.

    Combines per-response classification (every indexed response) with the
    session-level product detection in ``botwalls``. ``environment_blocked``
    entries never count toward site gates.
    """
    where = "1 = 1"
    params: list[Any] = []
    if host:
        where += " AND e.host = ?"
        params.append(host.lower())

    entries = {
        int(r["entry_id"]): r
        for r in conn.execute(
            f"SELECT e.entry_id, e.host, e.path, e.status FROM entries e WHERE {where} ORDER BY e.entry_id LIMIT 3000",
            params,
        )
    }
    heads: dict[int, dict[str, list[str]]] = {}
    for r in conn.execute(
        f"""
        SELECT h.entry_id, h.name, h.value_raw FROM headers h
        JOIN entries e ON e.entry_id = h.entry_id
        WHERE {where} AND h.side = 'response' ORDER BY h.entry_id LIMIT 60000
        """,
        params,
    ):
        heads.setdefault(int(r["entry_id"]), {}).setdefault(r["name"], []).append(r["value_raw"] or "")
    bodies: dict[int, str] = {}
    for r in conn.execute(
        f"""
        SELECT b.entry_id, b.preview_text FROM bodies b JOIN entries e ON e.entry_id = b.entry_id
        WHERE {where} AND b.side = 'response' AND b.preview_text IS NOT NULL
        ORDER BY b.entry_id LIMIT 3000
        """,
        params,
    ):
        bodies[int(r["entry_id"])] = r["preview_text"] or ""

    agg: dict[tuple[str, str | None], dict[str, Any]] = {}
    env_ids: list[int] = []
    for eid, row in entries.items():
        url = f"{row['host']}{row['path']}"
        for g in classify_response(int(row["status"] or 0), heads.get(eid, {}), bodies.get(eid, ""), url):
            if g["class"] == "environment_blocked":
                env_ids.append(eid)
            key = (g["class"], g.get("vendor"))
            cur = agg.get(key)
            if cur is None:
                cur = agg[key] = {**g, "entry_ids": []}
            else:
                cur["evidence"] = list(dict.fromkeys(cur["evidence"] + g["evidence"]))[:8]
                if g["action"] == "stop":
                    cur["action"] = "stop"
                    cur["severity"] = "blocker"
            if eid not in cur["entry_ids"] and len(cur["entry_ids"]) < 12:
                cur["entry_ids"].append(eid)

    # Cookie-name based product evidence (set-cookie values are not indexed raw).
    env_set = set(env_ids)
    try:
        from hardly.core.botwalls import detect_bot_protection

        prot = detect_bot_protection(conn, host=host, limit=40)
    except Exception:  # noqa: BLE001
        prot = {"vendors": []}
    for v in prot["vendors"]:
        cls = _VENDOR_CLASS.get(v["category"])
        if cls not in {"bot_wall", "rate_limit"} or v["state"] not in {"blocked", "challenged"}:
            continue
        ids = [i for i in (v.get("blocked_entry_ids") or []) if i not in env_set]
        for slot in v.get("evidence") or []:
            if slot["kind"] == "challenge_page":
                ids += [i for i in slot["entry_ids"] if i not in env_set]
        if not ids:
            continue
        key = (cls, v["id"])
        cur = agg.get(key)
        names = [f"{e['kind']}:{e['match']}" for e in (v.get("evidence") or [])][:8] + [f"state:{v['state']}"]
        if cur is None:
            cur = agg[key] = _gate(cls, names, vendor=v["id"])
        else:
            cur["evidence"] = list(dict.fromkeys(cur["evidence"] + names))[:8]
        for i in ids:
            if i not in cur["entry_ids"] and len(cur["entry_ids"]) < 12:
                cur["entry_ids"].append(i)
        # vendor-level bot_wall that is really a 429 -> keep as-is

    # Drop "generic bot_wall" claims fully attributable to environment blocks.
    gates = [g for g in agg.values() if g["class"] == "environment_blocked" or g["entry_ids"]]
    order = {c: i for i, c in enumerate(GATE_CLASSES)}
    gates.sort(key=lambda g: (order.get(g["class"], 99), g.get("vendor") or ""))
    by_class: dict[str, int] = {}
    by_action: dict[str, int] = {}
    for g in gates:
        by_class[g["class"]] = by_class.get(g["class"], 0) + 1
        by_action[g["action"]] = by_action.get(g["action"], 0) + 1
    env_gate = next((g for g in gates if g["class"] == "environment_blocked"), None)
    out = {
        "host": host,
        "gate_count": len(gates),
        "gates": gates,
        "by_class": by_class,
        "by_action": by_action,
        "environment_blocked": {
            "detected": env_gate is not None,
            "verdict": ENV_MESSAGE if env_gate else None,
            "entry_ids": sorted(env_set)[:12],
            "evidence": env_gate["evidence"] if env_gate else [],
        },
        "policy": POLICY["rules"],
        "next": _next_text(by_class, by_action),
    }
    return finish(out, explain, "policy", "next")


def _next_text(by_class: dict[str, int], by_action: dict[str, int]) -> str:
    if not by_class:
        return "No gates observed."
    bits = []
    if "environment_blocked" in by_class:
        bits.append(f"Environment block: {ENV_MESSAGE}; do not treat it as a site wall.")
    if by_action.get("stop"):
        bits.append("Stop at each stop-sign gate; never probe whether it is enforced or retry in a loop.")
    if by_action.get("accept_click_through"):
        bits.append("Click-through terms may be accepted once by an ordinary form post (terms permit automation).")
    return " ".join(bits)


def summarize_gates(gates_result: dict[str, Any] | None) -> dict[str, Any]:
    """Compact class counts + actions for the brief."""
    g = gates_result or {}
    env = g.get("environment_blocked") or {}
    sm = g.get("gate_summary") or g
    return {
        "gate_count": len(g.get("gates") or []),
        "by_class": sm.get("by_class") or {},
        "by_action": sm.get("by_action") or {},
        "environment_blocked": bool(env.get("detected")),
        "classes": [
            {"class": x["class"], "vendor": x.get("vendor"), "action": x["action"]}
            for x in (g.get("gates") or [])[:8]
        ],
    }


__all__ = [
    "GATE_CLASSES",
    "POLICY",
    "ENV_MESSAGE",
    "action_for",
    "classify_response",
    "classify_gates",
    "summarize_gates",
]
