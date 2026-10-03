"""Identify bot-protection / WAF / captcha products from wire-level evidence.

A signature catalog keyed on technology fingerprints — cookie names, response
headers, request URLs/scripts, and challenge-page wording — not on any site.
Reports which product is in use, how sure we are, what evidence matched, and
the observed state (``blocked`` / ``challenged`` / ``clearance_seen`` /
``present``). hardly never solves or evades these; a captcha or managed
challenge means switching to an interactive capture with a person.

Only cookie *names*, header names/values of non-secret headers, and URL paths
are reported — never cookie values or tokens.
"""

from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass, field
from typing import Any

_STRONG, _MEDIUM, _WEAK = 3, 2, 1


@dataclass(frozen=True)
class Vendor:
    id: str
    name: str
    category: str  # cdn_waf | bot_manager | captcha | proof_of_work | waiting_room | rate_limit | generic
    cookies: tuple[tuple[str, int], ...] = ()
    headers: tuple[tuple[str, int], ...] = ()  # matched against "name: value" (lowercase)
    urls: tuple[tuple[str, int], ...] = ()  # matched against host+path(+query) of requests and script srcs
    body: tuple[tuple[str, int], ...] = ()
    block_body: tuple[str, ...] = ()  # wording of an actual block/challenge page
    clearance_cookies: tuple[str, ...] = ()  # cookie present => challenge was passed
    block_statuses: tuple[int, ...] = (403, 429)
    note: str = ""
    # True when a status alone (with only a header fingerprint) must not count
    # as a block: the header is informational, the block page wording decides.
    status_needs_wording: bool = False
    _re: dict[str, list[tuple[re.Pattern[str], int]]] = field(default_factory=dict, compare=False, hash=False)


def _v(**kw: Any) -> Vendor:
    return Vendor(**kw)


CATALOG: tuple[Vendor, ...] = (
    _v(
        id="cloudflare", name="Cloudflare (WAF / Bot Management / Turnstile)", category="cdn_waf",
        cookies=((r"^__cf_bm$", 2), (r"^cf_clearance$", 3), (r"^__cfduid$", 2), (r"^_cfuvid$", 2)),
        headers=((r"^cf-ray:", 2), (r"^server: cloudflare", 2), (r"^cf-mitigated: ", 3), (r"^cf-chl-", 3)),
        urls=((r"/cdn-cgi/challenge-platform/", 3), (r"/cdn-cgi/l/chk_jschl", 3), (r"challenges\.cloudflare\.com", 3)),
        body=((r"cf-chl-|cf_chl_opt|window\._cf_chl", 3), (r"__cf_chl_", 3)),
        block_body=(r"just a moment\.\.\.", r"checking your browser before accessing", r"attention required! \| cloudflare",
                    r"error code: 1020", r"enable javascript and cookies to continue"),
        clearance_cookies=("cf_clearance",), block_statuses=(403, 429, 503),
    ),
    _v(
        id="akamai", name="Akamai (Bot Manager / edge)", category="bot_manager",
        cookies=((r"^_abck$", 3), (r"^bm_sz$", 3), (r"^ak_bmsc$", 3), (r"^bm_sv$", 3), (r"^bm_mi$", 3), (r"^akacd_", 2), (r"^akavpau_", 2)),
        headers=((r"^server: akamaighost", 2), (r"^x-akamai-", 2), (r"^akamai-grn:", 2), (r"^server-timing: .*ak_p", 1)),
        urls=((r"errors\.edgesuite\.net", 3), (r"/akam/\d+/", 3)),
        body=((r"reference #\d+\.[0-9a-f.]+", 2),),
        block_body=(r"access denied", r"you don't have permission to access"),
        clearance_cookies=(), block_statuses=(403,),
        note="_abck cookie is a sensor cookie; ~0~ vs ~-1~ in its value (not reported) indicates validated vs not.",
    ),
    _v(
        id="imperva", name="Imperva / Incapsula", category="cdn_waf",
        cookies=((r"^incap_ses_", 3), (r"^visid_incap_", 3), (r"^reese84$", 3), (r"^nlbi_", 2), (r"^___utmvc$", 3)),
        headers=((r"^x-iinfo:", 3), (r"^x-cdn: (imperva|incapsula)", 3)),
        urls=((r"/_incapsula_resource", 3),),
        block_body=(r"incapsula incident id", r"request unsuccessful"),
        clearance_cookies=("reese84",), block_statuses=(403, 503),
    ),
    _v(
        id="datadome", name="DataDome", category="bot_manager",
        cookies=((r"^datadome$", 3),),
        headers=((r"^x-datadome", 3), (r"^x-dd-b:", 3)),
        urls=((r"captcha-delivery\.com", 3), (r"(js|api-js)\.datadome\.co", 3), (r"datadome\.co", 2)),
        body=((r"geo\.captcha-delivery\.com", 3), (r"\bdd=\{", 2)),
        block_body=(r"please enable js and disable any ad blocker",),
        clearance_cookies=("datadome",), block_statuses=(403,),
    ),
    _v(
        id="humansecurity", name="HUMAN / PerimeterX", category="bot_manager",
        cookies=((r"^_px\d?$", 3), (r"^_pxvid$", 3), (r"^_pxhd$", 3), (r"^pxcts$", 3), (r"^_pxff_", 2), (r"^_pxmvid$", 3)),
        urls=((r"px-cloud\.net", 3), (r"px-cdn\.net", 3), (r"perimeterx\.net", 3), (r"/xhr/api/v2/collector", 3), (r"/px/client/", 3)),
        body=((r"px-captcha", 3), (r"_pxappid|window\._px", 3)),
        block_body=(r"press & hold", r"press and hold to confirm you are a human"),
        block_statuses=(403,),
    ),
    _v(
        id="kasada", name="Kasada", category="bot_manager",
        headers=((r"^x-kpsdk-", 3),),
        urls=((r"/ips\.js(\?|$)", 3), (r"/tl(\?|$)", 1)),
        block_statuses=(429, 403),
    ),
    _v(
        id="f5", name="F5 (BIG-IP ASM / Distributed Cloud Bot Defense / Shape)", category="bot_manager",
        cookies=((r"^TS[0-9a-f]{8,}", 2), (r"^TSPD_", 3), (r"^f5avr", 3), (r"^_imp_apg_r_$", 3),
                 (r"^f5_cspm$", 3), (r"^BIGipServer", 1)),
        headers=((r"^x-f5-", 2), (r"^server: volt-adc", 3), (r"^x-volterra-", 3)),
        urls=((r"/TSPD/", 3),),
        body=((r"/TSPD/[0-9a-f]+", 3), (r"\bTSPD_101\b", 3)),
        block_body=(r"the requested url was rejected\. please consult with your administrator",
                    r"request rejected", r"your support id is", r"support id:? ?\d+"),
        block_statuses=(200, 403),
    ),
    _v(
        id="aws-waf", name="AWS WAF (Bot Control / CAPTCHA)", category="cdn_waf",
        cookies=((r"^aws-waf-token$", 3),),
        headers=((r"^x-amzn-waf-action:", 3), (r"^x-amzn-errortype: ", 1)),  # action challenge|captcha comes back as 202
        urls=((r"awswaf\.com", 3), (r"/awswaf/", 3)),
        body=((r"awswafintegration|awscaptcha", 3),),
        clearance_cookies=("aws-waf-token",), block_statuses=(202, 403, 405),
    ),
    _v(
        id="sucuri", name="Sucuri Website Firewall", category="cdn_waf",
        cookies=((r"^sucuri_cloudproxy_", 3),),
        headers=((r"^x-sucuri-id:", 3), (r"^x-sucuri-cache:", 3), (r"^server: sucuri", 3)),
        block_body=(r"sucuri website firewall",),
        block_statuses=(403,),
    ),
    _v(
        id="vercel", name="Vercel Security Checkpoint", category="cdn_waf",
        cookies=((r"^_vcrcs$", 3),),
        headers=((r"^x-vercel-mitigated: ", 3), (r"^x-vercel-challenge-token:", 3)),
        block_body=(r"vercel security checkpoint",),
        clearance_cookies=("_vcrcs",), block_statuses=(403, 429),
    ),
    _v(
        id="anubis", name="Anubis (proof-of-work)", category="proof_of_work",
        cookies=((r"anubis-auth$", 3), (r"^within\.website-x-cmd-anubis", 3)),
        urls=((r"/\.within\.website/x/cmd/anubis/", 3),),
        block_body=(r"making sure you.?re not a bot", r"protected by anubis"),
        clearance_cookies=("techaro.lol-anubis-auth",), block_statuses=(200, 403),
    ),
    _v(
        id="radware", name="Radware Bot Manager / ShieldSquare", category="bot_manager",
        cookies=((r"^__uzm[a-f]$", 3), (r"^rbzid$", 2), (r"^rbzsessionid$", 2)),
        urls=((r"shieldsquare", 3), (r"perfdrive\.com", 3), (r"radwarebotmanager", 3)),
        block_body=(r"radware bot manager",),
        block_statuses=(403, 429),
    ),
    _v(
        id="reblaze", name="Reblaze", category="cdn_waf",
        cookies=((r"^rbzid$", 3), (r"^rbzsessionid$", 3)),
        headers=((r"^server: reblaze", 3),),
        block_statuses=(403,),
    ),
    _v(
        id="netacea", name="Netacea", category="bot_manager",
        cookies=((r"^_mitata", 3), (r"^_mitatacookie$", 3)),
        headers=((r"^x-netacea", 3),),
        block_statuses=(403,),
    ),
    _v(
        id="ddos-guard", name="DDoS-Guard", category="cdn_waf",
        cookies=((r"^__ddg\d_", 3), (r"^__ddgid_", 3)),
        headers=((r"^server: ddos-guard", 3),),
        urls=((r"ddos-guard\.net", 3),),
        block_statuses=(403,),
    ),
    _v(
        id="signal-sciences", name="Fastly Signal Sciences", category="cdn_waf",
        headers=((r"^x-sigsci-", 3),),
        block_statuses=(406, 403),
    ),
    _v(
        id="queue-it", name="Queue-it (virtual waiting room)", category="waiting_room",
        cookies=((r"^QueueITAccepted-", 3), (r"^QueueIT", 2)),
        headers=((r"^x-queueit-", 3),),
        urls=((r"queue-it\.net", 3), (r"queueit", 1)),
        block_statuses=(),
    ),
    _v(
        id="recaptcha", name="Google reCAPTCHA", category="captcha",
        urls=((r"google\.com/recaptcha/", 3), (r"gstatic\.com/recaptcha/", 3), (r"recaptcha\.net/recaptcha/", 3)),
        body=((r"g-recaptcha(?!-response)\b", 3), (r"g-recaptcha-response", 2), (r"grecaptcha\.", 2)),
        block_statuses=(),
    ),
    _v(
        id="hcaptcha", name="hCaptcha", category="captcha",
        urls=((r"hcaptcha\.com", 3),),
        body=((r"\bh-captcha\b", 3), (r"h-captcha-response", 2)),
        block_statuses=(),
    ),
    _v(
        id="turnstile", name="Cloudflare Turnstile", category="captcha",
        urls=((r"challenges\.cloudflare\.com/turnstile/", 3),),
        body=((r"\bcf-turnstile\b", 3), (r"cf-turnstile-response", 2)),
        block_statuses=(),
    ),
    _v(
        id="arkose", name="Arkose Labs (FunCaptcha)", category="captcha",
        urls=((r"arkoselabs\.com", 3), (r"funcaptcha\.com", 3), (r"/fc/gt2/public_key/", 3)),
        body=((r"funcaptcha|arkoselabs", 3), (r"\bfc-token\b", 2)),
        block_statuses=(),
    ),
    _v(
        id="geetest", name="GeeTest", category="captcha",
        urls=((r"geetest\.com", 3), (r"/gt4?\.js", 2)),
        body=((r"geetest_", 3), (r"initGeetest", 3)),
        block_statuses=(),
    ),
    _v(
        id="friendly-captcha", name="Friendly Captcha", category="captcha",
        urls=((r"friendlycaptcha", 3),),
        body=((r"frc-captcha", 3), (r"frc-captcha-solution", 3)),
        block_statuses=(),
    ),
    _v(
        id="mtcaptcha", name="MTCaptcha", category="captcha",
        urls=((r"mtcaptcha\.com", 3),),
        body=((r"mtcaptcha-verifiedtoken", 3), (r"\bmtcaptcha\b", 2)),
        block_statuses=(),
    ),
    _v(
        id="azure-front-door", name="Azure Front Door", category="cdn_waf",
        headers=((r"^x-azure-ref:", 1), (r"^x-azure-fdid:", 1)),
        block_body=(r"the request is blocked", r"request is blocked"),
        block_statuses=(403,), status_needs_wording=True,
        note="x-azure-ref is informational on its own; only the 403 'request is blocked' page means blocked.",
    ),
    _v(
        id="app-rate-limit", name="Application-level rate limit / challenge redirect", category="rate_limit",
        headers=((r"^retry-after:", 2), (r"^location: [^ ]*/challenge", 2)),
        urls=((r"^[^/]+/challenge[\w-]*(/|\?|$)", 2),),
        body=((r"too many requests in the past (minute|hour|\d+ (seconds|minutes))", 3),
              (r"(rate|request) limit (exceeded|reached)", 2)),
        block_body=(r"too many requests in the past", r"too many requests",
                    r"you have been rate.?limited"),
        block_statuses=(429,),
    ),
    _v(
        id="google-sorry", name="Google 'unusual traffic' interstitial", category="generic",
        urls=((r"/sorry/index", 3),),
        block_body=(r"unusual traffic from your computer network",),
        block_statuses=(429, 403),
    ),
    _v(
        id="generic-block", name="Unidentified block / challenge page", category="generic",
        body=((r"verify (that )?you are (a )?human", 1), (r"are you a robot", 1), (r"\bcaptcha\b", 1)),
        block_body=(r"access denied", r"request blocked", r"automated (access|requests)", r"unusual traffic"),
        block_statuses=(403, 429),
    ),
)


def _compiled(v: Vendor) -> dict[str, list[tuple[re.Pattern[str], int]]]:
    if not v._re:
        for kind in ("cookies", "headers", "urls", "body"):
            v._re[kind] = [
                (re.compile(p, re.I), w) for p, w in getattr(v, kind) if w > 0
            ]
        v._re["block_body"] = [(re.compile(p, re.I), 1) for p in v.block_body]
    return v._re


_SCRIPT_SRC = re.compile(r"""<script[^>]+\bsrc\s*=\s*['"]([^'"]+)['"]""", re.I)
_IFRAME_SRC = re.compile(r"""<iframe[^>]+\bsrc\s*=\s*['"]([^'"]+)['"]""", re.I)


def detect_bot_protection(
    conn: sqlite3.Connection,
    *,
    har_path: str | None = None,
    host: str | None = None,
    limit: int = 20,
) -> dict[str, Any]:
    """Score every catalog product against cookies, headers, URLs and bodies."""
    ev: dict[str, dict[tuple[str, str], dict[str, Any]]] = {v.id: {} for v in CATALOG}
    scores: dict[str, int] = {v.id: 0 for v in CATALOG}
    blocked: dict[str, set[int]] = {v.id: set() for v in CATALOG}
    challenged: dict[str, set[int]] = {v.id: set() for v in CATALOG}

    def note(vid: str, kind: str, match: str, weight: int, entry_id: int | None) -> None:
        key = (kind, match)
        slot = ev[vid].get(key)
        if slot is None:
            slot = ev[vid][key] = {"kind": kind, "match": match, "weight": weight, "entry_ids": []}
            scores[vid] += weight
        if entry_id is not None and len(slot["entry_ids"]) < 6 and entry_id not in slot["entry_ids"]:
            slot["entry_ids"].append(entry_id)

    # --- cookie names (values never read) ---------------------------------
    cookie_names: set[str] = set()
    try:
        from hardly.core.cookies import cookie_timeline

        tl = cookie_timeline(conn, har_path=har_path, host=None, limit=500)
        cookie_names = set(tl.get("names_set") or []) | set(tl.get("names_sent") or [])
    except Exception:  # noqa: BLE001
        pass
    cookie_seen: set[str] = set()
    for name in cookie_names:
        for v in CATALOG:
            for pat, w in _compiled(v)["cookies"]:
                if pat.search(name):
                    note(v.id, "cookie", name, w, None)
                    cookie_seen.add(name)

    # --- request URLs -----------------------------------------------------
    for row in conn.execute(
        "SELECT entry_id, host, path, query_raw, status FROM entries ORDER BY entry_id LIMIT 8000"
    ):
        url = f"{row['host']}{row['path']}" + (f"?{row['query_raw']}" if row["query_raw"] else "")
        for v in CATALOG:
            for pat, w in _compiled(v)["urls"]:
                if pat.search(url):
                    note(v.id, "url", f"{row['host']}{_short_path(row['path'])}", w, int(row["entry_id"]))

    # --- response headers (non-secret only) -------------------------------
    header_rows = conn.execute(
        """
        SELECT h.entry_id, h.name, h.value_raw, e.status FROM headers h
        JOIN entries e ON e.entry_id = h.entry_id
        WHERE h.side = 'response' AND h.value_raw IS NOT NULL
        ORDER BY h.entry_id LIMIT 40000
        """
    )
    for row in header_rows:
        line = f"{row['name']}: {row['value_raw']}".lower()[:300]
        for v in CATALOG:
            for pat, w in _compiled(v)["headers"]:
                if pat.search(line):
                    note(v.id, "header", row["name"].lower() + _safe_value(row["name"], row["value_raw"]), w, int(row["entry_id"]))

    # --- bodies: markers, script/iframe sources, block wording ------------
    for row in conn.execute(
        """
        SELECT e.entry_id, e.host, e.status, b.content_type, b.preview_text
        FROM entries e JOIN bodies b ON b.entry_id = e.entry_id AND b.side = 'response'
        WHERE b.preview_text IS NOT NULL ORDER BY e.entry_id LIMIT 3000
        """
    ):
        text = (row["preview_text"] or "")[:60_000]
        if not text:
            continue
        eid, status = int(row["entry_id"]), int(row["status"] or 0)
        srcs = _SCRIPT_SRC.findall(text) + _IFRAME_SRC.findall(text)
        for v in CATALOG:
            rx = _compiled(v)
            for pat, w in rx["body"]:
                if pat.search(text):
                    note(v.id, "body", pat.pattern[:48], w, eid)
            for src in srcs:
                for pat, w in rx["urls"]:
                    if pat.search(src):
                        note(v.id, "script", _short_src(src), w, eid)
            lowered = text[:6000].lower()
            if any(p.search(lowered) for p, _ in rx["block_body"]) and (
                scores[v.id] > 0 or v.id == "generic-block"
            ):
                if status in v.block_statuses or status in (0, 200, 202):
                    challenged[v.id].add(eid)
                    note(v.id, "challenge_page", "block/challenge wording", 2 if v.id != "generic-block" else 1, eid)
                if status in v.block_statuses:
                    blocked[v.id].add(eid)

    # --- status-based blocking for products with positive evidence --------
    status_by_entry = {
        int(r["entry_id"]): int(r["status"] or 0)
        for r in conn.execute("SELECT entry_id, status FROM entries")
    }
    for v in CATALOG:
        if v.id == "generic-block":
            continue
        for slot in ev[v.id].values():
            for eid in slot["entry_ids"]:
                if (
                    status_by_entry.get(eid) in v.block_statuses
                    and slot["kind"] in {"header", "challenge_page"}
                    and not (v.status_needs_wording and slot["kind"] == "header")
                ):
                    blocked[v.id].add(eid)

    vendors: list[dict[str, Any]] = []
    for v in CATALOG:
        score = scores[v.id]
        if score <= 0:
            continue
        if v.id == "generic-block":
            explained = set()
            for o in CATALOG:
                if o.id != "generic-block" and scores[o.id] >= 3:
                    explained |= blocked[o.id] | challenged[o.id]
                    for slot in ev[o.id].values():
                        explained |= set(slot["entry_ids"])
            if (blocked[v.id] | challenged[v.id]) <= explained:
                continue  # every generic block is already explained by a product
        strong = score >= 5 or any(s["weight"] >= 3 for s in ev[v.id].values())
        confidence = "high" if strong and score >= 3 else "medium" if score >= 2 else "low"
        clearance = sorted(c for c in v.clearance_cookies if c in cookie_seen or c in cookie_names)
        if blocked[v.id]:
            state = "blocked"
        elif challenged[v.id]:
            state = "challenged"
        elif clearance:
            state = "clearance_seen"
        else:
            state = "present"
        vendors.append(
            {
                "id": v.id,
                "name": v.name,
                "category": v.category,
                "confidence": confidence,
                "score": score,
                "state": state,
                "evidence": sorted(ev[v.id].values(), key=lambda s: -s["weight"])[:8],
                "blocked_entry_ids": sorted(blocked[v.id])[:8],
                "clearance_cookies_seen": clearance,
                **({"note": v.note} if v.note else {}),
            }
        )
    vendors.sort(key=lambda d: (-{"high": 2, "medium": 1, "low": 0}[d["confidence"]], -d["score"]))
    blocking = [d for d in vendors if d["state"] in {"blocked", "challenged"}]
    needs_person = [d["id"] for d in blocking]
    return {
        "host": host,
        "vendors": vendors[:limit],
        "vendor_count": len(vendors),
        "blocking": [d["id"] for d in blocking],
        "recommendation": (
            "A challenge or block was observed. Re-capture in interactive mode "
            "(headed browser, real channel, a person completes the check) and "
            "analyse that HAR; hardly does not solve or evade these."
            if blocking
            else "Protection fingerprints seen but no blocking observed in this capture."
            if vendors
            else "No known bot-protection fingerprints found."
        ),
        "needs_person": needs_person,
    }


def classify_response_vendors(
    status: int,
    headers: dict[str, Any],
    body: str = "",
    url: str = "",
    cookies: tuple[str, ...] | list[str] = (),
) -> list[dict[str, Any]]:
    """Score the catalog against ONE response (pure; no index needed).

    ``headers`` maps response header names to a string or list of strings;
    ``url`` is ``host/path`` or a full URL. Only evidence *names* are returned
    (header names, cookie names, URL paths, wording markers) - never values.
    """
    status = int(status or 0)
    lines: list[str] = []
    cookie_names = set(cookies or ())
    for k, v in (headers or {}).items():
        vals = v if isinstance(v, (list, tuple)) else [v]
        for item in vals:
            item = "" if item is None else str(item)
            lines.append(f"{k}: {item}".lower()[:300])
            if str(k).lower() == "set-cookie":
                for part in item.split("\n"):
                    name = part.split("=", 1)[0].strip()
                    if name and "=" in part:
                        cookie_names.add(name)
    text = (body or "")[:60_000]
    lowered = text[:6000].lower()
    bare = re.sub(r"^[a-z][a-z0-9+.-]*://", "", url or "")
    srcs = _SCRIPT_SRC.findall(text) + _IFRAME_SRC.findall(text)

    out: list[dict[str, Any]] = []
    scored: dict[str, tuple[int, list[dict[str, Any]], bool, bool]] = {}
    for v in CATALOG:
        rx = _compiled(v)
        ev: dict[tuple[str, str], dict[str, Any]] = {}

        def add(kind: str, match: str, weight: int) -> None:
            ev.setdefault((kind, match), {"kind": kind, "match": match, "weight": weight})

        for name in cookie_names:
            for pat, w in rx["cookies"]:
                if pat.search(name):
                    add("cookie", name, w)
        for line in lines:
            for pat, w in rx["headers"]:
                if pat.search(line):
                    hname = line.split(":", 1)[0]
                    add("header", hname + _safe_value(hname, line.split(": ", 1)[-1]), w)
        for pat, w in rx["urls"]:
            if bare and pat.search(bare):
                add("url", _short_path(bare.split("?")[0]), w)
            for src in srcs:
                if pat.search(src):
                    add("script", _short_src(src), w)
        for pat, w in rx["body"]:
            if text and pat.search(text):
                add("body", pat.pattern[:48], w)
        scored[v.id] = (sum(e["weight"] for e in ev.values()), list(ev.values()), False, False)
        score, evl, _, _ = scored[v.id]
        wording = bool(lowered) and any(p.search(lowered) for p, _ in rx["block_body"])
        if wording and (score > 0 or v.id == "generic-block"):
            evl.append({"kind": "challenge_page", "match": "block/challenge wording", "weight": 1})
            score += 1
        header_block = any(
            e["kind"] == "header" and e["weight"] >= 1 for e in evl
        ) and not v.status_needs_wording
        in_block = status in v.block_statuses
        challenged = wording and (score > 0 or v.id == "generic-block") and (
            in_block or (status in (0, 200, 202) and v.id != "generic-block")
        )
        blocked = (wording and in_block and score > 0) or (header_block and in_block and score > 1)
        if v.id == "generic-block":
            blocked = wording and in_block
        scored[v.id] = (score, evl, challenged or blocked, blocked)

    strong_ids = {vid for vid, (sc, _, _, _) in scored.items() if sc >= 3 and vid != "generic-block"}
    for v in CATALOG:
        score, evl, challenged, blocked = scored[v.id]
        if score <= 0 or not evl:
            continue
        if v.id == "generic-block" and (strong_ids or not challenged):
            continue  # explained by a named product, or nothing blocked
        state = "blocked" if blocked else "challenged" if challenged else "present"
        if v.id != "generic-block" and score < 1:
            continue
        out.append(
            {
                "id": v.id,
                "name": v.name,
                "category": v.category,
                "state": state,
                "score": score,
                "evidence": [{"kind": e["kind"], "match": e["match"]} for e in evl][:8],
            }
        )
    out.sort(key=lambda d: -d["score"])
    return out


def _short_path(path: str) -> str:
    return (path or "/")[:60]


def _short_src(src: str) -> str:
    return re.sub(r"\?.*$", "", src)[:80]


def _safe_value(name: str, value: str) -> str:
    """Header values are only echoed for short vendor-status headers."""
    if name.lower() in {"cf-mitigated", "x-amzn-waf-action", "x-vercel-mitigated", "x-datadome", "x-sucuri-cache"}:
        return f"={str(value)[:30]}"
    return ""
