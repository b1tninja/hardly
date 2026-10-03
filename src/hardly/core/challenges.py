"""Detect HTTP auth challenges, throttling/lockout signals and captcha widgets.

Technology-level: header-based challenge schemes (Basic/Bearer/Digest/Negotiate
/…), rate-limit and lockout responses, and captcha widget markup. Reports
scheme and parameter *names*; challenge nonces/opaque values and sitekeys'
values are never returned.
"""

from __future__ import annotations

import re
import sqlite3
from typing import Any

_SAFE_PARAMS = frozenset({"realm", "error", "error_description", "scope", "qop", "algorithm", "charset", "stale"})
_SCHEME = re.compile(r"(?:^|,\s*)([A-Za-z][A-Za-z0-9\-_.~+/]*)(?=\s+[A-Za-z_]+=|\s*$|\s*,)", re.I)
_PARAM = re.compile(r"([A-Za-z_][A-Za-z0-9_\-]*)\s*=\s*(\"[^\"]*\"|[^,\s]+)")

_RATE_HEADER = re.compile(r"^(retry-after|x-ratelimit-.*|ratelimit-.*|x-rate-limit-.*)$", re.I)
_LOCKOUT_TEXT = re.compile(
    r"too many (login |sign-?in |failed )?(attempts|requests)|account (is )?(temporarily )?(locked|disabled)|"
    r"try again (in|after|later)|rate limit(ed)?|exceeded .{0,30}(attempts|limit)|temporarily blocked",
    re.I,
)
_CAPTCHAS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("recaptcha", re.compile(r"g-recaptcha|recaptcha/(api|enterprise)\.js|grecaptcha\.", re.I)),
    ("hcaptcha", re.compile(r"h-captcha|hcaptcha\.com/1/api\.js", re.I)),
    ("turnstile", re.compile(r"cf-turnstile|challenges\.cloudflare\.com/turnstile", re.I)),
    ("arkose", re.compile(r"funcaptcha|arkoselabs\.com|arkose", re.I)),
    ("geetest", re.compile(r"geetest", re.I)),
    ("friendly-captcha", re.compile(r"frc-captcha|friendlycaptcha", re.I)),
    ("image-captcha", re.compile(r"<img[^>]+(captcha|verifycode|validatecode)", re.I)),
)
# Only the names a form actually submits; element ids like "captcha-demo-form" are noise.
_CAPTCHA_FIELD = re.compile(
    r"\bname\s*=\s*[\'\"](g-recaptcha-response|h-captcha-response|cf-turnstile-response|fc-token|"
    r"frc-captcha-solution|geetest_[a-z]+|mtcaptcha-verifiedtoken|captcha(?:_?(?:code|answer|input|text|response))?)[\'\"]",
    re.I,
)


def parse_challenges(value: str) -> list[dict[str, Any]]:
    """Split a WWW-Authenticate value into schemes with safe parameters."""
    out: list[dict[str, Any]] = []
    # Split at scheme boundaries: a token followed by a param, outside quotes.
    parts = re.split(r",\s*(?=[A-Za-z][A-Za-z0-9\-_.~+/]*\s+[A-Za-z_]+=)", value.strip())
    for part in parts:
        head = re.match(r"\s*([A-Za-z][A-Za-z0-9\-_.~+/]*)(.*)$", part, re.S)
        if not head:
            continue
        scheme, rest = head.group(1), head.group(2)
        names, safe = [], {}
        for m in _PARAM.finditer(rest):
            name = m.group(1).lower()
            names.append(name)
            if name in _SAFE_PARAMS:
                safe[name] = m.group(2).strip('"')[:80]
        out.append({"scheme": scheme, "params": names, "values": safe})
    return out


def detect_challenges(
    conn: sqlite3.Connection, *, host: str | None = None, limit: int = 20
) -> dict[str, Any]:
    where = "e.is_noise = 0"
    params: list[Any] = []
    if host:
        where += " AND e.host = ?"
        params.append(host.lower())

    challenges: list[dict[str, Any]] = []
    rows = conn.execute(
        f"""
        SELECT e.entry_id, e.method, e.host, e.path, e.path_template, e.status,
               h.name AS hname, h.value_raw AS hvalue
        FROM entries e JOIN headers h ON h.entry_id = e.entry_id AND h.side = 'response'
        WHERE {where} AND lower(h.name) IN ('www-authenticate', 'proxy-authenticate')
        ORDER BY e.entry_id LIMIT 200
        """,
        params,
    ).fetchall()
    for row in rows:
        parsed = parse_challenges(row["hvalue"] or "")
        entry = {
            "entry_id": row["entry_id"],
            "method": row["method"],
            "host": row["host"],
            "path": row["path_template"] or row["path"],
            "status": row["status"],
            "header": row["hname"].lower(),
            "schemes": parsed,
        }
        retry = conn.execute(
            """
            SELECT e2.entry_id, e2.status FROM entries e2
            JOIN headers h2 ON h2.entry_id = e2.entry_id AND h2.side = 'request'
            WHERE e2.entry_id > ? AND e2.method = ? AND e2.host = ?
              AND e2.path = ? AND lower(h2.name) IN ('authorization', 'proxy-authorization')
            ORDER BY e2.entry_id LIMIT 1
            """,
            (row["entry_id"], row["method"], row["host"], row["path"]),
        ).fetchone()
        if retry:
            entry["retried_with_credentials"] = {
                "entry_id": retry["entry_id"],
                "status": retry["status"],
            }
        challenges.append(entry)

    throttling: list[dict[str, Any]] = []
    for row in conn.execute(
        f"""
        SELECT e.entry_id, e.method, e.host, e.path_template, e.path, e.status,
               sb.preview_text AS body
        FROM entries e
        LEFT JOIN bodies sb ON sb.entry_id = e.entry_id AND sb.side = 'response'
        WHERE {where} AND (e.status IN (423, 429) OR e.status IN (401, 403, 503, 200))
        ORDER BY e.entry_id LIMIT 1500
        """,
        params,
    ):
        status = int(row["status"] or 0)
        rate = [
            {"name": h["name"].lower(), "value": (h["value_raw"] or "")[:40]}
            for h in conn.execute(
                "SELECT name, value_raw FROM headers WHERE entry_id=? AND side='response'",
                (row["entry_id"],),
            )
            if _RATE_HEADER.match(h["name"])
        ]
        text_hit = bool(row["body"] and _LOCKOUT_TEXT.search(row["body"][:6000]))
        if status in (423, 429) or (rate and any(r["name"] == "retry-after" for r in rate)) or (
            text_hit and status != 200
        ):
            throttling.append(
                {
                    "entry_id": row["entry_id"],
                    "method": row["method"],
                    "host": row["host"],
                    "path": row["path_template"] or row["path"],
                    "status": status,
                    "rate_headers": rate,
                    "lockout_text": text_hit,
                }
            )
        elif rate and status == 200 and len(throttling) < 3 and any(
            r["name"].startswith(("x-ratelimit", "ratelimit", "x-rate-limit")) for r in rate
        ):
            # Quota advertised on successful responses: informative, keep a few.
            throttling.append(
                {
                    "entry_id": row["entry_id"],
                    "method": row["method"],
                    "host": row["host"],
                    "path": row["path_template"] or row["path"],
                    "status": status,
                    "rate_headers": rate,
                    "lockout_text": False,
                    "advertised_only": True,
                }
            )

    captcha: dict[str, dict[str, Any]] = {}
    for row in conn.execute(
        f"""
        SELECT e.entry_id, sb.preview_text AS body
        FROM entries e JOIN bodies sb ON sb.entry_id = e.entry_id AND sb.side = 'response'
        WHERE {where} AND (sb.content_type LIKE '%html%' OR sb.preview_text LIKE '<%')
        ORDER BY e.entry_id LIMIT 500
        """,
        params,
    ):
        body = row["body"] or ""
        for name, pat in _CAPTCHAS:
            if pat.search(body):
                info = captcha.setdefault(name, {"name": name, "entry_ids": [], "fields": set()})
                info["entry_ids"].append(row["entry_id"])
                info["fields"].update(m.group(1).lower() for m in _CAPTCHA_FIELD.finditer(body))
                info["sitekey_attr"] = info.get("sitekey_attr") or ("data-sitekey" in body)
    captcha_out = [
        {
            "name": c["name"],
            "entry_ids": sorted(set(c["entry_ids"]))[:8],
            "response_fields": sorted(c["fields"])[:6],
            "has_sitekey_attr": bool(c.get("sitekey_attr")),
        }
        for c in captcha.values()
    ]
    return {
        "host": host,
        "auth_challenges": challenges[:limit],
        "throttling": throttling[:limit],
        "captcha_widgets": captcha_out[:limit],
        "next": (
            "Challenges: replay with the advertised scheme (Digest needs the "
            "nonce from the 401). Throttling: honour Retry-After and back off. "
            "Captcha: needs a person (interactive mode) — hardly will not solve it."
        ),
    }
