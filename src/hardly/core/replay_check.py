"""Replay minimisation: which pieces of a captured request actually matter?

Replays one entry (or an ordered flow of entries) with httpx and a cookie jar,
then removes one element at a time (header, cookie, query param, body field,
prior step) and compares an *outcome signature* against the baseline.

Safety rules:
  * Secrets never come from the index (it stores them redacted / withheld).
    They are supplied only through ``overrides`` and are reported by NAME.
  * GET/HEAD only unless ``allow_unsafe=True``.
  * Hard stop on 429, Retry-After, or a gate classification with action stop.
  * Captcha / challenge token fields are never sent, never ablated.
  * At most 5 same-host redirects are followed; the chain statuses are reported.
  * Output carries names and short plain-language findings, never bodies/values.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import time
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit

import httpx

from hardly.core.netguard import check_url, new_client
from hardly.core.redact import (
    REDACTED,
    classify_value_shape,
    is_sensitive_header,
    is_sensitive_key,
)
from hardly.core.safe_json import safe_loads

try:  # sibling module is built in parallel; degrade gracefully
    from hardly.core.gates import classify_response as _classify_response
except Exception:  # pragma: no cover - depends on sibling
    _classify_response = None

SAFE_METHODS = frozenset({"GET", "HEAD"})
MAX_REDIRECTS = 5

_PLUMBING_HEADERS = frozenset(
    {
        "content-length",
        "host",
        "connection",
        "transfer-encoding",
        "accept-encoding",
        "te",
        "keep-alive",
        "upgrade",
        "cookie",
    }
)
# Commonly decisive headers, in priority order.
_DECISIVE_HEADERS = ("x-requested-with", "content-type", "accept", "referer", "origin")

_CAPTCHA_NORMALISED = frozenset(
    {
        "grecaptcharesponse",
        "hcaptcharesponse",
        "cfturnstileresponse",
        "captchatoken",
        "recaptchatoken",
    }
)
_SECRET_SHAPES = frozenset({"jwt", "bearer_jwt", "bearer_token", "basic_auth"})
_CHALLENGE_WORDS = (
    "captcha",
    "challenge",
    "turnstile",
    "just a moment",
    "access denied",
    "cf-chl",
    "akamai",
    "are you a robot",
)


class _Halt(Exception):
    def __init__(self, reason: str, at: str | None = None):
        super().__init__(reason)
        self.reason = reason
        self.at = at


class _Budget(Exception):
    pass


def is_captcha_name(name: str) -> bool:
    norm = re.sub(r"[^a-z0-9]", "", name.lower())
    return norm in _CAPTCHA_NORMALISED or "captcha" in norm or "turnstile" in norm


def _unresolved(value: Any) -> bool:
    """True when a stored value is a redaction placeholder (possibly nested)."""
    if isinstance(value, str):
        return REDACTED in value
    if isinstance(value, dict):
        return any(_unresolved(v) for v in value.values())
    if isinstance(value, list):
        return any(_unresolved(v) for v in value)
    return False


# --------------------------------------------------------------------------
# Building requests from the index
# --------------------------------------------------------------------------


def _captured_cookie_names(conn: sqlite3.Connection, entry_id: int) -> list[str]:
    """Cookie NAMES sent with an entry (values are never read into output)."""
    names: list[str] = []
    for r in conn.execute(
        "SELECT value_raw, value_redacted FROM headers "
        "WHERE entry_id = ? AND side = 'request' AND lower(name) = 'cookie'",
        (entry_id,),
    ).fetchall():
        text = r["value_raw"] or r["value_redacted"] or ""
        for part in text.split(";"):
            n = part.split("=", 1)[0].strip()
            if n and "=" in part and n not in names:
                names.append(n)
    # Cookie headers are stored redacted; ingest still records NAMES of token-shaped cookies.
    for r in conn.execute(
        "SELECT DISTINCT name FROM value_shapes "
        "WHERE entry_id = ? AND side = 'request' AND where_kind = 'cookie' AND name IS NOT NULL",
        (entry_id,),
    ).fetchall():
        if r["name"] not in names:
            names.append(r["name"])
    return names


def parse_cookie_header(value: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for part in str(value).split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            if k.strip():
                out[k.strip()] = v.strip()
    return out


def _empty_names() -> dict[str, list[str]]:
    return {"headers": [], "cookies": [], "query": [], "fields": [], "prior_steps": []}


def _build_step(
    conn: sqlite3.Connection,
    entry_id: int,
    overrides: dict[str, Any],
    *,
    is_target: bool,
    needs: dict[str, list[str]],
    captcha: list[str],
) -> dict | None:
    row = conn.execute("SELECT * FROM entries WHERE entry_id = ?", (entry_id,)).fetchone()
    if not row:
        return None

    ov_headers = {str(k).lower(): (str(k), str(v)) for k, v in (overrides.get("headers") or {}).items()}
    ov_query = {str(k): str(v) for k, v in (overrides.get("query") or {}).items()}
    ov_body = dict(overrides.get("body") or {})

    # ---- headers
    headers: dict[str, str] = {}
    for h in conn.execute(
        "SELECT name, value_raw, value_redacted FROM headers WHERE entry_id = ? AND side = 'request' ORDER BY id",
        (entry_id,),
    ).fetchall():
        name = h["name"]
        low = name.lower()
        if low in _PLUMBING_HEADERS or low.startswith(":"):
            continue
        if low in ov_headers:
            headers[ov_headers[low][0]] = ov_headers[low][1]
            continue
        raw = h["value_raw"]
        if (
            is_sensitive_header(name)
            or is_sensitive_key(name)
            or raw is None
            or classify_value_shape(raw) in _SECRET_SHAPES
        ):
            if name not in needs["headers"]:
                needs["headers"].append(name)
            continue
        headers[name] = str(raw)
    cookie_header_captured = bool(
        conn.execute(
            "SELECT 1 FROM headers WHERE entry_id = ? AND side = 'request' AND lower(name) = 'cookie'",
            (entry_id,),
        ).fetchone()
    )
    if cookie_header_captured and not overrides.get("cookies") and "cookie" not in ov_headers:
        names = _captured_cookie_names(conn, entry_id)
        if names:
            for cn in names:
                if cn not in needs["cookies"]:
                    needs["cookies"].append(cn)
        elif "Cookie" not in needs["headers"]:
            needs["headers"].append("Cookie")
    have = {k.lower() for k in headers}
    for low, (name, val) in ov_headers.items():
        if low not in have and low not in _PLUMBING_HEADERS:
            headers[name] = val
    if "cookie" in ov_headers:
        headers["Cookie"] = ov_headers["cookie"][1]

    # ---- query
    query: list[tuple[str, str]] = []
    seen_q: set[str] = set()
    for k, v in parse_qsl(row["query_raw"] or "", keep_blank_values=True):
        seen_q.add(k)
        if is_captcha_name(k):
            if k not in captcha:
                captcha.append(k)
            continue
        if k in ov_query:
            query.append((k, ov_query[k]))
        elif REDACTED in v or is_sensitive_key(k):
            if k not in needs["query"]:
                needs["query"].append(k)
        else:
            query.append((k, v))
    if is_target:
        for k, v in ov_query.items():
            if k not in seen_q and not is_captcha_name(k):
                query.append((k, v))

    # ---- body
    body_kind = "none"
    fields: dict[str, Any] = {}
    raw_body: str | None = None
    body_row = conn.execute(
        "SELECT preview_text, content_type, size FROM bodies WHERE entry_id = ? AND side = 'request'",
        (entry_id,),
    ).fetchone()
    req_ct = next((v for k, v in headers.items() if k.lower() == "content-type"), "") or (
        (body_row["content_type"] if body_row else "") or ""
    )
    text = body_row["preview_text"] if body_row else None
    if text:
        parsed: Any = None
        kind_guess = "raw"
        if "json" in req_ct.lower() or text.lstrip().startswith(("{", "[")):
            try:
                parsed = safe_loads(text)
                kind_guess = "json" if isinstance(parsed, dict) else "raw"
            except ValueError:
                kind_guess = "raw"
        elif "x-www-form-urlencoded" in req_ct.lower() or (
            "=" in text and "\n" not in text.strip() and "multipart" not in req_ct.lower()
        ):
            kind_guess = "form"
        if kind_guess == "json":
            body_kind = "json"
            for k, v in parsed.items():
                if is_captcha_name(str(k)):
                    if k not in captcha:
                        captcha.append(str(k))
                elif k in ov_body:
                    fields[k] = ov_body[k]
                elif _unresolved(v) or is_sensitive_key(str(k)):
                    if k not in needs["fields"]:
                        needs["fields"].append(str(k))
                else:
                    fields[k] = v
        elif kind_guess == "form":
            body_kind = "form"
            for k, v in parse_qsl(text, keep_blank_values=True):
                if is_captcha_name(k):
                    if k not in captcha:
                        captcha.append(k)
                elif k in ov_body:
                    fields[k] = ov_body[k]
                elif REDACTED in v or is_sensitive_key(k):
                    if k not in needs["fields"]:
                        needs["fields"].append(k)
                else:
                    fields[k] = v
        else:
            body_kind = "raw"
            if REDACTED in text:
                if "(raw body)" not in needs["fields"]:
                    needs["fields"].append("(raw body)")
                body_kind = "none"
            else:
                raw_body = text
        if body_kind in {"json", "form"} and is_target:
            for k, v in ov_body.items():
                if k not in fields and not is_captcha_name(str(k)):
                    fields[k] = v
    return {
        "entry_id": entry_id,
        "method": row["method"],
        "scheme": row["scheme"],
        "host": row["host"],
        "path": row["path"],
        "headers": headers,
        "query": query,
        "body_kind": body_kind,
        "fields": fields,
        "raw_body": raw_body,
    }


# --------------------------------------------------------------------------
# Signatures and gates
# --------------------------------------------------------------------------


def _kind_of(resp: httpx.Response) -> str:
    if resp.request.method == "HEAD" or not resp.content:
        return "empty"
    ct = resp.headers.get("content-type", "").lower()
    text = resp.text
    head = text.lstrip()[:1]
    if "json" in ct:
        return "json"
    if "html" in ct or head == "<":
        return "html"
    if head in "{[":
        try:
            safe_loads(text)
            return "json"
        except ValueError:
            pass
    if "text" in ct or "xml" in ct:
        return "text"
    return "other"


_VOLATILE_KEY = re.compile(r"(time|date|stamp|^ts$|nonce|token|expires|^id$|uuid|trace|request_?id)", re.I)


def _canon(obj: Any, depth: int = 0) -> Any:
    if depth > 6:
        return "~"
    if isinstance(obj, dict):
        return {
            str(k): _canon(v, depth + 1)
            for k, v in sorted(obj.items(), key=lambda kv: str(kv[0]))
            if not _VOLATILE_KEY.search(str(k))
        }
    if isinstance(obj, list):
        return [_canon(v, depth + 1) for v in obj[:200]]
    return obj


def body_fingerprint(data: Any) -> str:
    """Short value-sensitive hash of a JSON body (volatile keys skipped)."""
    blob = json.dumps(_canon(data), sort_keys=True, default=str)
    return hashlib.sha1(blob.encode()).hexdigest()[:10]


def outcome_signature(resp: httpx.Response) -> dict:
    """Coarse, value-free outcome description."""
    kind = _kind_of(resp)
    sig: dict[str, Any] = {"status_class": f"{resp.status_code // 100}xx", "kind": kind}
    if kind == "json":
        try:
            data = resp.json()
        except ValueError:
            data = None
        if isinstance(data, dict):
            sig["keys"] = sorted(str(k) for k in data.keys())
            sig["body_fp"] = body_fingerprint(data)
        elif isinstance(data, list):
            sig["keys"] = ["[list]"]
            sig["length"] = len(data)
            sig["body_fp"] = body_fingerprint(data)
    elif kind == "html":
        n = len(resp.content)
        band = "xs" if n < 1024 else "s" if n < 10_240 else "m" if n < 102_400 else "l"
        sig["size_band"] = band
        sig["has_form"] = "<form" in resp.text.lower()
    return sig


def _describe(status: int, sig: dict) -> str:
    return f"{status} {str(sig.get('kind', '?')).upper()}"


def _gate_stop(resp: httpx.Response, allow: frozenset[str] = frozenset()) -> str | None:
    status = resp.status_code
    if status == 429:
        return "http_429"
    if "retry-after" in resp.headers:
        return "retry_after"
    body = ""
    try:
        body = resp.text[:20000]
    except Exception:
        pass
    if _classify_response is not None:
        try:
            for g in _classify_response(status, dict(resp.headers), body, str(resp.request.url)) or []:
                if isinstance(g, dict) and g.get("action") == "stop":
                    cls = str(g.get("class") or g.get("kind") or g.get("gate") or g.get("name") or "gate")
                    if cls in allow:
                        continue
                    return f"gate:{cls}"
        except Exception:
            pass
    elif status == 403 and any(w in body.lower() for w in _CHALLENGE_WORDS):
        return "challenge_403"
    return None


# --------------------------------------------------------------------------
# Runner
# --------------------------------------------------------------------------


class _Runner:
    def __init__(
        self,
        client: httpx.Client,
        *,
        max_requests: int,
        delay_s: float,
        allow_gates: frozenset[str] = frozenset(),
    ):
        self.allow_gates = allow_gates
        self.ablating = False
        self.client = client
        self.max_requests = max_requests
        self.delay_s = delay_s
        self.used = 0

    def reset_jar(self, cookies: dict[str, str], host: str) -> None:
        self.client.cookies.clear()
        domain = host.split(":")[0]
        for k, v in cookies.items():
            self.client.cookies.set(str(k), str(v), domain=domain)

    def snapshot(self) -> httpx.Cookies:
        return httpx.Cookies(self.client.cookies)

    def restore(self, snap: httpx.Cookies) -> None:
        self.client.cookies = httpx.Cookies(snap)

    def drop_cookie(self, name: str) -> None:
        jar = self.client.cookies.jar
        for c in [c for c in jar if c.name == name]:
            jar.clear(c.domain, c.path, c.name)

    def cookie_names(self) -> list[str]:
        out: list[str] = []
        for c in self.client.cookies.jar:
            if c.name not in out:
                out.append(c.name)
        return out

    def send(
        self,
        step: dict,
        drop: tuple[str, str] | None = None,
        drop_many: list[tuple[str, str]] | None = None,
    ) -> tuple[httpx.Response, list[int]]:
        """Send a step (following up to 5 same-host redirects). Returns (final response, chain statuses)."""
        headers = dict(step["headers"])
        query = list(step["query"])
        fields = dict(step["fields"])
        for cat, name in ([drop] if drop else []) + list(drop_many or []):
            if cat == "headers":
                headers = {k: v for k, v in headers.items() if k.lower() != name.lower()}
            elif cat == "query":
                query = [(k, v) for k, v in query if k != name]
            elif cat == "fields":
                fields.pop(name, None)
        content: bytes | None = None
        if step["body_kind"] == "json" and (step["fields"] or fields):
            content = json.dumps(fields).encode()
        elif step["body_kind"] == "form" and (step["fields"] or fields):
            content = urlencode([(k, str(v)) for k, v in fields.items()]).encode()
        elif step["body_kind"] == "raw" and step["raw_body"]:
            content = step["raw_body"].encode()

        url = f"{step['scheme']}://{step['host']}{step['path']}"
        if query:
            url += "?" + urlencode(query)
        method = step["method"]
        chain: list[int] = []
        base_host = step["host"].lower()
        for hop in range(MAX_REDIRECTS + 1):
            if self.used >= self.max_requests:
                raise _Budget()
            if self.used:
                if self.delay_s > 0:
                    time.sleep(self.delay_s)
            self.used += 1
            req = self.client.build_request(method, url, headers=headers, content=content)
            try:
                resp = self.client.send(req, follow_redirects=False)
            except httpx.HTTPError as exc:
                raise _Halt(f"transport_error:{type(exc).__name__}", step["path"]) from None
            chain.append(resp.status_code)
            # After the baseline, a login wall appearing means a removed piece carried the
            # session: that is an outcome to report, not a reason to stop.
            stop = _gate_stop(resp, self.allow_gates | ({"login"} if self.ablating else frozenset()))
            if stop:
                raise _Halt(stop, f"entry {step['entry_id']}")
            loc = resp.headers.get("location")
            if resp.status_code in (301, 302, 303, 307, 308) and loc and hop < MAX_REDIRECTS:
                nxt = urljoin(url, loc)
                if urlsplit(nxt).netloc.lower() != base_host:
                    return resp, chain  # never carry state to another host
                url = nxt
                if resp.status_code in (301, 302, 303) and method not in SAFE_METHODS:
                    method, content = "GET", None
                elif resp.status_code in (301, 302, 303):
                    content = None
                continue
            return resp, chain
        return resp, chain


def _is_sec_header(name: str) -> bool:
    return name.lower().startswith("sec-")


def _ordered_headers(names: list[str]) -> list[str]:
    def key(n: str) -> tuple[int, int]:
        low = n.lower()
        if low in _DECISIVE_HEADERS:
            return (0, _DECISIVE_HEADERS.index(low))
        if low.startswith("x-"):
            return (1, 0)
        return (2, 0)

    return sorted(names, key=key)


def replay_check(
    conn: sqlite3.Connection,
    entry_ids: int | list[int],
    *,
    overrides: dict[str, dict[str, Any]] | None = None,
    max_requests: int = 15,
    delay_s: float = 0.5,
    allow_unsafe: bool = False,
    client: httpx.Client | None = None,
    allow_gates: list[str] | None = None,
) -> dict:
    """Report which headers/cookies/params/fields/prior steps a replay REQUIRES vs. tolerates."""
    ids = [entry_ids] if isinstance(entry_ids, int) else [int(i) for i in entry_ids]
    if not ids:
        return {"error": "entry_ids is empty"}
    if overrides is not None and not isinstance(overrides, dict):
        return {"error": "overrides must be an object like {headers, cookies, query, body}"}
    overrides = dict(overrides or {})
    for part in ("headers", "cookies", "query", "body"):
        if part in overrides and not isinstance(overrides[part], dict):
            return {"error": f"overrides.{part} must be an object (name -> value)"}
    # A Cookie header override is itemised into named cookies for the jar.
    hdr_ov = dict(overrides.get("headers") or {})
    cookie_key = next((k for k in hdr_ov if str(k).lower() == "cookie"), None)
    if cookie_key is not None:
        merged = parse_cookie_header(str(hdr_ov.pop(cookie_key)))
        merged.update({str(k): str(v) for k, v in (overrides.get("cookies") or {}).items()})
        overrides["headers"] = hdr_ov
        overrides["cookies"] = merged
    gate_ok = frozenset(str(g) for g in (allow_gates or []))

    needs = _empty_names()
    needs_by_step: list[dict[str, list[str]]] = []
    captcha: list[str] = []
    steps: list[dict] = []
    for i, eid in enumerate(ids):
        step_needs = _empty_names()
        step = _build_step(conn, eid, overrides, is_target=(i == len(ids) - 1), needs=step_needs, captcha=captcha)
        if step is None:
            return {"error": f"entry_id {eid} not found"}
        steps.append(step)
        needs_by_step.append(step_needs)
        for cat, names in step_needs.items():
            for n in names:
                if n not in needs[cat]:
                    needs[cat].append(n)
    needs_out = {k: v for k, v in needs.items() if v and k != "prior_steps"}
    needs_out = {("body" if k == "fields" else k): v for k, v in needs_out.items()}

    if not allow_unsafe:
        refused = [{"entry_id": s["entry_id"], "method": s["method"]} for s in steps if s["method"] not in SAFE_METHODS]
        if refused:
            return {
                "error": "replay_check refuses non-idempotent methods without allow_unsafe=true",
                "refused": refused,
                "needs_override": needs_out,
                "requests_used": 0,
            }

    for st in steps:
        check_url(f"{st['scheme']}://{st['host']}/")
    own_client = client is None
    cl = client or new_client(timeout=20.0, follow_redirects=False)
    runner = _Runner(cl, max_requests=max_requests, delay_s=delay_s, allow_gates=gate_ok)
    target = steps[-1]
    prior = steps[:-1]
    ov_cookies = {str(k): str(v) for k, v in (overrides.get("cookies") or {}).items()}

    required = _empty_names()
    optional = _empty_names()
    not_tested = _empty_names()
    findings: list[str] = []
    halted: dict | None = None
    result: dict[str, Any] = {
        "entry_ids": ids,
        "target": {
            "entry_id": target["entry_id"],
            "method": target["method"],
            "host": target["host"],
            "path": target["path"],
        },
    }

    cap = conn.execute("SELECT status FROM entries WHERE entry_id = ?", (target["entry_id"],)).fetchone()
    cap_status = int(cap["status"]) if cap and cap["status"] else None
    if cap_status:
        result["captured"] = {"status": cap_status, "status_class": f"{cap_status // 100}xx"}

    def _halted(reason: str, at: str) -> dict:
        d: dict[str, Any] = {"reason": reason, "at": at}
        if reason.startswith("gate:"):
            d["gate_class"] = reason.split(":", 1)[1]
        return d

    def run_full(skip_idx: int | None = None):
        runner.reset_jar(ov_cookies, target["host"])
        for j, st in enumerate(prior):
            if j == skip_idx:
                continue
            runner.send(st)
        snap = runner.snapshot()
        resp, chain = runner.send(target)
        return resp, chain, snap

    try:
        try:
            resp, chain, snap = run_full()
        except _Budget:
            return {**result, "error": "max_requests too small for the baseline flow", "requests_used": runner.used}
        except _Halt as h:
            return {
                **result,
                "baseline": None,
                "halted": _halted(h.reason, h.at or "baseline"),
                "needs_override": needs_out,
                "skipped_captcha": captcha,
                "requests_used": runner.used,
                "findings": [f"halted during baseline: {h.reason}"],
            }
        base_sig = outcome_signature(resp)
        base_status = resp.status_code
        result["baseline"] = {"status": base_status, "signature": base_sig, "redirect_chain": chain}
        jar_names = runner.cookie_names()  # state after baseline
        runner.ablating = True
        if cap_status:
            same = base_status // 100 == cap_status // 100
            result["baseline_matches_captured"] = same
            if not same:
                findings.append(
                    f"baseline status {base_status} differs from the captured {cap_status}: "
                    "the replay is missing credentials or state, so required/optional results "
                    "may not reflect the original outcome"
                )

        if base_status >= 400:
            findings.append(
                f"baseline returned {_describe(base_status, base_sig)}; ablation skipped "
                "(supply missing overrides, see needs_override)"
            )
            halted = {"reason": "baseline_not_ok", "at": "baseline"}
            plan: list[tuple[str, str]] = []
            sec_group: list[str] = []
        else:
            plan = []
            hdrs = _ordered_headers(list(target["headers"].keys()))
            decisive = [h for h in hdrs if h.lower() in _DECISIVE_HEADERS]
            rest_h = [h for h in hdrs if h.lower() not in _DECISIVE_HEADERS]
            plan += [("headers", h) for h in decisive]
            plan += [("prior_steps", str(s["entry_id"])) for s in prior]
            cookie_names = list(ov_cookies.keys()) + [c for c in jar_names if c not in ov_cookies]
            plan += [("cookies", c) for c in cookie_names]
            plan += [("query", k) for k in dict.fromkeys(k for k, _ in target["query"])]
            plan += [("fields", k) for k in target["fields"]]
            sec_group = [h for h in rest_h if _is_sec_header(h)]
            rest_h = [h for h in rest_h if h not in sec_group]
            plan += [("headers", h) for h in rest_h]
            if len(sec_group) > 1:
                plan.append(("hgroup", "Sec-*"))
            else:
                plan += [("headers", h) for h in sec_group]

        def record(cat: str, name: str, changed: bool, trial_resp: httpx.Response | None) -> None:
            if cat == "hgroup":
                members = sec_group
                if changed:
                    required["headers"].extend(members)
                    assert trial_resp is not None
                    findings.append(
                        f"removing the Sec-*/sec-ch-* header group ({len(members)} headers, not bisected) changed "
                        f"{_describe(base_status, base_sig)} -> "
                        f"{_describe(trial_resp.status_code, outcome_signature(trial_resp))}"
                    )
                else:
                    optional["headers"].extend(members)
                return
            label = {"headers": "header", "cookies": "cookie", "query": "query param", "fields": "field", "prior_steps": "prior step"}[cat]
            if changed:
                required[cat].append(int(name) if cat == "prior_steps" else name)
                assert trial_resp is not None
                findings.append(
                    f"removing {label} {name} changed {_describe(base_status, base_sig)} -> "
                    f"{_describe(trial_resp.status_code, outcome_signature(trial_resp))}"
                )
            else:
                optional[cat].append(int(name) if cat == "prior_steps" else name)

        for idx, (cat, name) in enumerate(plan):
            cost = 1 if cat != "prior_steps" else len(steps) - 1
            if runner.used + cost > max_requests:
                for c2, n2 in plan[idx:]:
                    not_tested[c2].append(int(n2) if c2 == "prior_steps" else n2)
                findings.append(
                    f"request budget ({max_requests}) exhausted; {len(plan) - idx} element(s) not tested"
                )
                break
            try:
                if cat == "prior_steps":
                    skip = next(j for j, s in enumerate(prior) if str(s["entry_id"]) == name)
                    t_resp, _chain, _ = run_full(skip)
                else:
                    runner.restore(snap)
                    if cat == "cookies":
                        runner.drop_cookie(name)
                        t_resp, _chain = runner.send(target)
                    elif cat == "hgroup":
                        t_resp, _chain = runner.send(target, drop_many=[("headers", h) for h in sec_group])
                    else:
                        t_resp, _chain = runner.send(target, drop=(cat, name))
            except _Budget:
                for c2, n2 in plan[idx:]:
                    not_tested[c2].append(int(n2) if c2 == "prior_steps" else n2)
                break
            except _Halt as h:
                halted = _halted(h.reason, f"removing {cat} {name}")
                findings.append(f"hard stop ({h.reason}) while removing {cat.rstrip('s')} {name}; remaining elements not tested")
                for c2, n2 in plan[idx:]:
                    not_tested[c2].append(int(n2) if c2 == "prior_steps" else n2)
                break
            changed = outcome_signature(t_resp) != base_sig
            record(cat, name, changed, t_resp)

        # Joint ablation: either-or credentials (e.g. Authorization OR a session cookie)
        # each look optional alone; remove every optional credential piece together.
        if not halted and base_status < 400:
            ov_hdr_names = {str(k).lower() for k in (overrides.get("headers") or {})}
            cred_h = [
                h for h in optional["headers"]
                if is_sensitive_header(h) or is_sensitive_key(h) or h.lower() in ov_hdr_names
            ]
            cred_c = [c for c in optional["cookies"] if c in ov_cookies or is_sensitive_key(c)]
            if len(cred_h) + len(cred_c) >= 2 and runner.used < max_requests:
                try:
                    runner.restore(snap)
                    for c in cred_c:
                        runner.drop_cookie(c)
                    t_resp, _c = runner.send(target, drop_many=[("headers", h) for h in cred_h])
                except _Budget:
                    pass
                except _Halt as h:
                    halted = _halted(h.reason, "joint credential removal")
                    findings.append(f"hard stop ({h.reason}) during joint credential removal")
                else:
                    group = cred_h + cred_c
                    if outcome_signature(t_resp) != base_sig:
                        result["required_any_of"] = [group]
                        findings.append(
                            "credential pieces are individually optional but jointly required "
                            "(at least one of: " + ", ".join(group) + ") -> "
                            f"{_describe(t_resp.status_code, outcome_signature(t_resp))}"
                        )
    finally:
        if own_client:
            cl.close()

    if captcha:
        findings.append("captcha/challenge token fields were not sent or tested: " + ", ".join(captcha))
    for cat, label in (("headers", "headers"), ("cookies", "cookies"), ("query", "query params"), ("fields", "fields")):
        if required[cat]:
            findings.append(f"required {label}: " + ", ".join(map(str, required[cat])))
    if required["prior_steps"]:
        findings.append("required prior steps (entry ids): " + ", ".join(map(str, required["prior_steps"])))

    result.update(
        {
            "required": required,
            "optional": optional,
            "skipped_captcha": captcha,
            "needs_override": needs_out,
            "not_tested": not_tested,
            "requests_used": runner.used,
            "halted": halted,
            "findings": findings,
        }
    )
    return result
