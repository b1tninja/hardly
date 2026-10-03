"""HAR doctor: diagnose problems in a HAR file itself (not the browser).

``hardly_server_status`` checks the capture *environment*. This module checks
a finished *HAR*: truncated or missing bodies, sanitised headers, broken
timings, odd encodings, version/creator quirks, a stale index and so on. It
is content-neutral: it looks at structure, never at what a site is about.

The HAR is streamed with ijson (never loaded whole). Entry ids match the
ingest index (position in ``log.entries``).

Entry point: :func:`diagnose_har`. Tuning: :data:`KNOBS` / :func:`normalize_config`.
"""

from __future__ import annotations

import base64
import binascii
import fnmatch
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import ijson

from hardly.core.noise_hosts import is_noise_host

SEVERITIES = ("info", "warn", "error")
_SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}
#: Max entry ids listed per finding (``count`` is always the full count).
MAX_IDS = 50

#: code -> (default severity, one-line description)
CHECKS: dict[str, tuple[str, str]] = {
    "body_omitted": ("warn", "response body missing although the entry says it had one"),
    "body_truncated": ("warn", "response text is shorter than the declared size"),
    "preview_capped": ("info", "body longer than the index preview cap (indexed text is truncated)"),
    "bad_encoding": ("warn", "content.encoding is unknown or the base64 payload is invalid"),
    "base64_text": ("info", "textual body stored base64-encoded"),
    "request_body_missing": ("warn", "request with a body but no postData"),
    "no_timings": ("info", "entry has no usable timings"),
    "bad_timings": ("warn", "negative timing values other than -1"),
    "bad_start_time": ("warn", "startedDateTime missing or unparsable"),
    "out_of_order": ("info", "startedDateTime goes backwards beyond clock_skew_s"),
    "clock_skew": ("warn", "entry starts before its page beyond clock_skew_s"),
    "redirect_no_location": ("warn", "3xx redirect without Location"),
    "status_zero": ("warn", "status 0/-1/missing or _error (request failed or was blocked)"),
    "page_no_entries": ("warn", "page has no entries"),
    "dangling_pageref": ("warn", "entry pageref names a page that does not exist"),
    "missing_pageref": ("info", "pages exist but entries carry no pageref"),
    "missing_initiator": ("info", "Chrome-style HAR entries without _initiator"),
    "giant_entry": ("warn", "entry larger than thresholds.max_entry_bytes"),
    "duplicate_entry": ("warn", "identical entries (same request, time and response)"),
    "headers_redacted": ("warn", "request headers carry redacted values; replay impossible"),
    "cookies_stripped": ("warn", "Set-Cookie seen but no request ever sends cookies"),
    "http2_pseudo_headers": ("info", "HTTP/2 pseudo-headers (:method, :path ...) in headers"),
    "noise_hosts": ("info", "large share of tracker/ads/font noise hosts"),
    "mixed_hosts": ("info", "large share of entries off the primary host"),
    "har_version": ("warn", "unsupported HAR version or missing creator"),
    "creator_quirk": ("info", "known quirks of the tool that produced this HAR"),
    "index_stale": ("warn", "cached index no longer matches this HAR"),
}

#: code -> (hint, recapture flags: parameters of hardly_browser_start / hardly_browser_capture_discover)
FIXES: dict[str, tuple[str, dict[str, Any]]] = {
    "body_omitted": (
        "Recapture with response bodies enabled (omit_content=False); for Playwright use "
        "record_har_content='embed'.",
        {"omit_content": False},
    ),
    "body_truncated": (
        "The exporter cut the body. Recapture with omit_content=False and avoid DevTools "
        "'Save as HAR' on very large responses.",
        {"omit_content": False},
    ),
    "preview_capped": ("Informational: full text stays in the HAR; use hardly_entry_get/raw read for the rest.", {}),
    "bad_encoding": ("Re-export the HAR; the body encoding field is corrupt.", {}),
    "base64_text": ("Informational: hardly decodes textual base64 bodies at ingest.", {}),
    "request_body_missing": (
        "Recapture with request bodies recorded (omit_content=False); some exporters drop postData for "
        "multipart/binary uploads.",
        {"omit_content": False},
    ),
    "no_timings": ("Informational: timing-based tools (hardly_session_slow_requests) will skip these entries.", {}),
    "bad_timings": ("Re-export the HAR; timing fields are inconsistent.", {}),
    "bad_start_time": ("Re-export the HAR; ordering and page-relative checks are unreliable.", {}),
    "out_of_order": ("Informational: sort by startedDateTime before comparing; may indicate merged HARs.", {}),
    "clock_skew": ("Entries come from a different clock than their page; avoid merging HARs from several machines.", {}),
    "redirect_no_location": (
        "Redirect target was not recorded; recapture, or follow it via the next entry's Referer.",
        {},
    ),
    "status_zero": ("Check _error/_failureText; recapture, and avoid blockers that abort requests (exclude_noise=false).", {"exclude_noise": False}),
    "page_no_entries": ("Pages with no traffic can be dropped with `hardly write har-pruned HAR -o OUT`.", {}),
    "dangling_pageref": ("Re-export, or fix with `hardly write har-merged HAR -o OUT` on a single source.", {}),
    "missing_pageref": ("Informational: page grouping tools fall back to timing.", {}),
    "missing_initiator": ("Informational: initiator chains need a Chrome/Playwright capture.", {}),
    "giant_entry": (
        "Prune it (`hardly write har-pruned HAR -o OUT --drop-mime-types ...`) or raise thresholds.max_entry_bytes.",
        {},
    ),
    "duplicate_entry": ("The HAR was probably concatenated twice; dedupe with `hardly write har-merged HAR -o OUT`.", {}),
    "headers_redacted": (
        "Recapture without a sanitising exporter (Chrome 'Save all as HAR with content' keeps secrets "
        "only in the sensitive variant); replay needs real Authorization/Cookie values.",
        {},
    ),
    "cookies_stripped": (
        "Recapture with cookies kept; the HAR was sanitised so session replay cannot work.",
        {},
    ),
    "http2_pseudo_headers": ("Drop headers starting with ':' before replay (curl/requests reject them).", {}),
    "noise_hosts": ("Recapture with exclude_noise=true or strip them with `hardly write har-pruned HAR -o OUT --drop-noise`.", {"exclude_noise": True}),
    "mixed_hosts": ("Scope analysis with host=... or `hardly write har-split HAR --output-dir DIR --by host`.", {}),
    "har_version": ("Re-export as HAR 1.2.", {}),
    "creator_quirk": ("", {}),
    "index_stale": ("Re-run ingest (hardly_session_open(har_path, force=true)).", {}),
}

#: tuning knobs and their defaults
KNOBS: dict[str, Any] = {
    "checks": None,  # include list/globs (None = all)
    "exclude": [],  # exclude list/globs
    "severity_overrides": {},  # code -> info|warn|error
    "thresholds": {
        "max_entry_bytes": 10_000_000,
        "truncation_ratio": 0.9,  # text shorter than ratio*declared size => truncated
        "clock_skew_s": 5.0,
        "noise_ratio": 0.5,  # share of noise / off-primary-host entries to flag
        "min_entries": 10,  # ratio checks need at least this many entries
    },
    "strict": False,  # warn -> error
    "fail_on": "error",  # info|warn|error|never: exit_code=1 when a finding reaches it
    "host": None,  # glob or list of globs: only analyse matching hosts
    "ignore_hosts": [],
    "ignore_paths": [],
    "max_findings": None,
    "fix": True,  # include fix_hint / recapture suggestions
}

_REDACTED_RE = re.compile(
    r"^\W*(?:\**\s*)?(?:redacted|removed|stripped|masked|hidden|filtered|sanitized|sanitised|"
    r"\*{3,}|x{4,}|\.{3,}|<[^>]*>)(?:\s*\**)?\W*$",
    re.I,
)
_AUTH_HEADERS = {"authorization", "proxy-authorization", "cookie"}
_REDIRECTS = {301, 302, 303, 307, 308}
_BODY_METHODS = {"POST", "PUT", "PATCH"}
_TEXTUAL = ("text/", "json", "xml", "javascript", "ecmascript", "urlencoded", "html", "svg")


# --------------------------------------------------------------------------- config


def normalize_config(config: dict | str | Path | None) -> dict[str, Any]:
    """Merge a config (dict, JSON string, or JSON file path) over :data:`KNOBS`."""
    raw: dict[str, Any]
    if config is None:
        raw = {}
    elif isinstance(config, dict):
        raw = dict(config)
    else:
        text = str(config)
        p = Path(text)
        try:
            is_file = not text.lstrip().startswith("{") and p.is_file()
        except OSError:
            is_file = False
        raw = json.loads(p.read_text(encoding="utf-8") if is_file else text)
        if not isinstance(raw, dict):
            raise ValueError("config must be a JSON object")
    unknown = set(raw) - set(KNOBS)
    if unknown:
        raise ValueError(f"unknown config keys: {sorted(unknown)} (known: {sorted(KNOBS)})")
    cfg = {k: (dict(v) if isinstance(v, dict) else list(v) if isinstance(v, list) else v) for k, v in KNOBS.items()}
    for key, val in raw.items():
        if key == "thresholds":
            bad = set(val) - set(KNOBS["thresholds"])
            if bad:
                raise ValueError(f"unknown thresholds: {sorted(bad)}")
            cfg["thresholds"].update(val)
        elif key == "checks" and isinstance(val, dict):
            cfg["checks"] = val.get("include")
            cfg["exclude"] = list(val.get("exclude") or [])
        else:
            cfg[key] = val
    for key in ("checks", "exclude", "ignore_hosts", "ignore_paths", "host"):
        if isinstance(cfg[key], str):
            cfg[key] = [s.strip() for s in cfg[key].split(",") if s.strip()]
    for code, sev in (cfg["severity_overrides"] or {}).items():
        if code not in CHECKS:
            raise ValueError(f"severity_overrides: unknown check {code!r}")
        if sev not in SEVERITIES:
            raise ValueError(f"severity_overrides[{code}]: {sev!r} not in {SEVERITIES}")
    if cfg["fail_on"] not in (*SEVERITIES, "never"):
        raise ValueError("fail_on must be info|warn|error|never")
    return cfg


def add_cli_flags(parser) -> None:
    """Add the knobs as argparse flags (for ``hardly har file-check``)."""
    a = parser.add_argument
    a("--config", help="JSON file or JSON string with any of the knobs")
    a("--checks", help="comma list/globs of checks to run (default all)")
    a("--exclude", help="comma list/globs of checks to skip")
    a("--severity", action="append", metavar="CODE=LEVEL", help="override a severity (repeatable)")
    a("--max-entry-bytes", type=int)
    a("--truncation-ratio", type=float)
    a("--clock-skew-seconds", type=float, dest="clock_skew_s")
    a("--noise-ratio", type=float)
    a("--strict", action="store_true", help="treat warnings as errors")
    a("--fail-on", choices=[*SEVERITIES, "never"])
    a("--host", help="comma list of host globs to analyse")
    a("--ignore-host", action="append", dest="ignore_hosts")
    a("--ignore-path", action="append", dest="ignore_paths")
    a("--max-findings", type=int)
    a("--no-fix", action="store_true", help="omit fix hints")


def config_from_namespace(ns) -> dict[str, Any]:
    """Build a config dict from an argparse namespace made with :func:`add_cli_flags`."""
    cfg: dict[str, Any] = {}
    if getattr(ns, "config", None):
        cfg = normalize_config(ns.config)
        cfg = {k: v for k, v in cfg.items() if v != KNOBS[k]}
    th = dict(cfg.get("thresholds") or {})
    for flag, key in (
        ("max_entry_bytes", "max_entry_bytes"),
        ("truncation_ratio", "truncation_ratio"),
        ("clock_skew_s", "clock_skew_s"),
        ("noise_ratio", "noise_ratio"),
    ):
        if getattr(ns, flag, None) is not None:
            th[key] = getattr(ns, flag)
    if th:
        cfg["thresholds"] = th
    for flag in ("checks", "exclude", "host", "max_findings", "fail_on"):
        if getattr(ns, flag, None) is not None:
            cfg[flag] = getattr(ns, flag)
    if getattr(ns, "strict", False):
        cfg["strict"] = True
    if getattr(ns, "no_fix", False):
        cfg["fix"] = False
    for flag in ("ignore_hosts", "ignore_paths"):
        if getattr(ns, flag, None):
            cfg[flag] = list(getattr(ns, flag))
    if getattr(ns, "severity", None):
        cfg["severity_overrides"] = dict(s.split("=", 1) for s in ns.severity)
    return cfg


# --------------------------------------------------------------------------- helpers


def _num(v: Any) -> float | None:
    if v is None or isinstance(v, bool):
        return None
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _parse_ts(s: Any) -> float | None:
    if not isinstance(s, str) or not s:
        return None
    t = s.strip()
    if t.endswith(("Z", "z")):
        t = t[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(t)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def _hmap(headers: Any) -> dict[str, str]:
    out: dict[str, str] = {}
    for h in headers or []:
        if isinstance(h, dict):
            out.setdefault(str(h.get("name", "")).lower(), str(h.get("value", "")))
    return out


def _matches(value: str, globs: list[str] | None) -> bool:
    return any(fnmatch.fnmatchcase(value.lower(), g.lower()) for g in globs or [])


def _selected(code: str, cfg: dict) -> bool:
    inc, exc = cfg["checks"], cfg["exclude"]
    if inc and not _matches(code, inc):
        return False
    return not (exc and _matches(code, exc))


def _creator_family(creator: Any) -> str:
    name = str((creator or {}).get("name", "") if isinstance(creator, dict) else "").lower()
    for key, fam in (
        ("webinspector", "chrome"),
        ("chrome", "chrome"),
        ("chromium", "chrome"),
        ("playwright", "playwright"),
        ("firefox", "firefox"),
        ("firebug", "firefox"),
        ("mitmproxy", "mitmproxy"),
        ("charles", "charles"),
        ("fiddler", "fiddler"),
        ("hardly", "hardly"),
    ):
        if key in name:
            return fam
    return "unknown" if name else "missing"


_QUIRKS = {
    "chrome": "Chrome/DevTools HAR: bodies only with 'Save all as HAR with content'; HTTP/2 pseudo-headers and _initiator present; sanitised variant strips cookies/Authorization.",
    "playwright": "Playwright HAR: bodies need record_har_content='embed' (omit gives size -1); some XHR bodies are missing even when embedded; _monotonicTime fields are non-standard.",
    "firefox": "Firefox HAR: no _initiator, cached responses often lack bodies, pages carry pageTimings only.",
    "mitmproxy": "mitmproxy HAR: usually no pages/pageref, timings often -1, request bodies may be base64.",
    "charles": "Charles HAR: binary and many text bodies are base64-encoded, timings often -1, no pages.",
    "fiddler": "Fiddler HAR: bodies base64-encoded, comment fields carry session metadata.",
}


# --------------------------------------------------------------------------- core


class _Acc:
    def __init__(self) -> None:
        self.ids: dict[str, list[int]] = {}
        self.count: Counter[str] = Counter()
        self.notes: dict[str, list[str]] = {}

    def add(self, code: str, eid: int | None, note: str | None = None) -> None:
        self.count[code] += 1
        if eid is not None:
            ids = self.ids.setdefault(code, [])
            if len(ids) < MAX_IDS:
                ids.append(eid)
        if note:
            notes = self.notes.setdefault(code, [])
            if note not in notes and len(notes) < 3:
                notes.append(note)


def _stream_top(path: Path) -> dict[str, Any]:
    """Version, creator, browser, pages (small, usually before entries)."""
    top: dict[str, Any] = {"version": None, "creator": None, "pages": []}
    with path.open("rb") as f:
        for prefix, event, value in ijson.parse(f, use_float=True):
            if prefix == "log.version" and event == "string":
                top["version"] = value
            elif prefix == "log.entries" and event == "start_array":
                break
    with path.open("rb") as f:
        for c in ijson.items(f, "log.creator", use_float=True):
            top["creator"] = c
    with path.open("rb") as f:
        top["pages"] = [p for p in ijson.items(f, "log.pages.item", use_float=True)]
    return top


def _body_check(acc: _Acc, eid: int, entry: dict, req: dict, resp: dict, cfg: dict) -> None:
    th = cfg["thresholds"]
    method = str(req.get("method") or "GET").upper()
    status = int(_num(resp.get("status")) or 0)
    content = resp.get("content") if isinstance(resp.get("content"), dict) else {}
    text = content.get("text")
    size = _num(content.get("size"))
    mime = str(content.get("mimeType") or "").lower()
    enc = content.get("encoding")
    body_size = _num(resp.get("bodySize"))
    declared = max(x for x in (size, body_size, 0.0) if x is not None)
    expects_body = method != "HEAD" and status >= 200 and status not in (204, 205, 304) and status not in _REDIRECTS

    if expects_body and not text:
        if size == -1 or declared > 0:
            acc.add("body_omitted", eid, f"content.size={None if size is None else int(size)}")
    elif text:
        bad_enc = False
        if enc not in (None, "", "base64"):
            acc.add("bad_encoding", eid, f"unknown encoding {enc!r}")
            bad_enc = True
        raw_len = len(text)
        if enc == "base64":
            head = text[:4096]
            head = head[: len(head) - len(head) % 4]
            try:
                base64.b64decode(head, validate=True)
            except (binascii.Error, ValueError):
                acc.add("bad_encoding", eid, "invalid base64 payload")
                bad_enc = True
            raw_len = len(text) * 3 // 4
            if any(t in mime for t in _TEXTUAL):
                acc.add("base64_text", eid)
        else:
            raw_len = len(text.encode("utf-8", errors="replace")) if len(text) < 4_000_000 else len(text)
        if not bad_enc and size and size > 0 and raw_len < size * th["truncation_ratio"] and status != 206:
            acc.add("body_truncated", eid, f"{raw_len} of {int(size)} bytes")
        from hardly.index.ingest import HTML_PREVIEW_CHARS, PREVIEW_CHARS

        cap = HTML_PREVIEW_CHARS if "html" in mime else PREVIEW_CHARS
        if len(text) > cap:
            acc.add("preview_capped", eid, f"cap {cap} chars")

    # request body
    post = req.get("postData")
    rbs = _num(req.get("bodySize"))
    clen = _num(_hmap(req.get("headers")).get("content-length"))
    if method in _BODY_METHODS and not (isinstance(post, dict) and (post.get("text") or post.get("params"))):
        if (rbs and rbs > 0) or (clen and clen > 0):
            acc.add("request_body_missing", eid)

    big = max(declared, rbs or 0, len(text) if text else 0)
    if big > th["max_entry_bytes"]:
        acc.add("giant_entry", eid, f"{int(big)} bytes")


def _header_checks(acc: _Acc, eid: int, req: dict, resp: dict, state: dict) -> None:
    hdrs = req.get("headers") or []
    redacted = False
    for h in hdrs:
        if not isinstance(h, dict):
            continue
        name = str(h.get("name", ""))
        low = name.lower()
        val = str(h.get("value", ""))
        if name.startswith(":"):
            acc.add("http2_pseudo_headers", eid)
        if low == "cookie" and val.strip():
            state["req_cookie_seen"] = True
        if low in _AUTH_HEADERS:
            if _REDACTED_RE.match(val) or "redacted" in val.lower():
                redacted = True
    if req.get("cookies"):
        state["req_cookie_seen"] = True
    if redacted:
        acc.add("headers_redacted", eid)
    for h in resp.get("headers") or []:
        if isinstance(h, dict) and str(h.get("name", "")).startswith(":"):
            acc.add("http2_pseudo_headers", eid)
            break
    if resp.get("cookies") or any(
        isinstance(h, dict) and str(h.get("name", "")).lower() == "set-cookie" for h in resp.get("headers") or []
    ):
        state["set_cookie_ids"].append(eid)


def diagnose_har(conn, har_path: str | Path, config: dict | str | Path | None = None) -> dict[str, Any]:
    """Diagnose problems in a HAR file.

    ``conn`` is the session's SQLite connection (used only for the index
    staleness check; ``None`` is fine). Returns::

        {"har_path", "entries", "scoped_entries", "creator", "har_version",
         "findings": [{code, severity, count, entry_ids, message, fix_hint}],
         "summary": {"info": n, "warn": n, "error": n},
         "exit_code": 0|1, "dropped_findings": n, "recapture": {...}}

    Findings are sorted error -> warn -> info. See :data:`KNOBS` for ``config``.
    """
    cfg = normalize_config(config)
    th = cfg["thresholds"]
    path = Path(har_path)
    top = _stream_top(path)
    acc = _Acc()
    pages = top["pages"]
    page_ids = {str(p.get("id")) for p in pages if isinstance(p, dict) and p.get("id") is not None}
    page_start = {str(p.get("id")): _parse_ts(p.get("startedDateTime")) for p in pages if isinstance(p, dict)}
    family = _creator_family(top["creator"])
    state: dict[str, Any] = {"req_cookie_seen": False, "set_cookie_ids": []}

    total = scoped = 0
    pagerefs_used: set[str] = set()
    host_counts: Counter[str] = Counter()
    noise_ids: list[int] = []
    off_ids: dict[str, list[int]] = {}
    scoped_hosts: list[tuple[int, str]] = []
    seen: set[tuple] = set()
    prev_ts: float | None = None
    host_scope = cfg["host"]

    with path.open("rb") as f:
        for eid, entry in enumerate(ijson.items(f, "log.entries.item", use_float=True)):
            total += 1
            if not isinstance(entry, dict):
                continue
            req = entry.get("request") or {}
            resp = entry.get("response") or {}
            ref = entry.get("pageref")
            if ref is not None:
                pagerefs_used.add(str(ref))
            url = str(req.get("url") or "")
            parsed = urlparse(url)
            host = parsed.netloc.lower()
            if host_scope and not _matches(host, host_scope):
                continue
            if cfg["ignore_hosts"] and _matches(host, cfg["ignore_hosts"]):
                continue
            if cfg["ignore_paths"] and _matches(parsed.path or "/", cfg["ignore_paths"]):
                continue
            scoped += 1
            scoped_hosts.append((eid, host))
            host_counts[host] += 1

            status = _num(resp.get("status"))
            if status is None or status <= 0 or entry.get("_error") or resp.get("_error") or resp.get("_failureText"):
                why = entry.get("_error") or resp.get("_error") or resp.get("_failureText") or f"status {status}"
                acc.add("status_zero", eid, str(why)[:80])
            elif int(status) in _REDIRECTS:
                loc = _hmap(resp.get("headers")).get("location") or resp.get("redirectURL")
                if not loc:
                    acc.add("redirect_no_location", eid)

            _body_check(acc, eid, entry, req, resp, cfg)
            _header_checks(acc, eid, req, resp, state)

            # timings
            tm = entry.get("timings")
            total_ms = _num(entry.get("time"))
            vals = [_num(v) for k, v in (tm or {}).items() if k != "comment" and not str(k).startswith("_")] if isinstance(tm, dict) else []
            vals = [v for v in vals if v is not None]
            if not isinstance(tm, dict) or not vals or (all(v < 0 for v in vals) and (total_ms is None or total_ms < 0)):
                acc.add("no_timings", eid)
            elif any(v < -1 for v in vals):
                acc.add("bad_timings", eid)

            ts = _parse_ts(entry.get("startedDateTime"))
            if ts is None:
                acc.add("bad_start_time", eid)
            else:
                if prev_ts is not None and ts < prev_ts - th["clock_skew_s"]:
                    acc.add("out_of_order", eid, f"{prev_ts - ts:.1f}s backwards")
                prev_ts = ts if prev_ts is None else max(prev_ts, ts)
                ps = page_start.get(str(ref)) if ref is not None else None
                if ps is not None and ts < ps - th["clock_skew_s"]:
                    acc.add("clock_skew", eid, f"{ps - ts:.1f}s before page")

            if ref is not None and page_ids and str(ref) not in page_ids:
                acc.add("dangling_pageref", eid, f"pageref {ref!r}")
            if ref is None and pages and family not in ("mitmproxy", "charles"):
                acc.add("missing_pageref", eid)
            if family == "chrome" and "_initiator" not in entry:
                acc.add("missing_initiator", eid)

            key = (
                req.get("method"),
                url,
                entry.get("startedDateTime"),
                resp.get("status"),
                (resp.get("content") or {}).get("size"),
                (resp.get("content") or {}).get("text") and hash(resp["content"]["text"]),
            )
            if key in seen:
                acc.add("duplicate_entry", eid)
            else:
                seen.add(key)

    # pages without entries (based on all entries, regardless of scope)
    for p in pages:
        if isinstance(p, dict) and p.get("id") is not None and str(p["id"]) not in pagerefs_used:
            acc.add("page_no_entries", None, f"page {p['id']!r}")
    # cookies stripped
    if state["set_cookie_ids"] and not state["req_cookie_seen"]:
        for eid in state["set_cookie_ids"][:MAX_IDS]:
            acc.ids.setdefault("cookies_stripped", []).append(eid)
        acc.count["cookies_stripped"] = len(state["set_cookie_ids"])

    # host mix
    if scoped >= th["min_entries"] and scoped_hosts:
        noisy = [(e, h) for e, h in scoped_hosts if is_noise_host(h)]
        if len(noisy) / scoped >= th["noise_ratio"]:
            acc.count["noise_hosts"] = len(noisy)
            acc.ids["noise_hosts"] = [e for e, _ in noisy[:MAX_IDS]]
            acc.notes["noise_hosts"] = [f"{len(noisy)}/{scoped} entries ({len(noisy) / scoped:.0%})"]
        primary = host_counts.most_common(1)[0][0]
        off = [(e, h) for e, h in scoped_hosts if h != primary]
        if len(off) / scoped >= th["noise_ratio"]:
            acc.count["mixed_hosts"] = len(off)
            acc.ids["mixed_hosts"] = [e for e, _ in off[:MAX_IDS]]
            acc.notes["mixed_hosts"] = [f"primary {primary}; {len(off)}/{scoped} entries elsewhere ({len(off) / scoped:.0%})"]

    # version / creator
    ver = top["version"]
    if ver not in ("1.1", "1.2"):
        acc.add("har_version", None, f"log.version={ver!r}")
    if family == "missing":
        acc.add("har_version", None, "log.creator missing")
    if family in _QUIRKS:
        acc.add("creator_quirk", None, _QUIRKS[family])

    # index staleness
    if conn is not None:
        _index_stale(conn, path, total, acc)

    return _finish(cfg, acc, path, total, scoped, top, family)


def _index_stale(conn, path: Path, total: int, acc: _Acc) -> None:
    try:
        meta = {r[0]: r[1] for r in conn.execute("SELECT key, value FROM meta")}
        st = path.stat()
        if meta.get("har_size") and int(meta["har_size"]) != st.st_size:
            acc.add("index_stale", None, "HAR size changed since indexing")
        elif meta.get("har_mtime") and abs(float(meta["har_mtime"]) - st.st_mtime) > 0.001:
            acc.add("index_stale", None, "HAR modified since indexing")
        if meta.get("entry_count") and int(meta["entry_count"]) != total:
            acc.add("index_stale", None, f"index has {meta['entry_count']} entries, HAR has {total}")
        if meta.get("har_path") and meta["har_path"] != str(path.resolve()):
            acc.add("index_stale", None, "index was built from a different file")
        # index_version lives in the sidecar json next to the db file
        from hardly.index.ingest import INDEX_VERSION

        row = conn.execute("PRAGMA database_list").fetchone()
        db_file = row[2] if row else ""
        if db_file:
            side = Path(db_file).with_suffix(".json")
            if side.is_file():
                iv = json.loads(side.read_text(encoding="utf-8")).get("index_version")
                if iv != INDEX_VERSION:
                    acc.add("index_stale", None, f"index_version {iv} != current {INDEX_VERSION}")
    except Exception:  # noqa: BLE001 - a broken index must not break the doctor
        acc.add("index_stale", None, "index metadata unreadable")


_GLOBAL = {"har_version", "index_stale", "page_no_entries", "noise_hosts", "mixed_hosts", "cookies_stripped", "creator_quirk"}


def _message(code: str, count: int, notes: list[str]) -> str:
    msg = CHECKS[code][1]
    if code not in _GLOBAL:
        msg = f"{count} entr{'y' if count == 1 else 'ies'}: {msg}"
    if notes:
        msg += " (" + "; ".join(notes) + ")"
    return msg


def _finish(cfg: dict, acc: _Acc, path: Path, total: int, scoped: int, top: dict, family: str) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    recapture: dict[str, Any] = {}
    for code, count in acc.count.items():
        if count <= 0 or not _selected(code, cfg):
            continue
        sev = (cfg["severity_overrides"] or {}).get(code) or CHECKS[code][0]
        if cfg["strict"] and sev == "warn" and code not in (cfg["severity_overrides"] or {}):
            sev = "error"
        hint, flags = FIXES.get(code, ("", {}))
        if cfg["fix"] and flags:
            recapture.update(flags)
        findings.append(
            {
                "code": code,
                "severity": sev,
                "count": count,
                "entry_ids": acc.ids.get(code, []),
                "message": _message(code, count, acc.notes.get(code, [])),
                "fix_hint": hint if cfg["fix"] else "",
            }
        )
    findings.sort(key=lambda f: (-_SEV_RANK[f["severity"]], -f["count"], f["code"]))
    dropped = 0
    if cfg["max_findings"] is not None and len(findings) > cfg["max_findings"]:
        dropped = len(findings) - int(cfg["max_findings"])
        findings = findings[: int(cfg["max_findings"])]
    summary = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITIES}
    return {
        "har_path": str(path),
        "entries": total,
        "scoped_entries": scoped,
        "har_version": top["version"],
        "creator": top["creator"],
        "creator_family": family,
        "findings": findings,
        "summary": summary,
        "exit_code": exit_code(findings, cfg["fail_on"]),
        "dropped_findings": dropped,
        "recapture": recapture if cfg["fix"] else {},
    }


def exit_code(findings: list[dict], fail_on: str = "error") -> int:
    """1 when any finding reaches ``fail_on`` severity, else 0 (``never`` -> 0)."""
    if fail_on == "never":
        return 0
    floor = _SEV_RANK[fail_on]
    return 1 if any(_SEV_RANK[f["severity"]] >= floor for f in findings) else 0
