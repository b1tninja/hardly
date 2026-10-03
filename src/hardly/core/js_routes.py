"""Mine URL path strings from JavaScript bodies (portal reverse-engineering).

Quoted paths in app JS (``'/Details/'``, ``\"/Search/GridResults\"``) often
reveal endpoints that never appear as top-level navigations.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urljoin, urlsplit

# Quoted absolute-path or relative app paths.
_PATH_LIT = re.compile(
    r"""(?P<q>['"])(?P<path>(?:\.\./)*(?:/[A-Za-z0-9_.${}-][^'"]{0,120}))(?P=q)"""
)
# Concat patterns: '/details/documentdetails/' + id
_PATH_CONCAT = re.compile(
    r"""(?P<q>['"])(?P<path>/[A-Za-z0-9_./${}-]{2,100}/)(?P=q)\s*\+"""
)

_SKIP_SUFFIX = (
    ".css",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".woff",
    ".woff2",
    ".ttf",
    ".map",
    ".ico",
)
_SKIP_PREFIX = ("/content/images", "/scripts/jquery", "/scripts/microsoft", "/scripts/knockout")
_SKIP_EXACT = {"/", "//", "/scripts/", "/content/", "/images/"}

_INTERESTING = re.compile(
    r"(search|detail|document|grid|image|party|login|auth|api|order|"
    r"result|view|info|index|ajax|post|get|jump|cart|disclaimer)",
    re.I,
)


_STRING_LIT = re.compile(r"'(?:[^'\\\n]|\\.)*'|\"(?:[^\"\\\n]|\\.)*\"")


def _safe_sample(js: str, m: re.Match[str], raw: str) -> str:
    """The call head up to and including the route literal: no payload values.

    Starts after the last statement boundary and blanks every string literal
    except the route itself, so ``note:'secret'`` earlier on the line is never
    echoed. Nothing after the route is included (that is where payloads live).
    """
    start = max(0, m.start() - 60)
    head = js[start : m.end() + 1]
    cut = max(head.rfind(c, 0, m.start() - start) for c in (";", "{", "}", "\n", ","))
    if cut >= 0:
        head = head[cut + 1 :]
    head = _STRING_LIT.sub(lambda s: s.group(0) if raw in s.group(0) else s.group(0)[0] * 2, head)
    return re.sub(r"\s+", " ", head).strip()[:120]


def extract_js_routes(js: str, *, base_url: str = "") -> list[dict[str, Any]]:
    """Return unique path candidates with scores and sample contexts."""
    if not (js or "").strip():
        return []
    found: dict[str, dict[str, Any]] = {}
    for regex in (_PATH_LIT, _PATH_CONCAT):
        for m in regex.finditer(js):
            raw = m.group("path")
            path = _normalize_path(raw, base_url=base_url)
            if not path or not _keep(path):
                continue
            ctx = _safe_sample(js, m, raw)
            row = found.setdefault(
                path,
                {
                    "path": path,
                    "count": 0,
                    "score": _score(path),
                    "samples": [],
                    "body_keys": [],
                    "method": None,
                },
            )
            row["count"] += 1
            keys, method = _call_details(js, m)
            for k in keys:
                if k not in row["body_keys"] and len(row["body_keys"]) < _MAX_KEYS:
                    row["body_keys"].append(k)
            if method and not row["method"]:
                row["method"] = method
            if len(row["samples"]) < 3 and ctx not in row["samples"]:
                row["samples"].append(ctx[:160])
    return sorted(
        found.values(),
        key=lambda r: (-r["score"], -r["count"], r["path"]),
    )


_MAX_KEYS = 12
_WINDOW = 400
_CALL_PREFIX = re.compile(
    r"""(?:\(\s*|\burl\s*:\s*|\.open\(\s*['"]\w+['"]\s*,\s*)$"""
)
_OPEN_PREFIX = re.compile(r"""\.open\(\s*['"](\w+)['"]\s*,\s*$""")
_VERB_CALL = re.compile(r"\.(get|post|put|patch|delete|getJSON|load)\(\s*$", re.I)
_METHOD_KV = re.compile(
    r"""\b(?:method|type)\s*:\s*['"](GET|POST|PUT|PATCH|DELETE|HEAD)['"]""", re.I
)
_KEY_RE = re.compile(r"""(?:^|[{,])\s*["']?([A-Za-z_$][\w$-]{0,40})["']?\s*:(?!:)""")
_HEADERS_OBJ = re.compile(r"\bheaders\s*:\s*\{[^{}]*\}", re.I)
_IDENT = re.compile(r"[A-Za-z_$][\w$-]{0,40}")
# Option names of fetch/$.ajax/axios, not payload fields.
_CONTROL_KEYS = {
    "method", "type", "url", "headers", "success", "error", "complete", "data",
    "body", "params", "credentials", "mode", "cache", "async", "timeout",
    "processdata", "beforesend", "datatype", "contenttype", "redirect",
    "referrer", "signal", "withcredentials", "responsetype", "xhrfields",
}


def _scan_call(js: str, pos: int) -> tuple[str, str]:
    """Return (raw, clean) text after ``pos`` up to the end of the call.

    ``clean`` keeps object keys but blanks string-literal VALUES so values can
    never be reported. Scanning stops at the enclosing closer, a callback
    (``function`` / ``=>``) or the window limit.
    """
    seg = js[pos : pos + _WINDOW]
    clean: list[str] = []
    depth = 0
    i = 0
    n = len(seg)
    while i < n:
        ch = seg[i]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if depth < 0:
                break
        elif ch == "=" and seg.startswith("=>", i):
            break
        elif ch == "f" and seg.startswith("function", i) and not (
            i and (seg[i - 1].isalnum() or seg[i - 1] in "_$")
        ):
            break
        if ch in "\"'":
            j = i + 1
            while j < n and seg[j] != ch:
                j += 2 if seg[j] == "\\" else 1
            inner = seg[i + 1 : j]
            k = j + 1
            while k < n and seg[k].isspace():
                k += 1
            is_key = k < n and seg[k] == ":" and _IDENT.fullmatch(inner)
            clean.append(ch + (inner if is_key else " " * len(inner)) + ch)
            i = j + 1
            continue
        clean.append(ch)
        i += 1
    return seg[:i], "".join(clean)


def _call_details(js: str, m: re.Match[str]) -> tuple[list[str], str | None]:
    """Payload KEY NAMES (never values) and HTTP method near a route literal."""
    before = js[max(0, m.start() - 80) : m.start()]
    if not _CALL_PREFIX.search(before):
        return [], None
    method: str | None = None
    vm = _VERB_CALL.search(before)
    if vm:
        verb = vm.group(1).lower()
        method = "GET" if verb in {"getjson", "load"} else verb.upper()
    om = _OPEN_PREFIX.search(before)
    pos = m.end()
    if om:
        method = om.group(1).upper()
        sm = re.search(r"\.send\(", js[pos : pos + _WINDOW])
        if not sm:
            return [], method
        pos += sm.end()
    raw, clean = _scan_call(js, pos)
    if not method:
        mm = _METHOD_KV.search(raw) or _METHOD_KV.search(
            js[max(0, m.start() - 160) : m.start()]
        )
        if mm:
            method = mm.group(1).upper()
    clean = _HEADERS_OBJ.sub("", clean)
    keys: list[str] = []
    for km in _KEY_RE.finditer(clean):
        name = km.group(1)
        if name.lower() in _CONTROL_KEYS or name in keys:
            continue
        keys.append(name)
        if len(keys) >= _MAX_KEYS:
            break
    return keys, method


def _normalize_path(raw: str, *, base_url: str = "") -> str | None:
    text = (raw or "").strip()
    if not text or "${" in text or "{" in text:
        return None
    # Strip query/hash leftovers inside the literal
    text = text.split("?", 1)[0].split("#", 1)[0]
    if text.startswith("../") or (not text.startswith("/") and base_url):
        joined = urljoin(base_url if base_url.endswith("/") else base_url + "/", text)
        parts = urlsplit(joined)
        text = parts.path or ""
    if not text.startswith("/"):
        return None
    # Collapse //
    while "//" in text:
        text = text.replace("//", "/")
    return text


def _keep(path: str) -> bool:
    lower = path.lower()
    if lower in _SKIP_EXACT or len(path) < 3:
        return False
    if any(lower.endswith(suf) for suf in _SKIP_SUFFIX):
        return False
    if any(lower.startswith(p) for p in _SKIP_PREFIX):
        return False
    # Require at least one path segment with a letter
    segs = [s for s in path.split("/") if s]
    if not segs:
        return False
    if not any(re.search(r"[A-Za-z]", s) for s in segs):
        return False
    return True


def _score(path: str) -> int:
    score = 1
    if _INTERESTING.search(path):
        score += 5
    segs = [s for s in path.split("/") if s]
    score += min(len(segs), 4)
    if path.rstrip("/").count("/") >= 2:
        score += 1
    lower = path.lower()
    if any(tok in lower for tok in ("detail", "document", "grid", "search")):
        score += 3
    if lower.endswith((".js", ".aspx", ".do", ".ashx")):
        score += 1
    return score
