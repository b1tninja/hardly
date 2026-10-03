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
            start = max(0, m.start() - 40)
            end = min(len(js), m.end() + 60)
            ctx = re.sub(r"\s+", " ", js[start:end]).strip()
            row = found.setdefault(
                path,
                {
                    "path": path,
                    "count": 0,
                    "score": _score(path),
                    "samples": [],
                },
            )
            row["count"] += 1
            if len(row["samples"]) < 3 and ctx not in row["samples"]:
                row["samples"].append(ctx[:160])
    return sorted(
        found.values(),
        key=lambda r: (-r["score"], -r["count"], r["path"]),
    )


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
