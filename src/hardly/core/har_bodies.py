"""Backfill HAR response bodies omitted by Playwright (content.size == -1).

Playwright's ``record_har_content=embed`` still leaves many XHR/fetch
responses without ``content.text``. During capture we keep a sidecar of
text-ish bodies from ``response.text()`` and merge them into the HAR after
the context closes so ``hardly_page_forms`` / ``hardly_entry_get`` see the HTML.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

# Cap per body so a runaway download cannot balloon the HAR.
MAX_BODY_CHARS = 2_000_000

_TEXTISH = (
    "text/",
    "json",
    "xml",
    "javascript",
    "ecmascript",
    "urlencoded",
    "html",
    "+json",
    "+xml",
)


def interesting_mime(mime: str | None) -> bool:
    """True when the Content-Type is worth storing for reverse-engineering."""
    if not mime:
        return True  # XHR often omits; still try text()
    lower = mime.lower()
    if "octet-stream" in lower or lower.startswith(("image/", "audio/", "video/", "font/")):
        return False
    return any(token in lower for token in _TEXTISH)


def shape_body(text: str, *, max_chars: int = MAX_BODY_CHARS) -> str:
    if len(text) <= max_chars:
        return text
    return text[:max_chars]


def merge_bodies_into_har(
    har_path: Path | str,
    bodies: list[dict[str, Any]],
) -> dict[str, int]:
    """Fill HAR entries that lack ``response.content.text``.

    Matching is FIFO on ``(method, url, status)``. Only empty / missing text
    is replaced; existing embedded content is left alone.
    """
    path = Path(har_path)
    stats = {"filled": 0, "skipped": 0, "unmatched": 0, "entries": 0}
    if not path.is_file() or not bodies:
        stats["unmatched"] = len(bodies)
        return stats

    data = json.loads(path.read_text(encoding="utf-8"))
    entries = (data.get("log") or {}).get("entries") or []
    stats["entries"] = len(entries)

    buckets: dict[tuple[str, str, int], list[dict[str, Any]]] = {}
    for row in bodies:
        method = str(row.get("method") or "GET").upper()
        url = str(row.get("url") or "")
        status = int(row.get("status") or 0)
        buckets.setdefault((method, url, status), []).append(row)

    for entry in entries:
        req = entry.get("request") or {}
        resp = entry.get("response") or {}
        content = resp.get("content")
        if not isinstance(content, dict):
            content = {}
            resp["content"] = content
            entry["response"] = resp
        text = content.get("text")
        if text:
            stats["skipped"] += 1
            continue
        key = (
            str(req.get("method") or "GET").upper(),
            str(req.get("url") or ""),
            int(resp.get("status") or 0),
        )
        bucket = buckets.get(key)
        if not bucket:
            continue
        row = bucket.pop(0)
        body = shape_body(str(row.get("text") or ""))
        if not body:
            continue
        content["text"] = body
        content["size"] = len(body.encode("utf-8", errors="replace"))
        mime = row.get("mime") or content.get("mimeType") or ""
        if mime and not content.get("mimeType"):
            content["mimeType"] = mime
        # Drop encoding hint if we stored plain text.
        if content.get("encoding") == "base64":
            content.pop("encoding", None)
        stats["filled"] += 1

    stats["unmatched"] = sum(len(v) for v in buckets.values())
    if stats["filled"]:
        path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    return stats
