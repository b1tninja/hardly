"""Helpers for telling when a stored body preview is only a prefix of the body.

HTML previews are capped at ~64k characters at ingest, so scanners that read
``bodies.preview_text`` can silently miss tables, links, data attributes or
grid markers that sit later in a large page. They report that instead.
"""

from __future__ import annotations

from typing import Any

_SLACK = 100  # size is bytes, preview is chars: ignore small encoding differences


def is_truncated(size: Any, preview: str | None) -> bool:
    """True when the stored body is clearly longer than its preview."""
    try:
        return size is not None and int(size) > len(preview or "") + _SLACK
    except (TypeError, ValueError):
        return False


def preview_warnings(truncated: list[dict[str, Any]], what: str = "content") -> list[str]:
    """One short warning for a list of ``{"entry_id", ...}`` truncated previews."""
    if not truncated:
        return []
    ids = sorted({int(t["entry_id"]) for t in truncated})[:8]
    return [
        f"{len(truncated)} HTML response preview(s) were truncated at ingest (only the first "
        f"~64k characters are stored), so {what} later in those pages may be missing "
        f"(entry_ids {ids}). Use hardly_entry for the page, or re-capture with smaller pages."
    ]
