"""URL parsing and path templating."""

from __future__ import annotations

import re
from urllib.parse import parse_qs, urlparse

UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
HEX_TOKEN_RE = re.compile(r"^[0-9a-fA-F]{16,}$")
NUMERIC_RE = re.compile(r"^\d+$")
BASE64ISH_RE = re.compile(r"^[A-Za-z0-9_-]{20,}$")


def parse_url(url: str) -> dict:
    """Return host, path, query dict, and scheme from a URL."""
    parsed = urlparse(url)
    query = parse_qs(parsed.query, keep_blank_values=True)
    # Flatten single-value lists for simpler storage/display
    flat_query = {
        k: (v[0] if len(v) == 1 else v) for k, v in query.items()
    }
    return {
        "scheme": parsed.scheme or "https",
        "host": parsed.netloc.lower(),
        "path": parsed.path or "/",
        "query": flat_query,
        "query_raw": parsed.query,
    }


def template_segment(segment: str) -> str:
    """Replace a dynamic path segment with a placeholder."""
    if not segment:
        return segment
    if UUID_RE.match(segment):
        return "{uuid}"
    if NUMERIC_RE.match(segment):
        return "{id}"
    if HEX_TOKEN_RE.match(segment):
        return "{token}"
    if BASE64ISH_RE.match(segment) and not segment.isalpha():
        return "{token}"
    return segment


def path_template(path: str) -> str:
    """Collapse dynamic segments in a URL path."""
    if not path or path == "/":
        return path or "/"
    parts = path.split("/")
    return "/".join(template_segment(p) if p else p for p in parts)
