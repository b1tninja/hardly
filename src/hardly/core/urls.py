"""URL parsing and path templating."""

from __future__ import annotations

import re
from urllib.parse import parse_qs, urlsplit

from hardly.core.redact import path_param_shapes, redact_path

#: ``parse_qs`` with no cap will build a dict per field of a hostile query string.
_MAX_QUERY_FIELDS = 2000

UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
HEX_TOKEN_RE = re.compile(r"^[0-9a-fA-F]{16,}$")
NUMERIC_RE = re.compile(r"^\d+$")
BASE64ISH_RE = re.compile(r"^[A-Za-z0-9_-]{20,}$")


def _flat_query(qs: str) -> dict:
    if not qs:
        return {}
    if qs.count("&") >= _MAX_QUERY_FIELDS:
        qs = "&".join(qs.split("&", _MAX_QUERY_FIELDS)[:_MAX_QUERY_FIELDS])
    try:
        query = parse_qs(
            qs, keep_blank_values=True, max_num_fields=_MAX_QUERY_FIELDS, separator="&"
        )
    except ValueError:
        return {}
    return {k: (v[0] if len(v) == 1 else v) for k, v in query.items()}


def parse_url(url: str) -> dict:
    """Return host, path, query dict, and scheme from a URL.

    ``host`` never includes ``user:pass@`` (``userinfo`` says one was present).
    ``path`` keeps ``;jsessionid``-style matrix parameters with the value redacted;
    ``path_params`` is name and shape only. ``urlsplit`` is used on purpose:
    ``urlparse`` drops those parameters into a separate field and they were lost.
    """
    if not isinstance(url, str):
        url = ""
    parsed = urlsplit(url)
    netloc = parsed.netloc
    userinfo = "@" in netloc
    if userinfo:
        netloc = netloc.rsplit("@", 1)[1]
    raw_path = parsed.path or "/"
    return {
        "scheme": parsed.scheme or "https",
        "host": netloc.lower(),
        "userinfo": userinfo,
        "path": redact_path(raw_path) or "/",
        "path_params": [
            {"name": name, "shape": shape or "token"}
            for name, shape in path_param_shapes(raw_path)
        ],
        "query": _flat_query(parsed.query),
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
