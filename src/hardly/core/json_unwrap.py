"""Unwrap double-encoded JSON (a JSON string whose content is JSON).

Some servers return ``"{\\"Table\\":{...}}"`` -- a JSON *string* containing a
JSON document. Technology-level only; nothing here inspects values.
"""

from __future__ import annotations

import json
from typing import Any

# Bodies larger than this are not worth re-parsing for the wrapper check.
_MAX_CHARS = 8_000_000


def unwrap_json_string(text: str | None, max_depth: int = 3) -> tuple[Any, int]:
    """Parse ``text`` until the result stops being a string.

    Returns ``(value, layers)`` where ``layers`` is the number of string
    wrappers peeled. ``layers == 0`` means ``text`` was ordinary JSON (or not
    JSON at all, in which case ``value`` is ``text``). A caller that wants the
    double-encoded case checks ``layers >= 1`` and
    ``isinstance(value, (dict, list))``.
    """
    if text is None:
        return None, 0
    cur: str = text
    layers = 0
    while True:
        try:
            value = json.loads(cur)
        except (json.JSONDecodeError, TypeError, ValueError, RecursionError):
            break
        if not isinstance(value, str):
            return value, layers
        if layers >= max_depth:
            break  # cannot peel another wrapper
        layers += 1
        cur = value
    return cur, layers


def unwrap_double_encoded(text: str | None, max_depth: int = 3) -> Any | None:
    """Return the inner dict/list when ``text`` is a double-encoded JSON string."""
    if not text or len(text) > _MAX_CHARS:
        return None
    stripped = text.strip()
    if not stripped.startswith('"'):
        return None
    value, layers = unwrap_json_string(stripped, max_depth)
    if layers >= 1 and isinstance(value, (dict, list)):
        return value
    return None
