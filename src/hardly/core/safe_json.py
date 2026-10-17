"""``json.loads`` for untrusted text: nesting is capped, so no walker downstream can be blown up.

A HAR body (or a JSON string inside one) can be nested a thousand levels deep. The C parser then
raises ``RecursionError`` (not a ``ValueError``) and recursive walkers further on fail the same way.
:func:`safe_loads` raises ``json.JSONDecodeError`` instead, for text nested deeper than
``MAX_DEPTH`` (no real API response is), so every existing ``except ValueError`` just works.
"""

from __future__ import annotations

import json
from typing import Any

#: Deepest nesting accepted from untrusted text.
MAX_DEPTH = 100


def too_deep(obj: Any, limit: int = MAX_DEPTH) -> bool:
    """Iterative depth check (never recurses)."""
    stack: list[tuple[Any, int]] = [(obj, 1)]
    while stack:
        cur, depth = stack.pop()
        if depth > limit:
            return True
        if isinstance(cur, dict):
            children = cur.values()
        elif isinstance(cur, list):
            children = cur
        else:
            continue
        stack.extend((c, depth + 1) for c in children if isinstance(c, (dict, list)))
    return False


def safe_loads(text: str | bytes, **kw: Any) -> Any:
    try:
        obj = json.loads(text, **kw)
    except RecursionError as exc:
        raise json.JSONDecodeError("JSON nested too deeply", "", 0) from exc
    if isinstance(obj, (dict, list)) and too_deep(obj):
        raise json.JSONDecodeError(f"JSON nested deeper than {MAX_DEPTH} levels", "", 0)
    return obj
