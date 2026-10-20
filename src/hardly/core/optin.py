"""Boolean opt-in for confirm and overwrite.

``if value`` treats any non-empty string, including ``"false"`` and ``"0"``, as
yes. These two flags permit a live request or a file replacement, so only a
real ``True`` counts. MCP validation coerces a JSON boolean before the call;
this is what still holds when a caller passes the value straight through.
"""

from __future__ import annotations


def is_explicit_true(value: object) -> bool:
    return value is True
