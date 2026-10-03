"""ASP.NET AJAX (UpdatePanel) partial-response parsing.

A partial response is a sequence of ``length|type|id|content|`` records, where
``length`` is the character count of ``content``. Types seen in the wild:
``updatePanel``, ``hiddenField``, ``scriptBlock``, ``pageRedirect``, ``error``,
``formAction``, ``asyncPostBackControlIDs`` and friends.

``parse_delta`` is dependency-free on purpose: generated client stubs embed
its source (``inspect.getsource``) so the stub parses responses at run time.
``summarize_delta`` reports shapes only (types, ids, hidden-field *names*,
sizes) - never panel markup or hidden values.
"""

from __future__ import annotations

from typing import Any


def parse_delta(text):
    """Return [(type, id, content), ...]; [] when text is not a partial response."""
    out = []
    pos = 0
    n = len(text or "")
    while pos < n:
        bar = text.find("|", pos)
        if bar < 0 or not text[pos:bar].isdigit():
            return []
        length = int(text[pos:bar])
        t_end = text.find("|", bar + 1)
        if t_end < 0:
            return []
        i_end = text.find("|", t_end + 1)
        if i_end < 0:
            return []
        start = i_end + 1
        end = start + length
        if end > n or (end < n and text[end] != "|"):
            return []
        out.append((text[bar + 1:t_end], text[t_end + 1:i_end], text[start:end]))
        pos = end + 1
    return out


def delta_hidden(text):
    """Hidden-field updates carried by a partial response: {name: value}."""
    return {i: c for t, i, c in parse_delta(text) if t == "hiddenField" and i}


def is_delta(text: str | None) -> bool:
    return bool(text) and bool(parse_delta(text))


def summarize_delta(text: str | None) -> dict[str, Any] | None:
    """Shape of a partial response (no content, no hidden values), or None."""
    segs = parse_delta(text or "")
    if not segs:
        return None
    types: dict[str, int] = {}
    for t, _i, _c in segs:
        types[t] = types.get(t, 0) + 1
    return {
        "format": "aspnet-ajax-delta",
        "segments": len(segs),
        "types": types,
        "update_panels": [i for t, i, _c in segs if t == "updatePanel"][:20],
        "hidden_fields": sorted({i for t, i, _c in segs if t == "hiddenField"}),
        "redirect": any(t == "pageRedirect" for t, _i, _c in segs),
        "error": next((i for t, i, _c in segs if t == "error"), None),
    }
