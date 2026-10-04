"""Defuse markup that makes older ``html.parser`` builds quadratic.

CPython's ``html.parser`` before the 2025 security fixes re-scans to the end of the text for every
unterminated ``<tag``; a run of thousands of them takes minutes. A ``<`` that is followed by another
``<`` before any ``>`` can never start a well-formed tag, so it is turned into an entity first.
The pass is linear, and only rewrites a document with more than ``_LIMIT`` such starts, so ordinary
markup (even a ``<`` inside a quoted attribute) is parsed exactly as written.
"""

from __future__ import annotations

import re

_STRAY_LT = re.compile(r"<(?=[^<>]*<)")
_TRAILING_LT = re.compile(r"<(?=[^<>]*\Z)")


_LIMIT = 200


def defuse_html(text: str) -> str:
    if "<" not in text:
        return text
    for i, _ in enumerate(_STRAY_LT.finditer(text)):
        if i >= _LIMIT:
            break
    else:
        return text
    return _TRAILING_LT.sub("&lt;", _STRAY_LT.sub("&lt;", text))
