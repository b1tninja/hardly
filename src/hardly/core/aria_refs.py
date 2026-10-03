"""Parse Playwright AI aria-snapshot YAML for [ref=eN] markers."""

from __future__ import annotations

import re
from typing import Any

# - button "Submit" [ref=e12] [cursor=pointer]
# - textbox "Email" [ref=e3]:
_LINE = re.compile(
    r"""
    ^\s*-\s+
    (?P<role>[\w-]+)
    (?:\s+"(?P<name>[^"]*)")?
    (?P<rest>[^\n]*)
    """,
    re.VERBOSE | re.MULTILINE,
)
_REF = re.compile(r"\[ref=(?P<ref>e\d+)\]")


def parse_aria_refs(aria_yaml: str, *, limit: int = 80) -> list[dict[str, Any]]:
    """Extract compact ``{ref, role, name}`` rows from an AI aria snapshot."""
    out: list[dict[str, Any]] = []
    if not aria_yaml:
        return out
    for match in _LINE.finditer(aria_yaml):
        rest = match.group("rest") or ""
        ref_m = _REF.search(rest)
        if not ref_m:
            continue
        row = {
            "ref": ref_m.group("ref"),
            "role": match.group("role"),
            "name": match.group("name") or None,
        }
        out.append(row)
        if len(out) >= min(limit, 200):
            break
    return out


def normalize_aria_ref(value: str) -> str:
    """Accept ``e12``, ``ref=e12``, or ``[ref=e12]`` → ``e12``."""
    text = str(value or "").strip()
    if not text:
        return ""
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1].strip()
    if text.lower().startswith("ref="):
        text = text.split("=", 1)[1].strip()
    return text
