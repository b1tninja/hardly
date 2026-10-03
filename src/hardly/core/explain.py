"""Shared helper for the evidence-only default.

Detectors report evidence (names, shapes, entry ids, counts). Canned prose such
as ``implication`` / ``advice`` / ``next`` strings is returned only when the
caller passes ``explain=True``.
"""

from __future__ import annotations

from typing import Any

# Severity vocabulary used by every layer that ranks findings.
SEVERITIES = ("info", "notice", "blocker")


def finish(out: dict[str, Any], explain: bool, *keys: str) -> dict[str, Any]:
    """Drop prose ``keys`` from ``out`` unless ``explain`` is true."""
    if not explain:
        for k in keys:
            out.pop(k, None)
    return out


def severity_rank(sev: str) -> int:
    try:
        return SEVERITIES.index(sev)
    except ValueError:
        return 0
