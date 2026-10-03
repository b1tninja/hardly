"""Classify browser/capture error messages (technology-level, no site logic)."""

from __future__ import annotations

import re
from typing import Any

# Navigation failures worth another try (aliased as capture.py ``_TRANSIENT_NAV``).
TRANSIENT_NAV: tuple[str, ...] = (
    "ERR_TOO_MANY_RETRIES",
    "ERR_CONNECTION_RESET",
    "ERR_CONNECTION_CLOSED",
    "ERR_EMPTY_RESPONSE",
    "ERR_HTTP2_PROTOCOL_ERROR",
    "ERR_NETWORK_CHANGED",
    "ERR_SOCKET_NOT_CONNECTED",
    "interrupted by another navigation",
)

_ENV_BLOCKED = (
    "ERR_TUNNEL_CONNECTION_FAILED",
    "host_not_allowed",
    "x-deny-reason",
)
_PROXY_CONNECT_RE = re.compile(
    r"(?i)\bconnect\b[^\n]{0,80}\b(403|502|407)\b|\b(403|502|407)\b[^\n]{0,40}\bconnect\b"
)
_TIMEOUT_RE = re.compile(r"(?i)timeout\s*\d+\s*ms\s*exceeded|\btimed out\b")

_ADVICE = {
    "environment_blocked": (
        "The network path (proxy / egress policy) refused this host. Retrying "
        "will not help; use an allowed host or ask the person to capture "
        "interactively from an unrestricted network."
    ),
    "transient": "Transient network/navigation failure; retry once or twice.",
    "cert": (
        "TLS certificate problem. Check the host and clock, or capture the "
        "site interactively with a trusted browser (channel=chrome)."
    ),
    "dns": "Hostname did not resolve. Check the URL spelling and DNS/network access.",
    "timeout": (
        "Operation timed out. Retry with a longer wait or a lighter recipe, "
        "try block_noise=true; if it keeps timing out switch to interactive mode."
    ),
    "refused": "Connection refused: nothing is listening at that host/port. Verify the URL.",
    "unknown": "Unclassified failure; read the error text and run `hardly capture doctor`.",
}
_RETRYABLE = {"transient", "timeout"}


def classify_capture_error(message: Any) -> dict[str, Any]:
    """Return ``{"class", "retryable", "advice"}`` for an error message."""
    text = str(message or "")
    low = text.lower()
    cls = "unknown"
    if any(m.lower() in low for m in _ENV_BLOCKED) or _PROXY_CONNECT_RE.search(text):
        cls = "environment_blocked"
    elif "err_cert_" in low or "ssl_error" in low:
        cls = "cert"
    elif "err_name_not_resolved" in low or "err_name_resolution_failed" in low:
        cls = "dns"
    elif "err_connection_refused" in low:
        cls = "refused"
    elif _TIMEOUT_RE.search(text):
        cls = "timeout"
    elif any(m.lower() in low for m in TRANSIENT_NAV):
        cls = "transient"
    return {"class": cls, "retryable": cls in _RETRYABLE, "advice": _ADVICE[cls]}


def with_error_class(payload: dict[str, Any], key: str = "error") -> dict[str, Any]:
    """Add ``error_class`` / ``error_retryable`` / ``error_advice`` when ``key`` is set."""
    msg = payload.get(key)
    if msg:
        info = classify_capture_error(msg)
        payload["error_class"] = info["class"]
        payload["error_retryable"] = info["retryable"]
        payload["error_advice"] = info["advice"]
    return payload
