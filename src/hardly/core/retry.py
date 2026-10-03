"""Retry/backoff helpers embedded into generated client stubs.

Both functions are dependency-free (local imports only) so stubs can embed
their source verbatim and unit tests exercise the very same code.
"""

from __future__ import annotations

RETRY_STATUSES = (429, 500, 502, 503, 504)


def retry_after_seconds(value, now=None):
    """Seconds to wait from a Retry-After header (delta-seconds or HTTP-date)."""
    import time
    from datetime import timezone
    from email.utils import parsedate_to_datetime

    if value is None:
        return None
    value = str(value).strip()
    if not value:
        return None
    if value.isdigit():
        return float(value)
    try:
        when = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if when is None:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    current = time.time() if now is None else now
    return max(0.0, when.timestamp() - current)


def backoff_delay(attempt, retry_after=None, base=1.0, cap=60.0, jitter=0.0):
    """Exponential delay for attempt 0,1,2...; never shorter than Retry-After."""
    import random

    delay = min(cap, base * (2 ** attempt))
    if retry_after is not None:
        delay = max(delay, min(retry_after, cap))
    return delay + (random.random() * jitter * delay if jitter else 0.0)
