"""Noise and inclusion filters for HAR entries."""

from __future__ import annotations

from urllib.parse import urlparse

STATIC_EXTENSIONS = frozenset(
    {
        ".js",
        ".css",
        ".map",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".svg",
        ".ico",
        ".webp",
        ".woff",
        ".woff2",
        ".ttf",
        ".eot",
        ".mp4",
        ".webm",
        ".mp3",
        ".wav",
        ".pdf",
        ".zip",
    }
)

TRACKER_HOST_FRAGMENTS = (
    "google-analytics",
    "googletagmanager",
    "googleadservices",
    "doubleclick",
    "facebook.net",
    "facebook.com",
    "fbcdn",
    "clarity.ms",
    "hotjar",
    "segment.io",
    "segment.com",
    "mixpanel",
    "amplitude",
    "sentry.io",
    "intercom.io",
    "intercomcdn",
    "intercomassets",
    "linkedin.com",
    "licdn.com",
    "twitter.com",
    "twimg.com",
    "ads-twitter",
    "capterra",
    "stripe.com",
    "m.stripe",
    "r.stripe",
    "js.stripe",
    "openai.com",
    "bzrcdn",
    "newrelic",
    "nr-data",
    "datadoghq",
    "fullstory",
    "heap-api",
    "mouseflow",
    "crazyegg",
    "optimizely",
    "cdn.segment",
)

NON_API_MIME_PREFIXES = (
    "image/",
    "font/",
    "audio/",
    "video/",
    "text/css",
    "text/javascript",
    "application/javascript",
    "application/x-javascript",
    "application/font",
)


def is_static_path(path: str) -> bool:
    lower = path.lower().split("?", 1)[0]
    return any(lower.endswith(ext) for ext in STATIC_EXTENSIONS)


def is_tracker_host(host: str) -> bool:
    h = host.lower()
    return any(frag in h for frag in TRACKER_HOST_FRAGMENTS)


def is_noise_mime(mime: str | None) -> bool:
    if not mime:
        return False
    m = mime.lower().split(";")[0].strip()
    return any(m.startswith(p) for p in NON_API_MIME_PREFIXES)


def is_noise(
    *,
    method: str,
    url: str,
    status: int | None = None,
    mime: str | None = None,
    exclude_options: bool = True,
) -> bool:
    """Return True if the entry is likely non-API noise."""
    if exclude_options and method.upper() == "OPTIONS":
        return True
    parsed = urlparse(url)
    host = parsed.netloc.lower()
    path = parsed.path or "/"
    if is_tracker_host(host):
        return True
    if is_static_path(path):
        return True
    if is_noise_mime(mime):
        return True
    # WebSocket upgrade responses
    if status == 101:
        return True
    return False
