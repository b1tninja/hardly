"""Opt-in request blocking for headless capture (``block_noise=True``).

Aborts requests that add traffic weight but no API/portal signal:
analytics / ads / social widgets (reusing ``filters.TRACKER_HOST_FRAGMENTS``
minus payment/AI vendors, which sites may legitimately need), map-tile
servers, web-font hosts, plus heavy resource types (``media``, ``font``).

Document navigations are never blocked. Default is OFF because blocking can
break sites (e.g. consent walls that depend on a tag manager).
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from hardly.core.filters import TRACKER_HOST_FRAGMENTS

# Entries from TRACKER_HOST_FRAGMENTS that are not noise for capture purposes
# (payment iframes, AI APIs) - a flow may depend on them.
_KEEP_FRAGMENTS = frozenset(
    {"stripe.com", "m.stripe", "r.stripe", "js.stripe", "openai.com"}
)

#: Substring fragments (matched against the lower-cased host).
NOISE_HOST_FRAGMENTS: tuple[str, ...] = tuple(
    f for f in TRACKER_HOST_FRAGMENTS if f not in _KEEP_FRAGMENTS
) + (
    # ads
    "googlesyndication",
    "adservice.",
    "adsystem",
    "adnxs",
    "criteo",
    "taboola",
    "outbrain",
    "scorecardresearch",
    "quantserve",
    "siteimproveanalytics",
    # social widgets / embeds
    "platform.twitter",
    "connect.facebook",
    "addthis",
    "sharethis",
    # web fonts
    "fonts.googleapis",
    "fonts.gstatic",
    "use.typekit",
    "use.fontawesome",
    "kit.fontawesome",
    # map tiles
    "arcgisonline",
    "tile.openstreetmap",
    "tiles.mapbox",
    "api.mapbox.com/styles",
)

#: Map-tile URL shapes (``/z/x/y.png`` style) on any host.
_TILE_PATH_RE = re.compile(r"(?i)/tiles?/\d{1,2}/\d+/\d+(\.|\?|$)|/\d{1,2}/\d+/\d+\.(png|jpe?g|webp|pbf|mvt)(\?|$)")
_HEAVY_EXT_RE = re.compile(r"(?i)\.(mp4|webm|m4v|mov|avi|mp3|wav|ogg|woff2?|ttf|otf|eot)(\?|#|$)")
#: Playwright resource types always aborted.
HEAVY_RESOURCE_TYPES = frozenset({"media", "font"})
_NEVER_BLOCK_TYPES = frozenset({"document"})


def is_noise_host(host: str) -> bool:
    low = (host or "").lower()
    return bool(low) and any(frag in low for frag in NOISE_HOST_FRAGMENTS)


def block_reason(url: str, resource_type: str = "") -> str | None:
    """Return a short reason string when the request should be aborted."""
    rtype = (resource_type or "").lower()
    if rtype in _NEVER_BLOCK_TYPES:
        return None
    parsed = urlparse(url or "")
    host = (parsed.hostname or "").lower()
    if parsed.scheme in {"data", "blob", "about", "file"}:
        return None
    if rtype in HEAVY_RESOURCE_TYPES:
        return f"type:{rtype}"
    if is_noise_host(host) or is_noise_host(host + parsed.path):
        return "noise_host"
    if _TILE_PATH_RE.search(parsed.path or ""):
        return "map_tile"
    if _HEAVY_EXT_RE.search(parsed.path or ""):
        return "heavy_media"
    return None


class NoiseBlocker:
    """``context.route`` handler that aborts noisy requests and counts them."""

    def __init__(self, *, max_hosts: int = 8) -> None:
        self.count = 0
        self.hosts: dict[str, int] = {}
        self._max_hosts = max_hosts

    def handle(self, route: Any) -> None:
        request = route.request
        reason = block_reason(request.url, getattr(request, "resource_type", "") or "")
        if reason is None:
            route.continue_()
            return
        self.count += 1
        host = (urlparse(request.url).hostname or "?").lower()
        self.hosts[host] = self.hosts.get(host, 0) + 1
        route.abort()

    def install(self, context: Any) -> None:
        context.route("**/*", self.handle)

    def summary(self) -> dict[str, Any]:
        top = sorted(self.hosts.items(), key=lambda kv: -kv[1])[: self._max_hosts]
        return {
            "blocked_requests": self.count,
            "blocked_hosts": [h for h, _ in top],
        }
