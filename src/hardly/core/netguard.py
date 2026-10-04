"""Outbound URL guard: keep live tools away from loopback, private and metadata addresses.

hardly fetches URLs on an agent's behalf, and many of those URLs come from untrusted data (a HAR,
a crawled page, a redirect ``Location``). :func:`check_url` is the single policy:

* only ``http`` / ``https``; no userinfo (``user:pass@host``); no control characters or backslashes;
* the host is resolved (every A/AAAA record) and refused when ANY address is loopback, private
  (RFC 1918, ULA), link-local (169.254.0.0/16 including cloud metadata, fe80::/10), CGNAT
  (100.64.0.0/10), multicast, reserved, unspecified or otherwise not globally routable, including
  IPv4-mapped / 6to4 / NAT64 IPv6 forms of those;
* the names ``localhost``, ``*.localhost``, ``*.local`` and ``*.internal`` are refused without lookup.

:func:`new_client` returns an ``httpx.Client`` that re-validates EVERY request it sends (redirect
hops included, even ``follow_redirects=True``) and, when no proxy is involved, connects to the
address it validated (original ``Host`` header and TLS SNI kept), so there is no second DNS lookup
between check and connect. Behind an HTTP proxy the proxy resolves the name itself, so only the
local check applies (see SECURITY.md, "DNS rebinding").

Opt out for legitimate local testing with ``HARDLY_ALLOW_PRIVATE_HOSTS=1`` (CLI:
``--allow-private-hosts``). Clients passed in by a caller (``client=``) are the caller's
responsibility and are not wrapped.
"""

from __future__ import annotations

import ipaddress
import os
import socket
from typing import Any
from urllib.parse import urlsplit

import httpx

from hardly.session import SessionError

ALLOW_ENV = "HARDLY_ALLOW_PRIVATE_HOSTS"
_TRUE = {"1", "true", "yes", "on"}
_BLOCKED_SUFFIXES = (".localhost", ".local", ".internal")
_BLOCKED_NAMES = {"localhost", "local", "internal"}


class HostNotAllowed(SessionError, httpx.TransportError):
    """The URL's scheme, userinfo or host is refused by the outbound guard.

    Also an ``httpx.TransportError`` so per-request error handling in the live tools records it
    like any other failed request instead of crashing a whole run.
    """

    code = "host_not_allowed"

    def __init__(self, message: str, hint: str | None = None):
        SessionError.__init__(self, message, hint or default_hint())


def default_hint() -> str:
    return (
        f"Only public http(s) hosts are allowed. For a local or private test target set "
        f"{ALLOW_ENV}=1 (CLI: --allow-private-hosts) and repeat the call. Never set it for "
        "URLs that came from untrusted data."
    )


def private_hosts_allowed() -> bool:
    return (os.environ.get(ALLOW_ENV) or "").strip().lower() in _TRUE


def allow_private_hosts(on: bool = True) -> None:
    """Process-wide opt-out (used by the ``--allow-private-hosts`` CLI flag)."""
    if on:
        os.environ[ALLOW_ENV] = "1"


# ----------------------------------------------------------------------------- classification


def _blocked_ip(ip: ipaddress._BaseAddress) -> str | None:
    """Reason an address is refused, or None when it is a normal public address."""
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            return _blocked_ip(ip.ipv4_mapped)
        if ip.sixtofour is not None:
            return _blocked_ip(ip.sixtofour)
        if ip.teredo is not None:
            return "teredo"
        packed = ip.packed
        if packed[:12] == bytes.fromhex("0064ff9b0000000000000000"):  # NAT64 64:ff9b::/96
            return _blocked_ip(ipaddress.IPv4Address(packed[12:]))
        if packed[:12] == b"\x00" * 12 and packed[12:] != b"\x00" * 4:  # IPv4-compatible ::a.b.c.d
            return _blocked_ip(ipaddress.IPv4Address(packed[12:]))
    if ip.is_loopback:
        return "loopback"
    if ip.is_unspecified:
        return "unspecified"
    if ip.is_multicast:
        return "multicast"
    if ip.is_link_local:
        return "link-local (cloud metadata range)"
    if ip.is_private:
        return "private"
    if ip.is_reserved:
        return "reserved"
    if not ip.is_global:  # CGNAT 100.64/10, benchmarking, documentation, ...
        return "not globally routable"
    return None


def _blocked_name(host: str) -> str | None:
    h = host.rstrip(".").lower()
    if h in _BLOCKED_NAMES or h.endswith(_BLOCKED_SUFFIXES):
        return "local name"
    return None


def _resolve(host: str, port: int) -> list[str]:
    """Every address for ``host`` (indirection so tests can fake DNS)."""
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    seen: list[str] = []
    for info in infos:
        addr = info[4][0].split("%", 1)[0]
        if addr not in seen:
            seen.append(addr)
    return seen


def _refuse(url: str, why: str) -> HostNotAllowed:
    from hardly.core.redact import redact_url

    return HostNotAllowed(f"URL not allowed ({why}): {redact_url(url)[:200]}")


def check_url(url: str | httpx.URL, *, resolve: bool = True) -> list[str]:
    """Validate ``url`` for an outbound request; return the validated addresses.

    Raises :class:`HostNotAllowed` (code ``host_not_allowed``). An unresolvable name is not an
    error here (the request will fail on its own); every address it does resolve to must be public.
    With ``HARDLY_ALLOW_PRIVATE_HOSTS=1`` only the scheme and userinfo rules still apply.
    """
    raw = str(url).strip()
    if any(ord(c) < 0x21 or ord(c) == 0x7F for c in raw) or "\\" in raw:
        raise _refuse(raw, "control characters, spaces or backslashes")
    try:
        parsed = httpx.URL(raw)
        sp = urlsplit(raw)
    except (httpx.InvalidURL, ValueError) as exc:
        raise _refuse(raw, f"unparseable: {type(exc).__name__}") from exc
    if parsed.scheme not in ("http", "https"):
        raise _refuse(raw, f"scheme {parsed.scheme or '(none)'!r}, only http and https")
    if parsed.userinfo or sp.username is not None or sp.password is not None or "@" in sp.netloc:
        raise _refuse(raw, "credentials in the URL")
    host = parsed.host
    if not host:
        raise _refuse(raw, "no host")
    # The parser httpx connects with and the stdlib one must agree on the host.
    a, b = (sp.hostname or "").rstrip(".").lower(), host.rstrip(".").lower()
    if a != b:
        try:
            same = a.encode("idna").decode() == b
        except UnicodeError:
            same = False
        if not same:
            raise _refuse(raw, "ambiguous host")
    if private_hosts_allowed():
        return []
    return check_host(host, parsed.port or (443 if parsed.scheme == "https" else 80), url=raw, resolve=resolve)


def _legacy_ipv4(host: str) -> ipaddress.IPv4Address | None:
    """``inet_aton`` forms (``2130706433``, ``0x7f.1``, ``0177.0.0.1``) that some resolvers accept and others (Windows) do not."""
    parts = host.split(".")
    if not 1 <= len(parts) <= 4 or not all(parts):
        return None
    nums = []
    for part in parts:
        try:
            if part[:2].lower() == "0x":
                nums.append(int(part[2:], 16))
            elif part[0] == "0" and len(part) > 1:
                nums.append(int(part, 8))
            elif part.isdigit():
                nums.append(int(part))
            else:
                return None
        except ValueError:
            return None
    *head, last = nums
    if any(n > 255 for n in head) or last >= 256 ** (4 - len(head)):
        return None
    value = last
    for i, n in enumerate(head):
        value |= n << (8 * (3 - i))
    return ipaddress.IPv4Address(value)


def check_host(host: str, port: int = 443, *, url: str = "", resolve: bool = True) -> list[str]:
    """The host half of :func:`check_url` (no scheme/userinfo rules, no opt-out)."""
    shown = url or host
    try:
        ip = ipaddress.ip_address(host.strip("[]").split("%", 1)[0])
    except ValueError:
        ip = _legacy_ipv4(host)
    if ip is not None:
        why = _blocked_ip(ip)
        if why:
            raise _refuse(shown, f"{host} is {why}")
        return [str(ip)]
    why = _blocked_name(host)
    if why:
        raise _refuse(shown, f"host {host!r} is a {why}")
    if not resolve:
        return []
    try:
        addrs = _resolve(host, port)
    except (OSError, UnicodeError):
        return []  # does not resolve: the request itself will fail
    for addr in addrs:
        try:
            a = ipaddress.ip_address(addr)
        except ValueError:
            raise _refuse(shown, f"{host} resolves to an unparseable address") from None
        why = _blocked_ip(a)
        if why:
            raise _refuse(shown, f"{host} resolves to {addr} ({why})")
    return addrs


def check_urls(urls: list[str]) -> None:
    for u in urls:
        check_url(u)


def blocked_reason(url: str) -> str | None:
    """None when ``url`` passes, else the refusal message (for plans that report instead of raise)."""
    try:
        check_url(url)
    except HostNotAllowed as exc:
        return exc.message
    return None


# ----------------------------------------------------------------------------- client


def _request_hook(request: httpx.Request) -> None:
    """Runs before every request httpx sends, redirect hops included."""
    if private_hosts_allowed():
        check_url(request.url, resolve=False)
        return
    addrs = check_url(request.url)
    if addrs:
        request.extensions["pin_addrs"] = addrs


class _PinningTransport(httpx.BaseTransport):
    """Wrap a direct transport: connect to the validated address, keep the Host header and TLS SNI."""

    def __init__(self, inner: httpx.BaseTransport) -> None:
        self._inner = inner

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        addrs = request.extensions.get("pin_addrs")
        host = request.url.host
        if not addrs or not host or host.strip("[]") in addrs:
            return self._inner.handle_request(request)
        last: Exception | None = None
        for addr in addrs:
            ext = dict(request.extensions)
            ext["sni_hostname"] = host
            pinned = httpx.Request(
                request.method,
                request.url.copy_with(host=addr),
                headers=request.headers,
                stream=request.stream,
                extensions=ext,
            )
            try:
                return self._inner.handle_request(pinned)
            except httpx.ConnectError as exc:
                last = exc
        assert last is not None
        raise last

    def close(self) -> None:  # the wrapped transport is closed by the client
        return None


class GuardedClient(httpx.Client):
    """``httpx.Client`` that validates every request (redirect hops too) and pins direct connections."""

    def __init__(self, **kwargs: Any) -> None:
        hooks = dict(kwargs.pop("event_hooks", None) or {})
        hooks["request"] = [_request_hook, *hooks.get("request", [])]
        kwargs.setdefault("follow_redirects", False)
        super().__init__(event_hooks=hooks, **kwargs)
        self._hardly_pin = _PinningTransport(self._transport)

    def _transport_for_url(self, url: httpx.URL) -> httpx.BaseTransport:  # noqa: D401
        t = super()._transport_for_url(url)
        # Only the direct (non-proxy) transport is pinned: a proxy resolves the name itself.
        return self._hardly_pin if t is self._transport else t


def new_client(**kwargs: Any) -> httpx.Client:
    """An ``httpx.Client`` whose every request passes :func:`check_url` (and pins the address)."""
    return GuardedClient(**kwargs)
