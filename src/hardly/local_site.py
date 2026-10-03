"""Tiny synthetic site for offline soak: no network, no real website.

Serves pages that exercise technology detectors (WebForms hidden state,
token-name indirection login, JSON API). Content is invented.
"""

from __future__ import annotations

import json
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterator

_WEBFORMS = """<!doctype html><html><head><title>Widget directory</title></head><body>
<form method="post" action="./directory.aspx" id="form1">
<input type="hidden" name="__EVENTTARGET" value="">
<input type="hidden" name="__EVENTARGUMENT" value="">
<input type="hidden" name="__VIEWSTATE" value="/wEPDwUKLTE2NjM0NTY3ODlkZA==">
<input type="hidden" name="__VIEWSTATEGENERATOR" value="A1B2C3D4">
<input type="hidden" name="__EVENTVALIDATION" value="/wEdAAJexample0000validation">
<label for="ctl00_q">Widget name</label>
<input type="text" name="ctl00$q" id="ctl00_q">
<input type="submit" name="ctl00$go" value="Search" id="ctl00_go">
<a href="javascript:__doPostBack('ctl00$next','')">Next page</a>
</form></body></html>"""

_LOGIN = """<!doctype html><html><head><title>Sign in</title></head><body>
<form method="post" action="/login.action">
<input type="hidden" name="app.token.name" value="token">
<input type="hidden" name="token" value="0123456789ABCDEF0123456789ABCDEF">
<label>User <input type="text" name="username" autocomplete="username"></label>
<label>Pass <input type="password" name="password" autocomplete="current-password"></label>
<button type="submit">Sign in</button></form></body></html>"""

_CAPTCHA = """<!doctype html><html><body><form method="post" action="/login.action">
<div class="cf-turnstile" data-sitekey="1x00000000000000000000AA"></div>
<div class="h-captcha" data-sitekey="10000000-ffff-ffff-ffff-000000000001"></div>
<textarea name="cf-turnstile-response"></textarea><textarea name="h-captcha-response"></textarea>
</form><script src="https://challenges.cloudflare.com/turnstile/v0/api.js"></script></body></html>"""

# Multi-hop portal: landing (header search box only) -> services (JS button)
# -> lookup (real form). Used to test navigation helpers.
_PORTAL = """<!doctype html><html><head><title>Portal</title></head><body>
<form action="/portal/find"><input type="search" name="q" placeholder="Search site"></form>
<nav><a href="/portal/about">About us</a> <a href="/login">Sign in</a>
<a href="/portal/pay">Pay a bill</a> <a href="/portal/services">Online services</a></nav>
</body></html>"""

_PORTAL_SERVICES = """<!doctype html><html><body><h1>Online services</h1>
<a href="/portal/faq">FAQ</a>
<button id="go-widgets" onclick="location.href='/portal/lookup'">Widget lookup</button>
<a href="/portal/about">About us</a></body></html>"""

_PORTAL_LOOKUP = """<!doctype html><html><body><h1>Widget lookup</h1>
<form method="get" action="/portal/results"><label>Widget name <input type="text" name="name"></label>
<label>Category <select name="category"><option>a</option><option>b</option></select></label>
<input type="submit" value="Search"></form></body></html>"""

# Real-world navigation traps: hidden mobile trigger, link in an inactive
# carousel slide, a target=_blank link, and utility forms that are not the goal.
_PORTAL_TRAPS = """<!doctype html><html><body>
<form action="/subscribe" method="post"><input type="email" name="email"><input type="submit" value="Subscribe"></form>
<form action="/find"><input type="text" name="keys"><input type="submit" value="Go"></form>
<button id="mobile-trigger-search" style="display:none" onclick="location.href='/nowhere'">View Search</button>
<div style="visibility:hidden"><a href="/portal/lookup">Business entity search</a></div>
<a href="/portal/lookup" target="_blank">Records lookup (opens in new tab)</a>
</body></html>"""

# First candidate points at a closed port (browser error page); second works.
_PORTAL_BROKEN = """<!doctype html><html><body>
<a href="http://127.0.0.1:1/records">Records search</a>
<a href="/portal/lookup">Entity lookup</a>
<a href="/portal/feedback">Did you find what you needed?</a>
</body></html>"""

# Hop 2 has several keyword-only content links; only the one that names a search is eligible.
_PORTAL_W1 = """<!doctype html><html><body><a href="/portal/w2">Permit services</a></body></html>"""
_PORTAL_W2 = """<!doctype html><html><body>
<a href="/portal/guide">Permit application guide</a> <a href="/portal/forms">Fire permit forms</a>
<a href="/portal/lookup">Permit search</a></body></html>"""
# A page whose only candidates are keyword-only: navigation must stop, not wander.
_PORTAL_DEAD = """<!doctype html><html><body><a href="/portal/w3">Permit services</a></body></html>"""
_PORTAL_W3 = """<!doctype html><html><body><a href="/portal/guide">Permit application guide</a>
<a href="/portal/forms">Fire permit forms</a></body></html>"""
# A header "Sign in" box on an otherwise ordinary, link-rich page is not a login wall.
_PORTAL_HEADER_LOGIN = (
    "<!doctype html><html><body><header><form action=\"/login.action\" method=\"post\">"
    "<input name=\"u\"><input type=\"password\" name=\"p\"><button>Sign in</button></form></header>"
    + "".join(f'<a href="/portal/p{i}">Info page {i}</a> ' for i in range(18))
    + '<a href="/portal/lookup">Widget lookup</a></body></html>'
)

# Client-rendered lookup: the form only exists after a script runs.
_PORTAL_SPA = """<!doctype html><html><body><div id="app">Loading…</div>
<script>setTimeout(function(){document.getElementById('app').innerHTML=
'<form action="/portal/results"><input type="text" name="owner_name"><input type="text" name="parcel_number">'+
'<input type="submit" value="Go"></form>';},700);</script></body></html>"""
_PORTAL_SPA_HOME = """<!doctype html><html><body><a href="/portal/spa">Parcel search</a></body></html>"""

_INDEX = """<!doctype html><html><head><title>Local demo</title></head><body>
<a href="/directory.aspx">Widget directory search</a> <a href="/login">Sign in</a>
<a href="/api/items">items</a></body></html>"""


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args: object) -> None:  # silence
        pass

    def _send(
        self,
        body: str,
        ctype: str = "text/html; charset=utf-8",
        cookie: str = "",
        status: int = 200,
        headers: dict[str, str] | None = None,
    ) -> None:
        data = body.encode()
        self.send_response(status)
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path == "/directory.aspx":
            self._send(_WEBFORMS, cookie="ASP.NET_SessionId=localdemo0001; path=/; HttpOnly")
        elif path == "/login":
            self._send(_LOGIN, cookie="JSESSIONID=localdemo0002; path=/; HttpOnly; SameSite=Lax")
        elif path == "/portal":
            self._send(_PORTAL)
        elif path == "/portal/spa":
            self._send(_PORTAL_SPA)
        elif path == "/portal/spahome":
            self._send(_PORTAL_SPA_HOME)
        elif path == "/portal/w1":
            self._send(_PORTAL_W1)
        elif path == "/portal/w2":
            self._send(_PORTAL_W2)
        elif path == "/portal/dead":
            self._send(_PORTAL_DEAD)
        elif path == "/portal/w3":
            self._send(_PORTAL_W3)
        elif path == "/portal/hl":
            self._send(_PORTAL_HEADER_LOGIN)
        elif path == "/portal/broken":
            self._send(_PORTAL_BROKEN)
        elif path == "/portal/traps":
            self._send(_PORTAL_TRAPS)
        elif path == "/portal/services":
            self._send(_PORTAL_SERVICES)
        elif path == "/portal/lookup":
            self._send(_PORTAL_LOOKUP)
        elif path.startswith("/portal/"):
            self._send("<html><body><p>" + path.rsplit("/", 1)[-1] + "</p></body></html>")
        elif path == "/private":
            if self.headers.get("Authorization"):
                self._send("ok")
            else:
                self._send(
                    "authentication required",
                    status=401,
                    headers={"WWW-Authenticate": 'Basic realm="local-demo", charset="UTF-8"'},
                )
        elif path == "/limited":
            self._send(
                "Too many attempts, try again later",
                status=429,
                headers={"Retry-After": "30", "X-RateLimit-Remaining": "0"},
            )
        elif path == "/captcha":
            self._send(_CAPTCHA)
        elif path == "/api/items":
            self._send(json.dumps({"items": [{"id": 1, "name": "alpha"}]}), "application/json")
        else:
            self._send(_INDEX)

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(length)
        self._send(_INDEX)


def start() -> tuple[ThreadingHTTPServer, str]:
    """Start the site on an ephemeral loopback port (daemon thread).

    For process-lifetime use; call ``server.shutdown()`` yourself if needed.
    """
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


@contextmanager
def serve() -> Iterator[str]:
    """Run the synthetic site for the duration of a ``with`` block."""
    server, base = start()
    try:
        yield base
    finally:
        server.shutdown()
        server.server_close()
