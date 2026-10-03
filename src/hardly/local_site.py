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

_INDEX = """<!doctype html><html><head><title>Local demo</title></head><body>
<a href="/directory.aspx">Widget directory search</a> <a href="/login">Sign in</a>
<a href="/api/items">items</a></body></html>"""


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args: object) -> None:  # silence
        pass

    def _send(self, body: str, ctype: str = "text/html; charset=utf-8", cookie: str = "") -> None:
        data = body.encode()
        self.send_response(200)
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
