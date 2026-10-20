"""HAR import edges: a bad entry must not abort the file, and secrets must not land in the index."""

from __future__ import annotations

import json
import sqlite3

from hardly.core.cookies import cookie_timeline
from hardly.core.redact import REDACTED
from hardly.index.ingest import ingest_memory

_USER_PW = "SuperSecretPass"
_PATH_SECRET = "PATHSECRET99abc"
_QUERY_SECRET = "ONLYINARRAY"
_COOKIE_SECRET = "COOKIESECRET99"
_SET_SECRET = "SETSECRET99"


def _har() -> str:
    # Written as text so ``1e999`` stays a non-finite number for the parser.
    return """{"log":{"version":"1.2","entries":[
      null,
      {"request":{"method":"GET","url":"https://svc:%s@legacy.example.com/app/login;jsessionid=%s?x=1",
        "headers":["nope",{"name":"Accept","value":"text/plain"}],"queryString":[],"cookies":[]},
       "response":{"status":1e999,"statusText":"","headers":[],"cookies":[],
        "content":{"mimeType":"text/plain","text":"ok","size":2}}},
      {"request":{"method":" post ","url":"https://api.example.com/search",
        "headers":[],"queryString":[{"name":"token","value":"%s"},"bogus"],
        "cookies":[{"name":"sid","value":"%s"}]},
       "response":{"status":200,"statusText":"OK","headers":[],
        "cookies":[{"name":"session","value":"%s","httpOnly":true,"secure":true,"sameSite":"Lax"}],
        "content":{"mimeType":"application/json","text":"{}"}}}
    ]}}""" % (_USER_PW, _PATH_SECRET, _QUERY_SECRET, _COOKIE_SECRET, _SET_SECRET)


def _texts(conn: sqlite3.Connection) -> str:
    chunks: list[str] = []
    for (name,) in conn.execute("SELECT name FROM sqlite_master WHERE type IN ('table', 'view')"):
        if name.startswith("sqlite_"):
            continue
        for row in conn.execute(f'SELECT * FROM "{name}"'):
            chunks.append(" ".join("" if v is None else str(v) for v in row))
    return "\n".join(chunks)


def test_malformed_entries_and_secret_placement(tmp_path):
    path = tmp_path / "edges.har"
    path.write_text(_har(), encoding="utf-8")
    stats, conn = ingest_memory(path)
    assert stats["skipped"] == 1
    assert stats["entries"] == 2

    rows = {r["entry_id"]: r for r in conn.execute("SELECT * FROM entries")}
    assert 0 not in rows  # the null entry kept its position and was not stored
    assert set(rows) == {1, 2}
    first, second = rows[1], rows[2]

    assert first["host"] == "legacy.example.com"
    assert _USER_PW.casefold() not in first["host"]
    assert f";jsessionid={REDACTED}" in first["path"]
    assert _PATH_SECRET not in first["path"]
    assert first["status"] is None
    assert second["method"] == "POST"
    assert second["status"] == 200
    query = json.loads(second["query_json"])
    assert "token" in query and _QUERY_SECRET not in json.dumps(query)
    assert _QUERY_SECRET not in (second["query_raw"] or "")

    shapes = [(r["where_kind"], r["shape"], r["name"]) for r in conn.execute(
        "SELECT where_kind, shape, name FROM value_shapes")]
    assert ("url", "basic_auth", "userinfo") in shapes
    assert any(kind == "path" and name.lower() == "jsessionid" for kind, _shape, name in shapes)
    assert any(kind == "cookie" and name == "sid" for kind, _shape, name in shapes)
    assert any(kind == "cookie" and name == "session" for kind, _shape, name in shapes)

    headers = [r["name"] for r in conn.execute("SELECT name FROM headers")]
    assert "Accept" in headers
    assert "nope" not in headers

    blob = _texts(conn)
    for secret in (_USER_PW, _USER_PW.casefold(), _PATH_SECRET, _QUERY_SECRET, _COOKIE_SECRET, _SET_SECRET):
        assert secret not in blob

    live = cookie_timeline(conn)
    assert live["source"] == "har"
    assert "sid" in live["names_sent"]
    assert "session" in live["names_set"]
    assert "session" in live["by_flag"]["httponly"]
    assert "session" in live["by_flag"]["secure"]
    assert _COOKIE_SECRET not in json.dumps(live) and _SET_SECRET not in json.dumps(live)

    conn.execute("UPDATE meta SET value = ? WHERE key = 'har_path'", (str(tmp_path / "gone.har"),))
    offline = cookie_timeline(conn)
    assert offline["source"] == "index"
    assert "sid" in offline["names_sent"]
    assert "session" in offline["names_set"]


def test_query_string_is_capped(tmp_path):
    qs = "&".join(f"p{i}=v" for i in range(3000))
    entry = {
        "request": {
            "method": "GET", "url": f"https://api.example.com/q?{qs}",
            "headers": [], "queryString": [], "cookies": [],
        },
        "response": {"status": 200, "headers": [], "cookies": [], "content": {"mimeType": "text/plain", "text": "ok"}},
    }
    path = tmp_path / "wide.har"
    path.write_text(json.dumps({"log": {"version": "1.2", "entries": [entry]}}), encoding="utf-8")
    _stats, conn = ingest_memory(path)
    stored = json.loads(conn.execute("SELECT query_json FROM entries").fetchone()[0])
    assert len(stored) == 2000
    assert "p0" in stored and "p2999" not in stored
