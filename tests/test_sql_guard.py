"""Ad-hoc SQL stays a read, even when the limit argument is not an integer."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from hardly import session as sess
from hardly.core.redact import REDACTED
from hardly.index import query as q

FIXTURE = Path(__file__).parent / "fixtures" / "sample.har"


@pytest.fixture()
def conn(tmp_path, monkeypatch):
    monkeypatch.setenv("HARDLY_RUNTIME_DIR", str(tmp_path / "rt"))
    info = sess.open_har(FIXTURE, force=True)
    return sess.require_conn(info["session_id"])


def test_limit_text_is_not_interpolated(conn):
    before = conn.execute("SELECT count(*) FROM entries").fetchone()[0]
    one = q.run_sql(conn, "SELECT entry_id FROM entries", limit="1")
    assert one["row_count"] == 1
    out = q.run_sql(conn, "SELECT entry_id FROM entries", limit="1; DROP TABLE entries")
    assert "error" not in out
    assert conn.execute("SELECT count(*) FROM entries").fetchone()[0] == before
    leaked = q.run_sql(conn, "SELECT entry_id FROM entries", limit="1 UNION SELECT 'injected'")
    assert "injected" not in json_rows(leaked)


def test_authorizer_denies_writes_and_keeps_fts(conn):
    conn.set_authorizer(q._guard_sql)
    try:
        with pytest.raises(sqlite3.DatabaseError):
            conn.execute("PRAGMA query_only=OFF")
        with pytest.raises(sqlite3.DatabaseError):
            conn.execute("CREATE TABLE pwned (id INTEGER)")
    finally:
        conn.set_authorizer(q._allow_all)
    assert conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='pwned'"
    ).fetchone() is None
    matched = q.run_sql(conn, "SELECT entry_id FROM bodies_fts WHERE bodies_fts MATCH 'a'")
    assert "authorization denied" not in matched.get("error", "").lower()
    conn.set_authorizer(q._guard_sql)
    try:
        walked = [row[0] for row in conn.execute(
            "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < 3) SELECT x FROM c"
        )]
    finally:
        conn.set_authorizer(q._allow_all)
    assert walked == [1, 2, 3]


def test_hidden_raw_and_short_secrets(conn):
    raw = q.run_sql(conn, "SELECT value_raw FROM headers")
    assert "error" not in raw
    assert raw["rows"]
    assert all(row["value_raw"] is None for row in raw["rows"])
    cell = q.run_sql(conn, "SELECT 'password=x' AS cell")
    assert REDACTED in cell["rows"][0]["cell"]
    plain = q.run_sql(conn, "SELECT 'ok' AS cell")
    assert plain["rows"][0]["cell"] == "ok"
    denied = q.run_sql(conn, "SELECT load_extension('nope')")
    assert "error" in denied


def json_rows(result: dict) -> str:
    return " ".join(str(v) for row in result.get("rows", []) for v in row.values())
