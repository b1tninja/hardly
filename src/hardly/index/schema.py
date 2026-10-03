"""SQLite schema for HAR sessions."""

from __future__ import annotations

import sqlite3
from pathlib import Path

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS entries (
    entry_id INTEGER PRIMARY KEY,
    method TEXT NOT NULL,
    scheme TEXT NOT NULL DEFAULT 'https',
    host TEXT NOT NULL,
    path TEXT NOT NULL,
    path_template TEXT NOT NULL,
    query_json TEXT,
    query_raw TEXT,
    status INTEGER,
    mime TEXT,
    started_datetime TEXT,
    time_ms REAL,
    is_noise INTEGER NOT NULL DEFAULT 0,
    has_req_body INTEGER NOT NULL DEFAULT 0,
    has_resp_body INTEGER NOT NULL DEFAULT 0,
    pageref TEXT,
    initiator_type TEXT,
    initiator_url TEXT
);

CREATE INDEX IF NOT EXISTS idx_entries_host ON entries(host);
CREATE INDEX IF NOT EXISTS idx_entries_template ON entries(host, method, path_template);
CREATE INDEX IF NOT EXISTS idx_entries_noise ON entries(is_noise);
CREATE INDEX IF NOT EXISTS idx_entries_path ON entries(path);
CREATE INDEX IF NOT EXISTS idx_entries_pageref ON entries(pageref);
CREATE INDEX IF NOT EXISTS idx_entries_initiator ON entries(initiator_url);

CREATE TABLE IF NOT EXISTS headers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    entry_id INTEGER NOT NULL REFERENCES entries(entry_id),
    side TEXT NOT NULL,
    name TEXT NOT NULL,
    value_redacted TEXT,
    value_raw TEXT
);

CREATE INDEX IF NOT EXISTS idx_headers_entry ON headers(entry_id, side);

CREATE TABLE IF NOT EXISTS bodies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    entry_id INTEGER NOT NULL REFERENCES entries(entry_id),
    side TEXT NOT NULL,
    content_type TEXT,
    size INTEGER NOT NULL DEFAULT 0,
    preview_text TEXT,
    sha256 TEXT,
    UNIQUE(entry_id, side)
);

CREATE INDEX IF NOT EXISTS idx_bodies_entry ON bodies(entry_id);

-- Signals computed at ingest on the FULL body (the stored preview is capped).
CREATE TABLE IF NOT EXISTS body_signals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    entry_id INTEGER NOT NULL REFERENCES entries(entry_id),
    kind TEXT NOT NULL,
    name TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_body_signals_entry ON body_signals(entry_id, kind);

CREATE VIRTUAL TABLE IF NOT EXISTS bodies_fts USING fts5(
    entry_id UNINDEXED,
    side UNINDEXED,
    preview_text
);

CREATE TABLE IF NOT EXISTS value_shapes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    entry_id INTEGER NOT NULL REFERENCES entries(entry_id),
    side TEXT NOT NULL,
    where_kind TEXT NOT NULL,
    name TEXT,
    shape TEXT NOT NULL
);

-- Shape-only summaries of stream encodings (grpc-web, protobuf, msgpack, csv, sse, websocket).
CREATE TABLE IF NOT EXISTS stream_info (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    entry_id INTEGER NOT NULL REFERENCES entries(entry_id),
    side TEXT NOT NULL,
    kind TEXT NOT NULL,
    summary_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_stream_info_entry ON stream_info(entry_id);

CREATE INDEX IF NOT EXISTS idx_shapes_entry ON value_shapes(entry_id);
CREATE INDEX IF NOT EXISTS idx_shapes_shape ON value_shapes(shape);
"""


def _finish(conn: sqlite3.Connection) -> sqlite3.Connection:
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    # Sorts and temp tables stay in RAM (allowed on read-only databases too).
    conn.execute("PRAGMA temp_store = MEMORY")
    return conn


def connect(db_path: str) -> sqlite3.Connection:
    """Open a writable connection (ingest, tests). Sessions use open_readonly/open_memory.

    MCP dispatches each tool call on its own thread. A session keeps one
    connection; SQLite's default serialized mode makes that safe.
    No WAL: cached indexes are single-file, written once and then read-only.
    """
    return _finish(sqlite3.connect(db_path, check_same_thread=False))


def connect_ingest(db_path: str) -> sqlite3.Connection:
    """Writable connection tuned for a one-shot bulk build (no journal, no fsync)."""
    conn = connect(db_path)
    if db_path != ":memory:":
        conn.execute("PRAGMA journal_mode = OFF")
        conn.execute("PRAGMA synchronous = OFF")
    return conn


def connect_memory() -> sqlite3.Connection:
    """A private in-memory database; only this one connection can ever see it."""
    return connect(":memory:")


def path_to_ro_uri(db_path: str | Path) -> str:
    """file: URI (mode=ro) for a path; correct quoting and drive letters on Windows."""
    return Path(db_path).resolve().as_uri() + "?mode=ro"


def open_readonly(db_path: str | Path) -> sqlite3.Connection:
    """Open a cached index read-only: no locks to write, no sidecars, rejects writes."""
    conn = sqlite3.connect(path_to_ro_uri(db_path), uri=True, check_same_thread=False)
    return _finish(conn)


def seal(conn: sqlite3.Connection) -> sqlite3.Connection:
    """Make a writable (memory) connection reject writes, like a read-only open."""
    conn.commit()
    conn.execute("PRAGMA query_only = ON")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA_SQL)
    conn.commit()
