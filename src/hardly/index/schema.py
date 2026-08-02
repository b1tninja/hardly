"""SQLite schema for HAR sessions."""

from __future__ import annotations

import sqlite3

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
    has_resp_body INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_entries_host ON entries(host);
CREATE INDEX IF NOT EXISTS idx_entries_template ON entries(host, method, path_template);
CREATE INDEX IF NOT EXISTS idx_entries_noise ON entries(is_noise);
CREATE INDEX IF NOT EXISTS idx_entries_path ON entries(path);

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

CREATE VIRTUAL TABLE IF NOT EXISTS bodies_fts USING fts5(
    entry_id UNINDEXED,
    side UNINDEXED,
    preview_text
);
"""


def connect(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA_SQL)
    conn.commit()
