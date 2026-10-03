"""Atomic file writes for the index cache (temp file in the same dir + os.replace)."""

from __future__ import annotations

import contextlib
import os
import sqlite3
import time
import uuid
from pathlib import Path

TMP_PREFIX = ".hardly-"
TMP_SUFFIX = ".tmp"
STRAY_MAX_AGE_S = 15 * 60


def tmp_path_for(final: Path, kind: str = "w") -> Path:
    """A unique temp name next to ``final`` (same filesystem, so os.replace is atomic)."""
    return final.parent / f"{TMP_PREFIX}{kind}-{final.stem}-{uuid.uuid4().hex[:8]}{TMP_SUFFIX}"


def remove_quietly(path: Path) -> None:
    """Delete a file and any SQLite sidecars; ignore failures (e.g. Windows locks)."""
    for suffix in ("", "-journal", "-wal", "-shm"):
        with contextlib.suppress(OSError):
            Path(str(path) + suffix).unlink()


def replace_file(tmp: Path, final: Path) -> None:
    """os.replace with a short retry (Windows can briefly hold a just-closed file)."""
    last: OSError | None = None
    for attempt in range(5):
        try:
            os.replace(tmp, final)
            return
        except PermissionError as exc:
            last = exc
            time.sleep(0.05 * (attempt + 1))
    assert last is not None
    raise last


def atomic_write_text(final: Path, text: str) -> None:
    tmp = tmp_path_for(final, "meta")
    try:
        tmp.write_text(text, encoding="utf-8")
        replace_file(tmp, final)
    finally:
        remove_quietly(tmp)


def persist_connection(conn: sqlite3.Connection, final: Path) -> int:
    """Write a compact, WAL-free copy of ``conn`` to ``final`` atomically. Returns bytes.

    VACUUM INTO writes a temp file in the destination directory which is then
    renamed over ``final``; a crash leaves either the old file or the new one.
    """
    final.parent.mkdir(parents=True, exist_ok=True)
    tmp = tmp_path_for(final, "db")
    try:
        conn.commit()
        # query_only (memory sessions) also blocks VACUUM INTO; lift it just for the copy.
        qo = conn.execute("PRAGMA query_only").fetchone()[0]
        if qo:
            conn.execute("PRAGMA query_only = OFF")
        try:
            conn.execute("VACUUM INTO ?", (str(tmp),))
        finally:
            if qo:
                conn.execute("PRAGMA query_only = ON")
        # Stale sidecars from an older (WAL) cache must not pair with the new file.
        for suffix in ("-wal", "-shm", "-journal"):
            with contextlib.suppress(OSError):
                Path(str(final) + suffix).unlink()
        replace_file(tmp, final)
        return final.stat().st_size
    finally:
        remove_quietly(tmp)


def cleanup_stray_temps(directory: Path, max_age_s: float = STRAY_MAX_AGE_S) -> list[str]:
    """Remove leftover ``.hardly-*.tmp`` files (crashed writers) older than ``max_age_s``."""
    removed: list[str] = []
    try:
        candidates = list(directory.glob(f"{TMP_PREFIX}*{TMP_SUFFIX}*"))
    except OSError:
        return removed
    now = time.time()
    for path in candidates:
        try:
            if path.is_file() and now - path.stat().st_mtime >= max_age_s:
                path.unlink()
                removed.append(path.name)
        except OSError:
            continue
    return removed
