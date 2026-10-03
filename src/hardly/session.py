"""HAR session management and cache."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
from pathlib import Path
from typing import Any

from hardly.index.ingest import INDEX_VERSION, ingest_har
from hardly.index.schema import connect

_lock = threading.Lock()
_sessions: dict[str, dict[str, Any]] = {}


def cache_dir() -> Path:
    override = os.environ.get("HARDLY_CACHE_DIR")
    base = Path(override) if override else Path.home() / ".cache" / "hardly"
    base.mkdir(parents=True, exist_ok=True)
    return base


def _path_map_entries() -> list[tuple[str, str]]:
    """Host-prefix → container-prefix pairs for path rewriting."""
    entries: list[tuple[str, str]] = []
    mapping = os.environ.get("HARDLY_PATH_MAP", "")
    if mapping:
        for part in mapping.split(";"):
            part = part.strip()
            if not part or "=" not in part:
                continue
            host_prefix, container_prefix = part.split("=", 1)
            entries.append((host_prefix.strip(), container_prefix.strip()))
    # Default Docker workspace mapping when /workspace is mounted
    workspace = os.environ.get("HARDLY_WORKSPACE", "/workspace")
    if Path(workspace).is_dir():
        for host in ("D:\\code", "D:/code", "/d/code", "d:\\code", "d:/code"):
            entries.append((host, workspace))
    return entries


def resolve_path(path: str | Path) -> Path:
    """Resolve a path, applying host→container aliases (Docker mounts).

    HARDLY_PATH_MAP examples:
      D:\\code=/workspace
      D:\\code=/workspace;D:/code=/workspace

    When HARDLY_WORKSPACE exists (default /workspace), common host roots
    under D:\\code are mapped automatically.
    """
    # Normalize accidental double-escapes from shells (D:\\\\code -> D:\\code)
    raw = str(path).replace("\\\\", "\\")
    # Also accept forward-slash Windows paths
    candidates = [raw, raw.replace("\\", "/")]
    for host_prefix, container_prefix in _path_map_entries():
        host_prefix = host_prefix.rstrip("\\/")
        container_prefix = container_prefix.rstrip("/")
        for candidate in candidates:
            if candidate.lower().startswith(host_prefix.lower()):
                rest = candidate[len(host_prefix) :].lstrip("\\/")
                mapped = f"{container_prefix}/{rest}".replace("\\", "/")
                return Path(mapped)
            # Match D:/code even when prefix is D:\code
            host_fwd = host_prefix.replace("\\", "/")
            cand_fwd = candidate.replace("\\", "/")
            if cand_fwd.lower().startswith(host_fwd.lower()):
                rest = cand_fwd[len(host_fwd) :].lstrip("/")
                mapped = f"{container_prefix}/{rest}"
                return Path(mapped)
    return Path(raw).expanduser()


def _cache_key(har_path: Path) -> str:
    stat = har_path.stat()
    raw = f"{har_path.resolve()}|{stat.st_size}|{stat.st_mtime_ns}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _session_id(har_path: Path) -> str:
    return _cache_key(har_path)


def open_har(har_path: str | Path, *, force: bool = False) -> dict:
    """Index a HAR file (or reuse cache) and register an in-memory session."""
    path = resolve_path(har_path)
    try:
        path = path.resolve()
    except OSError:
        pass
    if not path.is_file():
        return {
            "error": f"HAR file not found: {path}",
            "hint": "In Docker, host paths are mapped via HARDLY_PATH_MAP "
            "(e.g. D:\\code → /workspace). Use /workspace/... or a mapped host path.",
        }

    sid = _session_id(path)
    db_path = cache_dir() / f"{sid}.db"
    meta_path = cache_dir() / f"{sid}.json"

    with _lock:
        if sid in _sessions and not force:
            conn = _sessions[sid]["conn"]
            from hardly.index.query import summary

            return {
                "session_id": sid,
                "cached": True,
                "mode": "archive",
                "next": (
                    "Mode=archive. Use hardly_hosts / hardly_brief / "
                    "hardly_endpoints — do not Read the HAR."
                ),
                **summary(conn),
            }

        need_ingest = force or not db_path.exists() or not meta_path.exists()
        if not need_ingest:
            try:
                meta = json.loads(meta_path.read_text(encoding="utf-8"))
                stat = path.stat()
                if (
                    meta.get("har_path") != str(path)
                    or meta.get("index_version") != INDEX_VERSION
                    or meta.get("har_size") != stat.st_size
                    or abs(meta.get("har_mtime", 0) - stat.st_mtime) > 0.001
                ):
                    need_ingest = True
            except (OSError, json.JSONDecodeError):
                need_ingest = True

        # Close the previous connection first: ingest deletes the database file,
        # which fails on Windows while a connection to it is still open.
        if sid in _sessions:
            try:
                _sessions[sid]["conn"].close()
            except sqlite3.Error:
                pass

        if need_ingest:
            stats = ingest_har(path, db_path)
            meta_path.write_text(json.dumps(stats, indent=2), encoding="utf-8")
            cached = False
        else:
            stats = json.loads(meta_path.read_text(encoding="utf-8"))
            cached = True

        conn = connect(str(db_path))
        _sessions[sid] = {
            "conn": conn,
            "har_path": str(path),
            "db_path": str(db_path),
        }

        return {
            "session_id": sid,
            "cached": cached,
            "mode": "archive",
            "har_path": stats.get("har_path", str(path)),
            "entries": stats.get("entries"),
            "noise": stats.get("noise"),
            "api": stats.get("api"),
            "hosts": stats.get("hosts"),
            "methods": stats.get("methods"),
            "statuses": stats.get("statuses"),
            "next": (
                "Mode=archive. Use hardly_hosts / hardly_brief / "
                "hardly_endpoints — do not Read the HAR."
            ),
        }


def get_conn(session_id: str) -> sqlite3.Connection | None:
    with _lock:
        sess = _sessions.get(session_id)
        return sess["conn"] if sess else None


def reopen_session(session_id: str, *, force: bool = False) -> dict:
    """Reattach a cached session after MCP restart (by session_id).

    Prefers reopening the original HAR path via open_har. If the HAR file is
    gone but the SQLite index remains, attaches the index read-only for query.
    """
    sid = (session_id or "").strip()
    if not sid:
        return {"error": "session_id required"}
    with _lock:
        if sid in _sessions and not force:
            from hardly.index.query import summary

            return {
                "session_id": sid,
                "cached": True,
                "reopened": False,
                **summary(_sessions[sid]["conn"]),
            }

    meta_path = cache_dir() / f"{sid}.json"
    db_path = cache_dir() / f"{sid}.db"
    if not meta_path.is_file() and not db_path.is_file():
        return {
            "error": f"Unknown session_id: {sid}",
            "hint": "Call hardly_list_sessions, then hardly_open(har_path) or reopen.",
        }

    meta: dict[str, Any] = {}
    if meta_path.is_file():
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            meta = {}

    har_path = meta.get("har_path")
    if har_path:
        resolved = resolve_path(har_path)
        if resolved.is_file():
            result = open_har(resolved, force=force)
            if "error" not in result:
                result["reopened"] = True
            return result

    if not db_path.is_file():
        return {
            "error": f"Cache incomplete for session_id {sid}",
            "har_path": har_path,
            "hint": "Re-run hardly_open with the HAR path.",
        }

    from hardly.index.query import summary

    with _lock:
        if sid in _sessions:
            try:
                _sessions[sid]["conn"].close()
            except sqlite3.Error:
                pass
        conn = connect(str(db_path))
        _sessions[sid] = {
            "conn": conn,
            "har_path": har_path or "",
            "db_path": str(db_path),
        }
        return {
            "session_id": sid,
            "cached": True,
            "reopened": True,
            "har_missing": not bool(har_path and Path(str(har_path)).is_file()),
            "har_path": har_path,
            **summary(conn),
            "next": (
                "Index attached from cache. Correlate/cookies prefer the HAR "
                "on disk — re-open the path if token matching looks thin."
            ),
        }


def require_conn(session_id: str) -> sqlite3.Connection:
    conn = get_conn(session_id)
    if conn is not None:
        return conn
    # MCP restarts drop in-memory sessions; auto-reattach from cache.
    result = reopen_session(session_id)
    if "error" in result:
        raise KeyError(
            f"Unknown session_id: {session_id}. Call hardly_open first "
            f"(or hardly_reopen if list_sessions still shows it)."
        )
    conn = get_conn(session_id)
    if conn is None:
        raise KeyError(f"Unknown session_id: {session_id}. Call hardly_open first.")
    return conn


def get_har_path(session_id: str) -> Path | None:
    """Return the on-disk HAR path for an open session, if known."""
    with _lock:
        sess = _sessions.get(session_id)
        if sess and sess.get("har_path"):
            path = Path(sess["har_path"])
            return path if path.is_file() else None
    # Fall back to meta after reopen / for closed sessions.
    meta_path = cache_dir() / f"{session_id}.json"
    if meta_path.is_file():
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            path = Path(meta.get("har_path") or "")
            return path if path.is_file() else None
        except (OSError, json.JSONDecodeError, TypeError):
            return None
    return None


def list_sessions() -> list[dict]:
    with _lock:
        open_ids = set(_sessions.keys())
    result = []
    for meta_path in cache_dir().glob("*.json"):
        sid = meta_path.stem
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        result.append(
            {
                "session_id": sid,
                "open": sid in open_ids,
                "har_path": meta.get("har_path"),
                "entries": meta.get("entries"),
                "api": meta.get("api"),
                "noise": meta.get("noise"),
            }
        )
    # Also include open sessions missing meta (shouldn't happen)
    for sid in open_ids:
        if not any(r["session_id"] == sid for r in result):
            result.append(
                {
                    "session_id": sid,
                    "open": True,
                    "har_path": _sessions[sid]["har_path"],
                }
            )
    return result


def close_session(session_id: str) -> dict:
    with _lock:
        sess = _sessions.pop(session_id, None)
    if not sess:
        return {"closed": False, "error": f"Unknown session_id: {session_id}"}
    try:
        sess["conn"].close()
    except sqlite3.Error:
        pass
    return {"closed": True, "session_id": session_id}
