"""HAR session management and cache."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
from pathlib import Path
from typing import Any

from hardly.index.atomic import atomic_write_text, cleanup_stray_temps, persist_connection
from hardly.index.ingest import INDEX_VERSION, ingest_har, ingest_memory
from hardly.index.schema import open_readonly, seal

_lock = threading.Lock()
_sessions: dict[str, dict[str, Any]] = {}


def cache_dir() -> Path:
    override = os.environ.get("HARDLY_CACHE_DIR")
    base = Path(override) if override else Path.home() / ".cache" / "hardly"
    base.mkdir(parents=True, exist_ok=True)
    return base


STORAGE_MODES = ("auto", "disk", "memory")
DEFAULT_STORAGE = "disk"
DEFAULT_MEMORY_MAX_MB = 25.0
MEMORY_NOTE = (
    "storage=memory: the index lives only in this process and nothing derived from the HAR is "
    "written to disk. It is gone after a restart (hardly_reopen cannot restore it); call "
    "hardly_open(har_path) again, or hardly_persist(session_id) to keep a copy."
)


def _memory_max_bytes() -> float:
    raw = (os.environ.get("HARDLY_INDEX_MEMORY_MAX_MB") or "").strip()
    try:
        mb = float(raw) if raw else DEFAULT_MEMORY_MAX_MB
    except ValueError:
        mb = DEFAULT_MEMORY_MAX_MB
    return max(0.0, mb) * 1024 * 1024


def resolve_storage(requested: str | None, har_path: Path | None = None) -> str:
    """Effective storage ('memory' or 'disk') from the parameter, HARDLY_INDEX, then the default.

    ``auto`` picks memory for HARs up to HARDLY_INDEX_MEMORY_MAX_MB (default 25), else disk.
    Raises ValueError for an unknown value given as a parameter; a bad env value is ignored.
    """
    if requested is not None and str(requested).strip():
        mode = str(requested).strip().lower()
        if mode not in STORAGE_MODES:
            raise ValueError(f"storage must be one of {', '.join(STORAGE_MODES)} (got {requested!r})")
    else:
        mode = (os.environ.get("HARDLY_INDEX") or "").strip().lower()
        if mode not in STORAGE_MODES:
            mode = DEFAULT_STORAGE
    if mode == "auto":
        try:
            small = har_path is not None and har_path.stat().st_size <= _memory_max_bytes()
        except OSError:
            small = False
        return "memory" if small else "disk"
    return mode


def _is_wal(db_path: Path) -> bool:
    """True for a legacy WAL-mode cache (header bytes 18/19 == 2); those are rebuilt."""
    try:
        with db_path.open("rb") as f:
            head = f.read(20)
        return len(head) >= 20 and head[18] == 2 and head[19] == 2
    except OSError:
        return False


def _drop_session(sid: str) -> None:
    """Close and forget a session's connection (needed before replacing its file on Windows)."""
    sess = _sessions.pop(sid, None)
    if sess:
        try:
            sess["conn"].close()
        except sqlite3.Error:
            pass


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


def _live_result(sid: str, sess: dict[str, Any]) -> dict:
    from hardly.index.query import summary

    out = {
        "session_id": sid,
        "cached": True,
        "mode": "archive",
        "storage": sess["storage"],
        "next": (
            "Mode=archive. Use hardly_hosts / hardly_brief / "
            "hardly_endpoints — do not Read the HAR."
        ),
        **summary(sess["conn"]),
    }
    if sess["storage"] == "memory":
        out["note"] = MEMORY_NOTE
    return out


def open_har(
    har_path: str | Path, *, force: bool = False, storage: str | None = None
) -> dict:
    """Index a HAR file (or reuse cache) and register a session.

    storage: 'disk' (cached, survives restarts), 'memory' (nothing written to disk) or 'auto'
    (memory for small HARs); default from HARDLY_INDEX, else 'disk'.
    """
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
    try:
        want = resolve_storage(storage, path)
    except ValueError as exc:
        return {"error": str(exc)}

    sid = _session_id(path)

    with _lock:
        live = _sessions.get(sid)
        # An explicit storage that differs from the live session switches it; otherwise reuse.
        if live and not force and (storage is None or live["storage"] == want):
            return _live_result(sid, live)

        # Close the previous connection first: replacing the database file fails on
        # Windows while a connection to it is still open.
        _drop_session(sid)

        if want == "memory":
            stats, conn = ingest_memory(path)
            seal(conn)
            _sessions[sid] = {
                "conn": conn,
                "har_path": str(path),
                "db_path": None,
                "storage": "memory",
                "stats": stats,
            }
            return {
                "session_id": sid,
                "cached": False,
                "mode": "archive",
                "storage": "memory",
                "har_path": stats.get("har_path", str(path)),
                "entries": stats.get("entries"),
                "noise": stats.get("noise"),
                "api": stats.get("api"),
                "hosts": stats.get("hosts"),
                "methods": stats.get("methods"),
                "statuses": stats.get("statuses"),
                "note": MEMORY_NOTE,
                "next": (
                    "Mode=archive. Use hardly_hosts / hardly_brief / "
                    "hardly_endpoints — do not Read the HAR."
                ),
            }

        db_path = cache_dir() / f"{sid}.db"
        meta_path = db_path.with_suffix(".json")
        cleanup_stray_temps(db_path.parent)
        need_ingest = (
            force or not db_path.exists() or not meta_path.exists() or _is_wal(db_path)
        )
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

        if need_ingest:
            # Atomic: the db is replaced in one rename, and the meta (which marks the cache
            # valid) is written last, so a crash never leaves a half-written cache.
            stats = ingest_har(path, db_path)
            atomic_write_text(meta_path, json.dumps(stats, indent=2))
            cached = False
        else:
            stats = json.loads(meta_path.read_text(encoding="utf-8"))
            cached = True

        conn = open_readonly(db_path)
        _sessions[sid] = {
            "conn": conn,
            "har_path": str(path),
            "db_path": str(db_path),
            "storage": "disk",
            "stats": stats,
        }

        return {
            "session_id": sid,
            "cached": cached,
            "mode": "archive",
            "storage": "disk",
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
    Sessions opened with storage=memory are never cached: after a restart they are gone.
    """
    sid = (session_id or "").strip()
    if not sid:
        return {"error": "session_id required"}
    with _lock:
        live = _sessions.get(sid)
        if live and not force:
            from hardly.index.query import summary

            return {
                "session_id": sid,
                "cached": True,
                "reopened": False,
                "storage": live["storage"],
                **summary(live["conn"]),
            }
        live_har = live["har_path"] if live and live["storage"] == "memory" else None

    if live_har and Path(live_har).is_file():
        result = open_har(live_har, force=True, storage="memory")
        if "error" not in result:
            result["reopened"] = True
        return result

    meta_path = cache_dir() / f"{sid}.json"
    db_path = cache_dir() / f"{sid}.db"
    if not meta_path.is_file() and not db_path.is_file():
        return {
            "error": f"Unknown session_id: {sid}",
            "hint": "Call hardly_list_sessions, then hardly_open(har_path) or reopen. "
            "Sessions opened with storage=memory are not cached and are gone after a "
            "restart: call hardly_open(har_path) again.",
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
            result = open_har(resolved, force=force, storage="disk")
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
        _drop_session(sid)
        conn = open_readonly(db_path)
        _sessions[sid] = {
            "conn": conn,
            "har_path": har_path or "",
            "db_path": str(db_path),
            "storage": "disk",
            "stats": meta,
        }
        return {
            "session_id": sid,
            "cached": True,
            "reopened": True,
            "storage": "disk",
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
    # MCP restarts drop live sessions; auto-reattach disk sessions from cache.
    result = reopen_session(session_id)
    if "error" in result:
        raise KeyError(
            f"Unknown session_id: {session_id}. Call hardly_open first "
            f"(or hardly_reopen if list_sessions still shows it). Sessions opened with "
            f"storage=memory do not survive a restart."
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


def get_storage(session_id: str) -> str:
    """'memory' or 'disk' for a session (live session wins; cached-only means disk)."""
    with _lock:
        sess = _sessions.get(session_id)
    return sess["storage"] if sess else "disk"


def list_sessions() -> list[dict]:
    with _lock:
        live = {sid: dict(v) for sid, v in _sessions.items()}
    result: dict[str, dict] = {}
    for meta_path in cache_dir().glob("*.json"):
        sid = meta_path.stem
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(meta, dict) or "har_path" not in meta:
            continue
        result[sid] = {
            "session_id": sid,
            "open": sid in live,
            "storage": "disk",
            "har_path": meta.get("har_path"),
            "entries": meta.get("entries"),
            "api": meta.get("api"),
            "noise": meta.get("noise"),
        }
    # Memory sessions have no cache entry; an open memory session overrides a cached one.
    for sid, sess in live.items():
        if sess["storage"] != "memory":
            if sid not in result:
                result[sid] = {
                    "session_id": sid,
                    "open": True,
                    "storage": "disk",
                    "har_path": sess["har_path"],
                }
            continue
        stats = sess.get("stats") or {}
        result[sid] = {
            "session_id": sid,
            "open": True,
            "storage": "memory",
            "har_path": sess["har_path"],
            "entries": stats.get("entries"),
            "api": stats.get("api"),
            "noise": stats.get("noise"),
        }
    return list(result.values())


def close_session(session_id: str) -> dict:
    with _lock:
        sess = _sessions.pop(session_id, None)
    if not sess:
        return {"closed": False, "error": f"Unknown session_id: {session_id}"}
    try:
        sess["conn"].close()
    except sqlite3.Error:
        pass
    out = {"closed": True, "session_id": session_id, "storage": sess["storage"]}
    if sess["storage"] == "memory":
        out["note"] = "Memory session discarded; hardly_open(har_path) rebuilds it."
    return out


def persist_session(
    session_id: str, path: str | Path | None = None, *, overwrite: bool = False
) -> dict:
    """Save a session's index to a compact, WAL-free SQLite file (VACUUM INTO, never in place).

    Without ``path`` a memory session is saved into the cache dir as <sid>.db plus its meta, so
    it reattaches after a restart like any disk session. With ``path`` only the database file is
    written. An existing target is refused unless overwrite=True; writes go via temp + rename.
    """
    try:
        conn = require_conn(session_id)
    except KeyError as exc:
        return {"error": str(exc)}
    with _lock:
        sess = _sessions.get(session_id)
        if not sess:
            return {"error": f"Unknown session_id: {session_id}"}
        storage = sess["storage"]
        own = sess.get("db_path")
        stats = dict(sess.get("stats") or {})

        if path is None:
            if storage == "disk":
                size = Path(own).stat().st_size if own and Path(own).is_file() else None
                return {
                    "persisted": True,
                    "session_id": session_id,
                    "storage": "disk",
                    "path": own,
                    "size_bytes": size,
                    "note": "Already stored in the cache; nothing to do.",
                }
            target = cache_dir() / f"{session_id}.db"
        else:
            target = resolve_path(path)
            if target.is_dir():
                return {"error": f"path is a directory: {target}"}
        target = target.expanduser().absolute()

        if own and target == Path(own).absolute():
            return {"error": "Refusing to write over the session's own cache file."}
        if target.exists() and not overwrite:
            return {
                "error": f"Target exists: {target}",
                "hint": "Pass overwrite=true to replace it (written atomically via temp + rename).",
            }
        try:
            size = persist_connection(conn, target)
            if path is None:
                stats["storage"] = "disk"
                stats["db_path"] = str(target)
                atomic_write_text(target.with_suffix(".json"), json.dumps(stats, indent=2))
        except (OSError, sqlite3.Error) as exc:
            return {"error": f"persist failed: {exc}"}
        return {
            "persisted": True,
            "session_id": session_id,
            "storage": storage,
            "path": str(target),
            "size_bytes": size,
            "cache_entry": path is None,
        }
