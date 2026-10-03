"""HAR sessions: one rule, idempotent open, contextlib-style handles.

Give an output path to save; otherwise nothing is written::

    with open_session("capture.har") as s:                  # in memory, nothing on disk
        conn = s.conn                                       # read-only sqlite3 connection
    with open_session("capture.har", output_path="idx.db"):  # also saves the index there
        ...
    with open_session("idx.db") as s:                       # a saved index: no re-ingest
        ...

The MCP/CLI layer (:func:`open_har` and friends) is a thin dict-returning wrapper over this.
There is no cache, no storage mode and no registry of opened paths.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import sqlite3
import threading
from pathlib import Path
from typing import Any

from hardly.index.atomic import persist_connection, remove_quietly, replace_file, tmp_path_for
from hardly.index.ingest import INDEX_VERSION, ingest_memory
from hardly.index.schema import open_readonly, seal

# The one name of the "where to save" argument (Python/MCP/CLI wrappers use this spelling).
OUTPUT_PARAM = "output_path"
RULE = "Give an output path to save; otherwise nothing is written."

_lock = threading.RLock()
_sessions: dict[str, _Live] = {}


# ---------------------------------------------------------------- errors


class SessionError(Exception):
    """Base for session errors; ``code`` is the stable machine-readable error code."""

    code = "session_error"

    def __init__(self, message: str, hint: str | None = None):
        super().__init__(message)
        self.message = message
        self.hint = hint

    def __str__(self) -> str:
        return self.message

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"error": self.message, "code": self.code}
        if self.hint:
            out["hint"] = self.hint
        return out


class UnknownSession(SessionError, KeyError):
    code = "unknown_session"


class OutputExists(SessionError):
    code = "output_exists"


class OutputError(SessionError):
    code = "output_error"


class IndexOutdated(SessionError):
    code = "index_outdated"


class HarNotFound(SessionError, FileNotFoundError):
    code = "har_not_found"


MEMORY_NOTE = (
    "Nothing is written to disk: the index lives only in this process and is gone after "
    f"hardly_close or a restart. {RULE} (hardly_open again with {OUTPUT_PARAM}, or "
    "hardly_export_har to save the HAR itself)."
)


# ---------------------------------------------------------------- paths


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


# ---------------------------------------------------------------- index files

_SQLITE_MAGIC = b"SQLite format 3\x00"


def _read_index_meta(path: Path) -> dict[str, str] | None:
    """Embedded meta of a saved index file, or None when ``path`` is not one."""
    try:
        with path.open("rb") as f:
            if f.read(16) != _SQLITE_MAGIC:
                return None
        conn = open_readonly(path)
    except (OSError, sqlite3.Error):
        return None
    try:
        meta = {r[0]: r[1] for r in conn.execute("SELECT key, value FROM meta")}
    except sqlite3.Error:
        return None
    finally:
        conn.close()
    return meta if "index_version" in meta and "har_path" in meta else None


# ---------------------------------------------------------------- live sessions


class _Live:
    """One live session shared by every handle that opened the same input path."""

    def __init__(self, sid: str, input_path: Path, conn: sqlite3.Connection):
        self.sid = sid
        self.input_path = input_path
        self.har_path = input_path  # source HAR (for an index input: the HAR it was built from)
        self.from_index = False
        self.conn = conn
        self.saved_to: Path | None = None
        self.refs = 0
        self.pinned = False  # held by the MCP/CLI dict layer until hardly_close
        self.ephemeral = False  # source HAR was a temporary capture file, already deleted
        self.closed = False
        self.info: dict[str, Any] = {}

    def refresh_info(self) -> None:
        from hardly.index.query import summary

        info: dict[str, Any] = {
            "session_id": self.sid,
            "mode": "archive",
            "opened_from": "index" if self.from_index else "har",
            "saved_to": str(self.saved_to) if self.saved_to else None,
            **summary(self.conn),
            "next": (
                "Mode=archive. Use hardly_hosts / hardly_brief / "
                "hardly_endpoints — do not Read the HAR."
            ),
        }
        if self.ephemeral:
            info["har_path"] = None
            info["ephemeral"] = True
        if self.saved_to is None and not self.from_index:
            info["note"] = MEMORY_NOTE
        self.info = info


class Session:
    """A handle on a live session. Use as a context manager or call :meth:`close`.

    Opening the same input again returns another handle on the *same* live session (reference
    counted); the session is torn down when the last handle closes. ``close()`` is idempotent per
    handle and saves nothing extra.
    """

    def __init__(self, live: _Live):
        self._live = live
        self._closed = False

    @property
    def session_id(self) -> str:
        return self._live.sid

    @property
    def conn(self) -> sqlite3.Connection:
        return self._live.conn

    @property
    def info(self) -> dict[str, Any]:
        return dict(self._live.info)

    @property
    def har_path(self) -> Path:
        return self._live.har_path

    @property
    def saved_to(self) -> Path | None:
        return self._live.saved_to

    @property
    def closed(self) -> bool:
        return self._closed

    def close(self) -> None:
        with _lock:
            if self._closed:
                return
            self._closed = True
            self._live.refs -= 1
            if self._live.refs <= 0 and not self._live.pinned:
                _finalize(self._live)

    def __enter__(self) -> Session:
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def __repr__(self) -> str:
        return f"<Session {self.session_id} {'closed' if self._closed else 'open'}>"


def _finalize(live: _Live) -> None:
    """Forget the live session and close its connection (before any file is replaced)."""
    if _sessions.get(live.sid) is live:
        del _sessions[live.sid]
    if live.closed:
        return
    live.closed = True
    try:
        live.conn.close()
    except sqlite3.Error:
        pass


def _session_id(input_path: Path) -> str:
    return hashlib.sha256(str(input_path).encode()).hexdigest()[:16]


def session_id_for(path: str | os.PathLike) -> str:
    """Pure function of the resolved input path (HAR or saved index)."""
    return _session_id(_resolve(path))


def _resolve(path: str | os.PathLike) -> Path:
    p = resolve_path(path)
    try:
        return p.resolve()
    except OSError:
        return p


def _check_output(output: Path, input_path: Path, overwrite: bool, source_har: Path | None) -> None:
    """Fail fast (before ingesting or writing) when an output path cannot be used."""
    if output.is_dir():
        raise OutputError(f"{OUTPUT_PARAM} is a directory: {output}", "Give a file name.")
    if output in (input_path, source_har):
        raise OutputError(f"Refusing to write over the input itself: {output}")
    if output.exists() and not overwrite:
        raise OutputExists(
            f"{OUTPUT_PARAM} already exists: {output}",
            "Pass overwrite=true to replace it (written atomically via temp + rename), or "
            "choose another path.",
        )


def _save(live: _Live, output: Path, overwrite: bool) -> None:
    _check_output(output, live.input_path, overwrite, live.har_path)
    for other in _sessions.values():
        if other is not live and other.input_path == output:
            raise OutputError(
                f"{output} is open as session {other.sid}; refusing to replace it.",
                f"Call hardly_close(session_id='{other.sid}') first.",
            )
    try:
        persist_connection(live.conn, output)
    except (OSError, sqlite3.Error) as exc:
        raise OutputError(f"saving the index failed: {exc}") from exc
    live.saved_to = output


def _load(sid: str, path: Path) -> _Live:
    meta = _read_index_meta(path)
    if meta is not None:
        try:
            version = int(meta.get("index_version", -1))
        except ValueError:
            version = -1
        if version != INDEX_VERSION:
            raise IndexOutdated(
                f"{path} is an index from another hardly version "
                f"(index_version {version}, this build {INDEX_VERSION}).",
                "Re-open the original HAR with output_path to rebuild it: "
                f"hardly_open(har_path='{meta.get('har_path')}', {OUTPUT_PARAM}='{path}', "
                "overwrite=true).",
            )
        live = _Live(sid, path, open_readonly(path))
        live.from_index = True
        live.har_path = Path(meta["har_path"])
        return live
    _stats, conn = ingest_memory(path)
    return _Live(sid, path, seal(conn))


def open_session(
    har_or_index: str | os.PathLike,
    output_path: str | os.PathLike | None = None,
    overwrite: bool = False,
    *,
    force: bool = False,
    _ephemeral: bool = False,
) -> Session:
    """Index a HAR (or open a saved index) and return a :class:`Session`.

    Give ``output_path`` to also save the index there (atomic, never in place, refused if the file
    exists unless ``overwrite``); otherwise nothing is written. The input may be a HAR or an index
    file saved earlier (detected by its SQLite header and embedded meta; no re-ingest). The session
    id is a pure function of the resolved input path; opening it again returns the same live
    session without re-ingesting, and with ``output_path`` just saves it there. ``force=True``
    re-ingests a HAR (the live session is rebuilt in place).
    """
    path = _resolve(har_or_index)
    if not path.is_file():
        raise HarNotFound(
            f"HAR file not found: {path}",
            "In Docker, host paths are mapped via HARDLY_PATH_MAP "
            "(e.g. D:\\code → /workspace). Use /workspace/... or a mapped host path.",
        )
    output = _resolve(output_path) if output_path else None
    sid = _session_id(path)
    with _lock:
        live = _sessions.get(sid)
        if output is not None:
            _check_output(output, path, overwrite, live.har_path if live else None)
        if live is None or force:
            built = _load(sid, path)
            built.ephemeral = _ephemeral
            if live is None:
                live = built
                _sessions[sid] = live
            else:  # rebuild in place so existing handles see the fresh connection
                old = live.conn
                live.conn, live.from_index, live.har_path = built.conn, built.from_index, built.har_path
                live.ephemeral = built.ephemeral
                try:
                    old.close()
                except sqlite3.Error:
                    pass
        elif _ephemeral:
            live.ephemeral = True
        try:
            if output is not None:
                _save(live, output, overwrite)
        except BaseException:
            if live.refs <= 0 and not live.pinned:
                _finalize(live)
            raise
        live.refs += 1
        live.refresh_info()
        return Session(live)


# ---------------------------------------------------------------- dict layer (MCP / CLI)


def _err(exc: BaseException) -> dict[str, Any]:
    if isinstance(exc, SessionError):
        return exc.to_dict()
    return {"error": str(exc)}


def open_har(
    har_path: str | Path,
    *,
    force: bool = False,
    output_path: str | Path | None = None,
    overwrite: bool = False,
    ephemeral: bool = False,
) -> dict:
    """Open (or reuse) a session and keep it open until ``close_session`` (MCP/CLI semantics).

    ``har_path`` is a HAR or a saved index. With ``output_path`` the index is also saved there;
    without it nothing is written. Errors come back as ``{"error", "code", "hint"}`` (codes:
    har_not_found, output_exists, output_error, index_outdated). ``ephemeral`` marks a session
    whose HAR was a temporary capture file that the caller deletes after this call.
    """
    try:
        handle = open_session(
            har_path, output_path, overwrite, force=force, _ephemeral=ephemeral
        )
    except (SessionError, OSError, sqlite3.Error) as exc:
        return _err(exc)
    live = handle._live
    with _lock:
        live.pinned = True
        out = dict(live.info)
        handle.close()
    return out


def get_conn(session_id: str) -> sqlite3.Connection | None:
    with _lock:
        live = _sessions.get(session_id)
        return live.conn if live else None


def unknown_session(session_id: str) -> UnknownSession:
    return UnknownSession(
        f"Unknown session_id: {session_id}",
        "Session ids do not survive hardly_close or a restart. Call hardly_open again with the "
        "HAR path - or the saved index path - exactly as before: "
        "hardly_open(har_path='<path>'). A session from an ephemeral capture (no output path) "
        "lived only in memory and its HAR was deleted: capture again and pass har_path to keep "
        "it. hardly_list_sessions shows what is open.",
    )


def require_conn(session_id: str) -> sqlite3.Connection:
    conn = get_conn(session_id)
    if conn is None:
        raise unknown_session(session_id)
    return conn


def get_har_path(session_id: str) -> Path | None:
    """The on-disk source HAR path for an open session, if it still exists."""
    with _lock:
        live = _sessions.get(session_id)
        if live is None or live.ephemeral:
            return None
        return live.har_path if live.har_path.is_file() else None


def list_sessions() -> list[dict]:
    """Live sessions only."""
    with _lock:
        live = list(_sessions.items())
    result = []
    for sid, lv in live:
        info = lv.info
        row = {
            "session_id": sid,
            "open": True,
            "har_path": info.get("har_path"),
            "saved_to": info.get("saved_to"),
            "entries": info.get("entries"),
            "api": info.get("api"),
            "noise": info.get("noise"),
        }
        if lv.ephemeral:
            row["ephemeral"] = True
        result.append(row)
    return result


def get_saved_to(session_id: str) -> str | None:
    with _lock:
        live = _sessions.get(session_id)
    return str(live.saved_to) if live and live.saved_to else None


def close_session(session_id: str) -> dict:
    """Close a session for every holder (hardly_close)."""
    with _lock:
        live = _sessions.get(session_id)
        if live is None:
            return {"closed": False, **unknown_session(session_id).to_dict()}
        live.pinned = False
        _finalize(live)
    out: dict[str, Any] = {"closed": True, "session_id": session_id}
    if live.saved_to is None and not live.from_index:
        out["note"] = "Memory session discarded; hardly_open(har_path) rebuilds it."
    return out


def export_har(session_id: str, output_path: str | Path, *, overwrite: bool = False) -> dict:
    """Write a copy of the session's source HAR to ``output_path`` (atomic, never in place).

    Works while the source HAR file still exists. A session from an ephemeral capture has no
    HAR left (it was deleted after ingest): pass an output path to the capture next time.
    """
    with _lock:
        live = _sessions.get(session_id)
    if live is None:
        return unknown_session(session_id).to_dict()
    if live.ephemeral:
        return {
            "error": f"The HAR for session {session_id} was an ephemeral capture and is gone.",
            "code": "har_ephemeral_gone",
            "hint": (
                "Only the index exists: hardly_open(har_path=<HAR>, output_path=...) saves "
                "an index. To keep the HAR, capture again with har_path / -o, or pass "
                "export_path to hardly_capture_stop."
            ),
        }
    src = live.har_path
    if not src.is_file():
        return {
            "error": f"Source HAR no longer exists: {src}",
            "code": "har_missing",
            "hint": "The index in this session is still queryable.",
        }
    target = resolve_path(output_path).expanduser().absolute()
    if target.is_dir():
        return {"error": f"{OUTPUT_PARAM} is a directory: {target}", "code": "output_error"}
    if target == src.absolute():
        return {"error": "Refusing to write over the source HAR.", "code": "output_error"}
    if target.exists() and not overwrite:
        return {
            "error": f"{OUTPUT_PARAM} already exists: {target}",
            "code": "output_exists",
            "hint": "Pass overwrite=true to replace it (written atomically via temp + rename).",
        }
    try:
        size = copy_atomic(src, target)
    except OSError as exc:
        return {"error": f"export failed: {exc}", "code": "output_error"}
    return {
        "exported": True,
        "session_id": session_id,
        "saved_to": str(target),
        "size_bytes": size,
        "note": "HAR files contain live secrets: protect this copy.",
    }


def copy_atomic(src: Path, dest: Path, *, private: bool = True) -> int:
    """Copy ``src`` to ``dest`` via a temp file in dest's directory + os.replace."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = tmp_path_for(dest, "har")
    try:
        shutil.copyfile(src, tmp)
        if private and os.name != "nt":
            os.chmod(tmp, 0o600)
        replace_file(tmp, dest)
        return dest.stat().st_size
    finally:
        remove_quietly(tmp)
