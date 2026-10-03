"""Private, short-lived HAR files for captures that were given no output path.

A capture without an explicit output path records to a private temp file in the OS temp
location (``<tempdir>/hardly-<uid>/ephemeral/``, dir mode 0700, files 0600), is ingested into a
Memory session, and the file is deleted right after (also on error, at interpreter exit, and by
a sweep of orphans older than an hour after a crash). Nothing lives under the home directory.
"""

from __future__ import annotations

import atexit
import contextlib
import os
import tempfile
import threading
import time
import uuid
from pathlib import Path

SWEEP_MAX_AGE_S = 3600.0
KEEP_HINT = (
    "No output path was given, so the HAR was not kept: it exists only as an in-memory session. "
    "To keep it, capture again with output_path / -o (or har_path), or pass export_path to "
    "hardly_capture_stop."
)
INTERACTIVE_WARNING = (
    "WARNING: no output path was given, so the HAR will exist only in memory and be discarded "
    "when this capture stops. To keep it pass har_path now, or export_path to "
    "hardly_capture_stop."
)

_lock = threading.Lock()
_pending: set[str] = set()
_swept = False


def runtime_dir() -> Path:
    """Private scratch dir in the OS temp location (``HARDLY_RUNTIME_DIR`` overrides, explicitly).

    Holds capture state, slot locks and ephemeral HARs only; never index data.
    """
    override = (os.environ.get("HARDLY_RUNTIME_DIR") or "").strip()
    if override:
        base = Path(override)
    else:
        uid = os.getuid() if hasattr(os, "getuid") else os.environ.get("USERNAME", "user")
        base = Path(tempfile.gettempdir()) / f"hardly-{uid}"
    base.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        with contextlib.suppress(OSError):
            base.chmod(0o700)
    return base


def ephemeral_dir() -> Path:
    d = runtime_dir() / "ephemeral"
    d.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        with contextlib.suppress(OSError):
            d.chmod(0o700)
    global _swept
    if not _swept:
        _swept = True
        sweep_ephemeral()
    return d


def is_ephemeral_path(path: str | os.PathLike | None) -> bool:
    """True when ``path`` lies directly inside this cache's ephemeral dir."""
    if not path:
        return False
    try:
        p = Path(path).absolute()
        return p.parent == (runtime_dir() / "ephemeral").absolute()
    except OSError:
        return False


def new_ephemeral_har(label: str = "capture") -> Path:
    """Reserve a private 0600 file path for a recording; registered for cleanup at exit."""
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in label)[:30] or "capture"
    path = ephemeral_dir() / f"{safe}-{uuid.uuid4().hex[:12]}.har"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(fd)
    with _lock:
        _pending.add(str(path))
    return path


def secure_file(path: Path) -> None:
    """Make sure a recorded file is owner-only (the browser may have recreated it)."""
    if os.name != "nt":
        with contextlib.suppress(OSError):
            path.chmod(0o600)


def discard(path: str | os.PathLike | None) -> bool:
    """Delete an ephemeral file (and its trace sidecar); only ever inside the ephemeral dir."""
    if not path or not is_ephemeral_path(path):
        return False
    p = Path(path)
    removed = False
    for candidate in (p, p.with_suffix(".trace.zip")):
        try:
            candidate.unlink()
            removed = removed or candidate == p
        except FileNotFoundError:
            pass
        except OSError:
            pass
    with _lock:
        _pending.discard(str(p))
    return removed


def _cleanup_pending() -> None:
    with _lock:
        paths = list(_pending)
    for p in paths:
        discard(p)


atexit.register(_cleanup_pending)


def sweep_ephemeral(max_age_s: float = SWEEP_MAX_AGE_S) -> list[str]:
    """Remove orphaned ephemeral files older than ``max_age_s`` (crash leftovers)."""
    d = runtime_dir() / "ephemeral"
    removed: list[str] = []
    try:
        entries = list(d.iterdir())
    except OSError:
        return removed
    now = time.time()
    for p in entries:
        try:
            st = p.lstat()
            if now - st.st_mtime >= max_age_s and not p.is_dir():
                p.unlink()  # unlinks a symlink itself; never follows it
                removed.append(p.name)
        except OSError:
            continue
    return removed
