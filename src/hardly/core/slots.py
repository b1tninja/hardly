"""Cross-process capture slot limiter.

Browser captures are heavy; dozens of agents launching Chromium at once starve
each other and time out. This module caps concurrent browser captures with
``fcntl`` file locks under ``<cache_dir>/slots/`` so separate processes (MCP
server, CLI, capture workers) share one limit.

- ``HARDLY_CAPTURE_SLOTS`` - max concurrent captures (default 4; ``0`` or
  negative = unlimited, no locking).
- ``HARDLY_CAPTURE_SLOT_TIMEOUT`` - default seconds to wait for a slot
  (default 300; ``0`` = fail immediately when all slots are busy).

Layout::

    slots/slot-<n>.lock            flock()ed while a capture holds slot n
    slots/wait-<pid>-<tok>.marker  one per waiting process (content: pid)

Waiting markers whose pid is dead are ignored (and removed). Where ``fcntl``
is unavailable (Windows) the limiter degrades to a no-op with a warning.
"""

from __future__ import annotations

import contextlib
import os
import time
import uuid
import warnings
from collections.abc import Iterator
from pathlib import Path
from typing import Any

try:  # pragma: no cover - platform dependent
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None  # type: ignore[assignment]

DEFAULT_SLOTS = 4
DEFAULT_TIMEOUT_S = 300.0
_POLL_S = 0.1
_warned_noop = False


class SlotTimeoutError(RuntimeError):
    """No capture slot became free in time."""

    #: Same vocabulary as ``capture_errors.classify_capture_error``.
    error_class = "slot_timeout"
    error_retryable = True

    def to_dict(self) -> dict[str, Any]:
        from hardly.core.capture_errors import with_error_class

        return with_error_class({"status": "error", "error": str(self)})


def slot_limit() -> int:
    """Configured slot count; ``0`` means unlimited."""
    raw = (os.environ.get("HARDLY_CAPTURE_SLOTS") or "").strip()
    if not raw:
        return DEFAULT_SLOTS
    try:
        n = int(raw)
    except ValueError:
        return DEFAULT_SLOTS
    return n if n > 0 else 0


def default_timeout_s() -> float:
    raw = (os.environ.get("HARDLY_CAPTURE_SLOT_TIMEOUT") or "").strip()
    if not raw:
        return DEFAULT_TIMEOUT_S
    try:
        return max(0.0, float(raw))
    except ValueError:
        return DEFAULT_TIMEOUT_S


def slots_dir() -> Path:
    from hardly.session import cache_dir

    path = cache_dir() / "slots"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


_MARKER_GRACE_S = 2.0


def _write_marker(directory: Path) -> Path:
    """Create a wait marker atomically (never visible half-written)."""
    name = f"wait-{os.getpid()}-{uuid.uuid4().hex[:8]}.marker"
    final = directory / name
    tmp = directory / f".tmp-{name}"
    tmp.write_text(f"{os.getpid()}\n", encoding="utf-8")
    os.replace(tmp, final)
    return final


def _live_markers(directory: Path, *, prune: bool = True) -> list[Path]:
    live: list[Path] = []
    for marker in directory.glob("wait-*.marker"):
        try:
            pid = int(marker.read_text(encoding="utf-8").strip().split()[0])
        except (OSError, ValueError, IndexError):
            pid = 0
            # A marker being created by another waiter may read empty for an
            # instant; do not prune (or ignore) a very fresh one.
            try:
                if (
                    marker.stat().st_size == 0
                    and time.time() - marker.stat().st_mtime < _MARKER_GRACE_S
                ):
                    live.append(marker)
                    continue
            except OSError:
                continue
        if _pid_alive(pid):
            live.append(marker)
        elif prune:
            with contextlib.suppress(OSError):
                marker.unlink()
    return live


def _fcntl_ok() -> bool:
    global _warned_noop
    if fcntl is None:
        if not _warned_noop:
            _warned_noop = True
            warnings.warn(
                "fcntl unavailable; capture slot limiting is disabled",
                RuntimeWarning,
                stacklevel=3,
            )
        return False
    return True


class SlotHandle:
    """A held capture slot.

    ``close_fd`` drops this process's descriptor; the lock persists while a
    child process that inherited the descriptor (via ``pass_fds``) is alive.
    """

    def __init__(self, fd: int | None, info: dict[str, Any]) -> None:
        self.fd = fd
        self.info = info

    def close_fd(self) -> None:
        if self.fd is not None:
            with contextlib.suppress(OSError):
                os.close(self.fd)
            self.fd = None

    def release(self) -> None:
        """Release the lock for every holder of this descriptor."""
        if self.fd is not None and fcntl is not None:
            with contextlib.suppress(OSError):
                fcntl.flock(self.fd, fcntl.LOCK_UN)
        self.close_fd()


def _try_slot(directory: Path, n: int) -> int | None:
    path = directory / f"slot-{n}.lock"
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o644)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)  # type: ignore[union-attr]
    except OSError:
        os.close(fd)
        return None
    with contextlib.suppress(OSError):
        os.ftruncate(fd, 0)
        os.write(fd, f"{os.getpid()}\n".encode())
    return fd


def acquire_slot(timeout_s: float | None = None) -> SlotHandle:
    """Block until a slot is free (or raise ``SlotTimeoutError``)."""
    limit = slot_limit()
    if limit == 0 or not _fcntl_ok():
        return SlotHandle(None, {"waited_s": 0.0, "queue_depth": 0, "slot": -1})
    timeout = default_timeout_s() if timeout_s is None else max(0.0, float(timeout_s))
    directory = slots_dir()
    start = time.monotonic()
    marker: Path | None = None
    queue_depth = 0
    try:
        while True:
            for n in range(limit):
                fd = _try_slot(directory, n)
                if fd is not None:
                    return SlotHandle(
                        fd,
                        {
                            "waited_s": round(time.monotonic() - start, 3),
                            "queue_depth": queue_depth,
                            "slot": n,
                        },
                    )
            waited = time.monotonic() - start
            if marker is None:
                # Publish our marker *before* counting so two simultaneous
                # waiters each see the other (counting first made both see 0).
                marker = _write_marker(directory)
            # Keep the highest depth seen while polling: a peer that times out
            # first removes its marker, so a single count at our own timeout
            # can read 0 even though it was waiting alongside us.
            queue_depth = max(
                queue_depth,
                len([m for m in _live_markers(directory) if m != marker]),
            )
            if waited >= timeout:
                raise SlotTimeoutError(
                    f"waited {waited:.0f}s for a capture slot; "
                    f"{limit} running, {queue_depth} others waiting "
                    "(raise HARDLY_CAPTURE_SLOTS or retry later)"
                )
            time.sleep(min(_POLL_S, max(0.01, timeout - waited)))
    finally:
        if marker is not None:
            with contextlib.suppress(OSError):
                marker.unlink()


@contextlib.contextmanager
def capture_slot(timeout_s: float | None = None) -> Iterator[dict[str, Any]]:
    """Hold a capture slot for the ``with`` body; yields waited_s/queue_depth/slot."""
    handle = acquire_slot(timeout_s)
    try:
        yield dict(handle.info)
    finally:
        handle.release()


def slot_status() -> dict[str, Any]:
    """Observable limiter state: configured slots, held slots, waiting processes."""
    limit = slot_limit()
    if limit == 0 or fcntl is None:
        return {"slots": limit, "in_use": 0, "waiting": 0, "unlimited": limit == 0}
    directory = slots_dir()
    in_use = 0
    for n in range(limit):
        fd = _try_slot(directory, n)
        if fd is None:
            in_use += 1
        else:
            with contextlib.suppress(OSError):
                fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)
    return {
        "slots": limit,
        "in_use": in_use,
        "waiting": len(_live_markers(directory)),
        "unlimited": False,
    }
