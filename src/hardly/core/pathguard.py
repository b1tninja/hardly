"""Write-path guard: every file hardly writes on a caller's behalf goes through :func:`guard_write`.

Rules (checked on the real path, symlinks followed, so a link inside an allowed directory cannot
point the write somewhere else):

* the target must lie inside an allowed root: the current working directory, the OS temp
  directory, the container workspace (``HARDLY_WORKSPACE``, default ``/workspace`` when it exists)
  and every entry of ``HARDLY_WRITE_DIRS`` (``os.pathsep`` separated). ``HARDLY_WRITE_DIRS=*``
  turns the allowlist off (unsafe: documented in SECURITY.md);
* never a special file (device, socket, FIFO), whatever the allowlist says;
* never a credential or shell-startup location under the home directory (``.ssh``, ``.gnupg``,
  ``.aws``, ``.kube``, ``.config/gcloud``, shell rc files, ...) or inside a ``.git`` directory,
  even when that location is inside an allowed root and even with ``HARDLY_WRITE_DIRS=*``.

Existing-file handling (``overwrite``) stays with the callers; this module only decides *where*
writing is acceptable. Failure raises :class:`PathNotAllowed` (code ``path_not_allowed``).
"""

from __future__ import annotations

import os
import stat
import tempfile
from pathlib import Path

from hardly.session import SessionError

WRITE_DIRS_ENV = "HARDLY_WRITE_DIRS"

#: Paths relative to the home directory that are never written, anywhere inside them.
_DENIED_HOME_DIRS = (
    ".ssh", ".gnupg", ".aws", ".azure", ".kube", ".docker", ".config/gcloud", ".config/gh",
    ".config/fish", ".password-store",
)
#: Individual files relative to the home directory.
_DENIED_HOME_FILES = (
    ".bashrc", ".bash_profile", ".bash_login", ".bash_logout", ".profile", ".zshrc", ".zshenv",
    ".zprofile", ".zlogin", ".zlogout", ".cshrc", ".tcshrc", ".kshrc", ".inputrc", ".netrc",
    ".git-credentials", ".gitconfig", ".npmrc", ".pypirc", ".pgpass",
)


class PathNotAllowed(SessionError):
    code = "path_not_allowed"


def _real(path: str | os.PathLike[str]) -> Path:
    return Path(os.path.realpath(os.path.expanduser(str(path))))


def _home() -> Path | None:
    try:
        return _real(Path.home())
    except (RuntimeError, OSError):
        return None


def allow_all() -> bool:
    return (os.environ.get(WRITE_DIRS_ENV) or "").strip() == "*"


def allowed_roots() -> list[Path]:
    """The directories writes may go to (empty list entries are skipped)."""
    roots: list[Path] = []
    try:
        cwd = _real(os.getcwd())
        if cwd != Path(cwd.anchor):  # a filesystem-root cwd would allow everything
            roots.append(cwd)
    except OSError:
        pass
    roots.append(_real(tempfile.gettempdir()))
    ws = (os.environ.get("HARDLY_WORKSPACE") or "").strip() or "/workspace"
    if os.path.isdir(ws):
        roots.append(_real(ws))
    for part in (os.environ.get(WRITE_DIRS_ENV) or "").split(os.pathsep):
        part = part.strip()
        if part and part != "*":
            roots.append(_real(part))
    out: list[Path] = []
    for r in roots:
        if r not in out:
            out.append(r)
    return out


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _denied(real: Path) -> str | None:
    home = _home()
    if home is not None and _inside(real, home):
        rel = real.relative_to(home).as_posix()
        for d in _DENIED_HOME_DIRS:
            if rel == d or rel.startswith(d + "/"):
                return f"~/{d} holds credentials or tool configuration"
        if rel in _DENIED_HOME_FILES:
            return f"~/{rel} is a shell/credential startup file"
    if ".git" in real.parts:
        return "inside a .git directory (hooks and config can run code)"
    return None


def _hint() -> str:
    roots = ", ".join(str(r) for r in allowed_roots())
    return (
        f"Write inside an allowed directory ({roots}) or add one with {WRITE_DIRS_ENV}="
        "<dir>[<pathsep><dir>...]. Credential and shell-startup locations under your home "
        "directory are never writable."
    )


def guard_write(path: str | os.PathLike[str], *, label: str = "output_path") -> Path:
    """Return ``path`` (as a ``Path``, unchanged) when writing there is acceptable, else raise."""
    p = Path(path)
    real = _real(p)
    why = _denied(real)
    if why:
        raise PathNotAllowed(f"{label} {str(p)!r} is not writable: {why}", _hint())
    try:
        st = os.stat(real)
    except OSError:
        st = None
    if st is not None and not (stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode)):
        raise PathNotAllowed(f"{label} {str(p)!r} is a special file (device, socket or pipe)", _hint())
    if not allow_all() and not any(_inside(real, r) for r in allowed_roots()):
        raise PathNotAllowed(f"{label} {str(p)!r} is outside the directories hardly may write to", _hint())
    return p
