"""Find usable Playwright-style Chromium builds on disk (no driver start)."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

#: Only mappings known for certain. Anything else is reported as "unknown".
PLAYWRIGHT_FOR_CHROMIUM_BUILD: dict[str, str] = {"1194": "1.56.x"}

_BUILD_RE = re.compile(r"-(\d+)$")


def search_roots() -> list[Path]:
    """Browser roots in priority order: env, /opt/pw-browsers, ~/.cache/ms-playwright."""
    roots: list[Path] = []
    env = (os.environ.get("PLAYWRIGHT_BROWSERS_PATH") or "").strip()
    if env and env != "0":
        roots.append(Path(env).expanduser())
    roots.append(Path("/opt/pw-browsers"))
    roots.append(Path.home() / ".cache" / "ms-playwright")
    seen: set[str] = set()
    out: list[Path] = []
    for root in roots:
        key = str(root)
        if key not in seen:
            seen.add(key)
            out.append(root)
    return out


def _usable(path: Path) -> bool:
    try:
        return path.is_file() and os.access(path, os.X_OK)
    except OSError:
        return False


def scan_chromium_builds(roots: list[Path] | None = None) -> list[dict[str, Any]]:
    """Return installed chromium builds, newest build first, full chromium before shell.

    Each item: ``{"build", "kind": "chromium"|"headless_shell", "path", "root"}``.
    The unversioned ``chromium`` entry (often a symlink) is listed with
    ``build`` resolved from its target when possible.
    """
    found: list[dict[str, Any]] = []
    seen: set[str] = set()

    def add(build: str, kind: str, path: Path, root: Path) -> None:
        if not _usable(path):
            return
        real = str(path.resolve())
        if real in seen:
            return
        seen.add(real)
        found.append({"build": build, "kind": kind, "path": str(path), "root": str(root)})

    for root in roots if roots is not None else search_roots():
        if not root.is_dir():
            continue
        for d in sorted(root.glob("chromium-*")):
            m = _BUILD_RE.search(d.name)
            if not m:
                continue
            for pat in ("chrome-linux*/chrome", "chrome-win*/chrome.exe"):
                for exe in sorted(d.glob(pat)):
                    add(m.group(1), "chromium", exe, root)
        for d in sorted(root.glob("chromium_headless_shell-*")):
            m = _BUILD_RE.search(d.name)
            if not m:
                continue
            for exe in sorted(d.glob("chrome-linux*/headless_shell")):
                add(m.group(1), "headless_shell", exe, root)
        plain = root / "chromium"
        if plain.exists() and _usable(plain):
            build = "unknown"
            m = re.search(r"chromium-(\d+)", str(plain.resolve()))
            if m:
                build = m.group(1)
            add(build, "chromium", plain, root)
    found.sort(
        key=lambda b: (
            b["kind"] != "chromium",
            -(int(b["build"]) if str(b["build"]).isdigit() else 0),
        )
    )
    return found


def pick_executable(
    builds: list[dict[str, Any]], *, headless: bool = True
) -> dict[str, Any] | None:
    for b in builds:
        if b["kind"] == "chromium":
            return b
    if headless:
        for b in builds:
            if b["kind"] == "headless_shell":
                return b
    return None


def expected_chromium_build(playwright_chromium_path: str | None = None) -> str | None:
    """Chromium build number the installed Playwright expects."""
    try:
        import playwright

        browsers_json = Path(playwright.__file__).parent / "driver" / "package" / "browsers.json"
        data = json.loads(browsers_json.read_text(encoding="utf-8"))
        for entry in data.get("browsers", []):
            if entry.get("name") == "chromium":
                return str(entry.get("revision"))
    except Exception:  # noqa: BLE001
        pass
    if playwright_chromium_path:
        m = re.search(r"chromium-(\d+)", str(playwright_chromium_path))
        if m:
            return m.group(1)
    return None


def pin_hint(builds: list[dict[str, Any]], expected: str | None) -> str | None:
    """Advice on pinning the Playwright version matching an installed build."""
    if not builds:
        return None
    parts = []
    for b in builds:
        pw = PLAYWRIGHT_FOR_CHROMIUM_BUILD.get(str(b["build"]), "unknown")
        parts.append(f"chromium build {b['build']} <-> playwright {pw}")
    known = [
        PLAYWRIGHT_FOR_CHROMIUM_BUILD[str(b["build"])]
        for b in builds
        if str(b["build"]) in PLAYWRIGHT_FOR_CHROMIUM_BUILD
    ]
    tail = (
        f" To use the matching bundled build, pin: pip install 'playwright=={known[0].replace('.x', '.*')}'."
        if known
        else " No known Playwright version for these builds (unknown); "
        "set HARDLY_BROWSER_EXECUTABLE to use one directly."
    )
    return "; ".join(parts) + f" (expected build: {expected or 'unknown'})." + tail
