"""Locate shipped docs and the Agent Skill; install/print the skill.

Works from a source checkout (``docs/``, ``skills/hardly/`` at the repo root)
and from an installed wheel (copied under ``hardly/_data``).
"""

from __future__ import annotations

import shutil
from pathlib import Path

_PKG = Path(__file__).resolve().parent
_REPO = _PKG.parents[1]

# MCP resource slug -> docs file name
DOC_RESOURCES: dict[str, str] = {
    "concepts": "concepts.md",
    "sdk-workflow": "sdk-workflow.md",
    "capture": "capture.md",
    "gate-policy": "gate-policy.md",
    "tools": "tools.md",
    "reporting": "reporting.md",
    "catalog": "catalog.md",
    "crawl-handoff": "crawl-handoff.md",
}

# Docs copied into the skill's references/ directory.
SKILL_REFERENCES = (
    "cheatsheet.md",
    "concepts.md",
    "sdk-workflow.md",
    "capture.md",
    "gate-policy.md",
    "reporting.md",
    "tools.md",
)


def _first_existing(*cands: Path) -> Path | None:
    for c in cands:
        if c.is_dir():
            return c
    return None


def docs_dir() -> Path | None:
    return _first_existing(_REPO / "docs", _PKG / "_data" / "docs")


def skill_dir() -> Path | None:
    return _first_existing(_REPO / "skills" / "hardly", _PKG / "_data" / "skills" / "hardly")


def read_doc(filename: str) -> str:
    d = docs_dir()
    if d is None or not (d / filename).is_file():
        return (
            f"Documentation file {filename} is not available in this install. "
            "Use hardly_guide_help(topic) or see the project docs/ directory."
        )
    return (d / filename).read_text(encoding="utf-8")


def default_skill_dest() -> Path:
    return Path.home() / ".claude" / "skills" / "hardly"


def skill_text() -> str:
    d = skill_dir()
    if d is None:
        raise FileNotFoundError("hardly skill files are not available in this install")
    return (d / "SKILL.md").read_text(encoding="utf-8")


def install_skill(dest: str | Path | None = None, *, force: bool = True) -> Path:
    """Copy the skill (SKILL.md + references/) to ``dest`` (the skill directory itself)."""
    src = skill_dir()
    if src is None:
        raise FileNotFoundError("hardly skill files are not available in this install")
    target = Path(dest).expanduser() if dest else default_skill_dest()
    if target.exists() and not force:
        raise FileExistsError(str(target))
    target.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src / "SKILL.md", target / "SKILL.md")
    refs = src / "references"
    if refs.is_dir():
        out = target / "references"
        out.mkdir(exist_ok=True)
        for f in sorted(refs.glob("*.md")):
            shutil.copy2(f, out / f.name)
    return target
