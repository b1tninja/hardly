"""Relative markdown links in the top-level docs, docs/ and skills/ must resolve."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

LINK = re.compile(r"(?<!!)\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
FENCE = re.compile(r"^(```|~~~)")


def _files() -> list[Path]:
    files = [ROOT / n for n in ("README.md", "AGENTS.md", "CONTRIBUTING.md", "SECURITY.md", "CHANGELOG.md")]
    files += sorted((ROOT / "docs").glob("*.md"))
    files += sorted((ROOT / "skills").rglob("*.md"))
    return [f for f in files if f.exists()]


def _slug(heading: str) -> str:
    text = re.sub(r"[`*_]", "", heading.strip().lower())
    text = re.sub(r"[^\w\- ]", "", text)
    return text.replace(" ", "-")


def _anchors(path: Path) -> set[str]:
    out: set[str] = set()
    in_fence = False
    for line in path.read_text(encoding="utf-8").splitlines():
        if FENCE.match(line):
            in_fence = not in_fence
        elif not in_fence and line.startswith("#"):
            out.add(_slug(line.lstrip("#")))
    return out


def _links(path: Path):
    in_fence = False
    for line in path.read_text(encoding="utf-8").splitlines():
        if FENCE.match(line):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        line = re.sub(r"`[^`]*`", "", line)
        for m in LINK.finditer(line):
            yield m.group(1)


@pytest.mark.parametrize("md", _files(), ids=lambda p: str(p.relative_to(ROOT)))
def test_relative_links_resolve(md: Path) -> None:
    problems = []
    for target in _links(md):
        if re.match(r"^[a-z][a-z0-9+.-]*:", target, re.I) or target.startswith("//"):
            continue  # external (http, mailto, ...)
        file_part, _, anchor = target.partition("#")
        dest = md if not file_part else (md.parent / file_part).resolve()
        if not dest.exists():
            problems.append(f"{target}: file not found")
            continue
        if anchor and dest.suffix == ".md" and dest.is_file() and anchor.lower() not in _anchors(dest):
            problems.append(f"{target}: anchor not found")
    assert not problems, f"{md.relative_to(ROOT)}: " + "; ".join(problems)
