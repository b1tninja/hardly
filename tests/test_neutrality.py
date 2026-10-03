"""Guard: hardly stays content neutral (no site/domain specifics in code, docs or fixtures)."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BANNED = re.compile(
    r"assessor|recorder|county|counties|parcel|wyobiz|asspy|clerk|\bdeed\b|property[ _-]search",
    re.I,
)
SKIP = {Path(__file__).resolve(), ROOT / "docs" / "scope.md"}
DIRS = ("src", "docs", "skills", "tests", "scripts")


def test_no_domain_specific_terms():
    hits = []
    for d in DIRS:
        for p in (ROOT / d).rglob("*"):
            if p.suffix not in {".py", ".md", ".json", ".toml", ".txt"} or p.resolve() in SKIP:
                continue
            if "__pycache__" in p.parts:
                continue
            for n, line in enumerate(p.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
                if BANNED.search(line):
                    hits.append(f"{p.relative_to(ROOT)}:{n}: {line.strip()[:80]}")
    assert not hits, "domain-specific terms found:\n" + "\n".join(hits[:20])
