"""Print the CHANGELOG section for a version. Usage: python scripts/release_notes.py X.Y.Z

Falls back to the [Unreleased] section when no dated section exists for the version.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


def extract(text: str, version: str) -> str:
    for label in (re.escape(version), "Unreleased"):
        m = re.search(rf"^## \[{label}\][^\n]*\n(.*?)(?=^## \[|\Z)", text, re.S | re.M)
        if m and m.group(1).strip():
            return m.group(1).strip() + "\n"
    return f"Release {version}. See CHANGELOG.md.\n"


def main(version: str) -> int:
    root = Path(__file__).resolve().parents[1]
    sys.stdout.write(extract((root / "CHANGELOG.md").read_text(encoding="utf-8"), version))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1]))
