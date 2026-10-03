"""Verify built wheel/sdist contain the runtime data. Usage: python scripts/check_dist.py [dist_dir]"""

from __future__ import annotations

import sys
import tarfile
import zipfile
from pathlib import Path

WHEEL_NEEDLES = ("hardly/_data/docs/README.md", "hardly/_data/skills/hardly/SKILL.md", "hardly/cli.py")
SDIST_NEEDLES = ("/docs/README.md", "/skills/hardly/SKILL.md", "/src/hardly/cli.py", "/pyproject.toml", "/server.json")


def main(dist: str = "dist") -> int:
    d = Path(dist)
    wheels, sdists = sorted(d.glob("*.whl")), sorted(d.glob("*.tar.gz"))
    if not wheels or not sdists:
        print(f"need one wheel and one sdist in {d}", file=sys.stderr)
        return 1
    names = zipfile.ZipFile(wheels[0]).namelist()
    missing = [n for n in WHEEL_NEEDLES if n not in names]
    snames = tarfile.open(sdists[0]).getnames()
    missing += [f"sdist:{n}" for n in SDIST_NEEDLES if not any(s.endswith(n) for s in snames)]
    if missing:
        print("missing from distributions:", ", ".join(missing), file=sys.stderr)
        return 1
    print("distribution contents ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(*sys.argv[1:2]))
