"""The MCP tool surface is frozen: names, parameter order, types, defaults, effect markers."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import dump_api_surface  # noqa: E402

SNAPSHOT = ROOT / "tests" / "api_surface.json"


def _diff(old: dict, new: dict) -> list[str]:
    out = []
    for n in sorted(set(old) - set(new)):
        out.append(f"removed tool {n}")
    for n in sorted(set(new) - set(old)):
        out.append(f"added tool {n}")
    for n in sorted(set(old) & set(new)):
        if old[n] != new[n]:
            out.append(f"changed tool {n}")
    return out


def test_api_surface_matches_snapshot():
    old = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    new = dump_api_surface.surface()
    changes = _diff(old, json.loads(json.dumps(new)))
    assert not changes, (
        "The MCP tool surface changed: "
        + "; ".join(changes[:10])
        + ". v1 tool names and parameters are permanent: if this change is deliberate, "
        "regenerate the snapshot with `python scripts/dump_api_surface.py` and commit it."
    )


def test_api_surface_conventions():
    surface = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    for name, spec in surface.items():
        assert re.fullmatch(r"hardly_[a-z]+(_[a-z]+){0,2}", name), name
        names = [p["name"] for p in spec["params"]]
        assert len(names) == len(set(names)), name
        for p in names:
            assert not p.endswith(("_json", "_ms")) and p not in {"dry_run", "include_noise", "timeout"}, (name, p)
        if spec["effect"] == "write":
            assert "overwrite" in names or name == "hardly_write_catalog_record", name
        if spec["effect"] == "send":
            assert "confirm" in names, name
        else:
            assert name == "hardly_browser_capture_discover" or "confirm" not in names or name.startswith("hardly_send_"), name
