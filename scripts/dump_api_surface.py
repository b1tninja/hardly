"""Write or check tests/api_surface.json, the committed MCP tool surface.

    python scripts/dump_api_surface.py          # regenerate the snapshot
    python scripts/dump_api_surface.py --check  # exit 1 if the snapshot is stale

For every MCP tool: ordered parameters (name, type, default, required) and the
effect marker taken from the name prefix (send_, write_, browser_ or none).
The v1 tool names and parameters are permanent: regenerate deliberately.
"""

from __future__ import annotations

import inspect
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
SNAPSHOT = ROOT / "tests" / "api_surface.json"

MARKERS = ("send_", "write_", "browser_")


def effect_marker(name: str) -> str:
    short = name.removeprefix("hardly_")
    for m in MARKERS:
        if short.startswith(m):
            return m.rstrip("_")
    return "read"


def surface() -> dict[str, dict]:
    from hardly import server

    tools: dict[str, dict] = {}
    for name in sorted(n for n, f in vars(server).items() if n.startswith("hardly_") and callable(f)):
        fn = getattr(server, name)
        params = []
        for p in inspect.signature(fn).parameters.values():
            required = p.default is inspect.Parameter.empty
            ann = p.annotation
            params.append(
                {
                    "name": p.name,
                    "type": ann if isinstance(ann, str) else getattr(ann, "__name__", str(ann)),
                    "default": None if required else p.default,
                    "required": required,
                }
            )
        tools[name] = {"effect": effect_marker(name), "params": params}
    return tools


def render() -> str:
    return json.dumps(surface(), indent=1, sort_keys=False) + "\n"


def main() -> int:
    text = render()
    if "--check" in sys.argv:
        ok = SNAPSHOT.is_file() and SNAPSHOT.read_text(encoding="utf-8") == text
        if not ok:
            print("tests/api_surface.json is stale; run python scripts/dump_api_surface.py")
        return 0 if ok else 1
    SNAPSHOT.write_text(text, encoding="utf-8")
    print(f"wrote {SNAPSHOT} ({len(json.loads(text))} tools)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
