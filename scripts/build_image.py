"""Build hardly-mcp image with Docker MCP self-describing metadata label."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
META = ROOT / "docker" / "server-metadata.json"
IMAGE = "hardly-mcp:latest"


def main() -> int:
    meta = json.dumps(json.loads(META.read_text(encoding="utf-8")), separators=(",", ":"))
    label = f"io.docker.server.metadata={meta}"
    cmd = ["docker", "build", "--label", label, "-t", IMAGE, str(ROOT)]
    print("==> Building", IMAGE)
    subprocess.run(cmd, check=True)
    inspect = subprocess.check_output(
        ["docker", "image", "inspect", IMAGE, "--format", "{{json .Config.Labels}}"],
        text=True,
    )
    labels = json.loads(inspect)
    raw = labels.get("io.docker.server.metadata")
    if not raw:
        print("ERROR: label missing", file=sys.stderr)
        return 1
    # Ensure it parses as JSON
    parsed = json.loads(raw)
    print("label ok:", parsed.get("name"), parsed.get("title"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
