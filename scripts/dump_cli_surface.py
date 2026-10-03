"""Write or check tests/cli_surface.json, the committed CLI command surface.

    python scripts/dump_cli_surface.py          # regenerate the snapshot
    python scripts/dump_cli_surface.py --check  # exit 1 if the snapshot is stale

For every command path (``session open``, ``send entry`` ...): the MCP tool it mirrors (null for
CLI-only commands) and its positionals and flags (flag strings, kind, required, default, choices).
The v1 command names and flags are permanent: regenerate deliberately.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
SNAPSHOT = ROOT / "tests" / "cli_surface.json"
API_SURFACE = ROOT / "tests" / "api_surface.json"

# Commands with no MCP tool of the same name (documented in docs/cli.md).
CLI_ONLY = (
    "serve",
    "skill install",
    "skill print",
    "soak live",
    "catalog init",
    "catalog show",
    "catalog export",
)


def tool_for(path: str) -> str | None:
    """The MCP tool a command path mirrors: first word, then the rest with hyphens as underscores."""
    group, _, rest = path.partition(" ")
    name = f"hardly_{group}_{rest.replace('-', '_')}" if rest else None
    tools = json.loads(API_SURFACE.read_text(encoding="utf-8"))
    return name if name in tools else None


def _json_safe(value):
    if value is argparse.SUPPRESS:
        return None
    try:
        json.dumps(value)
        return value
    except TypeError:
        return str(value)


def _walk(parser: argparse.ArgumentParser, path: tuple[str, ...] = ()):
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            for name, sub in action.choices.items():
                yield from _walk(sub, (*path, name))
            return
    yield " ".join(path), parser


def _args(parser: argparse.ArgumentParser) -> list[dict]:
    out: list[dict] = []
    for a in parser._actions:
        if isinstance(a, argparse._HelpAction):
            continue
        if not a.option_strings:
            out.append(
                {
                    "name": a.dest,
                    "kind": "positional",
                    "nargs": a.nargs,
                    "choices": list(a.choices) if a.choices else None,
                }
            )
            continue
        if isinstance(a, argparse.BooleanOptionalAction):
            kind = "bool"
        elif a.nargs == 0:
            kind = "flag"
        else:
            kind = "value"
        out.append(
            {
                "flags": list(a.option_strings),
                "kind": kind,
                "required": bool(a.required),
                "default": _json_safe(a.default),
                "choices": list(a.choices) if a.choices else None,
            }
        )
    return out


def surface() -> dict[str, dict]:
    """Every command path with its tool, help text and arguments (help is not pinned)."""
    from hardly import cli

    rows: dict[str, dict] = {}
    for path, parser in _walk(cli.build_parser()):
        rows[path] = {
            "tool": tool_for(path),
            "help": (parser.description or "").strip(),
            "args": _args(parser),
        }
    return dict(sorted(rows.items()))


def snapshot_view(full: dict[str, dict]) -> dict[str, dict]:
    """The pinned part: everything except the help text."""
    return {p: {"tool": r["tool"], "args": r["args"]} for p, r in full.items()}


def render() -> str:
    return json.dumps(snapshot_view(surface()), indent=1) + "\n"


def main() -> int:
    text = render()
    if "--check" in sys.argv:
        ok = SNAPSHOT.is_file() and SNAPSHOT.read_text(encoding="utf-8") == text
        if not ok:
            print("tests/cli_surface.json is stale; run python scripts/dump_cli_surface.py")
        return 0 if ok else 1
    SNAPSHOT.write_text(text, encoding="utf-8")
    print(f"wrote {SNAPSHOT} ({len(json.loads(text))} commands)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
