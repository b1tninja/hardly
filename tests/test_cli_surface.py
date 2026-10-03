"""The CLI surface is frozen: command paths, positionals, flags; and it mirrors the MCP tool names."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import dump_cli_surface  # noqa: E402

SNAPSHOT = ROOT / "tests" / "cli_surface.json"
API = json.loads((ROOT / "tests" / "api_surface.json").read_text(encoding="utf-8"))


def _diff(old: dict, new: dict) -> list[str]:
    out = []
    for n in sorted(set(old) - set(new)):
        out.append(f"removed command `{n}`")
    for n in sorted(set(new) - set(old)):
        out.append(f"added command `{n}`")
    for n in sorted(set(old) & set(new)):
        if old[n] != new[n]:
            out.append(f"changed command `{n}`")
    return out


def test_cli_surface_matches_snapshot():
    old = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    new = json.loads(dump_cli_surface.render())
    changes = _diff(old, new)
    assert not changes, (
        "The CLI surface changed: "
        + "; ".join(changes[:10])
        + ". v1 command names are permanent: if this change is deliberate, regenerate the "
        "snapshot with `python scripts/dump_cli_surface.py` (and `python scripts/gen_tool_docs.py`), "
        "add a CHANGELOG entry and commit."
    )


def test_every_command_mirrors_a_tool_or_is_declared_cli_only():
    surface = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    only = {p for p, row in surface.items() if row["tool"] is None}
    assert only == set(dump_cli_surface.CLI_ONLY)
    for path, row in surface.items():
        if row["tool"]:
            group, _, rest = path.partition(" ")
            assert row["tool"] == f"hardly_{group}_{rest.replace('-', '_')}"
            assert row["tool"] in API
    # Every tool has a command except the in-memory close.
    mirrored = {row["tool"] for row in surface.values() if row["tool"]}
    assert set(API) - mirrored == {"hardly_session_close"}


# Flags that exist only on the CLI, per command (everything else must be a tool parameter).
_EXTRAS = {
    "session open": {"output", "overwrite"},
    "session report": {"format"},
    "entry outline": {"markdown_only"},
    "write catalog-record": {"id", "name", "tags", "group", "endpoint"},
    "browser start": {"foreground", "slot_timeout_seconds"},
    "browser capture-discover": {
        "omit_content", "label", "same_tab", "trace", "slot_timeout_seconds", "diagnose_redirects",
        "brief",
    },
    "browser run-steps": {"steps"},
    "write export": {"output"},
    "write session-copy": {"output"},
    "write screenshot": {"output"},
    "write har-pruned": {"output"},
    "write har-scrubbed": {"output"},
    "write har-merged": {"output"},
    "catalog list": set(),
}
_POSITIONAL_OK = {"har", "other_har"}


def test_flags_reuse_tool_parameter_names():
    from hardly import cli

    parser_rows = {p: pr for p, pr in dump_cli_surface._walk(cli.build_parser())}
    for path, parser in parser_rows.items():
        tool = dump_cli_surface.tool_for(path)
        if tool is None:
            continue
        params = {p["name"] for p in API[tool]["params"]}
        extras = _EXTRAS.get(path, set())
        for a in parser._actions:
            dest = a.dest
            if dest == "help":
                continue
            if path == "har file-check":
                continue  # the doctor knobs map onto the tool's `config` object
            if not a.option_strings:
                ok = dest in params or dest in _POSITIONAL_OK or dest in extras
            else:
                ok = dest in params or dest in extras
            assert ok, f"`hardly {path}`: {a.option_strings or dest} is not a parameter of {tool}"


def test_live_commands_use_confirm_and_never_yes():
    surface = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    for path, row in surface.items():
        flags = {f for a in row["args"] for f in a.get("flags", [])}
        assert "--yes" not in flags and "--allow-gate" not in flags, path
        if path.startswith("send "):
            assert "--confirm" in flags, path
        if row["tool"]:
            assert not any(f.endswith(("-ms", "-s", "-json")) for f in flags), path


def test_old_command_names_are_gone():
    surface = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    groups = {p.split()[0] for p in surface}
    for old in ("open", "stats", "summary", "capabilities", "probe", "replay-check", "flow-replay",
                "crawl", "export-md", "export-openapi", "stub", "har-doctor", "redirect-diag"):
        assert old not in groups


def test_cli_docs_are_current():
    script = ROOT / "scripts" / "gen_cli_docs.py"
    rc = subprocess.run([sys.executable, str(script), "--check"]).returncode
    assert rc == 0, "docs/cli.md is stale: run python scripts/gen_tool_docs.py"
    rc = subprocess.run([sys.executable, str(ROOT / "scripts" / "dump_cli_surface.py"), "--check"]).returncode
    assert rc == 0
