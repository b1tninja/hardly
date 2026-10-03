"""Guard: MCP-registered tools stay in sync with capabilities.TOOLS."""

import inspect
import re

from hardly import capabilities, cli, server


def test_mcp_tools_match_capabilities():
    src = inspect.getsource(server)
    mcp_tools = set(re.findall(r"^def (hardly_\w+)\(", src, re.M))
    caps = set(capabilities.TOOLS)
    assert mcp_tools == caps, (
        f"mcp-only={sorted(mcp_tools - caps)} "
        f"caps-only={sorted(caps - mcp_tools)}"
    )
    assert len(caps) == len(capabilities.TOOLS)  # no dupes in tuple


def test_cli_has_core_analysis_commands():
    parser = cli.build_parser()
    choices = parser._subparsers._group_actions[0].choices
    for name in (
        "search",
        "entry",
        "hosts",
        "flow",
        "schema",
        "curl",
        "compare",
        "probe",
        "sessions",
        "brief",
        "help-tools",
        "modes",
        "capabilities",
    ):
        assert name in choices, name


def test_cli_smoke_brief(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("HARDLY_RUNTIME_DIR", str(tmp_path))
    from pathlib import Path

    fix = Path(__file__).parent / "fixtures" / "sample.har"
    parser = cli.build_parser()
    args = parser.parse_args(
        ["brief", str(fix), "--host", "portal.example.com"]
    )
    assert args.func(args) == 0
    out = capsys.readouterr().out
    assert "portal.example.com" in out


def test_tool_docs_are_current():
    import subprocess
    import sys
    from pathlib import Path

    script = Path(__file__).resolve().parents[1] / "scripts" / "gen_tool_docs.py"
    rc = subprocess.run([sys.executable, str(script), "--check"]).returncode
    assert rc == 0, "docs/tools.md is stale: run python scripts/gen_tool_docs.py"
