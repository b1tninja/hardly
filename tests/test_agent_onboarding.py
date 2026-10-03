"""Agent ergonomics: docstring lint, prompts, resources, skill, hardly_start, errors."""

from __future__ import annotations

import asyncio
import inspect
import json
import re
from pathlib import Path

from hardly import cli, resources, server

ROOT = Path(__file__).resolve().parents[1]


def _tool_funcs():
    return {
        n: f
        for n, f in vars(server).items()
        if n.startswith("hardly_") and callable(f)
    }


def _first_sentence(doc: str) -> str:
    para = " ".join(doc.strip().split("\n\n")[0].split())
    m = re.match(r"(.+?[.!?])(\s|$)", para)
    return m.group(1) if m else para


def test_tool_docstring_lint():
    funcs = _tool_funcs()
    assert len(funcs) > 90
    bad = []
    for name, fn in funcs.items():
        doc = inspect.getdoc(fn) or ""
        if not doc.strip():
            bad.append((name, "empty"))
            continue
        first = _first_sentence(doc)
        if len(first) > 160:
            bad.append((name, f"first sentence {len(first)} chars"))
        params = inspect.signature(fn).parameters
        if "confirm" in params and "confirm" not in doc:
            bad.append((name, "live tool must mention confirm"))
        if "confirm" in params and "LIVE" not in doc:
            bad.append((name, "live tool must be marked LIVE"))
    assert not bad, bad


def test_tool_docstrings_have_examples_or_are_simple():
    # Most tools carry a concrete example call.
    funcs = _tool_funcs()
    with_example = [n for n, f in funcs.items() if "Example" in (inspect.getdoc(f) or "")]
    assert len(with_example) >= len(funcs) * 0.8


def test_start_is_registered_and_plans():
    from hardly.capabilities import TOOLS

    assert "hardly_start" in TOOLS
    out = json.loads(server.hardly_start(goal="build a client SDK", har_path="/x/a.har"))
    assert out["mode"] == "archive"
    tools = [s["tool"] for s in out["plan"]]
    assert tools[0] == "hardly_open"
    assert "hardly_stub" in tools
    assert "capture_available" in out["environment"]
    assert out["rules"]
    assert len(json.dumps(out)) < 6000

    out = json.loads(server.hardly_start(goal="the page shows a captcha", url="https://example.com"))
    assert out["mode"] == "interactive"
    assert any(s["tool"] == "hardly_gates" for s in out["plan"])

    assert json.loads(server.hardly_start())["plan"]


def test_prompts_register_and_render():
    prompts = {p.name: p for p in asyncio.run(server.mcp.list_prompts())}
    for name in (
        "reverse_engineer_api",
        "build_client_sdk",
        "diagnose_blocked_capture",
        "verify_client",
    ):
        assert name in prompts, name

    async def render(name, args):
        res = await server.mcp.render_prompt(name, args)
        return "\n".join(
            getattr(getattr(m, "content", None), "text", "") for m in res.messages
        )

    text = asyncio.run(render("reverse_engineer_api", {"har_path": "/d/a.har"}))
    assert "/d/a.har" in text and "hardly_open" in text
    text = asyncio.run(render("build_client_sdk", {"session_id": "abc"}))
    assert "abc" in text and "hardly_stub" in text
    text = asyncio.run(render("diagnose_blocked_capture", {"url": "https://example.com"}))
    assert "https://example.com" in text and "STOP" in text
    text = asyncio.run(render("verify_client", {"session_id": "abc", "entry_id": "7"}))
    assert "entry_ids=[7]" in text and "confirm=true" in text


def test_resources_register_and_read():
    uris = {str(r.uri) for r in asyncio.run(server.mcp.list_resources())}
    want = {
        f"hardly://docs/{s}"
        for s in (
            "concepts",
            "sdk-workflow",
            "capture",
            "gate-policy",
            "tools",
            "reporting",
            "catalog",
            "crawl-handoff",
        )
    } | {"hardly://cheatsheet"}
    assert want <= uris

    async def read(uri):
        res = await server.mcp.read_resource(uri)
        return "".join(getattr(c, "content", "") or "" for c in res.contents)

    sheet = asyncio.run(read("hardly://cheatsheet"))
    assert "hardly_start" in sheet
    assert len(sheet.splitlines()) < 60
    assert "Gate policy" in asyncio.run(read("hardly://docs/gate-policy"))


def test_instructions_cover_workflow_and_safety():
    ins = server.INSTRUCTIONS
    for needle in ("hardly_start", "confirm=true", "Never Read a raw HAR", "captcha", "hardly://cheatsheet"):
        assert needle in ins, needle
    assert len(ins) < 3500


def test_skill_frontmatter_valid():
    skill = resources.skill_dir()
    assert skill is not None
    text = (skill / "SKILL.md").read_text(encoding="utf-8")
    m = re.match(r"---\n(.*?)\n---\n", text, re.S)
    assert m
    fm = dict(
        line.split(": ", 1) for line in m.group(1).splitlines() if ": " in line
    )
    assert fm["name"] == "hardly"
    assert re.fullmatch(r"[a-z0-9-]{1,64}", fm["name"])
    assert 0 < len(fm["description"]) <= 1024
    for trigger in ("HAR", "API", "SDK"):
        assert trigger in fm["description"]
    assert len(text.splitlines()) < 200
    for ref in re.findall(r"references/([\w-]+\.md)", text):
        assert (skill / "references" / ref).is_file(), ref


def test_skill_references_match_docs():
    script = ROOT / "scripts" / "gen_tool_docs.py"
    ns: dict = {"__file__": str(script)}
    exec(compile(script.read_text(encoding="utf-8"), str(script), "exec"), ns)  # noqa: S102
    assert ns["refs_current"](), "run python scripts/gen_tool_docs.py"


def test_skill_print_and_install(tmp_path, capsys):
    args = cli.build_parser().parse_args(["skill", "print"])
    assert args.func(args) == 0
    assert "name: hardly" in capsys.readouterr().out

    dest = tmp_path / "skills" / "hardly"
    args = cli.build_parser().parse_args(["skill", "install", "--dest", str(dest)])
    assert args.func(args) == 0
    assert (dest / "SKILL.md").is_file()
    assert (dest / "references" / "cheatsheet.md").is_file()

    # bare `hardly skill` prints
    args = cli.build_parser().parse_args(["skill"])
    assert args.func(args) == 0


def test_unknown_session_error_is_actionable():
    out = json.loads(server.hardly_summary("nope-does-not-exist"))
    assert "error" in out
    text = json.dumps(out)
    assert "hardly_open" in text and out["code"] == "unknown_session"


def test_missing_file_error_is_actionable():
    out = json.loads(server.hardly_open("/definitely/not/here.har"))
    assert "error" in out
    assert "path" in json.dumps(out).lower()


def test_confirm_missing_errors_say_how():
    out = json.loads(server.hardly_redirect_diag("https://example.com"))
    assert "confirm=true" in json.dumps(out)


def test_cli_start(capsys):
    args = cli.build_parser().parse_args(["start", "--goal", "x", "--har", "a.har"])
    assert args.func(args) == 0
    assert json.loads(capsys.readouterr().out)["plan"]
