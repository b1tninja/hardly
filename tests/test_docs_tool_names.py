"""Docs, skill, prompts and docstrings only use tool names, tool arguments and CLI commands that exist.

* every ``hardly_*`` name must be in ``tests/api_surface.json`` (so no old name survives);
* every ``hardly_name(key=value, ...)`` example must use real parameter names;
* every ``hardly <group> <command> ...`` example must parse with the real argparse parser.

``docs/api-decisions.md`` lists the old names on purpose and is exempt.
"""

from __future__ import annotations

import json
import re
import shlex
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
API = json.loads((ROOT / "tests" / "api_surface.json").read_text(encoding="utf-8"))
NAMES = set(API)

EXEMPT = {ROOT / "docs" / "api-decisions.md"}


def _doc_files() -> list[Path]:
    files = [ROOT / n for n in ("README.md", "AGENTS.md", "CONTRIBUTING.md", "SECURITY.md", "CHANGELOG.md", "server.json")]
    files += sorted((ROOT / "docs").glob("*.md"))
    files += sorted((ROOT / "skills").rglob("*.md"))
    files += sorted((ROOT / ".github").rglob("*.md")) + sorted((ROOT / ".github").rglob("*.yml"))
    files += sorted((ROOT / "docker").glob("*.y*ml")) + sorted((ROOT / "docker").glob("*.json"))
    files += [ROOT / "Dockerfile", ROOT / "pyproject.toml"]
    return [f for f in files if f.exists() and f not in EXEMPT]


def _src_files() -> list[Path]:
    return sorted((ROOT / "src" / "hardly").rglob("*.py")) + sorted((ROOT / "scripts").glob("*.py"))


def _texts() -> dict[str, str]:
    out = {str(f.relative_to(ROOT)): f.read_text(encoding="utf-8") for f in _doc_files() + _src_files()}
    return out


TEXTS = _texts()
TOKEN = re.compile(r"\bhardly_[a-z][a-z_]*")


def test_every_hardly_tool_name_exists():
    bad: list[str] = []
    for name, text in TEXTS.items():
        for m in TOKEN.finditer(text):
            tok = m.group(0)
            if tok in NAMES:
                continue
            if tok.endswith("_") and any(n.startswith(tok) for n in NAMES):
                continue  # a prefix such as hardly_send_*
            if tok.rstrip("_") in NAMES:
                continue
            if tok in {"hardly_mcp"}:
                continue
            line = text.count("\n", 0, m.start()) + 1
            bad.append(f"{name}:{line}: {tok}")
    assert not bad, "unknown tool names (renamed in v1? see docs/api-decisions.md):\n" + "\n".join(bad[:40])


def _calls(text: str):
    """Yield (offset, tool, args_text) for every ``hardly_x(...)`` call with balanced parentheses."""
    for m in re.finditer(r"\b(hardly_[a-z_]+)\(", text):
        depth, i, quote = 1, m.end(), ""
        while i < len(text) and depth:
            ch = text[i]
            if quote:
                if ch == "\\":
                    i += 1
                elif ch == quote:
                    quote = ""
            elif ch in "'\"":
                quote = ch
            elif ch in "([{":
                depth += 1
            elif ch in ")]}":
                depth -= 1
            i += 1
        if depth == 0:
            yield m.start(), m.group(1), text[m.end() : i - 1]


def _top_level_args(args: str) -> list[str]:
    parts, depth, quote, cur = [], 0, "", []
    for ch in args:
        if quote:
            cur.append(ch)
            if ch == quote:
                quote = ""
            continue
        if ch in "'\"":
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 0:
            parts.append("".join(cur).strip())
            cur = []
            continue
        cur.append(ch)
    if "".join(cur).strip():
        parts.append("".join(cur).strip())
    return parts


def test_tool_call_examples_use_real_parameters():
    bad: list[str] = []
    for name, text in TEXTS.items():
        for off, tool, args in _calls(text):
            if tool not in NAMES or args.strip() in {"", "..."} or "..." in args:
                continue
            params = [p["name"] for p in API[tool]["params"]]
            required = [p["name"] for p in API[tool]["params"] if p["required"]]
            given: list[str] = []
            positional = 0
            for part in _top_level_args(args):
                km = re.match(r"([A-Za-z_]\w*)\s*=(?!=)", part)
                if km:
                    given.append(km.group(1))
                else:
                    positional += 1
            where = f"{name}:{text.count(chr(10), 0, off) + 1}: {tool}({args[:60]})"
            unknown = [g for g in given if g not in params]
            if unknown:
                bad.append(f"{where} unknown argument(s) {unknown}")
            elif positional > len(params):
                bad.append(f"{where} too many positional arguments")
            else:
                covered = set(given) | set(params[:positional])
                # A prose fragment may leave out session_id (the context supplies it);
                # every other required argument must be present.
                missing = [r for r in required if r not in covered and r != "session_id"]
                if missing and name.endswith(".md"):  # source docstrings may show fragments
                    bad.append(f"{where} missing required argument(s) {missing}")
    assert not bad, "tool call examples that do not match the signatures:\n" + "\n".join(bad[:40])


# ----------------------------------------------------------------------------- CLI examples

FENCE = re.compile(r"^\s*(```|~~~)")
SPAN = re.compile(r"`([^`\n]+)`")
PSEUDO = re.compile(r"[<>\[\]|{}]|\.\.\.|\\$")


def _cli_lines(text: str):
    in_fence, pending = False, ""
    for lineno, raw in enumerate(text.splitlines(), 1):
        if FENCE.match(raw):
            in_fence = not in_fence
            pending = ""
            continue
        if in_fence:
            line = raw.strip()
            if line.startswith("$ "):
                line = line[2:]
            if pending:
                line = pending + " " + line
                pending = ""
            if line.endswith("\\"):
                pending = line[:-1].strip()
                continue
            if re.match(r"^(\w+=\S+\s+)*hardly\s+[a-z]", line):
                yield lineno, line, False
        else:
            for m in SPAN.finditer(raw):
                span = m.group(1).strip()
                if re.match(r"^hardly\s+[a-z]", span) and not PSEUDO.search(span):
                    yield lineno, span, True


def _cli_tokens(line: str) -> list[str] | None:
    line = re.split(r"\s(\||>|>>|&&|;)\s|\s#", line)[0]
    try:
        toks = shlex.split(line)
    except ValueError:
        return None
    while toks and re.match(r"^[A-Za-z_]\w*=", toks[0]):
        toks.pop(0)
    if len(toks) < 2 or toks[0] != "hardly":
        return None
    return toks[1:]


def test_cli_examples_parse_with_the_real_parser(capsys):
    from hardly import cli

    parser = cli.build_parser()
    bad: list[str] = []
    checked = 0
    for name, text in TEXTS.items():
        if name.endswith(".py") or name.endswith((".yml", ".yaml", ".json", ".toml")) or name == "Dockerfile":
            continue
        if name == "docs/cli.md":
            continue  # generated command table: bare commands without their positionals
        for lineno, line, line_is_span in _cli_lines(text):
            argv = _cli_tokens(line)
            if argv is None:
                continue
            if argv[0] in {"-h", "--help", "--version"}:
                continue
            checked += 1
            path_len = 1 if argv[0] in {"serve"} else 2
            if line_is_span and len(argv) <= path_len:
                # A bare command name in prose (`hardly session overview`): the path must exist.
                argv = argv + ["--help"]
            try:
                parser.parse_args(argv)
            except SystemExit as exc:
                if exc.code != 0:
                    bad.append(f"{name}:{lineno}: hardly {' '.join(argv)}")
    capsys.readouterr()
    assert checked >= 20, "expected many CLI examples in the docs"
    assert not bad, "CLI examples that the real parser rejects (see docs/cli.md):\n" + "\n".join(bad[:40])
