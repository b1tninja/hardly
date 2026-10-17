"""Every offline CLI command runs on the synthetic fixture and prints what the tool would."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from hardly import cli

FIX = str(Path(__file__).parent / "fixtures" / "sample.har")


def run(capsys, *argv: str) -> tuple[int, str]:
    with pytest.raises(SystemExit) as exc:
        cli.main(list(argv))
    return int(exc.value.code or 0), capsys.readouterr().out


OFFLINE = [
    ("server", "status"),
    ("guide", "help", "capture"),
    ("guide", "mode"),
    ("guide", "mode", "archive"),
    ("guide", "task-plan", "--goal", "x"),
    ("session", "list"),
    ("session", "overview", FIX),
    ("session", "traffic-stats", FIX, "--kind", "json"),
    ("session", "body-coverage", FIX),
    ("session", "issues", FIX),
    ("session", "duplicates", FIX),
    ("session", "slow-requests", FIX, "--min-elapsed-seconds", "0.5"),
    ("session", "report", FIX, "--categories", "access,auth"),
    ("session", "site-brief", FIX),
    ("session", "story", FIX, "--no-include-related"),
    ("session", "timeline", FIX, "--path-prefix", "/", "--offset", "1"),
    ("session", "redirect-history", FIX),
    ("session", "trace-value", FIX),
    ("session", "trace-value", FIX, "--name", "csrf_token"),
    ("session", "compare", FIX, FIX),
    ("session", "plan-steps", FIX),
    ("session", "sql", FIX, "select count(*) as n from entries"),
    ("entry", "search", FIX, "--method", "GET", "--limit", "3", "--offset", "1"),
    ("entry", "get", FIX, "1", "--max-body-chars", "50"),
    ("entry", "around", FIX, "3", "--before", "1", "--after", "1"),
    ("entry", "initiators", FIX, "3"),
    ("entry", "compare", FIX, "1", "2"),
    ("entry", "build-curl", FIX, "1", "--no-redact", "--no-use-env-placeholders"),
    ("entry", "body-query", FIX, "1", "--regex", "a"),
    ("entry", "outline", FIX, "1", "--format", "tree"),
    ("entry", "dependencies", FIX, "3"),
    ("endpoint", "list", FIX, "--limit", "5"),
    ("endpoint", "schema", FIX, "GET", "/api/items", "--host", "api.example.com", "--sections", "schema,param_roles"),
    ("endpoint", "graphql", FIX),
    ("endpoint", "streams", FIX),
    ("endpoint", "pagination", FIX),
    ("endpoint", "arcgis", FIX),
    ("tech", "stack", FIX),
    ("page", "list", FIX),
    ("page", "forms", FIX),
    ("page", "ui", FIX, "--sections", "links,handlers"),
    ("page", "embedded-routes", FIX, "--sections", "script_routes"),
    ("page", "tables", FIX),
    ("auth", "report", FIX, "--sections", "quick,credentials,cookies,secret_names"),
    ("gate", "bot-protection", FIX),
    ("client", "build", FIX, "--host", "portal.example.com"),
]


@pytest.mark.parametrize("argv", OFFLINE, ids=[" ".join(a[:2]) for a in OFFLINE])
def test_offline_command_runs(capsys, monkeypatch, tmp_path, argv):
    monkeypatch.setenv("HARDLY_RUNTIME_DIR", str(tmp_path))
    code, out = run(capsys, *argv)
    assert code == 0, out
    json.loads(out)


def test_merged_commands_print_the_tool_result(capsys):
    from hardly import server

    code, out = run(capsys, "auth", "report", FIX, "--sections", "cookies")
    assert code == 0 and json.loads(out)["sections"] == ["cookies"]
    code, out = run(capsys, "gate", "bot-protection", FIX, "--sections", "barriers")
    assert code == 0 and list(json.loads(out)) == ["sections", "barriers"]
    code, out = run(capsys, "endpoint", "schema", FIX, "GET", "/x", "--sections", "bogus")
    assert code == 1 and json.loads(out)["code"] == "unknown_section"
    assert json.loads(server.hardly_server_status())["sections"] == ["capabilities"]


def test_unknown_input_is_an_error_not_a_traceback(capsys):
    code, out = run(capsys, "entry", "get", "/no/such.har", "1")
    assert code == 1 and "error" in json.loads(out)
    code, out = run(capsys, "page", "ui", FIX, "--sections", "bogus")
    assert code == 1 and json.loads(out)["code"] == "unknown_section"


def test_write_commands_refuse_to_overwrite(capsys, tmp_path):
    out_file = tmp_path / "api.yaml"
    code, out = run(capsys, "write", "export", FIX, "--format", "openapi", "-o", str(out_file))
    assert code == 0 and out_file.is_file() and json.loads(out)["output_path"]
    code, out = run(capsys, "write", "export", FIX, "--format", "openapi", "-o", str(out_file))
    assert code == 1 and json.loads(out)["code"] == "output_exists"
    code, _ = run(capsys, "write", "export", FIX, "--format", "openapi", "-o", str(out_file), "--overwrite")
    assert code == 0

    copy = tmp_path / "copy.har"
    code, out = run(capsys, "write", "session-copy", FIX, "-o", str(copy))
    assert code == 0 and copy.is_file()
    idx = tmp_path / "idx.db"
    code, _ = run(capsys, "session", "open", FIX, "-o", str(idx))
    assert code == 0 and idx.is_file()
    code, out = run(capsys, "session", "overview", str(idx))
    assert code == 0 and json.loads(out)["requests"] == 15

    pruned = tmp_path / "p.har"
    code, _ = run(capsys, "write", "har-pruned", FIX, "-o", str(pruned), "--drop-hosts", "cdn.example.com")
    assert code == 0 and pruned.is_file()
    code, _ = run(capsys, "write", "har-scrubbed", FIX, "-o", str(tmp_path / "s.har"))
    assert code == 0
    code, _ = run(capsys, "write", "har-split", FIX, "--output-dir", str(tmp_path / "split"))
    assert code == 0
    code, _ = run(capsys, "write", "har-merged", FIX, str(pruned), "-o", str(tmp_path / "m.har"))
    assert code == 0
    code, out = run(capsys, "har", "file-check", FIX, "--clock-skew-seconds", "5")
    assert code in (0, 1) and "findings" in json.loads(out)


@pytest.mark.parametrize(
    "argv",
    [
        ("send", "entry", FIX, "1"),
        ("send", "entry-ablation", FIX, "1,2"),
        ("send", "entry-series", FIX, "--entry-id", "0"),
        ("send", "site-crawl", "http://example.com/"),
        ("send", "arcgis-explore", "http://example.com/arcgis/rest/services/X/MapServer"),
        ("send", "redirect-walk", "http://example.com/"),
        ("browser", "capture-discover", "http://example.com/", "--analyze"),
    ],
    ids=lambda a: " ".join(a[:2]),
)
def test_live_commands_only_plan_without_confirm(capsys, argv):
    code, out = run(capsys, *argv)
    data = json.loads(out)
    assert code == 0 and data.get("sent") is False and data.get("confirmed") is False, out


def test_catalog_commands(capsys, tmp_path):
    cat = str(tmp_path / "c.json")
    assert run(capsys, "catalog", "init", cat, "--name", "demo")[0] == 0
    code, out = run(
        capsys, "write", "catalog-record", cat, "--id", "t1", "--tags", "a,b", "--group", "region=r1",
        "--endpoint", "search=https://one.example/find,form",
    )
    assert code == 0 and json.loads(out)["targets"] == 1
    code, out = run(capsys, "write", "catalog-record", cat, "--id", "t1", "--tags", "c")
    assert json.loads(out)["saved"]["tags"] == ["a", "b", "c"]
    code, out = run(capsys, "catalog", "list", cat, "--tag", "a", "--group", "region=r1")
    assert code == 0 and json.loads(out)["count"] == 1
    code, out = run(capsys, "catalog", "list", cat, "--detail", "summary")
    assert json.loads(out)["targets"] == 1
    assert run(capsys, "catalog", "show", cat, "t1")[0] == 0
    assert run(capsys, "catalog", "show", cat, "nope")[0] == 1
    assert run(capsys, "catalog", "export", cat, "--format", "csv")[0] == 0
    code, out = run(capsys, "send", "catalog-verify", cat)
    assert code == 0 and json.loads(out)["sent"] is False


def test_bad_overrides_and_group_are_reported(capsys):
    code, out = run(capsys, "send", "entry-ablation", FIX, "1", "--overrides", "{nope")
    assert code == 1 and "inline JSON" in out
    code, out = run(capsys, "catalog", "list", "x.json", "--group", "novalue")
    assert code == 1 and "key=value" in out


def test_bare_group_prints_usage(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["session"])
    assert exc.value.code == 2
