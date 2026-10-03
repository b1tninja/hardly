"""One-pass evidence-index report (synthetic HARs, no network)."""

import json

import pytest

from hardly import cli, server
from hardly.core import report as R
from hardly.core.explain import SEVERITIES
from hardly.core.gates import classify_gates
from hardly.core.stack import fingerprint
from tests.test_botwalls import _entry, _open

SECRET = "SUPERSECRETVALUE9"
LOGIN = (
    '<html><form method="post" action="/login"><input name="user"><input type="password" name="pw">'
    '<input type="hidden" name="__VIEWSTATE" value="vs"></form>'
    '<table><tr><th>Name</th><th>Qty</th></tr><tr><td>widget</td><td>3</td></tr></table>'
    '<div data-url="/lookup" data-id="5"></div></html>'
)


def _entries():
    return [
        _entry(1, "https://a.example.com/", body=LOGIN, resp_headers={"X-Powered-By": "ASP.NET"}),
        _entry(2, "https://a.example.com/blocked", status=403,
               resp_headers={"Server": "cloudflare", "cf-mitigated": "challenge"}, body="Just a moment..."),
        _entry(3, f"https://a.example.com/api/items?token={SECRET}", ct="application/json",
               body='{"items":[{"id":1,"name":"x"}]}', set_cookies=["sessionid"]),
        _entry(4, "https://a.example.com/export.csv", ct="text/csv", body="a,b\n1,2"),
        _entry(5, "https://a.example.com/old", status=302),
    ]


@pytest.fixture
def opened(tmp_path, monkeypatch):
    return _open(tmp_path, monkeypatch, _entries())


def test_summary_is_small_and_counts_sections(opened):
    conn, har = opened
    rep = R.build_report(conn, har)
    assert rep["detail"] == "summary" and "findings" not in rep
    assert len(json.dumps(rep)) < 1500
    assert set(rep["sections"]) == set(R.SECTIONS)
    assert "access" in rep["with_findings"] and "run" not in rep["with_findings"]
    assert {b["kind"] for b in rep["blockers"]} == {"gate"}
    assert rep["sections"]["access"]["blocker"] >= 1


def test_standard_findings_shape_and_vocabulary(opened):
    conn, har = opened
    rep = R.build_report(conn, har, detail="standard")
    assert rep["findings"]
    for f in rep["findings"]:
        assert {"section", "kind", "severity", "label", "entry_ids"} <= set(f)
        assert f["severity"] in SEVERITIES
        assert f["section"] in R.SECTIONS
    kinds = {f["kind"] for f in rep["findings"]}
    assert {"gate", "technology", "login_form", "export_link", "forms", "tables", "run"} <= kinds


def test_never_leaks_secret_values(opened):
    conn, har = opened
    for detail in R.DETAILS:
        for explain in (False, True):
            blob = json.dumps(R.build_report(conn, har, detail=detail, explain=explain))
            md = R.render_markdown(R.build_report(conn, har, detail=detail, explain=explain))
            assert SECRET not in blob and SECRET not in md
            assert "SECRETVALUE" not in blob


def test_lookup_hint_is_generic(opened):
    conn, har = opened
    rep = R.build_report(conn, har, detail="standard")
    tech = next(f for f in rep["findings"] if f["kind"] == "technology")
    assert tech["lookup"]["technology"] == "aspnet-webforms"
    assert "ASP.NET WebForms" in tech["lookup"]["suggest_search"]
    assert "a.example.com" not in json.dumps([f.get("lookup") for f in rep["findings"]])


def test_explain_gates_prose(opened):
    conn, har = opened
    plain = R.build_report(conn, har, detail="standard")
    assert "explain" not in plain and not any("explain" in f for f in plain["findings"])
    rich = R.build_report(conn, har, detail="standard", explain=True)
    assert rich["explain"]["access"]
    assert any(f.get("explain") for f in rich["findings"] if f["kind"] == "technology")


def test_full_has_drill_pointers_and_more_than_standard(opened):
    conn, har = opened
    full = R.build_report(conn, har, detail="full")
    gate = next(f for f in full["findings"] if f["kind"] == "gate")
    assert gate["drill"]["tool"] == "hardly_gate_bot_protection"
    assert all("drill" in f for f in full["findings"] if f["kind"] != "run")
    assert "drill" not in next(f for f in R.build_report(conn, har, detail="standard")["findings"])


def test_sections_filter_and_validation(opened):
    conn, har = opened
    rep = R.build_report(conn, har, sections=["forms"], detail="standard")
    assert set(rep["sections"]) == {"forms"} and {f["section"] for f in rep["findings"]} == {"forms"}
    with pytest.raises(ValueError):
        R.build_report(conn, har, sections=["nope"])
    with pytest.raises(ValueError):
        R.build_report(conn, har, detail="huge")


def test_standard_caps_findings(opened, monkeypatch):
    conn, har = opened
    monkeypatch.setitem(R._CAPS, "standard", (1, 2, 2))
    rep = R.build_report(conn, har, detail="standard")
    per = {}
    for f in rep["findings"]:
        per[f["section"]] = per.get(f["section"], 0) + 1
        assert len(f["entry_ids"]) <= 2
    assert max(per.values()) == 1 and rep["truncated"]["access"] >= 1


def test_detector_failure_is_isolated(opened, monkeypatch):
    conn, har = opened
    import hardly.core.stack as stack_mod

    monkeypatch.setattr(stack_mod, "fingerprint", lambda *a, **k: 1 / 0)
    rep = R.build_report(conn, har, detail="standard")
    assert rep["errors"] == {"stack": "ZeroDivisionError"}
    assert not any(f["section"] == "stack" for f in rep["findings"])
    assert any(f["section"] == "access" for f in rep["findings"])


def test_markdown_and_file_output(opened, tmp_path):
    conn, har = opened
    rep = R.build_report(conn, har, detail="full", explain=True)
    md = R.render_markdown(rep)
    assert md.startswith("# HAR report") and "## access" in md and "| section |" in md and "lookup:" in md
    (tmp_path / "out").mkdir()
    out = R.write_report(rep, tmp_path / "out", har_path=har)
    assert out.name == "w.report.md" and out.read_text().startswith("# HAR report")
    j = R.write_report(rep, tmp_path / "r.json")
    assert json.loads(j.read_text())["detail"] == "full"
    assert R.default_output_path("/x/y/cap.har").name == "cap.report.md"


def test_gate_severity_vocabulary(opened):
    conn, _ = opened
    gates = classify_gates(conn)["gates"]
    assert gates and all(g["severity"] in SEVERITIES for g in gates)
    assert all(g["severity"] == "blocker" for g in gates if g["action"] == "stop")


def test_detectors_are_evidence_only_by_default(opened):
    conn, _ = opened
    g = classify_gates(conn)
    assert "policy" not in g and "next" not in g
    assert "policy" in classify_gates(conn, explain=True)
    fp = fingerprint(conn)
    assert "sdk_notes" not in fp and all("implications" not in t for t in fp["technologies"])
    assert fingerprint(conn, explain=True)["sdk_notes"]


def test_cli_report(opened, tmp_path, capsys, monkeypatch):
    _, har = opened
    parser = cli.build_parser()
    args = parser.parse_args(["session", "report", str(har), "--detail", "standard"])
    assert args.func(args) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["findings"]
    args = parser.parse_args(["write", "export", str(har), "--format", "report", "-o", str(har.parent / "w.report.json")])
    assert args.func(args) == 0
    assert (har.parent / "w.report.json").is_file()
    capsys.readouterr()
    args = parser.parse_args(["session", "report", str(har), "--format", "md"])
    assert args.func(args) == 0
    assert capsys.readouterr().out.startswith("# HAR report")
    args = parser.parse_args(["session", "report", str(har), "--categories", "bogus"])
    assert args.func(args) == 1


def test_mcp_tool(tmp_path, monkeypatch):
    from hardly import session as sess

    path = tmp_path / "m.har"
    path.write_text(json.dumps({"log": {"version": "1.2", "creator": {"name": "t", "version": "1"},
                                        "entries": _entries()}}))
    monkeypatch.setenv("HARDLY_RUNTIME_DIR", str(tmp_path / "cache"))
    sid = sess.open_har(str(path), force=True)["session_id"]
    out = json.loads(server.hardly_write_export(sid, "report", str(tmp_path / "rep.md"),
                                                categories=["access", "forms"], detail="standard"))
    assert "error" not in out and (tmp_path / "rep.md").is_file()
    assert "error" in json.loads(server.hardly_session_report(sid, detail="bad"))
