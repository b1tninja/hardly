"""Target catalog: schema, validation, IO, queries, adapter and runner (loopback only)."""

from __future__ import annotations

import json

import pytest

from hardly import local_site, server
from hardly.cli import main as cli_main
from hardly.core import catalog as C


def sample() -> C.Catalog:
    cat = C.Catalog(name="demo")
    cat.upsert({
        "id": "t1", "name": "Target One", "tags": ["example-a"],
        "groups": {"region": "r1", "subregion": "s1"},
        "endpoints": [{"role": "search", "url": "https://one.example/find", "kind": "form"},
                      {"role": "api", "url": "https://one.example/api?token=abc123&q=1", "kind": "api"}],
    })
    cat.upsert({"id": "t2", "tags": ["example-b"], "groups": {"region": "r2"},
                "endpoints": [{"role": "map", "url": "https://two.example/map", "status": "dead"}]})
    return cat


def test_redaction_and_validation():
    cat = sample()
    api = cat.get("t1").endpoint("api")
    assert "abc123" not in api.url and "q=1" in api.url
    ep = C.Endpoint.from_dict({"role": "r", "url": "https://u:p@x.example/a;jsessionid=ZZZ#frag"})
    assert "u:p" not in ep.url and "ZZZ" not in ep.url and "frag" not in ep.url
    bad = C.Catalog(targets=[
        C.Target(id="a", endpoints=[C.Endpoint("r", "ftp://x/y", kind="zzz", status="nope")]),
        C.Target(id="a"),
    ])
    text = " ".join(bad.validate())
    assert "http(s)" in text and "kind" in text and "status" in text and "duplicate id" in text
    with pytest.raises(C.CatalogError):
        bad.raise_if_invalid()
    with pytest.raises(C.CatalogError):
        C.Catalog.from_dict({"version": 99, "targets": []})


def test_upsert_merge_and_replace():
    cat = sample()
    cat.upsert({"id": "t1", "tags": ["x"], "groups": {"extra": "e"},
                "endpoints": [{"role": "search", "url": "https://one.example/find", "status": "verified"}]})
    t = cat.get("t1")
    assert t.tags == ["example-a", "x"] and t.groups["region"] == "r1" and t.groups["extra"] == "e"
    assert len(t.endpoints) == 2 and t.endpoint("search").status == "verified" and t.endpoint("search").kind == "form"
    cat.upsert({"id": "t1", "endpoints": []}, merge=False)
    assert cat.get("t1").endpoints == [] and len(cat.targets) == 2


def test_query_and_summary():
    cat = sample()
    assert [t.id for t in cat.select(tag="example-a")] == ["t1"]
    assert [t.id for t in cat.select(group={"region": "r2"})] == ["t2"]
    assert [t.id for t in cat.select(role="map")] == ["t2"]
    assert [t.id for t in cat.select(status="dead")] == ["t2"]
    assert [(t.id, e.role) for t, e in cat.endpoints(role="api")] == [("t1", "api")]
    s = cat.summary()
    assert s["targets"] == 2 and s["endpoints"] == 3
    assert s["by_status"] == {"dead": 1, "unverified": 2} and s["by_group"]["region"] == {"r1": 1, "r2": 1}


def test_save_load_roundtrip_atomic(tmp_path):
    p = tmp_path / "c.json"
    C.save(sample(), p)
    assert C.load(p).to_dict() == sample().to_dict()
    assert [f.name for f in tmp_path.iterdir()] == ["c.json"]  # no temp litter
    assert C.dumps(sample(), "csv").splitlines()[0].startswith("target,name")
    with pytest.raises(C.CatalogError):
        C.load(tmp_path / "missing.json")
    try:
        import yaml  # noqa: F401
    except ImportError:
        return
    y = tmp_path / "c.yaml"
    C.save(sample(), y)
    assert C.load(y).to_dict() == sample().to_dict()


@pytest.mark.usefixtures("allow_private_hosts")
def test_runner_polite_and_stops_on_gate(tmp_path):
    sleeps: list[float] = []
    with local_site.serve() as base:
        cat = C.Catalog(name="lb")
        cat.upsert({"id": "t", "endpoints": [
            {"role": "search", "url": f"{base}/portal/lookup"},
            {"role": "captcha", "url": f"{base}/captcha"},
            {"role": "after", "url": f"{base}/portal/about"},
        ]})
        p = tmp_path / "c.json"
        C.save(cat, p)
        runner = C.CatalogRunner(cat, path=p, confirm=True, delay_s=0.5, sleep=sleeps.append,
                                 clock=lambda: 0.0)
        out = runner.run()
    by = {r["role"]: r for r in out["results"]}
    assert by["search"]["status"] == "verified"
    assert by["captcha"]["status"] == "blocked" and "captcha" in by["captcha"]["gate_classes"]
    assert "after" not in by  # host stopped at the gate; nothing further attempted
    assert out["stopped_hosts"] and sleeps and all(s > 0 for s in sleeps)
    saved = C.load(p).get("t")
    assert saved.endpoint("captcha").status == "blocked" and saved.endpoint("captcha").last_checked
    assert saved.endpoint("after").status == "unverified"
    assert "evad" in json.dumps(out["next"])


@pytest.mark.usefixtures("allow_private_hosts")
def test_runner_resume_budget_and_confirm(tmp_path):
    with local_site.serve() as base:
        cat = C.Catalog()
        cat.upsert({"id": "t", "endpoints": [
            {"role": "a", "url": f"{base}/portal/lookup"},
            {"role": "b", "url": f"{base}/portal/about"},
            {"role": "c", "url": f"{base}/never"},
        ]})
        p = tmp_path / "c.json"
        C.save(cat, p)
        assert "error" in C.CatalogRunner(cat, path=p).run()  # no confirm -> plan only
        assert all(e.status == "unverified" for _, e in cat.endpoints())
        first = C.CatalogRunner(cat, path=p, confirm=True, delay_s=0, max_endpoints=1).run()
        assert first["checked"] == 1 and first["stopped"] == "max_endpoints"
        second = C.CatalogRunner(C.load(p), path=p, confirm=True, delay_s=0).run()
        assert second["checked"] == 2 and second["skipped_recent"] == 1
    final = C.load(p).get("t")
    assert final.endpoint("a").status == "verified"
    assert final.endpoint("c").status in ("verified", "dead")  # loopback demo site may serve a default page
    assert "<html" not in p.read_text()


@pytest.mark.usefixtures("allow_private_hosts")
def test_runner_request_budget():
    with local_site.serve() as base:
        cat = C.Catalog()
        cat.upsert({"id": "t", "endpoints": [{"role": str(i), "url": f"{base}/portal/p{i}"} for i in range(4)]})
        out = C.CatalogRunner(cat, confirm=True, delay_s=0, max_requests=3).run()
    assert out["stopped"] == "max_requests" and out["checked"] < 4


@pytest.mark.usefixtures("allow_private_hosts")
def test_adapter_subclass_discover_and_confirm_gate():
    class Mine(C.TargetAdapter):
        def discover(self, target):
            return [C.Endpoint("map", target.endpoints[0].url.replace("/lookup", "/services"))]

        def keywords(self, target, endpoint):
            return ("widget",)

    a = Mine()
    assert a.verify(C.Endpoint("r", "http://127.0.0.1:1/")).error  # confirm required
    with local_site.serve() as base:
        cat = C.Catalog()
        cat.upsert({"id": "t", "endpoints": [{"role": "search", "url": f"{base}/portal/lookup"}]})
        out = C.CatalogRunner(cat, a, confirm=True, delay_s=0, run_discover=True).run()
    assert out["discovered"] == 1 and {e.role for _, e in cat.endpoints()} == {"search", "map"}
    assert out["results"][0]["status"] == "verified"


@pytest.mark.usefixtures("allow_private_hosts")
def test_cli_and_mcp(tmp_path, capsys):
    p = str(tmp_path / "c.json")
    for argv in (
        ["catalog", "init", p, "--name", "demo"],
        ["write", "catalog-record", p, "--id", "t1", "--tags", "example-a", "--group", "region=r1",
         "--endpoint", "search=https://one.example/find,form"],
    ):
        with pytest.raises(SystemExit) as e:
            cli_main(argv)
        assert e.value.code == 0
    capsys.readouterr()
    with pytest.raises(SystemExit):
        cli_main(["catalog", "list", p, "--tag", "example-a"])
    rows = json.loads(capsys.readouterr().out)["rows"]
    assert rows[0]["kind"] == "form" and rows[0]["role"] == "search"
    with pytest.raises(SystemExit) as e:
        cli_main(["send", "catalog-verify", p])  # no --confirm: a plan, nothing sent
    assert e.value.code == 0
    assert json.loads(capsys.readouterr().out)["sent"] is False

    out = json.loads(server.hardly_write_catalog_record(p, {"id": "t2", "tags": ["example-b"]}))
    assert out["targets"] == 2
    assert json.loads(server.hardly_catalog_list(p, tag="example-a"))["count"] == 1
    assert json.loads(server.hardly_catalog_list(p, detail="summary"))["targets"] == 2
    bad = {"id": "t3", "endpoints": [{"role": "x", "url": "nope"}]}
    assert "error" in json.loads(server.hardly_write_catalog_record(p, bad))
    assert json.loads(server.hardly_send_catalog_verify(p))["sent"] is False  # no confirm: dry-run plan
    with local_site.serve() as base:
        ep = {"id": "lb", "endpoints": [{"role": "s", "url": f"{base}/portal/lookup"}]}
        server.hardly_write_catalog_record(p, ep)
        res = json.loads(server.hardly_send_catalog_verify(p, confirm=True, target_id="lb", delay_seconds=0))
    assert res["results"][0]["status"] == "verified"
