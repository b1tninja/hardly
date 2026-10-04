"""Outbound URL guard: policy, redirect re-validation, address pinning, tool-level refusals."""

from __future__ import annotations

import json

import httpx
import pytest

from hardly import server
from hardly import session as sess
from hardly.core import netguard
from hardly.core.netguard import HostNotAllowed, check_url, new_client

PUBLIC = "93.184.216.34"


@pytest.fixture(autouse=True)
def _guard_on(no_private_opt_in):
    """Default policy in every test of this module."""


@pytest.fixture
def fake_dns(monkeypatch):
    table: dict[str, list[str]] = {
        "public.test": [PUBLIC],
        "mixed.test": [PUBLIC, "10.0.0.5"],
        "meta.test": ["169.254.169.254"],
    }

    def resolve(host: str, port: int) -> list[str]:
        if host in table:
            return table[host]
        raise OSError("no such host")

    monkeypatch.setattr(netguard, "_resolve", resolve)
    return table


BLOCKED = [
    "http://127.0.0.1/", "http://127.1.2.3:8080/x", "http://[::1]/", "http://0.0.0.0/",
    "http://10.1.2.3/", "http://172.16.0.1/", "http://192.168.1.1/", "http://[fd00::1]/",
    "http://169.254.169.254/latest/meta-data/", "http://[fe80::1]/", "http://100.64.0.1/",
    "http://224.0.0.1/", "http://240.0.0.1/", "http://[::ffff:127.0.0.1]/", "http://[::ffff:10.0.0.1]/",
    "http://[::ffff:169.254.169.254]/", "http://[64:ff9b::a00:1]/", "http://[2002:7f00:1::]/",
    "http://localhost/", "http://LOCALHOST./", "http://a.b.localhost/", "http://printer.local/",
    "http://db.internal/", "http://2130706433/", "http://0x7f.0.0.1/", "http://0177.0.0.1/",
]


@pytest.mark.parametrize("url", BLOCKED)
def test_blocked_addresses_and_names(url):
    with pytest.raises(HostNotAllowed) as ei:
        check_url(url)
    assert ei.value.code == "host_not_allowed"
    assert "HARDLY_ALLOW_PRIVATE_HOSTS" in (ei.value.hint or "")


@pytest.mark.parametrize(
    "url",
    [
        "ftp://public.test/", "file:///etc/passwd", "gopher://public.test/", "http://user:pw@public.test/",
        "http://public.test\\@127.0.0.1/", "http://public.test/ x", "//public.test/", "public.test",
    ],
)
def test_scheme_userinfo_and_ambiguous_forms(url, fake_dns):
    with pytest.raises(HostNotAllowed):
        check_url(url)


def test_public_host_passes_and_returns_addresses(fake_dns):
    assert check_url("https://public.test/a?b=1") == [PUBLIC]
    assert check_url("http://93.184.216.34:8080/") == [PUBLIC]
    assert check_url("http://unresolvable.test/") == []  # fails on its own when sent


def test_any_private_record_refuses(fake_dns):
    with pytest.raises(HostNotAllowed, match="10.0.0.5"):
        check_url("http://mixed.test/")
    with pytest.raises(HostNotAllowed, match="169.254.169.254"):
        check_url("http://meta.test/")


def test_opt_out_env_keeps_scheme_and_userinfo_rules(monkeypatch, fake_dns):
    monkeypatch.setenv("HARDLY_ALLOW_PRIVATE_HOSTS", "1")
    assert check_url("http://127.0.0.1:9/") == []
    assert check_url("http://localhost/") == []
    with pytest.raises(HostNotAllowed):
        check_url("ftp://127.0.0.1/")
    with pytest.raises(HostNotAllowed):
        check_url("http://u:p@127.0.0.1/")


def test_cli_flag_sets_opt_out(monkeypatch):
    from hardly import cli

    monkeypatch.delenv("HARDLY_ALLOW_PRIVATE_HOSTS", raising=False)
    with pytest.raises(SystemExit):
        cli.main(["--allow-private-hosts", "send", "redirect-walk", "http://127.0.0.1:1/"])
    assert netguard.private_hosts_allowed()
    monkeypatch.delenv("HARDLY_ALLOW_PRIVATE_HOSTS")  # the CLI set it in os.environ


# ------------------------------------------------------------------ client: redirects and pinning


def _redirecting(location: str, seen: list[httpx.Request]):
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.host == PUBLIC and request.url.path == "/start":
            return httpx.Response(302, headers={"location": location})
        return httpx.Response(200, text="ok")

    return httpx.MockTransport(handler)


def test_followed_redirect_to_private_is_refused_before_it_is_sent(fake_dns):
    seen: list[httpx.Request] = []
    c = new_client(transport=_redirecting("http://169.254.169.254/latest", seen))
    with pytest.raises(HostNotAllowed):
        c.get("https://public.test/start", follow_redirects=True)
    assert [r.url.host for r in seen] == [PUBLIC]  # the metadata hop never reached the transport


def test_manual_hop_is_checked_too(fake_dns):
    seen: list[httpx.Request] = []
    c = new_client(transport=_redirecting("http://169.254.169.254/latest", seen))
    r = c.get("https://public.test/start")
    assert r.status_code == 302
    with pytest.raises(HostNotAllowed):
        c.get(r.headers["location"])
    assert len(seen) == 1


def test_connection_is_pinned_to_validated_address_with_host_and_sni(fake_dns):
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200)

    c = new_client(transport=httpx.MockTransport(handler))
    c.get("https://public.test/p?q=1")
    (req,) = seen
    assert req.url.host == PUBLIC
    assert req.headers["host"] == "public.test"
    assert req.extensions["sni_hostname"] == "public.test"


def test_host_not_allowed_is_an_httpx_error():
    with pytest.raises(httpx.HTTPError):
        new_client().get("http://10.0.0.1/")


# ------------------------------------------------------------------ tools


def _call(fn, **kw):
    return json.loads(fn(**kw))


@pytest.mark.parametrize("confirm", [False, True])
@pytest.mark.parametrize(
    "name,kw",
    [
        ("hardly_send_site_crawl", {"url": "http://169.254.169.254/"}),
        ("hardly_send_arcgis_explore", {"url": "http://10.0.0.1/arcgis/rest/services/X/MapServer"}),
        ("hardly_send_redirect_walk", {"url": "http://localhost:8080/"}),
        ("hardly_browser_capture_discover", {"url": "http://192.168.0.1/"}),
    ],
)
def test_url_tools_refuse_with_actionable_error(name, kw, confirm):
    out = _call(getattr(server, name), confirm=confirm, **kw)
    assert out["code"] == "host_not_allowed"
    assert "HARDLY_ALLOW_PRIVATE_HOSTS" in out["hint"]
    assert "sent" not in out


def test_browser_tools_refuse_initial_url(fake_dns):
    assert _call(server.hardly_browser_start, url="http://127.0.0.1:3000/")["code"] == "host_not_allowed"
    out = _call(server.hardly_browser_interact, action="goto", url="http://169.254.169.254/")
    assert out["code"] == "host_not_allowed"
    out = _call(
        server.hardly_browser_capture_discover,
        url="https://public.test/",
        analyze=True,
        steps=[{"op": "goto", "url": "http://10.0.0.1/"}],
        confirm=False,
    )
    assert out["code"] == "host_not_allowed"


def _har(tmp_path, host: str) -> str:
    entry = {
        "startedDateTime": "2024-01-01T00:00:00.000Z",
        "time": 5,
        "request": {
            "method": "GET", "url": f"http://{host}/api/x?a=1", "httpVersion": "HTTP/1.1", "headers": [],
            "queryString": [{"name": "a", "value": "1"}], "cookies": [], "headersSize": -1, "bodySize": 0,
        },
        "response": {
            "status": 200, "statusText": "OK", "httpVersion": "HTTP/1.1", "headers": [], "cookies": [],
            "content": {"size": 2, "mimeType": "application/json", "text": "{}"},
            "redirectURL": "", "headersSize": -1, "bodySize": 2,
        },
        "cache": {},
        "timings": {"send": 0, "wait": 5, "receive": 0},
    }
    p = tmp_path / "t.har"
    har = {"log": {"version": "1.2", "creator": {"name": "t", "version": "1"}, "entries": [entry]}}
    p.write_text(json.dumps(har))
    return sess.open_har(str(p), force=True)["session_id"]


@pytest.mark.parametrize("confirm", [False, True])
@pytest.mark.parametrize(
    "name,kw",
    [
        ("hardly_send_entry", {"entry_id": 0}),
        ("hardly_send_entry_ablation", {"entry_ids": [0]}),
        ("hardly_send_entry_series", {"entry_id": 0}),
    ],
)
def test_har_entry_tools_refuse_private_targets(tmp_path, name, kw, confirm):
    sid = _har(tmp_path, "169.254.169.254")
    out = _call(getattr(server, name), session_id=sid, confirm=confirm, **kw)
    assert out["code"] == "host_not_allowed", out
    assert "HARDLY_ALLOW_PRIVATE_HOSTS" in out["hint"]


def test_har_entry_tools_allow_public_dry_run(tmp_path, fake_dns):
    sid = _har(tmp_path, "public.test")
    out = _call(server.hardly_send_entry, session_id=sid, entry_id=0)
    assert out["sent"] is False and out["plan"]["requests"][0]["entry_id"] == 0


def test_catalog_verify_plan_reports_blocked_and_run_skips(tmp_path, fake_dns):
    from hardly.core import catalog as C

    cat = C.Catalog()
    cat.upsert(
        {
            "id": "t1",
            "endpoints": [
                {"role": "api", "url": "http://10.0.0.9/a"},
                {"role": "page", "url": "https://public.test/"},
            ],
        }
    )
    path = tmp_path / "cat.json"
    C.save(cat, path)
    plan = _call(server.hardly_send_catalog_verify, catalog_path=str(path))["plan"]["endpoints"]
    assert plan["blocked"][0]["code"] == "host_not_allowed" and "10.0.0.9" in plan["blocked"][0]["reason"]
    sent: list[str] = []

    class Adapter(C.DefaultAdapter):
        def verify(self, endpoint, **kw):
            sent.append(endpoint.url)
            return C.VerifyResult(status="verified", requests=1)

    run = C.CatalogRunner(C.load(path), adapter=Adapter(), confirm=True, delay_s=0, sleep=lambda s: None).run()
    assert sent == ["https://public.test/"]
    assert {"target": "t1", "role": "api", "error": "host_not_allowed"} in run["errors"]
    assert any("HARDLY_ALLOW_PRIVATE_HOSTS" in n for n in run["next"])


def test_crawl_library_refuses_without_opt_in():
    from hardly.core.crawl import crawl

    with pytest.raises(HostNotAllowed):
        crawl("http://127.0.0.1:9/", (), max_pages=1, depth=0, delay_s=0)
