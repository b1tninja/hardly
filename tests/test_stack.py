"""Technology fingerprinting (synthetic data only; no network)."""

import json
from pathlib import Path

import pytest

from hardly import session as sess
from hardly.core.stack import fingerprint, fingerprint_response

FIX = Path(__file__).parent / "fixtures" / "sample.har"
SECRET = "S3CR3T-VALUE-9f8e7d6c5b4a"


def _entry(url, *, status=200, resp_headers=None, req_headers=None, body="", mime="text/html",
           method="GET", post=None):
    req = {
        "method": method, "url": url, "httpVersion": "HTTP/1.1", "cookies": [],
        "headers": [{"name": k, "value": v} for k, v in (req_headers or {}).items()],
        "queryString": [], "headersSize": -1, "bodySize": -1,
    }
    if post is not None:
        req["postData"] = {"mimeType": "application/x-www-form-urlencoded", "text": post}
    hdrs = [{"name": "Content-Type", "value": mime}]
    for k, v in (resp_headers or {}).items():
        for item in (v if isinstance(v, list) else [v]):
            hdrs.append({"name": k, "value": item})
    return {
        "startedDateTime": "2024-01-01T00:00:00.000Z", "time": 5, "request": req,
        "response": {
            "status": status, "statusText": "OK", "httpVersion": "HTTP/1.1", "cookies": [],
            "headers": hdrs, "redirectURL": "", "headersSize": -1, "bodySize": len(body),
            "content": {"size": len(body), "mimeType": mime, "text": body},
        },
        "cache": {}, "timings": {"send": 0, "wait": 5, "receive": 0},
    }


@pytest.fixture
def run(tmp_path, monkeypatch):
    monkeypatch.setenv("HARDLY_CACHE_DIR", str(tmp_path / "cache"))

    def _run(entries, host=None):
        har = tmp_path / "t.har"
        har.write_text(json.dumps({"log": {"version": "1.2", "creator": {"name": "t", "version": "1"},
                                           "entries": entries}}))
        info = sess.open_har(str(har), force=True)
        conn = sess.require_conn(info["session_id"])
        return fingerprint(conn, host=host, explain=True)

    return _run


def _by_id(result):
    return {t["id"]: t for t in result["technologies"]}


def test_webforms_and_telerik(run):
    html = (
        '<form><input type="hidden" name="__VIEWSTATE" value="%s">'
        '<input type="hidden" name="__EVENTVALIDATION" value="x">'
        '<input type="hidden" name="ctl00_RadGrid_ClientState" value="{}">'
        '<a href="javascript:__doPostBack(\'a\',\'b\')">go</a></form>' % SECRET
    )
    r = run([_entry("https://a.test/Default.aspx", body=html,
                    resp_headers={"Set-Cookie": f"ASP.NET_SessionId={SECRET}; path=/; HttpOnly"})])
    t = _by_id(r)
    assert t["aspnet-webforms"]["confidence"] == "high"
    assert t["aspnet-webforms"]["category"] == "server_framework"
    assert "hidden fields" in t["aspnet-webforms"]["implications"]
    assert {"kind": "cookie", "match": "cookie:ASP.NET_SessionId"} in t["aspnet-webforms"]["evidence"]
    assert t["aspnet-webforms"]["entry_ids"] == [0]
    assert t["telerik-kendo"]["category"] == "ui_toolkit"
    assert SECRET not in json.dumps(r)
    assert any("ClientState" in n for n in r["sdk_notes"])
    assert "aspnet-webforms" in r["by_category"]["server_framework"]


def test_antiforgery_cookie_and_field(run):
    r = run([_entry("https://a.test/form", body='<input name="__RequestVerificationToken" value="%s">' % SECRET,
                    resp_headers={"Set-Cookie": f"__RequestVerificationToken={SECRET}; path=/"})])
    t = _by_id(r)["aspnet-antiforgery"]
    assert t["confidence"] == "high" and t["category"] == "auth_stack"
    assert "prior GET" in t["implications"]
    assert SECRET not in json.dumps(r)


def test_blazor_server_and_wasm(run):
    r = run([
        _entry("https://a.test/_blazor/negotiate?negotiateVersion=1", method="POST", mime="application/json", body="{}"),
        _entry("https://a.test/", body='<script src="_framework/blazor.server.js"></script>'),
        _entry("https://b.test/", body='<script src="_framework/blazor.webassembly.js"></script>'),
    ])
    t = _by_id(r)
    assert t["blazor-server"]["confidence"] == "high"
    assert "WebSocket" in t["blazor-server"]["implications"]
    assert "browser" in t["blazor-server"]["implications"]
    assert t["blazor-wasm"]["confidence"] == "high"


def test_laravel_inertia(run):
    r = run([_entry(
        "https://a.test/dash", mime="text/html",
        body='<div id="app" data-page="{&quot;component&quot;:&quot;X&quot;}"></div>',
        resp_headers={"Set-Cookie": [f"laravel_session={SECRET}; path=/", f"XSRF-TOKEN={SECRET}; path=/"],
                      "X-Inertia": "true"},
        req_headers={"X-XSRF-TOKEN": SECRET, "Cookie": f"laravel_session={SECRET}"},
    )])
    t = _by_id(r)
    assert t["laravel"]["confidence"] == "high"
    assert "X-XSRF-TOKEN" in t["laravel"]["implications"]
    assert t["inertia"]["confidence"] == "high" and t["inertia"]["category"] == "frontend"
    assert SECRET not in json.dumps(r)


def test_django_rails_express_spring_php(run):
    r = run([
        _entry("https://d.test/", body='<input name="csrfmiddlewaretoken" value="x">',
               resp_headers={"Set-Cookie": f"csrftoken={SECRET}"}),
        _entry("https://r.test/", body='<input name="authenticity_token" value="x">',
               resp_headers={"Set-Cookie": f"_myapp_session={SECRET}", "X-Request-Id": "abc"}),
        _entry("https://e.test/", resp_headers={"X-Powered-By": "Express", "Set-Cookie": f"connect.sid=s%3A{SECRET}"}),
        _entry("https://s.test/app;jsessionid=ABC123", resp_headers={"Set-Cookie": f"JSESSIONID={SECRET}"}),
        _entry("https://p.test/index.php", resp_headers={"X-Powered-By": "PHP/8.2", "Set-Cookie": f"PHPSESSID={SECRET}"}),
    ])
    t = _by_id(r)
    for tid in ("django", "rails", "express", "spring-servlet", "php"):
        assert t[tid]["confidence"] == "high", tid
        assert t[tid]["category"] == "server_framework"
        assert t[tid]["implications"]
    assert "x-request-id" in t["rails"]["implications"]
    assert SECRET not in json.dumps(r)


def test_named_token_form(run):
    html = ('<form><input type="hidden" name="form.token.name" value="tok_x1">'
            '<input type="hidden" name="tok_x1" value="abc"></form>')
    t = _by_id(run([_entry("https://a.test/f", body=html)]))
    assert t["named-token-form"]["confidence"] == "high"
    assert t["named-token-form"]["category"] == "auth_stack"


def test_frontend_frameworks(run):
    r = run([
        _entry("https://n.test/", body='<script id="__NEXT_DATA__" type="application/json">{}</script>'
                                       '<script src="/_next/static/a.js"></script>'),
        _entry("https://x.test/", body='<script>window.__NUXT__={}</script><script src="/_nuxt/a.js">'),
        _entry("https://r.test/", body='<div id="root"></div><script src="/static/react.production.min.js"></script>'),
        _entry("https://v.test/", body='<div id="app" data-v-1a2b3c4d></div>'),
        _entry("https://g.test/", body='<html ng-app="x"><script src="/js/angular.min.js"></script>'),
        _entry("https://h.test/", body='<app-root ng-version="17.0.1"></app-root>'),
    ])
    t = _by_id(r)
    assert t["nextjs"]["confidence"] == "high" and "hardly_routes" in t["nextjs"]["implications"]
    assert t["nuxt"]["confidence"] == "high"
    assert t["react"]["confidence"] == "low"
    assert t["vue"]["confidence"] in ("medium", "low")
    assert t["angularjs"]["confidence"] == "high"
    assert t["angular"]["confidence"] == "high"
    assert "hardly_routes" in t["angular"]["implications"]


def test_salesforce_aura(run):
    r = run([_entry("https://a.test/s/sfsites/aura?r=1&aura.ApexAction.execute=1", method="POST",
                    mime="application/json", body="{}",
                    post="message=%7B%7D&aura.context=%7B%7D&aura.pageURI=%2Fs%2F&aura.token=undefined")])
    t = _by_id(r)["salesforce-aura"]
    assert t["confidence"] == "high" and "form-encoded" in t["implications"]


def test_cms_and_site_builders(run):
    r = run([
        _entry("https://aem.test/", body='<link href="/etc.clientlibs/site/main.css"><img src="/content/dam/a.png">'),
        _entry("https://wp.test/", body='<link href="/wp-content/themes/x/style.css">'),
        _entry("https://dr.test/", resp_headers={"X-Generator": "Drupal 10"}, body="<script>Drupal.settings={}</script>"),
        _entry("https://wix.test/", body='<script src="https://static.parastorage.com/a.js"></script>'),
        _entry("https://sq.test/", body='<script src="https://static1.squarespace.com/a.js"></script>'),
        _entry("https://wf.test/", body='<html data-wf-page="1" data-wf-site="2">'),
        _entry("https://gd.test/", body='<img src="https://img1.wsimg.com/a.png">'),
        _entry("https://sp.test/", body='<script src="/_layouts/15/init.js"></script>',
               resp_headers={"MicrosoftSharePointTeamServices": "16.0"}),
    ])
    t = _by_id(r)
    for tid, cat in (("aem", "cms"), ("wordpress", "cms"), ("drupal", "cms"), ("wix", "site_builder"),
                     ("squarespace", "site_builder"), ("webflow", "site_builder"),
                     ("godaddy-builder", "site_builder"), ("sharepoint", "cms")):
        assert t[tid]["category"] == cat, tid
        assert t[tid]["confidence"] == "high", tid
        assert "link" in t[tid]["implications"], tid


def test_gis_stacks(run):
    r = run([
        _entry("https://gis.test/arcgis/rest/services/Parcels/FeatureServer/0/query?where=1%3D1&f=json",
               mime="application/json", body='{"objectIdFieldName":"OBJECTID","spatialReference":{}}'),
        _entry("https://exp.test/", body='<script src="https://experience.arcgis.com/x.js"></script>'),
        _entry("https://l.test/", body='<div class="leaflet-container"><div class="leaflet-pane"></div></div>'),
        _entry("https://tiles.test/12/655/1583.png", mime="image/png"),
        _entry("https://w.test/ows?service=WFS&request=GetFeature&typeName=x"),
    ])
    t = _by_id(r)
    assert t["arcgis-rest"]["confidence"] == "high" and t["arcgis-rest"]["category"] == "gis"
    assert "resultOffset" in t["arcgis-rest"]["implications"]
    assert t["arcgis-apps"]["category"] == "gis"
    assert t["leaflet"]["confidence"] == "high"
    assert t["map-tiles"]["confidence"] == "medium"
    assert t["ogc-services"]["confidence"] == "high"


def test_swagger(run):
    t = _by_id(run([_entry("https://a.test/openapi.json", mime="application/json",
                           body='{"openapi":"3.0.1","paths":{}}')]))
    assert t["swagger-openapi"]["confidence"] == "high"


def test_double_encoded_json(run):
    inner = json.dumps({"a": 1, "b": [1, 2]})
    r = run([_entry("https://a.test/api/x", mime="application/json", body=json.dumps(inner))])
    t = _by_id(r)["double-encoded-json"]
    assert t["category"] == "data_convention" and t["confidence"] == "high"
    r2 = run([_entry("https://a.test/api/x", mime="application/json", body=json.dumps("just a string"))])
    assert "double-encoded-json" not in _by_id(r2)


def test_host_filter(run):
    entries = [_entry("https://wp.test/", body='<link href="/wp-content/a.css">'),
               _entry("https://other.test/", body="<p>hi</p>")]
    assert "wordpress" not in _by_id(run(entries, host="other.test"))


def test_pure_response():
    out = fingerprint_response(
        200, {"Set-Cookie": f"laravel_session={SECRET}; HttpOnly", "X-Inertia": "true"}, "<html></html>",
        url="https://a.test/x",
    )
    ids = {t["id"]: t for t in out}
    assert ids["laravel"]["confidence"] == "high"
    assert ids["inertia"]["implications"]
    assert all(t["entry_ids"] == [] for t in out)
    assert SECRET not in json.dumps(out)
    assert fingerprint_response(200, {"Content-Type": "text/html"},
                                "<html><body><h1>Hello</h1><a href='/about'>About</a></body></html>") == []
    out = fingerprint_response(200, {}, '"{\\"a\\":1}"')
    assert out[0]["id"] == "double-encoded-json"


def test_plain_static_page_no_false_positives(run):
    page = ('<!doctype html><html><head><title>Hi</title><link rel="stylesheet" href="/style.css"></head>'
            '<body><div id="main"><h1>Hello</h1><a href="/about">About</a>'
            '<form action="/search"><input name="q"><input type="hidden" name="lang" value="en"></form>'
            '</div></body></html>')
    r = run([_entry("https://static.test/", body=page, resp_headers={"Server": "nginx"}),
             _entry("https://static.test/style.css", mime="text/css", body="body{margin:0}")])
    assert r["technologies"] == []
    assert r["sdk_notes"] == []


def test_sample_har_expected_set(tmp_path, monkeypatch):
    monkeypatch.setenv("HARDLY_CACHE_DIR", str(tmp_path))
    info = sess.open_har(str(FIX), force=True)
    conn = sess.require_conn(info["session_id"])
    r = fingerprint(conn)
    # The synthetic portal page carries WebForms + antiforgery markers; nothing else.
    assert {t["id"] for t in r["technologies"]} == {"aspnet-webforms", "aspnet-antiforgery"}
    assert all("S3CR3T" not in json.dumps(t) for t in r["technologies"])


def _ids(body, url="https://a.test/"):
    return {t["id"] for t in fingerprint_response(200, {}, body, url)}


def test_aspx_in_outbound_links_is_not_a_signal():
    body = '<a href="https://other.test/page.aspx">x</a><script src="/a/b.aspx?v=1"></script>'
    assert "aspnet-webforms" not in _ids(body)
    assert "aspnet-webforms" in _ids("", "https://a.test/default.aspx?x=1")


def test_ng_app_id_is_not_angularjs():
    assert "angularjs" not in _ids('<div ng-app-id="x"></div>')
    assert "angularjs" in _ids('<html ng-app="m"><div></div></html>')


def test_polyfills_alone_is_not_angular():
    assert "angular" not in _ids('<script src="/polyfills.js"></script>')


def test_bare_redoc_word_is_not_a_signal():
    assert "swagger-openapi" not in _ids("<p>The redoc of the matter.</p>")
    assert "swagger-openapi" in _ids("<redoc spec-url='x'></redoc>")
