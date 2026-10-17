"""Secret canary: distinctive secrets planted in a synthetic HAR must not appear in ANY tool output.

Every registered ``hardly_*`` read tool is called (arguments synthesised from its signature, over
every valid entry id, with every documented ``sections`` value), the live tools are called without
``confirm`` (dry-run plan) and the browser tools without a browser, ``write_*`` tools write into a
temp dir, and a representative set of CLI commands runs. Then no canary may occur in the returned
or printed text or in the shareable artefacts, in raw, URL-encoded or base64 form. Documented
placeholders (``PLACEHOLDER_*``, ``{{name}}``, ``***REDACTED***``) are asserted instead of values.
"""

from __future__ import annotations

import base64
import inspect
import json
import re
from pathlib import Path
from urllib.parse import quote, quote_plus

import pytest

from hardly import cli, server
from hardly import session as sess

# name -> value. Values carry characters that change under URL / base64 encoding.
CANARIES: dict[str, str] = {
    "req_authorization": "cnry01Bearer/AUTH+tok=Qx7",
    "req_cookie": "cnry02COOKIE/sess+val=Rw8",
    "req_xapikey": "cnry03XAPIKEY/val+key=Se9",
    "resp_setcookie": "cnry04SETCOOKIE/val+k=Tf1",
    "query_apikey": "cnry05QUERY/api+key=Ug2",
    "query_token": "cnry06QUERY/token+v=Vh3",
    "path_jsessionid": "cnry07PATHJSESS1ONID0Wi4",
    "form_password": "cnry08FORM/pass+word=Xj5",
    "form_csrf": "cnry09FORM/csrf+tok=Yk6",
    "json_password": "cnry10JSON/pass+word=Zl7",
    "json_nested_token": "cnry11JSON/nested+tok=Am8",
    "json_otp": "cnry12JSONotp9Bn9",
    "double_encoded": "cnry13DOUBLE/enc+tok=Co1",
    "resp_access_token": "cnry14ACCESS/tok+val=Dp2",
    "resp_refresh_token": "cnry15REFRESH/tok+v=Eq3",
    "resp_id_token_nested": "cnry16IDTOK/nested+v=Fr4",
    "location_token": "cnry17LOC/token+v=Gs5",
    "location_code": "cnry18LOC/code+v=Ht6",
    "html_underscore_csrf": "cnry19UNDERSCORECSRF/val+ue=Iu7",
    "html_hidden_csrf": "cnry20HIDDEN/csrf+v=Jv8",
    "html_hidden_token": "cnry21HIDDEN/tok+v=Kw9",
    "basic_password": "cnry22BASIC/pw+val=Lx1",
    "b64_json_secret": "cnry23B64SECRET/val+x=My2",
    "custom_session_header": "cnry24XSESS/header+v=Nz3",
    "referer_token": "cnry25REFERER/tok+v=Oa4",
    "link_header_key": "cnry26LINK/key+v=Pb5",
    "json_client_secret": "cnry27CLIENT/secret+v=Qc6",
    "url_userinfo": "cnry29USERINFOpwSe1",
    "ws_or_html_in_json": "cnry28HTMLINJSON/tok+v=Rd7",
}

# Values supplied to tools as ARGUMENTS (overrides, env): never echoed back either.
INPUT_CANARIES = {
    "override_header": "cnry90OVERRIDEHDR/v+1=Se8",
    "override_body": "cnry91OVERRIDEBODY/v+2=Tf9",
    "env_value": "cnry92ENVVAL/v+3=Ug1",
}


def _variants(value: str) -> dict[str, str]:
    out = {"raw": value, "quote": quote(value, safe=""), "quote_plus": quote_plus(value), "quote_default": quote(value)}
    raw = value.encode()
    for pad in range(3):
        enc = base64.b64encode(b"x" * pad + raw).decode()
        urlsafe = base64.urlsafe_b64encode(b"x" * pad + raw).decode()
        drop = (pad * 8 + 5) // 6 + (1 if pad else 0)
        out[f"b64_{pad}"] = enc[drop:-4]
        out[f"b64u_{pad}"] = urlsafe[drop:-4]
    return {k: v for k, v in out.items() if len(v) >= 12}


ALL_VARIANTS = {
    f"{name}:{kind}": text
    for name, value in {**CANARIES, **INPUT_CANARIES}.items()
    for kind, text in _variants(value).items()
}


def leaks(text: str) -> list[str]:
    return sorted({k for k, v in ALL_VARIANTS.items() if v in text})


# ------------------------------------------------------------------ the synthetic HAR


def _b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def _entry(method, url, *, req_headers=(), resp_headers=(), post=None, status=200, mime="application/json",
           body="{}", t=0, query=None):
    from urllib.parse import parse_qsl, urlsplit

    qs = query if query is not None else [{"name": k, "value": v} for k, v in parse_qsl(urlsplit(url).query)]
    req = {
        "method": method, "url": url, "httpVersion": "HTTP/1.1",
        "headers": [{"name": k, "value": v} for k, v in req_headers],
        "queryString": qs, "cookies": [], "headersSize": -1, "bodySize": 0,
    }
    if post:
        req["postData"] = post
    return {
        "startedDateTime": f"2024-01-01T00:00:{t:02d}.000Z",
        "time": 20 + t,
        "request": req,
        "response": {
            "status": status, "statusText": "", "httpVersion": "HTTP/1.1",
            "headers": [{"name": k, "value": v} for k, v in resp_headers], "cookies": [],
            "content": {"size": len(body), "mimeType": mime, "text": body},
            "redirectURL": dict(resp_headers).get("Location", ""), "headersSize": -1, "bodySize": len(body),
        },
        "cache": {},
        "timings": {"send": 1, "wait": 15, "receive": 4},
    }


def build_har() -> dict:
    c = CANARIES
    host = "https://app.example.com"
    entries = []

    html = (
        "<html><head><title>Sign in</title></head><body>"
        f'<form action="/api/login" method="post" id="f1">'
        f'<input type="hidden" name="_csrf" value="{c["html_underscore_csrf"]}">'
        f'<input type="hidden" name="csrf_token" value="{c["html_hidden_csrf"]}">'
        f'<input type="hidden" name="authenticity_token" value="{c["html_hidden_token"]}">'
        '<input type="text" name="username" value="alice">'
        '<input type="password" name="password" value="">'
        '<input type="submit" value="Sign in"></form>'
        f'<script>var cfg = {{"apiKey": "{c["json_client_secret"]}", "base": "/api"}};</script>'
        "</body></html>"
    )
    entries.append(_entry(
        "GET", f"{host}/app/login;jsessionid={c['path_jsessionid']}?next=/home",
        req_headers=[("Authorization", f"Bearer {c['req_authorization']}"), ("Cookie", f"session={c['req_cookie']}; theme=dark"),
                     ("X-Api-Key", c["req_xapikey"]), ("X-Session-Token", c["custom_session_header"]),
                     ("Referer", f"{host}/prev?token={c['referer_token']}&page=2")],
        resp_headers=[("Set-Cookie", f"sessionid={c['resp_setcookie']}; Path=/; HttpOnly"),
                      ("Link", f"<{host}/items?key={c['link_header_key']}&page=2>; rel=next"),
                      ("Content-Type", "text/html")],
        mime="text/html", body=html, t=0,
    ))

    form = (f"username=alice&password={quote_plus(c['form_password'])}&csrf_token={quote_plus(c['form_csrf'])}"
            f"&_csrf={quote_plus(c['html_underscore_csrf'])}")
    entries.append(_entry(
        "POST", f"{host}/api/login",
        req_headers=[("Content-Type", "application/x-www-form-urlencoded"), ("Cookie", f"session={c['req_cookie']}")],
        resp_headers=[("Location", f"{host}/app/home?token={c['location_token']}&code={c['location_code']}&ok=1"),
                      ("Set-Cookie", f"sessionid={c['resp_setcookie']}; Path=/")],
        post={"mimeType": "application/x-www-form-urlencoded", "text": form,
              "params": [{"name": "username", "value": "alice"}, {"name": "password", "value": c["form_password"]},
                         {"name": "csrf_token", "value": c["form_csrf"]}, {"name": "_csrf", "value": c["html_underscore_csrf"]}]},
        status=302, mime="text/html", body="", t=1,
    ))

    inner = json.dumps({"access_token": c["double_encoded"], "note": "x"})
    jbody = json.dumps({
        "user": "alice",
        "credentials": {"password": c["json_password"], "mfa": {"otp": c["json_otp"]}},
        "settings": {"deep": {"deeper": {"client_secret": c["json_client_secret"]}}},
        "payload": inner,
        "pw_b64": {"password": _b64(c["b64_json_secret"])},
    })
    resp = json.dumps({
        "access_token": c["resp_access_token"], "refresh_token": c["resp_refresh_token"],
        "data": {"items": [{"id": 1, "name": "widget"}], "auth": {"id_token": c["resp_id_token_nested"]}},
        "wrapped": json.dumps({"data": {"id_token": c["double_encoded"]}}),
        "id": 7, "name": "alice",
    })
    entries.append(_entry(
        "POST", f"{host}/api/v1/session",
        req_headers=[("Content-Type", "application/json"),
                     ("Authorization", "Basic " + _b64("alice:" + c["basic_password"]))],
        post={"mimeType": "application/json", "text": jbody}, body=resp, t=2,
    ))

    items = json.dumps({"items": [{"id": 1, "name": "widget", "owner": "alice"}], "total": 1, "page": 1})
    entries.append(_entry(
        "GET", f"{host}/portal/items?api_key={quote_plus(c['query_apikey'])}&token={quote_plus(c['query_token'])}&q=widgets&page=1",
        req_headers=[("Authorization", f"Bearer {c['req_authorization']}"), ("Accept", "application/json")],
        resp_headers=[("Content-Type", "application/json"),
                      ("Set-Cookie", f"sessionid={c['resp_setcookie']}; Path=/; Secure")],
        body=items, t=3,
    ))
    entries.append(_entry(
        "GET", f"{host}/portal/items?q=gadgets&page=2",
        req_headers=[("X-Api-Key", c["req_xapikey"])], body=items, t=4,
    ))
    table = ("<html><body><table id='results'><thead><tr><th>Id</th><th>Name</th></tr></thead>"
             "<tbody><tr><td>1</td><td>widget</td></tr></tbody></table></body></html>")
    entries.append(_entry("GET", f"{host}/app/results", mime="text/html", body=table, t=5,
                          req_headers=[("Cookie", f"session={c['req_cookie']}")]))
    frag = json.dumps({"html": f'<input type="hidden" name="csrf_token" value="{c["ws_or_html_in_json"]}">', "ok": True})
    entries.append(_entry("GET", f"https://svc:{c['url_userinfo']}@legacy.example.com/old/fragment", body=frag, t=6))
    return {"log": {"version": "1.2", "creator": {"name": "canary", "version": "1"}, "entries": entries}}


@pytest.fixture(scope="module")
def har_path(tmp_path_factory):
    p = tmp_path_factory.mktemp("canary") / "canary.har"
    p.write_text(json.dumps(build_har()))
    return p


@pytest.fixture
def sid(har_path):
    return sess.open_har(str(har_path), force=True)["session_id"]


@pytest.fixture(autouse=True)
def _no_opt_in(no_private_opt_in):
    pass




# ------------------------------------------------------------------ driving every tool

N_ENTRIES = 7


def _valid_choices(text: str) -> list[str]:
    """``Valid sections: a, b. Default: ...`` -> ['a', 'b'] from an error reply."""
    m = re.search(r"Valid (?:sections|[a-z_ ]+ values): ([^.]+)\.", text)
    return [s.strip() for s in m.group(1).split(",")] if m else []


def _tools() -> dict[str, object]:
    return {n: getattr(server, n) for n in dir(server) if n.startswith("hardly_") and callable(getattr(server, n))}


def _call(fn, **kw) -> str:
    try:
        out = fn(**kw)
    except Exception as exc:  # noqa: BLE001 - an exception text is output too
        out = f"EXC {type(exc).__name__}: {exc}"
    return out if isinstance(out, str) else json.dumps(out, default=str)


def _args_for(fn, sid: str, eid: int, tmp: Path, har: Path, tag: str) -> dict:
    """Synthesise arguments from the signature: ids from the HAR, paths inside ``tmp``."""
    kw: dict = {}
    for pname, p in inspect.signature(fn).parameters.items():
        if pname in ("session_id", "other_session_id"):
            kw[pname] = sid
        elif pname == "entry_id":
            kw[pname] = eid
        elif pname == "other_entry_id":
            kw[pname] = (eid + 1) % N_ENTRIES
        elif pname == "entry_ids":
            kw[pname] = [eid]
        elif pname == "host":
            kw[pname] = "app.example.com"
        elif pname == "har_path":
            kw[pname] = str(har)
        elif pname == "har_paths":
            kw[pname] = [str(har)]
        elif pname == "output_path":
            kw[pname] = str(tmp / f"{tag}.out")
        elif pname == "output_dir":
            kw[pname] = str(tmp / f"{tag}-dir")
        elif pname == "overwrite":
            kw[pname] = True
        elif pname == "sql":
            kw[pname] = "select * from entries"
        elif pname == "method":
            kw[pname] = "POST"
        elif pname == "path_template":
            kw[pname] = "/api/v1/session"
        elif pname == "url":
            kw[pname] = "https://app.example.com/"
        elif pname == "explain":
            kw[pname] = True
        elif p.default is inspect._empty:
            kw[pname] = None
    return kw


#: Tools that need files, a browser or catalogue input of their own: covered by dedicated tests.
SKIP_GENERIC = {
    "hardly_browser_start", "hardly_session_open", "hardly_session_close", "hardly_send_catalog_verify",
    "hardly_catalog_list", "hardly_write_catalog_record", "hardly_spec_contract_check",
    "hardly_write_screenshot", "hardly_browser_interact", "hardly_browser_run_steps",
}

#: Extra argument sets that reach other code paths of the same tool.
EXTRA_CALLS: dict[str, list[dict]] = {
    "hardly_entry_search": [
        {"body_contains": "cnry"}, {"body_contains": "csrf"}, {"header_contains": "cnry"},
        {"header_name": "Referer"}, {"header_name": "Location"}, {"path_contains": "jsession"},
        {"content_kind": "html"}, {"content_kind": "json"}, {"exclude_noise": False},
    ],
    "hardly_entry_body_query": [
        {"side": "request"}, {"jsonpath": "$..*"}, {"jsonpath": "$..password"}, {"regex": r"cnry\w+"},
        {"regex": r"(?i)value=.{0,60}"}, {"regex": "cnry", "side": "request", "context": 80},
    ],
    "hardly_entry_outline": [{"side": "request"}, {"format": "markdown"}, {"format": "json"}, {"format": "text"}],
    "hardly_page_forms": [{"side": "request"}],
    "hardly_page_ui": [{"side": "request"}],
    "hardly_session_report": [{"detail": "full"}, {"detail": "standard", "categories": ["auth"]}],
    "hardly_entry_build_curl": [{"use_env_placeholders": False}, {"redact": True}],
    "hardly_session_trace_value": [
        {"name": "csrf_token"}, {"name": "token"}, {"name": "access_token"}, {"name": "password"},
        {"name": "sessionid"}, {"value": CANARIES["location_token"]}, {"value": CANARIES["double_encoded"]},
        {"value": CANARIES["html_hidden_csrf"]}, {"value": CANARIES["resp_setcookie"]},
    ],
    "hardly_session_sql": [
        {"sql": f"select * from {t}"}
        for t in ("entries", "headers", "bodies", "value_shapes", "body_signals", "stream_info", "meta", "bodies_fts")
    ]
    + [{"sql": "select h.value_raw, h.value_redacted, e.query_raw, e.initiator_url from headers h join entries e using(entry_id)"}],
    "hardly_session_timeline": [{"path_prefix": "/api"}],
    "hardly_client_build": [{"entry_ids": [0, 1, 2, 3]}, {"entry_ids": [1]}, {"entry_ids": [2, 3, 4, 5, 6]}],
}


def run_all_tools(sid: str, tmp: Path, har: Path) -> tuple[dict[str, list[str]], list[tuple[str, Path]]]:
    """name -> outputs of every call; plus the files the write tools produced."""
    outputs: dict[str, list[str]] = {}
    written: list[tuple[str, Path]] = []
    for name, fn in sorted(_tools().items()):
        if name in SKIP_GENERIC:
            continue
        sig = inspect.signature(fn)
        per_entry = "entry_id" in sig.parameters or "entry_ids" in sig.parameters
        outs: list[str] = []
        for eid in range(N_ENTRIES) if per_entry else [0]:
            tag = f"{name}-{eid}"
            base = _args_for(fn, sid, eid, tmp, har, tag)
            if name == "hardly_write_export":
                for fmt in server._EXPORT_FORMATS:
                    ext = "yaml" if fmt == "openapi" else "json" if fmt == "postman" else "md"
                    p = tmp / f"export-{fmt}-{eid}.{ext}"
                    outs.append(_call(fn, **{**base, "format": fmt, "output_path": str(p)}))
                    if p.exists():
                        written.append((f"export:{fmt}", p))
                continue
            if name == "hardly_write_session_copy":
                base["format"] = "index"
            calls = [base] + [{**base, **extra} for extra in EXTRA_CALLS.get(name, [])]
            if "sections" in sig.parameters:
                valid = _valid_choices(_call(fn, **{**base, "sections": ["__nope__"]}))
                calls += [{**base, "sections": valid}] if valid else []
                calls += [{**base, "sections": [s]} for s in valid]
            for kw in calls:
                outs.append(_call(fn, **kw))
            if name.startswith("hardly_write_"):
                written.extend((name.removeprefix("hardly_"), p) for p in tmp.glob(f"{tag}*"))
        outputs[name] = outs
    return outputs, written


def _read_files(paths: list[tuple[str, Path]]) -> dict[str, str]:
    out: dict[str, str] = {}
    for label, p in paths:
        files = [f for f in p.rglob("*") if f.is_file()] if p.is_dir() else [p]
        for f in files:
            out[f"{label}:{f.name}"] = f.read_bytes().decode("utf-8", errors="replace")
    return out


@pytest.fixture(scope="module")
def run(har_path, tmp_path_factory):
    """One full pass over every tool (module-scoped: it is the expensive part)."""
    tmp = tmp_path_factory.mktemp("canary-out")
    sid = sess.open_har(str(har_path), force=True)["session_id"]
    outputs, written = run_all_tools(sid, tmp, har_path)
    return outputs, _read_files(written), sid


def test_every_tool_output_is_free_of_canaries(run):
    outputs, _files, _sid = run
    assert len(outputs) > 45
    bad = {n: leaks("\n".join(o)) for n, o in outputs.items() if leaks("\n".join(o))}
    assert not bad, bad
    # the harness really exercised tools that return data
    joined = "\n".join("\n".join(o) for o in outputs.values())
    assert re.search(r"\bapp\.example\.com\b", joined) and "***REDACTED***" in joined


# Files that are meant to be shared (everything else a write tool makes is a raw copy by design).
SHAREABLE = ("write_har_scrubbed", "export:")


def test_shareable_artifacts_are_free_of_canaries(run):
    _outputs, files, _sid = run
    shareable = {k: v for k, v in files.items() if k.startswith(SHAREABLE)}
    assert any(k.startswith("export:openapi") for k in shareable)
    assert any(k.startswith("write_har_scrubbed") for k in shareable)
    assert {k.split(":")[1] for k in shareable if k.startswith("export:")} >= set(server._EXPORT_FORMATS)
    bad = {k: leaks(v) for k, v in shareable.items() if leaks(v)}
    assert not bad, bad


def test_placeholders_instead_of_values(run):
    _outputs, files, _sid = run
    by_fmt: dict[str, list[str]] = {}
    for k, v in files.items():
        if k.startswith("export:"):
            by_fmt.setdefault(k.split(":")[1], []).append(v)
    assert any("PLACEHOLDER_" in v for v in by_fmt["client_python"])
    assert any("{{" in v and "}}" in v for v in by_fmt["postman"])
    scrubbed = next(v for k, v in files.items() if k.startswith("write_har_scrubbed"))
    assert "***REDACTED***" in scrubbed
    doc = json.loads(scrubbed)
    for header in ("Authorization", "Cookie", "Set-Cookie", "X-Api-Key"):
        values = [
            h["value"]
            for e in doc["log"]["entries"]
            for side in ("request", "response")
            for h in e[side]["headers"]
            if h["name"] == header
        ]
        assert values and all("REDACTED" in v for v in values), header


def test_raw_copies_are_documented_as_raw(run):
    """pruned / merged / split are faithful copies: they keep secrets (SECURITY.md says so)."""
    _outputs, files, _sid = run
    raw = [v for k, v in files.items() if k.startswith(("write_har_pruned", "write_har_merged", "write_har_split"))]
    assert raw and any(leaks(v) for v in raw)


def test_saved_index_holds_nothing_that_was_redacted(run):
    """An index written to disk keeps no raw header value or markup value that is redacted on display."""
    _outputs, files, _sid = run
    index = {k: v for k, v in files.items() if k.startswith("write_session_copy")}
    assert index
    bad = {k: leaks(v) for k, v in index.items() if leaks(v)}
    assert not bad, bad


def test_saved_index_reopens_and_still_answers(sid, tmp_path):
    out = tmp_path / "idx.sqlite"
    res = json.loads(server.hardly_write_session_copy(session_id=sid, output_path=str(out), format="index"))
    assert res["saved_to"]
    again = sess.open_session(out)
    try:
        text = server.hardly_endpoint_list(session_id=again.session_id)
        assert "/api/login" in text and not leaks(text)
    finally:
        again.close()


# ------------------------------------------------------------------ values supplied as arguments


def test_argument_values_are_never_echoed(sid):
    hdr, body, env = (INPUT_CANARIES[k] for k in ("override_header", "override_body", "env_value"))
    outs = [
        server.hardly_send_entry(session_id=sid, entry_id=3, header_overrides={"Authorization": hdr}, body_override=body),
        server.hardly_send_entry_ablation(
            session_id=sid,
            entry_ids=[3],
            overrides={"headers": {"Authorization": hdr}, "body": {"x": body}, "cookies": {"s": env}},
        ),
        server.hardly_send_entry_series(session_id=sid, entry_id=3, env={"Authorization": env}),
        server.hardly_browser_run_steps(steps=[{"op": "fill", "css": "#p", "value": body}]),
        server.hardly_browser_interact(action="fill", css="#p", value=hdr),
        server.hardly_session_trace_value(session_id=sid, value=env),
        server.hardly_session_trace_value(session_id=sid, value=CANARIES["location_token"]),
    ]
    text = "\n".join(outs)
    assert not leaks(text), leaks(text)
    plan = json.loads(outs[0])
    assert plan["sent"] is False and plan["plan"]["header_overrides"] == ["Authorization"]


def test_error_messages_do_not_echo_secrets(sid, tmp_path):
    out = str(tmp_path / "a.yaml")
    outs = [
        server.hardly_entry_get(session_id=sid, entry_id=999),
        server.hardly_session_sql(session_id=sid, sql="select value_raw from headers where value_raw like '%cnry%'"),
        server.hardly_session_sql(session_id=sid, sql="select * from nope"),
        server.hardly_entry_body_query(session_id=sid, entry_id=0, jsonpath="$..["),
        server.hardly_write_export(session_id=sid, format="openapi", output_path=out),
        server.hardly_write_export(session_id=sid, format="openapi", output_path=out),  # exists
        server.hardly_session_open(har_path=str(tmp_path / "missing.har")),
        server.hardly_har_file_check(har_path=str(tmp_path / "missing.har")),
    ]
    assert not leaks("\n".join(outs))


# ------------------------------------------------------------------ the CLI prints the same data

CLI_COMMANDS = [
    ["session", "open", "{har}"], ["session", "overview", "{har}"], ["session", "story", "{har}"],
    ["session", "report", "{har}", "--detail", "full"], ["session", "site-brief", "{har}"],
    ["session", "sql", "{har}", "select * from headers"],
    ["session", "trace-value", "{har}", "--name", "csrf_token"],
    ["entry", "get", "{har}", "{i}"], ["entry", "build-curl", "{har}", "{i}"], ["entry", "outline", "{har}", "{i}"],
    ["entry", "body-query", "{har}", "{i}", "--regex", "cnry"], ["entry", "initiators", "{har}", "{i}"],
    ["entry", "search", "{har}", "--body-contains", "cnry"], ["entry", "dependencies", "{har}", "{i}"],
    ["endpoint", "list", "{har}"], ["endpoint", "schema", "{har}", "POST", "/api/v1/session"],
    ["page", "forms", "{har}"], ["page", "ui", "{har}"], ["auth", "report", "{har}", "--explain"],
    ["client", "build", "{har}"], ["tech", "stack", "{har}"], ["gate", "bot-protection", "{har}"],
    ["send", "entry", "{har}", "{i}"], ["send", "entry-ablation", "{har}", "{i}"],
    ["send", "entry-series", "{har}", "--entry-id", "{i}"],
    ["write", "export", "{har}", "--format", "client_python", "-o", "{out}/cli-client.py"],
    ["write", "export", "{har}", "--format", "postman", "-o", "{out}/cli-pm.json"],
    ["write", "har-scrubbed", "{har}", "-o", "{out}/cli-scrubbed.har"],
]


def test_cli_output_is_free_of_canaries(har_path, tmp_path, capsys):
    printed: list[str] = []
    for argv in CLI_COMMANDS:
        for i in range(N_ENTRIES) if any("{i}" in a for a in argv) else [0]:
            args = [a.format(har=har_path, i=i, out=tmp_path) for a in argv]
            try:
                cli.main(args)
            except SystemExit:
                pass
            except Exception as exc:  # noqa: BLE001
                printed.append(f"EXC {exc}")
            cap = capsys.readouterr()
            printed.append(cap.out + cap.err)
    text = "\n".join(printed)
    assert not leaks(text), leaks(text)
    for name in ("cli-client.py", "cli-pm.json", "cli-scrubbed.har"):
        data = (tmp_path / name).read_text(errors="replace")
        assert not leaks(data), (name, leaks(data))
