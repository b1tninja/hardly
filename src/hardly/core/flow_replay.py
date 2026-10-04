"""Live, confirm-gated replay of the ordered steps a request depends on.

``replay_flow`` takes the minimal step list from :func:`flow_graph` (or an
explicit ``entry_ids`` list), executes it in order with a cookie jar, wires
values issued by earlier live responses into later requests (hidden fields,
Set-Cookie, JSON keys, Location segments, custom headers), fills secret inputs
only from an ``env`` mapping or ``HARDLY_INPUT_*`` environment variables, and
compares each live response with the captured one (status, content type,
body shape). It reports which step first diverged.

Safety (see docs/gate-policy.md): nothing is sent unless ``confirm=True``;
GET/HEAD only unless ``allow_unsafe``; requests are spaced by ``delay_s`` and
capped by ``max_requests``; redirects are never followed; the run halts at
HTTP 429, any Retry-After, or a gate classified as a stop sign. Output has
step numbers, entry ids, paths, statuses, content types and field *names* -
never values, bodies, cookies or headers.
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
from html.parser import HTMLParser
from typing import Any
from urllib.parse import parse_qsl, unquote, urlencode, urlsplit

import httpx

from hardly.core.ajax_delta import delta_hidden
from hardly.core.flow_graph import env_key, flow_graph
from hardly.core.netguard import check_url, new_client
from hardly.core.redact import REDACTED
from hardly.core.replay_check import _PLUMBING_HEADERS, _gate_stop, _unresolved

SAFE_METHODS = frozenset({"GET", "HEAD"})


# --------------------------------------------------------------------------
# Extraction from live responses
# --------------------------------------------------------------------------


class _Hidden(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.fields: dict[str, str] = {}

    def handle_starttag(self, tag, attrs):
        if tag != "input":
            return
        a = {k.lower(): (v or "") for k, v in attrs}
        if a.get("type", "").lower() == "hidden":
            n = a.get("name") or a.get("id")
            if n:
                self.fields[n] = a.get("value", "")


def hidden_fields(html: str) -> dict[str, str]:
    p = _Hidden()
    try:
        p.feed(html)
    except Exception:  # noqa: BLE001
        pass
    return p.fields


def _deep_find(obj: Any, key: str, depth: int = 0) -> Any:
    if depth > 8:
        return None
    if isinstance(obj, str) and obj.lstrip()[:1] in ("{", "["):
        try:
            obj = json.loads(obj)
        except ValueError:
            return None
    if isinstance(obj, dict):
        if key in obj and isinstance(obj[key], (str, int)):
            return obj[key]
        kids = list(obj.values())
    elif isinstance(obj, list):
        kids = obj
    else:
        return None
    for k in kids:
        found = _deep_find(k, key, depth + 1)
        if found is not None:
            return found
    return None


def _extract(edge: dict, live: dict, client: httpx.Client) -> str | None:
    where, name = edge["from_where"], edge.get("from_name")
    text: str = live["text"]
    if where == "set-cookie":
        for c in client.cookies.jar:
            if c.name == name and c.value is not None:
                v = c.value.strip('"')
                return unquote(v) if edge["to_where"] == "header" else v
        return None
    if where == "html.hidden":
        fields = {**hidden_fields(text), **delta_hidden(text)}
        return fields.get(name) if name else None
    if where == "response.json":
        try:
            found = _deep_find(json.loads(text), name or "")
        except ValueError:
            return None
        return None if found is None else str(found)
    if where == "response.form":
        for k, v in parse_qsl(text, keep_blank_values=True):
            if k == name:
                return v
        return None
    if where == "location":
        loc = live["headers"].get("location")
        parts = urlsplit(loc).path.strip("/").split("/") if loc else []
        i = edge.get("from_index")
        return parts[i] if i is not None and 0 <= i < len(parts) else None
    if where == "response.header":
        return live["headers"].get(name or "")
    return None


# --------------------------------------------------------------------------
# Planning
# --------------------------------------------------------------------------


def _set_deep(obj: Any, key: str, value: str) -> bool:
    hit = False
    if isinstance(obj, dict):
        for k in list(obj):
            if k == key and not isinstance(obj[k], (dict, list)):
                obj[k] = value
                hit = True
            else:
                hit = _set_deep(obj[k], key, value) or hit
    elif isinstance(obj, list):
        for item in obj:
            hit = _set_deep(item, key, value) or hit
    return hit


def _auth_scheme(conn: sqlite3.Connection, entry_id: int) -> str:
    row = conn.execute(
        "SELECT shape FROM value_shapes WHERE entry_id = ? AND lower(name) = 'authorization' LIMIT 1",
        (entry_id,),
    ).fetchone()
    shape = row["shape"] if row else None
    return {"bearer_jwt": "Bearer ", "bearer_token": "Bearer ", "basic_auth": "Basic "}.get(shape or "", "")


def _lookup_env(env: dict[str, str], item: dict) -> str | None:
    for key in (f"{item['step_entry_id']}.{item['name']}", item["name"], item["env_var"]):
        if key in env and env[key] not in (None, ""):
            return str(env[key])
    v = os.environ.get(item["env_var"])
    return v if v else None


def _plan_step(conn, step: dict, inputs: list[dict], env: dict[str, str], missing: list[dict]) -> dict:
    """Request template for one step; values are resolved at send time."""
    eid = step["entry_id"]
    row = conn.execute("SELECT * FROM entries WHERE entry_id = ?", (eid,)).fetchone()
    wires = step.get("wired") or []

    def wire(where: str, name: str | None, index: int | None = None):
        for e in wires:
            if e["to_where"] == where and (
                (name is not None and (e.get("to_name") or "").lower() == name.lower())
                or (name is None and e.get("to_index") == index)
            ):
                return e
        return None

    def env_for(where: str, name: str):
        for it in inputs:
            if it["where"] == where and it["name"].lower() == name.lower():
                val = _lookup_env(env, it)
                if val is None:
                    if not any(m["step_entry_id"] == eid and m["name"] == it["name"] for m in missing):
                        missing.append({k: it[k] for k in ("name", "where", "kind", "step_entry_id", "env_key", "env_var")})
                return ("env", val, it)
        return None

    def spec(where: str, name: str, literal: str):
        w = wire(where, name)
        if w:
            return ("wire", w)
        e = env_for(where, name)
        if e:
            return e
        if literal == REDACTED or REDACTED in literal:
            it = {"name": name, "where": where, "kind": "secret", "step_entry_id": eid,
                  "env_key": name, "env_var": env_key(name)}
            val = _lookup_env(env, it)
            if val is None and not any(m["step_entry_id"] == eid and m["name"] == name for m in missing):
                missing.append(it)
            return ("env", val, it)
        return ("lit", literal)

    headers: dict[str, Any] = {}
    for h in conn.execute(
        "SELECT name, value_raw FROM headers WHERE entry_id = ? AND side = 'request' ORDER BY id", (eid,)
    ):
        name, low = h["name"], h["name"].lower()
        if low in _PLUMBING_HEADERS or low.startswith(":"):
            continue
        w = wire("header", name)
        if w:
            headers[name] = ("wire", w)
            continue
        e = env_for("header", name)
        if e:
            headers[name] = e
        elif h["value_raw"] is None:
            it = {"name": name, "where": "header", "kind": "token", "step_entry_id": eid,
                  "env_key": name, "env_var": env_key(name)}
            val = _lookup_env(env, it)
            if val is None and not any(m["step_entry_id"] == eid and m["name"] == name for m in missing):
                missing.append(it)
            headers[name] = ("env", val, it)
        else:
            headers[name] = ("lit", h["value_raw"])

    query = [(k, spec("query", k, v)) for k, v in parse_qsl(row["query_raw"] or "", keep_blank_values=True)]

    path_parts = row["path"].split("/")
    segs: list[Any] = []
    real = 0
    for p in path_parts:
        if p == "":
            segs.append(("lit", p))
            continue
        w = wire("path", None, real)
        segs.append(("wire", w) if w else ("lit", p))
        real += 1

    cookies = []
    for it in inputs:
        if it["where"] == "cookie":
            val = _lookup_env(env, it)
            if val is None:
                if not any(m["step_entry_id"] == eid and m["name"] == it["name"] for m in missing):
                    missing.append({k: it[k] for k in ("name", "where", "kind", "step_entry_id", "env_key", "env_var")})
            else:
                cookies.append((it["name"], val))
    cookie_wires = [e for e in wires if e["to_where"] == "cookie" and e.get("via") != "cookie_jar"]

    body_row = conn.execute(
        "SELECT preview_text, content_type, size FROM bodies WHERE entry_id = ? AND side = 'request'", (eid,)
    ).fetchone()
    body: dict[str, Any] = {"kind": "none"}
    text = body_row["preview_text"] if body_row else None
    if text and row["method"] not in SAFE_METHODS:
        ct = ((body_row["content_type"] or "") + " " + str(headers.get("Content-Type", ("lit", ""))[1] or "")).lower()
        parsed = None
        if "json" in ct or text.lstrip().startswith(("{", "[")):
            try:
                parsed = json.loads(text)
            except ValueError:
                parsed = None
        if parsed is not None and isinstance(parsed, (dict, list)):
            fields = []
            names: set[str] = set()

            def collect(o: Any) -> None:
                if isinstance(o, dict):
                    for k, v in o.items():
                        if isinstance(v, (dict, list)):
                            collect(v)
                        else:
                            names.add(str(k))
                elif isinstance(o, list):
                    for v in o:
                        collect(v)

            collect(parsed)
            for nm in sorted(names):
                w, e = wire("request.json", nm), None
                if w:
                    fields.append((nm, ("wire", w)))
                else:
                    e = env_for("request.json", nm)
                    if e:
                        fields.append((nm, e))
            leftover = json.loads(text)
            # unresolved redaction markers that nothing supplies
            stripped = json.loads(text)
            for nm, _ in fields:
                _set_deep(stripped, nm, "x")
            if _unresolved(stripped):
                if not any(m["step_entry_id"] == eid and m["name"] == "(raw body)" for m in missing):
                    missing.append({"name": "(raw body)", "where": "request.json", "kind": "secret",
                                    "step_entry_id": eid, "env_key": "(raw body)", "env_var": env_key("raw_body")})
            body = {"kind": "json", "template": leftover, "fields": fields}
        elif "=" in text and "\n" not in text.strip() and "multipart" not in ct:
            pairs = [(k, spec("request.form", k, v)) for k, v in parse_qsl(text, keep_blank_values=True)]
            body = {"kind": "form", "pairs": pairs}
        else:
            if REDACTED in text:
                if not any(m["step_entry_id"] == eid and m["name"] == "(raw body)" for m in missing):
                    missing.append({"name": "(raw body)", "where": "body", "kind": "secret",
                                    "step_entry_id": eid, "env_key": "(raw body)", "env_var": env_key("raw_body")})
            else:
                body = {"kind": "raw", "text": text}

    return {
        "entry_id": eid, "order": step["order"], "method": row["method"], "scheme": row["scheme"],
        "host": row["host"], "path": row["path"], "segs": segs, "headers": headers, "query": query,
        "cookies": cookies, "cookie_wires": cookie_wires, "body": body,
        "auth_scheme": _auth_scheme(conn, eid),
    }


# --------------------------------------------------------------------------
# Comparison with the captured response
# --------------------------------------------------------------------------


def _essence(ct: str | None) -> str:
    return (ct or "").split(";")[0].strip().lower()


def _shape(text: str, ct: str) -> dict[str, Any]:
    ct = _essence(ct)
    t = (text or "").lstrip()
    if "json" in ct or t[:1] in ("{", "["):
        try:
            data = json.loads(text)
            while isinstance(data, str) and data.lstrip()[:1] in ("{", "["):
                data = json.loads(data)
        except ValueError:
            return {"kind": "json", "keys": None}
        if isinstance(data, dict):
            return {"kind": "json", "keys": sorted(str(k) for k in data)}
        return {"kind": "json", "keys": ["[list]"]}
    if "html" in ct or t[:1] == "<":
        return {"kind": "html", "has_form": "<form" in t.lower(),
                "hidden": sorted({*hidden_fields(text), *delta_hidden(text)})}
    return {"kind": "empty" if not t else "text"}


def _compare(conn, eid: int, live: dict) -> dict[str, Any]:
    row = conn.execute("SELECT status, mime FROM entries WHERE entry_id = ?", (eid,)).fetchone()
    b = conn.execute(
        "SELECT preview_text, content_type FROM bodies WHERE entry_id = ? AND side = 'response'", (eid,)
    ).fetchone()
    cap_ct = _essence((b["content_type"] if b else None) or row["mime"])
    live_ct = _essence(live["headers"].get("content-type"))
    cap = _shape((b["preview_text"] if b else "") or "", cap_ct)
    cur = _shape(live["text"], live_ct)
    status_ok = row["status"] is None or int(row["status"]) == live["status"]
    ct_ok = not cap_ct or cap_ct == live_ct
    missing: list[str] = []
    extra: list[str] = []
    shape_ok = cap["kind"] == cur["kind"] or (cap["kind"] in ("empty", "text") and cur["kind"] in ("empty", "text"))
    if shape_ok and cap["kind"] == "json" and cap.get("keys") is not None and cur.get("keys") is not None:
        missing = sorted(set(cap["keys"]) - set(cur["keys"]))
        extra = sorted(set(cur["keys"]) - set(cap["keys"]))
        shape_ok = not missing
    elif shape_ok and cap["kind"] == "html":
        missing = sorted(set(cap["hidden"]) - set(cur["hidden"]))
        shape_ok = not missing and (not cap["has_form"] or cur["has_form"])
    return {
        "status": {"captured": row["status"], "live": live["status"], "match": status_ok},
        "content_type": {"captured": cap_ct or None, "live": live_ct or None, "match": ct_ok},
        "body_shape": {
            "captured": cap["kind"], "live": cur["kind"], "match": shape_ok,
            "missing_names": missing, "extra_names": extra,
        },
        "match": status_ok and ct_ok and shape_ok,
    }


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------


def replay_flow(
    conn: sqlite3.Connection,
    entry_ids: list[int] | None = None,
    target: int | None = None,
    env: dict[str, str] | None = None,
    confirm: bool = False,
    *,
    delay_s: float = 0.5,
    max_requests: int = 20,
    allow_unsafe: bool = False,
    allow_gates: list[str] | None = None,
    hosts: list[str] | None = None,
    host: str | None = None,
    max_depth: int = 8,
    stop_on_divergence: bool = True,
    client: httpx.Client | None = None,
) -> dict[str, Any]:
    """Replay a flow live and report where it first diverges from the capture.

    Give ``target`` (steps come from ``flow_graph``) or an explicit ordered
    ``entry_ids`` list (the last one is the target). Without ``confirm=True``
    nothing is sent: the plan and any missing inputs are returned.
    """
    if entry_ids:
        ids = [int(i) for i in entry_ids]
        tid = ids[-1]
    elif target is not None:
        ids, tid = [], int(target)
    else:
        return {"error": "give entry_ids or target"}
    env = {str(k): str(v) for k, v in (env or {}).items() if v is not None}

    graph = flow_graph(conn, tid, host=host, max_depth=max_depth)
    if "error" in graph:
        return graph
    by_id = {s["entry_id"]: s for s in graph["steps"]}
    user_inputs = list(graph["user_inputs"])
    if ids:
        for eid in ids:
            if eid not in by_id:
                g = flow_graph(conn, eid, host=host, max_depth=0)
                if "error" in g:
                    return g
                by_id[eid] = next(s for s in g["steps"] if s["entry_id"] == eid)
                user_inputs += [i for i in g["user_inputs"] if i["step_entry_id"] == eid]
        order = ids
    else:
        order = [s["entry_id"] for s in graph["steps"]]
    chosen = set(order)
    steps = []
    for n, eid in enumerate(order, 1):
        s = dict(by_id[eid])
        m = conn.execute("SELECT method FROM entries WHERE entry_id = ?", (eid,)).fetchone()
        s["method"] = m["method"]
        s["safe"] = m["method"] in SAFE_METHODS
        s["order"] = n
        s["wired"] = [e for e in s.get("wired") or [] if e["from_entry_id"] in chosen]
        steps.append(s)

    if hosts is not None:
        allowed = {h.lower() for h in hosts}
        bad = [s["entry_id"] for s in steps if s["host"].lower() not in allowed]
        if bad:
            return {"error": "steps outside allowed hosts", "entry_ids": bad, "requests_used": 0}
    if not allow_unsafe:
        unsafe = [{"entry_id": s["entry_id"], "method": s["method"]} for s in steps if not s["safe"]]
        if unsafe:
            return {"error": "replay_flow refuses non-idempotent methods without allow_unsafe=true",
                    "refused": unsafe, "requests_used": 0}
    if len(steps) > max_requests:
        return {"error": "max_requests too small for this flow", "steps_needed": len(steps), "requests_used": 0}

    missing: list[dict] = []
    plans = []
    for s in steps:
        ins = [i for i in user_inputs if i["step_entry_id"] == s["entry_id"]]
        plans.append(_plan_step(conn, s, ins, env, missing))

    for p in plans:
        check_url(f"{p['scheme']}://{p['host']}/")
    summary = [
        {"order": s["order"], "entry_id": s["entry_id"], "method": s["method"], "host": s["host"],
         "path": s["path"], "depends_on": s["depends_on"]}
        for s in steps
    ]
    base = {"target": {"entry_id": tid}, "source": graph["source"], "steps": summary}
    if not confirm:
        return {**base, "confirmed": False, "sent": False, "requests_planned": len(steps),
                "missing_inputs": missing,
                "note": "Dry run: nothing was sent. Re-run with confirm=true to execute live."}
    if missing:
        return {**base, "confirmed": True, "sent": False, "error": "missing inputs",
                "missing_inputs": missing, "requests_used": 0,
                "note": "Supply these via env (env_key) or the env_var environment variable."}

    gate_ok = frozenset(str(g) for g in (allow_gates or []))
    own = client is None
    cl = client or new_client(timeout=20.0, follow_redirects=False)
    live_by_id: dict[int, dict] = {}
    results: list[dict] = []
    halted: dict | None = None
    first_div: dict | None = None
    used = 0
    try:
        for p in plans:
            eid = p["entry_id"]
            if used and delay_s > 0:
                time.sleep(delay_s)
            dom = p["host"].split(":")[0]
            for cn, cv in p["cookies"]:
                cl.cookies.set(cn, cv, domain=dom)

            def val(sp: tuple) -> str | None:
                if sp[0] == "lit":
                    return sp[1]
                if sp[0] == "env":
                    return sp[1]
                e = sp[1]
                live = live_by_id.get(e["from_entry_id"])
                return _extract(e, live, cl) if live else None

            unwired: list[str] = []

            def need(sp: tuple, label: str) -> str:
                v = val(sp)
                if v is None:
                    unwired.append(label)
                    return ""
                return v

            segs = [need(sp, "path") if sp[0] != "lit" else sp[1] for sp in p["segs"]]
            hdrs: dict[str, str] = {}
            for name, sp in p["headers"].items():
                v = need(sp, name)
                if name.lower() == "authorization" and sp[0] == "env" and " " not in v:
                    v = p["auth_scheme"] + v
                elif name.lower() == "authorization" and sp[0] == "wire":
                    v = p["auth_scheme"] + v
                hdrs[name] = v
            for e in p["cookie_wires"]:
                live = live_by_id.get(e["from_entry_id"])
                v = _extract(e, live, cl) if live else None
                if v is None:
                    unwired.append(e.get("to_name") or "cookie")
                else:
                    cl.cookies.set(e["to_name"], v, domain=dom)
            query = [(k, need(sp, k)) for k, sp in p["query"]]
            content: bytes | None = None
            b = p["body"]
            if b["kind"] == "form":
                content = urlencode([(k, need(sp, k)) for k, sp in b["pairs"]]).encode()
            elif b["kind"] == "json":
                tpl = json.loads(json.dumps(b["template"]))
                for nm, sp in b["fields"]:
                    _set_deep(tpl, nm, need(sp, nm))
                content = json.dumps(tpl).encode()
            elif b["kind"] == "raw":
                content = b["text"].encode()
            if unwired:
                halted = {"reason": "unwired_input", "at_entry_id": eid, "names": sorted(set(unwired))}
                results.append({"order": p["order"], "entry_id": eid, "sent": False, "match": False})
                if first_div is None:
                    first_div = {"order": p["order"], "entry_id": eid, "fields": ["unwired_input"]}
                break

            url = f"{p['scheme']}://{p['host']}" + "/".join(segs)
            if query:
                url += "?" + urlencode(query)
            used += 1
            try:
                resp = cl.send(cl.build_request(p["method"], url, headers=hdrs, content=content),
                               follow_redirects=False)
            except httpx.HTTPError as exc:
                halted = {"reason": f"transport_error:{type(exc).__name__}", "at_entry_id": eid}
                results.append({"order": p["order"], "entry_id": eid, "sent": True, "match": False})
                break
            live = {"status": resp.status_code, "headers": resp.headers, "text": resp.text}
            live_by_id[eid] = live
            cmp = _compare(conn, eid, live)
            res = {"order": p["order"], "entry_id": eid, "method": p["method"], "path": p["path"],
                   "sent": True, **cmp}
            results.append(res)
            stop = _gate_stop(resp, gate_ok)
            if stop:
                halted = {"reason": stop, "at_entry_id": eid}
                if stop.startswith("gate:"):
                    halted["gate_class"] = stop.split(":", 1)[1]
            if not cmp["match"] and first_div is None:
                bad = [k for k in ("status", "content_type", "body_shape") if not cmp[k]["match"]]
                first_div = {"order": p["order"], "entry_id": eid, "fields": bad}
            if halted:
                break
            if first_div and stop_on_divergence:
                break
    finally:
        if own:
            cl.close()

    return {
        **base,
        "confirmed": True,
        "sent": True,
        "requests_used": used,
        "results": results,
        "first_divergence": first_div,
        "halted": halted,
        "all_match": bool(results) and first_div is None and halted is None and len(results) == len(plans),
    }
