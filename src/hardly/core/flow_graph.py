"""Dependency graph of a request: which earlier response supplied each input.

For a target entry, every header, cookie, query/path value and body field that
was *issued by an earlier response* (Set-Cookie, hidden form field, JSON key,
Location segment, custom response header) is traced back to its producer by
matching values in memory. The closure of producers, sorted by capture order
(a valid topological order, because a producer always precedes its consumer),
is the minimal ordered set of steps needed to reproduce the target.

Inputs with no producer that look like secrets or credentials (passwords,
tokens, API keys, session cookies set before the capture began) are reported as
``user_inputs``: they must come from the user or environment at replay time.

Output carries names, shapes, lengths and entry ids only - never values. Raw
values are read from the original HAR (when still on disk) purely to match, and
are discarded; without the HAR the redacted index is used and fewer links can
be found (``source: "index"``).
"""

from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, unquote, unquote_plus, urlparse

import ijson

from hardly.core import correlate as _cor
from hardly.core.redact import (
    REDACTED,
    classify_value_shape,
    is_sensitive_header,
    is_sensitive_key,
)
from hardly.core.stub import _tokenish_value

_MAX_STEPS = 60
_SECRET_SHAPES = frozenset({"jwt", "bearer_jwt", "bearer_token", "basic_auth"})
_CRED_NAME = re.compile(
    r"(pass(word|wd)?|pwd|passcode|user(name)?|login|email|account|otp|pin)$", re.I
)
_APIKEY_NAME = re.compile(r"(api[-_]?key|apikey|x-api|access[-_]?key|client[-_]?secret)", re.I)
_RESP_HEADER_PRODUCER = re.compile(r"^x-", re.I)


def env_key(name: str) -> str:
    """Environment variable that supplies the user input called ``name``."""
    slug = re.sub(r"[^A-Za-z0-9]+", "_", name).strip("_").upper() or "INPUT"
    return "HARDLY_INPUT_" + slug


# --------------------------------------------------------------------------
# Loading: HAR (preferred, has raw values) or the redacted index
# --------------------------------------------------------------------------


def _walk_scalars(obj: Any, key: str | None, out: list, depth: int = 0) -> None:
    if depth > 6 or len(out) > 120:
        return
    if isinstance(obj, dict):
        for k, v in list(obj.items())[:60]:
            _walk_scalars(v, str(k), out, depth + 1)
    elif isinstance(obj, list):
        for item in obj[:20]:
            _walk_scalars(item, key, out, depth + 1)
    elif isinstance(obj, (str, int, float)) and not isinstance(obj, bool) and key:
        out.append((key, str(obj)))


def _body_inputs(post: dict) -> list[tuple[str, str, str]]:
    text = (post or {}).get("text") or ""
    found: list[tuple[str, str, str]] = []
    if text.lstrip().startswith(("{", "[")):
        try:
            data = json.loads(text)
            while isinstance(data, str) and data.lstrip()[:1] in ("{", "["):
                data = json.loads(data)
        except (ValueError, TypeError):
            data = None
        pairs: list[tuple[str, str]] = []
        _walk_scalars(data, None, pairs)
        found += [("request.json", k, v) for k, v in pairs]
    elif text:
        found += [("request.form", k, v) for k, v in parse_qsl(text, keep_blank_values=True) if k]
    if not text:
        for p in (post or {}).get("params") or []:
            if p.get("name"):
                found.append(("request.form", str(p["name"]), str(p.get("value") or "")))
    return found


def _node(entry_id: int, req: dict, resp: dict, *, cookie_names: list[str] | None = None) -> dict:
    """Normalise one HAR-shaped entry into producers and consumers."""
    url = req.get("url") or ""
    parsed = urlparse(url)
    method = (req.get("method") or "GET").upper()
    consume: list[dict] = []

    for k, v in parse_qsl(parsed.query, keep_blank_values=True):
        consume.append({"where": "query", "name": k, "value": v})
    for i, seg in enumerate(parsed.path.strip("/").split("/")):
        if _cor._keep_value(seg) and any(ch.isdigit() for ch in seg):
            consume.append({"where": "path", "name": None, "value": unquote(seg), "index": i})
    for h in req.get("headers") or []:
        name = str(h.get("name") or "")
        low = name.lower()
        value = str(h.get("value") or "")
        if low.startswith(":"):
            continue
        if low == "cookie":
            for part in value.split(";"):
                if "=" in part:
                    cn, cv = part.split("=", 1)
                    if cn.strip():
                        consume.append({"where": "cookie", "name": cn.strip(), "value": cv.strip()})
        elif low == "authorization":
            token = value.split(None, 1)[-1] if " " in value else value
            consume.append({"where": "header", "name": name, "value": token, "auth": True})
        elif not _cor._PLUMBING_HEADER.match(low):
            consume.append({"where": "header", "name": name, "value": value})
    for where, k, v in _body_inputs(req.get("postData") or {}):
        consume.append({"where": where, "name": k, "value": v})
    for n in cookie_names or []:
        if not any(c["where"] == "cookie" and c["name"] == n for c in consume):
            consume.append({"where": "cookie", "name": n, "value": ""})

    produce: list[dict] = []
    for where, value, name in _cor._extract_produce(resp):
        if where == "location":
            continue
        produce.append({"where": where, "name": name, "value": value})
    for h in resp.get("headers") or []:
        low = str(h.get("name") or "").lower()
        value = str(h.get("value") or "")
        if low == "location" and value:
            for i, part in enumerate(urlparse(value).path.strip("/").split("/")):
                if _cor._keep_value(part) and not part.isalpha():
                    produce.append({"where": "location", "name": None, "value": part, "index": i})
        elif _RESP_HEADER_PRODUCER.match(low) and _cor._keep_value(value):
            produce.append({"where": "response.header", "name": str(h.get("name")), "value": value})

    content = resp.get("content") or {}
    return {
        "entry_id": entry_id,
        "method": method,
        "host": parsed.netloc.lower(),
        "path": parsed.path or "/",
        "status": resp.get("status"),
        "mime": (content.get("mimeType") or "").split(";")[0].strip().lower() or None,
        "consume": consume,
        "produce": produce,
    }


def _nodes_from_har(path: Path, upto: int) -> dict[int, dict]:
    nodes: dict[int, dict] = {}
    with path.open("rb") as f:
        for i, entry in enumerate(ijson.items(f, "log.entries.item")):
            if i > upto:
                break
            req = entry.get("request") or {}
            if (req.get("method") or "").upper() == "OPTIONS":
                continue
            nodes[i] = _node(i, req, entry.get("response") or {})
    return nodes


def _nodes_from_index(conn: sqlite3.Connection, upto: int) -> dict[int, dict]:
    from hardly.core.replay_check import _captured_cookie_names

    nodes: dict[int, dict] = {}
    rows = conn.execute(
        "SELECT * FROM entries WHERE entry_id <= ? AND method != 'OPTIONS' ORDER BY entry_id",
        (upto,),
    ).fetchall()
    for row in rows:
        eid = row["entry_id"]

        def hdrs(side: str) -> list[dict]:
            out = []
            for h in conn.execute(
                "SELECT name, value_raw, value_redacted FROM headers WHERE entry_id = ? AND side = ?",
                (eid, side),
            ):
                val = h["value_raw"] if h["value_raw"] is not None else h["value_redacted"]
                out.append({"name": h["name"], "value": val or ""})
            return out

        def body(side: str) -> tuple[str, str]:
            b = conn.execute(
                "SELECT preview_text, content_type FROM bodies WHERE entry_id = ? AND side = ?",
                (eid, side),
            ).fetchone()
            return ((b["preview_text"] or ""), (b["content_type"] or "")) if b else ("", "")

        q = row["query_raw"] or ""
        url = f"{row['scheme']}://{row['host']}{row['path']}" + (f"?{q}" if q else "")
        rq_text, rq_ct = body("request")
        rs_text, rs_ct = body("response")
        req = {
            "method": row["method"],
            "url": url,
            "headers": [h for h in hdrs("request") if h["value"] != REDACTED or h["name"].lower() != "cookie"],
            "postData": {"text": rq_text, "mimeType": rq_ct},
        }
        resp = {
            "status": row["status"],
            "headers": [h for h in hdrs("response") if h["value"] != REDACTED],
            "content": {"text": rs_text, "mimeType": rs_ct or row["mime"] or ""},
        }
        nodes[eid] = _node(eid, req, resp, cookie_names=_captured_cookie_names(conn, eid))
    return nodes


# --------------------------------------------------------------------------
# Matching
# --------------------------------------------------------------------------


def _variants(value: str) -> list[str]:
    out = [value]
    for f in (unquote, unquote_plus):
        v = f(value)
        if v not in out:
            out.append(v)
    return out


def _classify_secret(c: dict) -> str | None:
    """Kind of user-supplied input an unmatched consumer represents, else None."""
    name, where, value = c.get("name") or "", c["where"], c["value"]
    shape = classify_value_shape(value)
    if where == "cookie":
        if is_sensitive_key(name) or shape or (value and (len(value) >= 16 or _tokenish_value(value))) or value == "":
            return "cookie"
        return None
    if where == "header":
        if c.get("auth"):
            return "token"
        if _APIKEY_NAME.search(name):
            return "api_key"
        if is_sensitive_header(name) or is_sensitive_key(name) or shape in _SECRET_SHAPES:
            return "token"
        return "opaque" if _tokenish_value(value) else None
    if where == "path":
        return None
    if where in ("query", "request.form", "request.json"):
        if is_sensitive_key(name):
            return "credential" if _CRED_NAME.search(name.split("$")[-1]) else "secret"
        if value == REDACTED or shape in _SECRET_SHAPES:
            return "secret"
        if _tokenish_value(value):
            return "opaque"
        if _CRED_NAME.search(name.split("$")[-1]) and re.search(r"pass|pwd", name, re.I):
            return "credential"
    return None


def flow_graph(
    conn: sqlite3.Connection,
    entry_id: int,
    host: str | None = None,
    max_depth: int = 8,
) -> dict[str, Any]:
    """Trace the minimal ordered steps that must precede ``entry_id``.

    ``host`` restricts producer steps to that host (default: any host).
    ``max_depth`` bounds how many producer hops are followed backwards.
    """
    row = conn.execute("SELECT * FROM entries WHERE entry_id = ?", (int(entry_id),)).fetchone()
    if not row:
        return {"error": f"entry_id {entry_id} not found"}
    entry_id = int(entry_id)
    har = _cor._har_path_from_meta(conn)
    source = "har"
    nodes: dict[int, dict] = {}
    if har:
        try:
            nodes = _nodes_from_har(har, entry_id)
        except Exception:  # noqa: BLE001 - unreadable HAR: fall back to the index
            nodes = {}
    if entry_id not in nodes:
        source = "index"
        nodes = _nodes_from_index(conn, entry_id)
    if entry_id not in nodes:
        return {"error": f"entry_id {entry_id} has no usable request"}

    host_l = host.lower() if host else None

    # value -> producers in capture order (matching is by value; never emitted)
    index: dict[str, list[tuple[int, dict]]] = {}
    for eid in sorted(nodes):
        for p in nodes[eid]["produce"]:
            if host_l and nodes[eid]["host"] != host_l:
                continue
            index.setdefault(p["value"], []).append((eid, p))

    cache: dict[int, tuple[list[dict], list[dict]]] = {}

    def resolve(eid: int) -> tuple[list[dict], list[dict]]:
        """(edges, unsourced) for one entry's inputs."""
        if eid in cache:
            return cache[eid]
        edges: list[dict] = []
        unsourced: list[dict] = []
        seen: set[tuple] = set()
        for c in nodes[eid]["consume"]:
            value = c["value"]
            match = None
            if value and value != REDACTED and _cor._keep_value(value):
                cands: list[tuple[int, dict]] = []
                for v in _variants(value):
                    cands += [(e, p) for e, p in index.get(v, []) if e < eid]
                if cands:
                    named = [x for x in cands if x[1].get("name") == c.get("name")]
                    match = max(named or cands, key=lambda x: x[0])
            if match:
                pe, p = match
                key = (c["where"], c.get("name"), c.get("index"))
                if key in seen:
                    continue
                seen.add(key)
                edge = {
                    "to_entry_id": eid,
                    "to_where": c["where"],
                    "to_name": c.get("name"),
                    "from_entry_id": pe,
                    "from_where": p["where"],
                    "from_name": p.get("name"),
                    "value_kind": _cor._value_kind(value),
                    "value_length": len(value),
                    "via": "cookie_jar" if c["where"] == "cookie" and p["where"] == "set-cookie" else "extract",
                }
                if "index" in c:
                    edge["to_index"] = c["index"]
                if "index" in p:
                    edge["from_index"] = p["index"]
                if c.get("auth"):
                    edge["auth"] = True
                edges.append(edge)
            else:
                kind = _classify_secret(c)
                if kind:
                    unsourced.append(
                        {
                            "where": c["where"],
                            "name": c.get("name"),
                            "kind": kind,
                            "shape": classify_value_shape(value) if value != REDACTED else None,
                            "auth": bool(c.get("auth")),
                        }
                    )
        cache[eid] = (edges, unsourced)
        return cache[eid]

    # Backward closure from the target, bounded by max_depth.
    depth_of: dict[int, int] = {entry_id: 0}
    frontier = [entry_id]
    truncated = False
    while frontier:
        nxt: list[int] = []
        for eid in frontier:
            for e in resolve(eid)[0]:
                src = e["from_entry_id"]
                if src in depth_of:
                    continue
                if depth_of[eid] + 1 > max_depth or len(depth_of) >= _MAX_STEPS:
                    truncated = True
                    continue
                depth_of[src] = depth_of[eid] + 1
                nxt.append(src)
        frontier = nxt

    order = sorted(depth_of)
    steps: list[dict] = []
    user_inputs: list[dict] = []
    all_edges: list[dict] = []
    seen_inputs: set[tuple] = set()
    for n, eid in enumerate(order, 1):
        node = nodes[eid]
        edges, unsourced = resolve(eid)
        edges = [e for e in edges if e["from_entry_id"] in depth_of]
        all_edges += edges
        ins = []
        for u in unsourced:
            nm = u["name"] or u["where"]
            item = {
                "name": nm,
                "where": u["where"],
                "kind": u["kind"],
                "shape": u["shape"],
                "step_entry_id": eid,
                "env_key": nm,
                "env_var": env_key(nm),
            }
            if u["auth"]:
                item["auth"] = True
            ins.append(item)
            k = (eid, u["where"], nm)
            if k not in seen_inputs:
                seen_inputs.add(k)
                user_inputs.append(item)
        steps.append(
            {
                "order": n,
                "entry_id": eid,
                "role": "target" if eid == entry_id else "dependency",
                "method": node["method"],
                "host": node["host"],
                "path": node["path"],
                "status": node["status"],
                "safe": node["method"] in ("GET", "HEAD"),
                "depends_on": sorted({e["from_entry_id"] for e in edges}),
                "wired": [
                    {k: v for k, v in e.items() if k != "to_entry_id"} for e in edges
                ],
                "user_inputs": [i["name"] for i in ins],
            }
        )

    return {
        "target": {
            "entry_id": entry_id,
            "method": row["method"],
            "host": row["host"],
            "path": row["path"],
        },
        "source": source,
        "step_count": len(steps),
        "steps": steps,
        "edges": all_edges,
        "user_inputs": user_inputs,
        "unsafe_steps": [s["entry_id"] for s in steps if not s["safe"]],
        "truncated": truncated,
        "note": (
            "Steps are topologically sorted (capture order). Values are never "
            "returned; supply user_inputs via env (key = env_key, or env var "
            "env_var). "
            + ("" if source == "har" else "HAR no longer on disk: matched against the redacted index only, links may be missing.")
        ).strip(),
    }
