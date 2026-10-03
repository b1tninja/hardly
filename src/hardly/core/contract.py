"""Contract drift: compare a fresh capture with a previously exported OpenAPI file.

Names, types and shapes only; no body or credential values are read or reported.
Note: "removed" means *not observed in this capture*, so coverage gaps look like removals.
"""

from __future__ import annotations

import json
import sqlite3
import tempfile
from pathlib import Path
from typing import Any

_METHODS = {"get", "put", "post", "delete", "patch", "head", "trace"}


def _load_spec(spec: Any) -> dict:
    if isinstance(spec, dict):
        if "paths" in spec:
            return spec
        if "path_template" in spec and "method" in spec:  # one endpoint_schema() result
            return _from_endpoint_schema(spec)
        raise ValueError("schema doc has neither 'paths' nor endpoint_schema fields")
    if isinstance(spec, list):
        merged: dict = {"openapi": "3.0.3", "paths": {}}
        for item in spec:
            for p, ops in _from_endpoint_schema(item)["paths"].items():
                merged["paths"].setdefault(p, {}).update(ops)
        return merged
    text = Path(spec).read_text(encoding="utf-8")
    try:
        return _load_spec(json.loads(text))
    except json.JSONDecodeError:
        try:
            import yaml  # optional
        except ImportError as exc:  # pragma: no cover
            raise ValueError("YAML spec needs PyYAML; export as JSON or install pyyaml") from exc
        return _load_spec(yaml.safe_load(text))


def _from_endpoint_schema(es: dict) -> dict:
    from hardly.core.export_openapi import _schema_to_openapi

    op: dict[str, Any] = {"responses": {"200": {"description": "HTTP 200"}}}
    if es.get("response_schema"):
        op["responses"]["200"]["content"] = {
            "application/json": {"schema": _schema_to_openapi(es["response_schema"])}
        }
    if es.get("request_schema"):
        op["requestBody"] = {
            "content": {"application/json": {"schema": _schema_to_openapi(es["request_schema"])}}
        }
    return {
        "openapi": "3.0.3",
        "servers": [{"url": f"https://{es.get('host', '')}"}],
        "paths": {es["path_template"]: {es["method"].lower(): op}},
    }


def _open_capture(conn_or_har: Any) -> tuple[sqlite3.Connection, Any]:
    if isinstance(conn_or_har, sqlite3.Connection):
        return conn_or_har, None
    from hardly.index.ingest import ingest_har
    from hardly.index.schema import connect

    tmp = tempfile.TemporaryDirectory(prefix="hardly-contract-")
    db = Path(tmp.name) / "c.db"
    ingest_har(conn_or_har, db)
    return connect(str(db)), tmp


def _flatten(nodes: list[dict]) -> dict:
    """Merge schema nodes (oneOf expanded) into types / props / required / items."""
    types: set[str] = set()
    props: dict[str, list[dict]] = {}
    items: list[dict] = []
    req_sets: list[set[str]] = []
    stack = list(nodes)
    while stack:
        n = stack.pop()
        if not isinstance(n, dict):
            continue
        if n.get("oneOf"):
            stack.extend(n["oneOf"])
            continue
        t = n.get("type")
        if t:
            types.add(t)
        elif n.get("properties"):
            types.add("object")
        if n.get("properties") is not None:
            for k, v in n["properties"].items():
                props.setdefault(k, []).append(v)
            req_sets.append(set(n.get("required") or []))
        if isinstance(n.get("items"), dict) and n["items"]:
            items.append(n["items"])
    # integer is a subset of number: treat as compatible when both appear
    required = set.intersection(*req_sets) if req_sets else set()
    return {"types": types, "props": props, "items": items, "required": required}


def _compat(a: set[str], b: set[str]) -> bool:
    if not a or not b:
        return True  # unknown/untyped on one side: nothing to compare
    def norm(s: set[str]) -> set[str]:
        return {"number" if x == "integer" else x for x in s}
    return norm(a) == norm(b)


def _walk(base: list[dict], fresh: list[dict], where: str, out: list[dict], depth: int = 0) -> None:
    if depth > 10:
        return
    fb, ff = _flatten(base), _flatten(fresh)
    if not _compat(fb["types"], ff["types"]):
        out.append({"kind": "retyped", "where": where, "was": sorted(fb["types"]), "now": sorted(ff["types"])})
        return
    for k in sorted(set(fb["props"]) | set(ff["props"])):
        w = f"{where}.{k}"
        if k not in ff["props"]:
            out.append({"kind": "removed", "where": w})
        elif k not in fb["props"]:
            out.append({"kind": "added", "where": w, "required": k in ff["required"]})
        else:
            if k in ff["required"] and k not in fb["required"]:
                out.append({"kind": "newly_required", "where": w})
            elif k in fb["required"] and k not in ff["required"]:
                out.append({"kind": "no_longer_required", "where": w})
            _walk(fb["props"][k], ff["props"][k], w, out, depth + 1)
    if fb["items"] and ff["items"]:
        _walk(fb["items"], ff["items"], f"{where}[]", out, depth + 1)


def _body_schemas(op: dict) -> dict[str, list[dict]]:
    res: dict[str, list[dict]] = {}
    rb = ((op.get("requestBody") or {}).get("content") or {}).get("application/json") or {}
    if rb.get("schema"):
        res["request"] = [rb["schema"]]
    for code, r in (op.get("responses") or {}).items():
        s = ((r.get("content") or {}).get("application/json") or {}).get("schema")
        if s:
            res[f"response.{code}"] = [s]
    return res


def _ops(doc: dict, host: str | None) -> dict[tuple[str, str], dict]:
    if host:
        urls = [s.get("url", "") for s in doc.get("servers") or []]
        if urls and not any(host.lower() in u.lower() for u in urls):
            return {}
    out = {}
    for path, item in (doc.get("paths") or {}).items():
        for m, op in (item or {}).items():
            if m.lower() in _METHODS and isinstance(op, dict):
                out[(m.upper(), path)] = op
    return out


def _scheme_shape(s: dict) -> dict:
    return {k: s[k] for k in ("type", "scheme", "in", "name", "bearerFormat") if k in s}


def _params(op: dict) -> dict[tuple[str, str], dict]:
    return {(p.get("in", ""), p.get("name", "")): p for p in op.get("parameters") or []}


def _op_security(op: dict) -> set[str]:
    return {k for req in op.get("security") or [] for k in req}


def diff_contracts(base: dict, fresh: dict, *, host: str | None = None) -> dict:
    """Diff two OpenAPI documents (baseline vs fresh)."""
    bops, fops = _ops(base, host), _ops(fresh, host)
    new_eps = sorted(f"{m} {p}" for m, p in set(fops) - set(bops))
    removed = sorted(f"{m} {p}" for m, p in set(bops) - set(fops))
    status_changes: list[dict] = []
    field_changes: list[dict] = []
    param_changes: list[dict] = []
    auth_changes: list[dict] = []

    for key in sorted(set(bops) & set(fops)):
        ep = f"{key[0]} {key[1]}"
        bo, fo = bops[key], fops[key]
        bs, fs = set((bo.get("responses") or {})), set((fo.get("responses") or {}))
        if bs != fs:
            status_changes.append({"endpoint": ep, "added": sorted(fs - bs), "removed": sorted(bs - fs)})
        bb, fb = _body_schemas(bo), _body_schemas(fo)
        for side in sorted(set(bb) & set(fb)):
            found: list[dict] = []
            _walk(bb[side], fb[side], "$", found)
            for f in found:
                field_changes.append({"endpoint": ep, "side": side, **f})
        bp, fp = _params(bo), _params(fo)
        for k in sorted(set(fp) - set(bp)):
            param_changes.append({"endpoint": ep, "kind": "added", "in": k[0], "name": k[1]})
        for k in sorted(set(bp) - set(fp)):
            param_changes.append({"endpoint": ep, "kind": "removed", "in": k[0], "name": k[1]})
        for k in sorted(set(bp) & set(fp)):
            bt = (bp[k].get("schema") or {}).get("type")
            ft = (fp[k].get("schema") or {}).get("type")
            if bt and ft and bt != ft:
                param_changes.append({"endpoint": ep, "kind": "retyped", "in": k[0], "name": k[1], "was": bt, "now": ft})
        sb, sf = _op_security(bo), _op_security(fo)
        if sb != sf:
            auth_changes.append({"scope": ep, "added": sorted(sf - sb), "removed": sorted(sb - sf)})

    bsch = (base.get("components") or {}).get("securitySchemes") or {}
    fsch = (fresh.get("components") or {}).get("securitySchemes") or {}
    for name in sorted(set(fsch) - set(bsch)):
        auth_changes.append({"scope": "scheme", "kind": "added", "name": name, "shape": _scheme_shape(fsch[name])})
    for name in sorted(set(bsch) - set(fsch)):
        auth_changes.append({"scope": "scheme", "kind": "removed", "name": name, "shape": _scheme_shape(bsch[name])})
    for name in sorted(set(bsch) & set(fsch)):
        if _scheme_shape(bsch[name]) != _scheme_shape(fsch[name]):
            auth_changes.append(
                {"scope": "scheme", "kind": "changed", "name": name,
                 "was": _scheme_shape(bsch[name]), "now": _scheme_shape(fsch[name])}
            )

    breaking_kinds = {"removed", "retyped"}
    breaking = (
        len(removed)
        + sum(1 for c in status_changes if c["removed"])
        + sum(1 for c in field_changes if c["kind"] in breaking_kinds
              or (c["kind"] == "newly_required" and c["side"] == "request")
              or (c["kind"] == "added" and c.get("required") and c["side"] == "request"))
    )
    summary = {
        "new_endpoints": len(new_eps),
        "removed_endpoints": len(removed),
        "status_changes": len(status_changes),
        "field_changes": len(field_changes),
        "parameter_changes": len(param_changes),
        "auth_changes": len(auth_changes),
        "potentially_breaking": breaking,
    }
    return {
        "drift": any(v for k, v in summary.items() if k != "potentially_breaking"),
        "summary": summary,
        "baseline_endpoints": len(bops),
        "capture_endpoints": len(fops),
        "new_endpoints": new_eps,
        "removed_endpoints": removed,
        "status_changes": status_changes,
        "field_changes": field_changes,
        "parameter_changes": param_changes,
        "auth_changes": auth_changes,
        "note": "'removed' means not observed in this capture; confirm coverage before treating as a real removal.",
    }


def check_contract(conn_or_har: Any, openapi_or_schema_doc: Any, host: str | None = None) -> dict:
    """Compare a fresh capture (open connection or HAR path) with a prior OpenAPI doc/file."""
    from hardly.core.export_openapi import build_openapi

    base = _load_spec(openapi_or_schema_doc)
    conn, tmp = _open_capture(conn_or_har)
    try:
        fresh = build_openapi(conn, host=host)
    finally:
        if tmp is not None:
            conn.close()
            tmp.cleanup()
    result = diff_contracts(base, fresh, host=host)
    result["host"] = host
    return result
