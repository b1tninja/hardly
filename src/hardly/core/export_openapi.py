"""Export a minimal OpenAPI 3.x document."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from hardly.core.schema_infer import infer_schema


def _parse_json(text: str | None) -> Any | None:
    if not text:
        return None
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return None


def _schema_to_openapi(schema: dict) -> dict:
    """Convert our compact schema to a loose OpenAPI schema object."""
    t = schema.get("type", "object")
    if t == "object" or (isinstance(t, str) and t.startswith("object")):
        props = {}
        for k, v in schema.get("properties", {}).items():
            props[k] = _schema_to_openapi(v)
        out: dict[str, Any] = {"type": "object", "properties": props}
        if schema.get("required"):
            out["required"] = schema["required"]
        return out
    if t == "array":
        return {
            "type": "array",
            "items": _schema_to_openapi(schema.get("items", {"type": "string"})),
        }
    base = t.rstrip("?").split("|")[0]
    mapping = {
        "integer": "integer",
        "number": "number",
        "boolean": "boolean",
        "string": "string",
        "null": "string",
    }
    return {"type": mapping.get(base, "string")}


def export_openapi(
    conn: sqlite3.Connection,
    output_path: str | Path,
    *,
    host: str | None = None,
    exclude_noise: bool = True,
    title: str = "HAR-derived API",
    as_yaml: bool = False,
) -> dict:
    clauses = ["1=1"]
    params: list[Any] = []
    if host:
        clauses.append("host = ?")
        params.append(host.lower())
    if exclude_noise:
        clauses.append("is_noise = 0")
    where = " AND ".join(clauses)

    endpoints = conn.execute(
        f"""
        SELECT method, host, path_template, COUNT(*) AS cnt
        FROM entries
        WHERE {where}
        GROUP BY method, host, path_template
        ORDER BY host, path_template, method
        """,
        params,
    ).fetchall()

    servers: dict[str, dict] = {}
    paths: dict[str, dict] = {}

    for ep in endpoints:
        server_url = f"https://{ep['host']}"
        servers[server_url] = {"url": server_url}
        path_key = ep["path_template"] or "/"
        method = ep["method"].lower()
        if method == "options":
            continue

        # Collect body samples
        samples_req: list[Any] = []
        samples_resp: list[Any] = []
        ep_clauses = ["e.method = ?", "e.host = ?", "e.path_template = ?"]
        ep_params: list[Any] = [ep["method"], ep["host"], ep["path_template"]]
        if exclude_noise:
            ep_clauses.append("e.is_noise = 0")
        rows = conn.execute(
            f"""
            SELECT e.entry_id, e.status FROM entries e
            WHERE {" AND ".join(ep_clauses)}
            LIMIT 15
            """,
            ep_params,
        ).fetchall()
        status_codes: set[int] = set()
        for r in rows:
            status_codes.add(r["status"] or 0)
            for side, bucket in (("request", samples_req), ("response", samples_resp)):
                b = conn.execute(
                    "SELECT preview_text FROM bodies WHERE entry_id = ? AND side = ?",
                    (r["entry_id"], side),
                ).fetchone()
                parsed = _parse_json(b["preview_text"] if b else None)
                if parsed is not None:
                    bucket.append(parsed)

        parameters = _path_parameters(path_key) + _query_parameters(conn, rows)
        auth_scheme = _operation_auth_scheme(conn, rows)
        op: dict[str, Any] = {
            "summary": f"{ep['method']} {path_key}",
            "operationId": f"{method}_{ep['host'].replace('.', '_')}_{path_key.strip('/').replace('/', '_').replace('{', '').replace('}', '')}"[:80],
            "responses": {},
        }
        for code in sorted(status_codes) or [200]:
            resp_obj: dict[str, Any] = {"description": f"HTTP {code}"}
            if samples_resp:
                resp_obj["content"] = {
                    "application/json": {
                        "schema": _schema_to_openapi(infer_schema(samples_resp))
                    }
                }
            op["responses"][str(code)] = resp_obj

        if parameters:
            op["parameters"] = parameters
        if auth_scheme:
            op["security"] = [{auth_scheme: []}]

        if samples_req and method in {"post", "put", "patch"}:
            op["requestBody"] = {
                "content": {
                    "application/json": {
                        "schema": _schema_to_openapi(infer_schema(samples_req))
                    }
                }
            }

        paths.setdefault(path_key, {})[method] = op

    security_schemes, security = _security_from_auth(conn, host=host)

    doc: dict[str, Any] = {
        "openapi": "3.0.3",
        "info": {"title": title, "version": "0.1.0"},
        "servers": list(servers.values()),
        "paths": paths,
    }
    if security_schemes:
        doc["components"] = {"securitySchemes": security_schemes}
        # No global requirement: public operations (login, docs) must stay open.
        # Operations that were called with credentials carry their own `security`.

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    if as_yaml or str(out).endswith((".yaml", ".yml")):
        text = _to_yaml(doc)
        out.write_text(text, encoding="utf-8")
        fmt = "yaml"
    else:
        out.write_text(json.dumps(doc, indent=2), encoding="utf-8")
        fmt = "json"

    return {
        "path": str(out.resolve()),
        "format": fmt,
        "paths": len(paths),
        "host": host,
        "security_schemes": list(security_schemes.keys()),
    }


def _security_from_auth(
    conn: sqlite3.Connection, *, host: str | None
) -> tuple[dict[str, Any], list[dict[str, list]]]:
    """Build OpenAPI securitySchemes from hardly_auth heuristics."""
    from hardly.core.auth import detect_auth

    auth = detect_auth(conn, host=host)
    headers = {
        **(auth.get("auth_related_headers") or {}),
        **(auth.get("custom_auth_headers") or {}),
    }
    schemes: dict[str, Any] = {}
    shapes = {
        r["shape"]
        for r in conn.execute(
            "SELECT DISTINCT shape FROM value_shapes WHERE lower(name) = 'authorization'"
        )
    }
    challenge_schemes: set[str] = set()
    try:
        from hardly.core.challenges import detect_challenges

        for ch in detect_challenges(conn, host=host, limit=30)["auth_challenges"]:
            challenge_schemes |= {s["scheme"].lower() for s in ch["schemes"]}
    except Exception:  # noqa: BLE001
        pass
    if "basic_auth" in shapes or "basic" in challenge_schemes:
        schemes["basicAuth"] = {"type": "http", "scheme": "basic", "description": "HTTP Basic (Authorization header or 401 challenge seen)."}
    if "digest" in challenge_schemes:
        schemes["digestAuth"] = {"type": "http", "scheme": "digest", "description": "HTTP Digest challenge seen (401 WWW-Authenticate: Digest)."}
    if shapes & {"bearer_jwt", "bearer_token"} or "bearer" in challenge_schemes:
        bearer: dict[str, Any] = {"type": "http", "scheme": "bearer", "description": "Bearer token in the Authorization header."}
        if "bearer_jwt" in shapes:
            bearer["bearerFormat"] = "JWT"
        schemes["bearerAuth"] = bearer
    if "authorization" in headers and not (set(schemes) & {"basicAuth", "digestAuth", "bearerAuth"}):
        schemes["bearerAuth"] = {
            "type": "http",
            "scheme": "bearer",
            "description": "Authorization header seen in capture; scheme not determinable (value withheld).",
        }
    if "cookie" in headers or "set-cookie" in headers:
        schemes["cookieAuth"] = {
            "type": "apiKey",
            "in": "cookie",
            "name": _session_cookie_name(conn),
            "description": "Session cookie observed in capture.",
        }
    for name in sorted(headers):
        if name in {"authorization", "cookie", "set-cookie"}:
            continue
        if "csrf" in name or "xsrf" in name:
            key = "csrfHeader"
            if key not in schemes:
                schemes[key] = {
                    "type": "apiKey",
                    "in": "header",
                    "name": name,
                    "description": "CSRF / XSRF header observed in capture.",
                }
        elif "api" in name or name.endswith("-key") or "auth" in name:
            key = "apiKeyHeader"
            if key not in schemes:
                schemes[key] = {
                    "type": "apiKey",
                    "in": "header",
                    "name": name,
                }
    security = [{name: []} for name in schemes][:4]
    return schemes, security


_PATH_TYPE = {"id": "integer", "uuid": "string", "hex": "string", "token": "string"}


def _path_parameters(path_key: str) -> list[dict[str, Any]]:
    """Declare every ``{name}`` segment (OpenAPI 3 requires it)."""
    import re as _re

    out, seen = [], set()
    for name in _re.findall(r"\{([^}/]+)\}", path_key):
        if name in seen:
            continue
        seen.add(name)
        schema: dict[str, Any] = {"type": _PATH_TYPE.get(name, "string")}
        if name == "uuid":
            schema["format"] = "uuid"
        out.append({"name": name, "in": "path", "required": True, "schema": schema})
    return out


def _query_parameters(conn: sqlite3.Connection, rows: list[sqlite3.Row]) -> list[dict[str, Any]]:
    """Query parameter names seen on the sampled calls (values never exported)."""
    names: dict[str, bool] = {}
    for r in rows:
        q = conn.execute("SELECT query_json FROM entries WHERE entry_id = ?", (r["entry_id"],)).fetchone()
        try:
            data = json.loads((q["query_json"] if q else None) or "{}")
        except (json.JSONDecodeError, TypeError):
            continue
        if isinstance(data, dict):
            for k, v in data.items():
                vals = v if isinstance(v, list) else [v]
                names[k] = names.get(k, True) and all(str(x).lstrip("-").isdigit() for x in vals)
    return [
        {"name": k, "in": "query", "required": False, "schema": {"type": "integer" if is_int else "string"}}
        for k, is_int in sorted(names.items())
    ]


def _operation_auth_scheme(conn: sqlite3.Connection, rows: list[sqlite3.Row]) -> str | None:
    """Security scheme for an operation that was called with an Authorization header."""
    for r in rows:
        has = conn.execute(
            "SELECT 1 FROM headers WHERE entry_id = ? AND side = 'request' AND lower(name) = 'authorization'",
            (r["entry_id"],),
        ).fetchone()
        if not has:
            continue
        shape = conn.execute(
            "SELECT shape FROM value_shapes WHERE entry_id = ? AND lower(name) = 'authorization' LIMIT 1",
            (r["entry_id"],),
        ).fetchone()
        kind = shape["shape"] if shape else ""
        return {"basic_auth": "basicAuth"}.get(kind, "bearerAuth")
    return None


def _session_cookie_name(conn: sqlite3.Connection) -> str:
    """First observed cookie that looks like the session (not a CSRF/tracker)."""
    import re as _re

    from hardly.core.cookies import cookie_timeline

    try:
        names = cookie_timeline(conn, host=None, limit=60).get("names_set") or []
    except Exception:  # noqa: BLE001
        names = []
    for n in names:
        if _re.search(r"session|sess|sid|auth|token|jwt", n, _re.I) and not _re.search(r"csrf|xsrf", n, _re.I):
            return n
    return "session"


def _to_yaml(obj: Any, indent: int = 0) -> str:
    """Minimal YAML emitter (no PyYAML dependency)."""
    sp = "  " * indent
    if isinstance(obj, dict):
        if not obj:
            return "{}"
        lines = []
        for k, v in obj.items():
            if isinstance(v, (dict, list)):
                lines.append(f"{sp}{k}:")
                lines.append(_to_yaml(v, indent + 1))
            else:
                lines.append(f"{sp}{k}: {_yaml_scalar(v)}")
        return "\n".join(lines)
    if isinstance(obj, list):
        if not obj:
            return f"{sp}[]"
        lines = []
        for item in obj:
            if isinstance(item, (dict, list)):
                lines.append(f"{sp}-")
                lines.append(_to_yaml(item, indent + 1))
            else:
                lines.append(f"{sp}- {_yaml_scalar(item)}")
        return "\n".join(lines)
    return f"{sp}{_yaml_scalar(obj)}"


def _yaml_scalar(v: Any) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    s = str(v)
    if any(c in s for c in ":#{}[],&*?|>!%@`'\"") or s == "" or s.lower() in {"true", "false", "null"}:
        return json.dumps(s)
    return s
