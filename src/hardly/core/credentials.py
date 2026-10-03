"""Map credential / session evidence for agents (names and shapes only)."""

from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path
from typing import Any
import ijson

from hardly.core.auth import AUTH_PATH_RE, detect_auth
from hardly.core.cookies import cookie_timeline
from hardly.core.filters import is_noise
from hardly.core.redact import (
    classify_value_shape,
    is_sensitive_header,
    is_sensitive_key,
)
from hardly.core.secrets import locate_secrets
from hardly.core.urls import parse_url

_PASSWORD_KINDS = frozenset(
    {"html_password", "html_field", "form_field", "json_key", "query_param"}
)
_PASSWORD_NAME_RE = re.compile(
    r"password|passwd|\bpwd\b|\bpw\b|passcode|passphrase|secret",
    re.I,
)
_SESSION_COOKIE_RE = re.compile(
    r"session|sessid|jsession|asp\.?net|auth|token|sid$|^sid$|ssid|"
    r"jwt|remember|login|secure|csrf|xsrf|requestverification",
    re.I,
)
_CSRF_RE = re.compile(r"csrf|xsrf|requestverification|__requestverification", re.I)


def map_credentials(
    conn: sqlite3.Connection,
    *,
    har_path: str | Path | None = None,
    host: str | None = None,
    limit: int = 40,
) -> dict[str, Any]:
    """One-shot credential / login / session map — never returns secret values.

    Combines sensitive *names*, value *shapes* (jwt/hex/base64/…), session
    cookie names, query secrets, and a hypothesized login flow.
    """
    secrets = locate_secrets(conn, host=host, limit=min(limit, 60))
    auth = detect_auth(conn, host=host)
    cookies = cookie_timeline(conn, har_path=har_path, host=host, limit=80)

    password_fields = [
        h
        for h in secrets.get("hits") or []
        if h.get("kind") == "html_password"
        or (
            h.get("kind") in _PASSWORD_KINDS
            and _PASSWORD_NAME_RE.search(str(h.get("name") or ""))
        )
    ]
    # Also pull password-ish names from query params / forms not already listed.
    query_secrets = _query_secret_names(conn, host=host, limit=limit)
    for qs in query_secrets:
        if _PASSWORD_NAME_RE.search(qs["name"]) and not any(
            p["entry_id"] == qs["entry_id"] and p["name"].lower() == qs["name"].lower()
            for p in password_fields
        ):
            password_fields.append({**qs, "kind": "query_param"})

    session_cookies = sorted(
        {
            n
            for n in (cookies.get("names_set") or []) + (cookies.get("names_sent") or [])
            if _SESSION_COOKIE_RE.search(n)
        },
        key=str.lower,
    )
    csrf_names = sorted(
        {
            *(
                h["name"]
                for h in secrets.get("hits") or []
                if _CSRF_RE.search(str(h.get("name") or ""))
            ),
            *(n for n in session_cookies if _CSRF_RE.search(n)),
            *(
                qs["name"]
                for qs in query_secrets
                if _CSRF_RE.search(qs["name"])
            ),
        },
        key=str.lower,
    )

    shapes = _shape_hits(conn, har_path=har_path, host=host, limit=limit)
    flow = _login_flow(
        conn,
        host=host,
        password_fields=password_fields,
        auth=auth,
        session_cookies=session_cookies,
        shapes=shapes,
    )

    by_shape: dict[str, int] = {}
    for s in shapes:
        by_shape[s["shape"]] = by_shape.get(s["shape"], 0) + 1

    return {
        "host": host,
        "password_fields": password_fields[:limit],
        "password_field_count": len(password_fields),
        "login_paths": (auth.get("auth_path_entries") or [])[:20],
        "token_responses": (auth.get("token_response_entries") or [])[:20],
        "auth_headers": auth.get("auth_related_headers") or {},
        "custom_auth_headers": auth.get("custom_auth_headers") or {},
        "session_cookies": session_cookies,
        "csrf_names": csrf_names,
        "query_secrets": query_secrets[:limit],
        "shapes": shapes[:limit],
        "shapes_by_kind": by_shape,
        "login_flow": flow,
        "secret_names": secrets.get("names") or [],
        "notes": [
            "Names and value *shapes* only — never secret values.",
            "Chrome HARs often strip Authorization / Cookie; bodies still help.",
            *(auth.get("notes") or []),
        ],
        "next": (
            "Trace a name with hardly_trace; correlate reuse with "
            "hardly_correlate; compare pre/post login with "
            "hardly_compare_entries; stub with placeholders via hardly_stub."
        ),
    }


def _query_secret_names(
    conn: sqlite3.Connection,
    *,
    host: str | None,
    limit: int,
) -> list[dict[str, Any]]:
    clauses = ["e.is_noise = 0", "e.query_json IS NOT NULL"]
    params: list[Any] = []
    if host:
        clauses.append("e.host = ?")
        params.append(host.lower())
    rows = conn.execute(
        f"""
        SELECT e.entry_id, e.method, e.path, e.query_json
        FROM entries e
        WHERE {" AND ".join(clauses)}
        ORDER BY e.entry_id ASC
        LIMIT 400
        """,
        params,
    ).fetchall()
    out: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    for row in rows:
        try:
            query = json.loads(row["query_json"] or "{}")
        except (json.JSONDecodeError, TypeError):
            continue
        if not isinstance(query, dict):
            continue
        for name, value in query.items():
            if not name:
                continue
            sensitive = is_sensitive_key(str(name))
            shape = None
            if isinstance(value, str):
                shape = classify_value_shape(value)
            elif isinstance(value, list) and value and isinstance(value[0], str):
                shape = classify_value_shape(value[0])
            if not sensitive and not shape:
                continue
            key = (row["entry_id"], str(name).lower())
            if key in seen:
                continue
            seen.add(key)
            hit: dict[str, Any] = {
                "entry_id": row["entry_id"],
                "method": row["method"],
                "path": row["path"],
                "side": "request",
                "kind": "query_param",
                "name": str(name),
            }
            if shape:
                hit["shape"] = shape
            out.append(hit)
            if len(out) >= limit:
                return out
    return out


def _shape_hits(
    conn: sqlite3.Connection,
    *,
    har_path: str | Path | None,
    host: str | None,
    limit: int,
) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()

    # Query string values (raw in index — classify only).
    for qs in _query_secret_names(conn, host=host, limit=limit):
        shape = qs.get("shape")
        if not shape:
            continue
        key = (qs["entry_id"], "query", qs["name"].lower(), shape)
        if key in seen:
            continue
        seen.add(key)
        hits.append(
            {
                "entry_id": qs["entry_id"],
                "method": qs["method"],
                "path": qs["path"],
                "side": "request",
                "where": "query",
                "name": qs["name"],
                "shape": shape,
            }
        )

    # Non-sensitive header raw values (Authorization raw is withheld at ingest).
    clauses = ["e.is_noise = 0", "h.value_raw IS NOT NULL"]
    params: list[Any] = []
    if host:
        clauses.append("e.host = ?")
        params.append(host.lower())
    for row in conn.execute(
        f"""
        SELECT e.entry_id, e.method, e.path, h.side, h.name, h.value_raw
        FROM entries e
        JOIN headers h ON h.entry_id = e.entry_id
        WHERE {" AND ".join(clauses)}
        ORDER BY e.entry_id ASC
        LIMIT 800
        """,
        params,
    ):
        if is_sensitive_header(row["name"]):
            continue
        shape = classify_value_shape(row["value_raw"])
        if not shape:
            continue
        key = (row["entry_id"], row["side"], row["name"].lower(), shape)
        if key in seen:
            continue
        seen.add(key)
        hits.append(
            {
                "entry_id": row["entry_id"],
                "method": row["method"],
                "path": row["path"],
                "side": row["side"],
                "where": "header",
                "name": row["name"],
                "shape": shape,
            }
        )
        if len(hits) >= limit:
            break

    # Sensitive headers: optional HAR scan for shape only (values discarded).
    path = Path(har_path) if har_path else _har_path(conn)
    if path and path.is_file() and len(hits) < limit:
        for hit in _shapes_from_har(path, host=host, limit=limit - len(hits)):
            key = (
                hit["entry_id"],
                hit["side"],
                (hit.get("name") or "").lower(),
                hit["shape"],
            )
            if key in seen:
                continue
            seen.add(key)
            hits.append(hit)

    return hits[:limit]


def _shapes_from_har(
    har_path: Path,
    *,
    host: str | None,
    limit: int,
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    with har_path.open("rb") as f:
        for entry_id, entry in enumerate(ijson.items(f, "log.entries.item")):
            req = entry.get("request") or {}
            resp = entry.get("response") or {}
            url = req.get("url") or ""
            parsed = parse_url(url)
            if host and parsed["host"].lower() != host.lower():
                continue
            method = (req.get("method") or "GET").upper()
            mime = (resp.get("content") or {}).get("mimeType")
            if is_noise(
                method=method, url=url, status=resp.get("status"), mime=mime
            ):
                continue
            for side, headers in (
                ("request", req.get("headers") or []),
                ("response", resp.get("headers") or []),
            ):
                for h in headers:
                    name = str(h.get("name") or "")
                    if name.lower() not in {
                        "authorization",
                        "cookie",
                        "set-cookie",
                        "proxy-authorization",
                    }:
                        continue
                    value = str(h.get("value") or "")
                    # Cookie headers: classify each cookie *value* shape by name.
                    if name.lower() in {"cookie", "set-cookie"}:
                        for cname, cval in _cookie_pairs(value):
                            shape = classify_value_shape(cval)
                            if not shape and not _SESSION_COOKIE_RE.search(cname):
                                continue
                            out.append(
                                {
                                    "entry_id": entry_id,
                                    "method": method,
                                    "path": parsed["path"],
                                    "side": side,
                                    "where": "cookie",
                                    "name": cname,
                                    "shape": shape or "cookie",
                                }
                            )
                            if len(out) >= limit:
                                return out
                        continue
                    shape = classify_value_shape(value)
                    if not shape:
                        continue
                    out.append(
                        {
                            "entry_id": entry_id,
                            "method": method,
                            "path": parsed["path"],
                            "side": side,
                            "where": "header",
                            "name": name,
                            "shape": shape,
                        }
                    )
                    if len(out) >= limit:
                        return out
            # Request/response body shapes for JWT/hex/base64 (discard text).
            from hardly.core.redact import BASE64_RE, JWT_RE, LONG_HEX_RE

            for side, blob in (
                ("request", (req.get("postData") or {}).get("text")),
                ("response", (resp.get("content") or {}).get("text")),
            ):
                if not blob or not isinstance(blob, str) or len(blob) > 200_000:
                    continue
                found: list[str] = []
                if JWT_RE.search(blob):
                    found.append("jwt")
                if LONG_HEX_RE.search(blob):
                    found.append("hex")
                elif BASE64_RE.search(blob) and "jwt" not in found:
                    found.append("base64")
                for label in found:
                    out.append(
                        {
                            "entry_id": entry_id,
                            "method": method,
                            "path": parsed["path"],
                            "side": side,
                            "where": "body",
                            "name": None,
                            "shape": label,
                        }
                    )
                    if len(out) >= limit:
                        return out
    return out


def _cookie_pairs(header_value: str) -> list[tuple[str, str]]:
    """Return cookie name/value pairs (Set-Cookie → first pair only)."""
    attrs = {
        "path",
        "domain",
        "expires",
        "max-age",
        "secure",
        "httponly",
        "samesite",
    }
    set_cookie_style = bool(
        re.search(r"\b(?:Path|HttpOnly|SameSite|Max-Age)\s*=", header_value, re.I)
        or re.search(r"\bHttpOnly\b", header_value, re.I)
    )
    pairs: list[tuple[str, str]] = []
    for part in header_value.split(";"):
        part = part.strip()
        if "=" not in part:
            continue
        name, _, val = part.partition("=")
        name = name.strip()
        if not name or name.lower() in attrs:
            continue
        pairs.append((name, val.strip()))
        if set_cookie_style:
            return pairs
    return pairs


def _login_flow(
    conn: sqlite3.Connection,
    *,
    host: str | None,
    password_fields: list[dict[str, Any]],
    auth: dict[str, Any],
    session_cookies: list[str],
    shapes: list[dict[str, Any]],
) -> dict[str, Any]:
    """Hypothesize a login sequence from password posts → tokens/cookies."""
    steps: list[dict[str, Any]] = []
    cred_ids = sorted(
        {
            h["entry_id"]
            for h in password_fields
            if h.get("side") == "request"
            or h.get("kind") in {"json_key", "form_field", "query_param", "html_password"}
        }
    )
    # Prefer POST/PUT credential submissions on auth-ish paths.
    for eid in cred_ids:
        row = conn.execute(
            "SELECT entry_id, method, host, path, status FROM entries "
            "WHERE entry_id = ?",
            (eid,),
        ).fetchone()
        if not row:
            continue
        role = "credential_submit"
        if AUTH_PATH_RE.search(row["path"] or ""):
            role = "login_submit"
        steps.append(
            {
                "role": role,
                "entry_id": row["entry_id"],
                "method": row["method"],
                "host": row["host"],
                "path": row["path"],
                "status": row["status"],
            }
        )

    for tr in auth.get("token_response_entries") or []:
        steps.append(
            {
                "role": "token_issue",
                "entry_id": tr["entry_id"],
                "method": tr.get("method"),
                "path": tr.get("path"),
                "status": tr.get("status"),
                "token_keys": tr.get("token_keys"),
            }
        )

    for s in shapes:
        if s.get("shape") in {"bearer_jwt", "bearer_token", "jwt"} and s.get(
            "where"
        ) in {"header", "body"}:
            steps.append(
                {
                    "role": "auth_material",
                    "entry_id": s["entry_id"],
                    "method": s.get("method"),
                    "path": s.get("path"),
                    "shape": s["shape"],
                    "where": s.get("where"),
                    "name": s.get("name"),
                }
            )

    # De-dupe by (role, entry_id), keep order by entry_id.
    uniq: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    for step in sorted(steps, key=lambda s: (s.get("entry_id") or 0, s["role"])):
        key = (step["role"], step.get("entry_id"), step.get("shape"), step.get("name"))
        if key in seen:
            continue
        seen.add(key)
        uniq.append(step)

    return {
        "step_count": len(uniq),
        "steps": uniq[:30],
        "session_cookies": session_cookies,
        "confidence": (
            "high"
            if cred_ids and (auth.get("token_response_count") or session_cookies)
            else "medium"
            if cred_ids or auth.get("auth_path_count")
            else "low"
        ),
    }


def _har_path(conn: sqlite3.Connection) -> Path | None:
    row = conn.execute(
        "SELECT value FROM meta WHERE key = 'har_path'"
    ).fetchone()
    if not row:
        return None
    path = Path(row["value"] if isinstance(row, sqlite3.Row) else row[0])
    return path if path.is_file() else None
