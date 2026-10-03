"""Map credential / session evidence for agents (names and shapes only)."""

from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path
from urllib.parse import parse_qsl, urlparse
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
_USER_NAME_RE = re.compile(
    r"user(name)?|e[-_]?mail|login|account|userid|user_?id|identifier|phone|mobile",
    re.I,
)
# Names that contain "user" but are not a login identity.
_NOT_IDENTITY_RE = re.compile(
    r"agent|ip_?address|user_?type|user_?info|user_?count|user_?role|user_?group|"
    r"user_?list|users$|accountnumber|account_?type|login_?count|last_?login",
    re.I,
)
_OAUTH_PARAM_RE = re.compile(
    r"^(code|state|redirect_uri|client_id|client_secret|scope|grant_type|"
    r"refresh_token|access_token|id_token|nonce|code_challenge|"
    r"code_verifier|response_type)$",
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
    # One input can surface as html_field and html_password: keep a single row.
    _rank = {"html_password": 0}
    _dedup: dict[tuple[Any, str, Any], dict[str, Any]] = {}
    for h in sorted(password_fields, key=lambda h: _rank.get(str(h.get("kind")), 1)):
        _dedup.setdefault((h.get("entry_id"), str(h.get("name") or "").lower(), h.get("side")), h)
    password_fields = sorted(_dedup.values(), key=lambda h: (h.get("entry_id") or 0, str(h.get("name") or "")))
    # Also pull password-ish names from query params / forms not already listed.
    query_secrets = _query_secret_names(conn, host=host, limit=limit)
    for qs in query_secrets:
        if _PASSWORD_NAME_RE.search(qs["name"]) and not any(
            p["entry_id"] == qs["entry_id"] and p["name"].lower() == qs["name"].lower()
            for p in password_fields
        ):
            password_fields.append({**qs, "kind": "query_param"})

    identity_fields = _identity_fields(
        conn,
        host=host,
        secrets_hits=secrets.get("hits") or [],
        password_fields=password_fields,
        limit=limit,
    )
    oauth = _oauth_signals(conn, host=host, query_secrets=query_secrets, limit=limit)

    cookie_names = (cookies.get("names_set") or []) + (cookies.get("names_sent") or [])
    session_cookies = sorted(
        {
            n
            for n in cookie_names
            if _SESSION_COOKIE_RE.search(n)
            and not _CSRF_RE.search(n)  # csrftoken guards forms; it is not the session
            and "(redacted" not in n.lower()
        }
        | _behavioral_session_cookies(conn, cookies, password_fields),
        key=str.lower,
    )
    csrf_names = sorted(
        {
            *(
                h["name"]
                for h in secrets.get("hits") or []
                if _CSRF_RE.search(str(h.get("name") or ""))
            ),
            *(n for n in cookie_names if _CSRF_RE.search(n) and "(redacted" not in n.lower()),
            *_credential_post_csrf_names(conn, password_fields),
            *(
                qs["name"]
                for qs in query_secrets
                if _CSRF_RE.search(qs["name"])
            ),
        },
        key=str.lower,
    )

    shapes = _shape_hits(conn, har_path=har_path, host=host, limit=limit)
    webauthn = _webauthn_signals(conn, host=host)
    spa_suspected = _spa_login_suspected(conn, host=host, password_fields=password_fields)
    aborted = _aborted_entries(conn, host=host)
    flow = _login_flow(
        conn,
        host=host,
        password_fields=password_fields,
        identity_fields=identity_fields,
        auth=auth,
        session_cookies=session_cookies,
        shapes=shapes,
        oauth=oauth,
        webauthn_steps=webauthn.get("steps"),
    )

    by_shape: dict[str, int] = {}
    for s in shapes:
        by_shape[s["shape"]] = by_shape.get(s["shape"], 0) + 1

    return {
        "host": host,
        "password_fields": password_fields[:limit],
        "password_field_count": len(password_fields),
        "identity_fields": identity_fields[:limit],
        "identity_field_count": len(identity_fields),
        "login_paths": (auth.get("auth_path_entries") or [])[:20],
        "token_responses": (auth.get("token_response_entries") or [])[:20],
        "auth_headers": auth.get("auth_related_headers") or {},
        "custom_auth_headers": auth.get("custom_auth_headers") or {},
        "session_cookies": session_cookies,
        "cookie_flags": (cookies.get("flags") or [])[:limit],
        "cookie_flags_by": cookies.get("by_flag") or {},
        "csrf_names": csrf_names,
        "anti_forgery_forms": _anti_forgery_forms(conn, host=host, limit=limit),
        "webauthn": webauthn,
        "spa_login_suspected": spa_suspected,
        "aborted_entries": aborted,
        "oauth": oauth,
        "query_secrets": query_secrets[:limit],
        "shapes": shapes[:limit],
        "shapes_by_kind": by_shape,
        "login_flow": flow,
        "secret_names": secrets.get("names") or [],
        "notes": [
            "Names and value *shapes* only — never secret values.",
            *(
                [
                    "Client-rendered page(s) with no form markup: login inputs are probably "
                    "created by JavaScript. Use hardly_capture_aria or a recipe `evaluate` "
                    "step after load to read the rendered fields."
                ]
                if spa_suspected
                else []
            ),
            *(
                [f"{aborted['count']} of {aborted['total']} entries have no response "
                 "(status -1/0: aborted, blocked, or capture stopped early)."]
                if aborted["count"] >= 3 and aborted["count"] * 5 >= aborted["total"]
                else []
            ),
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

    # Prefer ingest-time tags (fast; no HAR re-scan).
    indexed = _shapes_from_index(conn, host=host, limit=limit)
    if indexed:
        return indexed

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


def _shapes_from_index(
    conn: sqlite3.Connection,
    *,
    host: str | None,
    limit: int,
) -> list[dict[str, Any]]:
    """Read value_shapes rows written at ingest time."""
    try:
        row = conn.execute(
            "SELECT COUNT(*) AS n FROM sqlite_master "
            "WHERE type='table' AND name='value_shapes'"
        ).fetchone()
        if not row or int(row["n"] if isinstance(row, sqlite3.Row) else row[0]) < 1:
            return []
        count = conn.execute("SELECT COUNT(*) AS n FROM value_shapes").fetchone()
        if not count or int(count["n"] if isinstance(count, sqlite3.Row) else count[0]) < 1:
            return []
    except sqlite3.Error:
        return []

    clauses = ["e.is_noise = 0"]
    params: list[Any] = []
    if host:
        clauses.append("e.host = ?")
        params.append(host.lower())
    rows = conn.execute(
        f"""
        SELECT e.entry_id, e.method, e.path, s.side, s.where_kind, s.name, s.shape
        FROM value_shapes s
        JOIN entries e ON e.entry_id = s.entry_id
        WHERE {" AND ".join(clauses)}
        ORDER BY e.entry_id ASC, s.id ASC
        LIMIT ?
        """,
        [*params, limit],
    ).fetchall()
    return [
        {
            "entry_id": r["entry_id"],
            "method": r["method"],
            "path": r["path"],
            "side": r["side"],
            "where": r["where_kind"],
            "name": r["name"],
            "shape": r["shape"],
            "source": "index",
        }
        for r in rows
    ]


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
                # Same rule as ingest: a bare token body only. Structured bodies
                # are judged by token-like keys at ingest, never as a whole
                # document (a long path or hash would otherwise match).
                stripped = blob.strip()
                if (
                    len(stripped) <= 4096
                    and " " not in stripped
                    and "<" not in stripped
                    and not stripped.startswith(("{", "["))
                ):
                    bare = classify_value_shape(stripped)
                    if bare and bare != "jwt":
                        found.append(bare)
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


def _identity_fields(
    conn: sqlite3.Connection,
    *,
    host: str | None,
    secrets_hits: list[dict[str, Any]],
    password_fields: list[dict[str, Any]],
    limit: int,
) -> list[dict[str, Any]]:
    """Username/email/login field names, preferably paired with password entries."""
    pwd_ids = {h["entry_id"] for h in password_fields}
    out: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()

    for h in secrets_hits:
        name = str(h.get("name") or "")
        kind = str(h.get("kind") or "")
        is_identity = kind == "html_identity" or (
            name
            and _USER_NAME_RE.search(name)
            and not _PASSWORD_NAME_RE.search(name)
            and not _NOT_IDENTITY_RE.search(name)
        )
        if not is_identity:
            continue
        key = (h["entry_id"], name.lower())
        if key in seen:
            continue
        seen.add(key)
        out.append(
            {
                **{k: h[k] for k in ("entry_id", "method", "path", "side", "kind") if k in h},
                "name": name,
                "paired_with_password": h["entry_id"] in pwd_ids,
            }
        )

    # Scan HTML bodies for autocomplete=username/email near passwords.
    from hardly.core.secrets import html_autocomplete_fields

    clauses = ["e.is_noise = 0", "b.preview_text LIKE '%autocomplete%'"]
    params: list[Any] = []
    if host:
        clauses.append("e.host = ?")
        params.append(host.lower())
    for body in conn.execute(
        f"""
        SELECT e.entry_id, e.method, e.path, b.side, b.preview_text
        FROM entries e
        JOIN bodies b ON b.entry_id = e.entry_id
        WHERE {" AND ".join(clauses)}
        ORDER BY e.entry_id ASC
        LIMIT 80
        """,
        params,
    ):
        for name, kind, ac in html_autocomplete_fields(body["preview_text"] or ""):
            if kind != "html_identity":
                continue
            key = (body["entry_id"], name.lower())
            if key in seen:
                continue
            seen.add(key)
            out.append(
                {
                    "entry_id": body["entry_id"],
                    "method": body["method"],
                    "path": body["path"],
                    "side": body["side"],
                    "kind": "html_autocomplete",
                    "name": name,
                    "autocomplete": ac,
                    "paired_with_password": body["entry_id"] in pwd_ids,
                }
            )
            if len(out) >= limit:
                return out[:limit]

    # Form / JSON field names on the same entries as passwords.
    for eid in sorted(pwd_ids)[:40]:
        row = conn.execute(
            "SELECT e.entry_id, e.method, e.path, b.side, b.preview_text "
            "FROM entries e "
            "JOIN bodies b ON b.entry_id = e.entry_id "
            "WHERE e.entry_id = ? AND b.preview_text IS NOT NULL",
            (eid,),
        ).fetchall()
        for body in row:
            text = body["preview_text"] or ""
            for name in _field_names_in_preview(text):
                if (
                    not _USER_NAME_RE.search(name)
                    or _PASSWORD_NAME_RE.search(name)
                    or _NOT_IDENTITY_RE.search(name)
                ):
                    continue
                key = (eid, name.lower())
                if key in seen:
                    continue
                seen.add(key)
                out.append(
                    {
                        "entry_id": eid,
                        "method": body["method"],
                        "path": body["path"],
                        "side": body["side"],
                        "kind": "paired_field",
                        "name": name,
                        "paired_with_password": True,
                    }
                )
                if len(out) >= limit:
                    return out[:limit]
    return out[:limit]


def _field_names_in_preview(text: str) -> list[str]:
    names: list[str] = []
    stripped = text.lstrip()
    if stripped.startswith(("{", "[")):
        try:
            data = json.loads(text)
        except (json.JSONDecodeError, TypeError):
            data = None
        if data is not None:
            from hardly.core.secrets import _json_keys

            return [str(k) for k in _json_keys(data)[:80]]
    if "=" in text and "<" not in text[:40]:
        from urllib.parse import parse_qsl

        for key, _ in parse_qsl(text, keep_blank_values=True):
            if key:
                names.append(key)
    for m in re.finditer(
        r"""<(?:input|textarea)\b[^>]*\bname\s*=\s*['"]([^'"]+)['"]""",
        text,
        re.I,
    ):
        names.append(m.group(1))
    return names


def _oauth_signals(
    conn: sqlite3.Connection,
    *,
    host: str | None,
    query_secrets: list[dict[str, Any]],
    limit: int,
) -> dict[str, Any]:
    """OAuth-ish query/body parameter names (code, state, redirect_uri, …)."""
    hits: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    for qs in query_secrets:
        if _OAUTH_PARAM_RE.match(str(qs.get("name") or "")):
            key = (qs["entry_id"], qs["name"].lower())
            if key in seen:
                continue
            seen.add(key)
            hits.append({**qs, "kind": "oauth_query"})

    clauses = ["e.is_noise = 0"]
    params: list[Any] = []
    if host:
        clauses.append("e.host = ?")
        params.append(host.lower())
    # Path hints: /oauth, /authorize, /token, /callback
    rows = conn.execute(
        f"""
        SELECT e.entry_id, e.method, e.host, e.path, e.status, e.query_json
        FROM entries e
        WHERE {" AND ".join(clauses)}
          AND (
            lower(e.path) LIKE '%oauth%'
            OR lower(e.path) LIKE '%authorize%'
            OR lower(e.path) LIKE '%/token%'
            OR lower(e.path) LIKE '%callback%'
            OR lower(e.path) LIKE '%openid%'
          )
        ORDER BY e.entry_id ASC
        LIMIT 40
        """,
        params,
    ).fetchall()
    paths = [
        {
            "entry_id": r["entry_id"],
            "method": r["method"],
            "host": r["host"],
            "path": r["path"],
            "status": r["status"],
        }
        for r in rows
    ]
    for r in rows:
        try:
            query = json.loads(r["query_json"] or "{}")
        except (json.JSONDecodeError, TypeError):
            continue
        if not isinstance(query, dict):
            continue
        for name in query:
            if not _OAUTH_PARAM_RE.match(str(name)):
                continue
            key = (r["entry_id"], str(name).lower())
            if key in seen:
                continue
            seen.add(key)
            hits.append(
                {
                    "entry_id": r["entry_id"],
                    "method": r["method"],
                    "path": r["path"],
                    "side": "request",
                    "kind": "oauth_query",
                    "name": str(name),
                }
            )
            if len(hits) >= limit:
                break

    # Token requests carry code_verifier/grant_type/... in the POST body.
    for p in list(paths):
        if (p.get("method") or "").upper() == "POST":
            for name in _request_field_names(conn, int(p["entry_id"])):
                if _OAUTH_PARAM_RE.match(name) and (int(p["entry_id"]), name.lower()) not in seen:
                    seen.add((int(p["entry_id"]), name.lower()))
                    hits.append({"entry_id": p["entry_id"], "method": p["method"], "path": p["path"],
                                 "side": "request", "kind": "oauth_body", "name": name})
    # A 3xx whose Location carries code/id_token is the callback hop.
    for r in conn.execute(
        """
        SELECT e.entry_id, e.method, e.host, e.path, e.status, h.value_raw AS loc
        FROM entries e JOIN headers h ON h.entry_id = e.entry_id AND h.side = 'response'
        WHERE e.status BETWEEN 300 AND 399 AND lower(h.name) = 'location'
        ORDER BY e.entry_id LIMIT 200
        """
    ):
        try:
            names = {k.lower() for k, _ in parse_qsl(urlparse(r["loc"] or "").query or (r["loc"] or "").split("#", 1)[-1])}
        except ValueError:
            continue
        if not ({"code", "id_token", "access_token"} & names) or "error" in names and "code" not in names:
            continue
        for name in sorted(names & {"code", "state", "session_state", "id_token", "access_token"}):
            hits.append({"entry_id": r["entry_id"], "method": r["method"], "path": r["path"],
                         "side": "response", "kind": "oauth_redirect", "name": name})
        if not any(p["entry_id"] == r["entry_id"] for p in paths):
            paths.append({"entry_id": r["entry_id"], "method": r["method"], "host": r["host"],
                          "path": r["path"], "status": r["status"], "callback_redirect": True})
        else:
            for p in paths:
                if p["entry_id"] == r["entry_id"]:
                    p["callback_redirect"] = True

    flow = _oauth_flow_steps(paths, hits)
    return {
        "param_hits": hits[:limit],
        "paths": paths[:20],
        "param_names": sorted({h["name"] for h in hits}, key=str.lower),
        "flow": flow,
        "likely": bool(hits or paths),
    }


def _oauth_flow_steps(
    paths: list[dict[str, Any]],
    param_hits: list[dict[str, Any]],
) -> dict[str, Any]:
    """Stitch authorize → callback(code) → token when entry order allows."""
    params_by_entry: dict[int, set[str]] = {}
    for h in param_hits:
        eid = int(h["entry_id"])
        params_by_entry.setdefault(eid, set()).add(str(h["name"]).lower())

    steps: list[dict[str, Any]] = []
    for p in paths:
        path_l = (p.get("path") or "").lower()
        names = params_by_entry.get(int(p["entry_id"]), set())
        role = "oauth_other"
        if p.get("callback_redirect"):
            role = "callback"
        elif "authorize" in path_l or path_l.endswith("/auth") or "/oauth2/auth" in path_l:
            role = "authorize"
        elif "token" in path_l and "authorize" not in path_l:
            role = "token"
        elif "callback" in path_l or "redirect" in path_l:
            role = "callback"
        elif "code" in names and "state" in names:
            role = "callback"
        elif "code_challenge" in names or "code_verifier" in names:
            role = "pkce"
        elif "grant_type" in names or "refresh_token" in names:
            role = "token"
        steps.append(
            {
                "role": role,
                "entry_id": p["entry_id"],
                "method": p.get("method"),
                "path": p.get("path"),
                "status": p.get("status"),
                "params": sorted(names),
            }
        )

    roles = {s["role"] for s in steps}
    has_pkce = any("code_challenge" in s.get("params", []) or "code_verifier" in s.get("params", []) for s in steps) or "pkce" in roles
    return {
        "step_count": len(steps),
        "steps": steps[:20],
        "has_authorize": "authorize" in roles,
        "has_callback": "callback" in roles,
        "has_token": "token" in roles,
        "has_pkce": has_pkce,
        "stitched": ("authorize" in roles and ("callback" in roles or "token" in roles))
        or ("callback" in roles and "token" in roles),
    }


def _login_flow(
    conn: sqlite3.Connection,
    *,
    host: str | None,
    password_fields: list[dict[str, Any]],
    identity_fields: list[dict[str, Any]],
    auth: dict[str, Any],
    session_cookies: list[str],
    shapes: list[dict[str, Any]],
    oauth: dict[str, Any],
    webauthn_steps: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Hypothesize a login sequence from password posts → tokens/cookies."""
    steps: list[dict[str, Any]] = []
    cred_ids = sorted(
        {
            h["entry_id"]
            for h in password_fields
            if h.get("side") == "request"
            or h.get("kind") in {"query_param", "html_password"}
            # json/form keys count only on the request side: dummy-style APIs
            # echo "password" back in profile responses.
            or (h.get("kind") in {"json_key", "form_field"} and h.get("side") != "response")
        }
    )
    id_by_entry: dict[Any, str] = {}
    # Response-side names first so a request field (what the client sends) wins.
    for f in sorted(
        (f for f in identity_fields if f.get("paired_with_password")),
        key=lambda f: f.get("side") == "request",
    ):
        id_by_entry[f["entry_id"]] = f["name"]
    # Prefer POST/PUT credential submissions on auth-ish paths.
    for eid in cred_ids:
        row = conn.execute(
            "SELECT entry_id, method, host, path, status FROM entries "
            "WHERE entry_id = ?",
            (eid,),
        ).fetchone()
        if not row:
            continue
        is_submit = (row["method"] or "").upper() in {"POST", "PUT", "PATCH"}
        role = "credential_submit"
        if AUTH_PATH_RE.search(row["path"] or ""):
            role = "login_submit"
        if not is_submit:
            # A GET that merely contains a password input is the login *page*.
            role = "login_page"
        step: dict[str, Any] = {
            "role": role,
            "entry_id": row["entry_id"],
            "method": row["method"],
            "host": row["host"],
            "path": row["path"],
            "status": row["status"],
        }
        if eid in id_by_entry:
            step["identity_field"] = id_by_entry[eid]
        if is_submit:
            step.update(_submit_outcome(conn, row))
        steps.append(step)

    for tr in auth.get("token_response_entries") or []:
        if _request_had_authorization(conn, tr["entry_id"]):
            continue  # echo endpoint (e.g. /bearer): the client already held the token
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

    for wa in (webauthn_steps or [])[:6]:
        steps.append(wa)

    try:
        from hardly.core.challenges import detect_challenges

        for ch in detect_challenges(conn, host=host, limit=10)["auth_challenges"]:
            steps.append(
                {
                    "role": "auth_challenge",
                    "entry_id": ch["entry_id"],
                    "method": ch["method"],
                    "path": ch["path"],
                    "status": ch["status"],
                    "schemes": [s["scheme"] for s in ch["schemes"]],
                }
            )
            retry = ch.get("retried_with_credentials")
            if retry:
                steps.append(
                    {
                        "role": "auth_retry",
                        "entry_id": retry["entry_id"],
                        "method": ch["method"],
                        "path": ch["path"],
                        "status": retry["status"],
                    }
                )
    except Exception:  # noqa: BLE001 — challenge detection is additive
        pass

    for p in (oauth.get("paths") or [])[:10]:
        steps.append(
            {
                "role": "oauth_path",
                "entry_id": p["entry_id"],
                "method": p.get("method"),
                "path": p.get("path"),
                "status": p.get("status"),
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
        "identity_fields": [f["name"] for f in identity_fields[:10]],
        "oauth_likely": bool(oauth.get("likely")),
        "confidence": (
            "high"
            if cred_ids and (auth.get("token_response_count") or session_cookies)
            else "medium"
            if cred_ids or auth.get("auth_path_count") or oauth.get("likely")
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


def _anti_forgery_forms(
    conn: sqlite3.Connection, *, host: str | None, limit: int
) -> list[dict[str, Any]]:
    """Forms whose hidden fields use the token-name indirection pattern.

    Names and form actions only; token values are never read out.
    """
    from hardly.core.html_forms import extract_html_structure

    where = "e.is_noise = 0 AND sb.preview_text LIKE '%<form%'"
    params: list[Any] = []
    if host:
        where += " AND e.host = ?"
        params.append(host.lower())
    rows = conn.execute(
        f"""
        SELECT e.entry_id, e.scheme, e.host, e.path, sb.preview_text AS body
        FROM entries e
        JOIN bodies sb ON sb.entry_id = e.entry_id AND sb.side = 'response'
        WHERE {where}
        ORDER BY e.entry_id LIMIT 200
        """,
        params,
    ).fetchall()
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for row in rows:
        structure = extract_html_structure(
            row["body"], base_url=f"{row['scheme']}://{row['host']}{row['path']}"
        )
        for form in structure.get("forms") or []:
            pair = form.get("anti_forgery")
            if not pair:
                continue
            key = (form.get("action") or "", pair["name_field"], pair["token_field"])
            if key in seen:
                continue
            seen.add(key)
            out.append(
                {
                    "entry_id": row["entry_id"],
                    "action": form.get("action") or "",
                    "method": form.get("method") or "",
                    **pair,
                }
            )
            if len(out) >= limit:
                return out
    return out


# --- helpers added from live testing ---------------------------------------

_BODY_CSRF_RE = re.compile(
    r"^_?(token|csrf\w*|xsrf\w*|authenticity_token|csrfmiddlewaretoken|__requestverificationtoken|nonce)$", re.I
)
_SPA_ROOT_RE = re.compile(
    r"""<div[^>]+id=["'](root|app|__next|__nuxt)["']|<app-root|ng-app|__NEXT_DATA__|data-reactroot""", re.I
)


def _request_field_names(conn: sqlite3.Connection, entry_id: int) -> list[str]:
    """Top-level field names of a request body (form or JSON); never values."""
    row = conn.execute(
        "SELECT preview_text FROM bodies WHERE entry_id = ? AND side = 'request'", (entry_id,)
    ).fetchone()
    text = (row["preview_text"] if row else None) or ""
    text = text.strip()
    if not text:
        return []
    if text.startswith("{"):
        try:
            data = json.loads(text)
        except ValueError:
            return re.findall(r'"([^"\\]{1,60})"\s*:', text[:2000])[:40]
        return [str(k) for k in data][:40] if isinstance(data, dict) else []
    if "<" in text[:20]:
        return []
    return [k for k, _ in parse_qsl(text, keep_blank_values=True)][:40]


def _credential_post_csrf_names(conn: sqlite3.Connection, password_fields: list[dict[str, Any]]) -> list[str]:
    """Token-ish field names sent alongside the credentials (e.g. ``_token``)."""
    out: set[str] = set()
    for eid in {int(h["entry_id"]) for h in password_fields if h.get("entry_id") is not None}:
        for name in _request_field_names(conn, eid):
            if _BODY_CSRF_RE.match(name.split("$")[-1]):
                out.add(name)
    return sorted(out)


def _behavioral_session_cookies(
    conn: sqlite3.Connection, cookies: dict[str, Any], password_fields: list[dict[str, Any]]
) -> set[str]:
    """HttpOnly cookies first set by/after a credential POST are the session."""
    post_ids = [
        int(h["entry_id"])
        for h in password_fields
        if h.get("entry_id") is not None
    ]
    if not post_ids:
        return set()
    posts = conn.execute(
        f"SELECT entry_id FROM entries WHERE method IN ('POST','PUT','PATCH') AND entry_id IN ({','.join('?' * len(post_ids))})",
        post_ids,
    ).fetchall()
    if not posts:
        return set()
    first = min(int(r["entry_id"]) for r in posts)
    return {
        f["name"]
        for f in cookies.get("flags") or []
        if f.get("httponly") and int(f.get("entry_id") or 0) >= first and not _CSRF_RE.search(f["name"])
    }


def _submit_outcome(conn: sqlite3.Connection, row: sqlite3.Row) -> dict[str, Any]:
    """How a credential POST ended: redirect target path, rejection, or page."""
    status = int(row["status"] or 0)
    if 300 <= status < 400:
        loc = conn.execute(
            "SELECT value_raw FROM headers WHERE entry_id = ? AND side = 'response' AND lower(name) = 'location'",
            (row["entry_id"],),
        ).fetchone()
        target = urlparse((loc["value_raw"] if loc else "") or "").path or None
        return {"outcome": "redirect", **({"redirect_to": target} if target else {})}
    if status in (401, 403, 422, 429):
        return {"outcome": "rejected"}
    if 200 <= status < 300:
        ctype = conn.execute(
            "SELECT content_type FROM bodies WHERE entry_id = ? AND side = 'response'", (row["entry_id"],)
        ).fetchone()
        kind = (ctype["content_type"] or "").lower() if ctype else ""
        return {
            "outcome": "ok_json" if "json" in kind else "page_returned",
            **({"note": "200 HTML after a credential POST is often a failed login redisplayed; compare with a redirect"} if "html" in kind else {}),
        }
    return {"outcome": "unknown"}


def _aborted_entries(conn: sqlite3.Connection, *, host: str | None) -> dict[str, int]:
    total = conn.execute("SELECT COUNT(*) FROM entries").fetchone()[0]
    count = conn.execute("SELECT COUNT(*) FROM entries WHERE status IS NULL OR status <= 0").fetchone()[0]
    return {"count": int(count), "total": int(total)}


def _spa_login_suspected(conn: sqlite3.Connection, *, host: str | None, password_fields: list[dict[str, Any]]) -> bool:
    if password_fields:
        return False
    for row in conn.execute(
        """
        SELECT b.preview_text FROM entries e JOIN bodies b ON b.entry_id = e.entry_id AND b.side = 'response'
        WHERE e.status = 200 AND b.content_type LIKE '%html%' AND length(b.preview_text) BETWEEN 1 AND 12000
        ORDER BY e.entry_id LIMIT 40
        """
    ):
        text = row["preview_text"] or ""
        if _SPA_ROOT_RE.search(text) and "<form" not in text.lower():
            return True
    return False


_WEBAUTHN_OPTION_KEYS = {"challenge", "pubkeycredparams", "rp", "allowcredentials", "authenticatorselection", "excludecredentials", "rpid"}
_WEBAUTHN_RESPONSE_KEYS = {"clientdatajson", "attestationobject", "authenticatordata", "signature", "userhandle", "rawid"}


def _webauthn_signals(conn: sqlite3.Connection, *, host: str | None) -> dict[str, Any]:
    """Passkey/WebAuthn ceremony: option fetch (challenge…) and verify (clientDataJSON…)."""
    steps: list[dict[str, Any]] = []
    for row in conn.execute(
        """
        SELECT e.entry_id, e.method, e.path, e.status, b.side, b.preview_text
        FROM entries e JOIN bodies b ON b.entry_id = e.entry_id
        WHERE b.preview_text LIKE '%{%' AND (
            lower(b.preview_text) LIKE '%challenge%' OR lower(b.preview_text) LIKE '%clientdatajson%'
            OR lower(b.preview_text) LIKE '%attestationobject%' OR lower(b.preview_text) LIKE '%authenticatordata%')
        ORDER BY e.entry_id LIMIT 200
        """
    ):
        text = (row["preview_text"] or "")[:20000]
        keys = {k.lower() for k in re.findall(r'"([A-Za-z]{2,40})"\s*:', text)}
        opt = len(keys & _WEBAUTHN_OPTION_KEYS)
        resp = len(keys & _WEBAUTHN_RESPONSE_KEYS)
        if row["side"] == "response" and "challenge" in keys and opt >= 2:
            role = "webauthn_options"
        elif row["side"] == "request" and ("clientdatajson" in keys or "attestationobject" in keys or resp >= 2):
            role = "webauthn_verify"
        else:
            continue
        steps.append({"role": role, "entry_id": row["entry_id"], "method": row["method"],
                      "path": row["path"], "status": row["status"],
                      "fields": sorted(keys & (_WEBAUTHN_OPTION_KEYS | _WEBAUTHN_RESPONSE_KEYS))})
    return {
        "likely": bool(steps),
        "has_options": any(s["role"] == "webauthn_options" for s in steps),
        "has_verify": any(s["role"] == "webauthn_verify" for s in steps),
        "steps": steps[:10],
    }


def _request_had_authorization(conn: sqlite3.Connection, entry_id: int) -> bool:
    row = conn.execute(
        "SELECT 1 FROM headers WHERE entry_id = ? AND side = 'request' "
        "AND lower(name) IN ('authorization', 'proxy-authorization') LIMIT 1",
        (entry_id,),
    ).fetchone()
    return row is not None
