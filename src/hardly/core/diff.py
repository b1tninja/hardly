"""Compare endpoint coverage between two HAR sessions."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any


def diff_sessions(
    conn_a: sqlite3.Connection,
    conn_b: sqlite3.Connection,
    *,
    host: str | None = None,
    exclude_noise: bool = True,
    credentials: bool = True,
    har_path_a: str | Path | None = None,
    har_path_b: str | Path | None = None,
) -> dict[str, Any]:
    """Diff path templates between two indexed sessions."""
    set_a = _endpoint_set(conn_a, host=host, exclude_noise=exclude_noise)
    set_b = _endpoint_set(conn_b, host=host, exclude_noise=exclude_noise)
    only_a = sorted(set_a - set_b)
    only_b = sorted(set_b - set_a)
    both = sorted(set_a & set_b)
    out: dict[str, Any] = {
        "host": host,
        "a_count": len(set_a),
        "b_count": len(set_b),
        "shared_count": len(both),
        "only_in_a": [
            {"method": m, "host": h, "path_template": p} for m, h, p in only_a[:80]
        ],
        "only_in_b": [
            {"method": m, "host": h, "path_template": p} for m, h, p in only_b[:80]
        ],
        "shared_sample": [
            {"method": m, "host": h, "path_template": p} for m, h, p in both[:20]
        ],
        "next": (
            "only_in_b are new since capture A — useful after a second "
            "recording that reached detail/search the first missed."
        ),
    }
    if credentials:
        out["credentials"] = diff_credentials(
            conn_a,
            conn_b,
            host=host,
            har_path_a=har_path_a,
            har_path_b=har_path_b,
        )
        if out["credentials"].get("changed"):
            out["next"] = (
                "Credentials/session material changed between A and B — see "
                "credentials.only_in_b / shapes. " + out["next"]
            )
    return out


def diff_credentials(
    conn_a: sqlite3.Connection,
    conn_b: sqlite3.Connection,
    *,
    host: str | None = None,
    har_path_a: str | Path | None = None,
    har_path_b: str | Path | None = None,
) -> dict[str, Any]:
    """Diff credential maps (names/shapes only) between two sessions."""
    from hardly.core.credentials import map_credentials

    a = map_credentials(conn_a, har_path=har_path_a, host=host, limit=40)
    b = map_credentials(conn_b, har_path=har_path_b, host=host, limit=40)

    def _names(rows: list[dict[str, Any]], key: str = "name") -> set[str]:
        return {str(r.get(key) or "").lower() for r in rows if r.get(key)}

    cookies_a = {c.lower() for c in (a.get("session_cookies") or [])}
    cookies_b = {c.lower() for c in (b.get("session_cookies") or [])}
    csrf_a = {c.lower() for c in (a.get("csrf_names") or [])}
    csrf_b = {c.lower() for c in (b.get("csrf_names") or [])}
    shapes_a = set((a.get("shapes_by_kind") or {}).keys())
    shapes_b = set((b.get("shapes_by_kind") or {}).keys())
    pwd_a = _names(a.get("password_fields") or [])
    pwd_b = _names(b.get("password_fields") or [])
    id_a = _names(a.get("identity_fields") or [])
    id_b = _names(b.get("identity_fields") or [])

    only_cookies_b = sorted(cookies_b - cookies_a)
    only_shapes_b = sorted(shapes_b - shapes_a)
    changed = bool(
        only_cookies_b
        or only_shapes_b
        or (pwd_b - pwd_a)
        or (id_b - id_a)
        or (csrf_b - csrf_a)
        or (a.get("login_flow") or {}).get("confidence")
        != (b.get("login_flow") or {}).get("confidence")
    )
    return {
        "changed": changed,
        "session_cookies": {
            "only_in_a": sorted(cookies_a - cookies_b),
            "only_in_b": only_cookies_b,
            "shared": sorted(cookies_a & cookies_b),
        },
        "csrf_names": {
            "only_in_a": sorted(csrf_a - csrf_b),
            "only_in_b": sorted(csrf_b - csrf_a),
            "shared": sorted(csrf_a & csrf_b),
        },
        "password_fields": {
            "only_in_a": sorted(pwd_a - pwd_b),
            "only_in_b": sorted(pwd_b - pwd_a),
            "shared": sorted(pwd_a & pwd_b),
        },
        "identity_fields": {
            "only_in_a": sorted(id_a - id_b),
            "only_in_b": sorted(id_b - id_a),
            "shared": sorted(id_a & id_b),
        },
        "shapes": {
            "only_in_a": sorted(shapes_a - shapes_b),
            "only_in_b": only_shapes_b,
            "shared": sorted(shapes_a & shapes_b),
            "counts_a": a.get("shapes_by_kind") or {},
            "counts_b": b.get("shapes_by_kind") or {},
        },
        "login_flow": {
            "confidence_a": (a.get("login_flow") or {}).get("confidence"),
            "confidence_b": (b.get("login_flow") or {}).get("confidence"),
            "steps_a": (a.get("login_flow") or {}).get("step_count"),
            "steps_b": (b.get("login_flow") or {}).get("step_count"),
        },
        "oauth_likely": {
            "a": bool((a.get("oauth") or {}).get("likely")),
            "b": bool((b.get("oauth") or {}).get("likely")),
        },
    }


def _endpoint_set(
    conn: sqlite3.Connection,
    *,
    host: str | None,
    exclude_noise: bool,
) -> set[tuple[str, str, str]]:
    clauses = ["method != 'OPTIONS'"]
    params: list[Any] = []
    if exclude_noise:
        clauses.append("is_noise = 0")
    if host:
        clauses.append("host = ?")
        params.append(host.lower())
    where = " AND ".join(clauses)
    rows = conn.execute(
        f"""
        SELECT DISTINCT method, host, path_template
        FROM entries
        WHERE {where}
        """,
        params,
    ).fetchall()
    return {(r["method"], r["host"], r["path_template"]) for r in rows}
