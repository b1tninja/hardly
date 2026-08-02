"""FastMCP server exposing hardly tools."""

from __future__ import annotations

import json
from typing import Any

from fastmcp import FastMCP

from hardly import session as sess
from hardly.session import resolve_path
from hardly.core.auth import detect_auth
from hardly.core.curl import entry_to_curl
from hardly.core.export_md import export_markdown
from hardly.core.export_openapi import export_openapi
from hardly.core.flows import get_flow
from hardly.core.probe import probe_entry
from hardly.index import query as q

mcp = FastMCP(
    "hardly",
    instructions=(
        "HAR analysis tools. Always open a HAR with hardly_open first, then use "
        "session_id with other tools. Responses are redacted and truncated — "
        "never read the raw HAR file into context."
    ),
)


def _ok(data: Any) -> str:
    return json.dumps(data, indent=2, default=str)


def _err(exc: Exception) -> str:
    return _ok({"error": str(exc)})


@mcp.tool
def hardly_open(har_path: str, force: bool = False) -> str:
    """Index a HAR file into a queryable session. Returns session_id and summary counts.

    Prefer this over reading the HAR directly. Reuses cache when the file is unchanged.
    """
    return _ok(sess.open_har(har_path, force=force))


@mcp.tool
def hardly_list_sessions() -> str:
    """List cached and currently open HAR sessions."""
    return _ok({"sessions": sess.list_sessions()})


@mcp.tool
def hardly_close(session_id: str) -> str:
    """Close an open session (cache file is kept on disk)."""
    return _ok(sess.close_session(session_id))


@mcp.tool
def hardly_summary(session_id: str) -> str:
    """Host, method, and status histograms for a session."""
    try:
        conn = sess.require_conn(session_id)
    except KeyError as exc:
        return _err(exc)
    return _ok(q.summary(conn))


@mcp.tool
def hardly_hosts(session_id: str, exclude_noise: bool = False) -> str:
    """List hosts with request counts."""
    try:
        conn = sess.require_conn(session_id)
    except KeyError as exc:
        return _err(exc)
    return _ok({"hosts": q.list_hosts(conn, exclude_noise=exclude_noise)})


@mcp.tool
def hardly_endpoints(
    session_id: str,
    host: str | None = None,
    exclude_noise: bool = True,
    limit: int = 100,
    offset: int = 0,
) -> str:
    """List grouped API endpoints (METHOD + path template) with counts."""
    try:
        conn = sess.require_conn(session_id)
    except KeyError as exc:
        return _err(exc)
    return _ok(
        q.list_endpoints(
            conn,
            host=host,
            exclude_noise=exclude_noise,
            limit=min(limit, 500),
            offset=offset,
        )
    )


@mcp.tool
def hardly_search(
    session_id: str,
    host: str | None = None,
    path_contains: str | None = None,
    method: str | None = None,
    status: int | None = None,
    body_contains: str | None = None,
    exclude_noise: bool = True,
    exclude_options: bool = True,
    limit: int = 50,
    offset: int = 0,
) -> str:
    """Search entries by host, path, method, status, or body text. Returns entry IDs."""
    try:
        conn = sess.require_conn(session_id)
    except KeyError as exc:
        return _err(exc)
    return _ok(
        q.search_entries(
            conn,
            host=host,
            path_contains=path_contains,
            method=method,
            status=status,
            body_contains=body_contains,
            exclude_noise=exclude_noise,
            exclude_options=exclude_options,
            limit=min(limit, 200),
            offset=offset,
        )
    )


@mcp.tool
def hardly_entry(session_id: str, entry_id: int, body_chars: int = 4000) -> str:
    """Get one entry with redacted headers and truncated bodies."""
    try:
        conn = sess.require_conn(session_id)
    except KeyError as exc:
        return _err(exc)
    return _ok(q.get_entry(conn, entry_id, body_chars=min(body_chars, 20000)))


@mcp.tool
def hardly_compare_entries(session_id: str, entry_id_a: int, entry_id_b: int) -> str:
    """Diff headers and JSON body keys between two entries."""
    try:
        conn = sess.require_conn(session_id)
    except KeyError as exc:
        return _err(exc)
    return _ok(q.compare_entries(conn, entry_id_a, entry_id_b))


@mcp.tool
def hardly_auth(session_id: str, host: str | None = None) -> str:
    """Detect auth-related paths, token responses, and auth headers for a host."""
    try:
        conn = sess.require_conn(session_id)
    except KeyError as exc:
        return _err(exc)
    return _ok(detect_auth(conn, host=host))


@mcp.tool
def hardly_flow(
    session_id: str,
    host: str | None = None,
    path_prefix: str | None = None,
    exclude_options: bool = True,
    exclude_noise: bool = True,
    limit: int = 100,
    offset: int = 0,
) -> str:
    """Chronological request flow (useful for login/MFA sequences)."""
    try:
        conn = sess.require_conn(session_id)
    except KeyError as exc:
        return _err(exc)
    return _ok(
        get_flow(
            conn,
            host=host,
            path_prefix=path_prefix,
            exclude_options=exclude_options,
            exclude_noise=exclude_noise,
            limit=min(limit, 500),
            offset=offset,
        )
    )


@mcp.tool
def hardly_schema(
    session_id: str,
    method: str,
    host: str,
    path_template: str,
    limit: int = 20,
) -> str:
    """Infer request/response JSON schemas for an endpoint template."""
    try:
        conn = sess.require_conn(session_id)
    except KeyError as exc:
        return _err(exc)
    return _ok(
        q.endpoint_schema(
            conn,
            method=method,
            host=host,
            path_template=path_template,
            limit=min(limit, 50),
        )
    )


@mcp.tool
def hardly_sql(session_id: str, sql: str, limit: int = 100) -> str:
    """Run a read-only SELECT against the session SQLite index."""
    try:
        conn = sess.require_conn(session_id)
    except KeyError as exc:
        return _err(exc)
    return _ok(q.run_sql(conn, sql, limit=min(limit, 500)))


@mcp.tool
def hardly_export_md(
    session_id: str,
    output_path: str,
    host: str | None = None,
    exclude_noise: bool = True,
    max_endpoints: int = 200,
) -> str:
    """Write a redacted API.md for endpoints in the session."""
    try:
        conn = sess.require_conn(session_id)
    except KeyError as exc:
        return _err(exc)
    return _ok(
        export_markdown(
            conn,
            resolve_path(output_path),
            host=host,
            exclude_noise=exclude_noise,
            max_endpoints=max_endpoints,
        )
    )


@mcp.tool
def hardly_export_openapi(
    session_id: str,
    output_path: str,
    host: str | None = None,
    exclude_noise: bool = True,
    title: str = "HAR-derived API",
) -> str:
    """Write an OpenAPI 3 document (JSON or YAML by extension)."""
    try:
        conn = sess.require_conn(session_id)
    except KeyError as exc:
        return _err(exc)
    return _ok(
        export_openapi(
            conn,
            resolve_path(output_path),
            host=host,
            exclude_noise=exclude_noise,
            title=title,
        )
    )


@mcp.tool
def hardly_curl(
    session_id: str,
    entry_id: int,
    redact: bool = True,
    use_env_placeholders: bool = True,
) -> str:
    """Generate a curl command for an entry (secrets redacted by default)."""
    try:
        conn = sess.require_conn(session_id)
    except KeyError as exc:
        return _err(exc)
    return _ok(
        entry_to_curl(
            conn,
            entry_id,
            redact=redact,
            use_env_placeholders=use_env_placeholders,
        )
    )


@mcp.tool
def hardly_probe(
    session_id: str,
    entry_id: int,
    confirm: bool = False,
    header_overrides_json: str | None = None,
    body_override: str | None = None,
    timeout: float = 30.0,
) -> str:
    """Replay a request live. Requires confirm=true. Sensitive HAR headers are skipped unless provided in header_overrides_json (JSON object)."""
    try:
        conn = sess.require_conn(session_id)
    except KeyError as exc:
        return _err(exc)
    overrides = None
    if header_overrides_json:
        try:
            overrides = json.loads(header_overrides_json)
        except json.JSONDecodeError as exc:
            return _err(exc)
    return _ok(
        probe_entry(
            conn,
            entry_id,
            confirm=confirm,
            header_overrides=overrides,
            body_override=body_override,
            timeout=timeout,
        )
    )


@mcp.prompt
def document_api(host: str) -> str:
    """Guide for documenting an API host from a loaded HAR."""
    return (
        f"Document the API for host `{host}` using hardly tools only "
        f"(do not read the HAR file). Steps:\n"
        "1. hardly_summary / hardly_endpoints(host=...)\n"
        "2. hardly_auth(host=...) and hardly_flow(host=...)\n"
        "3. hardly_entry / hardly_schema for important endpoints\n"
        "4. hardly_export_md to write API.md\n"
        "Keep responses redacted; prefer entry IDs over large bodies."
    )


@mcp.prompt
def find_auth_flow(host: str) -> str:
    """Guide for tracing login/MFA on a host."""
    return (
        f"Trace authentication for `{host}` with hardly tools:\n"
        "1. hardly_auth(host=...)\n"
        "2. hardly_flow(host=..., path_prefix=/login or similar)\n"
        "3. hardly_compare_entries on pre/post MFA login requests\n"
        "4. Note tokens in response bodies (Chrome may strip Authorization cookies)."
    )


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
