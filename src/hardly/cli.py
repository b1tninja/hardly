"""Command-line interface for hardly (non-MCP)."""

from __future__ import annotations

import argparse
import json
import sys

from hardly import session as sess
from hardly.core.auth import detect_auth
from hardly.core.export_md import export_markdown
from hardly.core.export_openapi import export_openapi
from hardly.index import query as q


def _print(data: object) -> None:
    print(json.dumps(data, indent=2, default=str))


def cmd_open(args: argparse.Namespace) -> int:
    result = sess.open_har(args.har, force=args.force)
    _print(result)
    return 0 if "error" not in result else 1


def cmd_summary(args: argparse.Namespace) -> int:
    result = sess.open_har(args.har)
    if "error" in result:
        _print(result)
        return 1
    conn = sess.require_conn(result["session_id"])
    _print(q.summary(conn))
    return 0


def cmd_endpoints(args: argparse.Namespace) -> int:
    result = sess.open_har(args.har)
    if "error" in result:
        _print(result)
        return 1
    conn = sess.require_conn(result["session_id"])
    _print(
        q.list_endpoints(
            conn,
            host=args.host,
            exclude_noise=not args.include_noise,
            limit=args.limit,
        )
    )
    return 0


def cmd_export_md(args: argparse.Namespace) -> int:
    result = sess.open_har(args.har)
    if "error" in result:
        _print(result)
        return 1
    conn = sess.require_conn(result["session_id"])
    _print(
        export_markdown(
            conn,
            args.output,
            host=args.host,
            exclude_noise=not args.include_noise,
        )
    )
    return 0


def cmd_export_openapi(args: argparse.Namespace) -> int:
    result = sess.open_har(args.har)
    if "error" in result:
        _print(result)
        return 1
    conn = sess.require_conn(result["session_id"])
    _print(
        export_openapi(
            conn,
            args.output,
            host=args.host,
            exclude_noise=not args.include_noise,
            title=args.title,
        )
    )
    return 0


def cmd_auth(args: argparse.Namespace) -> int:
    result = sess.open_har(args.har)
    if "error" in result:
        _print(result)
        return 1
    conn = sess.require_conn(result["session_id"])
    _print(detect_auth(conn, host=args.host))
    return 0


def cmd_serve(_args: argparse.Namespace) -> int:
    from hardly.server import main as server_main

    server_main()
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="hardly",
        description="HAR analysis — index, query, document, and probe APIs",
    )
    sub = p.add_subparsers(dest="command", required=True)

    open_p = sub.add_parser("open", help="Index a HAR file")
    open_p.add_argument("har")
    open_p.add_argument("--force", action="store_true")
    open_p.set_defaults(func=cmd_open)

    sum_p = sub.add_parser("summary", help="Summarize a HAR")
    sum_p.add_argument("har")
    sum_p.set_defaults(func=cmd_summary)

    ep_p = sub.add_parser("endpoints", help="List endpoints")
    ep_p.add_argument("har")
    ep_p.add_argument("--host")
    ep_p.add_argument("--include-noise", action="store_true")
    ep_p.add_argument("--limit", type=int, default=100)
    ep_p.set_defaults(func=cmd_endpoints)

    md_p = sub.add_parser("export-md", help="Export API.md")
    md_p.add_argument("har")
    md_p.add_argument("-o", "--output", required=True)
    md_p.add_argument("--host")
    md_p.add_argument("--include-noise", action="store_true")
    md_p.set_defaults(func=cmd_export_md)

    oa_p = sub.add_parser("export-openapi", help="Export OpenAPI")
    oa_p.add_argument("har")
    oa_p.add_argument("-o", "--output", required=True)
    oa_p.add_argument("--host")
    oa_p.add_argument("--title", default="HAR-derived API")
    oa_p.add_argument("--include-noise", action="store_true")
    oa_p.set_defaults(func=cmd_export_openapi)

    auth_p = sub.add_parser("auth", help="Detect auth patterns")
    auth_p.add_argument("har")
    auth_p.add_argument("--host")
    auth_p.set_defaults(func=cmd_auth)

    serve_p = sub.add_parser("serve", help="Run MCP server (stdio)")
    serve_p.set_defaults(func=cmd_serve)

    return p


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    code = args.func(args)
    sys.exit(code)


if __name__ == "__main__":
    main()
