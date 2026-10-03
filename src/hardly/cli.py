"""Command-line interface for hardly (non-MCP)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

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


def cmd_reopen(args: argparse.Namespace) -> int:
    result = sess.reopen_session(args.session_id, force=args.force)
    _print(result)
    return 0 if "error" not in result else 1


def cmd_stats(args: argparse.Namespace) -> int:
    from hardly.core.stats import traffic_stats

    result = sess.open_har(args.har)
    if "error" in result:
        _print(result)
        return 1
    conn = sess.require_conn(result["session_id"])
    _print(
        traffic_stats(
            conn, host=args.host, exclude_noise=not args.include_noise
        )
    )
    return 0


def cmd_summary(args: argparse.Namespace) -> int:
    result = sess.open_har(args.har)
    if "error" in result:
        _print(result)
        return 1
    conn = sess.require_conn(result["session_id"])
    _print(q.summary(conn))
    return 0


def cmd_sessions(_args: argparse.Namespace) -> int:
    _print({"sessions": sess.list_sessions()})
    return 0


def cmd_hosts(args: argparse.Namespace) -> int:
    result = sess.open_har(args.har)
    if "error" in result:
        _print(result)
        return 1
    conn = sess.require_conn(result["session_id"])
    _print(
        {
            "hosts": q.list_hosts(conn, exclude_noise=not args.include_noise),
            "preferred_host": q.preferred_host(conn),
        }
    )
    return 0


def cmd_search(args: argparse.Namespace) -> int:
    result = sess.open_har(args.har)
    if "error" in result:
        _print(result)
        return 1
    conn = sess.require_conn(result["session_id"])
    _print(
        q.search_entries(
            conn,
            host=args.host,
            path_contains=args.path or None,
            method=args.method or None,
            status=args.status,
            body_contains=args.body or None,
            header_name=args.header_name or None,
            header_contains=args.header_contains or None,
            mime_contains=args.mime or None,
            content_kind=args.kind or None,
            exclude_noise=not args.include_noise,
            limit=args.limit,
        )
    )
    return 0


def cmd_entry(args: argparse.Namespace) -> int:
    result = sess.open_har(args.har)
    if "error" in result:
        _print(result)
        return 1
    conn = sess.require_conn(result["session_id"])
    _print(q.get_entry(conn, args.entry_id, body_chars=args.body_chars))
    return 0


def cmd_content(args: argparse.Namespace) -> int:
    from hardly.core.classify import summarize_content

    result = sess.open_har(args.har)
    if "error" in result:
        _print(result)
        return 1
    conn = sess.require_conn(result["session_id"])
    _print(
        summarize_content(
            conn,
            host=args.host,
            kind=args.kind or None,
            exclude_noise=not args.include_noise,
            limit=args.limit,
        )
    )
    return 0


def cmd_outline(args: argparse.Namespace) -> int:
    from hardly.core.outline import outline_entry

    result = sess.open_har(args.har)
    if "error" in result:
        _print(result)
        return 1
    conn = sess.require_conn(result["session_id"])
    out = outline_entry(
        conn,
        args.entry_id,
        format=args.format,
        max_depth=args.depth,
        side=args.side,
    )
    if args.markdown_only and out.get("markdown"):
        print(out["markdown"])
        return 0 if "error" not in out else 1
    _print(out)
    return 0 if "error" not in out else 1


def cmd_flow(args: argparse.Namespace) -> int:
    from hardly.core.flows import get_flow

    result = sess.open_har(args.har)
    if "error" in result:
        _print(result)
        return 1
    conn = sess.require_conn(result["session_id"])
    _print(
        get_flow(
            conn,
            host=args.host,
            path_prefix=args.path_prefix or None,
            exclude_noise=not args.include_noise,
            limit=args.limit,
        )
    )
    return 0


def cmd_schema(args: argparse.Namespace) -> int:
    result = sess.open_har(args.har)
    if "error" in result:
        _print(result)
        return 1
    conn = sess.require_conn(result["session_id"])
    _print(
        q.endpoint_schema(
            conn,
            method=args.method,
            host=args.host,
            path_template=args.path_template,
            limit=args.limit,
        )
    )
    return 0


def cmd_curl(args: argparse.Namespace) -> int:
    from hardly.core.curl import entry_to_curl

    result = sess.open_har(args.har)
    if "error" in result:
        _print(result)
        return 1
    conn = sess.require_conn(result["session_id"])
    _print(
        entry_to_curl(
            conn,
            args.entry_id,
            redact=not args.no_redact,
            use_env_placeholders=not args.no_env,
        )
    )
    return 0


def cmd_compare(args: argparse.Namespace) -> int:
    result = sess.open_har(args.har)
    if "error" in result:
        _print(result)
        return 1
    conn = sess.require_conn(result["session_id"])
    _print(q.compare_entries(conn, args.entry_a, args.entry_b))
    return 0


def cmd_probe(args: argparse.Namespace) -> int:
    from hardly.core.probe import probe_entry

    result = sess.open_har(args.har)
    if "error" in result:
        _print(result)
        return 1
    conn = sess.require_conn(result["session_id"])
    _print(
        probe_entry(
            conn,
            args.entry_id,
            confirm=args.yes,
            header_overrides={},
            body_override=None,
            timeout=args.timeout,
        )
    )
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


def cmd_brief(args: argparse.Namespace) -> int:
    from hardly.core.brief import portal_brief

    result = sess.open_har(args.har)
    if "error" in result:
        _print(result)
        return 1
    sid = result["session_id"]
    conn = sess.require_conn(sid)
    _print(
        portal_brief(
            conn,
            har_path=sess.get_har_path(sid),
            host=args.host,
        )
    )
    return 0


def cmd_story(args: argparse.Namespace) -> int:
    from hardly.core.story import portal_story

    result = sess.open_har(args.har)
    if "error" in result:
        _print(result)
        return 1
    conn = sess.require_conn(result["session_id"])
    _print(
        portal_story(
            conn,
            host=args.host,
            limit=args.limit,
            exclude_noise=not args.include_noise,
            include_related=not args.no_related,
        )
    )
    return 0


def cmd_stub(args: argparse.Namespace) -> int:
    from hardly.core.stub import client_stub

    result = sess.open_har(args.har)
    if "error" in result:
        _print(result)
        return 1
    conn = sess.require_conn(result["session_id"])
    ids = None
    if args.entry_ids:
        ids = [int(x) for x in args.entry_ids.split(",") if x.strip()]
    _print(
        client_stub(
            conn,
            entry_ids=ids,
            host=args.host,
            output_path=args.output or None,
            class_name=args.class_name,
        )
    )
    return 0


def cmd_correlate(args: argparse.Namespace) -> int:
    from hardly.core.correlate import correlate_tokens

    result = sess.open_har(args.har)
    if "error" in result:
        _print(result)
        return 1
    sid = result["session_id"]
    conn = sess.require_conn(sid)
    _print(
        correlate_tokens(
            conn,
            har_path=sess.get_har_path(sid),
            host=args.host,
            limit=args.limit,
        )
    )
    return 0


def cmd_cookies(args: argparse.Namespace) -> int:
    from hardly.core.cookies import cookie_timeline

    result = sess.open_har(args.har)
    if "error" in result:
        _print(result)
        return 1
    sid = result["session_id"]
    conn = sess.require_conn(sid)
    _print(
        cookie_timeline(
            conn,
            har_path=sess.get_har_path(sid),
            host=args.host,
            limit=args.limit,
        )
    )
    return 0


def cmd_diff(args: argparse.Namespace) -> int:
    from hardly.core.diff import diff_sessions

    a = sess.open_har(args.har_a)
    b = sess.open_har(args.har_b)
    if "error" in a:
        _print(a)
        return 1
    if "error" in b:
        _print(b)
        return 1
    _print(
        diff_sessions(
            sess.require_conn(a["session_id"]),
            sess.require_conn(b["session_id"]),
            host=args.host,
            exclude_noise=not args.include_noise,
            credentials=not getattr(args, "no_credentials", False),
            har_path_a=sess.get_har_path(a["session_id"]),
            har_path_b=sess.get_har_path(b["session_id"]),
        )
    )
    return 0


def cmd_find_search(args: argparse.Namespace) -> int:
    from hardly.core.search_nav import find_search_entry

    result = sess.open_har(args.har)
    if "error" in result:
        _print(result)
        return 1
    conn = sess.require_conn(result["session_id"])
    _print(
        find_search_entry(
            conn, host=args.host, keywords=args.keyword or [], limit=args.limit
        )
    )
    return 0


def cmd_grids(args: argparse.Namespace) -> int:
    from hardly.core.grids import detect_grids

    result = sess.open_har(args.har)
    if "error" in result:
        _print(result)
        return 1
    conn = sess.require_conn(result["session_id"])
    _print(detect_grids(conn, host=args.host, limit=args.limit))
    return 0


def cmd_challenges(args: argparse.Namespace) -> int:
    from hardly.core.challenges import detect_challenges

    result = sess.open_har(args.har)
    if "error" in result:
        _print(result)
        return 1
    conn = sess.require_conn(result["session_id"])
    _print(detect_challenges(conn, host=args.host, limit=args.limit))
    return 0


def cmd_data_attrs(args: argparse.Namespace) -> int:
    from hardly.core.data_attrs import scan_session

    result = sess.open_har(args.har)
    if "error" in result:
        _print(result)
        return 1
    conn = sess.require_conn(result["session_id"])
    _print(
        scan_session(
            conn, host=args.host, entry_id=args.entry_id, limit=args.limit
        )
    )
    return 0


def cmd_arcgis(args: argparse.Namespace) -> int:
    from hardly.core.arcgis import summarize_session

    result = sess.open_har(args.har)
    if "error" in result:
        _print(result)
        return 1
    conn = sess.require_conn(result["session_id"])
    _print(summarize_session(conn, host=args.host))
    return 0


def cmd_arcgis_explore(args: argparse.Namespace) -> int:
    from hardly.core.arcgis import explore

    out = explore(args.url, confirm=args.confirm)
    _print(out)
    return 1 if "error" in out else 0


def cmd_redirect_diag(args: argparse.Namespace) -> int:
    from hardly.core.redirect_diag import diagnose_redirects

    if not args.yes:
        _print({"error": "redirect-diag requires --yes (performs live GET requests)"})
        return 1
    _print(diagnose_redirects(args.url, max_hops=args.max_hops))
    return 0


def cmd_crawl(args: argparse.Namespace) -> int:
    from hardly.core.crawl import crawl

    if not args.yes:
        _print({"error": "crawl requires --yes (performs live GET requests)"})
        return 1
    result = crawl(
        args.url,
        tuple(args.keyword or ()),
        max_pages=args.max_pages,
        depth=args.depth,
        delay_s=args.delay,
        follow_external=args.follow_external,
        respect_robots=not args.ignore_robots,
        timeout_s=args.timeout,
    )
    _print(result)
    return 1 if "error" in result else 0



def cmd_replay_check(args: argparse.Namespace) -> int:
    from hardly.core.replay_check import replay_check

    if not args.yes:
        _print({"error": "replay-check requires --yes (sends live requests)"})
        return 1
    result = sess.open_har(args.har)
    if "error" in result:
        _print(result)
        return 1
    conn = sess.require_conn(result["session_id"])
    overrides = json.loads(args.overrides_json) if args.overrides_json else None
    _print(
        replay_check(
            conn,
            args.entry_ids,
            overrides=overrides,
            max_requests=args.max_requests,
            delay_s=args.delay,
            allow_unsafe=args.allow_unsafe,
        )
    )
    return 0


def cmd_stack(args: argparse.Namespace) -> int:
    from hardly.core.stack import fingerprint

    result = sess.open_har(args.har)
    if "error" in result:
        _print(result)
        return 1
    conn = sess.require_conn(result["session_id"])
    _print(fingerprint(conn, host=args.host, limit=args.limit))
    return 0


def cmd_auth_patterns(args: argparse.Namespace) -> int:
    from hardly.core.auth_patterns import detect_auth_patterns

    _print(detect_auth_patterns(args.har, host=args.host, kinds=args.kind or None))
    return 0


def cmd_tables(args: argparse.Namespace) -> int:
    from hardly.core.tables import scan_session

    result = sess.open_har(args.har)
    if "error" in result:
        _print(result)
        return 1
    conn = sess.require_conn(result["session_id"])
    _print(scan_session(conn, host=args.host, entry_id=args.entry_id))
    return 0


def cmd_gates(args: argparse.Namespace) -> int:
    from hardly.core.gates import classify_gates

    result = sess.open_har(args.har)
    if "error" in result:
        _print(result)
        return 1
    conn = sess.require_conn(result["session_id"])
    _print(classify_gates(conn, host=args.host))
    return 0


def cmd_recipe_plan(args: argparse.Namespace) -> int:
    from hardly.core.recipe_plan import recipe_from_story

    result = sess.open_har(args.har)
    if "error" in result:
        _print(result)
        return 1
    conn = sess.require_conn(result["session_id"])
    _print(
        recipe_from_story(
            conn,
            host=args.host,
            output_path=args.output or None,
            limit=args.limit,
        )
    )
    return 0


def cmd_redirects(args: argparse.Namespace) -> int:
    from hardly.core.redirects import redirect_chains

    result = sess.open_har(args.har)
    if "error" in result:
        _print(result)
        return 1
    conn = sess.require_conn(result["session_id"])
    _print(redirect_chains(conn, host=args.host, limit=args.limit))
    return 0


def cmd_issues(args: argparse.Namespace) -> int:
    from hardly.core.issues import find_issues

    result = sess.open_har(args.har)
    if "error" in result:
        _print(result)
        return 1
    conn = sess.require_conn(result["session_id"])
    _print(find_issues(conn, host=args.host, limit=args.limit))
    return 0


def cmd_trace(args: argparse.Namespace) -> int:
    from hardly.core.trace import trace_field

    result = sess.open_har(args.har)
    if "error" in result:
        _print(result)
        return 1
    sid = result["session_id"]
    conn = sess.require_conn(sid)
    _print(
        trace_field(
            conn,
            name=args.name or None,
            value=args.value or None,
            har_path=sess.get_har_path(sid),
            host=args.host,
            limit=args.limit,
        )
    )
    return 0


def cmd_secrets(args: argparse.Namespace) -> int:
    from hardly.core.secrets import locate_secrets

    result = sess.open_har(args.har)
    if "error" in result:
        _print(result)
        return 1
    conn = sess.require_conn(result["session_id"])
    _print(locate_secrets(conn, host=args.host, limit=args.limit))
    return 0


def cmd_credentials(args: argparse.Namespace) -> int:
    from hardly.core.credentials import map_credentials

    result = sess.open_har(args.har)
    if "error" in result:
        _print(result)
        return 1
    conn = sess.require_conn(result["session_id"])
    _print(
        map_credentials(
            conn,
            har_path=sess.get_har_path(result["session_id"]),
            host=args.host,
            limit=args.limit,
        )
    )
    return 0


def cmd_recommend(args: argparse.Namespace) -> int:
    from hardly.core.recommend import recommend_tools

    _print(recommend_tools(args.goal))
    return 0


def cmd_tree(args: argparse.Namespace) -> int:
    from hardly.core.tree import entry_tree

    result = sess.open_har(args.har)
    if "error" in result:
        _print(result)
        return 1
    conn = sess.require_conn(result["session_id"])
    _print(
        entry_tree(
            conn,
            args.entry_id,
            exclude_noise=not args.include_noise,
            child_limit=args.limit,
        )
    )
    return 0


def cmd_params(args: argparse.Namespace) -> int:
    from hardly.core.params import param_variance

    result = sess.open_har(args.har)
    if "error" in result:
        _print(result)
        return 1
    conn = sess.require_conn(result["session_id"])
    _print(
        param_variance(
            conn,
            method=args.method,
            host=args.host,
            path_template=args.path_template,
            limit=args.limit,
        )
    )
    return 0


def cmd_graphql(args: argparse.Namespace) -> int:
    from hardly.core.graphql import detect_graphql

    result = sess.open_har(args.har)
    if "error" in result:
        _print(result)
        return 1
    conn = sess.require_conn(result["session_id"])
    _print(detect_graphql(conn, host=args.host, limit=args.limit))
    return 0


def cmd_duplicates(args: argparse.Namespace) -> int:
    from hardly.core.duplicates import find_duplicates

    result = sess.open_har(args.har)
    if "error" in result:
        _print(result)
        return 1
    conn = sess.require_conn(result["session_id"])
    _print(
        find_duplicates(
            conn,
            host=args.host,
            exclude_noise=not args.include_noise,
            min_count=args.min_count,
            limit=args.limit,
        )
    )
    return 0


def cmd_slow(args: argparse.Namespace) -> int:
    from hardly.core.slow import slowest_entries

    result = sess.open_har(args.har)
    if "error" in result:
        _print(result)
        return 1
    conn = sess.require_conn(result["session_id"])
    _print(
        slowest_entries(
            conn,
            host=args.host,
            exclude_noise=not args.include_noise,
            limit=args.limit,
            min_ms=args.min_ms,
        )
    )
    return 0


def cmd_wall(args: argparse.Namespace) -> int:
    from hardly.core.wall import detect_walls

    result = sess.open_har(args.har)
    if "error" in result:
        _print(result)
        return 1
    conn = sess.require_conn(result["session_id"])
    _print(detect_walls(conn, host=args.host, limit=args.limit))
    return 0


def cmd_pages(args: argparse.Namespace) -> int:
    from hardly.core.pages import list_pages

    result = sess.open_har(args.har)
    if "error" in result:
        _print(result)
        return 1
    conn = sess.require_conn(result["session_id"])
    _print(
        list_pages(
            conn,
            host=args.host,
            exclude_noise=not args.include_noise,
            limit=args.limit,
        )
    )
    return 0


def cmd_export_brief(args: argparse.Namespace) -> int:
    from hardly.core.export_brief import export_brief_md

    result = sess.open_har(args.har)
    if "error" in result:
        _print(result)
        return 1
    sid = result["session_id"]
    conn = sess.require_conn(sid)
    _print(
        export_brief_md(
            conn,
            args.output,
            har_path=sess.get_har_path(sid),
            host=args.host,
        )
    )
    return 0


def cmd_export_postman(args: argparse.Namespace) -> int:
    from hardly.core.export_postman import export_postman

    result = sess.open_har(args.har)
    if "error" in result:
        _print(result)
        return 1
    conn = sess.require_conn(result["session_id"])
    _print(
        export_postman(
            conn,
            args.output,
            host=args.host,
            exclude_noise=not args.include_noise,
            name=args.name,
        )
    )
    return 0


def cmd_capabilities(_args: argparse.Namespace) -> int:
    from hardly.capabilities import capabilities

    _print(capabilities())
    return 0


def cmd_modes(args: argparse.Namespace) -> int:
    from hardly.core.modes import list_modes, mode_playbook, pick_mode

    mode = (getattr(args, "mode", None) or "").strip()
    if mode:
        _print(
            mode_playbook(
                mode,
                har_path=getattr(args, "har", "") or "",
                url=getattr(args, "url", "") or "",
                goal=getattr(args, "goal", "") or "",
            )
        )
        return 0
    if getattr(args, "goal", None) or getattr(args, "har", None) or getattr(
        args, "url", None
    ):
        _print(
            pick_mode(
                goal=getattr(args, "goal", "") or "",
                har_path=getattr(args, "har", "") or "",
                url=getattr(args, "url", "") or "",
            )
        )
        return 0
    _print(list_modes())
    return 0


def cmd_soak_live(args: argparse.Namespace) -> int:
    """Headless soak against public tech demos (captures HARs on the fly)."""
    from hardly.soak_live import main as soak_main

    argv: list[str] = []
    if getattr(args, "list", False):
        argv.append("--list")
    if getattr(args, "ids", "") or "":
        argv.extend(["--ids", args.ids])
    if getattr(args, "fail_soft", False):
        argv.append("--fail-soft")
    if getattr(args, "json", False):
        argv.append("--json")
    if getattr(args, "write_fixtures", "") or "":
        argv.extend(["--write-fixtures", args.write_fixtures])
    return soak_main(argv)


def cmd_help(args: argparse.Namespace) -> int:
    from hardly.core.help import tool_help

    _print(tool_help(args.topic or None))
    return 0


def cmd_coverage(args: argparse.Namespace) -> int:
    result = sess.open_har(args.har)
    if "error" in result:
        _print(result)
        return 1
    conn = sess.require_conn(result["session_id"])
    _print(
        q.body_coverage(
            conn,
            host=args.host,
            exclude_noise=not args.include_noise,
            limit=args.limit,
        )
    )
    return 0


def cmd_forms(args: argparse.Namespace) -> int:
    result = sess.open_har(args.har)
    if "error" in result:
        _print(result)
        return 1
    conn = sess.require_conn(result["session_id"])
    if args.entry_id is not None:
        _print(q.forms_for_entry(conn, args.entry_id, side=args.side))
    else:
        _print(
            q.list_forms(
                conn,
                host=args.host,
                side=args.side,
                exclude_noise=args.exclude_noise,
                limit=args.limit,
            )
        )
    return 0


def cmd_ui(args: argparse.Namespace) -> int:
    """Same inventory as forms; CLI alias for link/handler-first use."""
    return cmd_forms(args)


def cmd_routes(args: argparse.Namespace) -> int:
    result = sess.open_har(args.har)
    if "error" in result:
        _print(result)
        return 1
    conn = sess.require_conn(result["session_id"])
    _print(q.list_js_routes(conn, host=args.host, limit=args.limit))
    return 0


def cmd_around(args: argparse.Namespace) -> int:
    result = sess.open_har(args.har)
    if "error" in result:
        _print(result)
        return 1
    conn = sess.require_conn(result["session_id"])
    _print(
        q.entries_around(
            conn,
            args.entry_id,
            before=args.before,
            after=args.after,
            exclude_noise=not args.include_noise,
            host=args.host,
        )
    )
    return 0


def cmd_serve(_args: argparse.Namespace) -> int:
    from hardly.server import main as server_main

    server_main()
    return 0


def cmd_capture(args: argparse.Namespace) -> int:
    from hardly.capture import (
        CaptureError,
        capture_aria_snapshot,
        capture_for,
        capture_interactive,
        capture_page_url,
        capture_screenshot,
        click_capture,
        discover_apis,
        fill_capture,
        get_capture,
        list_capture_elements,
        list_captures,
        navigate_capture,
        press_capture,
        start_capture,
        stop_capture,
    )

    if not hasattr(args, "url"):
        args.url = ""
    action = getattr(args, "capture_action", None) or "run"
    try:
        if action == "list":
            _print({"captures": list_captures()})
            return 0
        if action == "status":
            _print(get_capture(args.capture_id))
            return 0
        if action == "stop":
            _print(
                stop_capture(
                    args.capture_id or None,
                    open_session=not args.no_open,
                )
            )
            return 0
        if action == "goto":
            _print(navigate_capture(args.capture_id or None, args.url))
            return 0
        if action == "elements":
            _print(
                list_capture_elements(
                    args.capture_id or None,
                    limit=args.limit,
                    query=args.query or "",
                )
            )
            return 0
        if action == "aria":
            _print(
                capture_aria_snapshot(
                    args.capture_id or None,
                    selector=getattr(args, "selector", "") or "",
                    mode=getattr(args, "mode", "") or "ai",
                )
            )
            return 0
        if action == "doctor":
            from hardly.capture import playwright_status

            _print(playwright_status())
            return 0
        if action == "screenshot":
            _print(
                capture_screenshot(
                    args.capture_id or None,
                    path=getattr(args, "path", "") or "",
                    full_page=bool(getattr(args, "full_page", False)),
                )
            )
            return 0
        if action == "click":
            _print(
                click_capture(
                    args.capture_id or None,
                    ref=getattr(args, "ref", "") or "",
                    xpath=args.xpath or "",
                    css=args.css or "",
                    text=args.text or "",
                    role=args.role or "",
                    name=args.name or "",
                )
            )
            return 0
        if action == "fill":
            _print(
                fill_capture(
                    args.capture_id or None,
                    value=args.value,
                    ref=getattr(args, "ref", "") or "",
                    xpath=args.xpath or "",
                    css=args.css or "",
                )
            )
            return 0
        if action == "press":
            _print(
                press_capture(
                    args.capture_id or None,
                    key=args.key or "Enter",
                    ref=getattr(args, "ref", "") or "",
                    xpath=args.xpath or "",
                    css=args.css or "",
                )
            )
            return 0
        if action == "url":
            _print(capture_page_url(args.capture_id or None))
            return 0
        if action == "recipe":
            from hardly.capture import run_capture_recipe

            steps = json.loads(Path(args.steps_file).read_text(encoding="utf-8"))
            _print(
                run_capture_recipe(
                    steps,
                    capture_id=args.capture_id or None,
                    stop_on_error=not args.continue_on_error,
                )
            )
            return 0
        if action == "discover":
            steps = None
            recipe_file = getattr(args, "recipe", "") or ""
            if recipe_file:
                steps = json.loads(Path(recipe_file).read_text(encoding="utf-8"))
            _print(
                discover_apis(
                    args.url,
                    args.output,
                    recipe=steps,
                    wait_seconds=float(
                        args.wait if getattr(args, "wait", None) is not None else 5
                    ),
                    channel=args.channel or "",
                    url_filter=args.url_filter or "",
                    omit_content=args.omit_content,
                    label=args.label or "",
                    open_session=not getattr(args, "no_open", False),
                    brief=not getattr(args, "no_brief", False),
                    same_tab=not getattr(args, "allow_popups", False),
                    trace=True if getattr(args, "trace", False) else None,
                    budget_seconds=getattr(args, "budget", None),
                    block_noise=bool(getattr(args, "block_noise", False)),
                )
            )
            return 0
        same_tab = not getattr(args, "allow_popups", False)
        use_trace = True if getattr(args, "trace", False) else None
        if action == "start":
            _print(
                start_capture(
                    args.url or "",
                    args.output,
                    headed=not args.headless,
                    channel=args.channel or "",
                    url_filter=args.url_filter or "",
                    omit_content=args.omit_content,
                    label=args.label or "",
                    user_data_dir=args.profile or None,
                    same_tab=same_tab,
                    trace=use_trace,
                    slot_timeout_s=getattr(args, "slot_timeout", None),
                )
            )
            return 0
        # Default: interactive or timed run
        if args.wait is not None:
            result = capture_for(
                args.url or "",
                args.output,
                wait_seconds=args.wait,
                headed=not args.headless,
                channel=args.channel or "",
                url_filter=args.url_filter or "",
                omit_content=args.omit_content,
                label=args.label or "",
                open_session=not args.no_open,
                same_tab=same_tab,
                trace=use_trace,
                budget_seconds=getattr(args, "budget", None),
                block_noise=bool(getattr(args, "block_noise", False)),
            )
        else:
            result = capture_interactive(
                args.url or "",
                args.output,
                headed=not args.headless,
                channel=args.channel or "",
                url_filter=args.url_filter or "",
                omit_content=args.omit_content,
                label=args.label or "",
                user_data_dir=args.profile or None,
                same_tab=same_tab,
                trace=use_trace,
            )
    except CaptureError as exc:
        _print({"error": str(exc)})
        return 1
    _print(result)
    return 0 if result.get("status") in ("stopped", "running", "starting") else 1


def _add_capture_flags(
    p: argparse.ArgumentParser, *, url: bool = True, url_default: Any = ""
) -> None:
    # discover declares its own required url; a second optional positional of
    # the same dest would silently overwrite it with "". The parent ``capture``
    # parser passes SUPPRESS so its default never clobbers a subcommand's url.
    if url:
        p.add_argument("url", nargs="?", default=url_default, help="Start URL (optional)")
    p.add_argument(
        "--budget",
        type=float,
        default=None,
        metavar="SECONDS",
        help="Hard per-call budget (headless): skip remaining recipe steps once "
        "exceeded (env HARDLY_CAPTURE_BUDGET)",
    )
    p.add_argument(
        "--block-noise",
        action="store_true",
        help="Headless: abort analytics/ads/fonts/map tiles/heavy media",
    )
    p.add_argument(
        "--slot-timeout",
        type=float,
        default=None,
        metavar="SECONDS",
        help="Max wait for a capture slot (env HARDLY_CAPTURE_SLOT_TIMEOUT, default 300)",
    )
    p.add_argument(
        "-o",
        "--output",
        help="HAR output path (default: ~/.cache/hardly/captures/...)",
    )
    p.add_argument(
        "--wait",
        type=float,
        default=None,
        help="Seconds to record then stop (default: wait for Enter / window close)",
    )
    p.add_argument(
        "--headless",
        action="store_true",
        help="Run without a visible window (scripted waits only)",
    )
    p.add_argument(
        "--channel",
        default="",
        help='Use installed browser: "chrome" or "msedge" (or HARDLY_BROWSER_CHANNEL)',
    )
    p.add_argument(
        "--url-filter",
        default="",
        help='Playwright glob for HAR entries (e.g. "**/AjaxPresentor.aspx*")',
    )
    p.add_argument(
        "--omit-content",
        action="store_true",
        help="Omit response bodies from the HAR (smaller file)",
    )
    p.add_argument("--label", default="", help="Filename label when -o is omitted")
    p.add_argument(
        "--profile",
        default="",
        help="Persistent browser profile directory (keeps cookies)",
    )
    p.add_argument(
        "--allow-popups",
        action="store_true",
        help="Allow real popup windows (default: force same-tab navigation)",
    )
    p.add_argument(
        "--trace",
        action="store_true",
        help="Write Playwright .trace.zip beside the HAR (or HARDLY_CAPTURE_TRACE=1)",
    )
    p.add_argument(
        "--no-open",
        action="store_true",
        help="Do not index the HAR into a hardly session after stop",
    )


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="hardly",
        description="HAR analysis - index, query, document, and probe APIs",
    )
    sub = p.add_subparsers(dest="command", required=True)

    caps_p = sub.add_parser(
        "capabilities",
        help="Show version / features (detect stale MCP installs)",
    )
    caps_p.set_defaults(func=cmd_capabilities)

    modes_p = sub.add_parser(
        "modes",
        help="List operating modes (archive / headless / interactive)",
    )
    modes_p.add_argument(
        "mode",
        nargs="?",
        default="",
        help="archive | headless | interactive (optional playbook)",
    )
    modes_p.add_argument("--goal", default="", help="Free-text goal for auto-pick")
    modes_p.add_argument("--har", default="", help="Existing HAR path hint")
    modes_p.add_argument("--url", default="", help="Target URL hint")
    modes_p.set_defaults(func=cmd_modes)

    soak_live_p = sub.add_parser(
        "soak-live",
        help="Headless soak: capture public tech demos on the fly (needs [capture])",
    )
    soak_live_p.add_argument(
        "--ids",
        default="",
        help="Comma-separated target ids (default: all); use --list",
    )
    soak_live_p.add_argument(
        "--list",
        action="store_true",
        help="Print the public target catalog and exit",
    )
    soak_live_p.add_argument(
        "--fail-soft",
        action="store_true",
        help="Treat soft targets (GraphQL UI, Swagger) as hard failures",
    )
    soak_live_p.add_argument(
        "--json",
        action="store_true",
        help="Print full JSON summary only",
    )
    soak_live_p.add_argument(
        "--write-fixtures",
        default="",
        help="Write small redacted HTML/JSON snippets from successful captures",
    )
    soak_live_p.set_defaults(func=cmd_soak_live)

    help_p = sub.add_parser(
        "help-tools",
        help="Categorized tool catalog (topic optional)",
    )
    help_p.add_argument(
        "topic",
        nargs="?",
        default="",
        help="portal | tokens | capture | tool name substring",
    )
    help_p.set_defaults(func=cmd_help)

    open_p = sub.add_parser("open", help="Index a HAR file")
    open_p.add_argument("har")
    open_p.add_argument("--force", action="store_true")
    open_p.set_defaults(func=cmd_open)

    reopen_p = sub.add_parser(
        "reopen",
        help="Reattach a cached session by session_id",
    )
    reopen_p.add_argument("session_id")
    reopen_p.add_argument("--force", action="store_true")
    reopen_p.set_defaults(func=cmd_reopen)

    stats_p = sub.add_parser(
        "stats",
        help="MIME / status / size / initiator stats",
    )
    stats_p.add_argument("har")
    stats_p.add_argument("--host")
    stats_p.add_argument("--include-noise", action="store_true")
    stats_p.set_defaults(func=cmd_stats)

    sum_p = sub.add_parser("summary", help="Summarize a HAR")
    sum_p.add_argument("har")
    sum_p.set_defaults(func=cmd_summary)

    sessions_p = sub.add_parser("sessions", help="List cached / open sessions")
    sessions_p.set_defaults(func=cmd_sessions)

    hosts_p = sub.add_parser("hosts", help="List hosts in a HAR")
    hosts_p.add_argument("har")
    hosts_p.add_argument("--include-noise", action="store_true")
    hosts_p.set_defaults(func=cmd_hosts)

    search_p = sub.add_parser("search", help="Search entries")
    search_p.add_argument("har")
    search_p.add_argument("--host")
    search_p.add_argument("--path", default="", help="Path substring")
    search_p.add_argument("--method", default="")
    search_p.add_argument("--status", type=int)
    search_p.add_argument("--body", default="", help="Body substring")
    search_p.add_argument("--header-name", default="")
    search_p.add_argument("--header-contains", default="")
    search_p.add_argument("--mime", default="")
    search_p.add_argument(
        "--kind",
        default="",
        help="Content kind: json, jsonl, jsonp, csv, html_table, pdf, image, …",
    )
    search_p.add_argument("--include-noise", action="store_true")
    search_p.add_argument("--limit", type=int, default=50)
    search_p.set_defaults(func=cmd_search)

    entry_p = sub.add_parser("entry", help="Show one entry (redacted)")
    entry_p.add_argument("har")
    entry_p.add_argument("entry_id", type=int)
    entry_p.add_argument("--body-chars", type=int, default=4000)
    entry_p.set_defaults(func=cmd_entry)

    content_p = sub.add_parser(
        "content",
        help="Classify response kinds (json/jsonl/csv/html_table/pdf/image/…)",
    )
    content_p.add_argument("har")
    content_p.add_argument("--host")
    content_p.add_argument(
        "--kind",
        default="",
        help="Filter: json, jsonl, jsonp, csv, html_table, pdf, image, …",
    )
    content_p.add_argument("--limit", type=int, default=80)
    content_p.add_argument("--include-noise", action="store_true")
    content_p.set_defaults(func=cmd_content)

    outline_p = sub.add_parser(
        "outline",
        help="HTML/XML document outline from an entry (markdown/tree/aria)",
    )
    outline_p.add_argument("har")
    outline_p.add_argument("entry_id", type=int)
    outline_p.add_argument(
        "--format",
        default="all",
        choices=("all", "markdown", "tree", "aria"),
    )
    outline_p.add_argument("--depth", type=int, default=8)
    outline_p.add_argument("--side", default="response")
    outline_p.add_argument(
        "--markdown-only",
        action="store_true",
        help="Print markdown outline to stdout (not JSON)",
    )
    outline_p.set_defaults(func=cmd_outline)

    flow_p = sub.add_parser("flow", help="Chronological request flow")
    flow_p.add_argument("har")
    flow_p.add_argument("--host")
    flow_p.add_argument("--path-prefix", default="")
    flow_p.add_argument("--include-noise", action="store_true")
    flow_p.add_argument("--limit", type=int, default=100)
    flow_p.set_defaults(func=cmd_flow)

    schema_p = sub.add_parser("schema", help="Infer JSON schema for an endpoint")
    schema_p.add_argument("har")
    schema_p.add_argument("method")
    schema_p.add_argument("host")
    schema_p.add_argument("path_template")
    schema_p.add_argument("--limit", type=int, default=20)
    schema_p.set_defaults(func=cmd_schema)

    curl_p = sub.add_parser("curl", help="Generate curl for an entry")
    curl_p.add_argument("har")
    curl_p.add_argument("entry_id", type=int)
    curl_p.add_argument("--no-redact", action="store_true")
    curl_p.add_argument("--no-env", action="store_true")
    curl_p.set_defaults(func=cmd_curl)

    compare_p = sub.add_parser("compare", help="Compare two entries")
    compare_p.add_argument("har")
    compare_p.add_argument("entry_a", type=int)
    compare_p.add_argument("entry_b", type=int)
    compare_p.set_defaults(func=cmd_compare)

    probe_p = sub.add_parser(
        "probe",
        help="Live replay an entry (requires --yes)",
    )
    probe_p.add_argument("har")
    probe_p.add_argument("entry_id", type=int)
    probe_p.add_argument("--yes", action="store_true", help="Confirm live request")
    probe_p.add_argument("--timeout", type=float, default=30.0)
    probe_p.set_defaults(func=cmd_probe)

    cov_p = sub.add_parser(
        "coverage",
        help="Body preview coverage (empty / truncated / size=-1)",
    )
    cov_p.add_argument("har")
    cov_p.add_argument("--host")
    cov_p.add_argument("--include-noise", action="store_true")
    cov_p.add_argument("--limit", type=int, default=20)
    cov_p.set_defaults(func=cmd_coverage)

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

    pm_p = sub.add_parser("export-postman", help="Export Postman Collection v2.1")
    pm_p.add_argument("har")
    pm_p.add_argument("-o", "--output", required=True)
    pm_p.add_argument("--host")
    pm_p.add_argument("--name", default="HAR-derived API")
    pm_p.add_argument("--include-noise", action="store_true")
    pm_p.set_defaults(func=cmd_export_postman)

    eb_p = sub.add_parser("export-brief", help="Export portal brief Markdown")
    eb_p.add_argument("har")
    eb_p.add_argument("-o", "--output", required=True)
    eb_p.add_argument("--host")
    eb_p.set_defaults(func=cmd_export_brief)

    auth_p = sub.add_parser("auth", help="Detect auth patterns")
    auth_p.add_argument("har")
    auth_p.add_argument("--host")
    auth_p.set_defaults(func=cmd_auth)

    brief_p = sub.add_parser(
        "brief",
        help="One-shot portal RE brief (story+forms+correlate+...)",
    )
    brief_p.add_argument("har")
    brief_p.add_argument("--host")
    brief_p.set_defaults(func=cmd_brief)

    story_p = sub.add_parser(
        "story",
        help="Annotated portal steps (roles, forms, labels)",
    )
    story_p.add_argument("har")
    story_p.add_argument("--host")
    story_p.add_argument("--limit", type=int, default=40)
    story_p.add_argument("--include-noise", action="store_true")
    story_p.add_argument(
        "--no-related",
        action="store_true",
        help="Do not merge same-apex API hosts (SPA app.* + api.*)",
    )
    story_p.set_defaults(func=cmd_story)

    stub_p = sub.add_parser(
        "stub",
        help="Generate a minimal urllib client sketch",
    )
    stub_p.add_argument("har")
    stub_p.add_argument("--host")
    stub_p.add_argument(
        "--entry-ids",
        default="",
        help="Comma-separated entry ids (default: from story)",
    )
    stub_p.add_argument("-o", "--output", help="Write .py to this path")
    stub_p.add_argument("--class-name", default="PortalClient")
    stub_p.set_defaults(func=cmd_stub)

    corr_p = sub.add_parser(
        "correlate",
        help="Find CSRF/session values reused across requests",
    )
    corr_p.add_argument("har")
    corr_p.add_argument("--host")
    corr_p.add_argument("--limit", type=int, default=40)
    corr_p.set_defaults(func=cmd_correlate)

    cookies_p = sub.add_parser(
        "cookies",
        help="Cookie name timeline (values omitted)",
    )
    cookies_p.add_argument("har")
    cookies_p.add_argument("--host")
    cookies_p.add_argument("--limit", type=int, default=60)
    cookies_p.set_defaults(func=cmd_cookies)

    diff_p = sub.add_parser(
        "diff",
        help="Compare endpoint templates (and credentials) between two HARs",
    )
    diff_p.add_argument("har_a")
    diff_p.add_argument("har_b")
    diff_p.add_argument("--host")
    diff_p.add_argument("--include-noise", action="store_true")
    diff_p.add_argument(
        "--no-credentials",
        action="store_true",
        help="Skip credentials/session map diff",
    )
    diff_p.set_defaults(func=cmd_diff)

    challenges_p = sub.add_parser(
        "challenges",
        help="Auth challenges, throttling/lockout, captcha widgets",
    )
    challenges_p.add_argument("har")
    challenges_p.add_argument("--host")
    challenges_p.add_argument("--limit", type=int, default=20)
    challenges_p.set_defaults(func=cmd_challenges)

    data_attrs_p = sub.add_parser(
        "data-attrs",
        help="Interpret HTML data-* attributes (dataset keys, endpoints, JSON, frameworks)",
    )
    data_attrs_p.add_argument("har")
    data_attrs_p.add_argument("--host")
    data_attrs_p.add_argument("--entry-id", type=int)
    data_attrs_p.add_argument("--limit", type=int, default=20)
    data_attrs_p.set_defaults(func=cmd_data_attrs)

    arcgis_p = sub.add_parser("arcgis", help="ArcGIS REST endpoints seen in a HAR")
    arcgis_p.add_argument("har")
    arcgis_p.add_argument("--host")
    arcgis_p.set_defaults(func=cmd_arcgis)

    arcgis_x = sub.add_parser("arcgis-explore", help="Live ArcGIS service exploration (needs --confirm)")
    arcgis_x.add_argument("url")
    arcgis_x.add_argument("--confirm", action="store_true")
    arcgis_x.set_defaults(func=cmd_arcgis_explore)

    rd_p = sub.add_parser(
        "redirect-diag",
        help="Diagnose a redirect loop / ERR_TOO_MANY_RETRIES (live GETs; requires --yes)",
    )
    rd_p.add_argument("url")
    rd_p.add_argument("--max-hops", type=int, default=12)
    rd_p.add_argument("--yes", action="store_true", help="Confirm live requests")
    rd_p.set_defaults(func=cmd_redirect_diag)

    crawl_p = sub.add_parser(
        "crawl",
        help="Curl-first polite crawl for candidate pages (live GETs; requires --yes)",
    )
    crawl_p.add_argument("url")
    crawl_p.add_argument("-k", "--keyword", action="append", help="Domain keyword (repeatable)")
    crawl_p.add_argument("--max-pages", type=int, default=12)
    crawl_p.add_argument("--depth", type=int, default=2)
    crawl_p.add_argument("--delay", type=float, default=1.0, help="Seconds between requests per host")
    crawl_p.add_argument("--follow-external", action="store_true")
    crawl_p.add_argument("--ignore-robots", action="store_true", help="Only where you are permitted")
    crawl_p.add_argument("--timeout", type=float, default=15.0)
    crawl_p.add_argument("--yes", action="store_true", help="Confirm live requests")
    crawl_p.set_defaults(func=cmd_crawl)


    rc_p = sub.add_parser(
    "replay-check",
    help="Replay a request/flow and report which headers, cookies, params, fields and prior steps are required",
    )
    rc_p.add_argument("har")
    rc_p.add_argument("entry_ids", type=int, nargs="+", help="One entry id, or an ordered flow (last = target)")
    rc_p.add_argument("--yes", action="store_true", help="Confirm live requests")
    rc_p.add_argument("--overrides-json", default=None, help='{"headers":{},"cookies":{},"query":{},"body":{}}')
    rc_p.add_argument("--max-requests", type=int, default=15)
    rc_p.add_argument("--delay", type=float, default=0.5)
    rc_p.add_argument("--allow-unsafe", action="store_true", help="Allow POST/PUT/PATCH/DELETE")
    rc_p.set_defaults(func=cmd_replay_check)

    stack_p = sub.add_parser(
    "stack",
    help="Fingerprint frameworks / CMS / GIS / UI toolkits and SDK implications",
    )
    stack_p.add_argument("har")
    stack_p.add_argument("--host")
    stack_p.add_argument("--limit", type=int, default=30)
    stack_p.set_defaults(func=cmd_stack)


    ap_p = sub.add_parser(
        "auth-patterns",
        help="Detect bearer/refresh login, OIDC/PKCE, SAML POST, double-submit CSRF, signed requests",
    )
    ap_p.add_argument("har")
    ap_p.add_argument("--host")
    ap_p.add_argument("--kind", action="append", help="Restrict to a detector (repeatable)")
    ap_p.set_defaults(func=cmd_auth_patterns)

    tables_p = sub.add_parser(
        "tables",
        help="HTML data tables: headers, counts, masked first row (no values)",
    )
    tables_p.add_argument("har")
    tables_p.add_argument("--host")
    tables_p.add_argument("--entry-id", type=int, dest="entry_id")
    tables_p.set_defaults(func=cmd_tables)

    gates_p = sub.add_parser("gates", help="Classify gates (bot wall, captcha, login, paywall, ...) and policy actions")
    gates_p.add_argument("har")
    gates_p.add_argument("--host")
    gates_p.set_defaults(func=cmd_gates)

    grids_p = sub.add_parser(
        "grids",
        help="Detect grid frameworks, JSON envelope and paging conventions",
    )
    grids_p.add_argument("har")
    grids_p.add_argument("--host")
    grids_p.add_argument("--limit", type=int, default=20)
    grids_p.set_defaults(func=cmd_grids)

    find_search_p = sub.add_parser(
        "find-search",
        help="Rank links likely to lead to a search page in a capture",
    )
    find_search_p.add_argument("har")
    find_search_p.add_argument("--host")
    find_search_p.add_argument(
        "--keyword", action="append", help="Domain term to boost (repeatable)"
    )
    find_search_p.add_argument("--limit", type=int, default=15)
    find_search_p.set_defaults(func=cmd_find_search)

    recipe_plan_p = sub.add_parser(
        "recipe-plan",
        help="Suggest a capture recipe from a portal story",
    )
    recipe_plan_p.add_argument("har")
    recipe_plan_p.add_argument("--host")
    recipe_plan_p.add_argument("--limit", type=int, default=30)
    recipe_plan_p.add_argument("-o", "--output", help="Write steps JSON")
    recipe_plan_p.set_defaults(func=cmd_recipe_plan)

    redir_p = sub.add_parser(
        "redirects",
        help="List 3xx redirect chains",
    )
    redir_p.add_argument("har")
    redir_p.add_argument("--host")
    redir_p.add_argument("--limit", type=int, default=30)
    redir_p.set_defaults(func=cmd_redirects)

    issues_p = sub.add_parser(
        "issues",
        help="Capture-quality issues (empty bodies, errors)",
    )
    issues_p.add_argument("har")
    issues_p.add_argument("--host")
    issues_p.add_argument("--limit", type=int, default=40)
    issues_p.set_defaults(func=cmd_issues)

    trace_p = sub.add_parser(
        "trace",
        help="Trace a field name or value across the capture",
    )
    trace_p.add_argument("har")
    trace_p.add_argument("--name", default="", help="Field/header/cookie name")
    trace_p.add_argument("--value", default="", help="Exact value (not echoed)")
    trace_p.add_argument("--host")
    trace_p.add_argument("--limit", type=int, default=40)
    trace_p.set_defaults(func=cmd_trace)

    secrets_p = sub.add_parser(
        "secrets",
        help="Locate sensitive field/header names (values omitted)",
    )
    secrets_p.add_argument("har")
    secrets_p.add_argument("--host")
    secrets_p.add_argument("--limit", type=int, default=40)
    secrets_p.set_defaults(func=cmd_secrets)

    cred_p = sub.add_parser(
        "credentials",
        help="Login/session map: passwords, cookies, JWT/hex/base64 shapes",
    )
    cred_p.add_argument("har")
    cred_p.add_argument("--host")
    cred_p.add_argument("--limit", type=int, default=40)
    cred_p.set_defaults(func=cmd_credentials)

    rec_p = sub.add_parser(
        "recommend",
        help="Suggest tools for a short goal string",
    )
    rec_p.add_argument("goal", help='e.g. "csrf tokens on guest portal"')
    rec_p.set_defaults(func=cmd_recommend)

    tree_p = sub.add_parser(
        "tree",
        help="Initiator parent/children for an entry",
    )
    tree_p.add_argument("har")
    tree_p.add_argument("entry_id", type=int)
    tree_p.add_argument("--include-noise", action="store_true")
    tree_p.add_argument("--limit", type=int, default=40)
    tree_p.set_defaults(func=cmd_tree)

    params_p = sub.add_parser(
        "params",
        help="Static vs dynamic params for an endpoint template",
    )
    params_p.add_argument("har")
    params_p.add_argument("method")
    params_p.add_argument("host")
    params_p.add_argument("path_template")
    params_p.add_argument("--limit", type=int, default=30)
    params_p.set_defaults(func=cmd_params)

    gql_p = sub.add_parser(
        "graphql",
        help="Detect GraphQL operations",
    )
    gql_p.add_argument("har")
    gql_p.add_argument("--host")
    gql_p.add_argument("--limit", type=int, default=40)
    gql_p.set_defaults(func=cmd_graphql)

    dup_p = sub.add_parser(
        "duplicates",
        help="Find repeated endpoint templates",
    )
    dup_p.add_argument("har")
    dup_p.add_argument("--host")
    dup_p.add_argument("--min-count", type=int, default=2)
    dup_p.add_argument("--include-noise", action="store_true")
    dup_p.add_argument("--limit", type=int, default=30)
    dup_p.set_defaults(func=cmd_duplicates)

    slow_p = sub.add_parser(
        "slow",
        help="List slowest requests by time_ms",
    )
    slow_p.add_argument("har")
    slow_p.add_argument("--host")
    slow_p.add_argument("--min-ms", type=float, default=0)
    slow_p.add_argument("--include-noise", action="store_true")
    slow_p.add_argument("--limit", type=int, default=20)
    slow_p.set_defaults(func=cmd_slow)

    wall_p = sub.add_parser(
        "wall",
        help="Detect bot walls / challenge pages",
    )
    wall_p.add_argument("har")
    wall_p.add_argument("--host")
    wall_p.add_argument("--limit", type=int, default=30)
    wall_p.set_defaults(func=cmd_wall)

    pages_p = sub.add_parser(
        "pages",
        help="List HAR pageref groups",
    )
    pages_p.add_argument("har")
    pages_p.add_argument("--host")
    pages_p.add_argument("--include-noise", action="store_true")
    pages_p.add_argument("--limit", type=int, default=40)
    pages_p.set_defaults(func=cmd_pages)

    forms_p = sub.add_parser(
        "forms",
        help="Extract HTML forms/inputs from response bodies",
    )
    forms_p.add_argument("har")
    forms_p.add_argument("--entry-id", type=int, dest="entry_id")
    forms_p.add_argument("--host")
    forms_p.add_argument(
        "--side",
        default="response",
        choices=("response", "request"),
    )
    forms_p.add_argument(
        "--exclude-noise",
        action="store_true",
        help="Skip static assets when scanning the whole HAR",
    )
    forms_p.add_argument("--limit", type=int, default=30)
    forms_p.set_defaults(func=cmd_forms)

    ui_p = sub.add_parser(
        "ui",
        help="Inventory links, onclick/onsubmit handlers, and forms",
    )
    ui_p.add_argument("har")
    ui_p.add_argument("--entry-id", type=int, dest="entry_id")
    ui_p.add_argument("--host")
    ui_p.add_argument(
        "--side",
        default="response",
        choices=("response", "request"),
    )
    ui_p.add_argument("--exclude-noise", action="store_true")
    ui_p.add_argument("--limit", type=int, default=30)
    ui_p.set_defaults(func=cmd_ui)

    routes_p = sub.add_parser(
        "routes",
        help="Mine URL path literals from JavaScript bodies",
    )
    routes_p.add_argument("har")
    routes_p.add_argument("--host")
    routes_p.add_argument("--limit", type=int, default=40)
    routes_p.set_defaults(func=cmd_routes)

    around_p = sub.add_parser(
        "around",
        help="List chronological neighbors of an entry (click -> XHR)",
    )
    around_p.add_argument("har")
    around_p.add_argument("entry_id", type=int)
    around_p.add_argument("--before", type=int, default=5)
    around_p.add_argument("--after", type=int, default=15)
    around_p.add_argument("--host")
    around_p.add_argument(
        "--include-noise",
        action="store_true",
        help="Include static assets in the window",
    )
    around_p.set_defaults(func=cmd_around)

    serve_p = sub.add_parser("serve", help="Run MCP server (stdio)")
    serve_p.set_defaults(func=cmd_serve)

    cap_p = sub.add_parser(
        "capture",
        help="Spawn a browser and record a HAR (requires [capture] extra)",
    )
    cap_sub = cap_p.add_subparsers(dest="capture_action")

    run_p = cap_sub.add_parser(
        "run",
        help="Record interactively or for --wait seconds (default action)",
    )
    _add_capture_flags(run_p)
    run_p.set_defaults(func=cmd_capture, capture_action="run")

    start_p = cap_sub.add_parser("start", help="Start recording; leave browser open")
    _add_capture_flags(start_p)
    start_p.set_defaults(func=cmd_capture, capture_action="start")

    discover_p = cap_sub.add_parser(
        "discover",
        help="Headless mode: load URL, optional recipe, open session + brief",
    )
    discover_p.add_argument("url")
    _add_capture_flags(discover_p, url=False)
    discover_p.add_argument(
        "--recipe",
        default="",
        help="JSON recipe steps file (goto/wait/aria/click/fill/…)",
    )
    discover_p.add_argument("--no-brief", action="store_true")
    discover_p.set_defaults(func=cmd_capture, capture_action="discover")

    stop_p = cap_sub.add_parser("stop", help="Stop a capture (latest if id omitted)")
    stop_p.add_argument("capture_id", nargs="?", default="")
    stop_p.add_argument("--no-open", action="store_true")
    stop_p.set_defaults(func=cmd_capture, capture_action="stop")

    list_p = cap_sub.add_parser("list", help="List captures")
    list_p.set_defaults(func=cmd_capture, capture_action="list")

    status_p = cap_sub.add_parser("status", help="Show one capture")
    status_p.add_argument("capture_id")
    status_p.set_defaults(func=cmd_capture, capture_action="status")

    goto_p = cap_sub.add_parser("goto", help="Navigate a running capture")
    goto_p.add_argument("url")
    goto_p.add_argument("--capture-id", dest="capture_id", default="")
    goto_p.set_defaults(func=cmd_capture, capture_action="goto")

    el_p = cap_sub.add_parser(
        "elements",
        help="List visible interactive elements (xpath/css) on the live tab",
    )
    el_p.add_argument("--capture-id", dest="capture_id", default="")
    el_p.add_argument("--limit", type=int, default=40)
    el_p.add_argument("--query", default="", help="CSS selector override")
    el_p.set_defaults(func=cmd_capture, capture_action="elements")

    aria_p = cap_sub.add_parser(
        "aria",
        help="Live Playwright accessibility snapshot (YAML) for the tab",
    )
    aria_p.add_argument("--capture-id", dest="capture_id", default="")
    aria_p.add_argument(
        "--selector",
        default="",
        help="Optional CSS scope (default: body)",
    )
    aria_p.add_argument(
        "--mode",
        default="ai",
        choices=("ai", "default"),
        help="ai includes [ref=eN] when Playwright >=1.59",
    )
    aria_p.set_defaults(func=cmd_capture, capture_action="aria")

    doctor_p = cap_sub.add_parser(
        "doctor",
        help="Diagnose Playwright package + browser binaries",
    )
    doctor_p.set_defaults(func=cmd_capture, capture_action="doctor")

    shot_p = cap_sub.add_parser(
        "screenshot",
        help="PNG screenshot of the live capture tab",
    )
    shot_p.add_argument("--capture-id", dest="capture_id", default="")
    shot_p.add_argument("-o", "--path", default="", help="Output .png path")
    shot_p.add_argument("--full-page", action="store_true")
    shot_p.set_defaults(func=cmd_capture, capture_action="screenshot")

    click_p = cap_sub.add_parser("click", help="Click an element on the live tab")
    click_p.add_argument("--capture-id", dest="capture_id", default="")
    click_p.add_argument(
        "--ref",
        default="",
        help="Aria ref from `hardly capture aria` (e12 / [ref=e12])",
    )
    click_p.add_argument("--xpath", default="")
    click_p.add_argument("--css", default="")
    click_p.add_argument("--text", default="")
    click_p.add_argument("--role", default="")
    click_p.add_argument("--name", default="")
    click_p.set_defaults(func=cmd_capture, capture_action="click")

    fill_p = cap_sub.add_parser("fill", help="Fill an input on the live tab")
    fill_p.add_argument("value")
    fill_p.add_argument("--capture-id", dest="capture_id", default="")
    fill_p.add_argument(
        "--ref",
        default="",
        help="Aria ref from `hardly capture aria`",
    )
    fill_p.add_argument("--xpath", default="")
    fill_p.add_argument("--css", default="")
    fill_p.set_defaults(func=cmd_capture, capture_action="fill")

    press_p = cap_sub.add_parser("press", help="Press a key on the live tab")
    press_p.add_argument("key", nargs="?", default="Enter")
    press_p.add_argument("--capture-id", dest="capture_id", default="")
    press_p.add_argument("--ref", default="")
    press_p.add_argument("--xpath", default="")
    press_p.add_argument("--css", default="")
    press_p.set_defaults(func=cmd_capture, capture_action="press")

    url_p = cap_sub.add_parser("url", help="Show the live tab URL/title")
    url_p.add_argument("--capture-id", dest="capture_id", default="")
    url_p.set_defaults(func=cmd_capture, capture_action="url")

    recipe_p = cap_sub.add_parser(
        "recipe",
        help="Run a JSON list of capture steps (goto/click/fill/wait/...)",
    )
    recipe_p.add_argument(
        "steps_file",
        help="JSON file: [{\"op\":\"goto\",\"url\":\"...\"}, ...]",
    )
    recipe_p.add_argument("--capture-id", dest="capture_id", default="")
    recipe_p.add_argument(
        "--continue-on-error",
        action="store_true",
        help="Keep going after a failed step",
    )
    recipe_p.set_defaults(func=cmd_capture, capture_action="recipe")

    # Bare `hardly capture URL` (no subcommand) — argparse needs a default path.
    _add_capture_flags(cap_p, url_default=argparse.SUPPRESS)
    cap_p.set_defaults(func=cmd_capture, capture_action="run")

    return p


_CAPTURE_ACTIONS = frozenset(
    {"run", "start", "discover", "stop", "list", "status", "goto", "elements",
     "aria", "doctor", "screenshot", "click", "fill", "press", "url", "recipe"}
)


def normalize_argv(argv: list[str]) -> list[str]:
    """Make bare ``hardly capture [flags] URL`` mean ``hardly capture run ...``.

    argparse cannot mix an optional positional with subcommands, so insert the
    default ``run`` action when no capture subcommand is present.
    """
    if not argv or argv[0] != "capture":
        return argv
    rest = argv[1:]
    if any(a in _CAPTURE_ACTIONS for a in rest if not a.startswith("-")):
        # A subcommand word is present (flag values like "-o run" are rare).
        return argv
    if any(a in {"-h", "--help"} for a in rest):
        return argv
    return ["capture", "run", *rest]


def main(argv: list[str] | None = None) -> None:
    import signal

    if hasattr(signal, "SIGPIPE"):  # `hardly ... | head` must not traceback
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    parser = build_parser()
    import sys as _sys

    args = parser.parse_args(normalize_argv(list(_sys.argv[1:] if argv is None else argv)))
    code = args.func(args)
    sys.exit(code)


if __name__ == "__main__":
    main()
