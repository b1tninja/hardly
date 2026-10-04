"""Command-line interface for hardly (non-MCP).

Grammar (v1, permanent; ``tests/cli_surface.json`` pins it, ``docs/cli.md`` lists it):

    hardly <group> <command> [positionals] [--flags]

The command path is the MCP tool name without ``hardly_``, split at the first underscore, the rest
joined with hyphens: ``hardly_session_traffic_stats`` is ``hardly session traffic-stats``.
Flags are the tool's parameter names with hyphens (``--exclude-noise``, ``--timeout-seconds``);
a boolean that defaults to true is spelled ``--x`` / ``--no-x``; lists are comma separated;
objects are inline JSON. The tool's ``session_id`` / ``har_path`` become a positional HAR (or saved
index) path. Live commands take ``--confirm`` and print only a plan without it.
CLI-only commands: ``serve``, ``skill install|print``, ``soak live``, ``catalog init|show|export``.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from hardly import session as sess
from hardly.index import query as q

_BOOL = argparse.BooleanOptionalAction


# ----------------------------------------------------------------------------- helpers


def _print(data: object) -> None:
    print(json.dumps(data, indent=2, default=str))


def _csv(text: str) -> list[str]:
    """``a,b`` -> ``['a', 'b']`` (argparse type for list-valued flags)."""
    return [s.strip() for s in text.split(",") if s.strip()]


def _csv_ints(tokens: list[str] | str) -> list[int]:
    """Entry ids as ``12 14`` or ``12,14`` (or both)."""
    if isinstance(tokens, str):
        tokens = [tokens]
    out: list[int] = []
    for tok in tokens:
        for part in tok.split(","):
            if part.strip():
                out.append(int(part))
    return out


def _entry_ids_arg(text: str) -> list[int]:
    try:
        return _csv_ints(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"entry ids must be integers: {text!r}") from exc


def _json_obj(text: str | None, flag: str) -> dict | None:
    """Inline JSON text for an object-valued flag (never a file path)."""
    if text is None:
        return None
    try:
        value = json.loads(text)
    except ValueError as exc:
        raise ValueError(f"{flag} must be inline JSON text, not a file path") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{flag} must be a JSON object")
    return value


def _kv_pairs(items: list[str] | None, what: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for item in items or []:
        key, sep, val = item.partition("=")
        if not sep or not key.strip():
            raise ValueError(f"{what} must look like key=value: {item!r}")
        out[key.strip()] = val.strip()
    return out


def _open(har: str) -> str | None:
    """Open (or re-open) a HAR or saved index; print the error and return None on failure."""
    result = sess.open_har(har)
    if "error" in result:
        _print(result)
        return None
    return result["session_id"]


def _conn(har: str):
    sid = _open(har)
    return None if sid is None else sess.require_conn(sid)


def _run_tool(tool: str, /, **kwargs: Any) -> int:
    """Call an MCP tool function in-process and print its JSON; exit 1 when it reports an error."""
    from hardly import server

    text = getattr(server, f"hardly_{tool}")(**kwargs)
    print(text)
    try:
        data = json.loads(text)
    except ValueError:
        return 0
    return 1 if isinstance(data, dict) and "error" in data else 0


def _delegate(tool: str, *params: str):
    """Handler that forwards parsed flags to an MCP tool (``dest`` or ``dest:tool_param``).

    A ``har`` positional is opened first and passed as ``session_id``. Used where one command
    mirrors a merged tool, so the CLI and the tool cannot drift apart.
    """

    def run(args: argparse.Namespace) -> int:
        kwargs: dict[str, Any] = {}
        for spec in params:
            dest, _, target = spec.partition(":")
            kwargs[target or dest] = getattr(args, dest)
        if hasattr(args, "har"):
            sid = _open(args.har)
            if sid is None:
                return 1
            kwargs["session_id"] = sid
        try:
            return _run_tool(tool, **kwargs)
        except ValueError as exc:
            _print({"error": str(exc)})
            return 1

    return run


# ----------------------------------------------------------------------------- guide, server, skill


def cmd_server_status(args: argparse.Namespace) -> int:
    return _run_tool("server_status", sections=args.sections)


def cmd_guide_help(args: argparse.Namespace) -> int:
    from hardly.core.help import tool_help

    _print(tool_help(args.topic or None))
    return 0


def cmd_guide_mode(args: argparse.Namespace) -> int:
    from hardly.core.modes import list_modes, mode_playbook, pick_mode

    mode = (args.mode or "").strip()
    goal, har_path, url = args.goal or "", args.har_path or "", args.url or ""
    if mode:
        _print(mode_playbook(mode, har_path=har_path, url=url, goal=goal))
    elif goal or har_path or url:
        _print(pick_mode(goal=goal, har_path=har_path, url=url))
    else:
        _print(list_modes())
    return 0


def cmd_guide_task_plan(args: argparse.Namespace) -> int:
    from hardly.core.start import build_plan

    _print(build_plan(goal=args.goal or "", har_path=args.har_path or "", url=args.url or ""))
    return 0


def cmd_skill(args: argparse.Namespace) -> int:
    from hardly import resources

    action = getattr(args, "skill_command", None) or "print"
    try:
        if action == "print":
            sys.stdout.write(resources.skill_text())
            return 0
        dest = resources.install_skill(args.dest or None)
    except (FileNotFoundError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"installed hardly skill to {dest}")
    return 0


def cmd_soak_live(args: argparse.Namespace) -> int:
    """Headless soak against public tech demos (captures HARs on the fly)."""
    from hardly.soak_live import main as soak_main

    argv: list[str] = []
    if args.list:
        argv.append("--list")
    if args.ids:
        argv.extend(["--ids", args.ids])
    if args.fail_soft:
        argv.append("--fail-soft")
    if args.json:
        argv.append("--json")
    if args.write_fixtures:
        argv.extend(["--write-fixtures", args.write_fixtures])
    return soak_main(argv)


def cmd_serve(_args: argparse.Namespace) -> int:
    from hardly.server import main as server_main

    server_main()
    return 0


# ----------------------------------------------------------------------------- session


def cmd_session_open(args: argparse.Namespace) -> int:
    result = sess.open_har(
        args.har_path, force=args.force, output_path=args.output, overwrite=args.overwrite
    )
    _print(result)
    return 0 if "error" not in result else 1


def cmd_session_list(_args: argparse.Namespace) -> int:
    _print({"sessions": sess.list_sessions()})
    return 0


def cmd_session_body_coverage(args: argparse.Namespace) -> int:
    conn = _conn(args.har)
    if conn is None:
        return 1
    _print(q.body_coverage(conn, host=args.host, exclude_noise=args.exclude_noise, limit=args.limit))
    return 0


def cmd_session_issues(args: argparse.Namespace) -> int:
    from hardly.core.issues import find_issues

    conn = _conn(args.har)
    if conn is None:
        return 1
    _print(find_issues(conn, host=args.host, limit=args.limit))
    return 0


def cmd_session_duplicates(args: argparse.Namespace) -> int:
    from hardly.core.duplicates import find_duplicates

    conn = _conn(args.har)
    if conn is None:
        return 1
    _print(
        find_duplicates(
            conn, host=args.host, exclude_noise=args.exclude_noise,
            min_count=args.min_count, limit=args.limit,
        )
    )
    return 0


def cmd_session_slow_requests(args: argparse.Namespace) -> int:
    from hardly.core.slow import slowest_entries

    conn = _conn(args.har)
    if conn is None:
        return 1
    _print(
        slowest_entries(
            conn, host=args.host, exclude_noise=args.exclude_noise, limit=args.limit,
            min_ms=args.min_elapsed_seconds * 1000.0,
        )
    )
    return 0


def cmd_session_report(args: argparse.Namespace) -> int:
    from hardly.core.report import build_report, render_markdown

    sid = _open(args.har)
    if sid is None:
        return 1
    conn = sess.require_conn(sid)
    try:
        rep = build_report(
            conn, sess.get_har_path(sid), host=args.host, sections=args.categories,
            detail=args.detail, explain=args.explain,
        )
    except ValueError as exc:
        _print({"error": str(exc)})
        return 1
    if args.format == "md":
        sys.stdout.write(render_markdown(rep))
    else:
        _print(rep)
    return 0


def cmd_session_site_brief(args: argparse.Namespace) -> int:
    from hardly.core.brief import portal_brief

    sid = _open(args.har)
    if sid is None:
        return 1
    _print(portal_brief(sess.require_conn(sid), har_path=sess.get_har_path(sid), host=args.host))
    return 0


def cmd_session_story(args: argparse.Namespace) -> int:
    from hardly.core.story import portal_story

    conn = _conn(args.har)
    if conn is None:
        return 1
    _print(
        portal_story(
            conn, host=args.host, limit=args.limit, exclude_noise=args.exclude_noise,
            include_related=args.include_related,
        )
    )
    return 0


def cmd_session_timeline(args: argparse.Namespace) -> int:
    from hardly.core.flows import get_flow

    conn = _conn(args.har)
    if conn is None:
        return 1
    _print(
        get_flow(
            conn, host=args.host, path_prefix=args.path_prefix or None,
            exclude_noise=args.exclude_noise, limit=args.limit, offset=args.offset,
        )
    )
    return 0


def cmd_session_redirect_history(args: argparse.Namespace) -> int:
    from hardly.core.redirects import redirect_chains

    conn = _conn(args.har)
    if conn is None:
        return 1
    _print(redirect_chains(conn, host=args.host, limit=args.limit, explain=args.explain))
    return 0


def cmd_session_compare(args: argparse.Namespace) -> int:
    from hardly.core.diff import diff_sessions

    a = sess.open_har(args.har)
    b = sess.open_har(args.other_har)
    for r in (a, b):
        if "error" in r:
            _print(r)
            return 1
    _print(
        diff_sessions(
            sess.require_conn(a["session_id"]),
            sess.require_conn(b["session_id"]),
            host=args.host,
            exclude_noise=args.exclude_noise,
            credentials=args.include_credentials,
            har_path_a=sess.get_har_path(a["session_id"]),
            har_path_b=sess.get_har_path(b["session_id"]),
        )
    )
    return 0


def cmd_session_plan_steps(args: argparse.Namespace) -> int:
    from hardly.core.recipe_plan import recipe_from_story

    conn = _conn(args.har)
    if conn is None:
        return 1
    _print(recipe_from_story(conn, host=args.host, output_path=None, limit=args.limit))
    return 0


# ----------------------------------------------------------------------------- entry


def cmd_entry_search(args: argparse.Namespace) -> int:
    conn = _conn(args.har)
    if conn is None:
        return 1
    _print(
        q.search_entries(
            conn,
            host=args.host,
            path_contains=args.path_contains or None,
            method=args.method or None,
            status=args.status,
            body_contains=args.body_contains or None,
            header_name=args.header_name or None,
            header_contains=args.header_contains or None,
            mime_contains=args.mime_contains or None,
            content_kind=args.content_kind or None,
            exclude_noise=args.exclude_noise,
            limit=args.limit,
            offset=args.offset,
        )
    )
    return 0


def cmd_entry_get(args: argparse.Namespace) -> int:
    conn = _conn(args.har)
    if conn is None:
        return 1
    _print(q.get_entry(conn, args.entry_id, body_chars=args.max_body_chars))
    return 0


def cmd_entry_around(args: argparse.Namespace) -> int:
    conn = _conn(args.har)
    if conn is None:
        return 1
    _print(
        q.entries_around(
            conn, args.entry_id, before=args.before, after=args.after,
            exclude_noise=args.exclude_noise, host=args.host,
        )
    )
    return 0


def cmd_entry_initiators(args: argparse.Namespace) -> int:
    from hardly.core.tree import entry_tree

    conn = _conn(args.har)
    if conn is None:
        return 1
    _print(entry_tree(conn, args.entry_id, exclude_noise=args.exclude_noise, child_limit=args.child_limit))
    return 0


def cmd_entry_compare(args: argparse.Namespace) -> int:
    conn = _conn(args.har)
    if conn is None:
        return 1
    _print(q.compare_entries(conn, args.entry_id, args.other_entry_id))
    return 0


def cmd_entry_build_curl(args: argparse.Namespace) -> int:
    from hardly.core.curl import entry_to_curl

    conn = _conn(args.har)
    if conn is None:
        return 1
    _print(
        entry_to_curl(
            conn, args.entry_id, redact=args.redact, use_env_placeholders=args.use_env_placeholders
        )
    )
    return 0


def cmd_entry_body_query(args: argparse.Namespace) -> int:
    from hardly.core.body_query import BodyQueryError, query_body

    conn = _conn(args.har)
    if conn is None:
        return 1
    try:
        _print(
            query_body(
                conn, args.entry_id, args.side, jsonpath=args.jsonpath, regex=args.regex,
                offset=args.offset, limit=args.limit,
            )
        )
    except BodyQueryError as exc:
        _print({"error": str(exc)})
        return 1
    return 0


def cmd_entry_outline(args: argparse.Namespace) -> int:
    from hardly.core.outline import outline_entry

    conn = _conn(args.har)
    if conn is None:
        return 1
    out = outline_entry(
        conn, args.entry_id, format=args.format, max_depth=args.max_depth, side=args.side
    )
    if args.markdown_only and out.get("markdown"):
        print(out["markdown"])
        return 0 if "error" not in out else 1
    _print(out)
    return 0 if "error" not in out else 1


def cmd_entry_dependencies(args: argparse.Namespace) -> int:
    from hardly.core.flow_graph import flow_graph

    conn = _conn(args.har)
    if conn is None:
        return 1
    _print(flow_graph(conn, args.entry_id, host=args.host, max_depth=args.max_depth))
    return 0


# ----------------------------------------------------------------------------- endpoint, spec, page


def cmd_endpoint_list(args: argparse.Namespace) -> int:
    conn = _conn(args.har)
    if conn is None:
        return 1
    _print(
        q.list_endpoints(
            conn, host=args.host, exclude_noise=args.exclude_noise, limit=args.limit
        )
    )
    return 0


def cmd_endpoint_graphql(args: argparse.Namespace) -> int:
    from hardly.core.graphql import detect_graphql

    conn = _conn(args.har)
    if conn is None:
        return 1
    _print(detect_graphql(conn, host=args.host, limit=args.limit))
    return 0


def cmd_endpoint_streams(args: argparse.Namespace) -> int:
    from hardly.core.streams import summarize_streams

    conn = _conn(args.har)
    if conn is None:
        return 1
    _print(summarize_streams(conn, host=args.host, kind=args.kind, limit=args.limit))
    return 0


def cmd_endpoint_pagination(args: argparse.Namespace) -> int:
    from hardly.core.pagination import detect_pagination

    conn = _conn(args.har)
    if conn is None:
        return 1
    _print(detect_pagination(conn, host=args.host, limit=args.limit))
    return 0


def cmd_endpoint_arcgis(args: argparse.Namespace) -> int:
    from hardly.core.arcgis import summarize_session

    conn = _conn(args.har)
    if conn is None:
        return 1
    _print(summarize_session(conn, host=args.host))
    return 0


def cmd_spec_contract_check(args: argparse.Namespace) -> int:
    from hardly.core.contract import check_contract

    conn = _conn(args.har)
    if conn is None:
        return 1
    try:
        _print(check_contract(conn, args.spec_path, host=args.host))
    except Exception as exc:  # noqa: BLE001
        _print({"error": str(exc)})
        return 1
    return 0


def cmd_page_list(args: argparse.Namespace) -> int:
    from hardly.core.pages import list_pages

    conn = _conn(args.har)
    if conn is None:
        return 1
    _print(list_pages(conn, host=args.host, exclude_noise=args.exclude_noise, limit=args.limit))
    return 0


def cmd_page_tables(args: argparse.Namespace) -> int:
    from hardly.core.tables import scan_session

    conn = _conn(args.har)
    if conn is None:
        return 1
    _print(scan_session(conn, host=args.host, entry_id=args.entry_id))
    return 0


def cmd_client_build(args: argparse.Namespace) -> int:
    from hardly.core.stub import client_stub

    conn = _conn(args.har)
    if conn is None:
        return 1
    _print(
        client_stub(
            conn, entry_ids=args.entry_ids, host=args.host, output_path=None,
            class_name=args.class_name,
        )
    )
    return 0


# ----------------------------------------------------------------------------- har files, write


def cmd_har_file_check(args: argparse.Namespace) -> int:
    from hardly.core import har_doctor

    try:
        res = har_doctor.diagnose_har(None, args.har_path, har_doctor.config_from_namespace(args))
    except (ValueError, OSError) as exc:
        _print({"error": str(exc)})
        return 2
    _print(res)
    return int(res.get("exit_code") or 0)


def cmd_write_har(args: argparse.Namespace) -> int:
    from hardly.core import har_tools

    try:
        kind = args.write_command
        if kind == "har-pruned":
            out = har_tools.prune_har(
                args.har_path, args.output, args.drop_hosts or (), args.drop_mime_types or (),
                args.drop_noise, overwrite=args.overwrite,
            )
        elif kind == "har-split":
            out = har_tools.split_har(args.har_path, args.by, args.output_dir, overwrite=args.overwrite)
        elif kind == "har-merged":
            out = har_tools.merge_hars(
                args.har_paths, args.output, overwrite=args.overwrite, dedupe=args.dedupe
            )
        else:
            out = har_tools.scrub_har(args.har_path, args.output, overwrite=args.overwrite)
    except (ValueError, OSError) as exc:
        _print({"error": str(exc)})
        return 2
    _print(out)
    return 0


def cmd_write_catalog_record(args: argparse.Namespace) -> int:
    from hardly.core import catalog as C

    try:
        endpoints = []
        for spec in args.endpoint or []:
            role, sep, rest = spec.partition("=")  # role=url[,kind]
            if not sep:
                raise ValueError(f"--endpoint must look like role=url[,kind]: {spec!r}")
            url, kind = rest, ""
            head, comma, tail = rest.rpartition(",")
            if comma and tail in C.KINDS:
                url, kind = head, tail
            endpoints.append({"role": role, "url": url, "kind": kind or None})
        target = {
            "id": args.id,
            "name": args.name or "",
            "tags": args.tags or [],
            "groups": _kv_pairs(args.group, "--group"),
            "endpoints": endpoints,
        }
    except ValueError as exc:
        _print({"error": str(exc)})
        return 1
    return _run_tool(
        "write_catalog_record", catalog_path=args.catalog_path, target=target,
        merge=args.merge, create=args.create,
    )


# ----------------------------------------------------------------------------- catalog


def cmd_catalog_list(args: argparse.Namespace) -> int:
    try:
        group = _kv_pairs(args.group, "--group") or None
    except ValueError as exc:
        _print({"error": str(exc)})
        return 1
    return _run_tool(
        "catalog_list", catalog_path=args.catalog_path, tag=args.tag, group=group,
        role=args.role, status=args.status, target_id=args.target_id, detail=args.detail,
    )


def cmd_catalog_init(args: argparse.Namespace) -> int:
    from hardly.core import catalog as C

    if Path(args.catalog_path).exists() and not args.force:
        _print({"error": "catalog file exists; pass --force to overwrite"})
        return 1
    C.save(C.Catalog(name=args.name), args.catalog_path)
    _print({"created": str(args.catalog_path), "name": args.name, "version": C.CATALOG_VERSION})
    return 0


def cmd_catalog_show(args: argparse.Namespace) -> int:
    from hardly.core import catalog as C

    try:
        t = C.load(args.catalog_path).get(args.target_id)
    except C.CatalogError as exc:
        _print({"error": str(exc)})
        return 1
    if t is None:
        _print({"error": f"no target {args.target_id!r}"})
        return 1
    _print(t.to_dict())
    return 0


def cmd_catalog_export(args: argparse.Namespace) -> int:
    from hardly.core import catalog as C

    try:
        text = C.dumps(C.load(args.catalog_path), args.format)
    except C.CatalogError as exc:
        _print({"error": str(exc)})
        return 1
    if args.output:
        from hardly.core.pathguard import guard_write

        guard_write(args.output)
        Path(args.output).write_text(text, encoding="utf-8", newline="\n")
        _print({"written": str(args.output), "format": args.format})
    else:
        print(text, end="")
    return 0


# ----------------------------------------------------------------------------- send (live)


def cmd_send_entry_ablation(args: argparse.Namespace) -> int:
    sid = _open(args.har)
    if sid is None:
        return 1
    try:
        overrides = _json_obj(args.overrides, "--overrides")
    except ValueError as exc:
        _print({"error": f"{exc}: " + '{"headers":{},"cookies":{},"query":{},"body":{}}'})
        return 1
    return _run_tool(
        "send_entry_ablation", session_id=sid, entry_ids=_csv_ints(args.entry_ids), confirm=args.confirm,
        overrides=overrides, max_requests=args.max_requests, delay_seconds=args.delay_seconds,
        allow_unsafe=args.allow_unsafe, allow_gates=args.allow_gates,
    )


def cmd_send_catalog_verify(args: argparse.Namespace) -> int:
    try:
        group = _kv_pairs(args.group, "--group") or None
    except ValueError as exc:
        _print({"error": str(exc)})
        return 1
    return _run_tool(
        "send_catalog_verify", catalog_path=args.catalog_path, confirm=args.confirm,
        write_back=args.write_back, tag=args.tag, group=group, role=args.role, status=args.status,
        target_id=args.target_id, delay_seconds=args.delay_seconds, max_requests=args.max_requests,
        max_endpoints=args.max_endpoints, recheck_after_seconds=args.recheck_after_seconds,
        force=args.force,
    )


def cmd_send_entry_series(args: argparse.Namespace) -> int:
    sid = _open(args.har)
    if sid is None:
        return 1
    try:
        env = _json_obj(args.env, "--env")
    except ValueError as exc:
        _print({"error": str(exc)})
        return 1
    return _run_tool(
        "send_entry_series", session_id=sid, entry_ids=args.entry_ids, entry_id=args.entry_id,
        confirm=args.confirm, env=env, delay_seconds=args.delay_seconds,
        max_requests=args.max_requests, allow_unsafe=args.allow_unsafe, allow_gates=args.allow_gates,
    )


# ----------------------------------------------------------------------------- browser


def _capture_error(exc: Exception) -> int:
    to_dict = getattr(exc, "to_dict", None)
    _print(to_dict() if to_dict else {"error": str(exc)})
    return 1


def cmd_browser_start(args: argparse.Namespace) -> int:
    from hardly.capture import CaptureError, capture_interactive, start_capture

    use_trace = True if args.trace else None
    common = dict(
        headed=args.headed,
        channel=args.channel or "",
        url_filter=args.url_filter or "",
        omit_content=args.omit_content,
        label=args.label or "",
        user_data_dir=args.profile or None,
        same_tab=args.same_tab,
        trace=use_trace,
        slot_timeout_s=args.slot_timeout_seconds,
    )
    try:
        if args.foreground:
            result = capture_interactive(args.url or "", args.har_output_path, **common)
            _print(result)
            return 0 if result.get("status") in ("stopped", "running", "starting") else 1
        if not args.har_output_path:
            _print(
                {
                    "error": "browser start needs -o/--har-output-path from the CLI: the HAR is "
                    "ephemeral without it and this process exits right after starting.",
                    "hint": "hardly browser start URL -o capture.har, or --foreground to record "
                    "until you close the window, or the MCP tools for an in-memory capture.",
                }
            )
            return 1
        _print(start_capture(args.url or "", args.har_output_path, **common))
        return 0
    except CaptureError as exc:
        return _capture_error(exc)


def cmd_browser_capture_discover(args: argparse.Namespace) -> int:
    from hardly.capture import CaptureError, capture_for, discover_apis

    steps = None
    if args.steps:
        steps = json.loads(Path(args.steps).read_text(encoding="utf-8"))
    if args.analyze and args.headed:
        _print({"error": "browser capture-discover: --analyze runs headless",
                "hint": "For a visible browser use `hardly browser start --headed`."})
        return 1
    if steps and not args.analyze:
        _print({"error": "browser capture-discover: --steps needs --analyze"})
        return 1
    if not args.confirm:
        return _run_tool(
            "browser_capture_discover", url=args.url, wait_seconds=args.wait_seconds,
            analyze=args.analyze, confirm=False, har_output_path=args.har_output_path,
            headed=args.headed, channel=args.channel, url_filter=args.url_filter, steps=steps,
            budget_seconds=args.budget_seconds, exclude_noise=args.exclude_noise,
            open_session=args.open_session,
        )
    wait = args.wait_seconds if args.wait_seconds is not None else (5.0 if args.analyze else 20.0)
    try:
        if args.analyze:
            _print(
                discover_apis(
                    args.url, args.har_output_path, recipe=steps, wait_seconds=wait,
                    channel=args.channel or "", url_filter=args.url_filter or "",
                    omit_content=args.omit_content, label=args.label or "",
                    open_session=args.open_session, brief=args.brief, same_tab=args.same_tab,
                    trace=True if args.trace else None, budget_seconds=args.budget_seconds,
                    block_noise=args.exclude_noise, slot_timeout_s=args.slot_timeout_seconds,
                    diagnose_redirects=args.diagnose_redirects,
                )
            )
            return 0
        result = capture_for(
            args.url, args.har_output_path, wait_seconds=wait, headed=args.headed,
            channel=args.channel or "", url_filter=args.url_filter or "",
            omit_content=args.omit_content, label=args.label or "",
            open_session=args.open_session, same_tab=args.same_tab,
            trace=True if args.trace else None, budget_seconds=args.budget_seconds,
            block_noise=args.exclude_noise, slot_timeout_s=args.slot_timeout_seconds,
            diagnose_redirects=args.diagnose_redirects,
        )
    except CaptureError as exc:
        return _capture_error(exc)
    _print(result)
    return 0 if result.get("status") in ("stopped", "running", "starting") else 1


def cmd_browser_run_steps(args: argparse.Namespace) -> int:
    steps = json.loads(Path(args.steps).read_text(encoding="utf-8"))
    return _run_tool(
        "browser_run_steps", steps=steps, capture_id=args.capture_id,
        stop_on_error=args.stop_on_error,
    )


# ----------------------------------------------------------------------------- parser


def _har(p: argparse.ArgumentParser, name: str = "har", help: str = "HAR file or saved index") -> None:
    p.add_argument(name, help=help)


def _host(p: argparse.ArgumentParser) -> None:
    p.add_argument("--host", help="Exact hostname; omitted = all hosts")


def _noise(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--exclude-noise", action=_BOOL, default=True,
        help="Skip static assets, analytics and other noise (default on)",
    )


def _limit(p: argparse.ArgumentParser, default: int | None = None, help: str = "Maximum rows") -> None:
    p.add_argument("--limit", type=int, default=default, help=help)


def _explain(p: argparse.ArgumentParser) -> None:
    p.add_argument("--explain", action="store_true", help="Include canned prose (implications / advice / next steps)")


def _confirm(p: argparse.ArgumentParser, what: str = "Send the requests") -> None:
    p.add_argument("--confirm", action="store_true", help=f"{what}; without it only the plan is printed")


def _sections(p: argparse.ArgumentParser, valid: str) -> None:
    p.add_argument("--sections", type=_csv, help=f"Comma list: {valid}")


def _output(p: argparse.ArgumentParser, help: str, required: bool = True) -> None:
    p.add_argument("-o", "--output", required=required, help=help)


def _overwrite(p: argparse.ArgumentParser) -> None:
    p.add_argument("--overwrite", action="store_true", help="Replace an existing output file")


def _capture_id(p: argparse.ArgumentParser) -> None:
    p.add_argument("--capture-id", help="Capture id (default: the latest running capture)")


def _browser_launch(p: argparse.ArgumentParser, *, headed_default: bool) -> None:
    p.add_argument("-o", "--har-output-path", help="HAR output path. Without it the capture is ephemeral: indexed in memory, HAR deleted")
    p.add_argument("--headed", action=_BOOL, default=headed_default, help="Show the browser window")
    p.add_argument("--channel", help='Installed browser: "chrome" or "msedge" (or HARDLY_BROWSER_CHANNEL)')
    p.add_argument("--url-filter", help='Playwright glob for HAR entries (e.g. "**/api/*")')
    p.add_argument("--omit-content", action="store_true", help="Omit response bodies from the HAR (smaller file)")
    p.add_argument("--label", help="Filename label when -o is omitted")
    p.add_argument("--same-tab", action=_BOOL, default=True, help="Force target=_blank navigation into the current tab")
    p.add_argument("--trace", action="store_true", help="Write a Playwright .trace.zip beside the HAR (or HARDLY_CAPTURE_TRACE=1)")
    p.add_argument("--slot-timeout-seconds", type=float, help="Max wait for a capture slot (env HARDLY_CAPTURE_SLOT_TIMEOUT, default 300)")


_GROUPS = {
    "server": "Server version, features and browser setup",
    "guide": "Orientation: task plan, operating modes, tool catalog",
    "session": "Open a HAR and read counts, findings, story, timeline",
    "entry": "One request: search, get, neighbours, body, dependencies",
    "endpoint": "API shape: endpoints, schemas, GraphQL, streams, pagination, ArcGIS",
    "spec": "Compare a capture with an OpenAPI file",
    "tech": "Technology fingerprint",
    "page": "Server-rendered pages: forms, UI controls, embedded routes, tables",
    "auth": "Authentication evidence (names and shapes, never values)",
    "gate": "Bot walls, captchas, challenges",
    "har": "Check a HAR file on disk",
    "client": "Generate client code (returned, not written)",
    "write": "Commands that write a file (refuse to overwrite without --overwrite)",
    "send": "LIVE commands that send requests (--confirm; a plan without it)",
    "browser": "Drive a real browser that records a HAR (needs the capture extra)",
    "capture": "List browser captures",
    "catalog": "Content-neutral target catalog",
    "skill": "Agent Skill: install into ~/.claude/skills/hardly or print SKILL.md",
    "soak": "Soak runs (developer tool)",
}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="hardly",
        description="HAR analysis - index, query, document, and probe APIs. "
        "hardly <group> <command>: the same names as the MCP tools (hardly_session_open is "
        "`hardly session open`). See docs/cli.md.",
    )
    p.add_argument(
        "--allow-private-hosts",
        action="store_true",
        help="Allow live commands to reach loopback/private hosts (same as HARDLY_ALLOW_PRIVATE_HOSTS=1); "
        "put it before the group, e.g. `hardly --allow-private-hosts send entry ...`",
    )
    top = p.add_subparsers(dest="group", required=True, metavar="GROUP")
    subs: dict[str, argparse._SubParsersAction] = {}

    def group(name: str, required: bool = True) -> None:
        gp = top.add_parser(name, help=_GROUPS[name], description=_GROUPS[name])
        subs[name] = gp.add_subparsers(dest=f"{name}_command", required=required, metavar="COMMAND")
        gp.set_defaults(group_parser=gp)

    def cmd(path: str, help: str, func) -> argparse.ArgumentParser:
        g, _, c = path.partition(" ")
        sp = subs[g].add_parser(c, help=help, description=help)
        sp.set_defaults(func=func)
        return sp

    for g in _GROUPS:
        group(g, required=g != "skill")

    # ---- server, guide
    c = cmd("server status", "Version, features, tool names and browser setup", cmd_server_status)
    _sections(c, "capabilities (default), browser_setup")

    c = cmd("guide help", "Categorized tool catalog (topic optional)", cmd_guide_help)
    c.add_argument("topic", nargs="?", default="", help="portal | tokens | capture | modes | tool name substring")
    c = cmd("guide mode", "List operating modes, one playbook, or auto-pick from goal / har-path / url", cmd_guide_mode)
    c.add_argument("mode", nargs="?", default="", help="archive | headless | interactive (optional playbook)")
    for flag, h in (("--goal", "Free-text goal"), ("--har-path", "Existing HAR path"), ("--url", "Target URL")):
        c.add_argument(flag, help=h)
    c = cmd("guide task-plan", "First-use plan: ordered tool calls plus environment state", cmd_guide_task_plan)
    for flag, h in (("--goal", "Free-text goal, e.g. 'build a client SDK'"), ("--har-path", "Existing HAR path"), ("--url", "Target URL")):
        c.add_argument(flag, help=h)

    # ---- session
    c = cmd("session open", "Index a HAR (or open a saved index); -o saves the index there", cmd_session_open)
    c.add_argument("har_path", help="HAR file or a previously saved index file")
    c.add_argument("--force", action="store_true", help="Re-ingest even if already indexed")
    c.add_argument("-o", "--output", help="Save the index to this file (atomic). Without it nothing is written")
    _overwrite(c)
    cmd("session list", "List open sessions", cmd_session_list)

    c = cmd("session overview", "Headline counts per server, method and status, plus main_host", _delegate("session_overview", "host", "exclude_noise", "limit"))
    _har(c)
    _host(c)
    _noise(c)
    _limit(c)
    c = cmd("session traffic-stats", "Distributions: MIME, status classes, sizes, timing, payload kinds", _delegate("session_traffic_stats", "host", "exclude_noise", "limit", "kind"))
    _har(c)
    _host(c)
    _noise(c)
    _limit(c)
    c.add_argument("--kind", help="Filter payload kinds: json, jsonl, jsonp, csv, html_table, pdf, image, ...")
    c = cmd("session body-coverage", "Body preview coverage (empty / truncated / size=-1)", cmd_session_body_coverage)
    _har(c)
    _host(c)
    _noise(c)
    _limit(c, 20)
    c = cmd("session issues", "Capture-quality issues (empty bodies, errors)", cmd_session_issues)
    _har(c)
    _host(c)
    _limit(c, 40)
    c = cmd("session duplicates", "Repeated endpoint templates", cmd_session_duplicates)
    _har(c)
    _host(c)
    _noise(c)
    _limit(c, 30)
    c.add_argument("--min-count", type=int, default=2, help="Minimum repeat count")
    c = cmd("session slow-requests", "Slowest requests by elapsed time", cmd_session_slow_requests)
    _har(c)
    _host(c)
    _noise(c)
    _limit(c, 20)
    c.add_argument("--min-elapsed-seconds", type=float, default=0.0, help="Only requests at least this slow")
    c = cmd("session report", "One-pass findings with severity: access, auth, stack, data, forms", cmd_session_report)
    _har(c)
    _host(c)
    c.add_argument("--categories", type=_csv, help="Comma list: access,auth,stack,data,forms")
    c.add_argument("--detail", choices=("summary", "standard", "full"), default="summary")
    c.add_argument("--format", choices=("json", "md"), default="json", help="Print JSON or Markdown")
    _explain(c)
    c = cmd("session site-brief", "One-shot digest of a server-rendered site", cmd_session_site_brief)
    _har(c)
    _host(c)
    c = cmd("session story", "Annotated user-journey steps (roles, forms, labels)", cmd_session_story)
    _har(c)
    _host(c)
    _limit(c, 40)
    _noise(c)
    c.add_argument("--include-related", action=_BOOL, default=True, help="Merge same-apex API hosts (SPA app.* + api.*)")
    c = cmd("session timeline", "Plain ordered request list", cmd_session_timeline)
    _har(c)
    _host(c)
    _noise(c)
    _limit(c, 100)
    c.add_argument("--path-prefix", default="", help="Only paths starting with this")
    c.add_argument("--offset", type=int, default=0, help="Rows to skip")
    c = cmd("session redirect-history", "Recorded 3xx redirect hops (offline)", cmd_session_redirect_history)
    _har(c)
    _host(c)
    _limit(c, 30)
    _explain(c)
    c = cmd("session trace-value", "Trace a field name or value; with neither, list reused dynamic values", _delegate("session_trace_value", "name", "value", "host", "limit"))
    _har(c)
    _host(c)
    _limit(c, None, "Maximum rows (default 40)")
    c.add_argument("--name", help="Field / header / cookie name")
    c.add_argument("--value", help="Exact value (not echoed)")
    c = cmd("session sql", "Read-only SELECT against the session's SQLite index", _delegate("session_sql", "sql", "limit"))
    _har(c)
    c.add_argument("sql", help="A single SELECT statement")
    _limit(c)
    c = cmd("session compare", "Compare endpoint templates (and credentials) between two HARs", cmd_session_compare)
    _har(c)
    _har(c, "other_har", "Second HAR file or saved index")
    _host(c)
    _noise(c)
    c.add_argument("--include-credentials", action=_BOOL, default=True, help="Diff the credentials/session map too")
    c = cmd("session plan-steps", "Suggest browser steps from the story (printed, not run)", cmd_session_plan_steps)
    _har(c)
    _host(c)
    _limit(c, 30)

    # ---- entry
    c = cmd("entry search", "Find entries by host, path, method, status, body, header or kind", cmd_entry_search)
    _har(c)
    _host(c)
    _noise(c)
    _limit(c, 50)
    c.add_argument("--offset", type=int, default=0, help="Rows to skip")
    c.add_argument("--path-contains", default="", help="Path substring")
    c.add_argument("--method", default="")
    c.add_argument("--status", type=int)
    c.add_argument("--body-contains", default="", help="Body substring")
    c.add_argument("--header-name", default="")
    c.add_argument("--header-contains", default="")
    c.add_argument("--mime-contains", default="")
    c.add_argument("--content-kind", default="", help="json, jsonl, jsonp, csv, html_table, pdf, image, ...")
    c = cmd("entry get", "Show one entry (redacted)", cmd_entry_get)
    _har(c)
    c.add_argument("entry_id", type=int)
    c.add_argument("--max-body-chars", type=int, default=4000)
    c = cmd("entry around", "Chronological neighbours of an entry (click -> XHR)", cmd_entry_around)
    _har(c)
    c.add_argument("entry_id", type=int)
    _host(c)
    _noise(c)
    c.add_argument("--before", type=int, default=5)
    c.add_argument("--after", type=int, default=15)
    c = cmd("entry initiators", "Initiator parent and children of an entry", cmd_entry_initiators)
    _har(c)
    c.add_argument("entry_id", type=int)
    _noise(c)
    c.add_argument("--child-limit", type=int, default=40)
    c = cmd("entry compare", "Compare two entries", cmd_entry_compare)
    _har(c)
    c.add_argument("entry_id", type=int)
    c.add_argument("other_entry_id", type=int)
    c = cmd("entry build-curl", "curl command for an entry (printed, not run)", cmd_entry_build_curl)
    _har(c)
    c.add_argument("entry_id", type=int)
    c.add_argument("--redact", action=_BOOL, default=True, help="Redact secrets (default on)")
    c.add_argument("--use-env-placeholders", action=_BOOL, default=True, help="Use $ENV placeholders for secrets (default on)")
    c = cmd("entry body-query", "Search inside a large body by JSONPath-lite or regex (paged)", cmd_entry_body_query)
    _har(c)
    c.add_argument("entry_id", type=int)
    c.add_argument("--side", default="response", choices=("request", "response"))
    c.add_argument("--jsonpath")
    c.add_argument("--regex")
    c.add_argument("--offset", type=int, default=0)
    _limit(c, 20)
    c = cmd("entry outline", "HTML/XML document outline (markdown, tree, aria)", cmd_entry_outline)
    _har(c)
    c.add_argument("entry_id", type=int)
    c.add_argument("--format", default="all", choices=("all", "markdown", "tree", "aria"))
    c.add_argument("--max-depth", type=int, default=8)
    c.add_argument("--side", default="response")
    c.add_argument("--markdown-only", action="store_true", help="Print the markdown outline (not JSON)")
    c = cmd("entry dependencies", "What a request depends on: prior steps and carried values", cmd_entry_dependencies)
    _har(c)
    c.add_argument("entry_id", type=int)
    _host(c)
    c.add_argument("--max-depth", type=int, default=8)

    # ---- endpoint, spec, tech
    c = cmd("endpoint list", "Endpoint templates with counts", cmd_endpoint_list)
    _har(c)
    _host(c)
    _noise(c)
    _limit(c, 100)
    c = cmd("endpoint schema", "Request/response shapes of one endpoint template", _delegate("endpoint_schema", "method", "path_template", "host", "sections", "limit"))
    _har(c)
    c.add_argument("method")
    c.add_argument("path_template")
    _host(c)
    _sections(c, "schema (default), param_roles")
    _limit(c)
    c = cmd("endpoint graphql", "GraphQL operations behind shared URLs", cmd_endpoint_graphql)
    _har(c)
    _host(c)
    _limit(c, 40)
    c = cmd("endpoint streams", "gRPC / protobuf / MessagePack / CSV / SSE / WebSocket bodies (shapes only)", cmd_endpoint_streams)
    _har(c)
    _host(c)
    _limit(c, 40)
    c.add_argument("--kind")
    c = cmd("endpoint pagination", "Cursor / next-link / Link-header pagination", cmd_endpoint_pagination)
    _har(c)
    _host(c)
    _limit(c, 20)
    c = cmd("endpoint arcgis", "ArcGIS REST endpoints seen in a capture", cmd_endpoint_arcgis)
    _har(c)
    _host(c)
    c = cmd("spec contract-check", "Drift between a capture and an exported OpenAPI file", cmd_spec_contract_check)
    _har(c)
    c.add_argument("spec_path", help="OpenAPI file")
    _host(c)
    c = cmd("tech stack", "Frameworks, CMS, GIS, UI toolkits and data grids", _delegate("tech_stack", "host", "limit", "explain"))
    _har(c)
    _host(c)
    _limit(c)
    _explain(c)

    # ---- page, auth, gate
    c = cmd("page list", "HAR pageref groups", cmd_page_list)
    _har(c)
    _host(c)
    _noise(c)
    _limit(c, 40)
    c = cmd("page forms", "HTML forms and inputs from response bodies", _delegate("page_forms", "entry_id", "host", "side", "exclude_noise", "limit", "offset"))
    _har(c)
    c.add_argument("--entry-id", type=int)
    _host(c)
    c.add_argument("--side", default="response", choices=("response", "request"))
    _noise(c)
    _limit(c)
    c.add_argument("--offset", type=int)
    c = cmd("page ui", "Links, handlers, labels and search links", _delegate("page_ui", "entry_id", "host", "side", "sections", "keywords", "exclude_noise", "limit", "offset"))
    _har(c)
    c.add_argument("--entry-id", type=int)
    _host(c)
    c.add_argument("--side", default="response", choices=("response", "request"))
    _sections(c, "links, handlers, labels (default all three), search_links")
    c.add_argument("--keywords", type=_csv, help="Comma list of domain terms for search_links")
    _noise(c)
    _limit(c)
    c.add_argument("--offset", type=int)
    c = cmd("page embedded-routes", "URL path literals in JavaScript and data-* attributes", _delegate("page_embedded_routes", "host", "entry_id", "sections", "explain", "limit", "offset"))
    _har(c)
    _host(c)
    c.add_argument("--entry-id", type=int)
    _sections(c, "script_routes, data_attrs (default both)")
    _explain(c)
    _limit(c)
    c.add_argument("--offset", type=int)
    c = cmd("page tables", "HTML data tables: headers, counts, masked first row", cmd_page_tables)
    _har(c)
    _host(c)
    c.add_argument("--entry-id", type=int)
    c = cmd("auth report", "Authentication evidence by section (names and shapes only)", _delegate("auth_report", "host", "sections", "pattern_kinds", "limit", "explain"))
    _har(c)
    _host(c)
    _sections(c, "quick (default), patterns, credentials, secret_names, cookies")
    c.add_argument("--pattern-kinds", type=_csv, help="Restrict the patterns section to these detectors")
    _limit(c)
    _explain(c)
    c = cmd("gate bot-protection", "Gates in a capture: bot walls, captcha, login, challenges, CDN/WAF products", _delegate("gate_bot_protection", "host", "sections", "limit", "explain"))
    _har(c)
    _host(c)
    _sections(c, "barriers, http_challenges, bot_protection (default all)")
    _limit(c)
    _explain(c)

    # ---- har, client
    from hardly.core import har_doctor as _hd

    c = cmd("har file-check", "Diagnose HAR problems (truncated bodies, sanitised cookies, skew, noise); exit code via --fail-on", cmd_har_file_check)
    c.add_argument("har_path", help="HAR file")
    _hd.add_cli_flags(c)
    c = cmd("client build", "Minimal Python (urllib) client sketch, printed", cmd_client_build)
    _har(c)
    _host(c)
    c.add_argument("--entry-ids", type=_entry_ids_arg, help="Comma list of entry ids (default: from the story)")
    c.add_argument("--class-name", default="PortalClient")

    # ---- write
    c = cmd("write export", "Write openapi, postman, api_markdown, site_brief, report, client_python or plan_steps",
            _delegate("write_export", "format", "output:output_path", "host", "exclude_noise", "title", "max_endpoints", "detail", "categories", "entry_ids", "class_name", "limit", "overwrite"))
    _har(c)
    c.add_argument("--format", required=True, choices=("openapi", "postman", "api_markdown", "site_brief", "report", "client_python", "plan_steps"))
    _output(c, "Output file (a directory for --format report gets <har>.report.md)")
    _host(c)
    _noise(c)
    _overwrite(c)
    c.add_argument("--title", help="API title (openapi) or collection name (postman)")
    c.add_argument("--max-endpoints", type=int)
    c.add_argument("--detail", choices=("summary", "standard", "full"), default="standard")
    c.add_argument("--categories", type=_csv, help="report: comma list access,auth,stack,data,forms")
    c.add_argument("--entry-ids", type=_entry_ids_arg, help="client_python: comma list of entry ids")
    c.add_argument("--class-name", help="client_python: class name")
    _limit(c, None, "plan_steps: maximum steps")
    c = cmd("write session-copy", "Save a copy of the source HAR (or the SQLite index), never in place", _delegate("write_session_copy", "output:output_path", "format", "overwrite"))
    _har(c)
    _output(c, "Where to write the copy")
    c.add_argument("--format", choices=("har", "index"), default="har")
    _overwrite(c)
    c = cmd("write har-pruned", "Drop hosts, MIME types or noise from a HAR (new file)", cmd_write_har)
    c.add_argument("har_path")
    _output(c, "Output HAR")
    _overwrite(c)
    c.add_argument("--drop-hosts", type=_csv, help="Comma list of hosts to drop")
    c.add_argument("--drop-mime-types", type=_csv, help="Comma list of MIME types to drop")
    c.add_argument("--drop-noise", action="store_true")
    c = cmd("write har-scrubbed", "Scrub secrets from a HAR (new file)", cmd_write_har)
    c.add_argument("har_path")
    _output(c, "Output HAR")
    _overwrite(c)
    c = cmd("write har-split", "Split a HAR by host or page into a directory", cmd_write_har)
    c.add_argument("har_path")
    c.add_argument("--output-dir", required=True, help="Output directory")
    _overwrite(c)
    c.add_argument("--by", choices=("host", "page"), default="host")
    c = cmd("write har-merged", "Merge several HARs into one (new file)", cmd_write_har)
    c.add_argument("har_paths", nargs="+", help="HAR files to merge")
    _output(c, "Output HAR")
    _overwrite(c)
    c.add_argument("--dedupe", action=_BOOL, default=True, help="Drop duplicate entries (default on)")
    c = cmd("write catalog-record", "Add or update one target in a catalog file", cmd_write_catalog_record)
    c.add_argument("catalog_path", help="Catalog JSON/YAML file")
    c.add_argument("--id", required=True, help="Target id")
    c.add_argument("--name")
    c.add_argument("--tags", type=_csv, help="Comma list of tags")
    c.add_argument("--group", action="append", help="key=value (repeatable)")
    c.add_argument("--endpoint", action="append", help="role=url[,kind] (repeatable)")
    c.add_argument("--merge", action=_BOOL, default=True, help="Merge into the target (--no-merge replaces it)")
    c.add_argument("--create", action="store_true", help="Create the catalog file if missing")
    c = cmd("write screenshot", "PNG screenshot of the running browser tab", _delegate("write_screenshot", "output:output_path", "capture_id", "full_page", "overwrite"))
    _output(c, "Output .png path")
    _capture_id(c)
    c.add_argument("--full-page", action="store_true")
    _overwrite(c)

    # ---- send (live)
    c = cmd("send entry", "LIVE: replay one captured request", _delegate("send_entry", "entry_id", "confirm", "timeout_seconds"))
    _har(c)
    c.add_argument("entry_id", type=int)
    _confirm(c, "Send the request")
    c.add_argument("--timeout-seconds", type=float, default=30.0)
    c = cmd("send entry-ablation", "LIVE: replay with one element removed at a time to find what is required", cmd_send_entry_ablation)
    _har(c)
    c.add_argument("entry_ids", nargs="+", type=str, help="One entry id, or an ordered flow (last = target); commas allowed")
    _confirm(c)
    c.add_argument("--overrides", help='Inline JSON: {"headers":{},"cookies":{},"query":{},"body":{}}')
    c.add_argument("--max-requests", type=int, default=15)
    c.add_argument("--delay-seconds", type=float, default=0.5)
    c.add_argument("--allow-unsafe", action="store_true", help="Allow POST/PUT/PATCH/DELETE")
    c.add_argument("--allow-gates", type=_csv, help="Comma list of gate classes to tolerate, e.g. login")
    c = cmd("send entry-series", "LIVE: replay an ordered series and find the first diverging step", cmd_send_entry_series)
    _har(c)
    c.add_argument("--entry-id", type=int, help="Target entry (its dependencies are replayed first)")
    c.add_argument("--entry-ids", type=_entry_ids_arg, help="Explicit ordered comma list of entry ids")
    _confirm(c)
    c.add_argument("--env", help="Inline JSON {name: value}; or use HARDLY_INPUT_<NAME> env vars")
    c.add_argument("--delay-seconds", type=float, default=0.5)
    c.add_argument("--max-requests", type=int, default=20)
    c.add_argument("--allow-unsafe", action="store_true")
    c.add_argument("--allow-gates", type=_csv, help="Comma list of gate classes to tolerate")
    c = cmd("send site-crawl", "LIVE: polite robots-aware crawl for candidate pages",
            _delegate("send_site_crawl", "url", "keywords", "confirm", "max_pages", "depth", "delay_seconds", "follow_external", "respect_robots", "timeout_seconds", "user_agent", "explain"))
    c.add_argument("url")
    _confirm(c)
    c.add_argument("--keywords", type=_csv, help="Comma list of domain terms")
    c.add_argument("--max-pages", type=int, default=12)
    c.add_argument("--depth", type=int, default=2)
    c.add_argument("--delay-seconds", type=float, default=1.0, help="Seconds between requests per host")
    c.add_argument("--follow-external", action="store_true")
    c.add_argument("--respect-robots", action=_BOOL, default=True, help="Honour robots.txt (default on; disable only where you are permitted)")
    c.add_argument("--timeout-seconds", type=float, default=15.0)
    c.add_argument("--user-agent", help='Default is an honest hardly UA; "browser" or a custom string')
    _explain(c)
    c = cmd("send arcgis-explore", "LIVE: explore an ArcGIS REST service (GET only, at most 7 requests)", _delegate("send_arcgis_explore", "url", "confirm"))
    c.add_argument("url")
    _confirm(c)
    c = cmd("send redirect-walk", "LIVE: follow a redirect chain by hand, with and without cookies", _delegate("send_redirect_walk", "url", "confirm", "max_hops"))
    c.add_argument("url")
    _confirm(c)
    c.add_argument("--max-hops", type=int, default=12)
    c = cmd("send catalog-verify", "LIVE: politely verify catalog endpoints", cmd_send_catalog_verify)
    c.add_argument("catalog_path")
    _confirm(c)
    c.add_argument("--write-back", action="store_true", help="Record statuses in the catalog file")
    _catalog_filters(c)
    c.add_argument("--delay-seconds", type=float, default=1.0, help="Seconds between requests per host")
    c.add_argument("--max-requests", type=int, default=50)
    c.add_argument("--max-endpoints", type=int)
    c.add_argument("--recheck-after-seconds", type=float, help="Re-verify endpoints older than this")
    c.add_argument("--force", action="store_true", help="Re-verify already-checked endpoints")

    # ---- browser, capture
    c = cmd("browser start", "Start recording in a real browser; the browser stays open", cmd_browser_start)
    c.add_argument("url", nargs="?", default="", help="Start URL (optional)")
    _browser_launch(c, headed_default=True)
    c.add_argument("--profile", help="Persistent browser profile directory (keeps cookies)")
    c.add_argument("--foreground", action="store_true", help="Record until you press Enter / close the window (CLI only)")
    c = cmd("browser stop", "Stop a capture and flush the HAR", _delegate("browser_stop", "capture_id", "open_session", "force"))
    _capture_id(c)
    c.add_argument("--open-session", action=_BOOL, default=True, help="Index the HAR into a session after stop")
    c.add_argument("--force", action="store_true")
    c = cmd("browser capture-discover", "LIVE: unattended time-boxed capture of a URL; --analyze also discovers its APIs", cmd_browser_capture_discover)
    c.add_argument("url")
    c.add_argument("--wait-seconds", type=float, help="Seconds to record (default 20; 5 with --analyze)")
    c.add_argument("--analyze", action="store_true", help="Headless: run --steps, open a session and return a brief")
    _confirm(c, "Load the URL in a browser")
    _browser_launch(c, headed_default=False)
    c.add_argument("--steps", help="JSON file of steps (goto/wait/aria/click/fill/find_click ...); needs --analyze")
    c.add_argument("--budget-seconds", type=float, help="Hard per-call budget (env HARDLY_CAPTURE_BUDGET)")
    c.add_argument("--exclude-noise", action=_BOOL, default=False, help="Abort analytics/ads/fonts/map tiles/heavy media while loading")
    c.add_argument("--open-session", action=_BOOL, default=True, help="Index the HAR into a session after stop")
    c.add_argument("--brief", action=_BOOL, default=True, help="With --analyze: attach the brief")
    c.add_argument("--diagnose-redirects", action="store_true", help="On a redirect-loop failure attach a capped diagnosis (a few polite live GETs)")
    c = cmd("browser interact", "Drive the running tab: goto, click, fill or press",
            _delegate("browser_interact", "action", "capture_id", "url", "ref", "css", "xpath", "text", "role", "name", "value", "key", "timeout_seconds"))
    c.add_argument("action", choices=("goto", "click", "fill", "press"))
    _capture_id(c)
    c.add_argument("--url", help="goto: where to navigate")
    c.add_argument("--ref", help="Aria ref from `hardly browser inspect --sections aria` (e12)")
    c.add_argument("--css")
    c.add_argument("--xpath")
    c.add_argument("--text")
    c.add_argument("--role")
    c.add_argument("--name")
    c.add_argument("--value", help="fill: the value to type")
    c.add_argument("--key", help="press: key name (default Enter)")
    c.add_argument("--timeout-seconds", type=float, default=10.0)
    c = cmd("browser inspect", "Read the running tab: url, elements, aria", _delegate("browser_inspect", "capture_id", "sections", "query", "limit", "selector", "mode"))
    _capture_id(c)
    _sections(c, "url (default), elements, aria")
    _limit(c)
    c.add_argument("--query", help="elements: CSS selector override")
    c.add_argument("--selector", help="aria: CSS scope (default body)")
    c.add_argument("--mode", choices=("ai", "default"), help="aria: ai includes [ref=eN]")
    c = cmd("browser run-steps", "Run a JSON list of steps (goto/click/fill/wait/...) on the running tab", cmd_browser_run_steps)
    c.add_argument("steps", help='JSON file: [{"op":"goto","url":"..."}, ...]')
    _capture_id(c)
    c.add_argument("--stop-on-error", action=_BOOL, default=True, help="Stop at the first failed step (default on)")
    c = cmd("capture list", "List browser captures, or the status of one", _delegate("capture_list", "capture_id"))
    _capture_id(c)

    # ---- catalog
    c = cmd("catalog list", "List catalog endpoints (one row each), filtered", cmd_catalog_list)
    c.add_argument("catalog_path")
    _catalog_filters(c)
    c.add_argument("--detail", choices=("summary", "full"), default="full", help="summary = counts by tag/group/role/status/gate/stack")
    c = cmd("catalog init", "Create an empty catalog file (.json, or .yaml with PyYAML)", cmd_catalog_init)
    c.add_argument("catalog_path")
    c.add_argument("--name", default="catalog")
    c.add_argument("--force", action="store_true")
    c = cmd("catalog show", "Show one target", cmd_catalog_show)
    c.add_argument("catalog_path")
    c.add_argument("target_id")
    c = cmd("catalog export", "Write the catalog as json, yaml or csv", cmd_catalog_export)
    c.add_argument("catalog_path")
    c.add_argument("--format", choices=("json", "yaml", "csv"), default="json")
    _output(c, "Output file (default: stdout)", required=False)

    # ---- skill, soak, serve
    sp = subs["skill"].add_parser("install", help="Write SKILL.md + references/")
    sp.add_argument("--dest", default="", help="Skill directory to write (default ~/.claude/skills/hardly)")
    sp.set_defaults(func=cmd_skill)
    sp = subs["skill"].add_parser("print", help="Print SKILL.md to stdout")
    sp.set_defaults(func=cmd_skill)
    top.choices["skill"].set_defaults(func=cmd_skill, dest="")

    c = subs["soak"].add_parser("live", help="Headless soak: capture public tech demos on the fly (needs the capture extra)")
    c.add_argument("--ids", default="", help="Comma-separated target ids (default: all); use --list")
    c.add_argument("--list", action="store_true", help="Print the public target catalog and exit")
    c.add_argument("--fail-soft", action="store_true", help="Treat soft targets (GraphQL UI, Swagger) as hard failures")
    c.add_argument("--json", action="store_true", help="Print full JSON summary only")
    c.add_argument("--write-fixtures", default="", help="Write small redacted HTML/JSON snippets from successful captures")
    c.set_defaults(func=cmd_soak_live)

    sp = top.add_parser("serve", help="Run the MCP server (stdio)")
    sp.set_defaults(func=cmd_serve)
    return p


def _catalog_filters(p: argparse.ArgumentParser) -> None:
    p.add_argument("--tag", help="Required tags, comma separated")
    p.add_argument("--group", action="append", help="Require group key=value (repeatable)")
    p.add_argument("--role", help="Endpoint role")
    p.add_argument("--status", choices=["unverified", "verified", "blocked", "dead", "needs_browser"])
    p.add_argument("--target-id", help="Only this target")


def main(argv: list[str] | None = None) -> None:
    import signal

    if hasattr(signal, "SIGPIPE"):  # `hardly ... | head` must not traceback
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    parser = build_parser()
    args = parser.parse_args(list(sys.argv[1:] if argv is None else argv))
    if not hasattr(args, "func"):
        args.group_parser.print_help()
        sys.exit(2)
    if getattr(args, "allow_private_hosts", False):
        from hardly.core.netguard import allow_private_hosts

        allow_private_hosts()
    try:
        code = args.func(args)
    except sess.SessionError as exc:  # guard refusals and other coded errors: JSON, not a traceback
        _print(exc.to_dict())
        code = 1
    sys.exit(code)


if __name__ == "__main__":
    main()
