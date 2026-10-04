"""FastMCP server exposing hardly tools.

Naming scheme (v1, permanent; ``tests/api_surface.json`` pins it):

* ``hardly_send_*``   sends network requests; confirm-gated (no ``confirm=true`` returns a plan).
* ``hardly_write_*``  writes a file; refuses to replace one unless ``overwrite=true``.
* ``hardly_browser_*`` drives or reads a real browser.
* everything else only reads loaded data (``session_open`` / ``session_close`` change memory only).

Merged tools take a ``sections`` list (or one scalar ``format`` / ``action`` enum); unset means
omitted or null, never ``''`` or ``0``; lists and objects are native JSON.
"""

from __future__ import annotations

import json
from typing import Any

from fastmcp import FastMCP

from hardly import session as sess
from hardly.session import resolve_path

INSTRUCTIONS = """\
hardly analyzes HAR files (recorded browser traffic) and can record them, so you \
can discover an API, understand login/session flows, and build a client SDK or \
OpenAPI spec. Use when asked to read/analyze a HAR, find endpoints, \
forms, cookies, CSRF or pagination, capture a site, or verify a client. \
Content-neutral: you supply site vocabulary, hardly detects technologies.

Start: call hardly_guide_task_plan(goal, har_path, url) for an ordered plan and \
environment state (browser available? sessions open?). Cheat sheet: resource \
hardly://cheatsheet. Workflow prompts: reverse_engineer_api, build_client_sdk, \
diagnose_blocked_capture, verify_client.

Names tell the effect: hardly_send_* sends requests (confirm-gated), \
hardly_write_* writes a file (overwrite=true to replace), hardly_browser_* \
drives a real browser; all other tools only read loaded data.

Workflow:
1. Choose mode. Have a .har: archive, hardly_session_open. Scriptable URL: \
headless, hardly_browser_capture_discover(analyze=true, confirm=true). \
Wall/captcha/MFA/login or a person is needed: interactive, \
hardly_browser_start(headed=true, channel='chrome'), ASK THE PERSON to use the \
window, then hardly_browser_stop(open_session=true).
2. Orient with session_id: hardly_session_report(detail='summary'), \
hardly_session_overview (use main_host as host=), then hardly_session_site_brief \
(HTML portals) or hardly_endpoint_list (JSON APIs).
3. Drill down: session_story / page_forms / entry_outline, auth_report / \
session_trace_value, entry_get, entry_body_query (big bodies), endpoint_schema, \
endpoint_pagination.
4. Produce: hardly_client_build, hardly_write_export (format=openapi | \
api_markdown | postman | site_brief | report | client_python; scratch dir).
5. Verify: hardly_entry_dependencies (offline), then hardly_send_entry_series / \
hardly_send_entry_ablation (live).

Rules:
- Never Read a raw HAR; use hardly_session_open and the query tools. Results are \
small, redacted and paged (limit/offset); keep limits small.
- send_* tools and browser_capture_discover send nothing without confirm=true \
(they return a plan); tell the person what will be sent first.
- Gates (bot wall, captcha, proof of work, waiting room, login, paywall, rate \
limit) are stop signs: do not evade or retry; use interactive capture with a \
person. An environment_blocked verdict means unknown, re-run elsewhere.
- Secret values are never returned. Supply secrets only via overrides/env.
- Only hardly_write_* tools write files (output_path / output_dir). Session ids do \
not survive an MCP restart: call hardly_session_open again with the same path. \
Tool missing: hardly_server_status (restart the server). Browser problems: \
hardly_server_status(sections=['browser_setup']).
"""

mcp = FastMCP("hardly", instructions=INSTRUCTIONS)


def _ok(data: Any) -> str:
    return json.dumps(data, indent=2, default=str)


class ToolError(sess.SessionError):
    """A caller mistake with a stable ``code`` and the exact fix in ``hint``."""

    def __init__(self, message: str, hint: str | None = None, code: str = "invalid_argument"):
        super().__init__(message, hint)
        self.code = code


def _hint_for(exc: Exception) -> tuple[str | None, str | None]:
    """(code, hint) for the most common first-use mistakes."""
    msg = str(exc.args[0]) if exc.args else str(exc)
    low = msg.lower()
    if "unknown session_id" in low:
        return (
            "unknown_session",
            "hardly_session_list shows known ids; otherwise hardly_session_open(har_path) or "
            "hardly_browser_capture_discover(url, analyze=true, confirm=true) creates a session.",
        )
    if isinstance(exc, FileExistsError) or "already exists" in low or "exists (pass overwrite" in low:
        return "output_exists", "Pass overwrite=true to replace it, or choose another output path."
    if isinstance(exc, FileNotFoundError) or "no such file" in low:
        return (
            "file_not_found",
            "Check the path (use an absolute path on the machine running the MCP "
            "server). Already-indexed HARs: hardly_session_list.",
        )
    if "confirm" in low and "true" in low:
        return "confirm_required", "Tell the person what will be sent, then repeat with confirm=true."
    if isinstance(exc, ImportError):
        return (
            "optional_dependency_missing",
            "Optional dependency missing: hardly_server_status(sections=['browser_setup']) "
            "lists the install commands.",
        )
    return None, None


def _err(exc: Exception) -> str:
    if isinstance(exc, sess.SessionError):
        return _ok(exc.to_dict())
    msg = str(exc.args[0]) if isinstance(exc, KeyError) and exc.args else str(exc)
    out: dict[str, Any] = {"error": msg}
    code, hint = _hint_for(exc)
    if code:
        out["code"] = code
    if hint and hint not in msg:
        out["hint"] = hint
    return _ok(out)


def _tool(fn):
    """Register an MCP tool; turn common exceptions into actionable JSON errors."""
    import functools

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except sess.SessionError as exc:
            return _err(exc)
        except (FileNotFoundError, FileExistsError, NotADirectoryError, ImportError) as exc:
            return _err(exc)
        except KeyError as exc:
            if "unknown session_id" in str(exc).lower():
                return _err(exc)
            raise
        except ValueError as exc:
            out = json.loads(_err(exc))
            out.setdefault("code", "invalid_argument")
            return _ok(out)
        except RecursionError:  # a pathologically nested body or argument, never a crash
            return _ok(
                {
                    "error": "the data is nested too deeply to process",
                    "code": "input_too_deep",
                    "hint": "A body or argument nests more than ~100 levels; use hardly_entry_body_query "
                    "(jsonpath/regex) on the entry, or hardly_har_file_check to find oversized entries.",
                }
            )
        except Exception as exc:  # noqa: BLE001
            if type(exc).__name__ == "CaptureError":
                return _err(exc)
            raise

    return mcp.tool(wrapper)


# ----------------------------------------------------------------------------- helpers


def _lim(value: int | None, default: int, cap: int) -> int:
    """limit: omitted -> tool default; always clamped to [1, cap]."""
    return max(1, min(default if value is None else int(value), cap))


def _off(value: int | None) -> int:
    return max(0, int(value or 0))


def _sections(tool: str, sections: list[str] | str | None, valid: tuple[str, ...], default: tuple[str, ...]) -> list[str]:
    """Validate a ``sections`` argument; unknown names raise ``unknown_section`` listing the valid ones."""
    if sections is None:
        return list(default)
    wanted = [sections] if isinstance(sections, str) else [str(s) for s in sections]
    if not wanted:
        return list(default)
    bad = [s for s in wanted if s not in valid]
    if bad:
        raise ToolError(
            f"{tool}: unknown section(s): {', '.join(bad)}",
            f"Valid sections: {', '.join(valid)}. Default: {', '.join(default)}.",
            "unknown_section",
        )
    return list(dict.fromkeys(wanted))


def _choice(tool: str, field: str, value: str, valid: tuple[str, ...]) -> str:
    if value not in valid:
        raise ToolError(
            f"{tool}: unknown {field} {value!r}",
            f"Valid {field} values: {', '.join(valid)}.",
            f"unknown_{field}",
        )
    return value


def _need(tool: str, name: str, value: Any, when: str = "") -> None:
    if value is None or value == "":
        raise ToolError(
            f"{tool}: {name} is required{when}",
            f"Pass {name}=...; see the tool description for the exact call.",
            "missing_argument",
        )


def _out(output_path: str | None, overwrite: bool, *, default_name: str | None = None):
    """Resolve a ``write_*`` target; refuse an existing file unless ``overwrite`` is true."""
    if not output_path:
        raise ToolError(
            "output_path is required",
            "write_* tools never choose a path: pass output_path=<file> (use a scratch directory).",
            "missing_argument",
        )
    from hardly.core.pathguard import guard_write

    p = resolve_path(output_path)
    if p.is_dir():
        if default_name is None:
            raise sess.OutputError(f"output_path is a directory: {p}", "Give a file name.")
        p = p / default_name
    guard_write(p)
    if p.exists() and not overwrite:
        raise sess.OutputExists(
            f"output_path already exists: {p}",
            "Pass overwrite=true to replace it, or choose another path.",
        )
    return p


_CONFIRM_HINT = (
    "Nothing was sent. Tell the person exactly what will be sent, then repeat the same call "
    "with confirm=true."
)


def _dry_run(plan: dict[str, Any]) -> str:
    """The reply of a confirm-gated tool called without ``confirm=true``."""
    return _ok({"confirmed": False, "sent": False, "plan": plan, "hint": _CONFIRM_HINT})


def _entry_rows(conn, entry_ids: list[int]) -> tuple[list[dict[str, Any]], list[int]]:
    from hardly.core.netguard import check_url
    from hardly.core.redact import redact_url

    rows: list[dict[str, Any]] = []
    missing: list[int] = []
    for eid in entry_ids:
        r = conn.execute(
            "SELECT entry_id, method, scheme, host, path, query_raw FROM entries WHERE entry_id = ?",
            (int(eid),),
        ).fetchone()
        if not r:
            missing.append(int(eid))
            continue
        url = f"{r['scheme'] or 'https'}://{r['host']}{r['path']}" + (f"?{r['query_raw']}" if r["query_raw"] else "")
        check_url(url)  # a plan must not hide a request the live call would refuse
        rows.append({"entry_id": int(r["entry_id"]), "method": r["method"], "url": redact_url(url)})
    return rows, missing


# ----------------------------------------------------------------------------- guide and server


@_tool
def hardly_server_status(sections: list[str] | None = None) -> str:
    """Server version, feature flags, tool names and browser availability; sections: capabilities (default), browser_setup. Call when a tool seems missing (restart the MCP server) or capture fails.

    ``capabilities``: version, features, tools, capture_available (small, ~3 KB).
    ``browser_setup``: Playwright package and browser binaries, with the exact install commands.
    Example: hardly_server_status(sections=['browser_setup']).
    """
    secs = _sections("server_status", sections, ("capabilities", "browser_setup"), ("capabilities",))
    out: dict[str, Any] = {"sections": secs}
    if "capabilities" in secs:
        from hardly.capabilities import capabilities

        out["capabilities"] = capabilities()
    if "browser_setup" in secs:
        from hardly.capture import playwright_status

        out["browser_setup"] = playwright_status()
    return _ok(out)


@_tool
def hardly_guide_help(topic: str | None = None) -> str:
    """Categorized catalog of tools and workflows; pass topic to filter. Use when you do not know which tool fits (topics: portal, tokens, capture, modes, or a tool name); for a task-specific plan use hardly_guide_task_plan. Example: hardly_guide_help(topic='capture').
    """
    from hardly.core.help import tool_help

    return _ok(tool_help(topic or None))


@_tool
def hardly_guide_mode(
    mode: str | None = None,
    goal: str | None = None,
    har_path: str | None = None,
    url: str | None = None,
) -> str:
    """List the three operating modes (archive, headless, interactive), or get the playbook for one mode, or auto-pick a mode from goal / har_path / url. Example: hardly_guide_mode(har_path='/data/capture.har').

    With no argument it lists the modes and when to use each. With ``mode`` it returns that mode's
    step-by-step playbook; with goal / har_path / url (and no mode) a mode is chosen for you.
    ``hardly_guide_task_plan`` is the better first call for a full ordered plan.
    """
    from hardly.core.modes import list_modes, mode_playbook, pick_mode

    if (mode or "").strip():
        return _ok(mode_playbook(mode, har_path=har_path or "", url=url or "", goal=goal or ""))
    if not any((goal, har_path, url)):
        return _ok(list_modes())
    return _ok(pick_mode(goal=goal or "", har_path=har_path or "", url=url or ""))


@_tool
def hardly_guide_task_plan(goal: str | None = None, har_path: str | None = None, url: str | None = None) -> str:
    """FIRST CALL for a new task: ordered plan of hardly tool calls with example arguments, environment state and recommended tools for the goal. Example: hardly_guide_task_plan(goal='reverse engineer the login flow', har_path='/data/capture.har').

    Pass what you know: goal (free text, e.g. 'build a client SDK'), har_path, url. Small output
    (~2 KB). For one mode's playbook use hardly_guide_mode, for the tool catalog hardly_guide_help.
    """
    from hardly.core.start import build_plan

    return _ok(build_plan(goal=goal or "", har_path=har_path or "", url=url or ""))


# ----------------------------------------------------------------------------- sessions, HAR files


@_tool
def hardly_session_open(har_path: str, force: bool = False) -> str:
    """Index a HAR file (or open a saved index) into a queryable session and return session_id plus summary counts. Start here for any HAR; never Read the raw HAR. Writes nothing (save an index with hardly_write_session_copy). Example: hardly_session_open(har_path='/data/capture.har').

    Opening the same path again returns the same session; force=true re-ingests the HAR.
    """
    return _ok(sess.open_har(har_path, force=force))


@_tool
def hardly_session_close(session_id: str) -> str:
    """Close an open session to free memory (the session is discarded; files saved with hardly_write_session_copy stay). Example: hardly_session_close(session_id='S').
    """
    return _ok(sess.close_session(session_id))


@_tool
def hardly_session_list() -> str:
    """List open HAR sessions (session_id, har_path, index_path). Use when you lost a session_id. No arguments. Example: hardly_session_list().
    """
    rows = []
    for r in sess.list_sessions():
        row = {k: v for k, v in r.items() if k != "saved_to"}
        row["index_path"] = r.get("saved_to")
        rows.append(row)
    return _ok({"count": len(rows), "sessions": rows})


@_tool
def hardly_write_session_copy(
    session_id: str,
    output_path: str,
    format: str = "har",
    overwrite: bool = False,
) -> str:
    """Writes a file: save a copy of the session's source HAR (format='har') or its SQLite index (format='index') to output_path. Never in place; refuses to overwrite unless overwrite=true. Example: hardly_write_session_copy(session_id='S', output_path='/data/keep.har').

    An ephemeral capture's HAR is already deleted (code har_ephemeral_gone): save the index instead,
    or capture again with har_output_path.
    """
    fmt = _choice("write_session_copy", "format", format, ("har", "index"))
    _need("write_session_copy", "output_path", output_path)
    res = sess.export_har(session_id, output_path, overwrite=overwrite) if fmt == "har" else sess.save_index(
        session_id, output_path, overwrite=overwrite
    )
    if "error" not in res:
        res["format"] = fmt
        res["output_path"] = res.get("saved_to")
        res["bytes"] = res.get("size_bytes")
    return _ok(res)


@_tool
def hardly_har_file_check(har_path: str, config: dict[str, Any] | None = None) -> str:
    """Diagnose a HAR file on disk (truncated/omitted bodies, sanitised cookies, clock skew, noise); no session needed. Findings carry a fix_hint such as recapture flags. Example: hardly_har_file_check(har_path='/data/capture.har').

    Session-level body counts are hardly_session_body_coverage. Optional ``config`` (object): checks,
    exclude, severity_overrides, thresholds{max_entry_bytes, truncation_ratio, clock_skew_s,
    noise_ratio, min_entries}, strict, fail_on, host, ignore_hosts, ignore_paths, max_findings, fix.
    """
    from hardly.core.har_doctor import diagnose_har

    return _ok(diagnose_har(None, har_path, config))


@_tool
def hardly_write_har_pruned(
    har_path: str,
    output_path: str,
    drop_hosts: list[str] | None = None,
    drop_mime_types: list[str] | None = None,
    drop_noise: bool = False,
    overwrite: bool = False,
) -> str:
    """Writes a file: a pruned copy of a HAR (drop hosts, mime globs, known noise); never in place, refuses an existing output_path unless overwrite=true. Example: hardly_write_har_pruned(har_path='/data/a.har', output_path='/data/a.small.har', drop_noise=true).
    """
    from hardly.core.har_tools import prune_har

    return _ok(prune_har(har_path, output_path, drop_hosts or [], drop_mime_types or [], drop_noise, overwrite=overwrite))


@_tool
def hardly_write_har_scrubbed(har_path: str, output_path: str, overwrite: bool = False) -> str:
    """Writes a file: a scrubbed copy of a HAR with secret values, cookies and auth headers replaced by ***REDACTED*** (structure and shapes kept). Never in place; needs overwrite=true to replace. Example: hardly_write_har_scrubbed(har_path='/data/a.har', output_path='/data/a.scrubbed.har').
    """
    from hardly.core.har_tools import scrub_har

    return _ok(scrub_har(har_path, output_path, overwrite=overwrite))


@_tool
def hardly_write_har_split(har_path: str, output_dir: str, by: str = "host", overwrite: bool = False) -> str:
    """Writes files: split a HAR into one file per host (by='host') or per page (by='page') inside output_dir, streaming. Example: hardly_write_har_split(har_path='/data/a.har', output_dir='/data/parts').

    Use for huge captures, then hardly_session_open each part. Refuses to overwrite existing parts unless overwrite=true.
    """
    from hardly.core.har_tools import split_har

    _choice("write_har_split", "by", by, ("host", "page"))
    return _ok(split_har(har_path, by, output_dir, overwrite=overwrite))


@_tool
def hardly_write_har_merged(
    har_paths: list[str],
    output_path: str,
    dedupe: bool = True,
    overwrite: bool = False,
) -> str:
    """Writes a file: merge several HARs into output_path, prefixing page ids and dropping exact duplicates (dedupe=true). Needs overwrite=true to replace. Example: hardly_write_har_merged(har_paths=['/data/a.har','/data/b.har'], output_path='/data/all.har').
    """
    from hardly.core.har_tools import merge_hars

    return _ok(merge_hars(har_paths, output_path, overwrite=overwrite, dedupe=dedupe))


# ----------------------------------------------------------------------------- catalog


@_tool
def hardly_catalog_list(
    catalog_path: str,
    tag: str | None = None,
    group: dict[str, Any] | None = None,
    role: str | None = None,
    status: str | None = None,
    target_id: str | None = None,
    detail: str = "full",
) -> str:
    """List targets from a content-neutral catalog file (JSON/YAML), filtered; no network. detail='summary' returns counts instead of rows. Tags and roles are defined by your project (docs/catalog.md). Example: hardly_catalog_list(catalog_path='/data/targets.json', detail='summary').

    One row per endpoint: target, tags, groups, role, kind, status, redacted url, gate classes,
    stack names. Filters: ``tag`` (comma-separated, all required), ``group`` (object of key->value),
    ``role``, ``status``, ``target_id``. hardly assigns no meaning to tags, group keys or roles.
    """
    from hardly.core import catalog as C

    _choice("catalog_list", "detail", detail, ("summary", "full"))
    try:
        cat = C.load(catalog_path)
        if detail == "summary":
            return _ok(cat.summary())
        rows = cat.table(
            tag=[t for t in (tag or "").split(",") if t.strip()] or None,
            group=group,
            role=role,
            status=status,
            target_id=target_id,
        )
        return _ok({"count": len(rows), "rows": rows})
    except C.CatalogError as exc:
        return _err(exc)


@_tool
def hardly_write_catalog_record(
    catalog_path: str,
    target: dict[str, Any],
    merge: bool = True,
    create: bool = False,
) -> str:
    """Writes a file: add or update one target in a catalog file in place (atomic, no network). URLs are redacted and validated. create=true makes the file if missing. Example: hardly_write_catalog_record(catalog_path='/data/targets.json', target={'id':'t1','endpoints':[{'role':'api','url':'https://example.com/api'}]}, create=true).

    Only that one target changes (there is no overwrite flag; merge=false replaces the target).
    ``target`` is {id, name, tags[], groups{}, endpoints:[{role, url, kind?, status?, gate_classes?,
    stack?, notes?, capture?:{recipe_ref, har_ref}}]}. merge=true unions tags, overlays groups and
    merges endpoints by (role, url); merge=false replaces the target.
    """
    from pathlib import Path

    from hardly.core import catalog as C

    try:
        existed = Path(catalog_path).exists()
        cat = C.Catalog() if (not existed and create) else C.load(catalog_path)
        t = cat.upsert(target, merge=merge)
        C.save(cat, catalog_path)
        return _ok(
            {
                "catalog_path": catalog_path,
                "action": "updated" if existed else "created",
                "saved": t.to_dict(),
                "targets": len(cat.targets),
            }
        )
    except C.CatalogError as exc:
        return _err(exc)


@_tool
def hardly_send_catalog_verify(
    catalog_path: str,
    confirm: bool = False,
    write_back: bool = False,
    tag: str | None = None,
    group: dict[str, Any] | None = None,
    role: str | None = None,
    status: str | None = None,
    target_id: str | None = None,
    delay_seconds: float = 1.0,
    max_requests: int = 50,
    max_endpoints: int | None = None,
    recheck_after_seconds: float | None = None,
    force: bool = False,
) -> str:
    """LIVE (confirm-gated): politely verify catalog endpoints (verified|blocked|dead|needs_browser). Without confirm=true it returns only the plan and sends nothing; write_back=true also records statuses in catalog_path. Example: hardly_send_catalog_verify(catalog_path='/data/targets.json', confirm=true, write_back=true).

    Per endpoint it runs one robots-aware, honest-UA fetch and records status, gate classes and
    stack names, never bodies or tokens. Per-host delay, request budget, resumable (already-checked
    endpoints are skipped unless force / recheck_after_seconds). Stops a host on any gate per
    docs/gate-policy.md; never evades.
    """
    from hardly.core import catalog as C

    filters = {
        "tag": [t for t in (tag or "").split(",") if t.strip()] or None,
        "group": group,
        "role": role,
        "status": status,
        "target_id": target_id,
    }
    try:
        cat = C.load(catalog_path)
        runner = C.CatalogRunner(
            cat,
            path=catalog_path if write_back else None,
            confirm=confirm,
            delay_s=delay_seconds,
            max_requests=max_requests,
            max_endpoints=max_endpoints,
            recheck_after_s=recheck_after_seconds,
            force=force,
        )
        if not confirm:
            return _dry_run({"endpoints": runner.plan(**filters), "write_back": write_back, "max_requests": max_requests})
        res = runner.run(**filters)
        res["write_back"] = write_back
        return _ok(res)
    except C.CatalogError as exc:
        return _err(exc)


# ----------------------------------------------------------------------------- browser


@_tool
def hardly_browser_start(
    url: str | None = None,
    har_output_path: str | None = None,
    headed: bool = True,
    channel: str | None = None,
    url_filter: str | None = None,
    omit_content: bool = False,
    label: str | None = None,
    profile: str | None = None,
    same_tab: bool = True,
    trace: bool = False,
) -> str:
    """Launch a real browser that records a HAR (needs the capture extra); returns capture_id. headed=true (default) is interactive: ASK THE PERSON to use the window, then call hardly_browser_stop. Example: hardly_browser_start(url='https://example.com', headed=true, channel='chrome').

    headed=false is headless: drive it with hardly_browser_inspect / hardly_browser_interact /
    hardly_browser_run_steps. For a one-shot unattended load prefer hardly_browser_capture_discover.
    Requires ``pip install -e ".[capture]"`` + ``playwright install chromium`` (see
    hardly_server_status). Prefer channel='chrome' for bot walls. url_filter is a Playwright glob.
    profile keeps cookies. Without har_output_path the HAR is ephemeral (memory only). same_tab
    (default true) forces target=_blank into the current tab. trace=true writes a ``.trace.zip``
    beside the HAR. Waits for a capture slot (HARDLY_CAPTURE_SLOTS); the result carries ``slot``.
    """
    from hardly.capture import start_capture

    result = start_capture(
        url or "",
        har_output_path or None,
        headed=headed,
        channel=channel or "",
        url_filter=url_filter or "",
        omit_content=omit_content,
        label=label or "",
        user_data_dir=profile or None,
        trace=True if trace else None,
        same_tab=same_tab,
    )
    return _ok(result)


@_tool
def hardly_browser_stop(capture_id: str | None = None, open_session: bool = True, force: bool = False) -> str:
    """Stop a running browser capture, flush the HAR and optionally open it as a session. Call when the person says they are done (interactive) or your steps are complete; then continue with hardly_session_site_brief(session_id). Example: hardly_browser_stop(open_session=true).

    An ephemeral capture (started without har_output_path) lives only in the returned session; save
    it with hardly_write_session_copy(format='index'). Omit capture_id for the latest running one.
    """
    from hardly.capture import stop_capture

    return _ok(stop_capture(capture_id or None, open_session=open_session, force=force))


@_tool
def hardly_capture_list(capture_id: str | None = None) -> str:
    """List browser captures (running and persisted) with ids and states, or the status of one capture_id. Poll it while a person drives an interactive capture. Example: hardly_capture_list(capture_id='c1').

    Use to find a capture_id after a restart. With capture_id the list holds exactly that capture
    (state, har_output_path, request counts).
    """
    from hardly.capture import CaptureError, get_capture, list_captures

    if capture_id:
        try:
            rows = [get_capture(capture_id)]
        except CaptureError as exc:
            return _err(exc)
    else:
        rows = list_captures()
    return _ok({"count": len(rows), "captures": rows})


@_tool
def hardly_browser_capture_discover(
    url: str,
    wait_seconds: float | None = None,
    analyze: bool = False,
    confirm: bool = False,
    har_output_path: str | None = None,
    headed: bool = False,
    channel: str | None = None,
    url_filter: str | None = None,
    steps: list[dict[str, Any]] | None = None,
    budget_seconds: float | None = None,
    exclude_noise: bool = False,
    open_session: bool = True,
) -> str:
    """LIVE (confirm-gated): unattended time-boxed browser capture of a URL; analyze=true also discovers its APIs and returns session_id plus a brief. Without confirm=true it returns only the plan. Example: hardly_browser_capture_discover(url='https://example.com', wait_seconds=8, analyze=true, confirm=true).

    analyze=false: load the URL, wait wait_seconds (default 20), stop; returns the raw HAR
    (har_output_path) and, with open_session=true, a session. analyze=true (headless only): optional
    ``steps`` (goto/wait/aria/click/fill/find_click...) then stop, open a session and return a brief
    (default wait 5). If the brief shows a wall or captcha, STOP and switch to interactive
    hardly_browser_start(headed=true, channel='chrome') with a person. budget_seconds is a hard
    per-call budget (env HARDLY_CAPTURE_BUDGET). exclude_noise=true aborts analytics/ad/font/
    map-tile/heavy-media requests while loading (default off: blocking can break sites).
    """
    from hardly.capture import capture_for, discover_apis
    from hardly.core.redact import redact_url

    if steps and not analyze:
        raise ToolError(
            "browser_capture_discover: steps need analyze=true",
            "Pass analyze=true to run steps, or drop steps for a plain timed load.",
            "invalid_argument",
        )
    if analyze and headed:
        raise ToolError(
            "browser_capture_discover: analyze=true runs headless",
            "For a visible browser use hardly_browser_start(headed=true) and ask the person.",
            "invalid_argument",
        )
    wait = float(wait_seconds) if wait_seconds is not None else (5.0 if analyze else 20.0)
    from hardly.core.netguard import check_url

    check_url(url)
    for st in steps or []:
        if isinstance(st, dict) and str(st.get("op") or "").lower() == "goto" and st.get("url"):
            check_url(str(st["url"]))
    if not confirm:
        return _dry_run(
            {
                "action": "load the URL in a real browser and record its traffic",
                "url": redact_url(url),
                "wait_seconds": wait,
                "analyze": analyze,
                "headed": headed,
                "channel": channel,
                "steps": len(steps or []),
                "budget_seconds": budget_seconds,
                "har_output_path": har_output_path,
                "open_session": open_session,
            }
        )
    if analyze:
        return _ok(
            discover_apis(
                url,
                har_output_path or None,
                recipe=steps,
                wait_seconds=wait,
                channel=channel or "",
                url_filter=url_filter or "",
                open_session=open_session,
                brief=True,
                budget_seconds=budget_seconds,
                block_noise=exclude_noise,
            )
        )
    return _ok(
        capture_for(
            url,
            har_output_path or None,
            wait_seconds=wait,
            headed=headed,
            channel=channel or "",
            url_filter=url_filter or "",
            open_session=open_session,
            budget_seconds=budget_seconds,
            block_noise=exclude_noise,
        )
    )


@_tool
def hardly_browser_interact(
    action: str,
    capture_id: str | None = None,
    url: str | None = None,
    ref: str | None = None,
    css: str | None = None,
    xpath: str | None = None,
    text: str | None = None,
    role: str | None = None,
    name: str | None = None,
    value: str | None = None,
    key: str | None = None,
    timeout_seconds: float = 10.0,
) -> str:
    """Drive the running browser tab: action=goto (needs url), click, fill (needs value) or press (key, default Enter). Prefer ref from hardly_browser_inspect(sections=['aria']). Example: hardly_browser_interact(action='click', ref='e12').

    Target one element per call with ``ref``, else ``css`` / ``xpath`` (from
    hardly_browser_inspect(sections=['elements'])), or ``text`` / ``role`` with ``name`` (click).
    Never type real credentials yourself: ask the person to use an interactive capture.
    Omit capture_id for the latest running capture.
    """
    from hardly.capture import click_capture, fill_capture, navigate_capture, press_capture

    act = _choice("browser_interact", "action", action, ("goto", "click", "fill", "press"))
    cid = capture_id or None
    ms = max(1, int(float(timeout_seconds) * 1000))
    if act == "goto":
        _need("browser_interact", "url", url, " for action='goto'")
        return _ok(navigate_capture(cid, url))
    if act == "click":
        return _ok(
            click_capture(
                cid, ref=ref or "", xpath=xpath or "", css=css or "", text=text or "",
                role=role or "", name=name or "", timeout_ms=ms,
            )
        )
    if act == "fill":
        _need("browser_interact", "value", value, " for action='fill'")
        return _ok(fill_capture(cid, value=value, ref=ref or "", xpath=xpath or "", css=css or "", timeout_ms=ms))
    return _ok(press_capture(cid, key=key or "Enter", ref=ref or "", xpath=xpath or "", css=css or "", timeout_ms=ms))


@_tool
def hardly_browser_inspect(
    capture_id: str | None = None,
    sections: list[str] | None = None,
    query: str | None = None,
    limit: int | None = None,
    selector: str | None = None,
    mode: str | None = None,
) -> str:
    """Read the running browser tab without navigating; sections: url (default), elements (css/xpath locators), aria (accessibility YAML with [ref=eN] handles). Example: hardly_browser_inspect(sections=['aria'], selector='main').

    ``url``: current URL and title (cheap check of where a click landed). ``elements``: visible
    links/buttons/inputs with locators; ``query`` is a CSS selector override, ``limit`` max rows
    (default 40, max 100). ``aria``: rendered ARIA tree, ``mode='ai'`` (default) asks for refs,
    ``selector`` scopes it (default body); the refs feed hardly_browser_interact. For offline HAR
    HTML bodies use hardly_entry_outline.
    """
    from hardly.capture import capture_aria_snapshot, capture_page_url, list_capture_elements

    secs = _sections("browser_inspect", sections, ("url", "elements", "aria"), ("url",))
    cid = capture_id or None
    out: dict[str, Any] = {"sections": secs}
    if "url" in secs:
        out["url"] = capture_page_url(cid)
    if "elements" in secs:
        out["elements"] = list_capture_elements(cid, limit=_lim(limit, 40, 100), query=query or "")
    if "aria" in secs:
        out["aria"] = capture_aria_snapshot(cid, selector=selector or "", mode=mode or "ai")
    return _ok(out)


@_tool
def hardly_browser_run_steps(steps: list[dict[str, Any]], capture_id: str | None = None, stop_on_error: bool = True) -> str:
    """Run a scripted list of steps on the running browser tab in one call (cheaper than many single calls). Use once you know the selectors; hardly_session_plan_steps suggests steps from a session. Example: hardly_browser_run_steps(steps=[{'op':'goto','url':'https://example.com'}]).

    Each step: ``{"op":"goto"|"wait"|"elements"|"click"|"fill"|"press"|"url"|"aria", ...}``.
    Example steps::

        [
          {"op":"goto","url":"https://example.com/search"},
          {"op":"wait","ms":1000},
          {"op":"click","text":"I Accept"},
          {"op":"fill","css":"#SearchOnName","value":"EXAMPLE"},
          {"op":"click","css":"input[type=submit]"},
          {"op":"wait","ms":2000},
          {"op":"elements","limit":30}
        ]
    """
    from hardly.capture import run_capture_recipe

    return _ok(run_capture_recipe(steps, capture_id=capture_id or None, stop_on_error=stop_on_error))


@_tool
def hardly_write_screenshot(
    output_path: str,
    capture_id: str | None = None,
    full_page: bool = False,
    overwrite: bool = False,
) -> str:
    """Writes a file: save a PNG screenshot of the running browser tab to output_path. Use to show a person or inspect a wall; refuses to overwrite unless overwrite=true. Example: hardly_write_screenshot(output_path='/tmp/page.png', full_page=true).
    """
    from hardly.capture import capture_screenshot

    target = _out(output_path, overwrite)
    return _ok(capture_screenshot(capture_id or None, path=str(target), full_page=full_page))


@_tool
def hardly_session_plan_steps(session_id: str, host: str | None = None, limit: int | None = None) -> str:
    """Suggest browser steps (goto/fill/click) from a session's story, ready for hardly_browser_run_steps. Heuristic: refine selectors with hardly_browser_inspect first. Nothing is run or written (hardly_write_export format=plan_steps saves them). Example: hardly_session_plan_steps(session_id='S').
    """
    from hardly.core.recipe_plan import recipe_from_story

    conn = sess.require_conn(session_id)
    return _ok(recipe_from_story(conn, host=host, output_path=None, limit=_lim(limit, 30, 60)))


# ----------------------------------------------------------------------------- capture orientation


@_tool
def hardly_session_overview(
    session_id: str,
    host: str | None = None,
    exclude_noise: bool = True,
    limit: int | None = None,
) -> str:
    """Headline COUNTS of a capture: requests per server, method and status, plus main_host (the app origin, not CDN/analytics). Run right after hardly_session_open; pass main_host as host= to later tools. Example: hardly_session_overview(session_id='S').

    Distributions (content types, sizes, timing) are hardly_session_traffic_stats; findings with
    severity are hardly_session_report; a digest of a server-rendered site is hardly_session_site_brief.
    """
    from hardly.core.overview import session_overview

    conn = sess.require_conn(session_id)
    res = session_overview(conn, host=host, exclude_noise=exclude_noise, limit=_lim(limit, 50, 200))
    res["index_path"] = sess.get_saved_to(session_id)
    return _ok(res)


@_tool
def hardly_session_traffic_stats(
    session_id: str,
    host: str | None = None,
    exclude_noise: bool = True,
    limit: int | None = None,
    kind: str | None = None,
) -> str:
    """DISTRIBUTIONS of a capture: MIME mix, status classes, body sizes, initiator types, timing and payload_kinds. Each has sample entry_ids. Example: hardly_session_traffic_stats(session_id='S', host='app.example.com').

    Counts per server/method/status are hardly_session_overview; slow requests
    hardly_session_slow_requests; repeated calls hardly_session_duplicates. ``kind`` filters the
    payload_kinds list; ``limit`` caps it (default 80).
    """
    from hardly.core.classify import summarize_content
    from hardly.core.stats import traffic_stats

    conn = sess.require_conn(session_id)
    out = traffic_stats(conn, host=host, exclude_noise=exclude_noise)
    out["payload_kinds"] = summarize_content(
        conn, host=host, kind=kind, exclude_noise=exclude_noise, limit=_lim(limit, 80, 400)
    )
    return _ok(out)


@_tool
def hardly_session_body_coverage(
    session_id: str,
    host: str | None = None,
    exclude_noise: bool = True,
    limit: int | None = None,
) -> str:
    """Count entries with usable body text versus empty or truncated. Use before trusting schema/client output, or when bodies look missing. Example: hardly_session_body_coverage(session_id='S').

    Useful after Playwright captures that used to omit XHR bodies (size=-1). For problems in the HAR
    file itself use hardly_har_file_check.
    """
    from hardly.index import query as q

    conn = sess.require_conn(session_id)
    return _ok(q.body_coverage(conn, host=host, exclude_noise=exclude_noise, limit=_lim(limit, 20, 50)))


@_tool
def hardly_session_issues(
    session_id: str,
    host: str | None = None,
    limit: int | None = None,
) -> str:
    """List capture-quality issues: empty bodies, 4xx/5xx, redirects without Location. Check before trusting other results; for HAR-file problems use hardly_har_file_check. Example: hardly_session_issues(session_id='S').
    """
    from hardly.core.issues import find_issues

    conn = sess.require_conn(session_id)
    return _ok(find_issues(conn, host=host, limit=_lim(limit, 40, 60)))


@_tool
def hardly_session_duplicates(
    session_id: str,
    host: str | None = None,
    exclude_noise: bool = True,
    min_count: int = 2,
    limit: int | None = None,
) -> str:
    """Find repeated method+path_template groups (polling, retries). Use to separate noise from real calls before documenting. Example: hardly_session_duplicates(session_id='S', min_count=5).
    """
    from hardly.core.duplicates import find_duplicates

    conn = sess.require_conn(session_id)
    return _ok(
        find_duplicates(conn, host=host, exclude_noise=exclude_noise, min_count=min_count, limit=_lim(limit, 30, 80))
    )


@_tool
def hardly_session_slow_requests(
    session_id: str,
    host: str | None = None,
    exclude_noise: bool = True,
    limit: int | None = None,
    min_elapsed_seconds: float | None = None,
) -> str:
    """List the slowest requests (time_ms) first. Use for performance questions; for the general traffic shape use hardly_session_traffic_stats. Example: hardly_session_slow_requests(session_id='S', min_elapsed_seconds=1).
    """
    from hardly.core.slow import slowest_entries

    conn = sess.require_conn(session_id)
    return _ok(
        slowest_entries(
            conn,
            host=host,
            exclude_noise=exclude_noise,
            limit=_lim(limit, 20, 50),
            min_ms=float(min_elapsed_seconds or 0) * 1000.0,
        )
    )


@_tool
def hardly_session_report(
    session_id: str,
    host: str | None = None,
    categories: list[str] | None = None,
    detail: str = "summary",
    explain: bool = False,
) -> str:
    """One-pass evidence index (access, auth, stack, data, forms): FINDINGS with severity info|notice|blocker and the drill-down tool for each. Start here for any unfamiliar capture; detail='summary' is ~1 KB. Example: hardly_session_report(session_id='S', detail='summary').

    Runs the existing detectors once and returns findings {section, kind, severity, label, entry_ids,
    names/shapes only, lookup}. detail: summary (counts per section + blockers) | standard |
    full (more findings + the drill-down tool per finding). ``categories`` restricts the sections
    (access, auth, stack, data, forms). Never returns secret values. explain=true adds canned prose.
    Writes nothing: hardly_write_export(format='report') saves it.
    """
    from hardly.core.report import build_report

    conn = sess.require_conn(session_id)
    return _ok(
        build_report(conn, sess.get_har_path(session_id), host=host, sections=categories, detail=detail, explain=explain)
    )


@_tool
def hardly_session_site_brief(session_id: str, host: str | None = None) -> str:
    """One-shot DIGEST of a server-rendered site: journey (story), forms, routes, reused values, cookies and issues in a compact result. Run this first on a freshly opened session of an HTML portal, then drill down with the tools it names. Example: hardly_session_site_brief(session_id='S').

    Findings with severities are hardly_session_report. Writes nothing: hardly_write_export
    (format='site_brief') saves it as Markdown.
    """
    from hardly.core.brief import portal_brief

    conn = sess.require_conn(session_id)
    return _ok(portal_brief(conn, har_path=sess.get_har_path(session_id), host=host))


@_tool
def hardly_session_story(
    session_id: str,
    host: str | None = None,
    exclude_noise: bool = True,
    include_related: bool = True,
    limit: int | None = None,
) -> str:
    """Annotated user-journey NARRATIVE: the session stitched into steps (role, forms, labels, fields) with duplicates collapsed. Prefer it over the plain list hardly_session_timeline when reversing portals or building a client. Example: hardly_session_story(session_id='S', host='app.example.com').

    It is the input to hardly_client_build. include_related=true adds non-noise traffic from sibling
    hosts on the same apex so SPA captures tell a full story.
    """
    from hardly.core.story import portal_story

    conn = sess.require_conn(session_id)
    return _ok(
        portal_story(
            conn,
            host=host,
            limit=_lim(limit, 40, 80),
            exclude_noise=exclude_noise,
            include_related=include_related,
        )
    )


@_tool
def hardly_session_timeline(
    session_id: str,
    host: str | None = None,
    path_prefix: str | None = None,
    exclude_noise: bool = True,
    limit: int | None = None,
    offset: int | None = None,
) -> str:
    """Plain ordered LIST of requests in time order for a host, optionally from a path_prefix; no annotation. Raw timeline for login/MFA sequences; hardly_session_story is the condensed narrative. Example: hardly_session_timeline(session_id='S', path_prefix='/login').
    """
    from hardly.core.flows import get_flow

    conn = sess.require_conn(session_id)
    return _ok(
        get_flow(
            conn,
            host=host,
            path_prefix=path_prefix,
            exclude_options=exclude_noise,
            exclude_noise=exclude_noise,
            limit=_lim(limit, 100, 500),
            offset=_off(offset),
        )
    )


@_tool
def hardly_session_redirect_history(
    session_id: str,
    host: str | None = None,
    limit: int | None = None,
    explain: bool = False,
) -> str:
    """List the RECORDED 3xx redirect hops with matched follow-up entry ids; sends nothing. Use to understand login/canonicalisation redirects; the live twin that follows a URL is hardly_send_redirect_walk. Example: hardly_session_redirect_history(session_id='S').
    """
    from hardly.core.redirects import redirect_chains

    conn = sess.require_conn(session_id)
    return _ok(redirect_chains(conn, host=host, limit=_lim(limit, 30, 80), explain=explain))


# ----------------------------------------------------------------------------- capture lookup


@_tool
def hardly_session_trace_value(
    session_id: str,
    name: str | None = None,
    value: str | None = None,
    host: str | None = None,
    limit: int | None = None,
) -> str:
    """Trace a field name or exact value across a capture: where it first appears and where it is reused. With neither name nor value, list every dynamic value (CSRF, ViewState, session cookies, tokens) reused from earlier responses. Example: hardly_session_trace_value(session_id='S', name='csrf_token').

    Values are never echoed back, only entry ids, location and shape.
    """
    conn = sess.require_conn(session_id)
    har = sess.get_har_path(session_id)
    if name or value:
        from hardly.core.trace import trace_field

        return _ok(
            trace_field(conn, name=name or None, value=value or None, har_path=har, host=host, limit=_lim(limit, 40, 80))
        )
    from hardly.core.correlate import correlate_tokens

    return _ok(correlate_tokens(conn, har_path=har, host=host, limit=_lim(limit, 40, 80)))


@_tool
def hardly_session_sql(session_id: str, sql: str, limit: int | None = None) -> str:
    """Run a read-only SELECT against the session's SQLite index. Escape hatch for questions no named tool answers; try those first. Example: hardly_session_sql(session_id='S', sql='select host, count(*) from entries group by host').
    """
    from hardly.index import query as q

    conn = sess.require_conn(session_id)
    return _ok(q.run_sql(conn, sql, limit=_lim(limit, 100, 500)))


@_tool
def hardly_session_compare(
    session_id: str,
    other_session_id: str,
    host: str | None = None,
    exclude_noise: bool = True,
    include_credentials: bool = True,
) -> str:
    """Compare endpoint templates (and credential maps) between two sessions: routes that appeared and disappeared. Use for logged out vs in, or before and after a site change. Example: hardly_session_compare(session_id='A', other_session_id='B').
    """
    from hardly.core.diff import diff_sessions

    conn_a = sess.require_conn(session_id)
    conn_b = sess.require_conn(other_session_id)
    return _ok(
        diff_sessions(
            conn_a,
            conn_b,
            host=host,
            exclude_noise=exclude_noise,
            credentials=include_credentials,
            har_path_a=sess.get_har_path(session_id),
            har_path_b=sess.get_har_path(other_session_id),
        )
    )


@_tool
def hardly_entry_search(
    session_id: str,
    host: str | None = None,
    path_contains: str | None = None,
    method: str | None = None,
    status: int | None = None,
    body_contains: str | None = None,
    header_name: str | None = None,
    header_contains: str | None = None,
    mime_contains: str | None = None,
    content_kind: str | None = None,
    exclude_noise: bool = True,
    limit: int | None = None,
    offset: int | None = None,
) -> str:
    """Find entries by host, path, method, status, body text, header or content_kind; returns small paged rows with entry_ids. Use to locate a specific request, then hardly_entry_get. Example: hardly_entry_search(session_id='S', body_contains='token', limit=10).

    ``content_kind`` uses the classifier: json, jsonl, jsonp, csv, html, html_table (or table), pdf,
    image, css, javascript, ... Result rows include ``content_kind`` / hints. exclude_noise=false
    also returns OPTIONS preflights and tracker traffic.
    """
    from hardly.index import query as q

    conn = sess.require_conn(session_id)
    return _ok(
        q.search_entries(
            conn,
            host=host,
            path_contains=path_contains,
            method=method,
            status=status,
            body_contains=body_contains,
            header_name=header_name,
            header_contains=header_contains,
            mime_contains=mime_contains,
            content_kind=content_kind,
            exclude_noise=exclude_noise,
            exclude_options=exclude_noise,
            limit=_lim(limit, 50, 200),
            offset=_off(offset),
        )
    )


@_tool
def hardly_entry_get(session_id: str, entry_id: int, max_body_chars: int | None = None) -> str:
    """Show one entry with redacted headers and truncated bodies (max_body_chars, default 4000). Use after entry_search/endpoint_list gives an entry_id; for large bodies use hardly_entry_body_query instead of raising max_body_chars. Example: hardly_entry_get(session_id='S', entry_id=12).
    """
    from hardly.index import query as q

    conn = sess.require_conn(session_id)
    return _ok(q.get_entry(conn, entry_id, body_chars=_lim(max_body_chars, 4000, 20000)))


@_tool
def hardly_entry_around(
    session_id: str,
    entry_id: int,
    before: int = 5,
    after: int = 15,
    host: str | None = None,
    exclude_noise: bool = True,
) -> str:
    """Show the requests just before and after one entry in TIME (a click and the XHRs that followed). Use with a navigation or grid-click entry_id to find the API it triggered; inspect rows with positive delta_ms. Example: hardly_entry_around(session_id='S', entry_id=30, after=8).

    What triggered an entry by the browser's own initiator data is hardly_entry_initiators.
    """
    from hardly.index import query as q

    conn = sess.require_conn(session_id)
    return _ok(
        q.entries_around(
            conn,
            entry_id,
            before=max(0, min(before, 50)),
            after=max(0, min(after, 100)),
            exclude_noise=exclude_noise,
            host=host,
        )
    )


@_tool
def hardly_entry_initiators(
    session_id: str,
    entry_id: int,
    exclude_noise: bool = True,
    child_limit: int | None = None,
) -> str:
    """Show the initiator parent and children of an entry (HAR _initiator/pageref): what triggered a request and what it triggered. Use to find who called an API; for time order use hardly_entry_around. Example: hardly_entry_initiators(session_id='S', entry_id=30).
    """
    from hardly.core.tree import entry_tree

    conn = sess.require_conn(session_id)
    return _ok(entry_tree(conn, entry_id, exclude_noise=exclude_noise, child_limit=_lim(child_limit, 40, 80)))


@_tool
def hardly_entry_compare(session_id: str, entry_id: int, other_entry_id: int) -> str:
    """Diff headers and JSON body keys between two entries of one session. Use to see what changed between a failing and a working request, or pre/post login. Example: hardly_entry_compare(session_id='S', entry_id=3, other_entry_id=9).
    """
    from hardly.index import query as q

    conn = sess.require_conn(session_id)
    return _ok(q.compare_entries(conn, entry_id, other_entry_id))


@_tool
def hardly_entry_build_curl(
    session_id: str,
    entry_id: int,
    redact: bool = True,
    use_env_placeholders: bool = True,
) -> str:
    """Build a curl command for one entry and return it as text (not executed); secrets are redacted by default. Use to show a person a single request; for a full client use hardly_client_build. Example: hardly_entry_build_curl(session_id='S', entry_id=12).
    """
    from hardly.core.curl import entry_to_curl

    conn = sess.require_conn(session_id)
    return _ok(entry_to_curl(conn, entry_id, redact=redact, use_env_placeholders=use_env_placeholders))


@_tool
def hardly_entry_body_query(
    session_id: str,
    entry_id: int,
    side: str = "response",
    jsonpath: str | None = None,
    regex: str | None = None,
    offset: int | None = None,
    limit: int | None = None,
    max_chars: int | None = None,
    context: int = 40,
    ignore_case: bool = False,
) -> str:
    """Search inside one large body without loading it: JSONPath-lite ($.a[*].b, ..key) or regex, paged (pass next_offset while has_more). Use instead of hardly_entry_get for big payloads; sensitive values come back as shapes. Example: hardly_entry_body_query(session_id='S', entry_id=12, jsonpath='$.items[*].id').
    """
    from hardly.core.body_query import BodyQueryError, query_body

    conn = sess.require_conn(session_id)
    try:
        return _ok(
            query_body(
                conn,
                entry_id,
                side,
                jsonpath=jsonpath,
                regex=regex,
                offset=_off(offset),
                limit=_lim(limit, 20, 100),
                max_chars=_lim(max_chars, 300, 2000),
                context=context,
                ignore_case=ignore_case,
            )
        )
    except BodyQueryError as exc:
        return _err(exc)


@_tool
def hardly_entry_outline(
    session_id: str,
    entry_id: int,
    format: str | None = None,
    max_depth: int = 8,
    side: str = "response",
) -> str:
    """Offline outline of an HTML/XML body from a HAR entry. format: markdown (headings/tables/forms/links), tree (tag tree) or aria (YAML); omit for all three. Example: hardly_entry_outline(session_id='S', entry_id=5, format='markdown').

    Use instead of reading raw HTML; for the live tab use hardly_browser_inspect(sections=['aria']).
    """
    from hardly.core.outline import outline_entry

    if format is not None:
        _choice("entry_outline", "format", format, ("markdown", "tree", "aria"))
    conn = sess.require_conn(session_id)
    return _ok(
        outline_entry(
            conn,
            entry_id,
            side=side or "response",
            format=format or "all",
            max_depth=min(max(1, max_depth), 14),
        )
    )


@_tool
def hardly_entry_dependencies(session_id: str, entry_id: int, host: str | None = None, max_depth: int = 8) -> str:
    """Trace what one request depends on: the earlier response behind each header, cookie, hidden field or value. Returns ordered minimal steps plus inputs the caller must supply. Offline; names and ids only. Example: hardly_entry_dependencies(session_id='S', entry_id=20).

    Use before writing a client for a multi-step flow; to track one value across the capture use
    hardly_session_trace_value.
    """
    from hardly.core.flow_graph import flow_graph

    conn = sess.require_conn(session_id)
    return _ok(flow_graph(conn, entry_id, host=host, max_depth=min(max_depth, 20)))


# ----------------------------------------------------------------------------- API shape, technology


@_tool
def hardly_endpoint_list(
    session_id: str,
    host: str | None = None,
    exclude_noise: bool = True,
    limit: int | None = None,
    offset: int | None = None,
) -> str:
    """List grouped endpoints (METHOD + path template) with counts, paged by limit/offset. The main API surface view for JSON APIs; for server-rendered pages use hardly_session_site_brief or hardly_page_forms. Example: hardly_endpoint_list(session_id='S', host='api.example.com').
    """
    from hardly.index import query as q

    conn = sess.require_conn(session_id)
    return _ok(
        q.list_endpoints(conn, host=host, exclude_noise=exclude_noise, limit=_lim(limit, 100, 500), offset=_off(offset))
    )


@_tool
def hardly_endpoint_schema(
    session_id: str,
    method: str,
    path_template: str,
    host: str | None = None,
    sections: list[str] | None = None,
    limit: int | None = None,
) -> str:
    """Request/response shapes of one endpoint template. Sections: schema (default; JSON field names and types), param_roles (each field static, dynamic or sensitive). Example: hardly_endpoint_schema(session_id='S', method='GET', path_template='/api/items/{id}').

    Use after hardly_endpoint_list. param_roles decides which parameters a client must compute versus
    hard-code. host defaults to the main host. Names and types only.
    """
    from hardly.index import query as q

    secs = _sections("endpoint_schema", sections, ("schema", "param_roles"), ("schema",))
    conn = sess.require_conn(session_id)
    h = host or q.preferred_host(conn)
    if not h:
        raise ToolError("endpoint_schema: no host in this capture", "Pass host=<hostname>.", "missing_argument")
    out: dict[str, Any] = {"sections": secs, "host": h}
    if "schema" in secs:
        out["schema"] = q.endpoint_schema(
            conn, method=method, host=h, path_template=path_template, limit=_lim(limit, 20, 50)
        )
    if "param_roles" in secs:
        from hardly.core.params import param_variance

        out["param_roles"] = param_variance(
            conn, method=method, host=h, path_template=path_template, limit=_lim(limit, 30, 80)
        )
    return _ok(out)


@_tool
def hardly_spec_contract_check(session_id: str, spec_path: str, host: str | None = None) -> str:
    """Compare a capture with a previously written OpenAPI file and report drift (new/removed endpoints, status, field, parameter, auth changes). Offline; removed means not observed. Example: hardly_spec_contract_check(session_id='S', spec_path='/data/api.yaml').
    """
    from hardly.core.contract import check_contract

    conn = sess.require_conn(session_id)
    return _ok(check_contract(conn, spec_path, host=host))


@_tool
def hardly_tech_stack(
    session_id: str,
    host: str | None = None,
    limit: int | None = None,
    explain: bool = False,
) -> str:
    """Fingerprint web frameworks, CMS, GIS stacks, UI toolkits and data-grid widgets from header/cookie names, paths and body previews. Absent technology gives count 0. Example: hardly_tech_stack(session_id='S', explain=true).

    explain=true adds SDK implications. Data-grid frameworks, JSON envelope conventions (OData,
    JSON:API, HAL, Relay) and paging/sort styles are under ``data_grids``. For CDN/WAF products use
    hardly_gate_bot_protection.
    """
    from hardly.core.grids import detect_grids
    from hardly.core.stack import fingerprint

    conn = sess.require_conn(session_id)
    out = fingerprint(conn, host=host, limit=_lim(limit, 30, 60), explain=explain)
    out["data_grids"] = detect_grids(conn, host=host, limit=_lim(limit, 20, 50), explain=explain)
    return _ok(out)


@_tool
def hardly_endpoint_graphql(session_id: str, host: str | None = None, limit: int | None = None) -> str:
    """Detect GraphQL operations (operationName, query, mutation) behind shared URLs, with evidence entry ids. Use when POSTs share one URL; then hardly_entry_get for a sample. Example: hardly_endpoint_graphql(session_id='S').
    """
    from hardly.core.graphql import detect_graphql

    conn = sess.require_conn(session_id)
    return _ok(detect_graphql(conn, host=host, limit=_lim(limit, 40, 80)))


@_tool
def hardly_endpoint_streams(
    session_id: str,
    host: str | None = None,
    kind: str | None = None,
    exclude_noise: bool = True,
    limit: int | None = None,
) -> str:
    """Summarise non-JSON stream/binary formats: gRPC(-web), protobuf, MessagePack, CSV/TSV, SSE, WebSocket frames, with evidence entry ids. Shapes only. Use when endpoints show odd content types. Example: hardly_endpoint_streams(session_id='S').
    """
    from hardly.core.streams import summarize_streams

    conn = sess.require_conn(session_id)
    return _ok(summarize_streams(conn, host=host, kind=kind, exclude_noise=exclude_noise, limit=_lim(limit, 40, 100)))


@_tool
def hardly_endpoint_pagination(session_id: str, host: str | None = None, limit: int | None = None) -> str:
    """Recognise cursor, next-link and Link-header pagination, with evidence entry ids. Shapes only. Use before writing a client loop over results. Example: hardly_endpoint_pagination(session_id='S', host='api.example.com').
    """
    from hardly.core.pagination import detect_pagination

    conn = sess.require_conn(session_id)
    return _ok(detect_pagination(conn, host=host, limit=_lim(limit, 20, 60)))


@_tool
def hardly_endpoint_arcgis(session_id: str, host: str | None = None) -> str:
    """List ArcGIS REST endpoints (MapServer/FeatureServer/etc.) seen in the capture: layer ids, parameter names, paging evidence. Sends nothing; the live twin is hardly_send_arcgis_explore. Example: hardly_endpoint_arcgis(session_id='S').
    """
    from hardly.core.arcgis import summarize_session

    conn = sess.require_conn(session_id)
    return _ok(summarize_session(conn, host=host))


# ----------------------------------------------------------------------------- pages


@_tool
def hardly_page_list(
    session_id: str,
    host: str | None = None,
    exclude_noise: bool = True,
    limit: int | None = None,
) -> str:
    """List HAR pageref groups (browser page loads) with document hints. Use to split a capture into navigations. Example: hardly_page_list(session_id='S').
    """
    from hardly.core.pages import list_pages

    conn = sess.require_conn(session_id)
    return _ok(list_pages(conn, host=host, exclude_noise=exclude_noise, limit=_lim(limit, 40, 80)))


@_tool
def hardly_page_forms(
    session_id: str,
    entry_id: int | None = None,
    host: str | None = None,
    side: str = "response",
    exclude_noise: bool = True,
    limit: int | None = None,
    offset: int | None = None,
) -> str:
    """Extract HTML forms and their inputs with signals (hidden fields, tokens, links, handlers). Use to reverse server-rendered pages instead of dumping HTML; entry_id gives the full inventory of one response, omit it to scan the session. Example: hardly_page_forms(session_id='S', entry_id=5).

    For link/handler/label-first workflows and search links use hardly_page_ui (same scan).
    """
    from hardly.index import query as q

    conn = sess.require_conn(session_id)
    if entry_id is not None:
        return _ok(q.forms_for_entry(conn, entry_id, side=side or "response"))
    return _ok(
        q.list_forms(
            conn,
            host=host,
            side=side or "response",
            exclude_noise=exclude_noise,
            limit=_lim(limit, 30, 100),
            offset=_off(offset),
        )
    )


_UI_KEYS: dict[str, set[str]] = {
    "links": {"links", "link_count"},
    "handlers": {"handlers", "handler_functions", "handler_count", "actions"},
    "labels": {"labels", "label_count"},
}
_UI_BASE = {"entry_id", "side", "url", "method", "status", "content_type", "note", "error", "count", "scanned", "limit", "offset", "next"}


def _ui_project(payload: dict[str, Any], secs: list[str]) -> dict[str, Any]:
    keep = set(_UI_BASE)
    for s in secs:
        keep |= _UI_KEYS.get(s, set())

    def one(d: dict[str, Any]) -> dict[str, Any]:
        return {k: v for k, v in d.items() if k in keep}

    if isinstance(payload.get("entries"), list):
        return {**one({k: v for k, v in payload.items() if k != "entries"}), "entries": [one(e) for e in payload["entries"]]}
    return one(payload)


@_tool
def hardly_page_ui(
    session_id: str,
    entry_id: int | None = None,
    host: str | None = None,
    side: str = "response",
    sections: list[str] | None = None,
    keywords: list[str] | None = None,
    exclude_noise: bool = True,
    limit: int | None = None,
    offset: int | None = None,
) -> str:
    """Inventory UI controls. Sections: links, handlers (onclick/onsubmit), labels (default all three), search_links (ranked links likely to lead to a search page). Example: hardly_page_ui(session_id='S', sections=['search_links'], keywords=['search']).

    Same scan as hardly_page_forms, projected to the UI parts; handler_functions names feed
    hardly_page_embedded_routes. entry_id inventories one response, omit it to scan the session.
    search_links takes ``keywords`` (the site's domain vocabulary): repeat per hop until a form with
    inputs appears; its next_step feeds hardly_browser_run_steps.
    """
    from hardly.index import query as q

    secs = _sections("page_ui", sections, ("links", "handlers", "labels", "search_links"), ("links", "handlers", "labels"))
    conn = sess.require_conn(session_id)
    out: dict[str, Any] = {"sections": secs}
    ui_secs = [s for s in secs if s in _UI_KEYS]
    if ui_secs:
        if entry_id is not None:
            payload = q.ui_for_entry(conn, entry_id, side=side or "response")
        else:
            payload = q.list_forms(
                conn,
                host=host,
                side=side or "response",
                exclude_noise=exclude_noise,
                limit=_lim(limit, 30, 100),
                offset=_off(offset),
            )
        out["ui"] = _ui_project(payload, ui_secs)
    if "search_links" in secs:
        from hardly.core.search_nav import find_search_entry

        out["search_links"] = find_search_entry(conn, host=host, keywords=keywords or [], limit=_lim(limit, 15, 40))
    return _ok(out)


@_tool
def hardly_page_embedded_routes(
    session_id: str,
    host: str | None = None,
    entry_id: int | None = None,
    sections: list[str] | None = None,
    explain: bool = False,
    limit: int | None = None,
    offset: int | None = None,
) -> str:
    """Mine endpoints the page embeds. Sections: script_routes (URL path literals in JavaScript), data_attrs (endpoints and config in HTML data-* attributes); default both. Example: hardly_page_embedded_routes(session_id='S', sections=['data_attrs'], entry_id=5).

    Use when search works but the detail URL is unknown, or on JS-heavy pages to find where the page
    gets its data; then hardly_entry_around on the click entry. data_attrs reports dataset keys,
    value kinds, embedded endpoint URLs and JSON config, never free text.
    """
    from hardly.index import query as q

    secs = _sections("page_embedded_routes", sections, ("script_routes", "data_attrs"), ("script_routes", "data_attrs"))
    conn = sess.require_conn(session_id)
    out: dict[str, Any] = {"sections": secs}
    if "script_routes" in secs:
        out["script_routes"] = q.list_js_routes(conn, host=host, limit=_lim(limit, 40, 100), offset=_off(offset))
    if "data_attrs" in secs:
        from hardly.core.data_attrs import scan_session

        out["data_attrs"] = scan_session(conn, host=host, entry_id=entry_id, limit=_lim(limit, 20, 60), explain=explain)
    return _ok(out)


@_tool
def hardly_page_tables(session_id: str, entry_id: int | None = None, host: str | None = None) -> str:
    """List HTML data tables: headers, row/column counts, column kinds and a masked first row (cell values never returned). Use to understand result grids before scraping or modelling them. Example: hardly_page_tables(session_id='S', entry_id=14).
    """
    from hardly.core.tables import scan_session

    conn = sess.require_conn(session_id)
    return _ok(scan_session(conn, host=host, entry_id=entry_id))


# ----------------------------------------------------------------------------- auth, gates


@_tool
def hardly_auth_report(
    session_id: str,
    host: str | None = None,
    sections: list[str] | None = None,
    pattern_kinds: list[str] | None = None,
    limit: int | None = None,
    explain: bool = False,
) -> str:
    """Authentication evidence; sections: quick (default; auth paths, token responses, header names), patterns, credentials, secret_names, cookies. Names, shapes and entry ids only, never values. Example: hardly_auth_report(session_id='S', sections=['credentials','cookies']).

    quick: a first auth check. patterns: named schemes (bearer+refresh, OIDC+PKCE, SAML POST,
    double-submit CSRF, signed requests; ``pattern_kinds`` filters). credentials: password fields,
    session cookies and flags, anti-forgery names, OAuth params, token shapes and a hypothesised
    login_flow (use before implementing login in a client). secret_names: sensitive header/field/
    query NAMES. cookies: per-server timeline of Set-Cookie / Cookie names.
    """
    secs = _sections(
        "auth_report", sections, ("quick", "patterns", "credentials", "secret_names", "cookies"), ("quick",)
    )
    conn = sess.require_conn(session_id)
    har = sess.get_har_path(session_id)
    out: dict[str, Any] = {"sections": secs}
    if "quick" in secs:
        from hardly.core.auth import detect_auth

        out["quick"] = detect_auth(conn, host=host)
    if "patterns" in secs:
        if har is None:
            out["patterns"] = {
                "error": "The source HAR is not on disk for this session (ephemeral capture or moved file)",
                "code": "har_unavailable",
                "hint": "Capture again with har_output_path, or hardly_session_open the HAR file.",
            }
        else:
            from hardly.core.auth_patterns import detect_auth_patterns

            out["patterns"] = detect_auth_patterns(har, host=host, kinds=pattern_kinds, explain=explain)
    if "credentials" in secs:
        from hardly.core.credentials import map_credentials

        out["credentials"] = map_credentials(conn, har_path=har, host=host, limit=_lim(limit, 40, 60), explain=explain)
    if "secret_names" in secs:
        from hardly.core.secrets import locate_secrets

        out["secret_names"] = locate_secrets(conn, host=host, limit=_lim(limit, 40, 60))
    if "cookies" in secs:
        from hardly.core.cookies import cookie_timeline

        out["cookies"] = cookie_timeline(conn, har_path=har, host=host, limit=_lim(limit, 60, 120))
    return _ok(out)


@_tool
def hardly_gate_bot_protection(
    session_id: str,
    host: str | None = None,
    sections: list[str] | None = None,
    limit: int | None = None,
    explain: bool = False,
) -> str:
    """Detect gates in a capture: bot walls, captcha, login, rate limits, 401/403/429 challenges and CDN/WAF bot-protection products. Never evades. Example: hardly_gate_bot_protection(session_id='S', explain=true).

    Call when requests are blocked, before any retry: every gate is a STOP sign (re-capture
    interactively with a person). barriers: each barrier (environment_blocked, bot_wall, captcha,
    proof_of_work, waiting_room, click_through_terms, login, paywall, rate_limit) with evidence
    names, entry_ids and a policy action (stop | accept_click_through | unknown_rerun).
    http_challenges: WWW-Authenticate schemes, 429/423/Retry-After lockout signals and captcha
    widget markup. bot_protection: vendors seen (Cloudflare, Akamai, Imperva, DataDome, HUMAN, ...)
    with a state each (blocked / challenged / clearance_seen / present). Challenge nonces are never
    returned; a CDN header on a normal page is informational, not a wall.
    """
    secs = _sections(
        "gate_bot_protection",
        sections,
        ("barriers", "http_challenges", "bot_protection"),
        ("barriers", "http_challenges", "bot_protection"),
    )
    conn = sess.require_conn(session_id)
    out: dict[str, Any] = {"sections": secs}
    if "barriers" in secs:
        from hardly.core.gates import classify_gates

        out["barriers"] = classify_gates(conn, host=host, explain=explain)
    if "http_challenges" in secs:
        from hardly.core.challenges import detect_challenges

        out["http_challenges"] = detect_challenges(conn, host=host, limit=_lim(limit, 20, 50), explain=explain)
    if "bot_protection" in secs:
        from hardly.core.wall import detect_walls

        out["bot_protection"] = detect_walls(conn, host=host, limit=_lim(limit, 30, 60), explain=explain)
    return _ok(out)


# ----------------------------------------------------------------------------- live (network)


@_tool
def hardly_send_entry(
    session_id: str,
    entry_id: int,
    confirm: bool = False,
    header_overrides: dict[str, str] | None = None,
    body_override: str | None = None,
    timeout_seconds: float = 30.0,
) -> str:
    """LIVE (confirm-gated): replay ONE captured request. Without confirm=true it returns only the plan and sends nothing, so tell the person what will be sent first. Sensitive HAR headers are skipped unless given in header_overrides. Example: hardly_send_entry(session_id='S', entry_id=12, confirm=true).

    For an ordered series use hardly_send_entry_series; to learn which elements are required
    hardly_send_entry_ablation. The offline curl text is hardly_entry_build_curl.
    """
    from hardly.core.probe import probe_entry

    conn = sess.require_conn(session_id)
    if not confirm:
        rows, missing = _entry_rows(conn, [entry_id])
        return _dry_run(
            {
                "requests": rows,
                "missing_entry_ids": missing,
                "header_overrides": sorted((header_overrides or {}).keys()),
                "body_override": body_override is not None,
                "timeout_seconds": timeout_seconds,
            }
        )
    return _ok(
        probe_entry(
            conn,
            entry_id,
            confirm=True,
            header_overrides=header_overrides,
            body_override=body_override,
            timeout=timeout_seconds,
        )
    )


@_tool
def hardly_send_entry_ablation(
    session_id: str,
    entry_ids: list[int],
    confirm: bool = False,
    overrides: dict[str, Any] | None = None,
    max_requests: int = 15,
    delay_seconds: float = 0.5,
    allow_unsafe: bool = False,
    allow_gates: list[str] | None = None,
) -> str:
    """LIVE (confirm-gated): find which headers, cookies, params, body fields and prior steps a request truly needs by replaying it with ONE element removed at a time. Without confirm=true it returns only the plan. Example: hardly_send_entry_ablation(session_id='S', entry_ids=[12], confirm=true).

    Reports REQUIRED vs OPTIONAL names only, never bodies. entry_ids may be an ordered flow (earlier
    ids are prior steps, the last is the target). Secrets only via ``overrides``
    {"headers":{},"cookies":{},"query":{},"body":{}}; missing ones are listed under needs_override.
    GET/HEAD only unless allow_unsafe=true. Hard stop on 429 / Retry-After / gate stop; captcha token
    fields are never sent. Budget-skipped items appear under not_tested.
    """
    from hardly.core.replay_check import replay_check

    conn = sess.require_conn(session_id)
    if not confirm:
        rows, missing = _entry_rows(conn, entry_ids)
        return _dry_run(
            {
                "requests": rows,
                "missing_entry_ids": missing,
                "max_requests": max_requests,
                "delay_seconds": delay_seconds,
                "allow_unsafe": allow_unsafe,
                "override_groups": sorted((overrides or {}).keys()),
                "method": "each entry is replayed once per removable element, at most max_requests requests",
            }
        )
    return _ok(
        replay_check(
            conn,
            entry_ids,
            overrides=overrides,
            max_requests=max_requests,
            delay_s=delay_seconds,
            allow_unsafe=allow_unsafe,
            allow_gates=allow_gates,
        )
    )


@_tool
def hardly_send_entry_series(
    session_id: str,
    entry_ids: list[int] | None = None,
    entry_id: int | None = None,
    confirm: bool = False,
    env: dict[str, str] | None = None,
    delay_seconds: float = 0.5,
    max_requests: int = 20,
    allow_unsafe: bool = False,
    allow_gates: list[str] | None = None,
) -> str:
    """LIVE (confirm-gated): replay an ordered series and report the first step whose status, content-type or body shape diverges. Without confirm=true it returns the dry-run plan and missing inputs. Example: hardly_send_entry_series(session_id='S', entry_id=20, confirm=true).

    Use to verify a client flow works. Secrets only via ``env`` {name: value} or HARDLY_INPUT_<NAME>
    env vars; values are never printed. GET/HEAD only unless allow_unsafe; halts on 429/Retry-After/
    gates.
    """
    from hardly.core.flow_replay import replay_flow

    conn = sess.require_conn(session_id)
    if not entry_ids and entry_id is None:
        raise ToolError("send_entry_series: give entry_ids or entry_id", "Pass entry_id=<target> or entry_ids=[...].", "missing_argument")
    return _ok(
        replay_flow(
            conn,
            entry_ids=entry_ids,
            target=entry_id,
            env=env,
            confirm=confirm,
            delay_s=delay_seconds,
            max_requests=max_requests,
            allow_unsafe=allow_unsafe,
            allow_gates=allow_gates,
        )
    )


@_tool
def hardly_send_site_crawl(
    url: str,
    keywords: list[str] | None = None,
    confirm: bool = False,
    max_pages: int = 12,
    depth: int = 2,
    delay_seconds: float = 1.0,
    follow_external: bool = False,
    respect_robots: bool = True,
    timeout_seconds: float = 15.0,
    user_agent: str | None = None,
    explain: bool = False,
) -> str:
    """LIVE (confirm-gated): curl-first, robots-aware, polite crawl that finds candidate pages (search forms first). Without confirm=true it returns only the plan. Use when headless Chromium is blocked or static HTML suffices; it stops at gates and never evades them. Example: hardly_send_site_crawl(url='https://example.com', keywords=['search'], confirm=true).

    Follows only links found in fetched HTML (never guesses hosts or paths), ranks them with
    ``keywords`` (nouns), honours robots.txt, waits delay_seconds between requests per host, strips
    session ids, and stops at gates and on 429/Retry-After. Caps: max_pages <= 40, depth <= 4.
    External registrable domains are only recorded unless follow_external=true (one hop). Returns
    candidates, per-page form field NAMES, gate classes and needs_browser pages (with `next` advice
    when explain=true); no bodies, URLs redacted. For needs_browser pages use
    hardly_browser_capture_discover with a find_click step.
    """
    from hardly.core.netguard import check_url
    from hardly.core.redact import redact_url

    check_url(url)
    if not confirm:
        return _dry_run(
            {
                "method": "GET",
                "url": redact_url(url),
                "keywords": keywords or [],
                "max_pages": min(max_pages, 40),
                "depth": min(depth, 4),
                "delay_seconds": delay_seconds,
                "follow_external": follow_external,
                "respect_robots": respect_robots,
            }
        )
    from hardly.core.crawl import crawl

    return _ok(
        crawl(
            url,
            tuple(keywords or ()),
            max_pages=max_pages,
            depth=depth,
            delay_s=delay_seconds,
            follow_external=follow_external,
            respect_robots=respect_robots,
            timeout_s=timeout_seconds,
            user_agent=user_agent,
            explain=explain,
        )
    )


@_tool
def hardly_send_arcgis_explore(url: str, confirm: bool = False) -> str:
    """LIVE (confirm-gated): politely explore an ArcGIS REST service or layer URL (GET only, at most 7 requests). Without confirm=true it returns only the plan, so show the person the URL first. For captured traffic use hardly_endpoint_arcgis. Example: hardly_send_arcgis_explore(url='https://host/arcgis/rest/services/X/MapServer', confirm=true).

    Returns layers, fields (personal-data-like and id fields FLAGGED), query templates and a one-row
    sample as field names + masked shapes, never values. Stops on 429 and on token-required
    (498/499); never guesses tokens.
    """
    from hardly.core.netguard import check_url
    from hardly.core.redact import redact_url

    check_url(url)
    if not confirm:
        return _dry_run(
            {"method": "GET", "url": redact_url(url), "max_requests": 7, "note": "1 service doc + up to 5 layer docs + 1 one-row sample query"}
        )
    from hardly.core.arcgis import explore

    return _ok(explore(url, confirm=True))


@_tool
def hardly_send_redirect_walk(url: str, confirm: bool = False, max_hops: int = 12) -> str:
    """LIVE (confirm-gated): explain a redirect loop (ERR_TOO_MANY_REDIRECTS) by following the chain by hand with and without cookies. Without confirm=true it returns only the plan. Reports statuses, redacted URLs and cookie names only. Example: hardly_send_redirect_walk(url='https://example.com', confirm=true).

    Reports the loop shape: www<->apex or http<->https flips, trailing-slash fights, growing return
    URLs, cookie-dependent redirects, and whether the alternate host resolves. Redirects already in
    a capture are hardly_session_redirect_history.
    """
    from hardly.core.netguard import check_url
    from hardly.core.redact import redact_url

    check_url(url)
    hops = max(2, min(max_hops, 20))
    if not confirm:
        return _dry_run({"method": "GET", "url": redact_url(url), "max_hops": hops, "note": "two passes: with and without cookies"})
    from hardly.core.redirect_diag import diagnose_redirects

    return _ok(diagnose_redirects(url, max_hops=hops))


# ----------------------------------------------------------------------------- generators


_EXPORT_FORMATS = ("openapi", "postman", "api_markdown", "site_brief", "report", "client_python", "plan_steps")


@_tool
def hardly_write_export(
    session_id: str,
    format: str,
    output_path: str,
    host: str | None = None,
    exclude_noise: bool = True,
    title: str | None = None,
    max_endpoints: int | None = None,
    detail: str = "standard",
    categories: list[str] | None = None,
    entry_ids: list[int] | None = None,
    class_name: str | None = None,
    limit: int | None = None,
    overwrite: bool = False,
) -> str:
    """Writes a file: export the session as format openapi, postman, api_markdown, site_brief, report, client_python or plan_steps to output_path. Secrets are redacted or placeholders; refuses to overwrite unless overwrite=true. Example: hardly_write_export(session_id='S', format='openapi', output_path='/tmp/api.yaml', host='api.example.com').

    openapi: OpenAPI 3 (JSON or YAML by file extension; input to hardly_spec_contract_check).
    postman: Collection v2.1 with {{placeholders}} (``title`` names it). api_markdown: API.md of the
    endpoints (``max_endpoints``, default 200). site_brief: the hardly_session_site_brief digest as
    Markdown. report: the hardly_session_report findings (``detail`` summary|standard|full,
    ``categories``; .json path = JSON, else Markdown; a directory gets <har>.report.md).
    client_python: the starter urllib client of hardly_client_build (``entry_ids``, ``class_name``).
    plan_steps: the JSON steps of hardly_session_plan_steps (``limit``).
    """
    fmt = _choice("write_export", "format", format, _EXPORT_FORMATS)
    conn = sess.require_conn(session_id)
    har = sess.get_har_path(session_id)
    if fmt == "report":
        stem = (har.stem if har else "hardly") + ".report.md"
        target = _out(output_path, overwrite, default_name=stem)
    else:
        target = _out(output_path, overwrite)
    if fmt == "openapi":
        from hardly.core.export_openapi import export_openapi

        res = export_openapi(conn, target, host=host, exclude_noise=exclude_noise, title=title or "HAR-derived API")
    elif fmt == "postman":
        from hardly.core.export_postman import export_postman

        res = export_postman(conn, target, host=host, exclude_noise=exclude_noise, name=title or "HAR-derived API")
    elif fmt == "api_markdown":
        from hardly.core.export_md import export_markdown

        res = export_markdown(conn, target, host=host, exclude_noise=exclude_noise, max_endpoints=_lim(max_endpoints, 200, 2000))
    elif fmt == "site_brief":
        from hardly.core.export_brief import export_brief_md

        res = export_brief_md(conn, target, har_path=har, host=host)
    elif fmt == "report":
        from hardly.core.report import build_report, write_report

        rep = build_report(conn, har, host=host, sections=categories, detail=detail)
        res = {"output_path": str(write_report(rep, target, har_path=har)), "detail": detail, "findings": len(rep.get("findings", []))}
    elif fmt == "client_python":
        from hardly.core.stub import client_stub

        res = client_stub(conn, entry_ids=entry_ids, host=host, output_path=target, class_name=class_name or "PortalClient")
    else:
        from hardly.core.recipe_plan import recipe_from_story

        res = recipe_from_story(conn, host=host, output_path=target, limit=_lim(limit, 30, 60))
    if isinstance(res, dict) and "error" not in res:
        res.setdefault("format", fmt)
        res.setdefault("output_path", str(target))
    return _ok(res)


@_tool
def hardly_client_build(
    session_id: str,
    entry_ids: list[int] | None = None,
    host: str | None = None,
    class_name: str | None = None,
) -> str:
    """Build a minimal Python (urllib) client sketch from story steps or chosen entry_ids and return it as text; secrets become PLACEHOLDER_* values. Writes nothing (hardly_write_export format=client_python saves it). Example: hardly_client_build(session_id='S', entry_ids=[12, 14]).

    Use as the last step of SDK work, after hardly_session_story / hardly_session_site_brief.
    """
    from hardly.core.stub import client_stub

    conn = sess.require_conn(session_id)
    return _ok(client_stub(conn, entry_ids=entry_ids, host=host, output_path=None, class_name=class_name or "PortalClient"))


# ----------------------------------------------------------------------------- prompts


@mcp.prompt
def analyze_har(har_path: str) -> str:
    """Archive mode: analyze an existing HAR file without Playwright."""
    return (
        f"Mode=archive. Analyze `{har_path}` with hardly tools only "
        "(do not Read the HAR file):\n"
        "1. hardly_session_open(har_path) -> session_id\n"
        "2. hardly_session_overview — use main_host for portals\n"
        "3. Portal: hardly_session_site_brief -> page_forms / entry_outline / "
        "session_trace_value\n"
        "4. JSON API: hardly_endpoint_list -> session_traffic_stats -> auth_report -> "
        "endpoint_schema\n"
        "5. Export: hardly_client_build / hardly_write_export (format=site_brief | "
        "openapi) as needed\n"
        "If you only have a URL (no HAR), switch to headless "
        "(hardly_browser_capture_discover) or interactive (capture_portal)."
    )


@mcp.prompt
def discover_apis(url: str) -> str:
    """Headless mode: agent loads a URL and discovers APIs automatically."""
    return (
        f"Mode=headless. Discover APIs for `{url}` without asking a person:\n"
        "1. hardly_server_status(sections=['browser_setup']) if capture_available is false.\n"
        "2. Prefer hardly_browser_capture_discover(url, analyze=true, channel='chrome', "
        "wait_seconds=8, confirm=true) for a one-shot load (+ optional steps). Without "
        "confirm=true it only returns the plan.\n"
        "3. Or loop: hardly_browser_start(url, headed=false) -> "
        "hardly_browser_inspect(sections=['aria']) -> hardly_browser_interact with ref -> "
        "hardly_browser_stop(open_session=true).\n"
        "4. Continue in archive mode: hardly_session_site_brief / endpoint_list / "
        "session_trace_value.\n"
        "5. If wall/CAPTCHA/empty bodies: switch to interactive "
        "(hardly_browser_start headed=true channel=chrome) and ASK THE PERSON.\n"
        "Never Read the HAR file into context."
    )


@mcp.prompt
def document_api(host: str) -> str:
    """Guide for documenting an API host from a loaded HAR (archive mode)."""
    return (
        f"Mode=archive. Document the API for host `{host}` using hardly "
        "tools only (do not read the HAR file). Steps:\n"
        "1. hardly_session_overview / hardly_endpoint_list(host=...)\n"
        "2. hardly_auth_report(host=...) and hardly_session_timeline(host=...)\n"
        "3. hardly_entry_get / hardly_endpoint_schema for important endpoints\n"
        "4. hardly_write_export(format='api_markdown') to write API.md\n"
        "Keep responses redacted; prefer entry IDs over large bodies."
    )


@mcp.prompt
def find_auth_flow(host: str) -> str:
    """Guide for tracing login/MFA on a host (archive mode)."""
    return (
        f"Mode=archive. Trace authentication for `{host}` with hardly:\n"
        "1. hardly_auth_report(host=...)\n"
        "2. hardly_session_timeline(host=..., path_prefix=/login or similar)\n"
        "3. hardly_entry_compare on pre/post MFA login requests\n"
        "4. Note tokens in response bodies (Chrome may strip Authorization cookies).\n"
        "If login needs a person/CAPTCHA, use interactive capture_portal first."
    )


@mcp.prompt
def capture_portal(url: str) -> str:
    """Interactive mode: person drives the browser; agent records and analyzes."""
    return (
        f"Mode=interactive. Record `{url}` with a person in the headed browser:\n"
        "1. hardly_server_status(sections=['browser_setup']) if capture_available is false.\n"
        "2. hardly_browser_start(url=..., headed=true, channel='chrome').\n"
        "3. ASK THE PERSON to complete the portal steps "
        "(cookies, search, open detail, login). Do not pretend you can see "
        "their screen — tell them what to do, then wait.\n"
        "4. Optional: hardly_write_screenshot / hardly_capture_list while they work.\n"
        "5. When they finish: hardly_browser_stop(open_session=true).\n"
        "6. hardly_session_site_brief(session_id), then page_forms / "
        "session_trace_value / page_embedded_routes as needed.\n"
        "If the flow is fully scriptable, prefer headless "
        "hardly_browser_capture_discover instead.\n"
        "Cursor's IDE browser does not feed HARs into hardly."
    )


@mcp.prompt
def reverse_engineer_api(har_path: str) -> str:
    """Workflow: reverse engineer the API behind an existing HAR file (archive mode)."""
    return (
        f"Reverse engineer the API in `{har_path}` using hardly tools only "
        "(never Read the HAR file; results are redacted and paged):\n"
        "1. hardly_session_open(har_path) -> session_id\n"
        "2. hardly_session_report(session_id, detail='summary') -> blockers, auth, stack\n"
        "3. hardly_session_overview -> note main_host; pass it as host= below\n"
        "4. HTML site: hardly_session_site_brief, then hardly_session_story / "
        "hardly_page_forms. JSON API: hardly_endpoint_list, hardly_endpoint_schema, "
        "hardly_endpoint_pagination\n"
        "5. Auth: hardly_auth_report(sections=['credentials','patterns']), "
        "hardly_session_trace_value for carried tokens\n"
        "6. Large body: hardly_entry_body_query instead of hardly_entry_get\n"
        "7. Output: hardly_write_export (format=openapi | api_markdown) to a scratch "
        "directory\n"
        "If the report shows a gate (bot wall, captcha, login), stop and see "
        "the diagnose_blocked_capture prompt. Never print secret values."
    )


@mcp.prompt
def build_client_sdk(session_id: str) -> str:
    """Workflow: turn an open session into a small client SDK."""
    return (
        f"Build a client SDK from session `{session_id}` (if it is unknown, "
        "hardly_session_list / hardly_session_open again):\n"
        "1. hardly_session_overview -> main_host; hardly_session_story(host=...) for the steps\n"
        "2. hardly_auth_report(sections=['credentials','patterns']) -> how login works\n"
        "3. hardly_session_trace_value (no name) + hardly_entry_dependencies(entry_id=<key "
        "request>) -> values that must be carried and the minimal prior steps\n"
        "4. hardly_endpoint_schema(sections=['schema','param_roles']) / "
        "hardly_endpoint_pagination for each endpoint you will wrap\n"
        "5. hardly_write_export(format='client_python', output_path=<scratch>/client.py) "
        "for the starter client (hardly_client_build returns it as text); secrets are "
        "PLACEHOLDER_* values, supply them via env, never hard-code\n"
        "6. Move the logic into your SDK package; keep site vocabulary there, "
        "not in hardly\n"
        "7. Verify with the verify_client prompt (live steps need the person's "
        "confirmation)."
    )


@mcp.prompt
def diagnose_blocked_capture(url: str) -> str:
    """Workflow: work out why a capture of a URL was blocked and what to do next."""
    return (
        f"Diagnose a blocked or empty capture of `{url}`:\n"
        "1. If a session exists: hardly_gate_bot_protection(session_id, explain=true) "
        "(barriers, http_challenges, bot_protection), hardly_session_issues\n"
        "2. environment_blocked means OUR sandbox/proxy refused: report 'unknown, "
        "re-run from another network', not a site wall\n"
        "3. bot_wall / captcha / proof_of_work / waiting_room / login / paywall / "
        "rate_limit are STOP signs: do not retry in a loop, do not try to solve or "
        "evade. Re-capture interactively: hardly_browser_start(url, headed=true, "
        "channel='chrome'), ask the person to complete the steps, then "
        "hardly_browser_stop(open_session=true)\n"
        "4. Redirect loop on a live URL: hardly_send_redirect_walk(url, confirm=true) "
        "after telling the person it makes live GETs\n"
        "5. No session at all: hardly_server_status(sections=['browser_setup']) "
        "(is the browser installed?)\n"
        "6. Static HTML may suffice: hardly_send_site_crawl(url, confirm=true) is "
        "polite and stops at gates\n"
        "Docs: resource hardly://docs/gate-policy."
    )


@mcp.prompt
def verify_client(session_id: str, entry_id: int) -> str:
    """Workflow: verify a generated client against the capture and the live site."""
    return (
        f"Verify a client for session `{session_id}`, target entry {entry_id}:\n"
        f"1. hardly_entry_dependencies(session_id, entry_id={entry_id}) -> ordered steps and "
        "the inputs you must supply\n"
        f"2. hardly_send_entry_series(session_id, entry_id={entry_id}, confirm=false) -> "
        "dry-run plan and missing inputs\n"
        "3. Tell the person exactly what will be sent, then repeat with "
        "confirm=true. Supply secrets via env / HARDLY_INPUT_<NAME>; never "
        "print them\n"
        f"4. hardly_send_entry_ablation(session_id, entry_ids=[{entry_id}], confirm=true) "
        "to learn which headers/cookies/fields are REQUIRED vs OPTIONAL\n"
        "5. After writing a spec: hardly_spec_contract_check(session_id, spec_path)\n"
        "Stop on 429, Retry-After or any gate; do not retry a challenged URL."
    )


def _register_doc_resources() -> None:
    from hardly.resources import DOC_RESOURCES, read_doc

    def make(filename: str):
        def _read() -> str:
            return read_doc(filename)

        return _read

    for slug, filename in DOC_RESOURCES.items():
        mcp.resource(
            f"hardly://docs/{slug}",
            name=f"hardly-docs-{slug}",
            description=f"hardly documentation: {slug}",
            mime_type="text/markdown",
        )(make(filename))


_register_doc_resources()


@mcp.resource(
    "hardly://cheatsheet",
    name="hardly-cheatsheet",
    description="One-page quick reference: modes, drill-down order, safety rules.",
    mime_type="text/markdown",
)
def cheatsheet() -> str:
    from hardly.resources import read_doc

    return read_doc("cheatsheet.md")


def main() -> None:
    from hardly.ephemeral import sweep_ephemeral

    sweep_ephemeral()  # crash leftovers from earlier runs
    mcp.run()


if __name__ == "__main__":
    main()
