"""FastMCP server exposing hardly tools."""

from __future__ import annotations

import json
from typing import Any

from fastmcp import FastMCP

from hardly import session as sess
from hardly.core.auth import detect_auth
from hardly.core.curl import entry_to_curl
from hardly.core.export_md import export_markdown
from hardly.core.export_openapi import export_openapi
from hardly.core.flows import get_flow
from hardly.core.probe import probe_entry
from hardly.index import query as q
from hardly.session import resolve_path

INSTRUCTIONS = """\
hardly analyzes HAR files (recorded browser traffic) and can record them, so you \
can discover an API, understand login/session flows, and build a client SDK or \
OpenAPI spec. Use when asked to read/analyze a HAR, find endpoints, \
forms, cookies, CSRF or pagination, capture a site, or verify a client. \
Content-neutral: you supply site vocabulary, hardly detects technologies.

Start: call hardly_start(goal, har_path, url) for an ordered plan and \
environment state (browser available? sessions open?). Cheat sheet: resource \
hardly://cheatsheet. Workflow prompts: reverse_engineer_api, build_client_sdk, \
diagnose_blocked_capture, verify_client.

Workflow:
1. Choose mode. Have a .har: archive, hardly_open. Scriptable URL: headless, \
hardly_discover. Wall/captcha/MFA/login or a person is needed: interactive, \
hardly_capture_start(headed=true, channel='chrome'), ASK THE PERSON to use the \
window, then hardly_capture_stop(open_session=true).
2. Orient with session_id: hardly_report(detail='summary'), hardly_hosts (use \
preferred_host as host=), then hardly_brief (HTML portals) or hardly_endpoints \
(JSON APIs).
3. Drill down: story/forms/outline, credentials/correlate/trace, entry, \
body_query (big bodies), schema, pagination.
4. Produce: hardly_stub, hardly_export_openapi, hardly_export_md (write to a \
scratch dir).
5. Verify: hardly_flow_graph (offline), then hardly_flow_replay / \
hardly_replay_check (live).

Rules:
- Never Read a raw HAR; use hardly_open and the query tools. Results are \
small, redacted and paged (limit/offset); keep limits small.
- Live tools (probe, crawl, replay_check, flow_replay, catalog_verify, \
arcgis_explore, redirect_diag) send nothing without confirm=true; tell the \
person what will be sent first.
- Gates (bot wall, captcha, proof of work, waiting room, login, paywall, rate \
limit) are stop signs: do not evade or retry; use interactive capture with a \
person. An environment_blocked verdict means unknown, re-run elsewhere.
- Secret values are never returned. Supply secrets only via overrides/env.
- After an MCP restart tools auto-reattach cached session_ids; \
hardly_list_sessions / hardly_reopen if not. Tool missing: hardly_capabilities \
(restart the server). Browser problems: hardly_capture_doctor.
"""

mcp = FastMCP("hardly", instructions=INSTRUCTIONS)


def _ok(data: Any) -> str:
    return json.dumps(data, indent=2, default=str)


def _hint_for(exc: Exception) -> str | None:
    """Actionable next step for the most common first-use mistakes."""
    msg = str(exc.args[0]) if exc.args else str(exc)
    low = msg.lower()
    if "unknown session_id" in low:
        return (
            "hardly_list_sessions shows known ids; hardly_reopen(session_id) "
            "reattaches a cached one; otherwise hardly_open(har_path) or "
            "hardly_discover(url) creates a session."
        )
    if isinstance(exc, FileNotFoundError) or "no such file" in low:
        return (
            "Check the path (use an absolute path on the machine running the MCP "
            "server). Already-indexed HARs: hardly_list_sessions."
        )
    if "confirm" in low and "true" in low:
        return "Live tool: tell the person what will be sent, then repeat with confirm=true."
    if isinstance(exc, ImportError):
        return "Optional dependency missing: run hardly_capture_doctor for install steps."
    return None


def _err(exc: Exception) -> str:
    msg = str(exc.args[0]) if isinstance(exc, KeyError) and exc.args else str(exc)
    out: dict[str, Any] = {"error": msg}
    hint = _hint_for(exc)
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
        except (FileNotFoundError, NotADirectoryError) as exc:
            return _err(exc)
        except KeyError as exc:
            if "unknown session_id" in str(exc).lower():
                return _err(exc)
            raise

    return mcp.tool(wrapper)


@_tool
def hardly_capabilities() -> str:
    """Report version, feature flags, tool names and whether browser capture is available. Call when a tool seems missing (stale MCP server: restart it) or to check capture_available. Small output (~3 KB).
    """
    from hardly.capabilities import capabilities

    return _ok(capabilities())


@_tool
def hardly_modes() -> str:
    """List the three operating modes (archive, headless, interactive) with when to use each. Call first if unsure; hardly_start gives a full ordered plan and hardly_mode a playbook for one mode.
    """
    from hardly.core.modes import list_modes

    return _ok(list_modes())


@_tool
def hardly_mode(
    mode: str = "",
    goal: str = "",
    har_path: str = "",
    url: str = "",
) -> str:
    """Get the step-by-step playbook for one mode, or auto-pick a mode from goal / har_path / url. Use after hardly_modes; hardly_start is the better first call for a first-time plan. Example: hardly_mode(har_path='/data/capture.har').
    """
    from hardly.core.modes import mode_playbook, pick_mode

    if (mode or "").strip():
        return _ok(
            mode_playbook(
                mode,
                har_path=har_path or "",
                url=url or "",
                goal=goal or "",
            )
        )
    return _ok(
        pick_mode(
            goal=goal or "",
            har_path=har_path or "",
            url=url or "",
        )
    )


@_tool
def hardly_help(topic: str = "") -> str:
    """Categorized catalog of tools and workflows; pass topic to filter. Use when you do not know which tool fits (topics: portal, tokens, capture, modes, or a tool name); for a goal-specific suggestion use hardly_recommend instead. Example: hardly_help(topic='capture').
    """
    from hardly.core.help import tool_help

    return _ok(tool_help(topic or None))


@_tool
def hardly_start(goal: str = "", har_path: str = "", url: str = "") -> str:
    """FIRST CALL for a new task: returns an ordered plan of hardly tool calls with example arguments, plus environment state (browser available? sessions open?). Pass what you know: goal (free text, e.g. 'build a client SDK'), har_path, url. Small output (~2 KB); for a deeper playbook of one mode use hardly_mode, for a tool catalog hardly_help. Example: hardly_start(goal='reverse engineer the login flow', har_path='/data/capture.har').
    """
    from hardly.core.start import build_plan

    return _ok(build_plan(goal=goal or "", har_path=har_path or "", url=url or ""))


@_tool
def hardly_open(har_path: str, force: bool = False, storage: str | None = None) -> str:
    """Index a HAR file into a queryable session and return session_id plus summary counts. Start here for any existing HAR; never Read the raw HAR file. Reuses the cache when the file is unchanged. storage=disk|memory|auto (default from HARDLY_INDEX, else disk); memory writes nothing to disk. Example: hardly_open(har_path='/data/capture.har'), then hardly_brief(session_id).
    """
    return _ok(sess.open_har(har_path, force=force, storage=storage))


@_tool
def hardly_capture_start(
    url: str = "",
    har_path: str = "",
    headed: bool = True,
    channel: str = "",
    url_filter: str = "",
    omit_content: bool = False,
    label: str = "",
    profile: str = "",
    same_tab: bool = True,
    trace: bool = False,
) -> str:
    """Launch a browser capture that records a HAR (needs the capture extra). headed=true (default) is interactive: ASK THE PERSON to use the window, then call hardly_capture_stop; headed=false is headless and you drive it with hardly_capture_aria / click / recipe. For a one-shot headless load prefer hardly_discover. Example: hardly_capture_start(url='https://example.com', headed=true, channel='chrome').

    Requires ``pip install -e ".[capture]"`` + ``playwright install chromium`` (see hardly_capture_doctor). Prefer channel='chrome' for bot walls. url_filter is a Playwright glob. profile keeps cookies. same_tab (default true) forces target=_blank into the current tab. trace=true writes a ``.trace.zip`` beside the HAR. Waits for a capture slot (HARDLY_CAPTURE_SLOTS); the result carries ``slot``.
    """
    try:
        from hardly.capture import CaptureError, start_capture
    except ImportError as exc:
        return _err(exc)
    try:
        result = start_capture(
            url,
            har_path or None,
            headed=headed,
            channel=channel,
            url_filter=url_filter,
            omit_content=omit_content,
            label=label,
            user_data_dir=profile or None,
            trace=True if trace else None,
            same_tab=same_tab,
        )
        # Keep channel_hint / aria-ref next from start_capture.
        return _ok(result)
    except CaptureError as exc:
        return _err(exc)


@_tool
def hardly_capture_stop(
    capture_id: str = "",
    open_session: bool = True,
    force: bool = False,
) -> str:
    """Stop a running capture, flush the HAR and optionally open it as a session. Call when the person says they are done (interactive) or your recipe is complete; then continue with hardly_brief(session_id). Omit capture_id to stop the latest running capture. Example: hardly_capture_stop(open_session=true).
    """
    try:
        from hardly.capture import CaptureError, stop_capture
    except ImportError as exc:
        return _err(exc)
    try:
        return _ok(
            stop_capture(
                capture_id or None,
                open_session=open_session,
                force=force,
            )
        )
    except CaptureError as exc:
        return _err(exc)


@_tool
def hardly_capture_goto(url: str, capture_id: str = "") -> str:
    """Navigate the running capture tab to a URL. Use during headless driving or to steer an interactive capture; omit capture_id for the latest. Example: hardly_capture_goto(url='https://example.com/search').
    """
    try:
        from hardly.capture import CaptureError, navigate_capture
    except ImportError as exc:
        return _err(exc)
    try:
        return _ok(navigate_capture(capture_id or None, url))
    except CaptureError as exc:
        return _err(exc)


@_tool
def hardly_capture_elements(
    capture_id: str = "",
    limit: int = 40,
    query: str = "",
) -> str:
    """List visible interactive elements (links, buttons, inputs) on the live capture tab with css/xpath locators. Use to find selectors for click/fill; for a ref-based accessibility tree prefer hardly_capture_aria. Example: hardly_capture_elements(limit=30).

    Returns tag/text/href plus ``css`` and ``xpath`` locators for each control
    (buttons, links, inputs, onclick nodes). Use those with
    hardly_capture_click / hardly_capture_fill. Omit capture_id = latest running.
    Optional ``query`` is a CSS selector override for which nodes to scan.
    """
    try:
        from hardly.capture import CaptureError, list_capture_elements
    except ImportError as exc:
        return _err(exc)
    try:
        return _ok(
            list_capture_elements(
                capture_id or None,
                limit=min(max(1, limit), 100),
                query=query or "",
            )
        )
    except CaptureError as exc:
        return _err(exc)


@_tool
def hardly_capture_click(
    capture_id: str = "",
    ref: str = "",
    xpath: str = "",
    css: str = "",
    text: str = "",
    role: str = "",
    name: str = "",
    timeout_ms: int = 10000,
) -> str:
    """Click an element on the live capture tab. Prefer ref from hardly_capture_aria; else xpath/css from hardly_capture_elements, or text= / role= with name=. Example: hardly_capture_click(ref='e12').
    """
    try:
        from hardly.capture import CaptureError, click_capture
    except ImportError as exc:
        return _err(exc)
    try:
        return _ok(
            click_capture(
                capture_id or None,
                ref=ref,
                xpath=xpath,
                css=css,
                text=text,
                role=role,
                name=name,
                timeout_ms=timeout_ms,
            )
        )
    except CaptureError as exc:
        return _err(exc)


@_tool
def hardly_capture_fill(
    capture_id: str = "",
    value: str = "",
    ref: str = "",
    xpath: str = "",
    css: str = "",
    timeout_ms: int = 10000,
) -> str:
    """Type a value into an input on the live capture tab. Prefer ref from hardly_capture_aria; else xpath or css. Never type real credentials yourself; ask the person to use interactive capture. Example: hardly_capture_fill(ref='e7', value='query').
    """
    try:
        from hardly.capture import CaptureError, fill_capture
    except ImportError as exc:
        return _err(exc)
    try:
        return _ok(
            fill_capture(
                capture_id or None,
                value=value,
                ref=ref,
                xpath=xpath,
                css=css,
                timeout_ms=timeout_ms,
            )
        )
    except CaptureError as exc:
        return _err(exc)


@_tool
def hardly_capture_press(
    capture_id: str = "",
    key: str = "Enter",
    ref: str = "",
    xpath: str = "",
    css: str = "",
    timeout_ms: int = 10000,
) -> str:
    """Press a key (e.g. Enter) on the live capture tab, optionally on a ref/xpath/css target. Example: hardly_capture_press(key='Enter', ref='e7').
    """
    try:
        from hardly.capture import CaptureError, press_capture
    except ImportError as exc:
        return _err(exc)
    try:
        return _ok(
            press_capture(
                capture_id or None,
                key=key,
                ref=ref,
                xpath=xpath,
                css=css,
                timeout_ms=timeout_ms,
            )
        )
    except CaptureError as exc:
        return _err(exc)


@_tool
def hardly_capture_url(capture_id: str = "") -> str:
    """Return the live capture tab's current URL and title. Cheap check of where a click or redirect landed. Example: hardly_capture_url().
    """
    try:
        from hardly.capture import CaptureError, capture_page_url
    except ImportError as exc:
        return _err(exc)
    try:
        return _ok(capture_page_url(capture_id or None))
    except CaptureError as exc:
        return _err(exc)


@_tool
def hardly_capture_aria(
    capture_id: str = "",
    selector: str = "",
    mode: str = "ai",
) -> str:
    """Live accessibility snapshot (YAML) of the capture tab with [ref=eN] handles; the best view for driving the UI headlessly. For offline HAR HTML bodies use hardly_outline instead. Example: hardly_capture_aria(selector='main').

    This is the rendered ARIA tree (roles/names/states) — best for driving the
    UI. ``mode="ai"`` (default) asks Playwright for refs like ``[ref=eN]`` when
    the installed build supports it; falls back to default otherwise.
    Optional CSS ``selector`` scopes the snapshot (default: body).
    For offline HAR HTML/XML bodies use ``hardly_outline`` instead.
    """
    try:
        from hardly.capture import CaptureError, capture_aria_snapshot
    except ImportError as exc:
        return _err(exc)
    try:
        return _ok(
            capture_aria_snapshot(
                capture_id or None,
                selector=selector or "",
                mode=mode or "ai",
            )
        )
    except CaptureError as exc:
        return _err(exc)


@_tool
def hardly_capture_doctor() -> str:
    """Diagnose the optional Playwright install (package vs browser binaries) and print the exact install commands. Call when capture_available is false or capture_start fails.

    Call when capture_available is false or capture_start fails. Returns
    version, which browsers are on disk, feature flags (aria_snapshot /
    aria_mode_ai), and the exact install commands to run.
    """
    try:
        from hardly.capture import playwright_status
    except ImportError as exc:
        return _err(exc)
    return _ok(playwright_status())


@_tool
def hardly_capture_screenshot(
    capture_id: str = "",
    path: str = "",
    full_page: bool = False,
) -> str:
    """Save a PNG screenshot of the live capture tab and return its path. Use to show a person or inspect a wall; path is optional (defaults to the cache dir). Example: hardly_capture_screenshot(full_page=true).
    """
    try:
        from hardly.capture import CaptureError, capture_screenshot
    except ImportError as exc:
        return _err(exc)
    try:
        return _ok(
            capture_screenshot(
                capture_id or None,
                path=path or "",
                full_page=full_page,
            )
        )
    except CaptureError as exc:
        return _err(exc)


@_tool
def hardly_capture_recipe(
    steps: list[dict],
    capture_id: str = "",
    stop_on_error: bool = True,
) -> str:
    """Run a scripted list of steps on the live capture tab in one call (cheaper than many single calls). Use once you know the selectors; prefer hardly_discover for a plain load.

    Each step: ``{"op":"goto"|"wait"|"elements"|"click"|"fill"|"press"|"url"|"aria",
    ...}``. Example::

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
    try:
        from hardly.capture import CaptureError, run_capture_recipe
    except ImportError as exc:
        return _err(exc)
    try:
        return _ok(
            run_capture_recipe(
                steps,
                capture_id=capture_id or None,
                stop_on_error=stop_on_error,
            )
        )
    except CaptureError as exc:
        return _err(exc)


@_tool
def hardly_capture_list() -> str:
    """List browser captures (running and persisted) with ids and states. Use to find a capture_id after a restart or to see what is still running. No arguments.
    """
    try:
        from hardly.capture import list_captures
    except ImportError as exc:
        return _err(exc)
    return _ok({"captures": list_captures()})


@_tool
def hardly_capture_status(capture_id: str = "") -> str:
    """Status of one capture_id, or the latest running capture if omitted: state, HAR path, entry counts. Poll this while a person drives an interactive capture. Example: hardly_capture_status().
    """
    try:
        from hardly.capture import CaptureError, get_capture, latest_running_id
    except ImportError as exc:
        return _err(exc)
    try:
        cid = capture_id or latest_running_id()
        if not cid:
            return _err(CaptureError("no running capture"))
        return _ok(get_capture(cid))
    except CaptureError as exc:
        return _err(exc)


@_tool
def hardly_capture_once(
    url: str,
    wait_seconds: float = 20,
    har_path: str = "",
    headed: bool = False,
    channel: str = "",
    url_filter: str = "",
    open_session: bool = True,
) -> str:
    """Timed capture: open a URL, wait wait_seconds, stop. Prefer hardly_discover for headless API discovery (it also opens a session and a brief); use this only for a raw timed HAR. Example: hardly_capture_once(url='https://example.com', wait_seconds=8).
    """
    try:
        from hardly.capture import CaptureError, capture_for
    except ImportError as exc:
        return _err(exc)
    try:
        return _ok(
            capture_for(
                url,
                har_path or None,
                wait_seconds=wait_seconds,
                headed=headed,
                channel=channel,
                url_filter=url_filter,
                open_session=open_session,
            )
        )
    except CaptureError as exc:
        return _err(exc)


@_tool
def hardly_discover(
    url: str,
    wait_seconds: float = 5,
    har_path: str = "",
    channel: str = "",
    url_filter: str = "",
    recipe_json: str = "",
    open_session: bool = True,
    brief: bool = True,
    budget_seconds: float = 0,
    block_noise: bool = False,
) -> str:
    """Headless one-shot API discovery: load a URL (optional recipe), stop, open a session and return a brief. Use when the page is scriptable and no person is needed; if the brief shows a wall or captcha, STOP and switch to interactive hardly_capture_start(headed=true, channel='chrome') with a person. Example: hardly_discover(url='https://example.com', wait_seconds=8).

    Agent-driven API discovery — no person needed. Returns ``session_id``,
    ``brief``, ``capture_mode=headless``, and ``mode=archive`` for drill-down.
    ``recipe_json`` is a JSON list of steps (goto/wait/aria/click/fill/…) or
    empty for a plain load+wait. A ``find_click`` step
    (``{"op":"find_click","keywords":["your","terms"],"max_hops":4}``) follows
    ranked links/buttons until a real search form appears. If the brief shows a wall, switch to
    interactive: hardly_capture_start(headed=true, channel=chrome) and ask
    the person.

    budget_seconds (or env HARDLY_CAPTURE_BUDGET) is a hard per-call budget:
    once exceeded, remaining recipe steps are skipped, the HAR is still
    written, and the result has budget={limit_s, used_s, exceeded,
    skipped_steps}. block_noise=true aborts analytics/ad/font/map-tile/heavy
    media requests (result: blocked_requests, blocked_hosts); default off
    because blocking can break sites. Concurrent captures queue on a
    cross-process slot limiter (HARDLY_CAPTURE_SLOTS, default 4); results carry
    slot={waited_s, queue_depth, slot}, and errors carry error_class /
    error_advice.
    """
    try:
        from hardly.capture import CaptureError, discover_apis
    except ImportError as exc:
        return _err(exc)
    steps: list | None = None
    if (recipe_json or "").strip():
        try:
            parsed = json.loads(recipe_json)
        except json.JSONDecodeError as exc:
            return _err(exc)
        if not isinstance(parsed, list):
            return _err(ValueError("recipe_json must be a JSON list of steps"))
        steps = parsed
    try:
        return _ok(
            discover_apis(
                url,
                har_path or None,
                recipe=steps,
                wait_seconds=wait_seconds,
                channel=channel,
                url_filter=url_filter,
                open_session=open_session,
                brief=brief,
                budget_seconds=(budget_seconds or None),
                block_noise=block_noise,
            )
        )
    except CaptureError as exc:
        return _err(exc)


@_tool
def hardly_list_sessions() -> str:
    """List cached and open HAR sessions (session_id, har_path, open flag, storage=disk|memory). Use after an MCP restart or when you lost a session_id; then hardly_reopen if open=false. No arguments.
    """
    return _ok({"sessions": sess.list_sessions()})


@_tool
def hardly_close(session_id: str) -> str:
    """Close an open session to free memory (a disk session's cache file stays, so hardly_reopen can restore it; a memory session is discarded). Example: hardly_close(session_id='S').
    """
    return _ok(sess.close_session(session_id))


@_tool
def hardly_persist(session_id: str, path: str | None = None, overwrite: bool = False) -> str:
    """Save a session's index as a compact SQLite file (for storage=memory sessions, which otherwise vanish on restart). Refuses to overwrite unless overwrite=true. Example: hardly_persist(session_id='S').
    """
    return _ok(sess.persist_session(session_id, path, overwrite=overwrite))


@_tool
def hardly_reopen(session_id: str, force: bool = False) -> str:
    """Reattach a cached session after an MCP restart without needing the HAR path. Use when hardly_list_sessions shows open=false for your session_id; other tools also auto-reattach. Memory sessions are not cached: reopen the HAR instead. Example: hardly_reopen(session_id='S').
    """
    return _ok(sess.reopen_session(session_id, force=force))


@_tool
def hardly_summary(session_id: str) -> str:
    """Host, method and status histograms for a session. Cheap first look at what a capture contains; for a full portal overview use hardly_brief, for an evidence index hardly_report. Example: hardly_summary(session_id='S').
    """
    try:
        conn = sess.require_conn(session_id)
    except KeyError as exc:
        return _err(exc)
    return _ok({**q.summary(conn), "storage": sess.get_storage(session_id)})


@_tool
def hardly_coverage(
    session_id: str,
    host: str | None = None,
    exclude_noise: bool = True,
    limit: int = 20,
) -> str:
    """Report how many entries have usable body text versus empty or truncated. Use before trusting schema/stub output, or when bodies look missing. Example: hardly_coverage(session_id='S').

    Useful after Playwright captures that used to omit XHR bodies (size=-1).
    """
    try:
        conn = sess.require_conn(session_id)
    except KeyError as exc:
        return _err(exc)
    return _ok(
        q.body_coverage(
            conn,
            host=host,
            exclude_noise=exclude_noise,
            limit=min(limit, 50),
        )
    )


@_tool
def hardly_hosts(session_id: str, exclude_noise: bool = False) -> str:
    """List hosts with request counts and the preferred_host (the app origin, not CDN/analytics). Run right after hardly_open to choose the host= argument for later tools. Example: hardly_hosts(session_id='S', exclude_noise=true).
    """
    try:
        conn = sess.require_conn(session_id)
    except KeyError as exc:
        return _err(exc)
    return _ok(
        {
            "hosts": q.list_hosts(conn, exclude_noise=exclude_noise),
            "preferred_host": q.preferred_host(conn),
        }
    )


@_tool
def hardly_endpoints(
    session_id: str,
    host: str | None = None,
    exclude_noise: bool = True,
    limit: int = 100,
    offset: int = 0,
) -> str:
    """List grouped endpoints (METHOD + path template) with counts, paged by limit/offset. The main API surface view for JSON APIs; for server-rendered pages use hardly_brief or hardly_forms. Example: hardly_endpoints(session_id='S', host='api.example.com').
    """
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


@_tool
def hardly_search(
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
    exclude_options: bool = True,
    limit: int = 50,
    offset: int = 0,
) -> str:
    """Find entries by host, path, method, status, body text, header or content_kind; returns small paged rows with entry_ids. Use to locate a specific request, then hardly_entry for detail. Example: hardly_search(session_id='S', body_contains='token', limit=10).

    ``content_kind`` uses the classifier: json, jsonl, jsonp, csv, html,
    html_table (or table), pdf, image, css, javascript, …
    Result rows include ``content_kind`` / hints.
    """
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
            header_name=header_name,
            header_contains=header_contains,
            mime_contains=mime_contains,
            content_kind=content_kind,
            exclude_noise=exclude_noise,
            exclude_options=exclude_options,
            limit=min(limit, 200),
            offset=offset,
        )
    )


@_tool
def hardly_stats(
    session_id: str,
    host: str | None = None,
    exclude_noise: bool = True,
) -> str:
    """MIME mix, status classes, body sizes, initiator types and timing for a session or host. Use for traffic shape; for slow requests see hardly_slow, for duplicates hardly_duplicates. Example: hardly_stats(session_id='S').
    """
    try:
        conn = sess.require_conn(session_id)
    except KeyError as exc:
        return _err(exc)
    from hardly.core.stats import traffic_stats

    return _ok(
        traffic_stats(conn, host=host, exclude_noise=exclude_noise)
    )


@_tool
def hardly_entry(session_id: str, entry_id: int, body_chars: int = 4000) -> str:
    """Show one entry with redacted headers and truncated bodies (body_chars, default 4000). Use after search/endpoints gives an entry_id; for large bodies use hardly_body_query instead of raising body_chars. Example: hardly_entry(session_id='S', entry_id=12).
    """
    try:
        conn = sess.require_conn(session_id)
    except KeyError as exc:
        return _err(exc)
    return _ok(q.get_entry(conn, entry_id, body_chars=min(body_chars, 20000)))


@_tool
def hardly_forms(
    session_id: str,
    entry_id: int | None = None,
    host: str | None = None,
    side: str = "response",
    exclude_noise: bool = False,
    limit: int = 30,
    offset: int = 0,
) -> str:
    """Extract HTML forms, inputs, links and handlers with signals (hidden fields, tokens). Use to reverse server-rendered pages instead of dumping HTML; entry_id gives the full inventory of one response, omit it to scan the session. For JS-first UIs see hardly_ui. Example: hardly_forms(session_id='S', entry_id=5).
    """
    try:
        conn = sess.require_conn(session_id)
    except KeyError as exc:
        return _err(exc)
    if entry_id is not None:
        return _ok(q.forms_for_entry(conn, entry_id, side=side or "response"))
    return _ok(
        q.list_forms(
            conn,
            host=host,
            side=side or "response",
            exclude_noise=exclude_noise,
            limit=min(limit, 100),
            offset=offset,
        )
    )


@_tool
def hardly_ui(
    session_id: str,
    entry_id: int | None = None,
    host: str | None = None,
    side: str = "response",
    exclude_noise: bool = False,
    limit: int = 30,
    offset: int = 0,
) -> str:
    """Inventory UI surfaces (links, onclick/onsubmit handlers, forms) for link/handler-first workflows. Same scan as hardly_forms; handler_functions names feed hardly_routes. Example: hardly_ui(session_id='S', host='app.example.com').
    """
    try:
        conn = sess.require_conn(session_id)
    except KeyError as exc:
        return _err(exc)
    if entry_id is not None:
        return _ok(q.ui_for_entry(conn, entry_id, side=side or "response"))
    return _ok(
        q.list_forms(
            conn,
            host=host,
            side=side or "response",
            exclude_noise=exclude_noise,
            limit=min(limit, 100),
            offset=offset,
        )
    )


@_tool
def hardly_routes(
    session_id: str,
    host: str | None = None,
    limit: int = 40,
    offset: int = 0,
) -> str:
    """Mine URL path literals from JavaScript bodies to reveal detail/API URLs the UI hard-codes. Use when search works but the detail URL is unknown; then hardly_around on the click entry. Example: hardly_routes(session_id='S').
    """
    try:
        conn = sess.require_conn(session_id)
    except KeyError as exc:
        return _err(exc)
    return _ok(
        q.list_js_routes(
            conn,
            host=host,
            limit=min(limit, 100),
            offset=offset,
        )
    )


@_tool
def hardly_around(
    session_id: str,
    entry_id: int,
    before: int = 5,
    after: int = 15,
    exclude_noise: bool = True,
    host: str | None = None,
) -> str:
    """Show chronological neighbours of one entry (a click and the XHRs that followed). Use with a navigation or grid-click entry_id to find the search/detail API it triggered; inspect rows with positive delta_ms. Example: hardly_around(session_id='S', entry_id=30, after=8).
    """
    try:
        conn = sess.require_conn(session_id)
    except KeyError as exc:
        return _err(exc)
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
def hardly_compare_entries(session_id: str, entry_id_a: int, entry_id_b: int) -> str:
    """Diff headers and JSON body keys between two entries. Use to see what changed between a failing and a working request, or pre/post login. Example: hardly_compare_entries(session_id='S', entry_id_a=3, entry_id_b=9).
    """
    try:
        conn = sess.require_conn(session_id)
    except KeyError as exc:
        return _err(exc)
    return _ok(q.compare_entries(conn, entry_id_a, entry_id_b))


@_tool
def hardly_auth(session_id: str, host: str | None = None) -> str:
    """Detect auth-related paths, token responses and auth header names for a host. Quick auth check; for a full login/credential map use hardly_credentials, for named patterns (OIDC, CSRF) hardly_auth_patterns. Example: hardly_auth(session_id='S', host='api.example.com').
    """
    try:
        conn = sess.require_conn(session_id)
    except KeyError as exc:
        return _err(exc)
    return _ok(detect_auth(conn, host=host))


@_tool
def hardly_flow(
    session_id: str,
    host: str | None = None,
    path_prefix: str | None = None,
    exclude_options: bool = True,
    exclude_noise: bool = True,
    limit: int = 100,
    offset: int = 0,
) -> str:
    """Chronological request flow for a host, optionally from a path_prefix. Raw timeline for login/MFA sequences; hardly_story is the condensed version for portals. Paged by limit/offset. Example: hardly_flow(session_id='S', path_prefix='/login').
    """
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


@_tool
def hardly_brief(
    session_id: str,
    host: str | None = None,
) -> str:
    """One-shot portal brief: story, forms, routes, correlations and issues in a compact result. Run this first on a freshly opened or discovered session of a server-rendered site, then drill down with the tools it names. Example: hardly_brief(session_id='S').
    """
    try:
        conn = sess.require_conn(session_id)
    except KeyError as exc:
        return _err(exc)
    from hardly.core.brief import portal_brief

    return _ok(
        portal_brief(
            conn,
            har_path=sess.get_har_path(session_id),
            host=host,
        )
    )


@_tool
def hardly_report(
    session_id: str,
    sections_json: str | None = None,
    detail: str = "summary",
    explain: bool = False,
    output_path: str | None = None,
) -> str:
    """One-pass evidence index (access, auth, stack, data, forms): findings with severity info|notice|blocker and the drill-down tool for each. Start here for any unfamiliar capture; detail='summary' is ~1 KB. Never returns secret values. Example: hardly_report(session_id='S', detail='summary').

    Runs the existing detectors once and returns findings {section, kind,
    severity info|notice|blocker, label, entry_ids, names/shapes only, lookup}.
    detail: summary (~1 KB: counts per section + blockers) | standard (capped
    findings) | full (more findings + the drill-down tool per finding).
    `sections_json` is an optional JSON list restricting the sections. Never
    returns secret values. explain=true adds canned prose (implications / next
    steps). `output_path` writes Markdown (or JSON for a .json path; a
    directory gets <har>.report.md) and returns the written path.
    """
    try:
        conn = sess.require_conn(session_id)
    except KeyError as exc:
        return _err(exc)
    sections = None
    if sections_json:
        try:
            sections = [str(s) for s in json.loads(sections_json)]
        except (json.JSONDecodeError, TypeError) as exc:
            return _err(exc)
    from hardly.core.report import build_report, write_report

    har_path = sess.get_har_path(session_id)
    try:
        rep = build_report(conn, har_path, sections=sections, detail=detail, explain=explain)
        if output_path:
            rep["output_path"] = str(write_report(rep, resolve_path(output_path), har_path=har_path))
    except (ValueError, OSError) as exc:
        return _err(exc)
    return _ok(rep)


@_tool
def hardly_story(
    session_id: str,
    host: str | None = None,
    limit: int = 40,
    exclude_noise: bool = True,
    include_related: bool = True,
) -> str:
    """Stitch a session into annotated steps (role, forms, labels, fields), collapsing duplicates. Prefer this over raw hardly_flow when reversing portals or building a client; it is the input to hardly_stub. Example: hardly_story(session_id='S', host='app.example.com').
    """
    try:
        conn = sess.require_conn(session_id)
    except KeyError as exc:
        return _err(exc)
    from hardly.core.story import portal_story

    return _ok(
        portal_story(
            conn,
            host=host,
            limit=min(limit, 80),
            exclude_noise=exclude_noise,
            include_related=include_related,
        )
    )


@_tool
def hardly_stub(
    session_id: str,
    entry_ids: list[int] | None = None,
    host: str | None = None,
    output_path: str = "",
    class_name: str = "PortalClient",
) -> str:
    """Generate a minimal Python (urllib) client sketch from story steps or chosen entry_ids. Use as the last step of SDK work, after hardly_story/brief; secrets become PLACEHOLDER_* values. Pass output_path to write a .py file (code is then omitted from the reply). Example: hardly_stub(session_id='S', output_path='/tmp/client.py').
    """
    try:
        conn = sess.require_conn(session_id)
    except KeyError as exc:
        return _err(exc)
    from hardly.core.stub import client_stub

    return _ok(
        client_stub(
            conn,
            entry_ids=entry_ids,
            host=host,
            output_path=output_path or None,
            class_name=class_name or "PortalClient",
        )
    )


@_tool
def hardly_correlate(
    session_id: str,
    host: str | None = None,
    limit: int = 40,
) -> str:
    """Find dynamic values (CSRF, ViewState, session cookies, JSON tokens) reused from earlier responses in later requests. Use to learn which values a client must carry; never returns raw values, only entry ids, name hints and shape. Example: hardly_correlate(session_id='S').
    """
    try:
        conn = sess.require_conn(session_id)
    except KeyError as exc:
        return _err(exc)
    from hardly.core.correlate import correlate_tokens

    return _ok(
        correlate_tokens(
            conn,
            har_path=sess.get_har_path(session_id),
            host=host,
            limit=min(limit, 80),
        )
    )


@_tool
def hardly_cookies(
    session_id: str,
    host: str | None = None,
    limit: int = 60,
) -> str:
    """Cookie name timeline (Set-Cookie / Cookie) per host. Values are never returned. Use to see when a session cookie is set or rotated; for flags and login mapping use hardly_credentials. Example: hardly_cookies(session_id='S').
    """
    try:
        conn = sess.require_conn(session_id)
    except KeyError as exc:
        return _err(exc)
    from hardly.core.cookies import cookie_timeline

    return _ok(
        cookie_timeline(
            conn,
            har_path=sess.get_har_path(session_id),
            host=host,
            limit=min(limit, 120),
        )
    )


@_tool
def hardly_diff(
    session_id_a: str,
    session_id_b: str,
    host: str | None = None,
    exclude_noise: bool = True,
    credentials: bool = True,
) -> str:
    """Compare endpoint templates (and credential maps) between two sessions. Use to see what changed between captures, e.g. logged out vs in, or before and after a site change. Example: hardly_diff(session_id_a='A', session_id_b='B').
    """
    try:
        conn_a = sess.require_conn(session_id_a)
        conn_b = sess.require_conn(session_id_b)
    except KeyError as exc:
        return _err(exc)
    from hardly.core.diff import diff_sessions

    return _ok(
        diff_sessions(
            conn_a,
            conn_b,
            host=host,
            exclude_noise=exclude_noise,
            credentials=credentials,
            har_path_a=sess.get_har_path(session_id_a),
            har_path_b=sess.get_har_path(session_id_b),
        )
    )


@_tool
def hardly_recipe_plan(
    session_id: str,
    host: str | None = None,
    output_path: str = "",
    limit: int = 30,
) -> str:
    """Suggest a capture recipe (goto/fill/click steps) from a session's story. Heuristic: refine selectors with hardly_capture_elements before running via hardly_capture_recipe. Pass output_path to write the steps JSON. Example: hardly_recipe_plan(session_id='S').
    """
    try:
        conn = sess.require_conn(session_id)
    except KeyError as exc:
        return _err(exc)
    from hardly.core.recipe_plan import recipe_from_story

    return _ok(
        recipe_from_story(
            conn,
            host=host,
            output_path=output_path or None,
            limit=min(limit, 60),
        )
    )


@_tool
def hardly_challenges(
    session_id: str,
    host: str | None = None,
    limit: int = 20,
    explain: bool = False,
) -> str:
    """Detect HTTP auth challenges, throttling/lockout signals and captcha widgets in a capture. Use when requests fail with 401/403/429 to learn why; for bot-protection products use hardly_wall, for a policy action use hardly_gates. Example: hardly_challenges(session_id='S').

    WWW-Authenticate / Proxy-Authenticate schemes (Basic, Bearer, Digest,
    Negotiate…) with safe parameters and whether the request was retried with
    credentials; 429/423/Retry-After/X-RateLimit-* and lockout wording; and
    captcha widget markup (reCAPTCHA, hCaptcha, Turnstile, Arkose…). Challenge
    nonces are never returned.
    """
    try:
        conn = sess.require_conn(session_id)
    except KeyError as exc:
        return _err(exc)
    from hardly.core.challenges import detect_challenges

    return _ok(detect_challenges(conn, host=host, limit=min(limit, 50), explain=explain))


@_tool
def hardly_data_attrs(
    session_id: str,
    host: str | None = None,
    entry_id: int | None = None,
    limit: int = 20,
    explain: bool = False,
) -> str:
    """Interpret HTML data-* attributes: dataset keys, value kinds, embedded endpoint URLs and JSON config, framework hints. Use on JS-heavy pages to find where the page gets its data. Example: hardly_data_attrs(session_id='S', entry_id=5).

    Per attribute: dataset key (data-foo-bar -> fooBar), counts, tags, value
    kinds (id/uuid/url/json/boolean/...), enum-like values, plus endpoint URLs
    and embedded JSON config the page hands to scripts, and framework hints
    (Bootstrap, Stimulus, Rails UJS, htmx, test hooks, tracking). Free text is
    never echoed.
    """
    try:
        conn = sess.require_conn(session_id)
    except KeyError as exc:
        return _err(exc)
    from hardly.core.data_attrs import scan_session

    return _ok(scan_session(conn, host=host, entry_id=entry_id, limit=min(limit, 60), explain=explain))


@_tool
def hardly_arcgis(session_id: str, host: str | None = None) -> str:
    """List ArcGIS REST endpoints (MapServer/FeatureServer/etc.) seen in a session: layer ids, parameter names, paging evidence. Offline and names-only; for live exploration use hardly_arcgis_explore. Example: hardly_arcgis(session_id='S').
    """
    try:
        conn = sess.require_conn(session_id)
    except KeyError as exc:
        return _err(exc)
    from hardly.core.arcgis import summarize_session

    return _ok(summarize_session(conn, host=host))


@_tool
def hardly_arcgis_explore(url: str, confirm: bool = False) -> str:
    """LIVE: politely explore an ArcGIS REST service or layer URL (GET only, at most 7 requests). Confirm-gated: requires confirm=true, so show the person the URL first; without it nothing is sent. For captured traffic use hardly_arcgis. Example: hardly_arcgis_explore(url='https://host/arcgis/rest/services/X/MapServer', confirm=true).

    Returns layers, fields (personal-data-like and id fields FLAGGED), query templates and a one-row sample as field names + masked shapes, never values. Stops on 429 and on token-required (498/499); never guesses tokens.
    """
    from hardly.core.arcgis import explore

    return _ok(explore(url, confirm=confirm))


@_tool
def hardly_redirect_diag(url: str, confirm: bool = False, max_hops: int = 12) -> str:
    """LIVE: explain a redirect loop (ERR_TOO_MANY_REDIRECTS) by following the chain by hand with and without cookies. Confirm-gated: requires confirm=true; without it nothing is sent. Reports statuses, redacted URLs and cookie names only. Example: hardly_redirect_diag(url='https://example.com', confirm=true).

    Reports the loop shape: www<->apex or http<->https flips, trailing-slash fights, growing return URLs, cookie-dependent redirects, and whether the alternate host resolves.
    """
    if not confirm:
        return _ok({"error": "redirect_diag requires confirm=true (performs live GET requests)"})
    from hardly.core.redirect_diag import diagnose_redirects

    try:
        return _ok(diagnose_redirects(url, max_hops=max(2, min(max_hops, 20))))
    except Exception as exc:  # noqa: BLE001
        return _err(exc)


@_tool
def hardly_crawl(
    start_url: str,
    keywords_json: str | None = None,
    confirm: bool = False,
    max_pages: int = 12,
    depth: int = 2,
    delay_s: float = 1.0,
    follow_external: bool = False,
    respect_robots: bool = True,
    timeout_s: float = 15.0,
    user_agent: str | None = None,
    explain: bool = False,
) -> str:
    """LIVE: curl-first, robots-aware, polite crawl that finds candidate pages (search forms first). Confirm-gated: requires confirm=true; without it nothing is sent. Use when headless Chromium is blocked or static HTML suffices; it stops at gates and never evades them. Example: hardly_crawl(start_url='https://example.com', keywords_json='["search"]', confirm=true).

    Follows only links found in fetched HTML (never guesses hosts or paths), ranks them with keywords_json (JSON list of nouns), honours robots.txt, waits delay_s between requests per host, strips session ids, and stops at gates and on 429/Retry-After. Caps: max_pages <= 40, depth <= 4. External registrable domains are only recorded unless follow_external=true (one hop). Returns candidates, per-page form field NAMES, gate classes and needs_browser pages (with `next` advice when explain=true); no bodies, URLs redacted. For needs_browser pages use hardly_capture_recipe or `capture discover` with a find_click step.
    """
    if not confirm:
        return _ok(
            {
                "error": "crawl requires confirm=true (performs live GET requests)",
                "hint": "Pass confirm=true; keep max_pages/depth small and respect robots.",
            }
        )
    keywords: list[str] = []
    if keywords_json:
        try:
            keywords = [str(k) for k in json.loads(keywords_json)]
        except (json.JSONDecodeError, TypeError) as exc:
            return _err(exc)
    from hardly.core.crawl import crawl

    try:
        return _ok(
            crawl(
                start_url,
                tuple(keywords),
                max_pages=max_pages,
                depth=depth,
                delay_s=delay_s,
                follow_external=follow_external,
                respect_robots=respect_robots,
                timeout_s=timeout_s,
                user_agent=user_agent,
                explain=explain,
            )
        )
    except Exception as exc:  # noqa: BLE001
        return _err(exc)



@_tool
def hardly_catalog_list(
    path: str,
    tag: str | None = None,
    group_json: str | None = None,
    role: str | None = None,
    status: str | None = None,
    target_id: str | None = None,
    summary: bool = False,
) -> str:
    """List targets from a content-neutral catalog file (JSON/YAML), filtered; no network. Use summary=true for counts instead of rows. Tags and roles are defined by your project (docs/catalog.md). Example: hardly_catalog_list(path='/data/targets.json', summary=true).

    One row per endpoint: target, tags, groups, role, kind, status, redacted url, gate
    classes, stack names. Filters: `tag` (comma-separated, all required), `group_json`
    (JSON object of key->value), `role`, `status`, `target_id`. summary=true returns
    counts by tag/group/role/status/gate class/stack instead. hardly assigns no meaning
    to tags, group keys or roles - a downstream project defines them (docs/catalog.md).
    """
    from hardly.core import catalog as C

    try:
        group = json.loads(group_json) if group_json else None
        if group is not None and not isinstance(group, dict):
            raise ValueError("group_json must be a JSON object")
        cat = C.load(path)
        if summary:
            return _ok(cat.summary())
        rows = cat.table(
            tag=[t for t in (tag or "").split(",") if t.strip()] or None,
            group=group, role=role, status=status, target_id=target_id,
        )
        return _ok({"count": len(rows), "rows": rows})
    except (C.CatalogError, ValueError) as exc:
        return _err(exc)


@_tool
def hardly_catalog_upsert(path: str, target_json: str, merge: bool = True, create: bool = False) -> str:
    """Add or update one target in a catalog file (atomic write, no network). Use to record what you learned about an endpoint; URLs are redacted and validated. Example: hardly_catalog_upsert(path='/data/targets.json', target_json='{"id":"t1","endpoints":[{"role":"api","url":"https://example.com/api"}]}', create=true).

    `target_json` is {id, name, tags[], groups{}, endpoints:[{role, url, kind?, status?,
    gate_classes?, stack?, notes?, capture?:{recipe_ref, har_ref}}]}. URLs are redacted
    (session ids / secret query values stripped) and validated (http(s), known kind and
    status enums). merge=true unions tags, overlays groups and merges endpoints by
    (role, url); merge=false replaces the target. create=true makes the file if missing.
    """
    from pathlib import Path

    from hardly.core import catalog as C

    try:
        data = json.loads(target_json)
        if not Path(path).exists() and create:
            cat = C.Catalog()
        else:
            cat = C.load(path)
        t = cat.upsert(data, merge=merge)
        C.save(cat, path)
        return _ok({"saved": t.to_dict(), "targets": len(cat.targets)})
    except (C.CatalogError, ValueError) as exc:
        return _err(exc)


@_tool
def hardly_catalog_verify(
    path: str,
    confirm: bool = False,
    tag: str | None = None,
    group_json: str | None = None,
    role: str | None = None,
    status: str | None = None,
    target_id: str | None = None,
    delay_s: float = 1.0,
    max_requests: int = 50,
    max_endpoints: int | None = None,
    recheck_after_s: float | None = None,
    force: bool = False,
) -> str:
    """LIVE: politely verify catalog endpoints and write statuses back (verified|blocked|dead|needs_browser). Confirm-gated: without confirm=true it returns only the plan (endpoints and hosts) and sends nothing. Stops a host on any gate per docs/gate-policy.md; never evades. Example: hardly_catalog_verify(path='/data/targets.json', confirm=true, max_requests=20).

    Per endpoint it runs one robots-aware, honest-UA crawl fetch and records status, gate classes and stack names, never bodies or tokens. Per-host delay, request budget, resumable (already-checked endpoints are skipped unless force/recheck_after_s).
    """
    from hardly.core import catalog as C

    try:
        group = json.loads(group_json) if group_json else None
        cat = C.load(path)
        runner = C.CatalogRunner(
            cat, path=path, confirm=confirm, delay_s=delay_s, max_requests=max_requests,
            max_endpoints=max_endpoints, recheck_after_s=recheck_after_s, force=force,
        )
        return _ok(
            runner.run(
                tag=[t for t in (tag or "").split(",") if t.strip()] or None,
                group=group, role=role, status=status, target_id=target_id,
            )
        )
    except (C.CatalogError, ValueError) as exc:
        return _err(exc)


@_tool
def hardly_replay_check(
    session_id: str,
    entry_ids: list[int],
    confirm: bool = False,
    overrides_json: str | None = None,
    max_requests: int = 15,
    delay_s: float = 0.5,
    allow_unsafe: bool = False,
    allow_gates: list[str] | None = None,
) -> str:
    """LIVE: find which headers, cookies, params, body fields and prior steps a request truly needs by replaying it with one element removed at a time. Confirm-gated: requires confirm=true; without it nothing is sent. Reports REQUIRED vs OPTIONAL names only, never bodies. Example: hardly_replay_check(session_id='S', entry_ids=[12], confirm=true).

    entry_ids may be an ordered flow (earlier ids are prior steps, the last is the target). Secrets only via overrides_json: {"headers":{},"cookies":{},"query":{},"body":{}}; missing ones are listed under needs_override. GET/HEAD only unless allow_unsafe=true. Hard stop on 429 / Retry-After / gate stop; captcha token fields are never sent. Budget-skipped items appear under not_tested.
    """
    if not confirm:
        return _ok(
            {
                "error": "replay_check requires confirm=true",
                "hint": "Pass confirm=true; supply secrets via overrides_json, never from the HAR.",
            }
        )
    try:
        conn = sess.require_conn(session_id)
    except KeyError as exc:
        return _err(exc)
    overrides = None
    if overrides_json:
        try:
            overrides = json.loads(overrides_json)
        except json.JSONDecodeError as exc:
            return _err(exc)
    from hardly.core.replay_check import replay_check

    return _ok(
        replay_check(
            conn,
            entry_ids,
            overrides=overrides,
            max_requests=max_requests,
            delay_s=delay_s,
            allow_unsafe=allow_unsafe,
            allow_gates=allow_gates,
        )
    )


@_tool
def hardly_auth_patterns(
    session_id: str, host: str | None = None, kinds_json: str | None = None, explain: bool = False
) -> str:
    """Detect generic auth patterns: bearer/refresh login, OIDC/PKCE, SAML POST, double-submit CSRF, signed-request headers. Names, shapes and entry ids only. Use after hardly_auth when you must implement login in a client. Example: hardly_auth_patterns(session_id='S').
    """
    path = sess.get_har_path(session_id)
    if path is None:
        return _err(KeyError(session_id))
    kinds = None
    if kinds_json:
        try:
            kinds = [str(k) for k in json.loads(kinds_json)]
        except (json.JSONDecodeError, TypeError) as exc:
            return _err(exc)
    from hardly.core.auth_patterns import detect_auth_patterns

    return _ok(detect_auth_patterns(path, host=host, kinds=kinds, explain=explain))


@_tool
def hardly_pagination(session_id: str, host: str | None = None, limit: int = 20) -> str:
    """Recognise cursor, next-link and Link-header pagination. Shapes and entry ids only. Use before writing a client loop over results. Example: hardly_pagination(session_id='S', host='api.example.com').
    """
    try:
        conn = sess.require_conn(session_id)
    except KeyError as exc:
        return _err(exc)
    from hardly.core.pagination import detect_pagination

    return _ok(detect_pagination(conn, host=host, limit=min(limit, 60)))


@_tool
def hardly_har_doctor(har_path: str, config_json: str | None = None) -> str:
    """Diagnose a HAR file for problems (truncated/omitted bodies, sanitised cookies, clock skew, noise) before or after opening it. Findings carry a fix_hint such as recapture flags. Example: hardly_har_doctor(har_path='/data/capture.har').

    Knobs in `config_json` (JSON object): checks, exclude, severity_overrides,
    thresholds{max_entry_bytes,truncation_ratio,clock_skew_s,noise_ratio,min_entries},
    strict, fail_on, host, ignore_hosts, ignore_paths, max_findings, fix.
    Findings carry code, severity, count, entry_ids and a fix_hint (e.g. recapture flags).
    """
    from hardly.core.har_doctor import diagnose_har

    try:
        return _ok(diagnose_har(None, har_path, config_json))
    except Exception as exc:  # noqa: BLE001
        return _err(exc)


@_tool
def hardly_har_prune(src: str, dst: str, drop_hosts_json: str | None = None, drop_mime_json: str | None = None, drop_noise: bool = False, overwrite: bool = False) -> str:
    """Write a pruned copy of a HAR (drop hosts, mime globs, known noise); never in place and refuses an existing dst unless overwrite=true. Use to shrink a large capture before sharing. Example: hardly_har_prune(src='/data/a.har', dst='/data/a.small.har', drop_noise=true).
    """
    from hardly.core.har_tools import prune_har

    try:
        return _ok(prune_har(src, dst, json.loads(drop_hosts_json or "[]"), json.loads(drop_mime_json or "[]"), drop_noise, overwrite=overwrite))
    except Exception as exc:  # noqa: BLE001
        return _err(exc)


@_tool
def hardly_har_split(src: str, outdir: str, by: str = "host", overwrite: bool = False) -> str:
    """Split a HAR into one file per host (or page), streaming. Use for huge captures; then hardly_open each part. Example: hardly_har_split(src='/data/a.har', outdir='/data/parts', by='host').
    """
    from hardly.core.har_tools import split_har

    try:
        return _ok(split_har(src, by, outdir, overwrite=overwrite))
    except Exception as exc:  # noqa: BLE001
        return _err(exc)


@_tool
def hardly_har_merge(paths_json: str, dst: str, overwrite: bool = False, dedupe: bool = True) -> str:
    """Merge several HARs (JSON list of paths) into one, prefixing page ids and dropping exact duplicates. Example: hardly_har_merge(paths_json='["/data/a.har","/data/b.har"]', dst='/data/all.har').
    """
    from hardly.core.har_tools import merge_hars

    try:
        return _ok(merge_hars(json.loads(paths_json), dst, overwrite=overwrite, dedupe=dedupe))
    except Exception as exc:  # noqa: BLE001
        return _err(exc)


@_tool
def hardly_har_scrub(src: str, dst: str, overwrite: bool = False) -> str:
    """Write a scrubbed copy of a HAR with secret values, cookies and auth headers replaced by ***REDACTED*** (structure and shapes kept). Use before sharing a capture; never in place. Example: hardly_har_scrub(src='/data/a.har', dst='/data/a.scrubbed.har').
    """
    from hardly.core.har_tools import scrub_har

    try:
        return _ok(scrub_har(src, dst, overwrite=overwrite))
    except Exception as exc:  # noqa: BLE001
        return _err(exc)


@_tool
def hardly_streams(session_id: str, host: str | None = None, kind: str | None = None, exclude_noise: bool = True, limit: int = 40) -> str:
    """Summarise non-JSON stream/binary formats: gRPC(-web), protobuf, MessagePack, CSV/TSV, SSE, WebSocket frames. Shapes only. Use when endpoints show odd content types. Example: hardly_streams(session_id='S').
    """
    try:
        conn = sess.require_conn(session_id)
    except KeyError as exc:
        return _err(exc)
    from hardly.core.streams import summarize_streams

    return _ok(summarize_streams(conn, host=host, kind=kind, exclude_noise=exclude_noise, limit=min(limit, 100)))


@_tool
def hardly_body_query(
    session_id: str,
    entry_id: int,
    side: str = "response",
    jsonpath: str | None = None,
    regex: str | None = None,
    offset: int = 0,
    limit: int = 20,
    max_chars: int = 300,
    context: int = 40,
    ignore_case: bool = False,
) -> str:
    """Search inside one large body without loading it: JSONPath-lite ($.a[*].b, ..key) or regex, paged (pass next_offset while has_more). Use instead of hardly_entry for big payloads; sensitive values come back as shapes. Example: hardly_body_query(session_id='S', entry_id=12, jsonpath='$.items[*].id').
    """
    try:
        conn = sess.require_conn(session_id)
    except KeyError as exc:
        return _err(exc)
    from hardly.core.body_query import BodyQueryError, query_body

    try:
        return _ok(query_body(conn, entry_id, side, jsonpath=jsonpath, regex=regex, offset=offset, limit=min(limit, 100), max_chars=min(max_chars, 2000), context=context, ignore_case=ignore_case))
    except BodyQueryError as exc:
        return _err(exc)


@_tool
def hardly_contract_check(session_id: str, openapi_path: str, host: str | None = None) -> str:
    """Compare a capture with a previously exported OpenAPI file and report drift (new/removed endpoints, status, field, parameter, auth changes). Use to verify a spec or SDK against fresh traffic; removed means not observed. Example: hardly_contract_check(session_id='S', openapi_path='/data/api.yaml').
    """
    try:
        conn = sess.require_conn(session_id)
    except KeyError as exc:
        return _err(exc)
    from hardly.core.contract import check_contract

    try:
        return _ok(check_contract(conn, openapi_path, host=host))
    except Exception as exc:  # noqa: BLE001
        return _err(exc)


@_tool
def hardly_flow_graph(session_id: str, entry_id: int, host: str | None = None, max_depth: int = 8) -> str:
    """Trace what one request depends on: the earlier response behind each header, cookie, hidden field or value. Returns ordered minimal steps plus inputs the caller must supply. Offline; names and ids only. Use before writing a client for a multi-step flow. Example: hardly_flow_graph(session_id='S', entry_id=20).
    """
    try:
        conn = sess.require_conn(session_id)
    except KeyError as exc:
        return _err(exc)
    from hardly.core.flow_graph import flow_graph

    return _ok(flow_graph(conn, entry_id, host=host, max_depth=min(max_depth, 20)))


@_tool
def hardly_flow_replay(
    session_id: str,
    target: int | None = None,
    entry_ids: list[int] | None = None,
    env_json: str | None = None,
    confirm: bool = False,
    delay_s: float = 0.5,
    max_requests: int = 20,
    allow_unsafe: bool = False,
    allow_gates: list[str] | None = None,
) -> str:
    """LIVE: replay an ordered flow and report the first step whose status, content-type or body shape diverges. Confirm-gated: without confirm=true it is a dry run (plan plus missing inputs). Use to verify a client flow works. Example: hardly_flow_replay(session_id='S', target=20, confirm=true).

    Secrets only via env_json {name: value} or HARDLY_INPUT_<NAME> env vars; values are never printed. GET/HEAD only unless allow_unsafe; halts on 429/Retry-After/gates.
    """
    try:
        conn = sess.require_conn(session_id)
        env = json.loads(env_json) if env_json else None
    except (KeyError, json.JSONDecodeError) as exc:
        return _err(exc)
    from hardly.core.flow_replay import replay_flow

    try:
        return _ok(
            replay_flow(conn, entry_ids=entry_ids, target=target, env=env, confirm=confirm, delay_s=delay_s,
                        max_requests=max_requests, allow_unsafe=allow_unsafe, allow_gates=allow_gates)
        )
    except Exception as exc:  # noqa: BLE001
        return _err(exc)


@_tool
def hardly_stack(
    session_id: str,
    host: str | None = None,
    limit: int = 30,
    explain: bool = False,
) -> str:
    """Fingerprint web frameworks, CMS, GIS stacks and UI toolkits from header/cookie names, paths and body previews; explain=true adds SDK implications. For CDN/WAF products use hardly_wall. Example: hardly_stack(session_id='S', explain=true).
    """
    try:
        conn = sess.require_conn(session_id)
    except KeyError as exc:
        return _err(exc)
    from hardly.core.stack import fingerprint

    return _ok(fingerprint(conn, host=host, limit=min(limit, 60), explain=explain))



@_tool
def hardly_tables(
    session_id: str,
    entry_id: int | None = None,
    host: str | None = None,
) -> str:
    """List HTML data tables: headers, row/column counts, column kinds and a masked first row (cell values never returned). Use to understand result grids before scraping or modelling them. Example: hardly_tables(session_id='S', entry_id=14).
    """
    try:
        conn = sess.require_conn(session_id)
    except KeyError as exc:
        return _err(exc)
    from hardly.core.tables import scan_session

    return _ok(scan_session(conn, host=host, entry_id=entry_id))


@_tool
def hardly_gates(session_id: str, host: str | None = None, explain: bool = False) -> str:
    """Classify the gates in a capture (bot wall, captcha, login, rate limit, click-through terms, environment block) with the policy action for each. Call when requests are blocked, before any retry; stop signs are never evaded. Example: hardly_gates(session_id='S', explain=true).

    Classes: environment_blocked (our sandbox/proxy refused - "unknown, re-run
    from another network", never a site wall), bot_wall, captcha,
    proof_of_work, waiting_room, click_through_terms, login, paywall,
    rate_limit. Each gate has evidence names (never values), entry_ids and an
    action: stop | accept_click_through | unknown_rerun. Policy: click-through
    terms may be accepted by an ordinary form post only if they do not forbid
    automation; everything else is a stop sign; never test enforcement or
    retry a challenged URL in a loop.
    """
    try:
        conn = sess.require_conn(session_id)
    except KeyError as exc:
        return _err(exc)
    from hardly.core.gates import classify_gates

    return _ok(classify_gates(conn, host=host, explain=explain))


@_tool
def hardly_grids(
    session_id: str,
    host: str | None = None,
    limit: int = 20,
    explain: bool = False,
) -> str:
    """Detect data-grid frameworks, JSON envelope conventions (OData, JSON:API, HAL, Relay) and paging/sort parameter styles. Names and counts only. Use before modelling list endpoints. Example: hardly_grids(session_id='S').
    """
    try:
        conn = sess.require_conn(session_id)
    except KeyError as exc:
        return _err(exc)
    from hardly.core.grids import detect_grids

    return _ok(detect_grids(conn, host=host, limit=min(limit, 50), explain=explain))


@_tool
def hardly_find_search(
    session_id: str,
    host: str | None = None,
    keywords: list[str] | None = None,
    limit: int = 15,
) -> str:
    """Rank links likely to lead to a search/lookup page and return a ready next_step click for hardly_capture_recipe. Pass keywords for the site's domain vocabulary. Repeat per hop until a form with inputs appears. Example: hardly_find_search(session_id='S', keywords=['search','lookup']).
    """
    try:
        conn = sess.require_conn(session_id)
    except KeyError as exc:
        return _err(exc)
    from hardly.core.search_nav import find_search_entry

    return _ok(
        find_search_entry(conn, host=host, keywords=keywords or [], limit=min(limit, 40))
    )


@_tool
def hardly_redirects(
    session_id: str,
    host: str | None = None,
    limit: int = 30,
    explain: bool = False,
) -> str:
    """List 3xx redirect hops with matched follow-up entry ids. Use to understand login/canonicalisation redirects; for loops on a live URL use hardly_redirect_diag. Example: hardly_redirects(session_id='S').
    """
    try:
        conn = sess.require_conn(session_id)
    except KeyError as exc:
        return _err(exc)
    from hardly.core.redirects import redirect_chains

    return _ok(
        redirect_chains(conn, host=host, limit=min(limit, 80), explain=explain)
    )


@_tool
def hardly_issues(
    session_id: str,
    host: str | None = None,
    limit: int = 40,
) -> str:
    """List capture-quality issues: empty bodies, 4xx/5xx, redirects without Location. Check before trusting other results; for HAR-file problems use hardly_har_doctor. Example: hardly_issues(session_id='S').
    """
    try:
        conn = sess.require_conn(session_id)
    except KeyError as exc:
        return _err(exc)
    from hardly.core.issues import find_issues

    return _ok(find_issues(conn, host=host, limit=min(limit, 60)))


@_tool
def hardly_trace(
    session_id: str,
    name: str = "",
    value: str = "",
    host: str | None = None,
    limit: int = 40,
) -> str:
    """Trace a field name or exact value across a capture: where it first appears and where it is reused. Pass name (e.g. __VIEWSTATE) and/or value; values are never echoed back, only entry ids, location and shape. Example: hardly_trace(session_id='S', name='csrf_token').
    """
    try:
        conn = sess.require_conn(session_id)
    except KeyError as exc:
        return _err(exc)
    from hardly.core.trace import trace_field

    return _ok(
        trace_field(
            conn,
            name=name or None,
            value=value or None,
            har_path=sess.get_har_path(session_id),
            host=host,
            limit=min(limit, 80),
        )
    )


@_tool
def hardly_secrets(
    session_id: str,
    host: str | None = None,
    limit: int = 40,
) -> str:
    """Locate sensitive header/field/query NAMES (password, token, cookie). Never returns values, only entry ids and names. For a login/session map use hardly_credentials. Example: hardly_secrets(session_id='S').
    """
    try:
        conn = sess.require_conn(session_id)
    except KeyError as exc:
        return _err(exc)
    from hardly.core.secrets import locate_secrets

    return _ok(locate_secrets(conn, host=host, limit=min(limit, 60)))


@_tool
def hardly_credentials(
    session_id: str,
    host: str | None = None,
    limit: int = 40,
    explain: bool = False,
) -> str:
    """Map login and credential evidence: password fields, session cookies and flags, CSRF, OAuth params, token shapes, and a hypothesised login_flow. Names and shapes only, never values. Use before implementing login in a client. Example: hardly_credentials(session_id='S').
    """
    try:
        conn = sess.require_conn(session_id)
    except KeyError as exc:
        return _err(exc)
    from hardly.core.credentials import map_credentials

    return _ok(
        map_credentials(
            conn,
            har_path=sess.get_har_path(session_id),
            host=host,
            limit=min(limit, 60),
            explain=explain,
        )
    )


@_tool
def hardly_recommend(goal: str) -> str:
    """Suggest which hardly tools to call next for a short goal string. Use when unsure mid-task; hardly_start is better for planning from scratch. Example: hardly_recommend(goal='find the login csrf token').
    """
    from hardly.core.recommend import recommend_tools

    return _ok(recommend_tools(goal))


@_tool
def hardly_tree(
    session_id: str,
    entry_id: int,
    exclude_noise: bool = True,
    child_limit: int = 40,
) -> str:
    """Show initiator parent and children for an entry (from HAR _initiator/pageref): what triggered a request and what it triggered. Use to find who called an API; for time order use hardly_around. Example: hardly_tree(session_id='S', entry_id=30).
    """
    try:
        conn = sess.require_conn(session_id)
    except KeyError as exc:
        return _err(exc)
    from hardly.core.tree import entry_tree

    return _ok(
        entry_tree(
            conn,
            entry_id,
            exclude_noise=exclude_noise,
            child_limit=min(child_limit, 80),
        )
    )


@_tool
def hardly_params(
    session_id: str,
    method: str,
    host: str,
    path_template: str,
    limit: int = 30,
) -> str:
    """Classify query/body fields as static, dynamic or sensitive across samples of an endpoint. Use to decide which parameters a client must compute versus hard-code. Example: hardly_params(session_id='S', method='GET', path_template='/api/items').
    """
    try:
        conn = sess.require_conn(session_id)
    except KeyError as exc:
        return _err(exc)
    from hardly.core.params import param_variance

    return _ok(
        param_variance(
            conn,
            method=method,
            host=host,
            path_template=path_template,
            limit=min(limit, 80),
        )
    )


@_tool
def hardly_outline(
    session_id: str,
    entry_id: int,
    format: str = "all",
    max_depth: int = 8,
    side: str = "response",
) -> str:
    """Offline outline of an HTML/XML body from a HAR entry: markdown (headings/tables/forms/links), a tag tree and an approximate aria YAML, redacted. Use instead of reading raw HTML; for the live tab use hardly_capture_aria. Example: hardly_outline(session_id='S', entry_id=5, format='markdown').
    """
    try:
        conn = sess.require_conn(session_id)
    except KeyError as exc:
        return _err(exc)
    from hardly.core.outline import outline_entry

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
def hardly_content(
    session_id: str,
    host: str | None = None,
    kind: str | None = None,
    exclude_noise: bool = True,
    limit: int = 80,
) -> str:
    """Classify response payloads (json, csv, html_table, pdf, image, ...) as a histogram with sample entry_ids. Use to learn what kinds of data a host serves; hardly_entry also carries a content object. Example: hardly_content(session_id='S', host='app.example.com').
    """
    try:
        conn = sess.require_conn(session_id)
    except KeyError as exc:
        return _err(exc)
    from hardly.core.classify import summarize_content

    return _ok(
        summarize_content(
            conn,
            host=host,
            kind=kind,
            exclude_noise=exclude_noise,
            limit=min(limit, 400),
        )
    )


@_tool
def hardly_graphql(
    session_id: str,
    host: str | None = None,
    limit: int = 40,
) -> str:
    """Detect GraphQL operations (operationName, query, mutation) in a capture. Use when POSTs share one URL; then hardly_entry for a sample. Example: hardly_graphql(session_id='S').
    """
    try:
        conn = sess.require_conn(session_id)
    except KeyError as exc:
        return _err(exc)
    from hardly.core.graphql import detect_graphql

    return _ok(detect_graphql(conn, host=host, limit=min(limit, 80)))


@_tool
def hardly_duplicates(
    session_id: str,
    host: str | None = None,
    exclude_noise: bool = True,
    min_count: int = 2,
    limit: int = 30,
) -> str:
    """Find repeated method+path_template groups (polling, retries). Use to separate noise from real calls before documenting. Example: hardly_duplicates(session_id='S', min_count=5).
    """
    try:
        conn = sess.require_conn(session_id)
    except KeyError as exc:
        return _err(exc)
    from hardly.core.duplicates import find_duplicates

    return _ok(
        find_duplicates(
            conn,
            host=host,
            exclude_noise=exclude_noise,
            min_count=min_count,
            limit=min(limit, 80),
        )
    )


@_tool
def hardly_slow(
    session_id: str,
    host: str | None = None,
    exclude_noise: bool = True,
    limit: int = 20,
    min_ms: float = 0,
) -> str:
    """List the slowest requests by time_ms. Use for performance questions; for general traffic shape use hardly_stats. Example: hardly_slow(session_id='S', min_ms=1000).
    """
    try:
        conn = sess.require_conn(session_id)
    except KeyError as exc:
        return _err(exc)
    from hardly.core.slow import slowest_entries

    return _ok(
        slowest_entries(
            conn,
            host=host,
            exclude_noise=exclude_noise,
            limit=min(limit, 50),
            min_ms=min_ms,
        )
    )


@_tool
def hardly_wall(
    session_id: str,
    host: str | None = None,
    limit: int = 30,
    explain: bool = False,
) -> str:
    """Report bot-protection products seen and walls actually hit (CDN/WAF and captcha vendors) with a state each. A wall means STOP and re-capture interactively with a person; it is never solved or evaded. Example: hardly_wall(session_id='S', explain=true).

    Identifies Cloudflare, Akamai, Imperva, DataDome, HUMAN/PerimeterX, Kasada,
    F5, AWS WAF, Vercel, Anubis, reCAPTCHA/hCaptcha/Turnstile/Arkose and more,
    with a state per product (blocked / challenged / clearance_seen / present).
    A CDN header on a normal page is informational, not a wall. Never solves or
    evades; a block means re-capture interactively with a person.
    """
    try:
        conn = sess.require_conn(session_id)
    except KeyError as exc:
        return _err(exc)
    from hardly.core.wall import detect_walls

    return _ok(detect_walls(conn, host=host, limit=min(limit, 60), explain=explain))


@_tool
def hardly_pages(
    session_id: str,
    host: str | None = None,
    exclude_noise: bool = True,
    limit: int = 40,
) -> str:
    """List HAR pageref groups (browser page loads) with document hints. Use to split a capture into navigations. Example: hardly_pages(session_id='S').
    """
    try:
        conn = sess.require_conn(session_id)
    except KeyError as exc:
        return _err(exc)
    from hardly.core.pages import list_pages

    return _ok(
        list_pages(
            conn,
            host=host,
            exclude_noise=exclude_noise,
            limit=min(limit, 80),
        )
    )


@_tool
def hardly_schema(
    session_id: str,
    method: str,
    host: str,
    path_template: str,
    limit: int = 20,
) -> str:
    """Infer request/response JSON schemas for one endpoint template. Use after hardly_endpoints to model an API call; names and types only. Example: hardly_schema(session_id='S', method='GET', path_template='/api/items/{id}').
    """
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


@_tool
def hardly_sql(session_id: str, sql: str, limit: int = 100) -> str:
    """Run a read-only SELECT against the session's SQLite index. Escape hatch for questions no named tool answers; try those first. Example: hardly_sql(session_id='S', sql='select host, count(*) from entries group by host').
    """
    try:
        conn = sess.require_conn(session_id)
    except KeyError as exc:
        return _err(exc)
    return _ok(q.run_sql(conn, sql, limit=min(limit, 500)))


@_tool
def hardly_export_md(
    session_id: str,
    output_path: str,
    host: str | None = None,
    exclude_noise: bool = True,
    max_endpoints: int = 200,
) -> str:
    """Write a redacted API.md describing the session's endpoints. Use to produce human documentation; for machine-readable specs use hardly_export_openapi. Example: hardly_export_md(session_id='S', output_path='/tmp/API.md', host='api.example.com').
    """
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


@_tool
def hardly_export_openapi(
    session_id: str,
    output_path: str,
    host: str | None = None,
    exclude_noise: bool = True,
    title: str = "HAR-derived API",
) -> str:
    """Write an OpenAPI 3 document (JSON or YAML by file extension) from observed traffic. Use as the final step of API discovery or as input to hardly_contract_check later. Example: hardly_export_openapi(session_id='S', output_path='/tmp/api.yaml', host='api.example.com').
    """
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


@_tool
def hardly_export_postman(
    session_id: str,
    output_path: str,
    host: str | None = None,
    exclude_noise: bool = True,
    name: str = "HAR-derived API",
) -> str:
    """Write a Postman Collection v2.1 JSON with secrets as {{placeholders}}. Use when the consumer works in Postman. Example: hardly_export_postman(session_id='S', output_path='/tmp/c.json').
    """
    try:
        conn = sess.require_conn(session_id)
    except KeyError as exc:
        return _err(exc)
    from hardly.core.export_postman import export_postman

    return _ok(
        export_postman(
            conn,
            resolve_path(output_path),
            host=host,
            exclude_noise=exclude_noise,
            name=name,
        )
    )


@_tool
def hardly_export_brief(
    session_id: str,
    output_path: str,
    host: str | None = None,
) -> str:
    """Write the portal brief (story, correlate, forms, routes) to a Markdown file. Use to hand findings to a person or another agent. Example: hardly_export_brief(session_id='S', output_path='/tmp/brief.md').
    """
    try:
        conn = sess.require_conn(session_id)
    except KeyError as exc:
        return _err(exc)
    from hardly.core.export_brief import export_brief_md

    return _ok(
        export_brief_md(
            conn,
            resolve_path(output_path),
            har_path=sess.get_har_path(session_id),
            host=host,
        )
    )


@_tool
def hardly_curl(
    session_id: str,
    entry_id: int,
    redact: bool = True,
    use_env_placeholders: bool = True,
) -> str:
    """Generate a curl command for one entry; secrets are redacted by default. Use to show a person a single request; for a full client use hardly_stub. Example: hardly_curl(session_id='S', entry_id=12).
    """
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


@_tool
def hardly_probe(
    session_id: str,
    entry_id: int,
    confirm: bool = False,
    header_overrides_json: str | None = None,
    body_override: str | None = None,
    timeout: float = 30.0,
) -> str:
    """LIVE: replay one captured request. Confirm-gated: requires confirm=true, so tell the person what will be sent first; without it nothing is sent. Sensitive HAR headers are skipped unless given in header_overrides_json (JSON object). For multi-step flows use hardly_flow_replay. Example: hardly_probe(session_id='S', entry_id=12, confirm=true).
    """
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
def analyze_har(har_path: str) -> str:
    """Archive mode: analyze an existing HAR file without Playwright."""
    return (
        f"Mode=archive. Analyze `{har_path}` with hardly tools only "
        "(do not Read the HAR file):\n"
        "1. hardly_open(har_path) -> session_id\n"
        "2. hardly_hosts — use preferred_host for portals\n"
        "3. Portal: hardly_brief -> forms / outline / correlate / trace\n"
        "4. JSON API: hardly_endpoints -> content -> auth -> schema\n"
        "5. Export: hardly_stub / export_brief / export_openapi as needed\n"
        "If you only have a URL (no HAR), switch to headless (hardly_discover) "
        "or interactive (capture_portal)."
    )


@mcp.prompt
def discover_apis(url: str) -> str:
    """Headless mode: agent loads a URL and discovers APIs automatically."""
    return (
        f"Mode=headless. Discover APIs for `{url}` without asking a person:\n"
        "1. hardly_capture_doctor if capture_available is false.\n"
        "2. Prefer hardly_discover(url, channel='chrome', wait_seconds=8) "
        "for a one-shot load (+ optional recipe_json).\n"
        "3. Or loop: hardly_capture_start(url, headed=false) -> "
        "hardly_capture_aria -> click/fill with ref -> "
        "hardly_capture_stop(open_session=true).\n"
        "4. Continue in archive mode: hardly_brief / endpoints / correlate.\n"
        "5. If wall/CAPTCHA/empty bodies: switch to interactive "
        "(hardly_capture_start headed=true channel=chrome) and ASK THE PERSON.\n"
        "Never Read the HAR file into context."
    )


@mcp.prompt
def document_api(host: str) -> str:
    """Guide for documenting an API host from a loaded HAR (archive mode)."""
    return (
        f"Mode=archive. Document the API for host `{host}` using hardly "
        "tools only (do not read the HAR file). Steps:\n"
        "1. hardly_summary / hardly_endpoints(host=...)\n"
        "2. hardly_auth(host=...) and hardly_flow(host=...)\n"
        "3. hardly_entry / hardly_schema for important endpoints\n"
        "4. hardly_export_md to write API.md\n"
        "Keep responses redacted; prefer entry IDs over large bodies."
    )


@mcp.prompt
def find_auth_flow(host: str) -> str:
    """Guide for tracing login/MFA on a host (archive mode)."""
    return (
        f"Mode=archive. Trace authentication for `{host}` with hardly:\n"
        "1. hardly_auth(host=...)\n"
        "2. hardly_flow(host=..., path_prefix=/login or similar)\n"
        "3. hardly_compare_entries on pre/post MFA login requests\n"
        "4. Note tokens in response bodies (Chrome may strip Authorization cookies).\n"
        "If login needs a person/CAPTCHA, use interactive capture_portal first."
    )


@mcp.prompt
def capture_portal(url: str) -> str:
    """Interactive mode: person drives the browser; agent records and analyzes."""
    return (
        f"Mode=interactive. Record `{url}` with a person in the headed browser:\n"
        "1. hardly_capture_doctor if capture_available is false.\n"
        "2. hardly_capture_start(url=..., headed=true, channel='chrome').\n"
        "3. ASK THE PERSON to complete the portal steps "
        "(cookies, search, open detail, login). Do not pretend you can see "
        "their screen — tell them what to do, then wait.\n"
        "4. Optional: hardly_capture_screenshot / _status while they work.\n"
        "5. When they finish: hardly_capture_stop(open_session=true).\n"
        "6. hardly_brief(session_id), then forms/correlate/routes as needed.\n"
        "If the flow is fully scriptable, prefer headless hardly_discover instead.\n"
        "Cursor's IDE browser does not feed HARs into hardly."
    )


@mcp.prompt
def reverse_engineer_api(har_path: str) -> str:
    """Workflow: reverse engineer the API behind an existing HAR file (archive mode)."""
    return (
        f"Reverse engineer the API in `{har_path}` using hardly tools only "
        "(never Read the HAR file; results are redacted and paged):\n"
        "1. hardly_open(har_path) -> session_id\n"
        "2. hardly_report(session_id, detail='summary') -> blockers, auth, stack\n"
        "3. hardly_hosts -> note preferred_host; pass it as host= below\n"
        "4. HTML site: hardly_brief, then hardly_story / hardly_forms. "
        "JSON API: hardly_endpoints, hardly_schema, hardly_pagination\n"
        "5. Auth: hardly_credentials, hardly_correlate, hardly_trace for carried tokens\n"
        "6. Large body: hardly_body_query instead of hardly_entry\n"
        "7. Output: hardly_export_openapi / hardly_export_md to a scratch directory\n"
        "If the report shows a gate (bot wall, captcha, login), stop and see "
        "the diagnose_blocked_capture prompt. Never print secret values."
    )


@mcp.prompt
def build_client_sdk(session_id: str) -> str:
    """Workflow: turn an open session into a small client SDK."""
    return (
        f"Build a client SDK from session `{session_id}` (if it is unknown, "
        "hardly_list_sessions / hardly_reopen):\n"
        "1. hardly_hosts -> preferred_host; hardly_story(host=...) for the steps\n"
        "2. hardly_credentials + hardly_auth_patterns -> how login works\n"
        "3. hardly_correlate + hardly_flow_graph(entry_id=<key request>) -> values "
        "that must be carried and the minimal prior steps\n"
        "4. hardly_schema / hardly_pagination / hardly_params for each endpoint "
        "you will wrap\n"
        "5. hardly_stub(output_path=<scratch>/client.py) for the starter client; "
        "secrets are PLACEHOLDER_* values, supply them via env, never hard-code\n"
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
        "1. If a session exists: hardly_gates(session_id, explain=true), "
        "hardly_wall, hardly_challenges, hardly_issues\n"
        "2. environment_blocked means OUR sandbox/proxy refused: report 'unknown, "
        "re-run from another network', not a site wall\n"
        "3. bot_wall / captcha / proof_of_work / waiting_room / login / paywall / "
        "rate_limit are STOP signs: do not retry in a loop, do not try to solve or "
        "evade. Re-capture interactively: hardly_capture_start(url, headed=true, "
        "channel='chrome'), ask the person to complete the steps, then "
        "hardly_capture_stop(open_session=true)\n"
        "4. Redirect loop on a live URL: hardly_redirect_diag(url, confirm=true) "
        "after telling the person it makes live GETs\n"
        "5. No session at all: hardly_capture_doctor (is the browser installed?)\n"
        "6. Static HTML may suffice: hardly_crawl(start_url, confirm=true) is "
        "polite and stops at gates\n"
        "Docs: resource hardly://docs/gate-policy."
    )


@mcp.prompt
def verify_client(session_id: str, entry_id: int) -> str:
    """Workflow: verify a generated client against the capture and the live site."""
    return (
        f"Verify a client for session `{session_id}`, target entry {entry_id}:\n"
        f"1. hardly_flow_graph(session_id, entry_id={entry_id}) -> ordered steps and "
        "the inputs you must supply\n"
        f"2. hardly_flow_replay(session_id, target={entry_id}, confirm=false) -> "
        "dry run: plan and missing inputs\n"
        "3. Tell the person exactly what will be sent, then repeat with "
        "confirm=true. Supply secrets via env_json / HARDLY_INPUT_<NAME>; never "
        "print them\n"
        f"4. hardly_replay_check(session_id, entry_ids=[{entry_id}], confirm=true) "
        "to learn which headers/cookies/fields are REQUIRED vs OPTIONAL\n"
        "5. After exporting a spec: hardly_contract_check(session_id, openapi_path)\n"
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
    mcp.run()


if __name__ == "__main__":
    main()
