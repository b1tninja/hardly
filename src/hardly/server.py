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
        "HAR analysis tools. Pick a mode with hardly_modes / hardly_mode first: "
        "(1) archive — open an existing HAR file and query it; "
        "(2) headless — hardly_discover or capture_start(headed=false) so the "
        "agent auto-drives the page and discovers APIs; "
        "(3) interactive — capture_start(headed=true, channel=chrome) and ASK "
        "THE PERSON to use the browser, then capture_stop. "
        "Never read the raw HAR into context. After open/discover/stop, use "
        "session_id with brief/endpoints/forms/correlate/…. "
        "hardly_help / hardly_recommend if unsure. After MCP restart, "
        "hardly_reopen or any tool auto-reattaches a cached session_id."
    ),
)


@mcp.tool
def hardly_capabilities() -> str:
    """Version, feature flags, and tool names — use to detect a stale MCP server."""
    from hardly.capabilities import capabilities

    return _ok(capabilities())


@mcp.tool
def hardly_modes() -> str:
    """List the three operating modes: archive, headless, interactive."""
    from hardly.core.modes import list_modes

    return _ok(list_modes())


@mcp.tool
def hardly_mode(
    mode: str = "",
    goal: str = "",
    har_path: str = "",
    url: str = "",
) -> str:
    """Playbook for one mode, or auto-pick from goal / har_path / url.

    Modes: archive (existing HAR file), headless (agent discovers APIs),
    interactive (ask the person to drive the headed browser). Pass mode= to
    force one; otherwise heuristics pick from the other args.
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


@mcp.tool
def hardly_help(topic: str = "") -> str:
    """Categorized tool catalog and workflows. Pass topic e.g. portal, tokens, capture, modes."""
    from hardly.core.help import tool_help

    return _ok(tool_help(topic or None))


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
    """Spawn Chromium with Playwright HAR recording.

    Modes: headed=true (default) = interactive — ASK THE PERSON to use the
    window, then hardly_capture_stop. headed=false = headless — agent drives
    with hardly_capture_aria / click / recipe (or use hardly_discover).
    Requires ``pip install -e ".[capture]"`` + ``playwright install chromium``.
    Prefer channel=\"chrome\" for Akamai/bot walls. url_filter is a Playwright
    glob. profile keeps cookies. same_tab (default true) forces target=_blank
    into the current tab. trace=true writes a ``.trace.zip`` beside the HAR.
    Waits for a capture slot (HARDLY_CAPTURE_SLOTS); the worker holds it until
    the capture stops. The result carries ``slot``.
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


@mcp.tool
def hardly_capture_stop(
    capture_id: str = "",
    open_session: bool = True,
    force: bool = False,
) -> str:
    """Stop a capture, flush the HAR, optionally hardly_open it.

    Omit capture_id to stop the latest running capture.
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


@mcp.tool
def hardly_capture_goto(url: str, capture_id: str = "") -> str:
    """Navigate the running capture's tab (latest if capture_id omitted)."""
    try:
        from hardly.capture import CaptureError, navigate_capture
    except ImportError as exc:
        return _err(exc)
    try:
        return _ok(navigate_capture(capture_id or None, url))
    except CaptureError as exc:
        return _err(exc)


@mcp.tool
def hardly_capture_elements(
    capture_id: str = "",
    limit: int = 40,
    query: str = "",
) -> str:
    """List visible interactive elements on the live capture tab.

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


@mcp.tool
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
    """Click a visible element on the live capture tab.

    Prefer ``ref`` from ``hardly_capture_aria`` (e.g. ``e12`` / ``[ref=e12]``).
    Else xpath/css from hardly_capture_elements, or text= / role=+name=.
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


@mcp.tool
def hardly_capture_fill(
    capture_id: str = "",
    value: str = "",
    ref: str = "",
    xpath: str = "",
    css: str = "",
    timeout_ms: int = 10000,
) -> str:
    """Fill an input/textarea on the live capture tab.

    Prefer ``ref`` from ``hardly_capture_aria``; else xpath or css.
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


@mcp.tool
def hardly_capture_press(
    capture_id: str = "",
    key: str = "Enter",
    ref: str = "",
    xpath: str = "",
    css: str = "",
    timeout_ms: int = 10000,
) -> str:
    """Press a key on the live tab (optionally on a ref/xpath/css locator)."""
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


@mcp.tool
def hardly_capture_url(capture_id: str = "") -> str:
    """Return the live capture tab's current URL and title."""
    try:
        from hardly.capture import CaptureError, capture_page_url
    except ImportError as exc:
        return _err(exc)
    try:
        return _ok(capture_page_url(capture_id or None))
    except CaptureError as exc:
        return _err(exc)


@mcp.tool
def hardly_capture_aria(
    capture_id: str = "",
    selector: str = "",
    mode: str = "ai",
) -> str:
    """Live Playwright accessibility snapshot (YAML) for the capture tab.

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


@mcp.tool
def hardly_capture_doctor() -> str:
    """Diagnose the optional Playwright install (package vs browser binaries).

    Call when capture_available is false or capture_start fails. Returns
    version, which browsers are on disk, feature flags (aria_snapshot /
    aria_mode_ai), and the exact install commands to run.
    """
    try:
        from hardly.capture import playwright_status
    except ImportError as exc:
        return _err(exc)
    return _ok(playwright_status())


@mcp.tool
def hardly_capture_screenshot(
    capture_id: str = "",
    path: str = "",
    full_page: bool = False,
) -> str:
    """PNG screenshot of the live capture tab (path optional → cache dir)."""
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


@mcp.tool
def hardly_capture_recipe(
    steps: list[dict],
    capture_id: str = "",
    stop_on_error: bool = True,
) -> str:
    """Run a scripted sequence on the live capture tab.

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


@mcp.tool
def hardly_capture_list() -> str:
    """List browser capture sessions (in-process and persisted sidecars)."""
    try:
        from hardly.capture import list_captures
    except ImportError as exc:
        return _err(exc)
    return _ok({"captures": list_captures()})


@mcp.tool
def hardly_capture_status(capture_id: str = "") -> str:
    """Status for one capture_id, or the latest running capture if omitted."""
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


@mcp.tool
def hardly_capture_once(
    url: str,
    wait_seconds: float = 20,
    har_path: str = "",
    headed: bool = False,
    channel: str = "",
    url_filter: str = "",
    open_session: bool = True,
) -> str:
    """Timed capture: open URL, wait, stop. Prefer hardly_discover for headless API discovery."""
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


@mcp.tool
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
    """Headless mode: load URL, optional recipe, stop, open session, brief.

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


@mcp.tool
def hardly_list_sessions() -> str:
    """List cached and currently open HAR sessions."""
    return _ok({"sessions": sess.list_sessions()})


@mcp.tool
def hardly_close(session_id: str) -> str:
    """Close an open session (cache file is kept on disk)."""
    return _ok(sess.close_session(session_id))


@mcp.tool
def hardly_reopen(session_id: str, force: bool = False) -> str:
    """Reattach a cached session after MCP restart (no HAR path needed).

    Other tools also auto-reopen on require_conn; call this explicitly when
    list_sessions shows open=false but you still have the session_id.
    """
    return _ok(sess.reopen_session(session_id, force=force))


@mcp.tool
def hardly_summary(session_id: str) -> str:
    """Host, method, and status histograms for a session."""
    try:
        conn = sess.require_conn(session_id)
    except KeyError as exc:
        return _err(exc)
    return _ok(q.summary(conn))


@mcp.tool
def hardly_coverage(
    session_id: str,
    host: str | None = None,
    exclude_noise: bool = True,
    limit: int = 20,
) -> str:
    """Body-preview coverage: how many entries have usable text vs empty/truncated.

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


@mcp.tool
def hardly_hosts(session_id: str, exclude_noise: bool = False) -> str:
    """List hosts with request counts."""
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
    header_name: str | None = None,
    header_contains: str | None = None,
    mime_contains: str | None = None,
    content_kind: str | None = None,
    exclude_noise: bool = True,
    exclude_options: bool = True,
    limit: int = 50,
    offset: int = 0,
) -> str:
    """Search entries by host, path, method, status, body, header, mime, or content_kind.

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


@mcp.tool
def hardly_stats(
    session_id: str,
    host: str | None = None,
    exclude_noise: bool = True,
) -> str:
    """MIME mix, status classes, body sizes, initiator types, timing."""
    try:
        conn = sess.require_conn(session_id)
    except KeyError as exc:
        return _err(exc)
    from hardly.core.stats import traffic_stats

    return _ok(
        traffic_stats(conn, host=host, exclude_noise=exclude_noise)
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
def hardly_forms(
    session_id: str,
    entry_id: int | None = None,
    host: str | None = None,
    side: str = "response",
    exclude_noise: bool = False,
    limit: int = 30,
    offset: int = 0,
) -> str:
    """Extract HTML forms, inputs, links, onclick/onsubmit handlers, and signals.

    Omit entry_id to scan the session. Pass entry_id for the full inventory
    on one response (values redacted / truncated). Prefer this over dumping
    HTML bodies when reversing guest portals.
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


@mcp.tool
def hardly_ui(
    session_id: str,
    entry_id: int | None = None,
    host: str | None = None,
    side: str = "response",
    exclude_noise: bool = False,
    limit: int = 30,
    offset: int = 0,
) -> str:
    """Inventory UI surfaces: links, onclick/onsubmit handlers, forms.

    Same scan as hardly_forms, named for link/handler-first workflows.
    ``handler_functions`` lists JS names to cross-check with hardly_routes.
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


@mcp.tool
def hardly_routes(
    session_id: str,
    host: str | None = None,
    limit: int = 40,
    offset: int = 0,
) -> str:
    """Mine URL path literals from JavaScript bodies (often reveals detail APIs).

    Prefer this when search works but the document-detail URL is unknown —
    app JS usually hard-codes paths like ``/Details/`` or ``/documentdetails/``.
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


@mcp.tool
def hardly_around(
    session_id: str,
    entry_id: int,
    before: int = 5,
    after: int = 15,
    exclude_noise: bool = True,
    host: str | None = None,
) -> str:
    """Chronological neighbors of one entry (click → following XHRs).

    Pass the entry_id of a navigation or grid click candidate; inspect
    positive ``delta_ms`` rows for the detail/search API that followed.
    Defaults to the same host as the center entry.
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
def hardly_brief(
    session_id: str,
    host: str | None = None,
) -> str:
    """One-shot portal RE brief: story + forms + routes + correlate + issues.

    Prefer this first on guest portals, then drill with the named tools.
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


@mcp.tool
def hardly_story(
    session_id: str,
    host: str | None = None,
    limit: int = 40,
    exclude_noise: bool = True,
    include_related: bool = True,
) -> str:
    """Stitch a portal session into annotated steps (role, forms, labels, fields).

    Prefer this over raw hardly_flow when reversing guest portals — collapses
    duplicates and attaches request field names / HTML form hints / labels.
    Same-apex API hosts are merged by default (SPA app.* + api.*).
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


@mcp.tool
def hardly_stub(
    session_id: str,
    entry_ids: list[int] | None = None,
    host: str | None = None,
    output_path: str = "",
    class_name: str = "PortalClient",
) -> str:
    """Generate a minimal urllib client sketch from story steps or entry_ids.

    Secrets become PLACEHOLDER_*. Pass output_path to write a .py file (code
    omitted from the tool response when written).
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


@mcp.tool
def hardly_correlate(
    session_id: str,
    host: str | None = None,
    limit: int = 40,
) -> str:
    """Find dynamic values reused from earlier responses into later requests.

    CSRF / ViewState / session cookies / JSON tokens. Never returns raw values
    — only entry ids, name hints, and value shape. Prefers the on-disk HAR.
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


@mcp.tool
def hardly_cookies(
    session_id: str,
    host: str | None = None,
    limit: int = 60,
) -> str:
    """Cookie name timeline (Set-Cookie / Cookie). Values are never returned."""
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


@mcp.tool
def hardly_diff(
    session_id_a: str,
    session_id_b: str,
    host: str | None = None,
    exclude_noise: bool = True,
    credentials: bool = True,
) -> str:
    """Compare endpoint templates (and credential maps) between two sessions."""
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


@mcp.tool
def hardly_recipe_plan(
    session_id: str,
    host: str | None = None,
    output_path: str = "",
    limit: int = 30,
) -> str:
    """Suggest a capture recipe (goto/fill/click) from hardly_story.

    Heuristic — refine selectors with hardly_capture_elements before running
    via hardly_capture_recipe. Pass output_path to write steps JSON to disk.
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


@mcp.tool
def hardly_challenges(
    session_id: str,
    host: str | None = None,
    limit: int = 20,
) -> str:
    """Detect HTTP auth challenges, throttling/lockout signals, captcha widgets.

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

    return _ok(detect_challenges(conn, host=host, limit=min(limit, 50)))


@mcp.tool
def hardly_data_attrs(
    session_id: str,
    host: str | None = None,
    entry_id: int | None = None,
    limit: int = 20,
) -> str:
    """Interpret HTML data-* attributes (MDN dataset model).

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

    return _ok(scan_session(conn, host=host, entry_id=entry_id, limit=min(limit, 60)))


@mcp.tool
def hardly_arcgis(session_id: str, host: str | None = None) -> str:
    """List ArcGIS REST endpoints (MapServer/FeatureServer/ImageServer/GeocodeServer) seen in the session.

    Service roots, layer ids, which layers were queried, parameter NAMES used,
    paging evidence and whether exceededTransferLimit was seen. Names only; offline.
    """
    try:
        conn = sess.require_conn(session_id)
    except KeyError as exc:
        return _err(exc)
    from hardly.core.arcgis import summarize_session

    return _ok(summarize_session(conn, host=host))


@mcp.tool
def hardly_arcgis_explore(url: str, confirm: bool = False) -> str:
    """Live, polite exploration of an ArcGIS REST service or layer URL (needs confirm=true).

    At most 1 service doc + 5 layer docs + 1 sample query (resultRecordCount=1),
    GET only. Returns layers, fields (personal-data-like and id fields FLAGGED),
    query templates and a one-row sample as field names + masked shapes, never
    values. Stops on 429 and on token-required (498/499); never guesses tokens.
    """
    from hardly.core.arcgis import explore

    return _ok(explore(url, confirm=confirm))


@mcp.tool
def hardly_redirect_diag(url: str, confirm: bool = False, max_hops: int = 12) -> str:
    """Explain a redirect loop (ERR_TOO_MANY_RETRIES/REDIRECTS). LIVE GETs: requires confirm=true.

    Follows the redirect chain by hand with and without cookies and reports the loop
    shape: www<->apex or http<->https flips, trailing-slash fights, growing return
    URLs, cookie-dependent redirects, and whether the alternate host resolves.
    Typical causes: bad rewrite rules or an unexpected (non-canonical) domain.
    Reports statuses, redacted URLs and cookie NAMES only.
    """
    if not confirm:
        return _ok({"error": "redirect_diag requires confirm=true (performs live GET requests)"})
    from hardly.core.redirect_diag import diagnose_redirects

    try:
        return _ok(diagnose_redirects(url, max_hops=max(2, min(max_hops, 20))))
    except Exception as exc:  # noqa: BLE001
        return _err(exc)


@mcp.tool
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
) -> str:
    """Curl-first, robots-aware, polite crawl that finds candidate pages. LIVE GETs: requires confirm=true.

    Plain HTTP often works where headless Chromium is blocked and most facts are in
    static HTML. Follows only links found in fetched HTML (never guesses hosts or
    paths), ranks them with your domain `keywords_json` (JSON list of nouns), honours
    robots.txt, waits delay_s between requests per host, strips session ids, and
    stops at gates (bot wall / captcha / environment block) and on 429/Retry-After.
    Caps: max_pages <= 40, depth <= 4. External registrable domains are only recorded
    unless follow_external=true (one hop). Returns candidates (search forms first),
    per-page form field NAMES, gate classes, needs_browser pages and `next` advice -
    no bodies, URLs redacted. Pages flagged needs_browser: use hardly_capture_recipe /
    `capture discover` with a find_click step.
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
            )
        )
    except Exception as exc:  # noqa: BLE001
        return _err(exc)



@mcp.tool
def hardly_catalog_list(
    path: str,
    tag: str | None = None,
    group_json: str | None = None,
    role: str | None = None,
    status: str | None = None,
    target_id: str | None = None,
    summary: bool = False,
) -> str:
    """List a content-neutral target catalog (JSON/YAML file), filtered. No network.

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


@mcp.tool
def hardly_catalog_upsert(path: str, target_json: str, merge: bool = True, create: bool = False) -> str:
    """Add or update one target in a catalog file (atomic write). No network.

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


@mcp.tool
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
    """Politely verify catalog endpoints and write statuses back. LIVE GETs: requires confirm=true.

    Without confirm returns only the plan (endpoints and hosts). Per endpoint it runs one
    robots-aware, honest-UA crawl fetch (hardly_crawl machinery), records status
    (verified|blocked|dead|needs_browser), gate classes and stack names - never bodies or
    tokens. Per-host delay, request budget, resumable (already-checked endpoints are
    skipped unless force/recheck_after_s). Stops a host on any gate, rate limit or
    environment block per docs/gate-policy.md; never evades or retries a challenge.
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


@mcp.tool
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
    """Live replay minimisation (needs confirm=true). Replays one entry (or an ordered flow of entry ids; earlier ids are prior steps, the last is the target) with a cookie jar, then removes one header / cookie / query param / body field / prior step at a time and reports which are REQUIRED vs OPTIONAL (names only, no bodies). Secrets only via overrides_json: {"headers":{},"cookies":{},"query":{},"body":{}}; missing ones are listed under needs_override. GET/HEAD only unless allow_unsafe=true. Hard stop on 429 / Retry-After / gate stop; captcha token fields are never sent. Budget-skipped items appear under not_tested."""
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


@mcp.tool
def hardly_auth_patterns(session_id: str, host: str | None = None, kinds_json: str | None = None) -> str:
    """Detect generic auth patterns: bearer/refresh JSON login, OIDC/PKCE, SAML POST, double-submit CSRF, signed-request headers.

    Names, shapes, lengths and entry ids only - never values. `kinds_json` is an
    optional JSON list restricting the detectors.
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

    return _ok(detect_auth_patterns(path, host=host, kinds=kinds))


@mcp.tool
def hardly_pagination(session_id: str, host: str | None = None, limit: int = 20) -> str:
    """Recognise cursor / next-link / Link-header pagination. Shapes and entry ids only, never values."""
    try:
        conn = sess.require_conn(session_id)
    except KeyError as exc:
        return _err(exc)
    from hardly.core.pagination import detect_pagination

    return _ok(detect_pagination(conn, host=host, limit=min(limit, 60)))


@mcp.tool
def hardly_stack(
    session_id: str,
    host: str | None = None,
    limit: int = 30,
) -> str:
    """Fingerprint web/front-end frameworks, CMS/site builders, GIS stacks and UI toolkits.

    Reads response/request header names, cookie names, URL paths and HTML/JS
    body previews. Each technology has a category, confidence, evidence
    (kind + marker label, never values), entry_ids and a one-sentence SDK
    implication (e.g. carry all WebForms hidden fields, echo XSRF cookie into
    a header, Blazor needs a browser, ArcGIS query params). Also flags the
    double-encoded-json data convention. CDN/WAF products: use hardly_wall.
    """
    try:
        conn = sess.require_conn(session_id)
    except KeyError as exc:
        return _err(exc)
    from hardly.core.stack import fingerprint

    return _ok(fingerprint(conn, host=host, limit=min(limit, 60)))



@mcp.tool
def hardly_tables(
    session_id: str,
    entry_id: int | None = None,
    host: str | None = None,
) -> str:
    """List HTML data tables: headers, row/column counts, masked first row.

    For each table that looks like a data grid (th / thead / bold first row,
    >=2 columns, >=1 data row; handles nested tables, colspan and ASP.NET
    GridView pagers) returns caption, headers, column_count, row_count,
    first_row_masked (values replaced by shapes: 9 digit, a/A letter),
    column_kinds (integer|date|money|text|empty over ALL rows),
    has_pager_hint and entry_id. Two-column definition-style tables come back
    as kind=label_value with their labels only. Cell values are never returned.
    """
    try:
        conn = sess.require_conn(session_id)
    except KeyError as exc:
        return _err(exc)
    from hardly.core.tables import scan_session

    return _ok(scan_session(conn, host=host, entry_id=entry_id))


@mcp.tool
def hardly_gates(session_id: str, host: str | None = None) -> str:
    """Classify the gates in a capture and the policy action for each.

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

    return _ok(classify_gates(conn, host=host))


@mcp.tool
def hardly_grids(
    session_id: str,
    host: str | None = None,
    limit: int = 20,
) -> str:
    """Detect data-grid frameworks, JSON envelope conventions and paging params.

    HTML grid libraries (DataTables, jqGrid, AG Grid, Kendo, RadGrid, GridView
    pager commands…), response envelopes (OData, JSON:API, HAL, Spring/DRF
    pagination, Relay, ArcGIS REST, GeoJSON…), request paging/sort parameter
    styles, and common data-* attributes. Names and counts only.
    """
    try:
        conn = sess.require_conn(session_id)
    except KeyError as exc:
        return _err(exc)
    from hardly.core.grids import detect_grids

    return _ok(detect_grids(conn, host=host, limit=min(limit, 50)))


@mcp.tool
def hardly_find_search(
    session_id: str,
    host: str | None = None,
    keywords: list[str] | None = None,
    limit: int = 15,
) -> str:
    """Rank links likely to lead to a search/lookup page.

    Generic signals (search, lookup, find, viewer...) plus optional caller
    ``keywords`` for the site's domain vocabulary. Returns candidates and a
    ready ``next_step`` click for hardly_capture_recipe; repeat per hop until
    a form with input fields appears.
    """
    try:
        conn = sess.require_conn(session_id)
    except KeyError as exc:
        return _err(exc)
    from hardly.core.search_nav import find_search_entry

    return _ok(
        find_search_entry(conn, host=host, keywords=keywords or [], limit=min(limit, 40))
    )


@mcp.tool
def hardly_redirects(
    session_id: str,
    host: str | None = None,
    limit: int = 30,
) -> str:
    """List 3xx redirect hops and matched follow-up entry ids when present."""
    try:
        conn = sess.require_conn(session_id)
    except KeyError as exc:
        return _err(exc)
    from hardly.core.redirects import redirect_chains

    return _ok(
        redirect_chains(conn, host=host, limit=min(limit, 80))
    )


@mcp.tool
def hardly_issues(
    session_id: str,
    host: str | None = None,
    limit: int = 40,
) -> str:
    """Capture-quality issues: empty bodies, 4xx/5xx, redirects without Location."""
    try:
        conn = sess.require_conn(session_id)
    except KeyError as exc:
        return _err(exc)
    from hardly.core.issues import find_issues

    return _ok(find_issues(conn, host=host, limit=min(limit, 60)))


@mcp.tool
def hardly_trace(
    session_id: str,
    name: str = "",
    value: str = "",
    host: str | None = None,
    limit: int = 40,
) -> str:
    """Trace a field name or exact value across the capture.

    Pass name (e.g. __VIEWSTATE) and/or value. Values are never echoed back —
    only entry ids, where, and value length/kind.
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


@mcp.tool
def hardly_secrets(
    session_id: str,
    host: str | None = None,
    limit: int = 40,
) -> str:
    """Locate sensitive header/field/query *names* (password, token, cookie, …).

    Never returns values — only entry ids and names. Prefer hardly_credentials
    for a login/session/JWT/hex/base64 map.
    """
    try:
        conn = sess.require_conn(session_id)
    except KeyError as exc:
        return _err(exc)
    from hardly.core.secrets import locate_secrets

    return _ok(locate_secrets(conn, host=host, limit=min(limit, 60)))


@mcp.tool
def hardly_credentials(
    session_id: str,
    host: str | None = None,
    limit: int = 40,
) -> str:
    """Map login/credential evidence: passwords, session cookies, CSRF, JWT/hex/base64 shapes.

    Names and value *shapes* only — never secret values. Builds a hypothesized
    login_flow from password submits → token responses → auth material.
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
        )
    )


@mcp.tool
def hardly_recommend(goal: str) -> str:
    """Suggest which hardly tools to call next for a short goal string."""
    from hardly.core.recommend import recommend_tools

    return _ok(recommend_tools(goal))


@mcp.tool
def hardly_tree(
    session_id: str,
    entry_id: int,
    exclude_noise: bool = True,
    child_limit: int = 40,
) -> str:
    """Initiator parent/children for an entry (from HAR _initiator / pageref)."""
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


@mcp.tool
def hardly_params(
    session_id: str,
    method: str,
    host: str,
    path_template: str,
    limit: int = 30,
) -> str:
    """Classify query/body fields as static, dynamic, or sensitive across samples."""
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


@mcp.tool
def hardly_outline(
    session_id: str,
    entry_id: int,
    format: str = "all",
    max_depth: int = 8,
    side: str = "response",
) -> str:
    """Offline HTML/XML document outline from a HAR entry body (no Playwright).

    Returns compact ``markdown`` (headings/tables/forms/links), indented
    ``tree`` (tag#id.class), and approximate ``aria`` YAML. Sensitive values
    are redacted. Prefer this over asking the model to parse raw HTML/XML.
    For the *live* accessibility tree during capture, use hardly_capture_aria.
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


@mcp.tool
def hardly_content(
    session_id: str,
    host: str | None = None,
    kind: str | None = None,
    exclude_noise: bool = True,
    limit: int = 80,
) -> str:
    """Classify response payloads: json/jsonl/jsonp/csv/html_table/pdf/image/css/…

    Returns a histogram plus sample entry_ids. Each hardly_entry also includes
    a ``content`` object (table headers, json keys, csv columns, hints).
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


@mcp.tool
def hardly_graphql(
    session_id: str,
    host: str | None = None,
    limit: int = 40,
) -> str:
    """Detect GraphQL operations (operationName / query / mutation)."""
    try:
        conn = sess.require_conn(session_id)
    except KeyError as exc:
        return _err(exc)
    from hardly.core.graphql import detect_graphql

    return _ok(detect_graphql(conn, host=host, limit=min(limit, 80)))


@mcp.tool
def hardly_duplicates(
    session_id: str,
    host: str | None = None,
    exclude_noise: bool = True,
    min_count: int = 2,
    limit: int = 30,
) -> str:
    """Find repeated method+path_template groups (polling / retries)."""
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


@mcp.tool
def hardly_slow(
    session_id: str,
    host: str | None = None,
    exclude_noise: bool = True,
    limit: int = 20,
    min_ms: float = 0,
) -> str:
    """List the slowest requests by HAR time_ms."""
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


@mcp.tool
def hardly_wall(
    session_id: str,
    host: str | None = None,
    limit: int = 30,
) -> str:
    """Report bot walls actually hit, plus the bot-protection products seen.

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

    return _ok(detect_walls(conn, host=host, limit=min(limit, 60)))


@mcp.tool
def hardly_pages(
    session_id: str,
    host: str | None = None,
    exclude_noise: bool = True,
    limit: int = 40,
) -> str:
    """List HAR pageref groups (browser page loads) with document hints."""
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
def hardly_export_postman(
    session_id: str,
    output_path: str,
    host: str | None = None,
    exclude_noise: bool = True,
    name: str = "HAR-derived API",
) -> str:
    """Write a Postman Collection v2.1 JSON (secrets as {{placeholders}})."""
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


@mcp.tool
def hardly_export_brief(
    session_id: str,
    output_path: str,
    host: str | None = None,
) -> str:
    """Write a portal RE brief Markdown file (story, correlate, forms, routes)."""
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


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
