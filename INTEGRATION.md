# Integration: hardly_replay_check

Core: `src/hardly/core/replay_check.py` (`replay_check(conn, entry_ids, *, overrides, max_requests=15, delay_s=0.5, allow_unsafe=False, client=None)`).
Tests: `tests/test_replay_check.py`. Add `from hardly.core.replay_check import replay_check` to the imports in server.py.

## 1. server.py (place after `hardly_probe`)

```python
@mcp.tool
def hardly_replay_check(
    session_id: str,
    entry_ids: list[int],
    confirm: bool = False,
    overrides_json: str | None = None,
    max_requests: int = 15,
    delay_s: float = 0.5,
    allow_unsafe: bool = False,
) -> str:
    """Live replay minimisation. Requires confirm=true. Replays one entry (or an ordered flow of entry ids; earlier ids are prior steps, the last is the target) with a cookie jar, then removes one header / cookie / query param / body field / prior step at a time and reports which are REQUIRED vs OPTIONAL (names only, no bodies). Secrets only via overrides_json: {"headers":{},"cookies":{},"query":{},"body":{}}; missing ones are listed under needs_override. GET/HEAD only unless allow_unsafe=true. Hard stop on 429 / Retry-After / gate stop; captcha token fields are never sent. Budget-skipped items appear under not_tested."""
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
    return _ok(
        replay_check(
            conn,
            entry_ids,
            overrides=overrides,
            max_requests=max_requests,
            delay_s=delay_s,
            allow_unsafe=allow_unsafe,
        )
    )
```

## 2. cli.py

```python
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
```

Parser (next to `probe_p`; ensure `json` is imported in cli.py):

```python
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
```

## 3. capabilities.py

Add `"hardly_replay_check",` to the tool-name list after `"hardly_probe",`.
Also suggested: core/help.py (list beside `hardly_probe`, ~line 107) and
core/recommend.py (~line 195: add `"hardly_replay_check"` to the probe/curl
suggestion, trigger words "which headers are required", "HTTP 500 unless", "minimal request").

## 4. Docs paragraphs

docs/technologies.md (Ajax / server-rendered portals):

> **Minimal replay.** Server frameworks often return a generic error (HTTP 500
> or an error page) when an implicit precondition is missing: an Ajax marker
> header (`X-Requested-With`), a cookie set by an earlier page load, a paging
> parameter, or a per-form hidden token. Do not guess which matters. Run
> `hardly_replay_check` on the entry (or the ordered flow of entry ids). It
> replays with a cookie jar, removes one header, cookie, query parameter, body
> field or prior step at a time, and compares a coarse outcome signature
> (status class, content kind, JSON top-level keys or an HTML size band and
> form presence). Pieces whose removal changes the signature are `required`;
> the rest are `optional`. Captcha/challenge token fields are never sent or
> tested, and the run halts on 429, Retry-After or a gate stop.

docs/sdk-workflow.md (before writing the client):

> **Trim the client with `hardly_replay_check`.** Once a request works, run it
> with `confirm=true` and your own `overrides_json` for secrets (cookies,
> auth headers, CSRF/hidden fields; the index never holds their values;
> `needs_override` lists the names you must supply). Encode only the `required`
> headers, cookies, parameters, fields and prior steps in the SDK; treat
> `optional` as safe to omit. Default is GET/HEAD only (`allow_unsafe` for
> writes, with care); keep `max_requests` small and honor `not_tested` by
> re-running with a larger budget only if needed. Output contains names and
> findings only, never response bodies or values.
