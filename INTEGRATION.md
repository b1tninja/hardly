# Integration notes: gate taxonomy / policy / recipe guard

`hardly_wall` and `hardly_brief` already gain the new output automatically
(`gates`, `gate_summary`, `environment_blocked` on wall; `gates` on brief), and
`hardly_challenges` gains `sitekeys` / `token_endpoints`. Optional new tool:

## 1. server.py

```python
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
```

## 2. cli.py

```python
def cmd_gates(args: argparse.Namespace) -> int:
    from hardly.core.gates import classify_gates

    result = sess.open_har(args.har)
    if "error" in result:
        _print(result)
        return 1
    conn = sess.require_conn(result["session_id"])
    _print(classify_gates(conn, host=args.host))
    return 0
```

Parser registration (next to `wall_p`):

```python
    gates_p = sub.add_parser("gates", help="Classify gates (bot wall, captcha, login, paywall, ...) and policy actions")
    gates_p.add_argument("har")
    gates_p.add_argument("--host")
    gates_p.set_defaults(func=cmd_gates)
```

## 3. capabilities.py

- `TOOLS`: add `"hardly_gates"`
- `FEATURES`: add `"gates"` and `"recipe_policy"`

Then run `python scripts/gen_tool_docs.py`.

## 4. docs/technologies.md (append under "Bot walls, WAFs and captchas")

```markdown
### Gate taxonomy and policy

`hardly_gates` (and the `gates` list in `hardly_wall`, summary in `hardly_brief`)
classifies each gate: `environment_blocked`, `bot_wall`, `captcha`,
`proof_of_work`, `waiting_room`, `click_through_terms`, `login`, `paywall`,
`rate_limit`, with an action `stop`, `accept_click_through` or `unknown_rerun`.
An `x-deny-reason` header (or a proxy-style 403/502 with no site-WAF
fingerprint) means *our* sandbox refused the request: it is reported as
"unknown - re-run from another network", never as a site wall. The catalog also
covers Azure Front Door (`x-azure-ref` alone is informational; the 403 "request
is blocked" page is a block), F5 (TSPD, `volt-adc`, "Request Rejected"), AWS WAF
challenges returned as HTTP 202, Imperva blocks returned as 503, and an
application-level `app-rate-limit` entry (429 + Retry-After, "too many requests
in the past minute", `/challenge*` redirects). `hardly_challenges` captcha
widgets add public `sitekeys` (max 3, truncated) and `token_endpoints` (requests
whose field names include a captcha token field; values never shown). Written
policy: [gate-policy.md](gate-policy.md). Headless recipes are guarded by
`hardly.core.recipe_policy.check_step`; `find_click` stops on a gated page.
```

Also link `gate-policy.md` from docs/README.md and AGENTS.md if desired.
