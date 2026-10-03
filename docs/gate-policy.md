# Gate policy

> Purpose: What to do at each kind of gate (bot wall, challenge, environment block): accept, stop, or re-run elsewhere.

A *gate* is anything between a client and content that needs a decision by a
person. hardly separates **"the site refused us"** from **"our sandbox refused
us"**, classifies each gate, never goes past one, and prints the class in the
brief. The machine-readable form is `hardly.core.gates.POLICY`.

## Classes and actions

| Class | Typical evidence | Action |
|-------|------------------|--------|
| `environment_blocked` | response header `x-deny-reason` (any value, e.g. `host_not_allowed`); 403/407/502 with proxy-style headers or wording and no site-WAF fingerprint | `unknown_rerun` |
| `bot_wall` | WAF / bot-manager block or challenge page; redirect into a `/challenge*` path | `stop` |
| `captcha` | captcha widget markup or script | `stop` |
| `proof_of_work` | proof-of-work interstitial | `stop` |
| `waiting_room` | virtual queue headers/scripts | `stop` |
| `click_through_terms` | disclaimer/terms form with an accept/agree submit (or a disclaimer-style path) | `accept_click_through`, or `stop` when the terms forbid automation |
| `login` | password-field page, HTTP 401 | `stop` |
| `paywall` | pricing wording ("$20 a day", "$50 per month", "purchase a pass"), HTTP 402 | `stop` |
| `rate_limit` | 429, `Retry-After`, lockout wording | `stop` |

## Rules

1. A click-through disclaimer may be accepted by an **ordinary form post**, once,
   only if the terms do not forbid automation. If they do, it is a stop sign.
2. Login, paywall, captcha, WAF/bot challenge, waiting room, rate limit, and
   terms that forbid automation are **stop signs**. Hand to a person (interactive
   mode) or drop the target.
3. **Never test whether a gate is enforced** server-side (no "does it still work
   without the token?" probing).
4. **Never retry a challenged URL in a loop.** One observation is enough.
5. An environment block is **unknown, not walled**: report
   "unknown - re-run from another network". It is never reported as a site wall
   and never suppresses or creates site-gate verdicts for that response.

## Where it is enforced

- `classify_response(status, headers, body, url)` - pure, per response.
- `classify_gates(conn, host)` - session level; `hardly_wall` returns `gates` and
  an `environment_blocked` verdict; `hardly_brief` prints a compact `gates`
  summary (class counts and actions).
- `hardly.core.recipe_policy.check_step` - headless recipe guard. Refuses
  click/fill/press/evaluate/fetch steps that target a captcha or challenge
  element, JS calling `grecaptcha.execute` / `turnstile.render` /
  `hcaptcha.execute`, and fills into password inputs unless the step sets
  `"allow_login": true`. Refusals return `ok: false`, `error: "policy: ..."`.
- `find_click` stops (`reached: false`, `blocked: [classes]`) when the settled
  page classifies as bot_wall, captcha, login, paywall or rate_limit.

Only evidence names (header, cookie, wording markers) are reported - never
cookie values, tokens or nonces.
