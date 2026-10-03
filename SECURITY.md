# Security and responsible use

## Responsible use

- Use hardly only on systems you own or are explicitly authorised to test or analyse.
- hardly does not evade access controls, captchas, bot walls or rate limits, and contributions that
  add such evasion will not be accepted. When a gate is detected the correct action is to stop, ask
  the person who is authorised to proceed, or re-run from a different environment
  ([docs/gate-policy.md](docs/gate-policy.md)).
- Live tools (`probe`, `crawl`, `redirect_diag`, `replay_check`, `replay_flow`, catalog verify, ...)
  send real traffic and are confirm-gated. Keep request budgets small and respect robots.txt and
  published usage terms.

## Handling HAR files

HAR files routinely contain passwords, session cookies, bearer tokens and personal data, including
in request and response bodies.

- Treat every capture as a secret. Never commit one (`*.har` is gitignored) or paste one into an
  issue, a chat or a model context.
- hardly redacts values in its output and reports names and shapes only, but redaction is
  best-effort. Review anything before sharing it. `hardly har scrub` can strip sensitive values
  from a HAR copy.
- The index cache (`~/.cache/hardly`, or `HARDLY_CACHE_DIR`) holds redacted previews, header and
  body data derived from the HAR. For sensitive captures use `HARDLY_INDEX=memory` (or
  `hardly_open(storage='memory')`): the index stays in process memory, no cache file or metadata is
  written and nothing derived is left on disk. `hardly_persist` is the only way such a session reaches
  disk, and only when you ask. Cache files are written atomically and opened read-only.
- Rotate any credential that appeared in a capture that was shared or stored insecurely.
- Test fixtures must be synthetic.

## Reporting a vulnerability

Please do not open a public issue containing exploit details or real secrets. Use the
repository's private vulnerability reporting (GitHub Security Advisories: the "Security" tab, then
"Report a vulnerability") if it is enabled, otherwise open a minimal public issue asking for a
private contact channel, without technical details. Include the hardly version, a description, and
synthetic reproduction steps. Expect an acknowledgement and a fix or mitigation plan in reasonable
time; this is a volunteer-maintained project.

In scope: secret leakage in output, bypasses of confirm gates, path traversal or unsafe file writes,
unsafe handling of untrusted HAR content. Out of scope: findings about third-party sites captured
with hardly.
