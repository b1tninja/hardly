# Contributing to hardly

Thanks for helping. The full contributor guide lives in [AGENTS.md](AGENTS.md) (repo map,
commands, conventions, safety rules). The short version:

1. Read [docs/scope.md](docs/scope.md). hardly is generic and content-neutral: technology and
   protocol detectors, generic resource kinds, safe mechanics. No named sites, organisations or
   regions, and no private HARs.
2. Set up: `pip install -e ".[dev]"`, then `pytest -q` and `ruff check .`
   (in a git worktree use `PYTHONPATH=src python -m pytest -q`).
3. Add a test with a synthetic fixture (or the loopback `hardly.local_site`). No network access.
4. If you touched a tool, docstring or doc: `python scripts/gen_tool_docs.py` and commit the result.
5. Open a pull request using the template; it repeats the scope checklist below.

## Scope checklist

- Would this still make sense if the target were a completely different kind of site?
- Does it read facts from the HAR or a live probe, rather than restate what a model already knows?
  (Prose advice stays behind `explain=true`.)
- Could it extend an existing tool or `hardly_report` section instead of adding a new tool?
- Names and shapes only in output, never secret values. Live tools are confirm-gated.
- No captcha, bot-wall or access-control evasion.
- Tests use neutral, synthetic data; `tests/test_neutrality.py` passes.

Maintainers cutting a release: [docs/releasing.md](docs/releasing.md). Add a `browser` marker to tests
that launch a real browser (they run nightly, not in the PR matrix).

Security issues: see [SECURITY.md](SECURITY.md). Release notes: [CHANGELOG.md](CHANGELOG.md).
