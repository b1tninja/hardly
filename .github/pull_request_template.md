## Summary

<!-- What changes and why. -->

## Scope checklist (see docs/scope.md)

- [ ] Makes sense for a completely different kind of site; no named sites, organisations or regions
- [ ] Reads facts from the HAR or a probe; prose advice only behind `explain=true`
- [ ] Extends an existing tool/section where possible rather than adding a new tool
- [ ] Output has names and shapes only, never secret values; live tools are confirm-gated
- [ ] No captcha, bot-wall or access-control evasion
- [ ] Tests use synthetic fixtures / loopback `local_site`; no private HARs, no network

## Verification

- [ ] `pytest -q` and `ruff check .` pass
- [ ] `python scripts/gen_tool_docs.py` run if tools, docstrings or docs changed
- [ ] `INDEX_VERSION` bumped if ingest output changed
