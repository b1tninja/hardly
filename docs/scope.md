# Scope: what belongs in hardly

hardly is a **generic, content-neutral** toolkit for reading and capturing HAR files and turning
what they show into facts a client SDK needs: endpoints, forms and labels, data/media kinds, and how
credentials and authentication are handled. It is also an MCP server so agents can do this safely.

## In scope

- Detection by **technology or protocol** (ASP.NET WebForms, ArcGIS REST, OIDC/PKCE, SAML, gRPC-web,
  grid libraries, bot-wall products): fingerprints and evidence, not site knowledge.
- Generic **resource classifications**: form, API, data, media, GIS service, auth, stream.
- Generic **mechanics**: capture, navigation, crawl, replay, redaction, reporting, stubs, OpenAPI.
- A **neutral extension point**: `TargetAdapter` / `Catalog` with free-form tags, groups and roles.
  Downstream projects define their own vocabulary and keep their own collections.
- Safety rules: confirm-gated live tools, no captcha/bot-wall evasion, no secret values in output.

## Out of scope (keep in the downstream project)

- Named websites, organisations, regions or jurisdictions, and their URLs, quirks or recipes.
- Domain vocabularies baked into code (callers pass keywords such as `find_click(keywords=[...])`).
- Content-type specific helpers (for example for one kind of record or register).
- Private HARs or captures as fixtures. Use synthetic data and the loopback `hardly.local_site`.

## Checklist for a change

1. Would it still make sense if the target were a completely different kind of site?
2. Does it read facts from the HAR or a live probe rather than restate what a model already knows?
   Prose advice stays behind `explain=true`.
3. Is it a new tool, or can it extend an existing one (a section of `hardly_report`, a detector)?
   Prefer extending; the tool surface is already large (`docs/tools.md`).
4. Tests use synthetic fixtures with neutral names; `tests/test_neutrality.py` enforces this.
