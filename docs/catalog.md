# Target catalog

A **catalog** is a versioned JSON (or YAML, if PyYAML is installed) file listing
*targets*, each with the *endpoints* you have discovered for it. It is generic
machinery: hardly assigns no meaning to tags, group keys or roles. A downstream
project defines those and subclasses [`TargetAdapter`](#the-downstream-subclass-pattern)
to plug in its own discovery.

Code: `hardly.core.catalog`. CLI: `hardly catalog ...`. MCP:
`hardly_catalog_list`, `hardly_catalog_upsert`, `hardly_catalog_verify`.

## Schema (version 1)

```json
{
  "name": "example",
  "version": 1,
  "targets": [
    {
      "id": "target-1",
      "name": "Example target",
      "tags": ["example-a"],
      "groups": {"region": "r1", "subregion": "s1"},
      "endpoints": [
        {
          "role": "search",
          "url": "https://one.example/find",
          "kind": "form",
          "status": "verified",
          "last_checked": "2026-01-01T00:00:00Z",
          "gate_classes": [],
          "stack": ["ASP.NET WebForms"],
          "notes": "",
          "capture": {"recipe_ref": "recipes/one-search.json", "har_ref": "hars/one.har"}
        }
      ]
    }
  ]
}
```

| Field | Meaning |
|-------|---------|
| `tags` | free-form strings (`example-a`); a query matches targets having all requested tags |
| `groups` | free-form `key: value` hierarchy (`region` / `subregion`); hardly only filters on it |
| `role` | free-form string per endpoint (`search`, `map`, `api`, ...) - yours to define |
| `kind` | optional hardly resource kind: `form` `api` `gis` `media` `page` `auth` `unknown` |
| `status` | `unverified` (default) `verified` `blocked` `dead` `needs_browser` |
| `gate_classes` | gate class names seen ([gate-policy.md](gate-policy.md)); names only |
| `stack` | technology names seen (names only, never values) |
| `capture` | references (`recipe_ref`, `har_ref`) to files you keep elsewhere; HARs are never stored in the catalog |

Validation (on load, upsert and save): ids unique; endpoint URLs absolute
`http(s)`; `kind` and `status` in the enums; `(role, url)` unique per target;
`version` supported. URLs are **redacted on the way in** with
`hardly.core.redact` - session ids, `;jsessionid=` path params and secret query
values are replaced, userinfo and fragments dropped, `notes` scrubbed - so a
catalog is safe to commit. Consequently a URL that only works with a secret in
it cannot be stored.

Files are written atomically (temp file in the same directory, then rename).

## CLI

```bash
hardly catalog init catalog.json --name example
hardly catalog add catalog.json --id target-1 --name "Example target" \
    --tag example-a --group region=r1 --group subregion=s1 \
    --endpoint search=https://one.example/find,form --endpoint api=https://one.example/api,api
hardly catalog list catalog.json --tag example-a --role search --status unverified
hardly catalog list catalog.json --summary          # counts by tag/group/role/status/gate/stack
hardly catalog show catalog.json target-1
hardly catalog verify catalog.json --yes --tag example-a --delay 2 --max-requests 40
hardly catalog export catalog.json --format csv -o catalog.csv
```

`add` merges into an existing target (tags unioned, groups overlaid, endpoints
merged by `(role, url)`); `--replace` replaces it. `verify` without `--yes`
prints nothing live (and exits 1). The MCP tools mirror this; `hardly_catalog_verify`
needs `confirm=true`.

## Verification

The default `TargetAdapter.verify` does one polite `hardly.core.crawl` fetch of the
endpoint (robots.txt honoured, honest User-Agent, gate-aware) and maps the result:

| Result | Status |
|--------|--------|
| 2xx, no gate | `verified` |
| 2xx, client-rendered (needs a browser) | `needs_browser` |
| 404 / 410 | `dead` |
| gate (bot wall, captcha, login, paywall, rate limit...) or robots disallow | `blocked`, gate classes recorded |
| `environment_blocked` (sandbox/network, not the site) | stays `unverified` - re-run from another network |
| transport error / other 4xx-5xx | status unchanged, attempt recorded |

Only statuses, gate class names and stack names are written back - never bodies,
cookies or tokens. Override `keywords()` / `crawl_options()` to tune the default,
or override `verify()` for your own checks (keep honouring gates).

### The runner

`CatalogRunner(catalog, adapter, path=..., confirm=True, ...)` iterates matching
endpoints and is:

- **polite**: per-host delay across endpoints (`delay_s`), plus the crawl's own
  robots/`Retry-After` handling;
- **budgeted**: `max_requests`, `max_endpoints`;
- **resumable**: the catalog is saved after every endpoint; endpoints already
  checked are skipped unless `force=True` or older than `recheck_after_s`;
- **gate-respecting** ([gate-policy.md](gate-policy.md)): the first captcha, bot
  wall, proof of work, waiting room, login, paywall, rate limit or environment
  block ends work on that host for the run. It never retries a challenged URL,
  never tests whether a gate is enforced, and never evades anything. Hand blocked
  endpoints to a person (interactive capture) or drop them.

Without `confirm=True` it returns a plan and an error, and makes no request.

## The downstream-subclass pattern

hardly stays content-neutral; your project owns the vocabulary and the seed data.

```python
from hardly.core import catalog as C

class MyAdapter(C.TargetAdapter):
    """Your project: knows what your tags, group keys and roles mean."""

    def discover(self, target: C.Target) -> list[C.Endpoint]:
        # e.g. derive candidates from your own seed data or a landing page you
        # fetched politely. Return unverified endpoints; the runner upserts them.
        base = target.groups.get("base_url", "")
        return [
            C.Endpoint(role="search", url=f"{base}/find", kind="form"),
            C.Endpoint(role="map", url=f"{base}/viewer", kind="gis"),
        ]

    def keywords(self, target, endpoint):
        # your domain nouns, used to rank links and spot search forms
        return ("search", "lookup")

    def crawl_options(self, endpoint):
        return {"max_pages": 3, "depth": 1} if endpoint.role == "search" else {}

cat = C.load("catalog.json")
runner = C.CatalogRunner(cat, MyAdapter(), path="catalog.json", confirm=True,
                         delay_s=2.0, max_requests=60, run_discover=True)
report = runner.run(tag="example-a", role="search")   # same filters as Catalog.select
```

Public API to build on: `Catalog`, `Target`, `Endpoint`, `TargetAdapter`
(`discover` abstract; `verify`, `keywords`, `crawl_options` overridable),
`VerifyResult`, `CatalogRunner`, `load` / `save` / `dumps` / `loads`,
`Catalog.upsert / merge / select / endpoints / summary / table`. Roles such as
`search`, `map`, `api` above are placeholders: downstream projects define their
own roles, tags and group keys, and keep their own recipes, captures and fixtures.
