# Integration: `hardly_stack` (technology fingerprint)

Module: `src/hardly/core/stack.py` -- `fingerprint(conn, host=None, limit=30)`
and pure `fingerprint_response(status, headers, body, url="")`.

## 1. server.py (place next to `hardly_wall`)

```python
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
```

## 2. cli.py

```python
def cmd_stack(args: argparse.Namespace) -> int:
    from hardly.core.stack import fingerprint

    _, conn = _open(args.har)   # use the same open helper cmd_wall uses
    _print(fingerprint(conn, host=args.host, limit=args.limit))
    return 0
```

Parser (next to `wall_p`):

```python
stack_p = sub.add_parser(
    "stack",
    help="Fingerprint frameworks / CMS / GIS / UI toolkits and SDK implications",
)
stack_p.add_argument("har")
stack_p.add_argument("--host")
stack_p.add_argument("--limit", type=int, default=30)
stack_p.set_defaults(func=cmd_stack)
```

(Mirror `cmd_wall`'s exact session-opening lines; only the core call differs.)

## 3. capabilities.py

- CLI commands list: add `"stack"` (next to `"wall"`).
- MCP tools list: add `"hardly_stack"` (next to `"hardly_wall"`).
- Optional help/recommend text: "Which frameworks/CMS/GIS stack is this? -> hardly_stack".

## 4. docs/technologies.md paragraph

```markdown
## Technology fingerprint (`hardly_stack`)

`hardly stack` / `hardly_stack` scores framework tells from cookie *names*,
header names, URL paths and HTML/JS previews, and attaches a one-line SDK
implication to each: server frameworks (ASP.NET WebForms and antiforgery,
Blazor Server/WASM, Laravel, Django, Rails, Express, Spring/servlet, PHP, JSF),
front ends (Next.js, Nuxt, React, Vue, AngularJS, Angular, Inertia, Salesforce
Aura), CMS and site builders (AEM, WordPress, Drupal, SharePoint, Wix,
Squarespace, Webflow, GoDaddy), UI toolkits (Telerik/Kendo, DevExpress), GIS
(ArcGIS REST and web apps, Leaflet, OpenLayers, Mapbox/MapLibre GL, OGC
WMS/WFS, slippy tiles), API docs (Swagger/OpenAPI), and data conventions
(double-encoded JSON). Confidence is high/medium/low from weighted evidence;
evidence lists marker labels only, never cookie or token values. CDN/WAF
products are reported by `hardly_wall`.
```
