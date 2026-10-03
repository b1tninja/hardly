# ArcGIS explorer integration

Module: `src/hardly/core/arcgis.py` (tests: `tests/test_arcgis.py`).
Public API: `parse_service`, `parse_layer`, `summarise_query_response`,
`query_templates(layer_url, layer)`, `find_service_urls(text)`,
`summarize_session(conn, host=None)`, `explore(url, confirm=False, client=None)`.

## 1. server.py tools

```python
@mcp.tool
def hardly_arcgis(session_id: str, host: str | None = None) -> str:
    """List ArcGIS REST endpoints (MapServer/FeatureServer/ImageServer/GeocodeServer) seen in the session: service roots, layer ids, which layers were queried, parameter NAMES used, paging evidence, exceededTransferLimit seen. Names only; offline."""
    try:
        conn = sess.require_conn(session_id)
    except KeyError as exc:
        return _err(exc)
    from hardly.core.arcgis import summarize_session

    return _ok(summarize_session(conn, host=host))


@mcp.tool
def hardly_arcgis_explore(url: str, confirm: bool = False) -> str:
    """Live, polite exploration of an ArcGIS REST service or layer URL. Requires confirm=true. At most 1 service doc + 5 layer docs + 1 sample query (resultRecordCount=1), GET only. Returns layers, fields (personal-data-like and id fields FLAGGED), query templates and a one-row sample as field names + masked shapes (never values). Stops on 429 and on token-required (498/499); never guesses tokens."""
    from hardly.core.arcgis import explore

    return _ok(explore(url, confirm=confirm))
```

(`hardly_arcgis_explore` needs no session. `find_service_urls` can be exposed
as `hardly_arcgis_find(text)` the same way if wanted.)

## 2. CLI

```python
def cmd_arcgis(args: argparse.Namespace) -> int:
    from hardly.core.arcgis import summarize_session

    result = sess.open_har(args.har)
    if "error" in result:
        _print(result)
        return 1
    conn = sess.require_conn(result["session_id"])
    _print(summarize_session(conn, host=args.host))
    return 0


def cmd_arcgis_explore(args: argparse.Namespace) -> int:
    from hardly.core.arcgis import explore

    out = explore(args.url, confirm=args.confirm)
    _print(out)
    return 1 if "error" in out else 0
```

```python
arcgis_p = sub.add_parser("arcgis", help="ArcGIS REST endpoints seen in a HAR")
arcgis_p.add_argument("har")
arcgis_p.add_argument("--host")
arcgis_p.set_defaults(func=cmd_arcgis)

arcgis_x = sub.add_parser("arcgis-explore", help="Live ArcGIS service exploration (needs --confirm)")
arcgis_x.add_argument("url")
arcgis_x.add_argument("--confirm", action="store_true")
arcgis_x.set_defaults(func=cmd_arcgis_explore)
```

## 3. capabilities.py

Add to the tool-name list (near `"hardly_grids"`):

```python
    "hardly_arcgis",
    "hardly_arcgis_explore",
```

## 4. docs/technologies.md paragraph

### ArcGIS REST

`hardly_arcgis` lists ArcGIS REST endpoints (`MapServer`, `FeatureServer`,
`ImageServer`, `GeocodeServer`) in an indexed capture: service roots, layer
ids, which layers were queried, parameter names used, paging evidence
(`resultOffset` / `resultRecordCount`) and whether `exceededTransferLimit` was
seen. `hardly_arcgis_explore(url, confirm=true)` makes at most one service
document, five layer documents and one one-row sample query, and reports
layers, fields (name, alias, type, domain), request templates (attribute,
count-only, distinct values, objectId paging fallback) and the sample as field
names plus masked shapes (digits 9, letters a) - never row values. Fields whose
names look like personal data (name, owner, phone, email, address, ssn, dob,
birth) are flagged, not hidden. A 498/499 response is reported as a
token-required gate: stop. `find_service_urls` extracts service URLs and item
ids from Experience Builder / Web AppBuilder configs and page text, and shows
the item data URL pattern
`https://<portal>/sharing/rest/content/items/<id>/data?f=json` without
fetching it.
