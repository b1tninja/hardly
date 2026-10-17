"""One-pass report: an EVIDENCE INDEX over the existing detectors.

``build_report`` runs the detectors that already exist (gates, walls, redirects,
credentials, auth patterns, challenges, stack, grids, tables, data attributes,
export links, endpoints/schemas, forms, search navigation) and condenses each
result into flat *findings*::

    {section, kind, severity (info|notice|blocker), label, entry_ids,
     names?, count?, lookup?, drill?}

Findings carry names, shapes, counts and entry ids only - never values. No
detection logic lives here; it only selects, ranks and caps what the detectors
return. Canned prose (implications / advice / next steps) is included only with
``explain=True``.

Detail levels: ``summary`` (~1 KB: counts per section + blockers), ``standard``
(findings, capped) and ``full`` (more findings, plus a ``drill`` pointer naming
the tool that expands each finding).
"""

from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path
from typing import Any

from hardly.core.explain import SEVERITIES, severity_rank

SECTIONS = ("access", "auth", "stack", "data", "forms", "run")
DETAILS = ("summary", "standard", "full")

# Per-detail caps: (findings per section, entry_ids per finding, names per finding)
_CAPS = {"summary": (0, 3, 6), "standard": (12, 8, 12), "full": (60, 20, 40)}
_SUMMARY_BLOCKERS = 5
_LABEL_MAX = 120
_NAME_MAX = 60

# kind -> drill-down tool (the one that returns the full evidence for it)
_DRILL = {
    "gate": "hardly_gate_bot_protection",
    "protection": "hardly_gate_bot_protection",
    "wall_status": "hardly_gate_bot_protection",
    "redirects": "hardly_session_redirect_history",
    "redirect_unresolved": "hardly_session_redirect_history",
    "login_form": "hardly_auth_report",
    "session_cookies": "hardly_auth_report",
    "csrf_names": "hardly_auth_report",
    "token_responses": "hardly_auth_report",
    "query_secrets": "hardly_auth_report",
    "oauth": "hardly_auth_report",
    "webauthn": "hardly_auth_report",
    "auth_pattern": "hardly_auth_report",
    "auth_challenge": "hardly_gate_bot_protection",
    "throttling": "hardly_gate_bot_protection",
    "captcha_widget": "hardly_gate_bot_protection",
    "technology": "hardly_tech_stack",
    "grid": "hardly_tech_stack",
    "json_envelope": "hardly_tech_stack",
    "paging_params": "hardly_tech_stack",
    "tables": "hardly_page_tables",
    "data_attrs": "hardly_page_embedded_routes",
    "data_endpoints": "hardly_page_embedded_routes",
    "export_link": "hardly_tech_stack",
    "endpoints": "hardly_endpoint_list",
    "schema": "hardly_endpoint_schema",
    "forms": "hardly_page_forms",
    "search_candidate": "hardly_page_ui",
    "run": "hardly_send_entry_ablation",
}

# kind -> the `sections` value that selects the evidence inside a sectioned drill-down tool
_DRILL_SECTIONS = {
    "login_form": ["credentials"],
    "session_cookies": ["credentials"],
    "csrf_names": ["credentials"],
    "token_responses": ["credentials"],
    "oauth": ["credentials"],
    "webauthn": ["credentials"],
    "query_secrets": ["secret_names"],
    "auth_pattern": ["patterns"],
    "data_attrs": ["data_attrs"],
    "data_endpoints": ["data_attrs"],
    "search_candidate": ["search_links"],
}

_LOOKUP_BY_CATEGORY = {
    "server_framework": "{name} form postback hidden state fields",
    "frontend_framework": "{name} how data is fetched from the API",
    "cms": "{name} REST API endpoints and authentication",
    "gis": "{name} REST query parameters and paging",
    "ui_toolkit": "{name} server-side data requests",
    "cdn_waf": "{name} challenge page behaviour and cookies",
    "bot_protection": "{name} challenge page behaviour and cookies",
    "captcha": "{name} widget token field and verification flow",
}
_LOOKUP_DEFAULT = "{name} request flow and session handling"


# --------------------------------------------------------------- helpers


def _clip(value: Any, n: int = _NAME_MAX) -> str:
    s = re.sub(r"\s+", " ", str(value if value is not None else "")).strip()
    return s if len(s) <= n else s[: n - 1] + "..."


def _ids(*sources: Any) -> list[int]:
    """Collect entry ids from ints / lists / dicts (keys ``entry_id``, ``*_ids``)."""
    out: list[int] = []

    def walk(o: Any, depth: int = 0) -> None:
        if depth > 6:
            return
        if isinstance(o, dict):
            for k, v in o.items():
                if k in ("entry_id", "sample_entry_id") and isinstance(v, int) and not isinstance(v, bool):
                    out.append(v)
                elif (k == "entry_ids" or k.endswith("_entry_ids")) and isinstance(v, list):
                    out.extend(i for i in v if isinstance(i, int) and not isinstance(i, bool))
                elif isinstance(v, (dict, list)):
                    walk(v, depth + 1)
        elif isinstance(o, list):
            for v in o:
                if isinstance(v, int) and not isinstance(v, bool):
                    out.append(v)
                else:
                    walk(v, depth + 1)

    for s in sources:
        walk(s)
    return sorted(dict.fromkeys(out))


def _lookup(tech_id: str, name: str, category: str | None) -> dict[str, str]:
    tpl = _LOOKUP_BY_CATEGORY.get(category or "", _LOOKUP_DEFAULT)
    return {"technology": tech_id, "suggest_search": tpl.format(name=name)}


class _Findings:
    def __init__(self) -> None:
        self.items: list[dict[str, Any]] = []

    def add(
        self,
        section: str,
        kind: str,
        severity: str,
        label: str,
        *,
        entry_ids: list[int] | None = None,
        names: list[str] | None = None,
        count: int | None = None,
        lookup: dict[str, str] | None = None,
        explain: str | None = None,
    ) -> None:
        if severity not in SEVERITIES:
            severity = "info"
        f: dict[str, Any] = {
            "section": section,
            "kind": kind,
            "severity": severity,
            "label": _clip(label, _LABEL_MAX),
            "entry_ids": list(entry_ids or []),
        }
        if names:
            f["names"] = [_clip(n) for n in dict.fromkeys(str(x) for x in names if x not in (None, ""))]
        if count is not None:
            f["count"] = int(count)
        if lookup:
            f["lookup"] = lookup
        if explain:
            f["explain"] = explain
        self.items.append(f)


# --------------------------------------------------------------- sections


def _access(conn: sqlite3.Connection, host: str | None, fx: _Findings, explain: bool, prose: dict) -> None:
    from hardly.core.gates import classify_gates
    from hardly.core.redirects import redirect_chains
    from hardly.core.wall import detect_walls

    gates = classify_gates(conn, host=host, explain=explain)
    for g in gates["gates"]:
        vendor = g.get("vendor")
        label = f"{g['class']} gate" + (f" ({vendor})" if vendor else "") + f" -> {g['action']}"
        lk = None
        if vendor:
            lk = _lookup(vendor, vendor, "bot_protection")
        fx.add(
            "access", "gate", g.get("severity") or "blocker",
            label, entry_ids=g.get("entry_ids"), names=g.get("evidence"), lookup=lk,
        )
    if explain and gates.get("next"):
        prose["access"] = gates["next"]

    walls = detect_walls(conn, host=host, explain=False)
    gate_vendors = {g.get("vendor") for g in gates["gates"] if g.get("vendor")}
    for p in walls.get("protection") or []:
        if p["state"] in {"blocked", "challenged"} and p["id"] in gate_vendors:
            continue  # already reported as a gate
        sev = "blocker" if p["state"] in {"blocked", "challenged"} else "info"
        fx.add(
            "access", "protection", sev, f"{p['name']} present ({p['state']})",
            names=[p["id"]], lookup=_lookup(p["id"], p["name"], p.get("category")),
        )
    so = walls.get("status_only") or []
    if so:
        fx.add(
            "access", "wall_status", "notice",
            f"{len(so)} plain block-status response(s) without vendor evidence",
            entry_ids=_ids(so), names=sorted({str(s["status"]) for s in so}), count=len(so),
        )

    chains = redirect_chains(conn, host=host, limit=200)["chains"]
    if chains:
        by_status: dict[str, int] = {}
        for c in chains:
            by_status[str(c["status"])] = by_status.get(str(c["status"]), 0) + 1
        fx.add(
            "access", "redirects", "info", f"{len(chains)} redirect response(s)",
            entry_ids=_ids(chains), names=[f"{k}x{v}" for k, v in sorted(by_status.items())], count=len(chains),
        )
        dangling = [c for c in chains if not c.get("target")]
        if dangling:
            fx.add(
                "access", "redirect_unresolved", "notice",
                f"{len(dangling)} redirect(s) with no captured follow-up request",
                entry_ids=_ids(dangling), count=len(dangling),
            )


def _auth(conn: sqlite3.Connection, har_path: str | Path | None, host: str | None, fx: _Findings,
          explain: bool, prose: dict) -> None:
    from hardly.core.challenges import detect_challenges
    from hardly.core.credentials import map_credentials

    cred = map_credentials(conn, har_path=har_path, host=host, limit=40, explain=explain)
    pw = cred.get("password_fields") or []
    if pw:
        fx.add(
            "auth", "login_form", "notice", f"{len(pw)} password field(s)",
            entry_ids=_ids(pw), names=[p.get("name") for p in pw] + [i.get("name") for i in cred.get("identity_fields") or []],
            count=len(pw),
        )
    for key, kind, label in (
        ("session_cookies", "session_cookies", "session cookie name(s)"),
        ("csrf_names", "csrf_names", "CSRF token name(s)"),
    ):
        vals = cred.get(key) or []
        if vals:
            names = [v if isinstance(v, str) else (v.get("name") if isinstance(v, dict) else str(v)) for v in vals]
            fx.add("auth", kind, "info", f"{len(vals)} {label}", names=names, count=len(vals))
    tr = cred.get("token_responses") or []
    if tr:
        fx.add("auth", "token_responses", "info", f"{len(tr)} token-bearing response(s)",
               entry_ids=_ids(tr), count=len(tr))
    qs = cred.get("query_secrets") or []
    if qs:
        fx.add(
            "auth", "query_secrets", "notice", f"{len(qs)} secret-like value(s) in URL query (names only)",
            entry_ids=_ids(qs), names=[q.get("name") for q in qs if isinstance(q, dict)], count=len(qs),
        )
    oauth = cred.get("oauth") or {}
    if oauth.get("likely"):
        fx.add("auth", "oauth", "info", "OAuth-style flow observed",
               entry_ids=_ids(oauth.get("flow")), names=oauth.get("param_names"))
    wa = cred.get("webauthn") or {}
    if wa.get("likely"):
        fx.add("auth", "webauthn", "notice", "WebAuthn ceremony observed (needs a person)")
    if explain and cred.get("next"):
        prose["auth"] = cred["next"]

    if har_path is not None:
        from hardly.core.auth_patterns import detect_auth_patterns

        ap = detect_auth_patterns(har_path, host=host, explain=False)
        for kind in ap.get("detected") or []:
            fx.add("auth", "auth_pattern", "info", f"auth pattern: {kind}",
                   entry_ids=_ids(ap.get(kind)), names=[kind])

    ch = detect_challenges(conn, host=host, limit=20, explain=False)
    if ch.get("auth_challenges"):
        schemes = sorted({str(c.get("scheme") or c.get("schemes") or "") for c in ch["auth_challenges"]} - {""})
        fx.add("auth", "auth_challenge", "notice", f"{len(ch['auth_challenges'])} HTTP auth challenge(s)",
               entry_ids=_ids(ch["auth_challenges"]), names=schemes, count=len(ch["auth_challenges"]))
    if ch.get("throttling"):
        fx.add("auth", "throttling", "notice", f"{len(ch['throttling'])} throttling/lockout signal(s)",
               entry_ids=_ids(ch["throttling"]), count=len(ch["throttling"]))
    if ch.get("captcha_widgets"):
        provs = sorted({str(c.get("provider") or c.get("vendor") or c.get("id") or "") for c in ch["captcha_widgets"]} - {""})
        fx.add("auth", "captcha_widget", "notice", f"{len(ch['captcha_widgets'])} captcha widget(s)",
               entry_ids=_ids(ch["captcha_widgets"]), names=provs, count=len(ch["captcha_widgets"]))


def _stack(conn: sqlite3.Connection, host: str | None, fx: _Findings, explain: bool, prose: dict) -> None:
    from hardly.core.data_attrs import scan_session as scan_data_attrs
    from hardly.core.grids import detect_grids
    from hardly.core.stack import fingerprint
    from hardly.core.tables import scan_session as scan_tables

    st = fingerprint(conn, host=host, limit=30, explain=explain)
    for t in st.get("technologies") or []:
        if t["confidence"] == "low":
            continue
        fx.add(
            "stack", "technology", "info", f"{t['name']} ({t['category']}, {t['confidence']})",
            entry_ids=t.get("entry_ids"), names=[e["kind"] + ":" + e["match"] for e in t.get("evidence") or []][:6],
            lookup=_lookup(t["id"], t["name"], t["category"]),
            explain=t.get("implications") if explain else None,
        )

    gr = detect_grids(conn, host=host, limit=20, explain=False)
    for g in gr.get("html_grids") or []:
        name = g.get("name") or g.get("id") or "grid"
        fx.add("stack", "grid", "info", f"HTML grid: {name}", entry_ids=_ids(g), names=[name],
               lookup=_lookup(str(name), str(name), "ui_toolkit"))
    for g in gr.get("json_envelopes") or []:
        name = g.get("name") or g.get("id") or "envelope"
        fx.add("stack", "json_envelope", "info", f"JSON envelope: {name}", entry_ids=_ids(g), names=[name])
    if gr.get("request_param_styles"):
        styles = [s.get("style") or s.get("name") or s.get("id") for s in gr["request_param_styles"] if isinstance(s, dict)]
        fx.add("stack", "paging_params", "info", "paging/sort parameter style(s)",
               entry_ids=_ids(gr["request_param_styles"]), names=styles)

    tb = scan_tables(conn, host=host)
    if tb.get("table_count"):
        data_tables = [t for t in tb["tables"] if t.get("kind") == "data"]
        hdrs: list[str] = []
        for t in data_tables[:6]:
            hdrs += t.get("headers") or []
        fx.add("stack", "tables", "info",
               f"{tb['table_count']} HTML table(s), {len(data_tables)} data table(s)",
               entry_ids=_ids(tb["tables"]), names=hdrs[:12], count=tb["table_count"])

    da = scan_data_attrs(conn, host=host, limit=20, explain=False)
    if da.get("attribute_count"):
        fx.add("stack", "data_attrs", "info", f"{da['attribute_count']} distinct data-* attribute(s)",
               entry_ids=_ids(da.get("attributes")), names=[a["name"] for a in da["attributes"]][:12],
               count=da["attribute_count"])
    if da.get("endpoints") or da.get("embedded_json"):
        n = len(da.get("endpoints") or []) + len(da.get("embedded_json") or [])
        fx.add("stack", "data_endpoints", "info", f"{n} endpoint/config value(s) handed to scripts via data-*",
               entry_ids=_ids(da.get("endpoints"), da.get("embedded_json")),
               names=[e.get("attr") for e in da.get("endpoints") or []], count=n)
    if explain and st.get("next"):
        prose["stack"] = st["next"]


def _data(conn: sqlite3.Connection, host: str | None, fx: _Findings) -> None:
    from hardly.core.export_links import export_links_report
    from hardly.index import query as q

    rep = export_links_report(conn, host)
    seen: set[tuple[str, tuple[str, ...]]] = set()
    for link in rep.get("export_links") or []:
        key = (link["path"], tuple(link.get("formats") or ()))
        if key in seen:
            continue
        seen.add(key)
        fx.add("data", "export_link", "info",
               f"{link.get('method', 'GET')} {link['path']} exports {'/'.join(link.get('formats') or []) or 'data'}",
               entry_ids=[link["entry_id"]] if link.get("entry_id") is not None else None,
               names=link.get("formats"))
    if rep.get("warnings"):
        fx.add("data", "export_link", "notice", "HTML previews were truncated; export links may be missed",
               count=rep.get("truncated_previews"))

    eps = q.list_endpoints(conn, host=host, exclude_noise=True, limit=500)
    rows = eps.get("endpoints") or []
    if rows:
        api = [e for e in rows if re.search(r"/(api|rest|graphql|odata|v\d+)\b|\.json$", e["path_template"], re.I)]
        top = sorted(rows, key=lambda e: -e["count"])[:8]
        fx.add("data", "endpoints", "info", f"{eps.get('total', len(rows))} endpoint(s), {len(api)} API-looking",
               entry_ids=[e["sample_entry_id"] for e in top if e.get("sample_entry_id") is not None],
               names=[f"{e['method']} {e['path_template']}" for e in (api or top)[:8]], count=eps.get("total", len(rows)))
        # Shape summaries (key names only) for the busiest JSON-looking endpoints.
        for e in (api or [])[:5]:
            try:
                sch = q.endpoint_schema(conn, method=e["method"], host=e["host"], path_template=e["path_template"], limit=5)
            except Exception:  # noqa: BLE001 - best effort
                continue
            keys = _schema_keys(sch.get("response_schema"))
            if keys:
                fx.add("data", "schema", "info", f"{e['method']} {e['path_template']} response shape",
                       entry_ids=[e["sample_entry_id"]] if e.get("sample_entry_id") is not None else None,
                       names=keys[:12])


def _schema_keys(schema: Any, depth: int = 0) -> list[str]:
    """Top-level property names from an inferred schema (names only)."""
    if not isinstance(schema, dict) or depth > 2:
        return []
    props = schema.get("properties") or schema.get("fields")
    if isinstance(props, dict):
        return [str(k) for k in props]
    items = schema.get("items")
    if isinstance(items, dict):
        return _schema_keys(items, depth + 1)
    return []


def _forms(conn: sqlite3.Connection, host: str | None, fx: _Findings) -> None:
    from hardly.core.search_nav import find_search_entry
    from hardly.index import query as q

    fr = q.list_forms(conn, host=host, side="response", exclude_noise=True, limit=100)
    seen: set[tuple[str, str]] = set()
    for ent in fr.get("entries") or []:
        for f in ent.get("forms") or []:
            action = re.sub(r"^[a-z][a-z0-9+.-]*://[^/]*", "", f.get("action") or "").split("?")[0] or "/"
            key = (f.get("method") or "GET", action)
            if key in seen:
                continue
            seen.add(key)
            names = f.get("field_names") or []
            has_pw = any(re.search(r"pass(word)?|pwd", n, re.I) for n in names)
            fx.add("forms", "forms", "notice" if has_pw else "info",
                   f"{key[0]} form -> {action} ({f.get('field_count', len(names))} field(s))",
                   entry_ids=[ent["entry_id"]], names=names[:12], count=f.get("field_count"))
    try:
        sn = find_search_entry(conn, host=host, keywords=[], limit=5)
    except Exception:  # noqa: BLE001
        sn = {}
    for c in sn.get("candidates") or []:
        fx.add("forms", "search_candidate", "info", f"search-like {c.get('kind', 'link')}: {_clip(c.get('text'), 50)}",
               entry_ids=_ids(c), names=[urlpath(c.get("href"))])


def urlpath(href: Any) -> str:
    return re.sub(r"^[a-z][a-z0-9+.-]*://[^/]*", "", str(href or ""), flags=re.I).split("?")[0] or "/"


def _run(fx: _Findings) -> None:
    fx.add("run", "run", "info", "no run results attached (placeholder; see hardly_send_entry_ablation)")


# --------------------------------------------------------------- build


def build_report(
    conn: sqlite3.Connection,
    har_path: str | Path | None,
    host: str | None = None,
    sections: list[str] | tuple[str, ...] | None = None,
    detail: str = "summary",
    explain: bool = False,
) -> dict[str, Any]:
    """Run the detectors once and return an evidence-index report (see module doc)."""
    if detail not in DETAILS:
        raise ValueError(f"detail must be one of {', '.join(DETAILS)}")
    wanted = [s for s in (sections or SECTIONS)]
    bad = [s for s in wanted if s not in SECTIONS]
    if bad:
        raise ValueError(f"unknown section(s): {', '.join(bad)}; valid: {', '.join(SECTIONS)}")
    wanted = [s for s in SECTIONS if s in wanted]

    fx = _Findings()
    prose: dict[str, str] = {}
    errors: dict[str, str] = {}
    runners = {
        "access": lambda: _access(conn, host, fx, explain, prose),
        "auth": lambda: _auth(conn, har_path, host, fx, explain, prose),
        "stack": lambda: _stack(conn, host, fx, explain, prose),
        "data": lambda: _data(conn, host, fx),
        "forms": lambda: _forms(conn, host, fx),
        "run": lambda: _run(fx),
    }
    for name in wanted:
        before = len(fx.items)
        try:
            runners[name]()
        except Exception as exc:  # noqa: BLE001 - one broken detector must not sink the report
            del fx.items[before:]
            errors[name] = type(exc).__name__

    per_section, id_cap, name_cap = _CAPS[detail]
    counts: dict[str, dict[str, int]] = {}
    for name in wanted:
        mine = [f for f in fx.items if f["section"] == name]
        counts[name] = {
            "findings": len(mine),
            "blocker": sum(f["severity"] == "blocker" for f in mine),
            "notice": sum(f["severity"] == "notice" for f in mine),
        }
    blockers = [f for f in fx.items if f["severity"] == "blocker"]

    out: dict[str, Any] = {
        "har": Path(str(har_path)).name if har_path else None,
        "host": host,
        "detail": detail,
        "sections": counts,
        "with_findings": [n for n in wanted if n != "run" and counts[n]["findings"]],
        "blockers": [
            {"section": b["section"], "kind": b["kind"], "label": b["label"], "entry_ids": b["entry_ids"][:3]}
            for b in blockers[:_SUMMARY_BLOCKERS]
        ],
    }
    if len(blockers) > _SUMMARY_BLOCKERS:
        out["blockers_more"] = len(blockers) - _SUMMARY_BLOCKERS
    if errors:
        out["errors"] = errors

    if detail != "summary":
        findings: list[dict[str, Any]] = []
        truncated: dict[str, int] = {}
        for name in wanted:
            mine = [f for f in fx.items if f["section"] == name]
            mine.sort(key=lambda f: -severity_rank(f["severity"]))  # stable: keeps detector order within a tier
            for f in mine[:per_section]:
                g = dict(f)
                g["entry_ids"] = g["entry_ids"][:id_cap]
                if "names" in g:
                    g["names"] = g["names"][:name_cap]
                if detail == "full":
                    tool = _DRILL.get(g["kind"])
                    if tool:
                        g["drill"] = {
                            "tool": tool,
                            **({"sections": _DRILL_SECTIONS[g["kind"]]} if g["kind"] in _DRILL_SECTIONS else {}),
                            **({"entry_id": g["entry_ids"][0]} if g["entry_ids"] else {}),
                        }
                findings.append(g)
            if len(mine) > per_section:
                truncated[name] = len(mine) - per_section
        out["findings"] = findings
        if truncated:
            out["truncated"] = truncated
    if explain and prose:
        out["explain"] = prose
    return out


# --------------------------------------------------------------- rendering


def render_markdown(report: dict[str, Any]) -> str:
    """Render a report dict as compact Markdown (evidence index)."""
    lines = [f"# HAR report{': ' + report['har'] if report.get('har') else ''}", ""]
    meta = [f"detail={report.get('detail')}"]
    if report.get("host"):
        meta.append(f"host={report['host']}")
    lines += [", ".join(meta), "", "## Sections", "", "| section | findings | blocker | notice |", "|---|---|---|---|"]
    for name, c in (report.get("sections") or {}).items():
        lines.append(f"| {name} | {c['findings']} | {c['blocker']} | {c['notice']} |")
    if report.get("blockers"):
        lines += ["", "## Blockers", ""]
        for b in report["blockers"]:
            ids = ",".join(map(str, b["entry_ids"]))
            lines.append(f"- [{b['section']}/{b['kind']}] {b['label']}" + (f" (entries {ids})" if ids else ""))
        if report.get("blockers_more"):
            lines.append(f"- ... {report['blockers_more']} more")
    if report.get("errors"):
        lines += ["", "## Errors", ""] + [f"- {k}: {v}" for k, v in report["errors"].items()]
    findings = report.get("findings") or []
    for name in (report.get("sections") or {}):
        mine = [f for f in findings if f["section"] == name]
        if not mine:
            continue
        lines += ["", f"## {name}", ""]
        for f in mine:
            row = f"- **{f['severity']}** `{f['kind']}` {f['label']}"
            if f.get("entry_ids"):
                row += f" - entries {','.join(map(str, f['entry_ids']))}"
            if f.get("names"):
                row += f" - names: {', '.join(f['names'])}"
            if f.get("lookup"):
                row += f" - lookup: \"{f['lookup']['suggest_search']}\""
            if f.get("drill"):
                row += f" - drill: {f['drill']['tool']}"
            lines.append(row)
            if f.get("explain"):
                lines.append(f"  - {f['explain']}")
    if report.get("truncated"):
        lines += ["", "_Truncated: " + ", ".join(f"{k} +{v}" for k, v in report["truncated"].items()) + "_"]
    if report.get("explain"):
        lines += ["", "## Notes", ""] + [f"- {k}: {v}" for k, v in report["explain"].items()]
    return "\n".join(lines) + "\n"


def default_output_path(har_path: str | Path, fmt: str = "md") -> Path:
    """``<har dir>/<har stem>.report.<fmt>`` - next to the HAR."""
    p = Path(har_path)
    return p.with_name(f"{p.stem}.report.{'json' if fmt == 'json' else 'md'}")


def write_report(report: dict[str, Any], path: str | Path, *, har_path: str | Path | None = None) -> Path:
    """Write the report. ``.json`` suffix -> JSON, else Markdown; a directory
    (or ``har_path`` with no ``path``) gets ``<har stem>.report.md`` inside it."""
    target = Path(path)
    if target.is_dir():
        stem = Path(str(har_path)).stem if har_path else "hardly"
        target = target / f"{stem}.report.md"
    from hardly.core.pathguard import guard_write

    guard_write(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.suffix.lower() == ".json":
        target.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    else:
        target.write_text(render_markdown(report), encoding="utf-8")
    return target


__all__ = ["SECTIONS", "DETAILS", "build_report", "render_markdown", "write_report", "default_output_path"]
