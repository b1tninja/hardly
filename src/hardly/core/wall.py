"""Detect bot walls / challenge pages that block plain HTTP clients."""

from __future__ import annotations

import sqlite3
from typing import Any

def detect_walls(
    conn: sqlite3.Connection,
    *,
    host: str | None = None,
    limit: int = 30,
) -> dict[str, Any]:
    """Report entries that were actually blocked or challenged, plus the products seen.

    A CDN/WAF header on a normal 200 response is *protection present*, not a
    wall: it is listed under ``protection`` but does not create a ``hit``. Hits
    need a block/challenge status or wording, backed by a named product or an
    explicit block page.
    """
    from hardly.core.botwalls import detect_bot_protection

    har_path = None
    try:
        row = conn.execute("SELECT value FROM meta WHERE key = 'har_path'").fetchone()
        har_path = row["value"] if row else None
    except sqlite3.Error:
        pass
    prot = detect_bot_protection(conn, har_path=har_path, host=host, limit=30)

    clauses = ["1 = 1"]
    params: list[Any] = []
    if host:
        clauses.append("e.host = ?")
        params.append(host.lower())
    where = " AND ".join(clauses)
    rows = {
        int(r["entry_id"]): r
        for r in conn.execute(
            f"""
            SELECT e.entry_id, e.method, e.host, e.path, e.status, e.mime
            FROM entries e WHERE {where} ORDER BY e.entry_id
            """,
            params,
        )
    }

    hits: list[dict[str, Any]] = []
    seen: set[int] = set()
    # Entries a named product reports as blocked/challenged.
    for vendor in prot["vendors"]:
        if vendor["state"] not in {"blocked", "challenged"}:
            continue
        ids = list(vendor.get("blocked_entry_ids") or [])
        for slot in vendor.get("evidence") or []:
            if slot["kind"] == "challenge_page":
                ids += slot["entry_ids"]
        for eid in ids:
            if eid in rows:
                _add(hits, seen, rows[eid], kinds=[vendor["id"]], detail=f"{vendor['state']} ({vendor['name']})")
    # Plain block statuses count only with corroboration; otherwise they are
    # ordinary auth/rate errors and are reported separately.
    status_only: list[dict[str, Any]] = []
    for eid, r in rows.items():
        if int(r["status"] or 0) in (403, 429, 503) and eid not in seen:
            if any(v["state"] in {"blocked", "challenged"} for v in prot["vendors"]):
                _add(hits, seen, r, kinds=["http_block"], detail=f"status {r['status']}")
            elif len(status_only) < 10:
                status_only.append(
                    {"entry_id": eid, "path": r["path"], "status": r["status"], "host": r["host"]}
                )
    # Environment blocks (our sandbox/proxy refused) are never site walls.
    from hardly.core.gates import ENV_MESSAGE, classify_gates

    gates = classify_gates(conn, host=host)
    env = gates["environment_blocked"]
    env_ids = set(env["entry_ids"])
    if env_ids:
        hits = [h for h in hits if h["entry_id"] not in env_ids]
        status_only = [s for s in status_only if s["entry_id"] not in env_ids]
    blocking = list(prot["blocking"])
    if env_ids:
        site_vendors = {g.get("vendor") for g in gates["gates"] if g["class"] != "environment_blocked"}
        blocking = [b for b in blocking if b in site_vendors]
    hits = hits[: min(limit, 60)]
    by_kind: dict[str, int] = {}
    for h in hits:
        for k in h.get("kinds") or []:
            by_kind[k] = by_kind.get(k, 0) + 1

    return {
        "host": host,
        "hit_count": len(hits),
        "by_kind": by_kind,
        "hits": hits,
        "blocking": blocking,
        "gates": gates["gates"],
        "gate_summary": {"by_class": gates["by_class"], "by_action": gates["by_action"]},
        "environment_blocked": env,
        "protection": [
            {k: v[k] for k in ("id", "name", "category", "confidence", "state")}
            for v in prot["vendors"]
        ],
        "status_only": status_only,
        "recommendation": prot["recommendation"],
        "next": (
            "Bot walls need headed Chrome capture (channel=chrome), not urllib. "
            "Use hardly_capture_start; then continue in archive mode on the saved HAR."
            if hits
            else f"Environment block: {ENV_MESSAGE}. Not a site wall."
            if env_ids
            else "No wall observed; protection fingerprints (if any) are informational."
        ),
    }


def _add(
    hits: list[dict[str, Any]],
    seen: set[int],
    row: sqlite3.Row,
    *,
    kinds: list[str],
    detail: str,
) -> None:
    eid = int(row["entry_id"])
    if eid in seen:
        # Merge kinds onto existing
        for h in hits:
            if h["entry_id"] == eid:
                for k in kinds:
                    if k not in h["kinds"]:
                        h["kinds"].append(k)
                if detail not in h.get("details", []):
                    h.setdefault("details", []).append(detail)
                return
        return
    seen.add(eid)
    hits.append(
        {
            "entry_id": eid,
            "method": row["method"],
            "host": row["host"],
            "path": row["path"],
            "status": row["status"],
            "mime": row["mime"],
            "kinds": list(kinds),
            "details": [detail],
        }
    )
