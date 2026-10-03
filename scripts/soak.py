"""Soak-test key analysis paths against HARs matched by glob (dev only).

    python scripts/soak.py "~/captures/*.har" "other/**/*.har"
    HARDLY_SOAK_GLOB="~/captures/*.har" python scripts/soak.py

With no arguments it runs the synthetic fixtures in tests/fixtures.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import time
import traceback
from pathlib import Path

os.environ.setdefault("HARDLY_RUNTIME_DIR", str(Path(tempfile.mkdtemp(prefix="hardly-soak-"))))

from hardly import session as sess
from hardly.core.brief import portal_brief
from hardly.core.correlate import correlate_tokens
from hardly.core.credentials import map_credentials
from hardly.core.graphql import detect_graphql
from hardly.core.help import tool_help
from hardly.core.issues import find_issues
from hardly.core.modes import list_modes, pick_mode
from hardly.core.pages import list_pages
from hardly.core.stats import traffic_stats
from hardly.core.story import portal_story
from hardly.core.tree import entry_tree
from hardly.core.wall import detect_walls
from hardly.index import query as q

DEFAULT_GLOB = str(Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "*.har")


def har_paths(patterns: list[str] | None = None) -> list[Path]:
    """Expand globs (``~`` and ``**`` supported) into a sorted, de-duplicated list.

    Sources, first non-empty wins: command-line arguments, then
    ``HARDLY_SOAK_GLOB`` (patterns separated by ``os.pathsep``), then the
    synthetic fixtures. Nothing site-specific is checked in.
    """
    import glob

    if not patterns:
        env = os.environ.get("HARDLY_SOAK_GLOB", "")
        patterns = [p for p in env.split(os.pathsep) if p] or [DEFAULT_GLOB]
    found: dict[str, Path] = {}
    for pattern in patterns:
        for hit in glob.glob(os.path.expanduser(pattern), recursive=True):
            path = Path(hit)
            if path.is_file():
                found[str(path.resolve())] = path
    return sorted(found.values(), key=lambda p: str(p))


# Patterns that must never appear in soak JSON (values from fixtures / live HARs).
_LEAK_RE = __import__("re").compile(
    r"(?i)(password\"\s*:\s*\"[^\*\"]{3,}|Bearer [A-Za-z0-9\-._~+/]+=*|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})"
)


def run_one(path: Path, *, expect_host: str | None = None) -> dict:
    t0 = time.perf_counter()
    out: dict = {"har": str(path), "size_mb": round(path.stat().st_size / 1e6, 1)}
    try:
        info = sess.open_har(str(path), force=True)
        if "error" in info:
            out["error"] = info
            return out
        sid = info["session_id"]
        conn = sess.require_conn(sid)
        out["open_s"] = round(time.perf_counter() - t0, 2)
        out["entries"] = info.get("entries")
        out["hosts"] = list((info.get("hosts") or {}).keys())[:5]

        host = q.preferred_host(conn)
        out["preferred_host"] = host
        out["expect_host"] = expect_host
        out["busiest_host"] = out["hosts"][0] if out["hosts"] else None
        if expect_host and (not host or expect_host.lower() not in host.lower()):
            out["ok"] = False
            out["error"] = (
                f"preferred_host {host!r} does not contain expected {expect_host!r}"
            )
            out["total_s"] = round(time.perf_counter() - t0, 2)
            return out
        summary = q.summary(conn)
        out["api"] = summary.get("api")
        out["noise"] = summary.get("noise")

        t1 = time.perf_counter()
        stats = traffic_stats(conn, host=host)
        out["stats_s"] = round(time.perf_counter() - t1, 2)
        out["status_classes"] = stats.get("status_classes")
        out["initiators"] = stats.get("initiators")[:5]

        t1 = time.perf_counter()
        walls = detect_walls(conn, host=host, limit=20)
        out["wall_s"] = round(time.perf_counter() - t1, 2)
        out["walls"] = walls.get("by_kind")

        t1 = time.perf_counter()
        issues = find_issues(conn, host=host, limit=20)
        out["issues_s"] = round(time.perf_counter() - t1, 2)
        out["issues"] = issues.get("by_kind")

        t1 = time.perf_counter()
        pages = list_pages(conn, limit=20)
        out["pages_s"] = round(time.perf_counter() - t1, 2)
        out["page_count"] = pages.get("page_count")
        out["unpaged"] = pages.get("unpaged_entries")

        t1 = time.perf_counter()
        corr = correlate_tokens(
            conn, har_path=sess.get_har_path(sid), host=host, limit=20
        )
        out["correlate_s"] = round(time.perf_counter() - t1, 2)
        out["correlations"] = corr.get("correlation_count")
        out["corr_source"] = corr.get("source")

        # Auto host pick (preferred_host inside brief)
        t1 = time.perf_counter()
        brief = portal_brief(conn, har_path=sess.get_har_path(sid))
        out["brief_s"] = round(time.perf_counter() - t1, 2)
        out["brief_host"] = brief.get("host")
        out["brief_steps"] = brief.get("step_count")
        out["brief_roles"] = brief.get("roles")
        out["brief_related"] = brief.get("related_hosts")
        out["js_routes"] = len(brief.get("js_routes") or [])
        story = portal_story(conn, host=host, limit=40)
        out["story_steps"] = story.get("step_count")
        out["story_hosts"] = story.get("hosts")

        # Tree on first non-noise entry with initiator children if possible
        row = conn.execute(
            """
            SELECT entry_id FROM entries
            WHERE is_noise = 0 AND initiator_url IS NOT NULL
            ORDER BY entry_id LIMIT 1
            """
        ).fetchone()
        if row:
            parent = conn.execute(
                """
                SELECT entry_id FROM entries
                WHERE is_noise = 0 AND (
                  scheme || '://' || host || path = ?
                  OR scheme || '://' || host || path || '?' || IFNULL(query_raw,'') = ?
                )
                ORDER BY entry_id LIMIT 1
                """,
                (
                    conn.execute(
                        "SELECT initiator_url FROM entries WHERE entry_id=?",
                        (row["entry_id"],),
                    ).fetchone()["initiator_url"],
                )
                * 2,
            ).fetchone()
            # simpler: tree the initiator target's children via entry that has kids
            kid = conn.execute(
                """
                SELECT initiator_url, COUNT(*) AS c FROM entries
                WHERE initiator_url IS NOT NULL AND is_noise = 0
                GROUP BY initiator_url ORDER BY c DESC LIMIT 1
                """
            ).fetchone()
            if kid:
                parent_row = conn.execute(
                    """
                    SELECT entry_id FROM entries
                    WHERE (scheme || '://' || host || path) = ?
                       OR (scheme || '://' || host || path || '?' || IFNULL(query_raw,'')) = ?
                    ORDER BY entry_id LIMIT 1
                    """,
                    (kid["initiator_url"], kid["initiator_url"]),
                ).fetchone()
                if parent_row:
                    tree = entry_tree(conn, parent_row["entry_id"])
                    out["tree_children"] = tree.get("child_count")
                    out["tree_entry"] = parent_row["entry_id"]

        gql = detect_graphql(conn, host=host, limit=10)
        out["graphql_ops"] = gql.get("operation_count")

        forms = q.list_forms(conn, host=host, exclude_noise=True, limit=20)
        out["form_pages"] = forms.get("count")
        asp = sum(
            1
            for e in forms.get("entries") or []
            if (e.get("webforms") or {}).get("aspnet")
        )
        out["aspnet_pages"] = asp
        label_total = sum(int(e.get("label_count") or 0) for e in forms.get("entries") or [])
        out["label_rows"] = label_total
        sample_labels = []
        for e in forms.get("entries") or []:
            for row in e.get("labels") or []:
                lab = row.get("label")
                if lab and lab not in sample_labels:
                    sample_labels.append(lab)
                if len(sample_labels) >= 8:
                    break
            if len(sample_labels) >= 8:
                break
        out["label_sample"] = sample_labels

        t1 = time.perf_counter()
        cred = map_credentials(
            conn, har_path=sess.get_har_path(sid), host=host, limit=30
        )
        out["cred_s"] = round(time.perf_counter() - t1, 2)
        out["cred_passwords"] = cred.get("password_field_count")
        out["cred_identity"] = cred.get("identity_field_count")
        out["cred_session_cookies"] = (cred.get("session_cookies") or [])[:8]
        out["cred_shapes"] = cred.get("shapes_by_kind")
        out["cred_oauth"] = bool((cred.get("oauth") or {}).get("likely"))
        out["cred_flow"] = (cred.get("login_flow") or {}).get("confidence")
        out["brief_cred"] = (brief.get("credentials") or {}).get("password_field_count")
        out["shapes_index"] = conn.execute(
            "SELECT COUNT(*) AS n FROM value_shapes"
        ).fetchone()["n"]

        mode = pick_mode(har_path=str(path))
        out["mode"] = mode.get("mode")
        out["modes_catalog"] = len(list_modes()["modes"])

        blob = json.dumps(out, default=str)
        leak = _LEAK_RE.search(blob)
        out["leak_check"] = "fail" if leak else "ok"
        if leak:
            out["leak_sample"] = leak.group(0)[:40]
            out["ok"] = False
            out["error"] = "possible secret value in soak output"
        else:
            out["ok"] = True
        out["total_s"] = round(time.perf_counter() - t0, 2)
    except Exception as exc:  # noqa: BLE001
        out["ok"] = False
        out["error"] = f"{type(exc).__name__}: {exc}"
        out["trace"] = traceback.format_exc()[-800:]
        out["total_s"] = round(time.perf_counter() - t0, 2)
    return out


def main(argv: list[str] | None = None) -> int:
    paths = har_paths(sys.argv[1:] if argv is None else argv)
    if not paths:
        print("no HARs matched (pass globs, or set HARDLY_SOAK_GLOB)")
        return 2
    print("cache", os.environ["HARDLY_RUNTIME_DIR"])
    print("help categories", len(tool_help()["categories"]))
    print("modes", [m["id"] for m in list_modes()["modes"]])
    results = []
    for path in paths:
        print("==>", path.name, flush=True)
        r = run_one(path)
        results.append(r)
        print(json.dumps({k: v for k, v in r.items() if k != "trace"}, indent=2))
        if r.get("trace"):
            print(r["trace"])
    failed = [r for r in results if not r.get("ok")]
    print("DONE", "ok", len(results) - len(failed), "fail", len(failed))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
