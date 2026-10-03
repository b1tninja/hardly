"""Headless live soak: capture public demos on the fly, then assert signals.

Usage::

    python -m hardly.soak_live
    python -m hardly.soak_live --ids local-webforms,httpbin-form
    HARDLY_LIVE_CAPTURE=1 pytest tests/test_live_soak.py

Requires ``pip install -e ".[capture]"`` and ``playwright install chromium``.
HARs are written under the cache captures dir (never committed).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import tempfile
import time
import traceback
from pathlib import Path
from typing import Any

from hardly.live_targets import LiveTarget, catalog_summary, list_targets


def _ensure_cache() -> Path:
    if not (os.environ.get("HARDLY_CACHE_DIR") or "").strip():
        os.environ["HARDLY_CACHE_DIR"] = tempfile.mkdtemp(prefix="hardly-live-soak-")
    return Path(os.environ["HARDLY_CACHE_DIR"])


_LOCAL: dict[str, Any] = {}


def _resolve_url(url: str) -> str:
    """Map ``local:/path`` onto the synthetic loopback site (started lazily)."""
    if not url.startswith("local:"):
        return url
    if "base" not in _LOCAL:
        from hardly.local_site import start

        _LOCAL["server"], _LOCAL["base"] = start()  # daemon thread; lives to exit
    return _LOCAL["base"] + url.removeprefix("local:")


def run_target(target: LiveTarget) -> dict[str, Any]:
    """Capture one target headlessly and evaluate expected analysis signals."""
    from hardly.capture import capture_headless, playwright_status
    from hardly.core.classify import summarize_content
    from hardly.core.credentials import map_credentials
    from hardly.core.graphql import detect_graphql
    from hardly.index import query as q
    from hardly import session as sess

    t0 = time.perf_counter()
    url = _resolve_url(target.url)
    out: dict[str, Any] = {
        "id": target.id,
        "url": target.url,
        "tech": list(target.tech),
        "soft": target.soft,
    }
    status = playwright_status()
    if not status.get("ready"):
        out["ok"] = False
        out["error"] = status.get("hint") or "Playwright not ready"
        out["total_s"] = round(time.perf_counter() - t0, 2)
        return out

    try:
        captured = capture_headless(
            url,
            wait_seconds=target.wait_seconds,
            recipe=list(target.recipe) or None,
            open_session=True,
            brief=True,
            label=f"live-{target.id}",
        )
    except Exception as exc:  # noqa: BLE001
        out["ok"] = False
        out["error"] = f"{type(exc).__name__}: {exc}"
        out["trace"] = traceback.format_exc()[-600:]
        out["total_s"] = round(time.perf_counter() - t0, 2)
        return out

    out["capture_s"] = round(time.perf_counter() - t0, 2)
    out["har_path"] = captured.get("har_path")
    out["har_bytes"] = captured.get("har_bytes")
    out["entries_hint"] = captured.get("entry_count_hint")
    out["bodies_filled"] = captured.get("bodies_filled")
    sid = captured.get("session_id")
    out["session_id"] = sid
    if captured.get("status") != "stopped" or not sid:
        out["ok"] = False
        out["error"] = captured.get("error") or "capture did not open a session"
        out["total_s"] = round(time.perf_counter() - t0, 2)
        return out

    conn = sess.require_conn(str(sid))
    host = q.preferred_host(conn)
    summary = q.summary(conn)
    forms = q.list_forms(conn, host=host, exclude_noise=True, limit=20)
    asp = sum(
        1
        for e in forms.get("entries") or []
        if (e.get("webforms") or {}).get("aspnet")
    )
    cred = map_credentials(conn, har_path=sess.get_har_path(str(sid)), host=host, limit=20)
    # GraphQL may live on an API host; scan unscoped when asserting GraphQL.
    gql = detect_graphql(
        conn,
        host=None if target.expect_graphql else host,
        limit=20,
    )
    content = summarize_content(conn, host=None, exclude_noise=False, limit=40)
    by_kind = content.get("by_kind") or {}
    json_hits = int(
        by_kind.get("json", 0)
        + by_kind.get("jsonl", 0)
        + by_kind.get("jsonp", 0)
    )
    # Tiny single-entry JSON captures sometimes land as mime-only.
    if json_hits == 0:
        json_hits = int(
            conn.execute(
                """
                SELECT COUNT(*) AS n FROM entries e
                LEFT JOIN bodies b ON b.entry_id = e.entry_id AND b.side = 'response'
                WHERE lower(IFNULL(e.mime, '')) LIKE '%json%'
                   OR lower(IFNULL(b.content_type, '')) LIKE '%json%'
                   OR IFNULL(b.preview_text, '') LIKE '{%'
                   OR IFNULL(b.preview_text, '') LIKE '[%'
                """
            ).fetchone()["n"]
            or 0
        )

    out["preferred_host"] = host
    out["entries"] = summary.get("entries") or summary.get("total") or out["entries_hint"]
    out["api"] = summary.get("api")
    out["form_pages"] = forms.get("count")
    out["aspnet_pages"] = asp
    out["password_fields"] = cred.get("password_field_count")
    out["graphql_ops"] = gql.get("operation_count")
    out["json_entries"] = json_hits
    out["brief_host"] = (captured.get("brief") or {}).get("host")
    out["label_rows"] = sum(
        int(e.get("label_count") or 0) for e in forms.get("entries") or []
    )

    failures: list[str] = []
    entries = int(out["entries"] or 0)
    if entries < target.min_entries:
        failures.append(f"entries {entries} < min {target.min_entries}")
    if target.expect_host and (
        not host or target.expect_host.lower() not in host.lower()
    ):
        failures.append(
            f"preferred_host {host!r} missing {target.expect_host!r}"
        )
    if target.expect_aspnet and asp < 1:
        failures.append("expected aspnet/VIEWSTATE page")
    if target.expect_forms and int(forms.get("count") or 0) < 1:
        failures.append("expected form pages")
    if target.expect_password and int(cred.get("password_field_count") or 0) < 1:
        failures.append("expected password field")
    if target.expect_graphql and int(gql.get("operation_count") or 0) < 1:
        failures.append("expected GraphQL operations")
    if target.expect_json and json_hits < 1:
        failures.append("expected JSON response bodies")

    out["failures"] = failures
    out["ok"] = not failures
    out["total_s"] = round(time.perf_counter() - t0, 2)
    return out


def write_fixtures(results: list[dict[str, Any]], out_dir: Path) -> list[dict[str, Any]]:
    """Write small offline HTML/JSON snippets from successful live captures.

    Never writes full HARs — only short previews useful as unit-test fixtures
    (VIEWSTATE form HTML, a GraphQL request body sample, etc.).
    """
    from hardly import session as sess

    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[dict[str, Any]] = []
    for r in results:
        if not r.get("ok") or not r.get("session_id"):
            continue
        sid = str(r["session_id"])
        conn = sess.require_conn(sid)
        tid = r["id"]
        # Prefer an HTML body with VIEWSTATE / forms for portal stacks.
        row = conn.execute(
            """
            SELECT e.entry_id, e.path, b.preview_text, b.content_type
            FROM entries e
            JOIN bodies b ON b.entry_id = e.entry_id AND b.side = 'response'
            WHERE b.preview_text IS NOT NULL AND length(b.preview_text) > 80
            ORDER BY
              CASE
                WHEN b.preview_text LIKE '%__VIEWSTATE%' THEN 0
                WHEN lower(IFNULL(b.content_type,'')) LIKE '%json%' THEN 1
                WHEN b.preview_text LIKE '%<form%' THEN 2
                ELSE 3
              END,
              length(b.preview_text) DESC
            LIMIT 1
            """
        ).fetchone()
        if not row:
            continue
        text = row["preview_text"] or ""
        # Cap fixture size; scrub common secret-ish lengths without inventing content.
        if len(text) > 12_000:
            text = text[:12_000] + "\n<!-- truncated by hardly soak_live -->\n"
        # Redact long VIEWSTATE / EVENTVALIDATION values to keep fixtures small.
        text = re.sub(
            r'(name="__(?:VIEWSTATE|EVENTVALIDATION|VIEWSTATEGENERATOR)"[^>]*value=")([^"]{40,})(")',
            r'\1[REDACTED]\3',
            text,
            flags=re.I,
        )
        ext = ".json" if "json" in (row["content_type"] or "").lower() or text.lstrip()[:1] in "{[" else ".html"
        path = out_dir / f"live_{tid}{ext}"
        path.write_text(text, encoding="utf-8")
        written.append(
            {
                "id": tid,
                "path": str(path),
                "entry_id": row["entry_id"],
                "bytes": path.stat().st_size,
            }
        )
        # GraphQL request sample when present.
        gql_req = conn.execute(
            """
            SELECT b.preview_text FROM entries e
            JOIN bodies b ON b.entry_id = e.entry_id AND b.side = 'request'
            WHERE e.method = 'POST' AND b.preview_text LIKE '%"query"%'
            ORDER BY e.entry_id DESC LIMIT 1
            """
        ).fetchone()
        if gql_req and gql_req["preview_text"]:
            gpath = out_dir / f"live_{tid}_graphql_request.json"
            sample = gql_req["preview_text"]
            if len(sample) > 4000:
                sample = sample[:4000]
            gpath.write_text(sample, encoding="utf-8")
            written.append({"id": tid, "path": str(gpath), "kind": "graphql_request"})
    manifest = out_dir / "manifest.json"
    manifest.write_text(json.dumps(written, indent=2) + "\n", encoding="utf-8")
    return written


def run_soak(
    *,
    ids: list[str] | None = None,
    fail_soft: bool = False,
    fixture_dir: str | Path | None = None,
) -> dict[str, Any]:
    """Run the live catalog (or a subset) and return a summary dict."""
    cache = _ensure_cache()
    targets = list_targets(ids=ids)
    results = [run_target(t) for t in targets]
    hard_fail = [
        r
        for r in results
        if not r.get("ok") and not (r.get("soft") and not fail_soft)
    ]
    soft_fail = [r for r in results if not r.get("ok") and r.get("soft")]
    fixtures: list[dict[str, Any]] = []
    if fixture_dir:
        fixtures = write_fixtures(results, Path(fixture_dir))
    return {
        "cache": str(cache),
        "targets": len(results),
        "ok": len(results) - len(hard_fail) - len(soft_fail),
        "soft_fail": len(soft_fail),
        "fail": len(hard_fail),
        "results": results,
        "fixtures": fixtures,
        "catalog": catalog_summary() if not ids else None,
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="python -m hardly.soak_live",
        description="Headless live soak against public tech demos",
    )
    p.add_argument(
        "--ids",
        default="",
        help="Comma-separated target ids (default: all)",
    )
    p.add_argument(
        "--list",
        action="store_true",
        help="Print the public target catalog and exit",
    )
    p.add_argument(
        "--fail-soft",
        action="store_true",
        help="Treat soft targets as hard failures",
    )
    p.add_argument(
        "--json",
        action="store_true",
        help="Print full JSON summary only",
    )
    p.add_argument(
        "--write-fixtures",
        default="",
        help="Write small redacted HTML/JSON snippets from successful captures",
    )
    args = p.parse_args(argv)

    if args.list:
        print(json.dumps(catalog_summary(), indent=2))
        return 0

    ids = [x.strip() for x in (args.ids or "").split(",") if x.strip()] or None
    print("cache", _ensure_cache(), flush=True)
    if ids:
        print("ids", ids, flush=True)
    else:
        print("targets", [t.id for t in list_targets()], flush=True)

    summary = run_soak(
        ids=ids,
        fail_soft=bool(args.fail_soft),
        fixture_dir=args.write_fixtures or None,
    )
    if args.json:
        print(json.dumps(summary, indent=2, default=str))
    else:
        for r in summary["results"]:
            print("==>", r["id"], flush=True)
            slim = {k: v for k, v in r.items() if k != "trace"}
            print(json.dumps(slim, indent=2, default=str))
            if r.get("trace"):
                print(r["trace"])
        print(
            "DONE",
            "ok",
            summary["ok"],
            "soft_fail",
            summary["soft_fail"],
            "fail",
            summary["fail"],
        )
    return 1 if summary["fail"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
