"""Headless live soak: capture public demos on the fly, then assert signals.

Usage::

    python -m hardly.soak_live
    python -m hardly.soak_live --ids wyobiz,httpbin-form
    HARDLY_LIVE_CAPTURE=1 pytest tests/test_live_soak.py

Requires ``pip install -e ".[capture]"`` and ``playwright install chromium``.
HARs are written under the cache captures dir (never committed).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
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


def run_target(target: LiveTarget) -> dict[str, Any]:
    """Capture one target headlessly and evaluate expected analysis signals."""
    from hardly.capture import capture_headless, playwright_status
    from hardly.core.credentials import map_credentials
    from hardly.core.graphql import detect_graphql
    from hardly.index import query as q
    from hardly import session as sess

    t0 = time.perf_counter()
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
            target.url,
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
    gql = detect_graphql(conn, host=host, limit=10)

    out["preferred_host"] = host
    out["entries"] = summary.get("entries") or summary.get("total") or out["entries_hint"]
    out["api"] = summary.get("api")
    out["form_pages"] = forms.get("count")
    out["aspnet_pages"] = asp
    out["password_fields"] = cred.get("password_field_count")
    out["graphql_ops"] = gql.get("operation_count")
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

    out["failures"] = failures
    out["ok"] = not failures
    out["total_s"] = round(time.perf_counter() - t0, 2)
    return out


def run_soak(
    *,
    ids: list[str] | None = None,
    fail_soft: bool = False,
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
    return {
        "cache": str(cache),
        "targets": len(results),
        "ok": len(results) - len(hard_fail) - len(soft_fail),
        "soft_fail": len(soft_fail),
        "fail": len(hard_fail),
        "results": results,
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

    summary = run_soak(ids=ids, fail_soft=bool(args.fail_soft))
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
