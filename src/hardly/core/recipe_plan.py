"""Turn a portal story into a suggested capture recipe (goto/fill/click)."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from hardly.core.story import portal_story


def recipe_from_story(
    conn: sqlite3.Connection,
    *,
    host: str | None = None,
    output_path: str | Path | None = None,
    limit: int = 30,
) -> dict[str, Any]:
    """Suggest Playwright capture recipe steps from an annotated story.

    Heuristic only — after the first goto the plan inserts an ``aria`` step so
    agents can swap css/name selectors for ``ref`` values from the live snapshot.
    """
    story = portal_story(conn, host=host, limit=limit)
    host = story.get("host") or host
    steps: list[dict[str, Any]] = []
    seen_goto = False
    fill_names: list[str] = []

    for step in story.get("steps") or []:
        role = step.get("role")
        method = step.get("method")
        path = step.get("path") or "/"
        scheme_host = _scheme_host(conn, step["entry_id"])
        url = f"{scheme_host}{path}" if scheme_host else path

        if not seen_goto and role in {"page", "search", "disclaimer", "auth"}:
            steps.append({"op": "goto", "url": url})
            steps.append({"op": "wait", "ms": 800})
            steps.append(
                {
                    "op": "aria",
                    "mode": "ai",
                    "note": (
                        "Replace following css/text selectors with ref=eN from "
                        "this snapshot's refs[] when possible"
                    ),
                }
            )
            seen_goto = True

        for form in step.get("forms") or []:
            for name in form.get("field_names") or []:
                if name.startswith("__") or name in fill_names:
                    continue
                if any(
                    x in name.lower()
                    for x in ("password", "pwd", "pass", "token", "viewstate")
                ):
                    continue
                fill_names.append(name)
                steps.append(
                    {
                        "op": "fill",
                        "css": f"[name='{name}']",
                        "value": f"PLACEHOLDER_{name}",
                        "note": (
                            f"from entry {step['entry_id']} form — "
                            "prefer ref from prior aria step if name matches"
                        ),
                    }
                )
            for fn in form.get("onsubmit_functions") or []:
                steps.append(
                    {
                        "op": "note",
                        "text": f"form onsubmit calls {fn} (entry {step['entry_id']})",
                    }
                )

        for label in step.get("labels") or []:
            text = (label.get("label") or "").strip()
            if text and len(text) < 40 and text.lower() in {
                "i accept",
                "accept",
                "agree",
                "continue",
                "search",
                "submit",
            }:
                steps.append({"op": "click", "text": text})

        for href in step.get("link_hrefs") or []:
            low = (href or "").lower()
            if any(k in low for k in ("accept", "agree", "disclaimer", "continue")):
                steps.append(
                    {
                        "op": "click",
                        "text": "I Accept",
                        "note": f"link href={href}",
                    }
                )
                break

        wf = step.get("webforms") or {}
        if wf.get("hidden_fields") or wf.get("dopostback"):
            steps.append(
                {
                    "op": "note",
                    "text": (
                        f"ASP.NET WebForms on entry {step['entry_id']}: "
                        f"hidden={wf.get('hidden_fields')} "
                        f"doPostBack={wf.get('dopostback')} — "
                        "do not hard-code VIEWSTATE; let the browser post"
                    ),
                }
            )
            for pb in (wf.get("dopostback") or [])[:3]:
                target = (pb.get("target") or "").split("$")[-1]
                if target and len(target) < 40:
                    steps.append(
                        {
                            "op": "click",
                            "css": f"[name='{pb.get('target')}'], #{target}, "
                            f"[id$='{target}']",
                            "note": f"__doPostBack target {pb.get('target')}",
                        }
                    )

        if role == "search" and method == "POST":
            steps.append(
                {
                    "op": "note",
                    "text": (
                        f"POST {path} fields={step.get('request_fields')} "
                        f"(entry {step['entry_id']}) - trigger via Search click "
                        "or fill+submit after elements()"
                    ),
                }
            )
        if role == "detail":
            steps.append(
                {
                    "op": "note",
                    "text": (
                        f"Detail hit {method} {path} (entry {step['entry_id']}). "
                        "Open a result row; use hardly_around on that entry."
                    ),
                }
            )

    # Capture recipe runner may not understand "note" — keep as comments in export.
    runnable = [s for s in steps if s.get("op") != "note"]
    notes = [s for s in steps if s.get("op") == "note"]

    written = None
    if output_path:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(runnable, indent=2), encoding="utf-8")
        written = str(path.resolve())

    return {
        "host": host,
        "step_count": len(runnable),
        "steps": runnable if not written else None,
        "notes": notes[:20],
        "output_path": written,
        "next": (
            "hardly_capture_start(channel=chrome) -> recipe (includes aria) -> "
            "swap css/text for ref=eN from aria.refs -> stop. "
            "Fallback: hardly_capture_elements for xpath/css."
        ),
    }


def _scheme_host(conn: sqlite3.Connection, entry_id: int) -> str | None:
    row = conn.execute(
        "SELECT scheme, host FROM entries WHERE entry_id = ?",
        (entry_id,),
    ).fetchone()
    if not row:
        return None
    return f"{row['scheme']}://{row['host']}"
