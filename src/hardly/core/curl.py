"""Generate curl commands from HAR entries."""

from __future__ import annotations

import json
import shlex
import sqlite3

from hardly.core.redact import REDACTED, is_sensitive_header, redact_header_value


def entry_to_curl(
    conn: sqlite3.Connection,
    entry_id: int,
    *,
    redact: bool = True,
    use_env_placeholders: bool = True,
) -> dict:
    """Build a curl command for an entry."""
    row = conn.execute(
        "SELECT * FROM entries WHERE entry_id = ?", (entry_id,)
    ).fetchone()
    if not row:
        return {"error": f"entry_id {entry_id} not found"}

    headers = conn.execute(
        "SELECT name, value_redacted, value_raw FROM headers WHERE entry_id = ? AND side = 'request'",
        (entry_id,),
    ).fetchall()

    body_row = conn.execute(
        "SELECT preview_text, size FROM bodies WHERE entry_id = ? AND side = 'request'",
        (entry_id,),
    ).fetchone()

    url = f"{row['scheme']}://{row['host']}{row['path']}"
    if row["query_raw"]:
        url = f"{url}?{row['query_raw']}"

    parts = ["curl", "-X", row["method"], shlex.quote(url)]
    placeholders: dict[str, str] = {}

    for h in headers:
        name = h["name"]
        # Prefer raw for accurate replay structure, but redact secrets
        raw = h["value_raw"] if h["value_raw"] is not None else h["value_redacted"]
        if redact and is_sensitive_header(name):
            if use_env_placeholders:
                env_name = name.upper().replace("-", "_")
                placeholders[env_name] = f"${{{env_name}}}"
                value = f"${{{env_name}}}"
            else:
                value = REDACTED
        else:
            value = redact_header_value(name, str(raw)) if redact else str(raw)
        parts.extend(["-H", shlex.quote(f"{name}: {value}")])

    if body_row and body_row["preview_text"]:
        body = body_row["preview_text"]
        if redact:
            try:
                from hardly.core.redact import redact_json

                data = json.loads(body)
                body = json.dumps(redact_json(data))
            except (json.JSONDecodeError, TypeError):
                pass
        parts.extend(["--data-raw", shlex.quote(body)])

    return {
        "entry_id": entry_id,
        "curl": " \\\n  ".join(parts),
        "placeholders": placeholders,
        "redacted": redact,
        "note": "Sensitive values use env placeholders or ***REDACTED***; supply real secrets to replay.",
    }
