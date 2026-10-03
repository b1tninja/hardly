"""Generate a minimal urllib client sketch from HAR entry ids."""

from __future__ import annotations

import json
import re
import sqlite3
import textwrap
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode

from hardly.core.redact import is_sensitive_key
from hardly.core.story import portal_story

_MAX_CODE_CHARS = 12_000


def client_stub(
    conn: sqlite3.Connection,
    *,
    entry_ids: list[int] | None = None,
    host: str | None = None,
    output_path: str | Path | None = None,
    class_name: str = "PortalClient",
) -> dict[str, Any]:
    """Build a redacted urllib sketch for the given entries (or a portal story)."""
    corr_notes: list[str] = []
    if entry_ids:
        ids = [int(x) for x in entry_ids][:30]
    else:
        story = portal_story(conn, host=host, limit=25)
        host = story.get("host") or host
        ids = [
            int(step["entry_id"])
            for step in story.get("steps") or []
            if step.get("method") in ("GET", "POST", "PUT", "PATCH", "DELETE")
        ][:25]
        if not ids:
            return {"error": "no entries to stub", "host": host}
    try:
        from hardly.core.correlate import correlate_tokens

        for c in (correlate_tokens(conn, host=host, limit=12).get("correlations") or []):
            hint = c.get("name_hint") or "value"
            corr_notes.append(
                f"# Correlate {hint}: entry {c.get('from_entry_id')} → "
                f"{c.get('to_entry_id')} ({c.get('to_where')})"
            )
    except Exception:  # noqa: BLE001
        pass

    steps_code: list[str] = []
    used_hosts: set[str] = set()
    needs_json = False
    if corr_notes:
        steps_code.append("\n".join(corr_notes[:12]))
    for entry_id in ids:
        piece = _entry_step(conn, entry_id)
        if not piece:
            continue
        used_hosts.add(piece["host"])
        needs_json = needs_json or bool(piece.get("needs_json"))
        steps_code.append(piece["code"])

    if not steps_code:
        return {"error": "no stubbable entries", "entry_ids": ids}

    base = next(iter(used_hosts)) if len(used_hosts) == 1 else "https://example.com"
    # Continuation lines must carry the template indent or dedent() finds none.
    json_import = "import json\n        " if needs_json else ""
    body = textwrap.dedent(
        f'''\
        """Auto-generated sketch from hardly_stub — review before use.

        Secrets are placeholders. Prefer cookies via CookieJar; do not commit
        live credentials. Generated for host hints: {", ".join(sorted(used_hosts))}.
        """

        from __future__ import annotations

        {json_import}from http.cookiejar import CookieJar
        from urllib.parse import urlencode
        from urllib.request import HTTPCookieProcessor, Request, build_opener

        BASE = {base!r}
        UA = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36"
        )


        class {class_name}:
            def __init__(self) -> None:
                self._opener = build_opener(HTTPCookieProcessor(CookieJar()))

            def _fetch(
                self,
                method: str,
                url: str,
                data: bytes | None = None,
                headers: dict[str, str] | None = None,
            ) -> tuple[int, str]:
                sent = {{"User-Agent": UA, "Accept": "*/*"}}
                if headers:
                    sent.update(headers)
                req = Request(url, data=data, headers=sent, method=method)
                with self._opener.open(req, timeout=60) as resp:
                    return int(resp.status), resp.read().decode("utf-8", "replace")

            def run(self) -> None:
                # Steps follow capture order. Fill PLACEHOLDER_* values.
        '''
    )
    indented = "\n".join(
        textwrap.indent(block.rstrip() + "\n", "        ") for block in steps_code
    )
    code = body + "\n" + indented + "\n\n\nif __name__ == \"__main__\":\n    " + class_name + "().run()\n"
    if len(code) > _MAX_CODE_CHARS:
        code = code[:_MAX_CODE_CHARS] + "\n# … truncated …\n"

    written = None
    if output_path:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(code, encoding="utf-8")
        written = str(path.resolve())

    return {
        "host": host or base,
        "entry_ids": ids,
        "output_path": written,
        "code": code if not written else None,
        "note": (
            "Sketch only — verify paths/fields against hardly_story / live probes. "
            "When output_path is set, code is written to disk and omitted here."
        ),
    }


def _entry_step(conn: sqlite3.Connection, entry_id: int) -> dict[str, Any] | None:
    row = conn.execute(
        "SELECT * FROM entries WHERE entry_id = ?", (entry_id,)
    ).fetchone()
    if not row:
        return None
    url = f"{row['scheme']}://{row['host']}{row['path']}"
    if row["query_raw"]:
        url = f"{url}?{row['query_raw']}"
    body_row = conn.execute(
        "SELECT preview_text, content_type FROM bodies "
        "WHERE entry_id = ? AND side = 'request'",
        (entry_id,),
    ).fetchone()
    headers = {
        h["name"]: h["value_redacted"]
        for h in conn.execute(
            "SELECT name, value_redacted FROM headers "
            "WHERE entry_id = ? AND side = 'request'",
            (entry_id,),
        )
    }
    interesting = {
        k: v
        for k, v in headers.items()
        if k.lower()
        in {
            "content-type",
            "accept",
            "x-requested-with",
            "origin",
            "referer",
        }
    }
    # Authorization/API-key headers: keep the *scheme*, never the value.
    for k in list(headers):
        low = k.lower()
        if low == "authorization":
            shape = conn.execute(
                "SELECT shape FROM value_shapes WHERE entry_id = ? AND lower(name) = 'authorization' LIMIT 1",
                (entry_id,),
            ).fetchone()
            kind = shape["shape"] if shape else ""
            interesting[k] = (
                "Basic PLACEHOLDER_BASIC_CREDENTIALS" if kind == "basic_auth"
                else "Bearer PLACEHOLDER_TOKEN"
            )
        elif low in {"api_key", "api-key", "apikey", "x-api-key", "x-auth-token", "x-access-token"}:
            interesting[k] = f"PLACEHOLDER_{low.upper().replace('-', '_')}"
    method = row["method"]
    lines = [
        f"# entry_id={entry_id} {method} {row['path']}",
    ]
    hdr_lit = json.dumps(interesting, indent=4)
    needs_json = False
    if method == "GET" or not (body_row and body_row["preview_text"]):
        lines.append(f"status, body = self._fetch({method!r}, {url!r}, headers={hdr_lit})")
        lines.append("assert status < 400, (status, body[:200])")
    else:
        raw = body_row["preview_text"]
        ct = (body_row["content_type"] or "").lower()
        if "json" in ct or raw.lstrip().startswith(("{", "[")):
            needs_json = True
            lines.append(f"payload = {_json_placeholder(raw)}")
            lines.append(
                f"hdrs = {hdr_lit}"
            )
            lines.append("hdrs = {**hdrs, 'Content-Type': 'application/json'}")
            lines.append(
                f"status, body = self._fetch({method!r}, {url!r}, "
                f"data=json.dumps(payload).encode(), headers=hdrs)"
            )
        else:
            fields = _form_placeholders(raw)
            lines.append(f"form = {json.dumps(fields, indent=4)}")
            lines.append(
                f"status, body = self._fetch({method!r}, {url!r}, "
                f"data=urlencode(form).encode(), headers={hdr_lit})"
            )
        lines.append("assert status < 400, (status, body[:200])")
    return {
        "host": f"{row['scheme']}://{row['host']}",
        "code": "\n".join(lines),
        "needs_json": needs_json,
    }


_ALWAYS_PLACEHOLDER = re.compile(
    r"^(__(VIEWSTATE|EVENTVALIDATION|VIEWSTATEGENERATOR|EVENTTARGET|"
    r"EVENTARGUMENT|REQUESTVERIFICATIONTOKEN).*|"
    r".*(csrf|xsrf|nonce).*)$",
    re.I,
)


def _form_placeholders(body: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for name, value in parse_qsl(body, keep_blank_values=True):
        if not name:
            continue
        if (
            is_sensitive_key(name)
            or _ALWAYS_PLACEHOLDER.match(name)
            or len(value) > 80
        ):
            out[name] = f"PLACEHOLDER_{_slug(name).upper()}"
        else:
            out[name] = value
        if len(out) >= 40:
            break
    return out


def _json_placeholder(text: str) -> str:
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return "{}"
    return json.dumps(_redact_obj(data), indent=4)


def _redact_obj(data: Any) -> Any:
    if isinstance(data, dict):
        out = {}
        for key, value in list(data.items())[:40]:
            if is_sensitive_key(str(key)):
                out[key] = f"PLACEHOLDER_{_slug(str(key)).upper()}"
            else:
                out[key] = _redact_obj(value)
        return out
    if isinstance(data, list):
        return [_redact_obj(data[0])] if data else []
    if isinstance(data, str) and len(data) > 80:
        return "PLACEHOLDER_LONG"
    return data


def _slug(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "_", name).strip("_") or "FIELD"
