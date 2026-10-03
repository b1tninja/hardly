"""Generate a urllib client sketch from HAR entry ids.

Values that an earlier response issued (hidden form fields, antiforgery
tokens, cookies echoed into headers, JSON session keys) are *carried forward*
with extraction code instead of placeholders. Only user-supplied inputs
(passwords, search terms) and values with no producer step stay as
``PLACEHOLDER_*`` keyword defaults of ``run(**inputs)``.
"""

from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from hardly.core.redact import is_sensitive_key
from hardly.core.story import portal_story

_MAX_CODE_CHARS = 60_000


class _Expr:
    """Raw Python source embedded in generated code."""

    def __init__(self, code: str) -> None:
        self.code = code


class _Spread:
    def __init__(self, code: str) -> None:
        self.code = code


_HELPERS = '''\
def _hidden_fields(html: str) -> dict[str, str]:
    """All <input type=hidden> fields (name -> value) in an HTML document."""
    found: dict[str, str] = {}

    class _P(HTMLParser):
        def handle_starttag(self, tag, attrs):
            if tag != "input":
                return
            a = {k.lower(): (v or "") for k, v in attrs}
            if a.get("type", "").lower() == "hidden":
                name = a.get("name") or a.get("id")
                if name:
                    found[name] = a.get("value", "")

    _P().feed(html)
    return found


def _hidden(html: str, name: str) -> str:
    fields = _hidden_fields(html)
    assert name in fields, f"hidden field {name!r} not found in previous response"
    return fields[name]


def _cookie(jar: CookieJar, name: str) -> str:
    """Current cookie value, URL-decoded (e.g. XSRF-TOKEN -> X-XSRF-TOKEN)."""
    for c in jar:
        if c.name == name and c.value is not None:
            return unquote(c.value)
    raise AssertionError(f"cookie {name!r} not set by an earlier response")


def _unwrap_json(text: str):
    """Parse JSON, then keep parsing while the result is itself a JSON string."""
    value = json.loads(text)
    while isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            break
    return value


def _deep_find(obj, key: str):
    if isinstance(obj, dict):
        if key in obj:
            return obj[key]
        children = list(obj.values())
    elif isinstance(obj, list):
        children = obj
    else:
        return None
    for child in children:
        if isinstance(child, str) and child.lstrip()[:1] in "{[":
            try:
                child = _unwrap_json(child)
            except ValueError:
                continue
        found = _deep_find(child, key)
        if found is not None:
            return found
    return None


def _json_path(text: str, path: str) -> str:
    """Value at dotted path ("a.b.0.c") of a possibly double-encoded JSON body.

    Falls back to a deep search for the last path segment.
    """
    cur = _unwrap_json(text)
    root = cur
    for part in path.split("."):
        if isinstance(cur, str) and cur.lstrip()[:1] in "{[":
            cur = _unwrap_json(cur)
        try:
            cur = cur[int(part)] if isinstance(cur, list) else cur[part]
        except (KeyError, IndexError, ValueError, TypeError):
            cur = _deep_find(root, path.rsplit(".", 1)[-1])
            break
    assert cur is not None, f"JSON path {path!r} not found in previous response"
    return str(cur)
'''


def client_stub(
    conn: sqlite3.Connection,
    *,
    entry_ids: list[int] | None = None,
    host: str | None = None,
    output_path: str | Path | None = None,
    class_name: str = "PortalClient",
) -> dict[str, Any]:
    """Build a redacted urllib client for the given entries (or a portal story)."""
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

    hits: list[dict[str, Any]] = []
    try:
        from hardly.core.correlate import correlate_tokens

        hits = list(
            correlate_tokens(conn, host=None, limit=80).get("correlations") or []
        )
    except Exception:  # noqa: BLE001
        hits = []

    position = {eid: i for i, eid in enumerate(ids)}
    wires: dict[int, list[dict[str, Any]]] = {}
    unwired: list[str] = []
    seen_wire: set[tuple] = set()
    for h in hits:
        to_id, from_id = h.get("to_entry_id"), h.get("from_entry_id")
        if to_id not in position or from_id not in position:
            continue
        if position[from_id] >= position[to_id]:
            continue
        if h.get("to_where") == "cookie":
            continue  # cookie jar replays Set-Cookie automatically
        key = (to_id, h.get("to_where"), h.get("to_name_hint"))
        if key in seen_wire:
            continue
        seen_wire.add(key)
        if _source_expr(conn, h) is None or not h.get("to_name_hint"):
            unwired.append(
                f"# Correlate {h.get('name_hint') or 'value'}: entry {from_id} → "
                f"{to_id} ({h.get('to_where')}) — wire by hand"
            )
            continue
        wires.setdefault(int(to_id), []).append(h)

    inputs: dict[str, str] = {}
    steps_code: list[str] = []
    used_hosts: set[str] = set()
    for entry_id in ids:
        piece = _entry_step(conn, entry_id, wires.get(entry_id, []), inputs)
        if not piece:
            continue
        used_hosts.add(piece["host"])
        steps_code.append(piece["code"])

    if not steps_code:
        return {"error": "no stubbable entries", "entry_ids": ids}

    base = next(iter(used_hosts)) if len(used_hosts) == 1 else "https://example.com"
    defaults = (
        "INPUT_DEFAULTS = {\n"
        + "".join(f"    {k!r}: {v!r},\n" for k, v in sorted(inputs.items()))
        + "}"
        if inputs
        else "INPUT_DEFAULTS: dict[str, str] = {}"
    )
    head = (
        '"""Auto-generated client from hardly_stub — review before use.\n\n'
        "Tokens issued by earlier responses (hidden fields, antiforgery values,\n"
        "cookies, JSON keys) are extracted at run time. User inputs are\n"
        "PLACEHOLDER_* defaults of run(**inputs); never commit live credentials.\n"
        f'Generated for host hints: {", ".join(sorted(used_hosts))}.\n'
        '"""\n\n'
        "from __future__ import annotations\n\n"
        "import json\n"
        "from html.parser import HTMLParser\n"
        "from http.cookiejar import CookieJar\n"
        "from urllib.parse import unquote, urlencode\n"
        "from urllib.request import HTTPCookieProcessor, Request, build_opener\n\n"
        f"BASE = {base!r}\n"
        "UA = (\n"
        '    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "\n'
        '    "(KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36"\n'
        ")\n"
        f"{defaults}\n\n\n"
    )
    cls = (
        f"class {class_name}:\n"
        "    def __init__(self) -> None:\n"
        "        self._jar = CookieJar()\n"
        "        self._opener = build_opener(HTTPCookieProcessor(self._jar))\n"
        "        self.resp: dict[int, str] = {}  # entry_id -> response body\n\n"
        "    def _fetch(\n"
        "        self,\n"
        "        method: str,\n"
        "        url: str,\n"
        "        data: bytes | None = None,\n"
        "        headers: dict[str, str] | None = None,\n"
        "    ) -> tuple[int, str]:\n"
        '        sent = {"User-Agent": UA, "Accept": "*/*"}\n'
        "        if headers:\n"
        "            sent.update(headers)\n"
        "        req = Request(url, data=data, headers=sent, method=method)\n"
        "        with self._opener.open(req, timeout=60) as resp:\n"
        '            return int(resp.status), resp.read().decode("utf-8", "replace")\n\n'
        "    def run(self, **inputs: str) -> None:\n"
        "        # Steps follow capture order; pass user inputs as keywords.\n"
        "        inp = {**INPUT_DEFAULTS, **inputs}\n"
    )
    blocks = ([("\n".join(unwired[:12]))] if unwired else []) + steps_code
    indented = "\n".join(_indent(b.rstrip() + "\n", "        ") for b in blocks)
    code = (
        head
        + _HELPERS
        + "\n\n"
        + cls
        + "\n"
        + indented
        + "\n\nif __name__ == \"__main__\":\n    "
        + class_name
        + "().run()\n"
    )
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
        "inputs": sorted(inputs),
        "code": code if not written else None,
        "note": (
            "Tokens are carried forward from earlier responses; user inputs are "
            "run(**inputs) keywords. Verify paths/fields against hardly_story / "
            "live probes. When output_path is set, code is written to disk and "
            "omitted here."
        ),
    }


def _indent(text: str, prefix: str) -> str:
    return "".join(
        (prefix + line) if line.strip() else line for line in text.splitlines(True)
    )


def _json_key_path(text: str | None, key: str) -> str:
    """Dotted path to ``key`` in a (possibly truncated) JSON preview, else key."""
    try:
        data = json.loads(text or "")
        while isinstance(data, str) and data.lstrip()[:1] in ("{", "["):
            data = json.loads(data)
    except (ValueError, TypeError):
        return key

    def walk(obj: Any, trail: list[str], depth: int) -> list[str] | None:
        if depth > 6:
            return None
        if isinstance(obj, dict):
            if key in obj and isinstance(obj[key], str):
                return trail + [key]
            for k, v in obj.items():
                r = walk(v, trail + [str(k)], depth + 1)
                if r:
                    return r
        elif isinstance(obj, list) and obj:
            return walk(obj[0], trail + ["0"], depth + 1)
        return None

    found = walk(data, [], 0)
    return ".".join(found) if found else key


def _source_expr(conn: sqlite3.Connection, hit: dict[str, Any]) -> str | None:
    where = hit.get("from_where")
    name = hit.get("from_name_hint")
    src = hit.get("from_entry_id")
    if not name or src is None:
        return None
    if where == "set-cookie":
        return f"_cookie(self._jar, {name!r})"
    if where == "html.hidden":
        return f"_hidden(self.resp[{src}], {name!r})"
    if where == "response.json":
        row = conn.execute(
            "SELECT preview_text FROM bodies WHERE entry_id = ? AND side = 'response'",
            (src,),
        ).fetchone()
        path = _json_key_path(row["preview_text"] if row else None, name)
        return f"_json_path(self.resp[{src}], {path!r})"
    return None


def _render(obj: Any, level: int = 0) -> str:
    pad = "    " * (level + 1)
    end = "    " * level
    if isinstance(obj, _Expr):
        return obj.code
    if isinstance(obj, dict):
        if not obj:
            return "{}"
        rows = []
        for k, v in obj.items():
            if isinstance(v, _Spread):
                rows.append(f"{pad}**{v.code},")
            else:
                rows.append(f"{pad}{json.dumps(k)}: {_render(v, level + 1)},")
        return "{\n" + "\n".join(rows) + f"\n{end}}}"
    if isinstance(obj, list):
        if not obj:
            return "[]"
        rows = [f"{pad}{_render(v, level + 1)}," for v in obj]
        return "[\n" + "\n".join(rows) + f"\n{end}]"
    return repr(obj)


def _input(name: str, inputs: dict[str, str]) -> _Expr:
    key = _slug(name).lower()
    inputs.setdefault(key, f"PLACEHOLDER_{_slug(name).upper()}")
    return _Expr(f"inp[{key!r}]")


def _entry_step(
    conn: sqlite3.Connection,
    entry_id: int,
    wires: list[dict[str, Any]],
    inputs: dict[str, str],
) -> dict[str, Any] | None:
    row = conn.execute(
        "SELECT * FROM entries WHERE entry_id = ?", (entry_id,)
    ).fetchone()
    if not row:
        return None
    base_url = f"{row['scheme']}://{row['host']}{row['path']}"
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
    interesting: dict[str, Any] = {
        k: v
        for k, v in headers.items()
        if k.lower()
        in {"content-type", "accept", "x-requested-with", "origin", "referer"}
    }
    # Authorization/API-key headers: keep the scheme, never the value.
    for k in list(headers):
        low = k.lower()
        if low == "authorization":
            shape = conn.execute(
                "SELECT shape FROM value_shapes WHERE entry_id = ? "
                "AND lower(name) = 'authorization' LIMIT 1",
                (entry_id,),
            ).fetchone()
            basic = bool(shape) and shape["shape"] == "basic_auth"
            interesting[k] = (
                "Basic PLACEHOLDER_BASIC_CREDENTIALS" if basic
                else "Bearer PLACEHOLDER_TOKEN"
            )
        elif low in {"api_key", "api-key", "apikey", "x-api-key", "x-auth-token", "x-access-token"}:
            interesting[k] = f"PLACEHOLDER_{low.upper().replace('-', '_')}"
    by_where: dict[str, list[dict[str, Any]]] = {}
    for w in wires:
        by_where.setdefault(w["to_where"], []).append(w)

    method = row["method"]
    lines = [f"# entry_id={entry_id} {method} {row['path']}"]

    # --- URL (query params may be carried) --------------------------------
    query_wires = {w["to_name_hint"]: w for w in by_where.get("query", [])}
    if query_wires and row["query_raw"]:
        query: dict[str, Any] = {}
        for k, v in parse_qsl(row["query_raw"], keep_blank_values=True):
            if k in query_wires:
                w = query_wires[k]
                lines.append(
                    f"# {k}: carried from entry {w['from_entry_id']} "
                    f"({w['from_where']})"
                )
                query[k] = _Expr(_source_expr(conn, w))
            elif is_sensitive_key(k) or len(v) > 80:
                query[k] = _input(k, inputs)
            else:
                query[k] = v
        lines.append(f"query = {_render(query)}")
        lines.append(f"url = {base_url!r} + '?' + urlencode(query)")
    else:
        url = base_url + (f"?{row['query_raw']}" if row["query_raw"] else "")
        lines.append(f"url = {url!r}")

    # --- headers ----------------------------------------------------------
    hdr_wires = by_where.get("header", [])
    hdrs: dict[str, Any] = dict(interesting)
    lower = {k.lower(): k for k in headers}
    for w in hdr_wires:
        hname = lower.get(w["to_name_hint"], w["to_name_hint"])
        lines.append(
            f"# {hname}: carried from entry {w['from_entry_id']} ({w['from_where']})"
        )
        hdrs[hname] = _Expr(_source_expr(conn, w))
    for w in by_where.get("authorization", []):
        scheme = "Bearer " if "bearer" in str(headers.get("Authorization", "")).lower() else ""
        lines.append(
            f"# Authorization: carried from entry {w['from_entry_id']} "
            f"({w['from_where']})"
        )
        hdrs["Authorization"] = _Expr(f"{scheme!r} + {_source_expr(conn, w)}")
    lines.append(f"hdrs = {_render(hdrs)}")

    # --- body -------------------------------------------------------------
    send = ""
    raw = body_row["preview_text"] if body_row else None
    if method != "GET" and raw:
        ct = (body_row["content_type"] or "").lower()
        if "json" in ct or raw.lstrip().startswith(("{", "[")):
            lines.append(f"payload = {_render(_json_placeholder(raw, inputs))}")
            for w in by_where.get("request.json", []):
                path = _json_key_path(raw, w["to_name_hint"]).split(".")
                target = "payload" + "".join(
                    f"[{int(p)}]" if p.isdigit() else f"[{p!r}]" for p in path
                )
                lines.append(
                    f"# {w['to_name_hint']}: carried from entry "
                    f"{w['from_entry_id']} ({w['from_where']})"
                )
                lines.append(f"{target} = {_source_expr(conn, w)}")
            lines.append("hdrs = {**hdrs, 'Content-Type': 'application/json'}")
            send = ", data=json.dumps(payload).encode()"
        else:
            form_wires = {w["to_name_hint"]: w for w in by_where.get("request.form", [])}
            hidden_srcs = sorted(
                {
                    w["from_entry_id"]
                    for w in form_wires.values()
                    if w["from_where"] == "html.hidden"
                }
            )
            carry_all = bool(hidden_srcs)
            form: dict[str, Any] = {}
            if carry_all:
                src = hidden_srcs[0]
                lines.append(
                    f"# hidden fields (VIEWSTATE, antiforgery, ...) carried "
                    f"from entry {src}"
                )
                form["**"] = _Spread(f"_hidden_fields(self.resp[{src}])")
            for name, val in parse_qsl(raw, keep_blank_values=True)[:40]:
                if not name:
                    continue
                if name in form_wires:
                    w = form_wires[name]
                    if w["from_where"] == "html.hidden" and carry_all:
                        continue  # already in the hidden-field spread
                    lines.append(
                        f"# {name}: carried from entry {w['from_entry_id']} "
                        f"({w['from_where']})"
                    )
                    form[name] = _Expr(_source_expr(conn, w))
                elif carry_all and _ALWAYS_PLACEHOLDER.match(name):
                    if re.match(r"^__EVENT(TARGET|ARGUMENT)$", name, re.I):
                        form[name] = val
                    # other token-ish hidden fields come from the spread
                elif (
                    is_sensitive_key(name)
                    or _ALWAYS_PLACEHOLDER.match(name)
                    or len(val) > 80
                ):
                    form[name] = _input(name, inputs)
                else:
                    form[name] = val
            lines.append(f"form = {_render(form)}")
            send = ", data=urlencode(form).encode()"

    lines.append(
        f"status, body = self._fetch({method!r}, url{send}, headers=hdrs)"
    )
    lines.append(f"self.resp[{entry_id}] = body")
    lines.append("assert status < 400, (status, body[:200])")
    return {
        "host": f"{row['scheme']}://{row['host']}",
        "code": "\n".join(lines),
    }


_ALWAYS_PLACEHOLDER = re.compile(
    r"^(__(VIEWSTATE|EVENTVALIDATION|VIEWSTATEGENERATOR|EVENTTARGET|"
    r"EVENTARGUMENT|REQUESTVERIFICATIONTOKEN).*|"
    r".*(csrf|xsrf|nonce).*)$",
    re.I,
)


def _json_placeholder(text: str, inputs: dict[str, str]) -> Any:
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return {}
    return _redact_obj(data, inputs)


def _redact_obj(data: Any, inputs: dict[str, str]) -> Any:
    if isinstance(data, dict):
        out = {}
        for key, value in list(data.items())[:40]:
            if is_sensitive_key(str(key)):
                out[key] = _input(str(key), inputs)
            else:
                out[key] = _redact_obj(value, inputs)
        return out
    if isinstance(data, list):
        return [_redact_obj(data[0], inputs)] if data else []
    if isinstance(data, str) and len(data) > 80:
        return "PLACEHOLDER_LONG"
    return data


def _slug(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "_", name).strip("_") or "FIELD"
