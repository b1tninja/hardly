"""Query one (possibly huge) HAR body without loading the whole HAR.

``query_body`` streams ``log.entries.item`` with ijson, keeps only the target
entry, and answers a JSONPath-lite query, a regex search, or a plain character
window - always capped, paged and redacted (sensitive keys / token-like values
come back as shapes, never values).

JSONPath-lite grammar: ``$`` root, ``.key``, ``['key']``, ``[n]`` (negative ok),
``[a:b]`` slice, ``[*]`` / ``.*`` wildcard, ``..key`` recursive descent.
"""

from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path
from typing import Any

from hardly.core.encodings import json_shape, type_name
from hardly.core.har_io import ijson_items
from hardly.core.redact import (
    REDACTED,
    classify_value_shape,
    is_sensitive_key,
    redact_form,
    redact_json,
    redact_markup_text,
    redact_string,
)
from hardly.core.safe_json import safe_loads

DEFAULT_LIMIT = 20
MAX_LIMIT = 200
MAX_PATTERN = 500
MAX_REDACT_CHARS = 2_000_000  # text modes redact this prefix once, then search/window the result
MAX_COUNT = 10_000
MAX_OUTPUT_CHARS = 12_000


class BodyQueryError(ValueError):
    pass


# ------------------------------------------------------------------ locating
def _har_path(src: Any) -> Path:
    if isinstance(src, sqlite3.Connection):
        row = src.execute("SELECT value FROM meta WHERE key = 'har_path'").fetchone()
        if not row:
            raise BodyQueryError("session has no har_path in meta")
        return Path(row[0])
    return Path(src)


def load_entry_body(
    har: Path, entry_id: int, side: str
) -> tuple[str | None, bytes | None, str | None]:
    """Stream the HAR to ``entry_id``; return (text, raw_bytes, mime)."""
    from hardly.index.ingest import _body_text, _raw_bytes

    if side not in ("request", "response"):
        raise BodyQueryError("side must be 'request' or 'response'")
    with har.open("rb") as f:
        for i, entry in enumerate(ijson_items(f, "log.entries.item")):
            if i != entry_id:
                continue
            if side == "request":
                content = (entry.get("request") or {}).get("postData")
            else:
                content = (entry.get("response") or {}).get("content")
            text, mime, _ = _body_text(content)
            raw = _raw_bytes(content, mime)
            if text is not None and text.startswith("(binary base64"):
                text = None
            return text, raw, mime
    raise BodyQueryError(f"entry_id {entry_id} not found")


# ------------------------------------------------------------------ JSONPath
_TOKEN = re.compile(
    r"""\.\.(?P<rec>[^.\[\s]+)
      | \.(?P<dot>\*|[^.\[\s]+)
      | \[(?P<br>[^\]]*)\]""",
    re.X,
)


def parse_jsonpath(expr: str) -> list[tuple[str, Any]]:
    e = expr.strip()
    if not e.startswith("$"):
        e = "$." + e if not e.startswith(("[", ".")) else "$" + e
    pos = 1
    steps: list[tuple[str, Any]] = []
    while pos < len(e):
        m = _TOKEN.match(e, pos)
        if not m:
            raise BodyQueryError(f"bad jsonpath at offset {pos}: {e[pos:pos + 12]!r}")
        pos = m.end()
        if m.group("rec") is not None:
            steps.append(("rec", m.group("rec")))
        elif m.group("dot") is not None:
            d = m.group("dot")
            steps.append(("wild", None) if d == "*" else ("key", d))
        else:
            b = m.group("br").strip()
            if b == "*":
                steps.append(("wild", None))
            elif re.fullmatch(r"-?\d+", b):
                steps.append(("idx", int(b)))
            elif re.fullmatch(r"-?\d*:-?\d*", b):
                a, _, c = b.partition(":")
                steps.append(("slice", (int(a) if a else None, int(c) if c else None)))
            elif len(b) >= 2 and b[0] == b[-1] and b[0] in "'\"":
                steps.append(("key", b[1:-1]))
            else:
                raise BodyQueryError(f"unsupported jsonpath selector [{b}]")
    return steps


def _children(node: Any, path: tuple):
    if isinstance(node, dict):
        for k, v in node.items():
            yield path + (k,), v
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield path + (i,), v


def _descend(node: Any, path: tuple, depth: int = 0):
    yield path, node
    if depth > 40:
        return
    for p, v in _children(node, path):
        yield from _descend(v, p, depth + 1)


def eval_jsonpath(data: Any, steps: list[tuple[str, Any]]):
    """Yield (path_tuple, value) for every match, lazily."""
    cur: list[tuple[tuple, Any]] = [((), data)]

    def apply(items, step):
        kind, arg = step
        for path, node in items:
            if kind == "key":
                if isinstance(node, dict) and arg in node:
                    yield path + (arg,), node[arg]
            elif kind == "idx":
                if isinstance(node, list) and -len(node) <= arg < len(node):
                    yield path + (arg % len(node),), node[arg]
            elif kind == "slice":
                if isinstance(node, list):
                    idxs = range(len(node))[slice(arg[0], arg[1])]
                    for i in idxs:
                        yield path + (i,), node[i]
            elif kind == "wild":
                yield from _children(node, path)
            elif kind == "rec":
                for p, v in _descend(node, path):
                    if p != path and isinstance(p[-1], str) and p[-1] == arg:
                        yield p, v
                    elif arg == "*" and p != path:
                        yield p, v

    stream: Any = cur
    for step in steps:
        stream = apply(stream, step)
    yield from stream


def _fmt_path(path: tuple) -> str:
    out = "$"
    for p in path:
        out += f"[{p}]" if isinstance(p, int) else (f".{p}" if re.fullmatch(r"[A-Za-z_]\w*", p) else f"['{p}']")
    return out


# ----------------------------------------------------------------- redaction
def _cap(s: str, n: int) -> str:
    return s if len(s) <= n else s[:n] + f"…(len={len(s)})"


def _present(value: Any, path: tuple, max_chars: int) -> dict[str, Any]:
    """Redacted, capped rendering of one match."""
    out: dict[str, Any] = {"path": _fmt_path(path), "type": type_name(value)}
    sens = any(isinstance(p, str) and is_sensitive_key(p) for p in path)
    if sens:
        out["redacted"] = True
        out["shape"] = (classify_value_shape(value) if isinstance(value, str) else None) or type_name(value)
        if isinstance(value, str):
            out["length"] = len(value)
        return out
    if isinstance(value, str):
        shape = classify_value_shape(value)
        if shape:
            out["shape"] = shape
            out["length"] = len(value)
        else:
            out["value"] = _cap(redact_json(value), max_chars)
        return out
    if isinstance(value, (dict, list)):
        red = redact_json(value)
        txt = json.dumps(red, default=str, ensure_ascii=False)
        out["size"] = len(value)
        if len(txt) <= max_chars:
            out["value"] = red
        else:
            out["shape"] = json_shape(value, max_depth=3)
            out["preview"] = txt[:max_chars] + "…"
        return out
    out["value"] = value if not hasattr(value, "as_tuple") else float(value)
    return out


_JSON_KV = re.compile(r'("(?P<k>[^"\\]{1,80})"\s*:\s*)"(?:[^"\\]|\\.){0,2000}"')


def redact_snippet(text: str) -> str:
    """Redact free text: sensitive JSON keys, tokens, form pairs."""

    def swap(m: re.Match) -> str:
        return m.group(1) + f'"{REDACTED}"' if is_sensitive_key(m.group("k")) else m.group(0)

    return redact_form(redact_markup_text(redact_string(_JSON_KV.sub(swap, text))))


def _parse_json_or_lines(text: str) -> Any:
    s = text.strip().lstrip("\ufeff")
    try:
        return safe_loads(s)
    except ValueError:
        pass
    rows = []
    for ln in s.splitlines():
        ln = ln.strip()
        if not ln:
            continue
        try:
            rows.append(safe_loads(ln))
        except ValueError:
            raise BodyQueryError("body is not JSON or JSON lines") from None
    if not rows:
        raise BodyQueryError("body is empty")
    return rows


# --------------------------------------------------------------------- entry
def query_body(
    har_path_or_conn: Any,
    entry_id: int,
    side: str = "response",
    jsonpath: str | None = None,
    regex: str | None = None,
    offset: int = 0,
    limit: int = DEFAULT_LIMIT,
    *,
    max_chars: int = 300,
    context: int = 40,
    ignore_case: bool = False,
) -> dict[str, Any]:
    """Query one body. Exactly one of jsonpath / regex, or neither for a char window.

    Returns ``{matches|window, total, offset, limit, has_more, next_offset, ...}``.
    jsonpath/regex offsets count matches; without either, offset counts characters.
    """
    offset = max(0, int(offset or 0))
    limit = max(1, min(int(limit or DEFAULT_LIMIT), MAX_LIMIT))
    if jsonpath and regex:
        raise BodyQueryError("pass jsonpath or regex, not both")
    har = _har_path(har_path_or_conn)
    if not har.exists():
        raise BodyQueryError(f"HAR not found: {har.name}")
    text, raw, mime = load_entry_body(har, entry_id, side)
    base: dict[str, Any] = {"entry_id": entry_id, "side": side, "mime": mime}

    if text is None:
        # Binary: answer with the stream-shape summary instead of bytes.
        from hardly.core.streams import analyze_body

        hit = analyze_body(mime, None, None, raw) if raw else None
        base.update(
            binary=True,
            size=len(raw) if raw else 0,
            stream=({"kind": hit[0], "summary": hit[1]} if hit else None),
            note="binary body: shape summary only",
        )
        return base

    from hardly.core.json_unwrap import unwrap_double_encoded

    inner = unwrap_double_encoded(text)
    if inner is not None:
        text = json.dumps(inner, ensure_ascii=False)
        base["double_encoded_unwrapped"] = True
    base["chars"] = len(text)
    max_chars = max(20, min(int(max_chars), 2000))

    if jsonpath:
        data = _parse_json_or_lines(text)
        steps = parse_jsonpath(jsonpath)
        matches: list[dict[str, Any]] = []
        total = 0
        budget = MAX_OUTPUT_CHARS
        for path, value in eval_jsonpath(data, steps):
            if total >= offset and len(matches) < limit and budget > 0:
                m = _present(value, path, max_chars)
                budget -= len(json.dumps(m, default=str))
                matches.append(m)
            total += 1
            if total >= MAX_COUNT:
                base["count_capped"] = True
                break
        end = offset + len(matches)
        base.update(
            jsonpath=jsonpath, matches=matches, total=total, offset=offset, limit=limit,
            has_more=end < total, next_offset=end if end < total else None,
        )
        return base

    if regex:
        if len(regex) > MAX_PATTERN:
            raise BodyQueryError("regex too long")
        try:
            rx = re.compile(regex, re.I if ignore_case else 0)
        except re.error as exc:
            raise BodyQueryError(f"bad regex: {exc}") from None
        # Search the REDACTED text: a secret value can neither match nor be cut out of context.
        scan = redact_snippet(text[:MAX_REDACT_CHARS])
        if len(text) > MAX_REDACT_CHARS:
            base["scan_truncated_at"] = MAX_REDACT_CHARS
        out: list[dict[str, Any]] = []
        total = 0
        budget = MAX_OUTPUT_CHARS
        for m in rx.finditer(scan):
            if total >= offset and len(out) < limit and budget > 0:
                a, b = m.start(), m.end()
                hit = m.group(0)
                shape = classify_value_shape(hit)
                shown = f"<{shape}>" if shape else _cap(hit, max_chars)
                pre = scan[max(0, a - context):a]
                post = scan[b:b + context]
                item = {
                    "at": a, "match": shown, "before": pre, "after": post,
                    "groups": [
                        (f"<{classify_value_shape(g)}>" if g and classify_value_shape(g) else _cap(g, 80))
                        if g is not None else None
                        for g in m.groups()[:6]
                    ],
                }
                budget -= len(json.dumps(item, default=str))
                out.append(item)
            total += 1
            if total >= MAX_COUNT:
                base["count_capped"] = True
                break
        end = offset + len(out)
        base.update(
            regex=regex, matches=out, total=total, offset=offset, limit=limit,
            has_more=end < total, next_offset=end if end < total else None,
        )
        return base

    # Plain window: offset/limit are characters.
    size = min(limit * 100, 4000) if limit <= MAX_LIMIT else 4000
    shown = redact_snippet(text[:MAX_REDACT_CHARS])  # redact the whole readable prefix, then window it
    chunk = shown[offset:offset + size]
    end = offset + len(chunk)
    base.update(
        window=chunk, offset=offset, length=len(chunk), total=len(shown),
        has_more=end < len(shown), next_offset=end if end < len(shown) else None,
        note="window offset/limit are characters of the redacted text (limit*100, max 4000)",
    )
    if len(text) > MAX_REDACT_CHARS:
        base["readable_prefix_chars"] = MAX_REDACT_CHARS
        base["note"] += f"; only the first {MAX_REDACT_CHARS} characters of a larger body are readable"
    return base
