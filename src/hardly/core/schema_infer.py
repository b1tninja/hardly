"""Infer schemas from JSON samples (all samples merged, secret-safe).

Node shape (keys appear only when relevant):

    type        object | array | string | integer | number | boolean | null |
                "a|b" for mixed scalars
    count       how many samples reached this node (nulls included)
    nullable    a null was seen here
    properties  {name: node}            (objects)
    required    [names present in every object sample]
    optional    True on a property missing from some object samples
    items       node                    (arrays; unions use ``oneOf``)
    oneOf       [node, ...]             (different shapes at one position)
    enum        low-cardinality, non-sensitive string values
    format      date | date-time | uuid | email | uri | id | money | jwt | hex | base64
    secret_shape  set instead of any value when the field looks sensitive
    length_range  [min, max]            (arrays)

Values are never kept except enum members, which are only emitted for
low-cardinality, plain-word strings under non-sensitive, non-personal keys.
"""

from __future__ import annotations

import json
import re
import sqlite3
from typing import Any

from hardly.core.redact import REDACTED, classify_value_shape, is_sensitive_key
from hardly.core.safe_json import safe_loads

MAX_ARRAY_ITEMS = 100
MAX_PROPERTIES = 120
ENUM_MAX_DISTINCT = 8
ENUM_MIN_SAMPLES = 3

_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_DATETIME_RE = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:?\d{2})?$")
_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_EMAIL_RE = re.compile(r"^[^@\s/]+@[^@\s/]+\.[A-Za-z]{2,}$")
_URL_RE = re.compile(r"^(https?://|//)[^\s]+$", re.I)
_MONEY_STR_RE = re.compile(r"^[-+]?[$€£]?\d{1,12}\.\d{2}$")
_MONEY_KEY_RE = re.compile(r"(price|amount|total|cost|balance|fee|subtotal|tax|charge|payment|salary)", re.I)
_ID_KEY_RE = re.compile(r"(^id$|_id$|Id$|^uid$)")
_WORD_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_ .-]{0,31}$")
# Keys whose values are personal / free text: never enumerate their values.
_PERSONAL_KEY_RE = re.compile(
    r"(name|email|phone|mobile|addr|street|city|zip|postal|user|owner|author|title|desc|text|comment|"
    r"message|note|body|label|subject|company|org|birth|dob|ssn|ip$)",
    re.I,
)


def _type_name(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return type(value).__name__


def _string_format(s: str) -> str | None:
    if not s or s == REDACTED:
        return None
    if _UUID_RE.match(s):
        return "uuid"
    if _DATE_RE.match(s):
        return "date"
    if _DATETIME_RE.match(s):
        return "date-time"
    if _EMAIL_RE.match(s):
        return "email"
    if _URL_RE.match(s):
        return "uri"
    shape = classify_value_shape(s)
    if shape in {"jwt", "hex", "base64"}:
        return shape
    if _MONEY_STR_RE.match(s):
        return "money"
    return None


def infer_schema(samples: list[Any], *, max_depth: int = 8) -> dict:
    """Merge every sample into one schema summary."""
    if not samples:
        return {"type": "unknown"}
    return _infer(samples, key=None, depth=0, max_depth=max_depth)


def _infer(samples: list[Any], *, key: str | None, depth: int, max_depth: int) -> dict:
    n = len(samples)
    if depth > max_depth:
        return {"type": "any", "count": n}
    non_null = [s for s in samples if s is not None]
    nullable = len(non_null) != n
    if not non_null:
        return {"type": "null", "count": n}

    groups: dict[str, list[Any]] = {}
    for s in non_null:
        t = _type_name(s)
        groups.setdefault(t, []).append(s)
    if "integer" in groups and "number" in groups:
        groups["number"] = groups.pop("integer") + groups["number"]

    nodes: list[dict] = []
    for t, vals in groups.items():
        if t == "object":
            nodes.extend(_infer_objects(vals, depth=depth, max_depth=max_depth))
        elif t == "array":
            nodes.append(_infer_array(vals, depth=depth, max_depth=max_depth))
        else:
            nodes.append(_infer_scalar(t, vals, key=key))

    if len(nodes) == 1:
        out = nodes[0]
    else:
        out = {
            "type": "|".join(dict.fromkeys(nd["type"] for nd in nodes)),
            "oneOf": nodes,
        }
    out["count"] = n
    if nullable:
        out["nullable"] = True
    return out


def _infer_scalar(t: str, vals: list[Any], *, key: str | None) -> dict:
    node: dict[str, Any] = {"type": t, "count": len(vals)}
    if t == "string":
        strs = [v for v in vals if isinstance(v, str)]
        fmts = {_string_format(s) for s in strs if s != REDACTED}
        fmt = next(iter(fmts)) if len(fmts) == 1 else None
        redacted = any(s == REDACTED for s in strs)
        if key and is_sensitive_key(key):
            node["secret_shape"] = fmt or ("redacted" if redacted else "opaque")
            return node
        if fmt in {"jwt", "hex", "base64"}:
            node["secret_shape"] = fmt
            return node
        if fmt:
            node["format"] = fmt
            return node
        if (
            key
            and not redacted
            and len(strs) >= ENUM_MIN_SAMPLES
            and not _PERSONAL_KEY_RE.search(key)
        ):
            distinct = sorted(set(strs))
            if (
                len(distinct) <= ENUM_MAX_DISTINCT
                and len(distinct) <= len(strs) // 2
                and all(_WORD_RE.match(v) and not classify_value_shape(v) for v in distinct)
            ):
                node["enum"] = distinct
    elif t == "integer":
        if key and _ID_KEY_RE.search(key):
            node["format"] = "id"
        elif key and _MONEY_KEY_RE.search(key):
            node["format"] = "money"
    elif t == "number":
        if key and _MONEY_KEY_RE.search(key):
            node["format"] = "money"
    return node


def _cluster_objects(dicts: list[dict]) -> list[list[dict]]:
    """Group objects whose key sets overlap enough to be one shape with optional fields."""
    clusters: list[tuple[set[str], list[dict]]] = []
    for d in dicts:
        keys = set(d)
        for union, members in clusters:
            inter = len(keys & union)
            if inter / max(1, len(keys | union)) >= 0.5 or (not keys and not union):
                union |= keys
                members.append(d)
                break
        else:
            clusters.append((set(keys), [d]))
    return [m for _, m in clusters]


def _infer_objects(dicts: list[dict], *, depth: int, max_depth: int) -> list[dict]:
    return [_infer_object(c, depth=depth, max_depth=max_depth) for c in _cluster_objects(dicts)]


def _infer_object(dicts: list[dict], *, depth: int, max_depth: int) -> dict:
    key_samples: dict[str, list[Any]] = {}
    for d in dicts:
        for k, v in d.items():
            key_samples.setdefault(str(k), []).append(v)
    n = len(dicts)
    properties: dict[str, Any] = {}
    required: list[str] = []
    names = sorted(key_samples)
    truncated = len(names) > MAX_PROPERTIES
    for k in names[:MAX_PROPERTIES]:
        vals = key_samples[k]
        node = _infer(vals, key=k, depth=depth + 1, max_depth=max_depth)
        if len(vals) == n:
            required.append(k)
        else:
            node["optional"] = True
        properties[k] = node
    result: dict[str, Any] = {"type": "object", "count": n, "properties": properties}
    if required:
        result["required"] = required
    if truncated:
        result["properties_truncated"] = len(names) - MAX_PROPERTIES
    return result


def _infer_array(lists: list[list], *, depth: int, max_depth: int) -> dict:
    items: list[Any] = []
    for lst in lists:
        items.extend(lst[:MAX_ARRAY_ITEMS])
    lengths = [len(lst) for lst in lists]
    result: dict[str, Any] = {
        "type": "array",
        "count": len(lists),
        "items": _infer(items, key=None, depth=depth + 1, max_depth=max_depth)
        if items
        else {"type": "unknown"},
        "length_range": [min(lengths), max(lengths)],
    }
    return result


def endpoint_samples(
    conn: sqlite3.Connection,
    *,
    method: str,
    host: str,
    path_template: str,
    exclude_noise: bool = False,
    limit: int = 500,
) -> list[dict]:
    """Every sampled call of an endpoint: ``{entry_id, status, request, response}`` (parsed JSON or None)."""
    sql = "SELECT entry_id, status FROM entries WHERE method = ? AND host = ? AND path_template IS ?"
    params: list[Any] = [method.upper(), host.lower(), path_template]
    if exclude_noise:
        sql += " AND is_noise = 0"
    rows = conn.execute(sql + " ORDER BY entry_id LIMIT ?", (*params, limit)).fetchall()
    out = []
    for r in rows:
        item = {"entry_id": r["entry_id"], "status": r["status"], "request": None, "response": None}
        for side in ("request", "response"):
            b = conn.execute(
                "SELECT preview_text FROM bodies WHERE entry_id = ? AND side = ?",
                (r["entry_id"], side),
            ).fetchone()
            text = b["preview_text"] if b else None
            if not text:
                continue
            try:
                parsed = safe_loads(text)
            except (json.JSONDecodeError, TypeError):
                continue
            if isinstance(parsed, str):
                from hardly.core.json_unwrap import unwrap_double_encoded

                inner = unwrap_double_encoded(text)
                if inner is not None:
                    parsed = inner
            item[side] = parsed
        out.append(item)
    return out
