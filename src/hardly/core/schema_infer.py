"""Infer lightweight schemas from JSON samples."""

from __future__ import annotations

from typing import Any


def _type_name(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int) and not isinstance(value, bool):
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


def _merge_types(a: str, b: str) -> str:
    if a == b:
        return a
    if a == "null":
        return f"{b}?"
    if b == "null":
        return f"{a}?"
    if a.endswith("?") and a[:-1] == b:
        return a
    if b.endswith("?") and b[:-1] == a:
        return b
    return f"{a}|{b}"


def infer_schema(samples: list[Any], *, max_depth: int = 8) -> dict:
    """Merge samples into a compact schema summary."""
    if not samples:
        return {"type": "unknown"}
    return _infer(samples, depth=0, max_depth=max_depth)


def _infer(samples: list[Any], *, depth: int, max_depth: int) -> dict:
    if depth > max_depth:
        return {"type": "any"}

    types: set[str] = set()
    for s in samples:
        types.add(_type_name(s))

    non_null = [s for s in samples if s is not None]
    if not non_null:
        return {"type": "null"}

    # Prefer object/array structure when present
    dicts = [s for s in non_null if isinstance(s, dict)]
    lists = [s for s in non_null if isinstance(s, list)]

    if dicts and not lists:
        return _infer_object(dicts, depth=depth, max_depth=max_depth, nullable="null" in types)
    if lists and not dicts:
        return _infer_array(lists, depth=depth, max_depth=max_depth, nullable="null" in types)

    type_str = samples[0]
    t = _type_name(non_null[0])
    for s in non_null[1:]:
        t = _merge_types(t, _type_name(s))
    if "null" in types and not t.endswith("?"):
        t = f"{t}?"
    return {"type": t}


def _infer_object(
    dicts: list[dict], *, depth: int, max_depth: int, nullable: bool
) -> dict:
    key_counts: dict[str, int] = {}
    key_samples: dict[str, list[Any]] = {}
    n = len(dicts)
    for d in dicts:
        for k, v in d.items():
            key_counts[k] = key_counts.get(k, 0) + 1
            key_samples.setdefault(k, []).append(v)

    properties = {}
    required = []
    for k, count in sorted(key_counts.items()):
        properties[k] = _infer(key_samples[k], depth=depth + 1, max_depth=max_depth)
        if count == n:
            required.append(k)
        else:
            properties[k]["optional"] = True

    result: dict[str, Any] = {"type": "object", "properties": properties}
    if required:
        result["required"] = required
    if nullable:
        result["nullable"] = True
    return result


def _infer_array(
    lists: list[list], *, depth: int, max_depth: int, nullable: bool
) -> dict:
    items: list[Any] = []
    for lst in lists:
        items.extend(lst[:20])  # sample items
    item_schema = _infer(items, depth=depth + 1, max_depth=max_depth) if items else {"type": "unknown"}
    result: dict[str, Any] = {"type": "array", "items": item_schema}
    if nullable:
        result["nullable"] = True
    lengths = [len(lst) for lst in lists]
    result["length_range"] = [min(lengths), max(lengths)]
    return result
