"""Compact HTML/XML outlines for MCP agents (no Playwright required).

Playwright's live ``page.ariaSnapshot()`` (YAML accessibility tree) is the gold
standard for *rendered* pages. This module approximates useful outlines from
stored HAR bodies with stdlib parsers so agents never ingest raw markup.
"""

from __future__ import annotations

import re
import sqlite3
import xml.etree.ElementTree as ET
from html.parser import HTMLParser
from typing import Any
from xml.etree.ElementTree import ParseError

from hardly.core.redact import is_sensitive_key, redact_string

_MAX_DEPTH = 14
_MAX_NODES = 400
_MAX_TEXT = 80
_MAX_MD_LINES = 200
_MAX_TABLE_ROWS = 8
_MAX_TABLE_COLS = 8

_STRUCT = frozenset(
    {
        "html",
        "head",
        "body",
        "main",
        "header",
        "footer",
        "nav",
        "section",
        "article",
        "aside",
        "div",
        "span",
        "form",
        "fieldset",
        "label",
        "table",
        "thead",
        "tbody",
        "tfoot",
        "tr",
        "th",
        "td",
        "ul",
        "ol",
        "li",
        "dl",
        "dt",
        "dd",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "p",
        "a",
        "button",
        "input",
        "select",
        "textarea",
        "option",
        "img",
        "svg",
        "iframe",
        "details",
        "summary",
        "dialog",
        "menu",
        "caption",
    }
)

_SKIP = frozenset(
    {
        "script",
        "style",
        "noscript",
        "template",
        "svg",
        "path",
        "meta",
        "link",
        "br",
        "hr",
        "wbr",
    }
)

_VOID = frozenset(
    {
        "area",
        "base",
        "br",
        "col",
        "embed",
        "hr",
        "img",
        "input",
        "link",
        "meta",
        "param",
        "source",
        "track",
        "wbr",
    }
)

_ROLE_FOR_TAG = {
    "a": "link",
    "button": "button",
    "input": None,  # depends on type
    "select": "combobox",
    "textarea": "textbox",
    "img": "img",
    "nav": "navigation",
    "main": "main",
    "header": "banner",
    "footer": "contentinfo",
    "form": "form",
    "table": "table",
    "tr": "row",
    "th": "columnheader",
    "td": "cell",
    "ul": "list",
    "ol": "list",
    "li": "listitem",
    "h1": "heading",
    "h2": "heading",
    "h3": "heading",
    "h4": "heading",
    "h5": "heading",
    "h6": "heading",
    "dialog": "dialog",
    "summary": "button",
}

_WS = re.compile(r"\s+")


def outline_markup(
    text: str,
    *,
    mime: str | None = None,
    path: str | None = None,
    format: str = "all",
    max_depth: int = 8,
) -> dict[str, Any]:
    """Build outline(s) from an HTML or XML string.

    ``format``: ``markdown`` | ``tree`` | ``aria`` | ``all``.
    """
    raw = (text or "").strip()
    if not raw:
        return {"error": "empty body", "format": format}
    kind = _detect_kind(raw, mime=mime, path=path)
    depth = max(1, min(int(max_depth), _MAX_DEPTH))
    fmt = (format or "all").lower()

    if kind == "xml":
        nodes = _parse_xml_tree(raw, max_depth=depth)
        source = "xml.etree"
    else:
        nodes = _parse_html_tree(raw, max_depth=depth)
        source = "html.parser"

    out: dict[str, Any] = {
        "markup_kind": kind,
        "parser": source,
        "node_count": _count_nodes(nodes),
        "note": (
            "Offline outline from stored body — not the live accessibility tree. "
            "For rendered ARIA YAML use hardly_capture_aria (Playwright "
            "page.ariaSnapshot) during a headed capture."
        ),
    }
    if fmt in {"markdown", "all"}:
        out["markdown"] = _to_markdown(nodes, kind=kind)
    if fmt in {"tree", "all"}:
        out["tree"] = _to_tree_lines(nodes)
    if fmt in {"aria", "all"}:
        out["aria"] = _to_aria_yaml(nodes)
    return out


def outline_entry(
    conn: sqlite3.Connection,
    entry_id: int,
    *,
    side: str = "response",
    format: str = "all",
    max_depth: int = 8,
) -> dict[str, Any]:
    """Outline HTML/XML from an indexed HAR entry body."""
    row = conn.execute(
        """
        SELECT e.entry_id, e.method, e.host, e.path, e.mime,
               b.preview_text, b.content_type, b.size
        FROM entries e
        LEFT JOIN bodies b ON b.entry_id = e.entry_id AND b.side = ?
        WHERE e.entry_id = ?
        """,
        (side, entry_id),
    ).fetchone()
    if not row:
        return {"error": f"entry_id {entry_id} not found"}
    body = row["preview_text"] or ""
    if not body.strip():
        return {
            "error": "no body preview",
            "entry_id": entry_id,
            "hint": "Re-capture with body backfill, or check omit-content / size=-1",
            "mime": row["content_type"] or row["mime"],
            "size": row["size"],
        }
    result = outline_markup(
        body,
        mime=row["content_type"] or row["mime"],
        path=row["path"],
        format=format,
        max_depth=max_depth,
    )
    result.update(
        {
            "entry_id": entry_id,
            "method": row["method"],
            "host": row["host"],
            "path": row["path"],
            "mime": row["content_type"] or row["mime"],
            "body_size": row["size"],
            "side": side,
        }
    )
    return result


# --- parsers -----------------------------------------------------------------


class _Node:
    __slots__ = ("tag", "attrs", "children", "text", "tail")

    def __init__(self, tag: str, attrs: dict[str, str] | None = None) -> None:
        self.tag = tag
        self.attrs = attrs or {}
        self.children: list[_Node] = []
        self.text = ""
        self.tail = ""


class _HtmlOutlineParser(HTMLParser):
    def __init__(self, *, max_depth: int) -> None:
        super().__init__(convert_charrefs=True)
        self.root = _Node("#document")
        self._stack: list[_Node] = [self.root]
        self._skip_depth = 0
        self._max_depth = max_depth
        self._nodes = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        t = tag.lower()
        if self._skip_depth:
            if t not in _VOID and t not in {"script", "style", "noscript", "template"}:
                # nested inside skip — still track for endtag balance via skip
                pass
            if t in {"script", "style", "noscript", "template"}:
                self._skip_depth += 1
            return
        if t in {"script", "style", "noscript", "template"}:
            self._skip_depth = 1
            return
        if t not in _STRUCT and t not in _ROLE_FOR_TAG and t not in {
            "html",
            "body",
            "head",
        }:
            # Keep unknown interactive-ish tags with role/id
            ad_pre = {k.lower(): (v or "") for k, v in attrs}
            if not (ad_pre.get("role") or ad_pre.get("id") or ad_pre.get("name")):
                return
        if len(self._stack) - 1 >= self._max_depth or self._nodes >= _MAX_NODES:
            return
        ad = {}
        for k, v in attrs:
            key = k.lower()
            if key in {
                "id",
                "class",
                "name",
                "type",
                "role",
                "href",
                "action",
                "method",
                "for",
                "alt",
                "title",
                "aria-label",
                "aria-labelledby",
                "placeholder",
                "value",
                "checked",
                "disabled",
                "readonly",
                "required",
                "colspan",
                "rowspan",
                "scope",
            } or key.startswith("data-"):
                val = v or ""
                if is_sensitive_key(key) or is_sensitive_key(val[:40]):
                    val = redact_string(val)[:40]
                elif len(val) > 120:
                    val = val[:117] + "..."
                ad[key] = val
        node = _Node(t, ad)
        self._stack[-1].children.append(node)
        self._nodes += 1
        if t not in _VOID:
            self._stack.append(node)

    def handle_endtag(self, tag: str) -> None:
        t = tag.lower()
        if self._skip_depth:
            if t in {"script", "style", "noscript", "template"}:
                self._skip_depth = max(0, self._skip_depth - 1)
            return
        # pop until tag
        for i in range(len(self._stack) - 1, 0, -1):
            if self._stack[i].tag == t:
                self._stack = self._stack[:i]
                break

    def handle_data(self, data: str) -> None:
        if self._skip_depth or len(self._stack) < 2:
            return
        text = _WS.sub(" ", data).strip()
        if not text:
            return
        cur = self._stack[-1]
        if len(cur.text) < _MAX_TEXT:
            cur.text = (cur.text + " " + text).strip()[:_MAX_TEXT]


def _parse_html_tree(html: str, *, max_depth: int) -> _Node:
    p = _HtmlOutlineParser(max_depth=max_depth)
    try:
        p.feed(html[:250_000])
        p.close()
    except Exception:  # noqa: BLE001
        pass
    return p.root


def _parse_xml_tree(text: str, *, max_depth: int) -> _Node:
    try:
        root_el = ET.fromstring(text[:250_000])
    except ParseError:
        # Fall back to HTML parser for XHTML-ish / broken XML
        return _parse_html_tree(text, max_depth=max_depth)
    root = _Node("#document")

    def walk(el: ET.Element, parent: _Node, depth: int) -> None:
        if depth > max_depth or _count_nodes(root) >= _MAX_NODES:
            return
        tag = el.tag.split("}")[-1].lower() if isinstance(el.tag, str) else "node"
        if tag in _SKIP and tag != "svg":
            return
        ad = {}
        for k, v in (el.attrib or {}).items():
            key = k.split("}")[-1].lower()
            if key in {
                "id",
                "name",
                "type",
                "role",
                "href",
                "class",
            } or key.startswith("data-"):
                val = str(v)
                if is_sensitive_key(key):
                    val = redact_string(val)[:40]
                ad[key] = val[:120]
        node = _Node(tag, ad)
        text = _WS.sub(" ", (el.text or "")).strip()
        if text:
            node.text = text[:_MAX_TEXT]
        parent.children.append(node)
        for child in list(el)[:80]:
            walk(child, node, depth + 1)

    walk(root_el, root, 1)
    return root


def _detect_kind(text: str, *, mime: str | None, path: str | None) -> str:
    m = (mime or "").lower()
    p = (path or "").lower()
    if "xml" in m and "html" not in m:
        return "xml"
    if p.endswith(".xml") or p.endswith(".aspx.resx"):
        return "xml"
    s = text.lstrip()
    if s.startswith("<?xml") or (s.startswith("<") and "html" not in s[:200].lower() and "xhtml" not in s[:200].lower()):
        # Heuristic: root looks like XML application payload
        if re.match(r"<\?xml\b", s) or re.match(r"<([A-Za-z_][\w:.-]*)\b[^>]*>", s):
            if "<html" not in s[:500].lower() and "<!doctype html" not in s[:200].lower():
                if "xml" in m or p.endswith(".xml") or s.startswith("<?xml"):
                    return "xml"
    return "html"


def _count_nodes(node: _Node) -> int:
    return 1 + sum(_count_nodes(c) for c in node.children)


# --- renderers ---------------------------------------------------------------


def _to_markdown(root: _Node, *, kind: str) -> str:
    lines: list[str] = []
    if kind == "xml":
        lines.append("_XML document outline (offline)_")
    else:
        lines.append("_HTML document outline (offline)_")
    lines.append("")

    def walk(node: _Node, list_prefix: str = "") -> None:
        if len(lines) >= _MAX_MD_LINES:
            return
        tag = node.tag
        if tag == "#document":
            for c in node.children:
                walk(c)
            return
        text = _safe_text(node.text)
        name = _accessible_name(node)

        if tag in {"h1", "h2", "h3", "h4", "h5", "h6"}:
            level = int(tag[1])
            lines.append(f"{'#' * level} {text or name or tag}")
            lines.append("")
        elif tag == "p" and text:
            lines.append(text)
            lines.append("")
        elif tag == "a":
            href = node.attrs.get("href") or ""
            label = text or name or href or "link"
            if href and not href.startswith(("javascript:", "#")):
                lines.append(f"- [{label}]({href})")
            else:
                lines.append(f"- {label}")
        elif tag == "button" or (
            tag == "input" and node.attrs.get("type", "text").lower() in {
                "submit",
                "button",
                "reset",
            }
        ):
            lines.append(f"- **button** {name or text or node.attrs.get('value') or 'unnamed'}")
        elif tag == "input":
            t = node.attrs.get("type", "text")
            nm = node.attrs.get("name") or name or "input"
            lines.append(f"- input[{t}] `{nm}`" + (f" — {text}" if text else ""))
        elif tag in {"select", "textarea"}:
            lines.append(f"- **{tag}** `{node.attrs.get('name') or name or ''}`")
        elif tag == "form":
            action = node.attrs.get("action") or ""
            method = (node.attrs.get("method") or "get").upper()
            lines.append(f"### Form {method} `{action}`")
            lines.append("")
            for c in node.children:
                walk(c)
            return
        elif tag == "table":
            _md_table(node, lines)
            return
        elif tag in {"ul", "ol"}:
            for c in node.children:
                if c.tag == "li":
                    item = _safe_text(c.text) or _accessible_name(c) or "(item)"
                    lines.append(f"- {item}")
                    for gc in c.children:
                        if gc.tag not in {"ul", "ol"}:
                            walk(gc)
            lines.append("")
            return
        elif tag in {"nav", "main", "header", "footer", "section", "article", "aside"}:
            title = name or tag
            lines.append(f"## {title}")
            lines.append("")
        elif tag == "img":
            alt = node.attrs.get("alt") or name or "image"
            lines.append(f"- image: {alt}")
        elif text and tag in {"div", "span", "label", "td", "th", "li", "dt", "dd", "caption"}:
            # Only emit leaf-ish text blocks to avoid noise
            if not node.children and text:
                lines.append(f"- {text}")

        for c in node.children:
            walk(c)

    walk(root)
    if len(lines) >= _MAX_MD_LINES:
        lines.append("…")
    return "\n".join(lines).strip() + "\n"


def _md_table(table: _Node, lines: list[str]) -> None:
    rows: list[list[str]] = []
    headers: list[str] = []

    def cells(tr: _Node, header: bool = False) -> list[str]:
        out = []
        for c in tr.children:
            if c.tag in {"th", "td"}:
                out.append(_safe_text(c.text) or _accessible_name(c) or "")
        return out[:_MAX_TABLE_COLS]

    def scan(node: _Node) -> None:
        if node.tag == "tr":
            if any(c.tag == "th" for c in node.children) and not headers:
                headers.extend(cells(node, True))
            else:
                rows.append(cells(node))
        for c in node.children:
            scan(c)

    scan(table)
    if not headers and rows:
        headers = [f"c{i+1}" for i in range(len(rows[0]))]
    if not headers:
        lines.append("_empty table_")
        lines.append("")
        return
    lines.append("| " + " | ".join(headers) + " |")
    lines.append("| " + " | ".join("---" for _ in headers) + " |")
    for row in rows[:_MAX_TABLE_ROWS]:
        padded = row + [""] * (len(headers) - len(row))
        lines.append("| " + " | ".join(padded[: len(headers)]) + " |")
    if len(rows) > _MAX_TABLE_ROWS:
        lines.append(f"_… {len(rows) - _MAX_TABLE_ROWS} more rows_")
    lines.append("")


def _to_tree_lines(root: _Node) -> list[str]:
    lines: list[str] = []

    def walk(node: _Node, depth: int) -> None:
        if len(lines) >= _MAX_MD_LINES:
            return
        if node.tag == "#document":
            for c in node.children:
                walk(c, depth)
            return
        indent = "  " * depth
        bits = [node.tag]
        if node.attrs.get("id"):
            bits.append(f"#{node.attrs['id']}")
        cls = node.attrs.get("class")
        if cls:
            bits.append("." + ".".join(cls.split()[:3]))
        if node.attrs.get("name"):
            bits.append(f"name={node.attrs['name']}")
        if node.attrs.get("type"):
            bits.append(f"type={node.attrs['type']}")
        if node.attrs.get("role"):
            bits.append(f"role={node.attrs['role']}")
        for dk, dv in node.attrs.items():
            if dk.startswith("data-") and any(
                x in dk for x in ("id", "href", "url", "action", "document")
            ):
                bits.append(f"{dk}={dv[:40]}")
        text = _safe_text(node.text)
        suffix = f' "{text}"' if text and not node.children else (
            f' "{text}"' if text and len(node.children) <= 1 else ""
        )
        lines.append(f"{indent}{' '.join(bits)}{suffix}")
        for c in node.children:
            walk(c, depth + 1)

    walk(root, 0)
    if len(lines) >= _MAX_MD_LINES:
        lines.append("…")
    return lines


def _to_aria_yaml(root: _Node) -> str:
    """Approximate Playwright aria-snapshot YAML from static markup."""
    lines: list[str] = []

    def walk(node: _Node, depth: int) -> None:
        if len(lines) >= _MAX_MD_LINES:
            return
        if node.tag == "#document":
            for c in node.children:
                walk(c, depth)
            return
        role = _role_for(node)
        if role is None and node.tag in {"div", "span"} and not node.attrs.get("role"):
            # Skip presentational wrappers but keep children
            for c in node.children:
                walk(c, depth)
            return
        if role is None:
            role = node.tag
        name = _accessible_name(node) or _safe_text(node.text)
        indent = "  " * depth
        attrs = []
        if role == "heading" and node.tag.startswith("h") and node.tag[1:].isdigit():
            attrs.append(f"level={node.tag[1]}")
        if node.attrs.get("type") and role in {"textbox", "button", "checkbox", "radio"}:
            attrs.append(f"type={node.attrs['type']}")
        if "disabled" in node.attrs:
            attrs.append("disabled")
        if node.attrs.get("checked") is not None or node.attrs.get("type") == "checkbox":
            if "checked" in node.attrs:
                attrs.append("checked")
        attr_s = (" [" + ", ".join(attrs) + "]") if attrs else ""
        if name:
            lines.append(f'{indent}- {role} "{_yaml_escape(name)}"{attr_s}')
        else:
            lines.append(f"{indent}- {role}{attr_s}")
        for c in node.children:
            # Avoid duplicating leaf text as child
            walk(c, depth + 1)

    walk(root, 0)
    if len(lines) >= _MAX_MD_LINES:
        lines.append("…")
    return "\n".join(lines) + ("\n" if lines else "")


def _role_for(node: _Node) -> str | None:
    if node.attrs.get("role"):
        return node.attrs["role"]
    tag = node.tag
    if tag == "input":
        t = (node.attrs.get("type") or "text").lower()
        return {
            "checkbox": "checkbox",
            "radio": "radio",
            "submit": "button",
            "button": "button",
            "reset": "button",
            "hidden": None,
            "password": "textbox",
            "email": "textbox",
            "search": "textbox",
            "text": "textbox",
            "number": "textbox",
            "tel": "textbox",
            "url": "textbox",
            "file": "button",
        }.get(t, "textbox")
    return _ROLE_FOR_TAG.get(tag)


def _accessible_name(node: _Node) -> str:
    for key in ("aria-label", "alt", "title", "placeholder"):
        if node.attrs.get(key):
            return _safe_text(node.attrs[key])
    if node.attrs.get("name") and node.tag in {"input", "select", "textarea", "button"}:
        return _safe_text(node.attrs["name"])
    return ""


def _safe_text(text: str | None) -> str:
    if not text:
        return ""
    t = _WS.sub(" ", text).strip()
    if is_sensitive_key(t[:40]):
        return redact_string(t)[:_MAX_TEXT]
    return t[:_MAX_TEXT]


def _yaml_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"')
