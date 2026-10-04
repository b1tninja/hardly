"""Extract forms / inputs / links / handlers from HTML (stdlib only).

Returns a compact, redacted inventory so agents can reverse guest portals
without loading full response bodies into context.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin

from hardly.core.htmlsafe import defuse_html
from hardly.core.redact import REDACTED, is_sensitive_key, redact_string, redact_url

_MAX_VALUE_CHARS = 80
_MAX_OPTIONS = 30
_MAX_FORMS = 20
_MAX_FIELDS = 80
_MAX_LOOSE = 40
_MAX_LINKS = 60
_MAX_HANDLERS = 60
_MAX_ACTIONS = 60
_MAX_LABELS = 60
_MAX_SIGNAL_SAMPLES = 12
_MAX_HANDLER_CHARS = 120

_SIGNAL_ATTRS = (
    "data-documentid",
    "data-href",
    "data-action",
    "data-url",
    "data-function",
    "formaction",
)

_HANDLER_ATTRS = (
    "onclick",
    "ondblclick",
    "onsubmit",
    "onchange",
    "onmousedown",
    "onmouseup",
    "onkeydown",
    "onload",
)

_FUNC_CALL = re.compile(r"\b([A-Za-z_$][\w$]*)\s*\(")
_SKIP_LINK_PREFIX = (
    "mailto:",
    "tel:",
    "data:",
    "#",
)
_SKIP_LINK_SUFFIX = (
    ".css",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".woff",
    ".ico",
)

_INTERACTIVE_RE = re.compile(
    r"<(?:form|input|select|textarea|a|button|area)\b|on(?:click|submit|change|dblclick)\s*=",
    re.I,
)
_DETAIL_RE = re.compile(
    r"detailLabel|docDetailRow|listDocDetails|formInput|<th\b|<dt\b|"
    r"font-weight-bolder|fc\d+span|\bclass=\"[^\"]*\bbase\b",
    re.I,
)

# Label div next to value div (detailLabel-style layouts)
_LABEL_ROW = re.compile(
    r'<div\b[^<>]*\bclass="[^"]*\bdetailLabel\b[^"]*"[^<>]*>\s*(.*?)\s*</div>\s*'
    r'<div\b[^<>]*\bclass="[^"]*\b(?:formInput|listDocDetails)\b[^"]*"[^<>]*>\s*(.*?)\s*</div>',
    re.I | re.S,
)
_TH_TD = re.compile(
    r"<tr\b[^<>]*>\s*<th\b[^<>]*>\s*(.*?)\s*</th>\s*<td\b[^<>]*>\s*(.*?)\s*</td>",
    re.I | re.S,
)
_DT_DD = re.compile(
    r"<dt\b[^<>]*>\s*(.*?)\s*</dt>\s*<dd\b[^<>]*>\s*(.*?)\s*</dd>",
    re.I | re.S,
)
# Bootstrap-style detail tables: bold label cell → value cell
_TD_BOLDER = re.compile(
    r'<td\b[^<>]*\bclass="[^"]*\bfont-weight-bolder\b[^"]*"[^<>]*>\s*(.*?)\s*</td>\s*'
    r"<td\b[^<>]*>\s*(.*?)\s*</td>",
    re.I | re.S,
)
# Label span cells: <td><span class="base" id="fcNspan">Label:</span></td><td>value</td>
# (ids are fc1span / fc2span / …; allow attributes in either order)
_TD_SPAN_BASE = re.compile(
    r"<td\b[^<>]*>\s*<span\b(?=[^<>]*\b(?:class=\"[^\"]*\bbase\b[^\"]*\"|id=\"fc\d+span\"))[^<>]*>"
    r"\s*(.*?)\s*</span>\s*</td>\s*<td\b[^<>]*>\s*(.*?)\s*</td>",
    re.I | re.S,
)
_TAG = re.compile(r"<[^<>]+>")

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


def extract_html_structure(html: str, *, base_url: str = "") -> dict[str, Any]:
    """Parse HTML into forms, links, handlers, labels, and portal-ish signals."""
    empty = {
        "forms": [],
        "loose_inputs": [],
        "links": [],
        "actions": [],
        "handlers": [],
        "handler_functions": [],
        "labels": [],
        "signals": {},
        "webforms": {"aspnet": False},
        "form_count": 0,
        "link_count": 0,
        "handler_count": 0,
        "label_count": 0,
        "field_count": 0,
    }
    if not (html or "").strip() or "<" not in html:
        return empty
    interactive = bool(_INTERACTIVE_RE.search(html))
    detailish = bool(_DETAIL_RE.search(html))
    if not interactive and not detailish:
        return empty

    forms: list[dict[str, Any]] = []
    loose: list[dict[str, Any]] = []
    links: list[dict[str, Any]] = []
    actions: list[dict[str, Any]] = []
    handlers: list[dict[str, Any]] = []
    functions: list[dict[str, Any]] = []
    signals: dict[str, Any] = {}
    if interactive:
        parser = _FormParser(base_url=base_url)
        try:
            parser.feed(defuse_html(html))
            parser.close()
        except Exception:  # noqa: BLE001 — broken HTML still yields partial inventory
            pass
        forms = [_finalize_form(f) for f in parser.forms[:_MAX_FORMS]]
        loose = [_finalize_field(f) for f in parser.loose[:_MAX_LOOSE]]
        links = parser.links[:_MAX_LINKS]
        actions = parser.actions[:_MAX_ACTIONS]
        handlers = parser.handlers[:_MAX_HANDLERS]
        functions = _summarize_handler_functions(handlers)
        signals = _summarize_signals(parser.signals)

    labels = extract_labeled_fields(html)
    webforms = detect_webforms(html)
    return {
        "forms": forms,
        "loose_inputs": loose,
        "links": links,
        "actions": actions,
        "handlers": handlers,
        "handler_functions": functions,
        "labels": labels,
        "signals": signals,
        "webforms": webforms,
        "form_count": len(forms),
        "link_count": len(links),
        "handler_count": len(handlers),
        "label_count": len(labels),
        "field_count": sum(len(f.get("fields") or []) for f in forms) + len(loose),
    }


_DOPOSTBACK = re.compile(
    r"""__doPostBack\s*\(\s*['"]([^'"]*)['"]\s*,\s*['"]([^'"]*)['"]\s*\)""",
    re.I,
)
_WF_HIDDEN = re.compile(
    r"""name\s*=\s*['"](__(?:VIEWSTATE|EVENTVALIDATION|VIEWSTATEGENERATOR|"""
    r"""EVENTTARGET|EVENTARGUMENT|REQUESTVERIFICATIONTOKEN)[^'"]*)['"]""",
    re.I,
)


def detect_webforms(html: str) -> dict[str, Any]:
    """ASP.NET WebForms / anti-forgery markers useful for client stubs."""
    if not html:
        return {"aspnet": False}
    postbacks = []
    for m in _DOPOSTBACK.finditer(html):
        postbacks.append({"target": m.group(1), "argument": m.group(2)})
        if len(postbacks) >= 20:
            break
    hidden = []
    for m in _WF_HIDDEN.finditer(html):
        name = m.group(1)
        if name not in hidden:
            hidden.append(name)
        if len(hidden) >= 20:
            break
    aspnet = bool(
        postbacks
        or any(n.startswith("__VIEWSTATE") or n.startswith("__EVENT") for n in hidden)
        or "aspnetForm" in html
        or "__VIEWSTATE" in html
    )
    return {
        "aspnet": aspnet,
        "hidden_fields": hidden,
        "dopostback": postbacks[:12],
        "dopostback_count": len(postbacks),
    }


def extract_labeled_fields(html: str) -> list[dict[str, Any]]:
    """Read-only label/value rows (detail pages, definition lists, tables)."""
    if not (html or "").strip():
        return []
    found: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    def add(label: str, value: str, *, source: str) -> None:
        lab = _clean_label(label)
        val = _clean_label(value)
        if not lab or lab.lower() in {"", "&nbsp;"}:
            return
        key = (lab.lower(), val[:80])
        if key in seen:
            return
        seen.add(key)
        if len(found) >= _MAX_LABELS:
            return
        found.append(
            {
                "label": lab,
                "value": _shape_value(lab, val) or "",
                "source": source,
            }
        )

    for label, value in _LABEL_ROW.findall(html):
        add(label, value, source="detailLabel")
    for label, value in _TH_TD.findall(html):
        add(label, value, source="th/td")
    for label, value in _DT_DD.findall(html):
        add(label, value, source="dt/dd")
    for label, value in _TD_BOLDER.findall(html):
        add(label, value, source="td/bolder")
    for label, value in _TD_SPAN_BASE.findall(html):
        add(label, value, source="td/span.base")
    return found


def _clean_label(value: str) -> str:
    from html import unescape

    text = unescape(_TAG.sub(" ", value or ""))
    text = re.sub(r"\s+", " ", text).replace("\xa0", " ").strip()
    return text.rstrip(":").strip()


class _FormParser(HTMLParser):
    def __init__(self, *, base_url: str = "") -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.forms: list[dict[str, Any]] = []
        self.loose: list[dict[str, Any]] = []
        self.links: list[dict[str, Any]] = []
        self.handlers: list[dict[str, Any]] = []
        self.actions: list[dict[str, Any]] = []
        self._action: dict[str, Any] | None = None
        self._action_text: list[str] = []
        self.signals: list[dict[str, str]] = []
        self._form: dict[str, Any] | None = None
        self._select: dict[str, Any] | None = None
        self._in_option = False
        self._option_value: str | None = None
        self._option_selected = False
        self._option_text: list[str] = []
        self._textarea: dict[str, Any] | None = None
        self._textarea_text: list[str] = []
        self._link: dict[str, Any] | None = None
        self._link_text: list[str] = []
        # XPath stack: each frame is (tag, nth-of-type among siblings)
        self._stack: list[tuple[str, int]] = []
        self._sibling_counts: list[dict[str, int]] = [{}]

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        ad = {k.lower(): (v if v is not None else "") for k, v in attrs}
        self._enter(tag)
        xpath = self._xpath(ad)
        self._note_signals(tag, ad)
        self._note_handlers(tag, ad, xpath=xpath)
        self._note_action(tag, ad, xpath)

        if tag == "form":
            action = ad.get("action") or ""
            if self.base_url and action and not action.startswith(
                ("http://", "https://", "//")
            ):
                action = urljoin(self.base_url, action)
            self._form = {
                "action": redact_url(action),
                "method": (ad.get("method") or "get").upper(),
                "id": ad.get("id") or "",
                "name": ad.get("name") or "",
                "enctype": ad.get("enctype") or "",
                "onsubmit": ad.get("onsubmit") or "",
                "xpath": xpath,
                "fields": [],
            }
            if tag in _VOID:
                self._leave(tag)
            return
        if tag in ("a", "area"):
            href = ad.get("href") or ad.get("data-href") or ""
            if href.strip().lower().startswith("javascript:"):
                # javascript: URLs are click handlers, not navigations.
                if len(self.handlers) < _MAX_HANDLERS:
                    code = href.split(":", 1)[1]
                    self.handlers.append(
                        {
                            "tag": tag,
                            "attr": "href",
                            "id": ad.get("id") or "",
                            "name": ad.get("name") or "",
                            "class": (ad.get("class") or "")[:80],
                            "code": _shape_handler(code),
                            "functions": _handler_functions(code),
                            "in_form": self._form is not None,
                            "xpath": xpath,
                        }
                    )
                if tag in _VOID:
                    self._leave(tag)
                return
            link = _shape_link(tag, href, ad, base_url=self.base_url)
            if link is not None:
                link["xpath"] = xpath
                self._link = link
                self._link_text = []
            if tag in _VOID:
                self._leave(tag)
            return
        if tag == "input":
            self._add_field(
                {
                    "kind": "input",
                    "type": (ad.get("type") or "text").lower(),
                    "name": ad.get("name") or "",
                    "id": ad.get("id") or "",
                    "value": ad.get("value") or "",
                    "checked": "checked" in ad,
                    "disabled": "disabled" in ad,
                    "xpath": xpath,
                }
            )
            self._leave(tag)
            return
        if tag == "button":
            self._add_field(
                {
                    "kind": "button",
                    "type": (ad.get("type") or "submit").lower(),
                    "name": ad.get("name") or "",
                    "id": ad.get("id") or "",
                    "value": ad.get("value") or "",
                    "checked": False,
                    "disabled": "disabled" in ad,
                    "xpath": xpath,
                }
            )
            # Buttons often navigate via formaction without being an <a>
            formaction = ad.get("formaction") or ""
            if formaction:
                link = _shape_link("button", formaction, ad, base_url=self.base_url)
                if link is not None:
                    link["text"] = ad.get("value") or ""
                    link["xpath"] = xpath
                    if len(self.links) < _MAX_LINKS:
                        self.links.append(link)
            return
        if tag == "select":
            self._select = {
                "kind": "select",
                "type": "select",
                "name": ad.get("name") or "",
                "id": ad.get("id") or "",
                "value": "",
                "checked": False,
                "disabled": "disabled" in ad,
                "xpath": xpath,
                "options": [],
            }
            return
        if tag == "option" and self._select is not None:
            self._in_option = True
            self._option_value = ad["value"] if "value" in ad else None
            self._option_selected = "selected" in ad
            self._option_text = []
            return
        if tag == "textarea":
            self._textarea = {
                "kind": "textarea",
                "type": "textarea",
                "name": ad.get("name") or "",
                "id": ad.get("id") or "",
                "value": "",
                "checked": False,
                "disabled": "disabled" in ad,
                "xpath": xpath,
            }
            self._textarea_text = []
            return
        if tag in _VOID:
            self._leave(tag)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        if tag not in _VOID and self._stack and self._stack[-1][0] == tag:
            self._leave(tag)

    def handle_endtag(self, tag: str) -> None:
        if self._action is not None and tag == self._action["tag"]:
            self._close_action()
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None
        elif tag in ("a", "area") and self._link is not None:
            text = re.sub(r"\s+", " ", "".join(self._link_text)).strip()
            if text:
                self._link["text"] = _shape_value("link_text", text) or ""
            if len(self.links) < _MAX_LINKS:
                self.links.append(self._link)
            self._link = None
            self._link_text = []
        elif tag == "option" and self._select is not None and self._in_option:
            text = "".join(self._option_text).strip()
            value = self._option_value if self._option_value is not None else text
            opts = self._select.setdefault("options", [])
            if len(opts) < _MAX_OPTIONS:
                row: dict[str, Any] = {
                    "value": _shape_value("option", value),
                    "selected": self._option_selected,
                }
                if text and text != value:
                    row["label"] = _shape_value("option_label", text)
                opts.append(row)
            if self._option_selected and not self._select.get("value"):
                self._select["value"] = value
            self._in_option = False
            self._option_value = None
            self._option_selected = False
            self._option_text = []
        elif tag == "select" and self._select is not None:
            self._add_field(self._select)
            self._select = None
        elif tag == "textarea" and self._textarea is not None:
            self._textarea["value"] = "".join(self._textarea_text)
            self._add_field(self._textarea)
            self._textarea = None
            self._textarea_text = []
        self._leave(tag)

    def handle_data(self, data: str) -> None:
        if self._in_option:
            self._option_text.append(data)
        if self._textarea is not None:
            self._textarea_text.append(data)
        if self._link is not None:
            self._link_text.append(data)
        if self._action is not None:
            self._action_text.append(data)

    def _note_action(self, tag: str, ad: dict[str, str], xpath: str) -> None:
        """Track JS-driven click targets (no navigable href) with visible text."""
        if self._action is not None:
            return
        href = (ad.get("href") or "").strip().lower()
        has_js = bool(ad.get("onclick")) or href.startswith("javascript:")
        is_input_btn = tag == "input" and (ad.get("type") or "").lower() in {
            "submit", "button", "image",
        }
        if tag == "a" and (has_js or href in {"", "#"}):
            kind = "postback" if "__dopostback" in (ad.get("href", "") + ad.get("onclick", "")).lower() else "js_link"
        elif tag == "button":
            kind = "button"
        elif is_input_btn:
            kind = "button"
        else:
            return
        action = {
            "kind": kind,
            "tag": tag,
            "id": ad.get("id") or "",
            "name": ad.get("name") or "",
            "text": "",
            "xpath": xpath,
        }
        if tag == "input":
            action["text"] = _shape_value("link_text", ad.get("value") or ad.get("alt") or "") or ""
            self._append_action(action)
            return
        self._action = action
        self._action_text = []

    def _append_action(self, action: dict[str, Any]) -> None:
        if len(self.actions) < _MAX_ACTIONS and (action["text"] or action["id"]):
            self.actions.append(action)

    def _close_action(self) -> None:
        action = self._action
        self._action = None
        if action is None:
            return
        text = re.sub(r"\s+", " ", "".join(self._action_text)).strip()
        action["text"] = _shape_value("link_text", text) or ""
        self._action_text = []
        self._append_action(action)

    def _enter(self, tag: str) -> None:
        counts = self._sibling_counts[-1]
        counts[tag] = counts.get(tag, 0) + 1
        self._stack.append((tag, counts[tag]))
        if tag not in _VOID:
            self._sibling_counts.append({})

    def _leave(self, tag: str) -> None:
        while self._stack:
            top, _ = self._stack[-1]
            self._stack.pop()
            if top not in _VOID and self._sibling_counts:
                self._sibling_counts.pop()
            if top == tag:
                break
        if not self._sibling_counts:
            self._sibling_counts = [{}]

    def _xpath(self, ad: dict[str, str] | None = None) -> str:
        el_id = (ad or {}).get("id") or ""
        if el_id and re.fullmatch(r"[A-Za-z_][\w:.-]*", el_id):
            return f'//*[@id="{el_id}"]'
        if not self._stack:
            return "/"
        # Deeply nested markup: only the innermost 64 steps (a //-rooted, still valid path), so a
        # page with thousands of unclosed elements cannot make every lookup O(depth).
        deep = len(self._stack) > 64
        steps = self._stack[-64:] if deep else self._stack
        return ("//" if deep else "/") + "/".join(f"{name}[{idx}]" for name, idx in steps)

    def _add_field(self, field: dict[str, Any]) -> None:
        if self._form is not None:
            fields = self._form["fields"]
            if len(fields) < _MAX_FIELDS:
                fields.append(field)
        elif len(self.loose) < _MAX_LOOSE:
            self.loose.append(field)

    def _note_signals(self, tag: str, ad: dict[str, str]) -> None:
        for key in _SIGNAL_ATTRS:
            if ad.get(key):
                self.signals.append({"tag": tag, "attr": key, "value": ad[key]})
        name = ad.get("name") or ""
        if name.startswith(
            ("field_", "NameList", "ctl00$", "__VIEWSTATE", "SearchOn")
        ):
            self.signals.append({"tag": tag, "attr": "name", "value": name})

    def _note_handlers(
        self, tag: str, ad: dict[str, str], *, xpath: str = ""
    ) -> None:
        for attr in _HANDLER_ATTRS:
            code = ad.get(attr) or ""
            if not code.strip():
                continue
            if len(self.handlers) >= _MAX_HANDLERS:
                return
            shaped = _shape_handler(code)
            functions = _handler_functions(code)
            self.handlers.append(
                {
                    "tag": tag,
                    "attr": attr,
                    "id": ad.get("id") or "",
                    "name": ad.get("name") or "",
                    "class": (ad.get("class") or "")[:80],
                    "code": shaped,
                    "functions": functions,
                    "in_form": self._form is not None,
                    "xpath": xpath,
                }
            )


def _shape_link(
    tag: str, href: str, ad: dict[str, str], *, base_url: str
) -> dict[str, Any] | None:
    raw = (href or "").strip()
    if not raw:
        return None
    lower = raw.lower()
    if lower.startswith("javascript:"):
        # Treat as a handler surface, not a navigation link.
        return None
    if any(lower.startswith(p) for p in _SKIP_LINK_PREFIX):
        if lower == "#" or lower.startswith("#"):
            # Keep in-page anchors only when they look like app routes (#/path)
            if not lower.startswith("#/"):
                return None
        else:
            return None
    path_only = raw.split("?", 1)[0].split("#", 1)[0].lower()
    if any(path_only.endswith(suf) for suf in _SKIP_LINK_SUFFIX):
        return None
    resolved = raw
    if base_url and not raw.startswith(("http://", "https://", "//", "#")):
        resolved = urljoin(base_url, raw)
    resolved, raw = redact_url(resolved), redact_url(raw)
    return {
        "tag": tag,
        "href": _shape_value("href", resolved) or "",
        "href_raw": _shape_value("href", raw) or "",
        "id": ad.get("id") or "",
        "name": ad.get("name") or "",
        "target": ad.get("target") or "",
        "text": "",
        "data_href": _shape_value("data-href", ad.get("data-href") or "") or None,
    }


def _shape_handler(code: str) -> str:
    text = redact_string(code.strip())
    if text == REDACTED:
        return REDACTED
    text = re.sub(r"\s+", " ", text)
    if len(text) > _MAX_HANDLER_CHARS:
        return f"{text[:_MAX_HANDLER_CHARS]}…(len={len(code)})"
    return text


def _handler_functions(code: str) -> list[str]:
    skip = {
        "if",
        "for",
        "while",
        "switch",
        "function",
        "return",
        "typeof",
        "new",
        "void",
        "catch",
        "with",
    }
    found: list[str] = []
    for name in _FUNC_CALL.findall(code or ""):
        if name in skip or name in found:
            continue
        found.append(name)
        if len(found) >= 8:
            break
    return found


def _summarize_handler_functions(handlers: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    attrs: dict[str, set[str]] = {}
    for row in handlers:
        for name in row.get("functions") or []:
            counts[name] = counts.get(name, 0) + 1
            attrs.setdefault(name, set()).add(row.get("attr") or "")
    return [
        {
            "name": name,
            "count": counts[name],
            "attrs": sorted(attrs[name]),
        }
        for name in sorted(counts, key=lambda n: (-counts[n], n))
    ][:40]


def _finalize_form(form: dict[str, Any]) -> dict[str, Any]:
    fields = [_finalize_field(f) for f in form.get("fields") or []]
    names = [f.get("name") for f in fields if f.get("name")]
    out: dict[str, Any] = {
        "action": form.get("action") or "",
        "method": form.get("method") or "GET",
        "id": form.get("id") or "",
        "name": form.get("name") or "",
        "enctype": form.get("enctype") or "",
        "xpath": form.get("xpath") or "",
        "field_count": len(fields),
        "field_names": names[:_MAX_FIELDS],
        "fields": fields,
    }
    token_pair = _named_token_pair(form.get("fields") or [])
    if token_pair:
        out["anti_forgery"] = token_pair
    onsubmit = form.get("onsubmit") or ""
    if onsubmit:
        out["onsubmit"] = _shape_handler(onsubmit)
        out["onsubmit_functions"] = _handler_functions(onsubmit)
    return out


def _named_token_pair(fields: list[dict[str, Any]]) -> dict[str, str] | None:
    """Detect the "token name indirection" anti-forgery pattern.

    One hidden field's *value* is the *name* of another hidden field that holds
    the token (e.g. ``token.name`` = ``token``). A client must read the first
    field to learn which parameter to send the token under. Technology-level:
    seen in several server frameworks, so no framework is named here.
    """
    hidden = {
        f.get("name"): f
        for f in fields
        if f.get("name") and (f.get("type") or "").lower() == "hidden"
    }
    for name, field in hidden.items():
        target = field.get("value")
        if not isinstance(target, str) or target == name or target not in hidden:
            continue
        if "token" not in f"{name} {target}".lower():
            continue
        return {
            "scheme": "named_token",
            "name_field": str(name),
            "token_field": target,
        }
    return None


def _finalize_field(field: dict[str, Any]) -> dict[str, Any]:
    name = field.get("name") or ""
    raw = field.get("value")
    out: dict[str, Any] = {
        "kind": field.get("kind") or "input",
        "type": field.get("type") or "",
        "name": name,
        "id": field.get("id") or "",
        "value": _shape_value(name, raw if isinstance(raw, str) else str(raw or "")),
    }
    if field.get("xpath"):
        out["xpath"] = field["xpath"]
    if field.get("checked"):
        out["checked"] = True
    if field.get("disabled"):
        out["disabled"] = True
    if field.get("options") is not None:
        out["options"] = field["options"]
        out["option_count"] = len(field["options"])
    return out


def _shape_value(name: str, value: str) -> str | None:
    if value is None:
        return None
    text = str(value)
    if not text:
        return ""
    if name and is_sensitive_key(name):
        return REDACTED
    text = redact_string(text)
    if text == REDACTED:
        return REDACTED
    if len(text) > _MAX_VALUE_CHARS:
        return f"{text[:_MAX_VALUE_CHARS]}…(len={len(text)})"
    return text


def _summarize_signals(signals: list[dict[str, str]]) -> dict[str, Any]:
    by_attr: dict[str, list[str]] = {}
    for row in signals:
        by_attr.setdefault(row["attr"], []).append(row["value"])
    out: dict[str, Any] = {}
    for attr, values in sorted(by_attr.items()):
        uniq: list[str] = []
        seen: set[str] = set()
        for value in values:
            shaped = _shape_value(attr, value) or ""
            if shaped in seen:
                continue
            seen.add(shaped)
            uniq.append(shaped)
            if len(uniq) >= _MAX_SIGNAL_SAMPLES:
                break
        out[attr] = {"count": len(values), "samples": uniq}
    return out
