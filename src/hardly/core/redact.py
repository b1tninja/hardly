"""Secret redaction for headers, bodies, and query params."""

from __future__ import annotations

import json
import re
from typing import Any

from hardly.core.safe_json import safe_loads

REDACTED = "***REDACTED***"

SENSITIVE_HEADER_NAMES = frozenset(
    {
        "authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "x-auth-token",
        "x-access-token",
        "x-csrf-token",
        "x-xsrf-token",
        "proxy-authorization",
        "x-amz-security-token",
    }
)

SENSITIVE_JSON_KEYS = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "token",
        "access_token",
        "refresh_token",
        "id_token",
        "api_key",
        "apikey",
        "authorization",
        "auth",
        "credentials",
        "private_key",
        "client_secret",
        "twofactorkey",
        "verificationkey",
        "session",
        "cookie",
        "jwt",
        "passcode",
        "passphrase",
        "accountnumber",
        "routingnumber",
        "cardnumber",
        "securitycode",
        "securityanswer",
        # anti-forgery values: replayable, so treated like credentials
        "csrf",
        "xsrf",
        "nonce",
        "authenticity",
    }
)

# Short names that are a secret only as the whole key ("Pwd" in Accela's sign-in, "pin"): matched exactly, so "shipping"
# or "pinned" are not redacted.
EXACT_SENSITIVE_KEYS = frozenset({"pwd", "pass", "pw", "pin", "otp", "ssn", "cvv", "cvc", "mfa", "code2fa"})

# Words that are secret only when they are the entire key.
_WHOLE_KEY_ONLY = frozenset({"auth", "credentials", "session", "cookie"})

# Query/path parameters whose values must not be echoed in URLs we report.
URL_SECRET_PARAMS = frozenset(
    {
        "code", "state", "nonce", "session_state", "id_token", "access_token",
        "refresh_token", "token", "ticket", "sig", "signature", "sid", "sessionid",
        "jsessionid", "phpsessid", "key", "apikey", "api_key", "auth", "password",
        "pwd", "secret", "client_secret", "assertion", "samlresponse", "samlrequest",
        "relaystate", "code_verifier", "otp", "verifier", "oauth_token",
    }
)
_PATH_PARAM_RE = re.compile(r"(;(?:jsessionid|sid|phpsessid|sessionid)=)[^/?#;&\"'\s<>]+", re.I)

JWT_RE = re.compile(
    r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"
)
LONG_HEX_RE = re.compile(r"\b[0-9a-fA-F]{32,}\b")
# URL-safe or std base64-ish blob (not a pure word); length keeps noise down.
BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/_=-])[A-Za-z0-9+/_-]{24,}={0,2}(?![A-Za-z0-9+/_=-])")
BEARER_RE = re.compile(r"^\s*Bearer\s+(\S+)\s*$", re.I)
BASIC_RE = re.compile(r"^\s*Basic\s+(\S+)\s*$", re.I)


def classify_value_shape(value: str | None) -> str | None:
    """Return a shape label for a secret-looking value — never echo the value.

    Labels: jwt | bearer_jwt | bearer_token | basic_auth | hex | base64 | uuid
    """
    if not value or not isinstance(value, str):
        return None
    text = value.strip()
    if not text or text == REDACTED:
        return None
    bearer = BEARER_RE.match(text)
    if bearer:
        inner = classify_value_shape(bearer.group(1))
        if inner == "jwt":
            return "bearer_jwt"
        return "bearer_token"
    if BASIC_RE.match(text):
        return "basic_auth"
    if JWT_RE.search(text):
        return "jwt"
    if re.fullmatch(
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        text,
    ):
        return "uuid"
    if LONG_HEX_RE.fullmatch(text) or (
        len(text) >= 32 and LONG_HEX_RE.fullmatch(text.replace("-", ""))
    ):
        return "hex"
    # Base64: long, alphabet-ish, not a plain English word.
    if len(text) >= 24 and BASE64_RE.fullmatch(text) and _looks_like_base64(text):
        # Prefer hex when the charset is only hex.
        if re.fullmatch(r"[0-9a-fA-F]+", text) and len(text) >= 32:
            return "hex"
        return "base64"
    return None


def _looks_like_base64(text: str) -> bool:
    """Reject kebab/snake/camel *words* (e.g. 'strict-origin-when-cross-origin')."""
    if text.isalpha() or text.islower() and "-" in text:
        return False
    if text.endswith("="):
        return True
    has_digit = any(c.isdigit() for c in text)
    has_upper = any(c.isupper() for c in text)
    has_lower = any(c.islower() for c in text)
    if "-" in text and re.fullmatch(r"[A-Za-z]+(?:-[A-Za-z]+)+", text):
        return False  # hyphenated words
    return has_digit and (has_upper or has_lower) or (has_upper and has_lower and len(text) >= 32)


def is_sensitive_header(name: str) -> bool:
    """Credential-bearing header: the known list plus any header NAMED like a secret (``X-Session-Token``)."""
    low = name.lower()
    return low in SENSITIVE_HEADER_NAMES or is_sensitive_key(name)


def is_sensitive_key(key: str) -> bool:
    k = key.lower().replace("-", "").replace("_", "")
    # An ASP.NET field name carries its control path ("ctl00$PlaceHolderMain$txtPwd"): judge its last part too.
    tail = re.split(r"[$.:\[\]]", key)[-1].lower().replace("-", "").replace("_", "") if key else k
    if k in EXACT_SENSITIVE_KEYS or tail in EXACT_SENSITIVE_KEYS:
        return True
    if tail.startswith(("txt", "tb")) and tail[3:] in EXACT_SENSITIVE_KEYS | {"password", "passwd"}:
        return True
    for s in SENSITIVE_JSON_KEYS:
        t = s.replace("_", "")
        if t in _WHOLE_KEY_ONLY:
            # Too generic as a substring: "authenticatorSelection",
            # "allowCredentials", "sessionCount"... are not secrets.
            if k == t:
                return True
        elif t in k:
            return True
    # also match keys that end with Token/Key/Secret/Password
    lower = key.lower()
    return any(
        lower.endswith(suf)
        for suf in ("token", "secret", "password", "passwd", "apikey")
    )


def _is_secret_param(name: str) -> bool:
    lowered = name.lower().replace("-", "_")
    return (
        lowered in URL_SECRET_PARAMS
        or lowered.replace("_", "") in URL_SECRET_PARAMS
        or is_sensitive_key(name)
    )


def redact_query_string(qs: str | None) -> str | None:
    """Replace values of secret-bearing query params; keep names and the rest."""
    if not qs or "=" not in qs:
        return qs
    pieces = []
    for chunk in qs.split("&"):
        name, sep, _val = chunk.partition("=")
        pieces.append(f"{name}={REDACTED}" if sep and _is_secret_param(name) else chunk)
    return "&".join(pieces)


def redact_query_dict(query: dict[str, Any] | None) -> dict[str, Any] | None:
    if not query:
        return query
    return {k: (REDACTED if _is_secret_param(str(k)) else v) for k, v in query.items()}


_LEN_MARKER_RE = re.compile(r"…\(len=\d+\)$")


def _split_len_marker(chunk: str) -> tuple[str, str]:
    """Split a trailing ``…(len=N)`` truncation marker off a query chunk."""
    m = _LEN_MARKER_RE.search(chunk)
    return (chunk[: m.start()], m.group(0)) if m else (chunk, "")


#: ``scheme://user:password@host``: the credentials part (never the host) is masked.
_USERINFO_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]{0,20}://)[^/?#@\s]{1,200}@")


def redact_url(url: str) -> str:
    """Hide secret-bearing query values and ``;jsessionid=`` style path params.

    Parameter *names* are kept so URLs stay useful for analysis.
    """
    if not url:
        return url
    out = _PATH_PARAM_RE.sub(lambda m: m.group(1) + REDACTED, url)
    out = _USERINFO_RE.sub(r"\1" + REDACTED + "@", out, count=1)
    if "?" not in out and "#" not in out:
        return out
    from urllib.parse import urlsplit, urlunsplit

    parts = urlsplit(out)

    def scrub(qs: str) -> str:
        if not qs or "=" not in qs:
            return qs
        pieces = []
        for chunk in qs.split("&"):
            chunk, marker = _split_len_marker(chunk)
            name, sep, val = chunk.partition("=")
            lowered = name.lower().replace("-", "_")
            bare = lowered.replace("_", "")
            if sep and (
                lowered in URL_SECRET_PARAMS or bare in URL_SECRET_PARAMS or is_sensitive_key(name)
            ):
                pieces.append(f"{name}={REDACTED}{marker}")
            else:
                pieces.append(chunk + marker)
        return "&".join(pieces)

    fragment = scrub(parts.fragment) if "=" in parts.fragment else parts.fragment
    return urlunsplit(parts._replace(query=scrub(parts.query), fragment=fragment))


_URL_STOP = frozenset(" \t\r\n<>\"'(),;[]{}|\\^`")
#: Longest URL-ish token examined (longer runs are cut, never scanned quadratically).
_MAX_URL_TOKEN = 8192


def redact_urls_in_text(text: str) -> str:
    """Mask secret query/fragment values of every URL-ish token in free text (linear time).

    A token is a run without whitespace or quoting delimiters around a ``?`` or ``#`` that is
    followed by ``name=value`` pairs: ``Location`` / ``Referer`` / ``Link`` header values, hrefs,
    URLs inside JSON strings.
    """
    if "=" not in text or ("?" not in text and "#" not in text):
        return text
    out: list[str] = []
    i, n = 0, len(text)
    while i < n:
        q = _next_anchor(text, i)
        if q < 0:
            break
        s = q
        while s > i and text[s - 1] not in _URL_STOP and q - s < _MAX_URL_TOKEN:
            s -= 1
        e = q + 1
        while e < n and text[e] not in _URL_STOP and e - q < _MAX_URL_TOKEN:
            e += 1
        tok = text[s:e]
        out.append(text[i:s])
        out.append(_redact_token(tok) if "=" in text[q:e] else tok)
        i = e
    out.append(text[i:])
    return "".join(out)


def _next_anchor(text: str, start: int) -> int:
    a, b = text.find("?", start), text.find("#", start)
    if a < 0:
        return b
    return a if b < 0 else min(a, b)


def _redact_token(tok: str) -> str:
    try:
        return redact_url(tok)
    except ValueError:  # urlsplit rejects some junk (bad IPv6 brackets)
        head, sep, tail = tok.partition("?")
        return head + sep + (redact_query_string(tail) or "") if sep else tok


def redact_string(value: str) -> str:
    if not value:
        return value
    out = _PATH_PARAM_RE.sub(lambda m: m.group(1) + REDACTED, JWT_RE.sub(REDACTED, value))
    out = redact_urls_in_text(out)
    # Only redact long hex if it looks like a secret (not in URLs as path ids alone)
    if len(value) >= 32 and LONG_HEX_RE.fullmatch(value.strip()):
        return REDACTED
    return out


def redact_header_value(name: str, value: str) -> str:
    if is_sensitive_header(name):
        return REDACTED
    return redact_string(value)  # also masks secret query values (Location, Referer, Link, ...)


def redact_headers(headers: list[dict] | dict) -> list[dict] | dict:
    if isinstance(headers, dict):
        return {k: redact_header_value(k, str(v)) for k, v in headers.items()}
    result = []
    for h in headers:
        name = h.get("name", "")
        value = h.get("value", "")
        result.append({"name": name, "value": redact_header_value(name, str(value))})
    return result


#: JSON larger than this is never parsed for a preview (memory); it takes the text path.
MAX_JSON_PARSE_CHARS = 8_000_000
#: A JSON document carried inside a JSON string (double-encoded) is unwrapped up to this size.
MAX_EMBEDDED_JSON_CHARS = 200_000
#: Pair objects whose "name"/"key" labels the secret and whose "value" holds it (HAR params, headers).
LABEL_KEYS = ("name", "key", "field", "header", "param", "id")


def redact_json(value: Any, *, depth: int = 0, max_depth: int = 12, markup: bool = True) -> Any:
    if depth > max_depth:
        return "..."
    if isinstance(value, dict):
        out = {}
        labelled = any(
            isinstance(value.get(lk), str) and is_sensitive_key(value[lk]) for lk in LABEL_KEYS
        )
        for k, v in value.items():
            if is_sensitive_key(str(k)) or (
                labelled and str(k).lower() == "value" and not isinstance(v, (dict, list))
            ):
                out[k] = REDACTED
            else:
                out[k] = redact_json(v, depth=depth + 1, max_depth=max_depth, markup=markup)
        return out
    if isinstance(value, list):
        # Cap list length in redacted output
        items = value[:50]
        redacted = [redact_json(v, depth=depth + 1, max_depth=max_depth, markup=markup) for v in items]
        if len(value) > 50:
            redacted.append(f"... ({len(value) - 50} more)")
        return redacted
    if isinstance(value, str):
        stripped = value.lstrip()
        if 2 <= len(stripped) <= MAX_EMBEDDED_JSON_CHARS and stripped[0] in "{[" and depth < max_depth:
            try:
                inner = safe_loads(stripped)
            except (ValueError, RecursionError):
                inner = None
            if isinstance(inner, (dict, list)):  # double-encoded JSON: redact what is inside
                return json.dumps(
                    redact_json(inner, depth=depth + 1, max_depth=max_depth, markup=markup), ensure_ascii=False
                )
        text = redact_string(value)
        return redact_form(redact_markup_text(text) if markup else text)
    return value


# --- markup / script text -------------------------------------------------------------------

_TAG_RE = re.compile(r"<([A-Za-z][\w:-]{0,30})\b([^<>]{1,4000})>")
_ATTR_RE = re.compile(
    r"""([^\s"'<>/=\\]{1,80})\s*=\s*(\\?"[^"]*?\\?"|\\?'[^']*?\\?'|[^\s"'<>\\]+)"""
)
_KV_RE = re.compile(
    r"""(["']?)([A-Za-z_$][\w$.-]{0,60})\1(\s*[:=]\s*)(["'])((?:\\.|(?!\4)[^\\\n]){0,2000})\4"""
)


#: The same assignment inside a JSON string that was serialised again: ``\"key\": \"value\"``.
_KV_ESC_RE = re.compile(
    r"""\\(["'])([A-Za-z_$][\w$.-]{0,60})\\\1(\s*:\s*)\\(["'])((?:(?!\\\4)[^\n]){0,2000}?)\\\4"""
)


def _unquote_attr(v: str) -> tuple[str, str, str]:
    """(opening quote, inner text, closing quote); the quotes may carry a backslash (JSON-escaped HTML)."""
    for q in ('"', "'"):
        for o, c in ((f"\\{q}", f"\\{q}"), (q, q)):
            if len(v) >= len(o) + len(c) and v.startswith(o) and v.endswith(c):
                return o, v[len(o):len(v) - len(c)], c
    return "", v, ""


def _redact_tag(m: re.Match) -> str:
    attrs = m.group(2)
    pairs = [(a.group(1), a.group(2), a.start(2), a.end(2)) for a in _ATTR_RE.finditer(attrs)]
    if not pairs:
        return m.group(0)
    by_name = {n.lower(): _unquote_attr(v)[1] for n, v, _s, _e in pairs}
    # <input name=X value=...> and <meta name=X content=...> carry the secret under another attribute.
    label = by_name.get("name") or by_name.get("id") or ""
    labelled = bool(label) and (is_sensitive_key(label) or by_name.get("type", "").lower() == "password")
    out: list[str] = []
    last = 0
    for n, v, s, e in pairs:
        if is_sensitive_key(n) or (labelled and n.lower() in ("value", "content")):
            qo, inner, qc = _unquote_attr(v)
            if inner and inner != REDACTED:
                out.append(attrs[last:s])
                out.append(f"{qo}{REDACTED}{qc}")
                last = e
    out.append(attrs[last:])
    return f"<{m.group(1)}{''.join(out)}>"


def _redact_kv(m: re.Match) -> str:
    key, value = m.group(2), m.group(5)
    if value and value != REDACTED and is_sensitive_key(key):
        q = m.group(4)
        return f"{m.group(1)}{key}{m.group(1)}{m.group(3)}{q}{REDACTED}{q}"
    return m.group(0)


def _redact_kv_esc(m: re.Match) -> str:
    key, value = m.group(2), m.group(5)
    if value and value != REDACTED and is_sensitive_key(key):
        k, q = m.group(1), m.group(4)
        return f"\\{k}{key}\\{k}{m.group(3)}\\{q}{REDACTED}\\{q}"
    return m.group(0)


def redact_markup_text(text: str) -> str:
    """Mask secrets in HTML / script / loose text: sensitive form fields and attributes, and
    ``"apiKey": "..."`` style assignments. Linear in the input (every pattern is length-bounded)."""
    if "<" in text:
        text = _TAG_RE.sub(_redact_tag, text)
    if ":" in text or "=" in text:
        text = _KV_RE.sub(_redact_kv, text)
        if '\\"' in text or "\\'" in text:
            text = _KV_ESC_RE.sub(_redact_kv_esc, text)
    return text


def redact_body_text(text: str | None, *, max_chars: int = 4000, markup: bool = True) -> dict:
    """Redact and optionally truncate a body string. Returns metadata dict.

    ``markup=False`` keeps HTML attribute / script values (the index keeps them so detectors can
    correlate a hidden-field value with a later request); everything shown to a caller uses the
    default ``markup=True``.
    """
    if text is None:
        return {"text": None, "size": 0, "truncated": False}
    size = len(text)
    truncated = size > max_chars
    preview = text[:max_chars] if truncated else text
    try:
        if len(text) > MAX_JSON_PARSE_CHARS:
            raise ValueError("too large to parse for a preview")
        parsed = safe_loads(preview if not truncated else text)
        redacted = redact_json(parsed, markup=markup)
        out_text = json.dumps(redacted, indent=2, default=str)
        if len(out_text) > max_chars:
            out_text = out_text[:max_chars]
            truncated = True
        return {"text": out_text, "size": size, "truncated": truncated, "json": True}
    except (TypeError, ValueError, RecursionError):  # not JSON, too big, or nested past the parser limit
        return {
            "text": redact_form(redact_markup_text(redact_string(preview)) if markup else redact_string(preview)),
            "size": size,
            "truncated": truncated,
            "json": False,
        }


_FORM_PAIR = re.compile(r"(^|&)([^&=\s]{1,200})=([^&]*)")


def redact_form(text: str) -> str:
    """Redact the values of sensitive fields in a form-encoded body (``Name=x&Pwd=y``); other text is unchanged."""
    if not text or "=" not in text or "\n" in text.strip() or text.lstrip()[:1] in ("{", "[", "<"):
        return text
    from urllib.parse import unquote_plus

    def swap(m: re.Match) -> str:
        key = unquote_plus(m.group(2))
        return f"{m.group(1)}{m.group(2)}={REDACTED}" if is_sensitive_key(key) else m.group(0)

    return _FORM_PAIR.sub(swap, text)
