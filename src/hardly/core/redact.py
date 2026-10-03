"""Secret redaction for headers, bodies, and query params."""

from __future__ import annotations

import json
import re
from typing import Any

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
    }
)

# Short names that are a secret only as the whole key ("Pwd" in Accela's sign-in, "pin"): matched exactly, so "shipping"
# or "pinned" are not redacted.
EXACT_SENSITIVE_KEYS = frozenset({"pwd", "pass", "pw", "pin", "otp", "ssn", "cvv", "cvc", "mfa", "code2fa"})

JWT_RE = re.compile(
    r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"
)
LONG_HEX_RE = re.compile(r"\b[0-9a-fA-F]{32,}\b")


def is_sensitive_header(name: str) -> bool:
    return name.lower() in SENSITIVE_HEADER_NAMES


def is_sensitive_key(key: str) -> bool:
    k = key.lower().replace("-", "").replace("_", "")
    # An ASP.NET field name carries its control path ("ctl00$PlaceHolderMain$txtPwd"): judge its last part too.
    tail = re.split(r"[$.:\[\]]", key)[-1].lower().replace("-", "").replace("_", "") if key else k
    if k in EXACT_SENSITIVE_KEYS or tail in EXACT_SENSITIVE_KEYS:
        return True
    if tail.startswith(("txt", "tb")) and tail[3:] in EXACT_SENSITIVE_KEYS | {"password", "passwd"}:
        return True
    for s in SENSITIVE_JSON_KEYS:
        if s.replace("_", "") in k or k == s.replace("_", ""):
            return True
    # also match keys that end with Token/Key/Secret/Password
    lower = key.lower()
    return any(
        lower.endswith(suf)
        for suf in ("token", "secret", "password", "passwd", "apikey")
    )


def redact_string(value: str) -> str:
    if not value:
        return value
    out = JWT_RE.sub(REDACTED, value)
    # Only redact long hex if it looks like a secret (not in URLs as path ids alone)
    if len(value) >= 32 and LONG_HEX_RE.fullmatch(value.strip()):
        return REDACTED
    return out


def redact_header_value(name: str, value: str) -> str:
    if is_sensitive_header(name):
        return REDACTED
    return redact_string(value)


def redact_headers(headers: list[dict] | dict) -> list[dict] | dict:
    if isinstance(headers, dict):
        return {k: redact_header_value(k, str(v)) for k, v in headers.items()}
    result = []
    for h in headers:
        name = h.get("name", "")
        value = h.get("value", "")
        result.append({"name": name, "value": redact_header_value(name, str(value))})
    return result


def redact_json(value: Any, *, depth: int = 0, max_depth: int = 12) -> Any:
    if depth > max_depth:
        return "..."
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if is_sensitive_key(str(k)):
                out[k] = REDACTED
            else:
                out[k] = redact_json(v, depth=depth + 1, max_depth=max_depth)
        return out
    if isinstance(value, list):
        # Cap list length in redacted output
        items = value[:50]
        redacted = [redact_json(v, depth=depth + 1, max_depth=max_depth) for v in items]
        if len(value) > 50:
            redacted.append(f"... ({len(value) - 50} more)")
        return redacted
    if isinstance(value, str):
        return redact_string(value)
    return value


def redact_body_text(text: str | None, *, max_chars: int = 4000) -> dict:
    """Redact and optionally truncate a body string. Returns metadata dict."""
    if text is None:
        return {"text": None, "size": 0, "truncated": False}
    size = len(text)
    truncated = size > max_chars
    preview = text[:max_chars] if truncated else text
    try:
        parsed = json.loads(preview if not truncated else text)
        redacted = redact_json(parsed)
        out_text = json.dumps(redacted, indent=2, default=str)
        if len(out_text) > max_chars:
            out_text = out_text[:max_chars]
            truncated = True
        return {"text": out_text, "size": size, "truncated": truncated, "json": True}
    except (json.JSONDecodeError, TypeError, ValueError):
        return {
            "text": redact_form(redact_string(preview)),
            "size": size,
            "truncated": truncated,
            "json": False,
        }


_FORM_PAIR = re.compile(r"(^|&)([^&=\s]{1,200})=([^&]*)")


def redact_form(text: str) -> str:
    """Redact the values of sensitive fields in a form-encoded body (``Name=x&Pwd=y``); other text is unchanged."""
    if not text or "=" not in text or "\n" in text.strip():
        return text
    from urllib.parse import unquote_plus

    def swap(m: re.Match) -> str:
        key = unquote_plus(m.group(2))
        return f"{m.group(1)}{m.group(2)}={REDACTED}" if is_sensitive_key(key) else m.group(0)

    return _FORM_PAIR.sub(swap, text)
