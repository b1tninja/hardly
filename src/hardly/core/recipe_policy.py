"""Recipe guard: refuse steps that would act on a gate.

Pure and offline. ``check_step(step) -> (ok, reason)``; a refusal reason starts
with ``policy:`` so recipe runners can return it as the step error. Refuses:

* click / fill / press / evaluate / fetch steps aimed at a captcha or
  challenge element (selector, text, ref or target containing
  recaptcha|hcaptcha|h-captcha|turnstile|captcha|challenge);
* JS that calls ``grecaptcha.execute`` / ``turnstile.render`` / ``hcaptcha.execute``;
* ``fill`` into a password input unless the step sets ``"allow_login": true``.

See ``docs/gate-policy.md``.
"""

from __future__ import annotations

import re
from typing import Any

_GATE_TARGET = re.compile(r"recaptcha|hcaptcha|h-captcha|turnstile|captcha|challenge", re.I)
_GATE_JS = re.compile(r"\b(?:grecaptcha(?:\.enterprise)?\.execute|turnstile\.render|hcaptcha\.execute)\b", re.I)
_PASSWORD_TARGET = re.compile(
    r"type\s*=\s*['\"]?password|\[type=['\"]?password|\b(?:password|passwd|pwd)\b", re.I
)
_GATED_OPS = {"click", "fill", "press", "evaluate", "fetch"}
_TARGET_KEYS = ("css", "selector", "text", "ref", "target", "name", "label", "role")


def check_step(step: dict[str, Any]) -> tuple[bool, str]:
    """Return ``(True, "")`` when the step is allowed, else ``(False, "policy: ...")``."""
    if not isinstance(step, dict):
        return True, ""
    op = str(step.get("op") or "").strip().lower()
    if op not in _GATED_OPS:
        return True, ""

    js = str(step.get("js") or step.get("expression") or "")
    if js and _GATE_JS.search(js):
        return False, "policy: step calls a captcha/challenge API (never trigger a gate)"

    for key in _TARGET_KEYS:
        val = step.get(key)
        if isinstance(val, str) and _GATE_TARGET.search(val):
            return False, f"policy: step targets a captcha/challenge element ({key})"
    if op == "fetch" and _GATE_TARGET.search(str(step.get("url") or "")):
        return False, "policy: fetch targets a captcha/challenge endpoint"
    if op == "evaluate" and js and _GATE_TARGET.search(js):
        return False, "policy: script touches a captcha/challenge element"

    if op == "fill" and not step.get("allow_login"):
        for key in ("css", "selector", "ref", "target", "name", "label"):
            val = step.get(key)
            if isinstance(val, str) and _PASSWORD_TARGET.search(val):
                return False, 'policy: fill into a password input needs "allow_login": true'
        if str(step.get("type") or "").lower() == "password":
            return False, 'policy: fill into a password input needs "allow_login": true'
    return True, ""
