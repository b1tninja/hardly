"""Browser-side helpers for headless navigation (content-neutral).

* ``PAGE_NAV_JS``: one evaluate-able function that walks a document **and its
  open shadow roots** and answers ``op`` = ``links`` (clickable controls with
  visibility and hover-trigger hints), ``forms``, ``consent`` (cookie/consent
  dialog candidates) or ``get`` (the element at ``idx``, for a handle).
* Pure Python classifiers for consent dialogs, so the decision logic is unit
  testable without a browser: ``classify_consent_label`` and
  ``consent_refusal``.

Same-origin iframes are handled by the caller running the function once per
frame. Closed shadow roots and cross-origin frames are not reachable by design.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

PAGE_NAV_JS = r"""
(arg) => {
  const all = [];
  const walk = (root, shadow) => {
    for (const el of root.querySelectorAll('*')) {
      all.push({el, shadow});
      if (el.shadowRoot) walk(el.shadowRoot, true);
    }
  };
  walk(document, false);
  const op = arg.op;
  if (op === 'get') { const e = all[arg.idx]; return e ? e.el : null; }
  const vis = (el) => {
    try {
      if (el.checkVisibility && !el.checkVisibility({checkVisibilityCSS: true, checkOpacity: true})) return false;
    } catch (e) {}
    const r = el.getBoundingClientRect();
    return r.width > 0 && r.height > 0;
  };
  const text = (el) => ((el.innerText || el.getAttribute('aria-label') || el.title || el.value || '')
      .replace(/\s+/g, ' ').trim());
  const idxOf = new Map();
  all.forEach((e, i) => idxOf.set(e.el, i));
  const CLICKY = 'a[href],button,[role=button],[role=link],[role=menuitem],[role=tab]';

  if (op === 'links') {
    const out = [];
    for (let i = 0; i < all.length && out.length < (arg.limit || 600); i++) {
      const {el, shadow} = all[i];
      const tag = el.tagName.toLowerCase();
      if (!el.matches(CLICKY)) continue;
      const visible = vis(el);
      let href = '';
      if (tag === 'a' && /^https?:/i.test(el.href || '')) href = el.href;
      let trigger = false;
      if (visible) {
        const hp = el.getAttribute('aria-haspopup');
        if ((hp && hp !== 'false') || el.getAttribute('aria-expanded') === 'false') trigger = true;
        else if (el.parentElement) {
          for (const sib of el.parentElement.children) {
            if (sib === el) continue;
            const inner = sib.querySelector('a[href],[role=menuitem]');
            if (inner && !vis(inner)) { trigger = true; break; }
          }
        }
      }
      out.push({idx: i, tag, text: text(el).slice(0, 120), href, target: el.getAttribute('target') || '',
                id: el.id || '', shadow, visible, trigger,
                kind: tag === 'a' ? 'link' : 'button'});
    }
    return out;
  }

  if (op === 'forms') {
    const out = [];
    for (let i = 0; i < all.length; i++) {
      const {el, shadow} = all[i];
      if (el.tagName !== 'FORM') continue;
      const fields = [];
      for (const f of el.elements) {
        const t = f.tagName.toLowerCase();
        if (t === 'fieldset' || t === 'button' || t === 'object' || t === 'output') continue;
        const ty = (f.type || '').toLowerCase();
        if (ty === 'hidden' || ty === 'submit' || ty === 'button' || ty === 'reset' || ty === 'image') continue;
        fields.push({kind: t === 'input' ? 'input' : t, type: t === 'input' ? ty : t,
                     name: f.name || '', id: f.id || ''});
      }
      out.push({idx: i, id: el.id || '', action: el.action || '', method: (el.method || 'get').toUpperCase(),
                shadow, visible: vis(el) || fields.length > 0 && !!el.querySelector('input,select,textarea') && vis(el.querySelector('input,select,textarea')),
                fields});
    }
    return out;
  }

  if (op === 'consent') {
    const NAME = /cookie|consent|gdpr|\bcmp\b|onetrust|didomi|cookiebot|privacy-?(banner|notice|prefs)|truste|quantcast|osano/;
    const out = [];
    const vw = window.innerWidth, vh = window.innerHeight;
    for (let i = 0; i < all.length && out.length < 12; i++) {
      const {el} = all[i];
      const tag = el.tagName.toLowerCase();
      if (tag === 'html' || tag === 'body' || tag === 'script' || tag === 'style') continue;
      const cn = typeof el.className === 'string' ? el.className : '';
      const name = (el.id + ' ' + cn).toLowerCase();
      const role = (el.getAttribute('role') || '').toLowerCase();
      let cand = role === 'dialog' || role === 'alertdialog' || el.getAttribute('aria-modal') === 'true'
                 || tag === 'dialog' || NAME.test(name);
      if (!cand && /^(div|section|aside|footer|form|header)$/.test(tag) && el.childElementCount > 0) {
        const cs = getComputedStyle(el);
        if (cs.position === 'fixed' || cs.position === 'sticky') {
          const r = el.getBoundingClientRect();
          cand = r.width >= 0.5 * vw && r.height < 0.6 * vh && (r.top <= 5 || r.bottom >= vh - 5);
        }
      }
      if (!cand || !vis(el)) continue;
      const t = text(el);
      if (t.length < 12 || t.length > 2500) continue;
      const controls = [];
      for (const c of el.querySelectorAll('a,button,[role=button],input[type=button],input[type=submit]')) {
        if (!vis(c) || !idxOf.has(c)) continue;
        controls.push({idx: idxOf.get(c), label: text(c).slice(0, 80), tag: c.tagName.toLowerCase()});
      }
      const html = (el.innerHTML || '').slice(0, 30000);
      out.push({idx: i, text: t.slice(0, 600), controls: controls.slice(0, 20),
                has_password: !!el.querySelector('input[type=password]'),
                has_captcha: /recaptcha|hcaptcha|h-captcha|turnstile|captcha|cf-chl/i.test(html),
                has_fields: el.querySelectorAll('input:not([type=hidden]):not([type=checkbox]):not([type=radio]),select,textarea').length});
    }
    return out;
  }
  return null;
}
"""

# --- consent-dialog decisions (pure) ----------------------------------------

_COOKIE_WORDS = re.compile(r"cookies?\b|gdpr|ccpa|tracking|consent|privacy (preferences|settings|choices)", re.I)
# "consent" / "privacy" alone is not enough to be a *cookie* dialog when the
# text is really about terms; require a cookie-ish word for the strict test.
_COOKIE_STRICT = re.compile(r"cookies?\b|gdpr|ccpa|tracking technolog|similar technolog|privacy (preferences|settings|choices)", re.I)
_TERMS_WORDS = re.compile(
    r"terms (of|and) (use|service|conditions)|terms & conditions|disclaimer|user agreement|"
    r"acceptable use|(must|have to) (accept|agree)|automated (access|means)|scrap",
    re.I,
)
_LOGIN_WORDS = re.compile(r"sign[ -]?in|log[ -]?in|username|password|e-?mail address|verification code", re.I)

_REJECT = re.compile(
    r"^(reject|decline|deny|refuse|disagree|no,? thanks?|no thank you|only (necessary|essential|required)|"
    r"(necessary|essential|required)( cookies)? only|use (necessary|essential)|continue without (accepting|agreeing)|"
    r"do not (sell|share|accept)|opt[- ]?out)\b",
    re.I,
)
_ACCEPT = re.compile(
    r"^(accept|agree|allow|i (accept|agree|understand)|ok(ay)?\b|got it|understood|yes,? i|"
    r"that'?s ok|continue)\b",
    re.I,
)
_MANAGE = re.compile(r"manage|prefer|settings|customi[sz]e|options|more|learn|policy|details|vendors|partners", re.I)
_AVOID = re.compile(r"sign[ -]?in|log[ -]?in|captcha|verify|subscribe|register|create account", re.I)


def classify_consent_label(label: str) -> str:
    """``reject`` | ``accept`` | ``other`` for a banner control's visible label."""
    text = re.sub(r"\s+", " ", (label or "").strip().strip("✓✔×x ")).strip()
    if not text or _AVOID.search(text):
        return "other"
    if _REJECT.search(text):
        return "reject"
    if _MANAGE.search(text) and not _ACCEPT.search(text):
        return "other"
    if _ACCEPT.search(text):
        return "accept"
    return "other"


def consent_refusal(container: dict[str, Any]) -> str:
    """Why a dialog must NOT be touched ("" when it is a plain cookie/consent dialog).

    Login, captcha and terms/disclaimer gates stay governed by gate policy
    (docs/gate-policy.md): they are never dismissed here.
    """
    text = str(container.get("text") or "")
    if container.get("has_captcha"):
        return "captcha"
    if container.get("has_password"):
        return "login"
    if not _COOKIE_WORDS.search(text):
        return "not_consent"
    if _LOGIN_WORDS.search(text) and container.get("has_fields"):
        return "login"
    if _TERMS_WORDS.search(text) and not _COOKIE_STRICT.search(text):
        return "terms_gate"
    if int(container.get("has_fields") or 0) > 1:
        return "form"
    return ""


def pick_consent_control(
    controls: list[dict[str, Any]], prefer: str = "reject"
) -> tuple[dict[str, Any] | None, str]:
    """Choose the control to click: ``prefer`` first (default reject), else the other."""
    prefer = "accept" if str(prefer).lower() == "accept" else "reject"
    order = [prefer, "accept" if prefer == "reject" else "reject"]
    for want in order:
        for c in controls:
            if classify_consent_label(c.get("label") or "") == want:
                return c, want
    return None, ""


def same_origin_frame(frame_url: str, page_url: str) -> bool:
    """True for frames the page can read: same origin, or about:blank / srcdoc."""
    if not frame_url or frame_url.startswith(("about:", "data:")):
        return not frame_url.startswith("data:")
    a, b = urlparse(frame_url), urlparse(page_url)
    return (a.scheme, a.netloc.lower()) == (b.scheme, b.netloc.lower())
