"""Live-page element inventory helpers for capture RPC.

The JS runs inside Playwright's page and returns a compact list of visible
interactive controls with CSS and XPath locators agents can click.
"""

from __future__ import annotations

# Executed via page.evaluate — keep self-contained, no external deps.
LIST_ELEMENTS_JS = r"""
(opts) => {
  const limit = Math.min(Number(opts.limit) || 40, 100);
  const query = opts.query || [
    'a[href]',
    'button',
    'input',
    'select',
    'textarea',
    'summary',
    '[onclick]',
    '[ondblclick]',
    '[role="button"]',
    '[role="link"]',
    '[role="menuitem"]',
    '[contenteditable="true"]',
  ].join(',');

  function visible(el) {
    if (!el || el.disabled) return false;
    const style = window.getComputedStyle(el);
    if (!style || style.display === 'none' || style.visibility === 'hidden') return false;
    if (Number(style.opacity) === 0) return false;
    const r = el.getBoundingClientRect();
    if (r.width < 1 || r.height < 1) return false;
    // Off-screen far away still listed if in document; prefer in-viewport-ish
    if (r.bottom < -20 || r.top > (window.innerHeight + 20)) return false;
    return true;
  }

  function cssPath(el) {
    if (el.id) return '#' + CSS.escape(el.id);
    const parts = [];
    let cur = el;
    for (let depth = 0; cur && cur.nodeType === 1 && depth < 6; depth++) {
      let part = cur.tagName.toLowerCase();
      if (cur.id) {
        parts.unshift('#' + CSS.escape(cur.id));
        break;
      }
      const parent = cur.parentElement;
      if (parent) {
        const siblings = [...parent.children].filter((c) => c.tagName === cur.tagName);
        if (siblings.length > 1) {
          const idx = siblings.indexOf(cur) + 1;
          part += ':nth-of-type(' + idx + ')';
        }
      }
      parts.unshift(part);
      cur = parent;
      if (cur && cur.tagName && cur.tagName.toLowerCase() === 'body') {
        parts.unshift('body');
        break;
      }
    }
    return parts.join(' > ');
  }

  function xpathFor(el) {
    if (el.id) return '//*[@id="' + el.id.replace(/"/g, '\\"') + '"]';
    const parts = [];
    let cur = el;
    while (cur && cur.nodeType === 1 && cur.tagName.toLowerCase() !== 'html') {
      let ix = 1;
      let sib = cur.previousElementSibling;
      while (sib) {
        if (sib.tagName === cur.tagName) ix += 1;
        sib = sib.previousElementSibling;
      }
      parts.unshift(cur.tagName.toLowerCase() + '[' + ix + ']');
      cur = cur.parentElement;
    }
    return '/' + parts.join('/');
  }

  function textOf(el) {
    const tag = el.tagName.toLowerCase();
    let t = '';
    if (tag === 'input' || tag === 'textarea') {
      t = el.getAttribute('placeholder') || el.value || el.getAttribute('aria-label') || '';
    } else if (tag === 'select') {
      const opt = el.selectedOptions && el.selectedOptions[0];
      t = (opt && opt.textContent) || el.getAttribute('aria-label') || '';
    } else {
      t = el.innerText || el.getAttribute('aria-label') || el.title || '';
    }
    return String(t).replace(/\s+/g, ' ').trim().slice(0, 80);
  }

  const nodes = [...document.querySelectorAll(query)];
  const out = [];
  for (const el of nodes) {
    if (!visible(el)) continue;
    const tag = el.tagName.toLowerCase();
    const href = el.getAttribute('href') || '';
    const onclick = el.getAttribute('onclick') || '';
    const entry = {
      tag,
      type: (el.getAttribute('type') || '').toLowerCase() || null,
      text: textOf(el) || null,
      id: el.id || null,
      name: el.getAttribute('name') || null,
      href: href ? href.slice(0, 160) : null,
      role: el.getAttribute('role') || null,
      onclick: onclick ? onclick.replace(/\s+/g, ' ').trim().slice(0, 100) : null,
      css: cssPath(el),
      xpath: xpathFor(el),
    };
    out.push(entry);
    if (out.length >= limit) break;
  }
  return {
    url: location.href,
    title: document.title || '',
    count: out.length,
    elements: out,
  };
}
"""
