"""HAR hygiene helpers: prune, split, merge, scrub.

All helpers stream with ijson (entries are processed one at a time), write to
a new file (temp file + atomic rename) and refuse to work in place. They are
content-neutral and never touch the source HAR.
"""

from __future__ import annotations

import base64
import binascii
import fnmatch
import json
import os
import re
import tempfile
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from decimal import Decimal
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import ijson

from hardly.core.filters import is_noise
from hardly.core.pathguard import guard_write
from hardly.core.redact import (
    JWT_RE,
    REDACTED,
    is_sensitive_header,
    is_sensitive_key,
    redact_form,
    redact_url,
)

# --------------------------------------------------------------------------- io


def _dumps(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, default=lambda o: float(o) if isinstance(o, Decimal) else str(o))


def _check_paths(src: Iterable[Path], dst: Path, overwrite: bool) -> None:
    guard_write(dst)
    dst_r = dst.resolve()
    for s in src:
        if s.resolve() == dst_r:
            raise ValueError(f"refusing to write in place: {s}")
    if dst.exists() and not overwrite:
        raise FileExistsError(f"{dst} exists (pass overwrite=True to replace it)")


def _entries(path: Path) -> Iterator[dict]:
    with path.open("rb") as f:
        yield from ijson.items(f, "log.entries.item", use_float=True)


def _meta(path: Path) -> dict[str, Any]:
    """Log-level fields other than entries (version, creator, browser, pages, comment)."""
    meta: dict[str, Any] = {"version": "1.2", "creator": {"name": "hardly", "version": "1"}, "pages": []}
    with path.open("rb") as f:
        for key in ("version", "creator", "browser", "comment"):
            f.seek(0)
            for v in ijson.items(f, f"log.{key}", use_float=True):
                meta[key] = v
    with path.open("rb") as f:
        meta["pages"] = list(ijson.items(f, "log.pages.item", use_float=True))
    return meta


@contextmanager
def _writer(dst: Path, meta: dict[str, Any], pages: list[dict] | None = None, overwrite: bool = False):
    """Yield ``emit(entry)``; writes a complete HAR to ``dst`` atomically on success."""
    guard_write(dst)
    dst.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=dst.name + ".", suffix=".tmp", dir=str(dst.parent))
    count = [0]
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            head = {k: v for k, v in meta.items() if k not in ("pages",)}
            head["pages"] = pages if pages is not None else meta.get("pages", [])
            body = _dumps(head)[:-1]  # drop closing brace
            out.write('{"log": ' + body + ', "entries": [')

            def emit(entry: dict) -> None:
                if count[0]:
                    out.write(",")
                out.write(_dumps(entry))
                count[0] += 1

            yield emit
            out.write("]}}")
        if dst.exists() and not overwrite:
            raise FileExistsError(str(dst))
        os.replace(tmp, dst)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _host(entry: dict) -> str:
    return urlparse(str((entry.get("request") or {}).get("url") or "")).netloc.lower()


def _any(value: str, globs: Iterable[str]) -> bool:
    v = value.lower()
    return any(fnmatch.fnmatchcase(v, g.lower()) for g in globs)


# --------------------------------------------------------------------------- prune


def prune_har(
    src: str | Path,
    dst: str | Path,
    drop_hosts: Iterable[str] = (),
    drop_mime: Iterable[str] = (),
    drop_noise: bool = False,
    *,
    overwrite: bool = False,
) -> dict[str, Any]:
    """Copy ``src`` to ``dst`` without entries on ``drop_hosts`` (globs), with
    a response MIME matching ``drop_mime`` (globs like ``image/*``), or that
    are tracker/static noise (``drop_noise``). Pages left without entries are
    dropped. Returns ``{kept, dropped, pages_dropped, dst}``."""
    src, dst = Path(src), Path(dst)
    _check_paths([src], dst, overwrite)
    hosts, mimes = list(drop_hosts), list(drop_mime)

    def drop(e: dict) -> bool:
        if hosts and _any(_host(e), hosts):
            return True
        resp = e.get("response") or {}
        mime = str((resp.get("content") or {}).get("mimeType") or "").split(";")[0].strip()
        if mimes and mime and _any(mime, mimes):
            return True
        if drop_noise:
            req = e.get("request") or {}
            return is_noise(
                method=str(req.get("method") or "GET"),
                url=str(req.get("url") or ""),
                status=int(resp.get("status") or 0) or None,
                mime=mime or None,
            )
        return False

    meta = _meta(src)
    had: set[str] = set()
    kept_refs: set[str] = set()
    for e in _entries(src):
        if e.get("pageref") is not None:
            had.add(str(e["pageref"]))
            if not drop(e):
                kept_refs.add(str(e["pageref"]))
    pages = [p for p in meta["pages"] if str(p.get("id")) not in had or str(p.get("id")) in kept_refs]
    kept = dropped = 0
    with _writer(dst, meta, pages, overwrite) as emit:
        for e in _entries(src):
            if drop(e):
                dropped += 1
            else:
                emit(e)
                kept += 1
    return {"dst": str(dst), "kept": kept, "dropped": dropped, "pages_dropped": len(meta["pages"]) - len(pages)}


# --------------------------------------------------------------------------- split


def _slug(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s).strip("_")[:80] or "unknown"


def split_har(src: str | Path, by: str = "host", outdir: str | Path = ".", *, overwrite: bool = False) -> dict[str, Any]:
    """Split ``src`` into one HAR per host or per page inside ``outdir``.

    Entries stream through one temp writer per group (memory stays flat; one
    open file per group). Each output keeps only the pages it uses. Returns ``{files: {group: {path, entries}}}``.
    """
    if by not in ("host", "page"):
        raise ValueError("by must be 'host' or 'page'")
    src, outdir = Path(src), Path(outdir)
    guard_write(outdir, label="output_dir")
    outdir.mkdir(parents=True, exist_ok=True)
    meta = _meta(src)
    page_by_id = {str(p.get("id")): p for p in meta["pages"]}

    # pass 1: groups
    groups: dict[str, int] = {}
    refs: dict[str, set[str]] = {}
    for e in _entries(src):
        k = _group(e, by)
        groups[k] = groups.get(k, 0) + 1
        if e.get("pageref") is not None:
            refs.setdefault(k, set()).add(str(e["pageref"]))
    names: dict[str, Path] = {}
    used: set[str] = set()
    for k in groups:
        base = _slug(k)
        name, i = base, 1
        while name in used:
            i += 1
            name = f"{base}_{i}"
        used.add(name)
        names[k] = outdir / f"{src.stem}.{name}.har"
        _check_paths([src], names[k], overwrite)

    # pass 2: one writer per group, via ExitStack
    from contextlib import ExitStack

    emitters: dict[str, Any] = {}
    with ExitStack() as stack:
        for k, p in names.items():
            pg = [page_by_id[r] for r in sorted(refs.get(k, ())) if r in page_by_id]
            emitters[k] = stack.enter_context(_writer(p, meta, pg, overwrite))
        for e in _entries(src):
            emitters[_group(e, by)](e)
    return {"files": {k: {"path": str(names[k]), "entries": groups[k]} for k in groups}}


def _group(e: dict, by: str) -> str:
    if by == "host":
        return _host(e) or "unknown"
    return str(e.get("pageref") or "no-page")


# --------------------------------------------------------------------------- merge


def merge_hars(paths: Iterable[str | Path], dst: str | Path, *, overwrite: bool = False, dedupe: bool = True) -> dict[str, Any]:
    """Merge several HARs into ``dst``, entries ordered by input file then
    position. Page ids are prefixed per source (``f1_``) so they cannot
    collide. Exact duplicates (same request/time/status) are dropped when
    ``dedupe``. Returns ``{entries, duplicates, sources}``."""
    srcs = [Path(p) for p in paths]
    if not srcs:
        raise ValueError("merge_hars needs at least one input")
    dst = Path(dst)
    _check_paths(srcs, dst, overwrite)
    metas = [_meta(s) for s in srcs]
    pages: list[dict] = []
    for i, m in enumerate(metas, 1):
        for p in m["pages"]:
            q = dict(p)
            q["id"] = f"f{i}_{p.get('id')}"
            pages.append(q)
    base = dict(metas[0])
    base["comment"] = f"merged by hardly from {len(srcs)} HARs"
    seen: set[tuple] = set()
    total = dups = 0
    with _writer(dst, base, pages, overwrite) as emit:
        for i, s in enumerate(srcs, 1):
            for e in _entries(s):
                if dedupe:
                    c = (e.get("response") or {}).get("content") or {}
                    key = (
                        (e.get("request") or {}).get("method"),
                        (e.get("request") or {}).get("url"),
                        e.get("startedDateTime"),
                        (e.get("response") or {}).get("status"),
                        c.get("size"),
                        hash(c.get("text") or ""),
                    )
                    if key in seen:
                        dups += 1
                        continue
                    seen.add(key)
                if e.get("pageref") is not None:
                    e["pageref"] = f"f{i}_{e['pageref']}"
                emit(e)
                total += 1
    return {"dst": str(dst), "entries": total, "duplicates": dups, "sources": len(srcs)}


# --------------------------------------------------------------------------- scrub

_AUTH_SCHEME_RE = re.compile(r"^(\s*(?:Bearer|Basic|Digest|Token|Negotiate)\s+)(.+)$", re.I)
_TEXTUAL = ("text/", "json", "xml", "javascript", "urlencoded", "html")
_BEARER_IN_TEXT = re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]{12,}")


def _scrub_header(name: str, value: str) -> str:
    if not (is_sensitive_header(name) or name.lower() in ("authorization", "cookie", "set-cookie")):
        return JWT_RE.sub(REDACTED, value)
    m = _AUTH_SCHEME_RE.match(value)
    if m:
        return m.group(1) + REDACTED
    if name.lower() in ("cookie", "set-cookie"):
        # keep cookie names and attributes, drop values
        parts = []
        for chunk in value.split(";"):
            k, sep, v = chunk.partition("=")
            first = not parts
            if sep and (first or k.strip().lower() not in _COOKIE_ATTRS):
                parts.append(f"{k}={REDACTED}")
            else:
                parts.append(chunk)
        return ";".join(parts)
    return REDACTED


_COOKIE_ATTRS = {"path", "domain", "expires", "max-age", "samesite", "version", "comment"}


def _scrub_json(v: Any) -> Any:
    if isinstance(v, dict):
        return {k: (REDACTED if is_sensitive_key(str(k)) and not isinstance(val, (dict, list)) else _scrub_json(val)) for k, val in v.items()}
    if isinstance(v, list):
        return [_scrub_json(x) for x in v]
    if isinstance(v, str):
        return _scrub_text_plain(v)
    return v


def _scrub_text_plain(s: str) -> str:
    return _BEARER_IN_TEXT.sub(lambda m: m.group(1) + REDACTED, JWT_RE.sub(REDACTED, s))


def _scrub_text(text: str, mime: str) -> str:
    stripped = text.lstrip()
    if stripped[:1] in "{[":
        try:
            return json.dumps(_scrub_json(json.loads(text)), ensure_ascii=False)
        except ValueError:
            pass
    if "urlencoded" in mime or ("=" in text and "\n" not in text.strip() and "<" not in text):
        text = redact_form(text)
    return _scrub_text_plain(text)


def _scrub_nv(items: Any, names_secret: bool = False) -> Any:
    out = []
    for it in items or []:
        if isinstance(it, dict):
            it = dict(it)
            n = str(it.get("name", ""))
            if "value" in it and (is_sensitive_key(n) or names_secret):
                it["value"] = REDACTED
            elif isinstance(it.get("value"), str):
                it["value"] = _scrub_text_plain(it["value"])
        out.append(it)
    return out


def _scrub_content(c: dict, mime: str) -> dict:
    c = dict(c)
    text = c.get("text")
    if not isinstance(text, str) or not text:
        return c
    m = (mime or c.get("mimeType") or "").lower()
    if c.get("encoding") == "base64":
        if not any(t in m for t in _TEXTUAL):
            return c
        try:
            raw = base64.b64decode(text, validate=False).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            return c
        c["text"] = base64.b64encode(_scrub_text(raw, m).encode("utf-8")).decode("ascii")
        return c
    c["text"] = _scrub_text(text, m)
    return c


def scrub_entry(e: dict) -> dict:
    """Return a scrubbed copy of one HAR entry (keeps keys, sizes and shapes)."""
    e = json.loads(_dumps(e))
    req = e.get("request") or {}
    resp = e.get("response") or {}
    if req.get("url"):
        req["url"] = redact_url(req["url"])
    if resp.get("redirectURL"):
        resp["redirectURL"] = redact_url(resp["redirectURL"])
    for side in (req, resp):
        side["headers"] = [
            {**h, "value": _scrub_header(str(h.get("name", "")), str(h.get("value", "")))} if isinstance(h, dict) else h
            for h in side.get("headers") or []
        ]
        side["cookies"] = _scrub_nv(side.get("cookies"), names_secret=True)
    if "queryString" in req:
        req["queryString"] = _scrub_nv(req["queryString"])
    post = req.get("postData")
    if isinstance(post, dict):
        if post.get("text"):
            post["text"] = _scrub_text(str(post["text"]), str(post.get("mimeType") or "").lower())
        if post.get("params"):
            post["params"] = _scrub_nv(post["params"])
    if isinstance(resp.get("content"), dict):
        resp["content"] = _scrub_content(resp["content"], str(resp["content"].get("mimeType") or ""))
    if isinstance(e.get("_initiator"), dict) and e["_initiator"].get("url"):
        e["_initiator"]["url"] = redact_url(e["_initiator"]["url"])
    return e


def scrub_har(src: str | Path, dst: str | Path, *, overwrite: bool = False) -> dict[str, Any]:
    """Write a scrubbed copy of ``src``: Authorization/Cookie/Set-Cookie and
    other sensitive headers, cookie values, secret query/form/JSON values and
    JWT/Bearer tokens in bodies become ``***REDACTED***``. Keys, structure,
    sizes, hosts and paths stay, so the HAR is still analysable (but replay
    needs the secrets back)."""
    src, dst = Path(src), Path(dst)
    _check_paths([src], dst, overwrite)
    meta = _meta(src)
    n = 0
    with _writer(dst, meta, None, overwrite) as emit:
        for e in _entries(src):
            emit(scrub_entry(e))
            n += 1
    return {"dst": str(dst), "entries": n}
