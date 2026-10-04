"""Content-neutral target catalog, adapter base class and polite runner.

A *catalog* is a versioned, JSON/YAML-serialisable list of *targets*; each
target has free-form ``tags``, free-form ``groups`` (a key/value hierarchy such
as ``region`` / ``subregion`` - hardly assigns no meaning to either) and a list
of *endpoints* (a free-form ``role`` plus a URL and verification facts).

hardly knows nothing about what the targets are. A downstream project defines
its own tags, group keys and roles, subclasses :class:`TargetAdapter` to
discover endpoints, and uses :class:`CatalogRunner` to verify them politely.
Verification stores names and shapes only (statuses, gate classes, stack names)
- never bodies, cookies or tokens - and every URL is redacted on the way in.
See ``docs/catalog.md`` and ``docs/gate-policy.md``.
"""

from __future__ import annotations

import abc
import csv
import io
import json
import os
import tempfile
import time
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from hardly.core.netguard import HostNotAllowed, blocked_reason, check_url, default_hint
from hardly.core.redact import redact_string, redact_url

CATALOG_VERSION = 1
KINDS: tuple[str, ...] = ("form", "api", "gis", "media", "page", "auth", "unknown")
STATUSES: tuple[str, ...] = ("unverified", "verified", "blocked", "dead", "needs_browser")
DEFAULT_STATUS = "unverified"

# Gate classes after which the runner stops touching that host (see gate-policy.md).
# environment_blocked is *unknown*, not a site wall: it stops the host for this
# run (the sandbox is the problem) but never marks the endpoint blocked.
_HOST_STOP_CLASSES = frozenset(
    {"bot_wall", "captcha", "proof_of_work", "waiting_room", "login", "paywall", "rate_limit", "environment_blocked"}
)


class CatalogError(ValueError):
    """Raised for an invalid catalog or an unreadable file."""


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def clean_endpoint_url(url: str) -> str:
    """Normalise a stored URL: drop userinfo and fragment, redact secret values."""
    url = (url or "").strip()
    parts = urlsplit(url)
    netloc = parts.netloc.rpartition("@")[2]
    return redact_url(urlunsplit(parts._replace(netloc=netloc, fragment="")))


def _strs(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        value = [value]
    out: list[str] = []
    for v in value:
        s = str(v).strip()
        if s and s not in out:
            out.append(s)
    return out


# ------------------------------------------------------------------ schema


@dataclass
class Endpoint:
    role: str
    url: str
    kind: str | None = None
    status: str = DEFAULT_STATUS
    last_checked: str | None = None
    gate_classes: list[str] = field(default_factory=list)
    stack: list[str] = field(default_factory=list)
    notes: str = ""
    capture: dict[str, str] = field(default_factory=dict)  # recipe_ref / har_ref

    @property
    def key(self) -> tuple[str, str]:
        return (self.role, self.url)

    @property
    def host(self) -> str:
        return (urlsplit(self.url).hostname or "").lower()

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"role": self.role, "url": self.url}
        if self.kind:
            d["kind"] = self.kind
        d["status"] = self.status
        if self.last_checked:
            d["last_checked"] = self.last_checked
        if self.gate_classes:
            d["gate_classes"] = list(self.gate_classes)
        if self.stack:
            d["stack"] = list(self.stack)
        if self.notes:
            d["notes"] = self.notes
        if self.capture:
            d["capture"] = dict(self.capture)
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Endpoint:
        if not isinstance(data, dict):
            raise CatalogError("endpoint must be an object")
        cap = data.get("capture") or {}
        if not isinstance(cap, dict):
            raise CatalogError("endpoint.capture must be an object")
        return cls(
            role=str(data.get("role") or "").strip(),
            url=clean_endpoint_url(str(data.get("url") or "")),
            kind=(str(data["kind"]).strip() or None) if data.get("kind") else None,
            status=str(data.get("status") or DEFAULT_STATUS).strip(),
            last_checked=str(data["last_checked"]) if data.get("last_checked") else None,
            gate_classes=_strs(data.get("gate_classes")),
            stack=_strs(data.get("stack")),
            notes=redact_string(str(data.get("notes") or "")),
            capture={str(k): redact_url(str(v)) for k, v in cap.items() if v},
        )


@dataclass
class Target:
    id: str
    name: str = ""
    tags: list[str] = field(default_factory=list)
    groups: dict[str, str] = field(default_factory=dict)
    endpoints: list[Endpoint] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "tags": list(self.tags),
            "groups": dict(self.groups),
            "endpoints": [e.to_dict() for e in self.endpoints],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Target:
        if not isinstance(data, dict):
            raise CatalogError("target must be an object")
        groups = data.get("groups") or {}
        if not isinstance(groups, dict):
            raise CatalogError("target.groups must be an object")
        return cls(
            id=str(data.get("id") or "").strip(),
            name=str(data.get("name") or "").strip(),
            tags=_strs(data.get("tags")),
            groups={str(k): str(v) for k, v in groups.items()},
            endpoints=[Endpoint.from_dict(e) for e in (data.get("endpoints") or [])],
        )

    def endpoint(self, role: str | None = None, url: str | None = None) -> Endpoint | None:
        for e in self.endpoints:
            if (role is None or e.role == role) and (url is None or e.url == clean_endpoint_url(url)):
                return e
        return None


def _merge_endpoint(old: Endpoint, new: Endpoint) -> None:
    """Fold ``new`` into ``old``: non-empty incoming values win."""
    if new.kind:
        old.kind = new.kind
    if new.status != DEFAULT_STATUS:
        old.status = new.status
    if new.last_checked:
        old.last_checked = new.last_checked
    for attr in ("gate_classes", "stack"):
        if getattr(new, attr):
            setattr(old, attr, list(getattr(new, attr)))
    if new.notes:
        old.notes = new.notes
    old.capture.update(new.capture)


@dataclass
class Catalog:
    name: str = "catalog"
    version: int = CATALOG_VERSION
    targets: list[Target] = field(default_factory=list)

    # -- serialisation
    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "version": self.version, "targets": [t.to_dict() for t in self.targets]}

    @classmethod
    def from_dict(cls, data: dict[str, Any], *, validate: bool = True) -> Catalog:
        if not isinstance(data, dict):
            raise CatalogError("catalog must be an object")
        version = data.get("version", CATALOG_VERSION)
        if not isinstance(version, int) or version < 1 or version > CATALOG_VERSION:
            raise CatalogError(f"unsupported catalog version {version!r} (supported: 1..{CATALOG_VERSION})")
        cat = cls(
            name=str(data.get("name") or "catalog"),
            version=version,
            targets=[Target.from_dict(t) for t in (data.get("targets") or [])],
        )
        if validate:
            cat.raise_if_invalid()
        return cat

    # -- validation
    def validate(self) -> list[str]:
        problems: list[str] = []
        seen: set[str] = set()
        for i, t in enumerate(self.targets):
            where = f"targets[{i}]"
            if not t.id:
                problems.append(f"{where}: id is required")
            elif t.id in seen:
                problems.append(f"{where}: duplicate id {t.id!r}")
            seen.add(t.id)
            eps: set[tuple[str, str]] = set()
            for j, e in enumerate(t.endpoints):
                ew = f"{where}.endpoints[{j}]"
                if not e.role:
                    problems.append(f"{ew}: role is required")
                parts = urlsplit(e.url)
                if parts.scheme not in ("http", "https") or not parts.netloc:
                    problems.append(f"{ew}: url must be absolute http(s)")
                if e.kind is not None and e.kind not in KINDS:
                    problems.append(f"{ew}: unknown kind {e.kind!r} (known: {', '.join(KINDS)})")
                if e.status not in STATUSES:
                    problems.append(f"{ew}: unknown status {e.status!r} (known: {', '.join(STATUSES)})")
                if e.key in eps:
                    problems.append(f"{ew}: duplicate endpoint (role, url)")
                eps.add(e.key)
        return problems

    def raise_if_invalid(self) -> None:
        problems = self.validate()
        if problems:
            raise CatalogError("invalid catalog: " + "; ".join(problems[:10]) + (" ..." if len(problems) > 10 else ""))

    # -- access
    def get(self, target_id: str) -> Target | None:
        return next((t for t in self.targets if t.id == target_id), None)

    def upsert(self, target: Target | dict[str, Any], *, merge: bool = True) -> Target:
        """Insert a target, or update the one with the same id.

        ``merge=True`` unions tags, overlays groups and merges endpoints by
        ``(role, url)``; ``merge=False`` replaces the target outright.
        """
        new = target if isinstance(target, Target) else Target.from_dict(target)
        if not new.id:
            raise CatalogError("target id is required")
        old = self.get(new.id)
        if old is None:
            self.targets.append(new)
            result = new
        elif not merge:
            self.targets[self.targets.index(old)] = new
            result = new
        else:
            if new.name:
                old.name = new.name
            old.tags = _strs(old.tags + new.tags)
            old.groups.update(new.groups)
            for ne in new.endpoints:
                oe = old.endpoint(ne.role, ne.url)
                if oe is None:
                    old.endpoints.append(ne)
                else:
                    _merge_endpoint(oe, ne)
            result = old
        self.raise_if_invalid()
        return result

    def merge(self, other: Catalog) -> None:
        for t in other.targets:
            self.upsert(t)

    def remove(self, target_id: str) -> bool:
        t = self.get(target_id)
        if t is None:
            return False
        self.targets.remove(t)
        return True

    # -- query
    def select(
        self,
        *,
        tag: str | Iterable[str] | None = None,
        group: dict[str, str] | None = None,
        role: str | None = None,
        status: str | None = None,
        target_id: str | None = None,
    ) -> list[Target]:
        """Targets matching every given filter (tags: all of them).

        ``role`` / ``status`` match when at least one endpoint matches.
        """
        want_tags = set(_strs(tag))
        out = []
        for t in self.targets:
            if target_id and t.id != target_id:
                continue
            if want_tags and not want_tags <= set(t.tags):
                continue
            if group and any(t.groups.get(k) != str(v) for k, v in group.items()):
                continue
            if (role or status) and not any(_ep_match(e, role, status) for e in t.endpoints):
                continue
            out.append(t)
        return out

    def endpoints(
        self,
        *,
        tag: str | Iterable[str] | None = None,
        group: dict[str, str] | None = None,
        role: str | None = None,
        status: str | None = None,
        target_id: str | None = None,
    ) -> Iterator[tuple[Target, Endpoint]]:
        for t in self.select(tag=tag, group=group, target_id=target_id):
            for e in t.endpoints:
                if _ep_match(e, role, status):
                    yield t, e

    # -- summaries
    def summary(self) -> dict[str, Any]:
        def bump(d: dict[str, int], k: str) -> None:
            d[k] = d.get(k, 0) + 1

        tags: dict[str, int] = {}
        groups: dict[str, dict[str, int]] = {}
        roles: dict[str, int] = {}
        statuses: dict[str, int] = {}
        gates: dict[str, int] = {}
        stacks: dict[str, int] = {}
        n_eps = 0
        for t in self.targets:
            for tag in t.tags:
                bump(tags, tag)
            for k, v in t.groups.items():
                bump(groups.setdefault(k, {}), v)
            for e in t.endpoints:
                n_eps += 1
                bump(roles, e.role)
                bump(statuses, e.status)
                for g in e.gate_classes:
                    bump(gates, g)
                for s in e.stack:
                    bump(stacks, s)
        return {
            "name": self.name,
            "version": self.version,
            "targets": len(self.targets),
            "endpoints": n_eps,
            "by_tag": dict(sorted(tags.items())),
            "by_group": {k: dict(sorted(v.items())) for k, v in sorted(groups.items())},
            "by_role": dict(sorted(roles.items())),
            "by_status": dict(sorted(statuses.items())),
            "by_gate_class": dict(sorted(gates.items())),
            "by_stack": dict(sorted(stacks.items())),
        }

    def table(self, **filters: Any) -> list[dict[str, Any]]:
        """Flat rows (one per endpoint) for lists / CSV."""
        return [
            {
                "target": t.id, "name": t.name, "tags": ",".join(t.tags),
                "groups": ",".join(f"{k}={v}" for k, v in sorted(t.groups.items())),
                "role": e.role, "kind": e.kind or "", "status": e.status, "url": e.url,
                "gate_classes": ",".join(e.gate_classes), "stack": ",".join(e.stack),
                "last_checked": e.last_checked or "",
            }
            for t, e in self.endpoints(**filters)
        ]


def _ep_match(e: Endpoint, role: str | None, status: str | None) -> bool:
    return (role is None or e.role == role) and (status is None or e.status == status)


# ------------------------------------------------------------------ files


def _yaml():
    try:
        import yaml  # type: ignore[import-not-found]
    except ImportError:
        return None
    return yaml


def _is_yaml(path: Path) -> bool:
    return path.suffix.lower() in (".yaml", ".yml")


def dumps(catalog: Catalog, fmt: str = "json") -> str:
    data = catalog.to_dict()
    if fmt == "json":
        return json.dumps(data, indent=2, sort_keys=False) + "\n"
    if fmt == "yaml":
        y = _yaml()
        if y is None:
            raise CatalogError("yaml output needs PyYAML (pip install pyyaml); use json")
        return y.safe_dump(data, sort_keys=False, allow_unicode=True)
    if fmt == "csv":
        rows = catalog.table()
        buf = io.StringIO()
        fields = list(rows[0]) if rows else ["target", "role", "status", "url"]
        w = csv.DictWriter(buf, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)
        return buf.getvalue()
    raise CatalogError(f"unknown format {fmt!r} (json|yaml|csv)")


def loads(text: str, fmt: str = "json") -> Catalog:
    if fmt == "yaml":
        y = _yaml()
        if y is None:
            raise CatalogError("yaml input needs PyYAML (pip install pyyaml)")
        try:
            data = y.safe_load(text)
        except Exception as exc:  # noqa: BLE001
            raise CatalogError(f"invalid yaml: {exc}") from exc
    else:
        try:
            data = json.loads(text)
        except ValueError as exc:
            raise CatalogError(f"invalid json: {exc}") from exc
    return Catalog.from_dict(data)


def load(path: str | os.PathLike[str]) -> Catalog:
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise CatalogError(f"cannot read {p.name}: {exc.strerror or exc}") from exc
    return loads(text, "yaml" if _is_yaml(p) else "json")


def save(catalog: Catalog, path: str | os.PathLike[str]) -> Path:
    """Validate, then write atomically (temp file in the same directory + rename)."""
    catalog.raise_if_invalid()
    p = Path(path)
    text = dumps(catalog, "yaml" if _is_yaml(p) else "json")
    from hardly.core.pathguard import guard_write

    guard_write(p)
    p.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{p.name}.", suffix=".tmp", dir=str(p.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, p)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return p


# ---------------------------------------------------------------- adapter


@dataclass
class VerifyResult:
    """Facts from one verification: names and shapes only."""

    status: str = DEFAULT_STATUS
    gate_classes: list[str] = field(default_factory=list)
    stack: list[str] = field(default_factory=list)
    kind: str | None = None
    notes: str = ""
    requests: int = 0  # live requests spent (counted against the runner budget)
    stop_host: bool = False  # a gate/rate limit: do not touch this host again this run
    error: str | None = None
    facts: dict[str, Any] = field(default_factory=dict)  # extra shape-only facts


class TargetAdapter(abc.ABC):
    """Hooks a downstream project subclasses. hardly ships no concrete subclass
    apart from :class:`DefaultAdapter` (which discovers nothing).

    * ``discover(target)`` - return candidate :class:`Endpoint` objects for a
      target (from your own seed data, a sitemap you fetched politely, a HAR...).
      Return unverified endpoints; the runner upserts them.
    * ``verify(endpoint, ...)`` - default: one polite ``hardly.core.crawl`` fetch
      (robots-aware, honest UA, gate-aware). Live requests need ``confirm=True``.
      Override to add your own checks, but keep honouring gates.
    * ``keywords(target, endpoint)`` / ``crawl_options(endpoint)`` - tune the
      default verification without overriding it.
    """

    @abc.abstractmethod
    def discover(self, target: Target) -> list[Endpoint]:
        """Candidate endpoints for ``target`` (no live traffic unless you add it)."""

    def keywords(self, target: Target, endpoint: Endpoint) -> tuple[str, ...]:
        """Domain nouns used to rank links / spot search forms during verify."""
        return ()

    def crawl_options(self, endpoint: Endpoint) -> dict[str, Any]:
        """Extra ``hardly.core.crawl.crawl`` keyword arguments (max_pages, depth, ...)."""
        return {}

    def verify(
        self,
        endpoint: Endpoint,
        *,
        target: Target | None = None,
        confirm: bool = False,
        delay_s: float = 1.0,
        client: Any = None,
    ) -> VerifyResult:
        if not confirm:
            return VerifyResult(error="verify performs live GET requests: pass confirm=True")
        from hardly.core.crawl import crawl

        opts: dict[str, Any] = {"max_pages": 1, "depth": 0, "delay_s": delay_s, "respect_robots": True}
        opts.update(self.crawl_options(endpoint))
        kw = self.keywords(target, endpoint) if target is not None else ()
        try:
            out = crawl(endpoint.url, tuple(kw), client=client, **opts)
        except Exception as exc:  # noqa: BLE001
            return VerifyResult(error=type(exc).__name__)
        return result_from_crawl(out)


class DefaultAdapter(TargetAdapter):
    """Discovers nothing; verifies with the default crawl. Used by the CLI/MCP."""

    def discover(self, target: Target) -> list[Endpoint]:
        return []


def result_from_crawl(out: dict[str, Any]) -> VerifyResult:
    """Map a ``crawl`` result to catalog facts (statuses, gate classes, stack names)."""
    if out.get("error"):
        return VerifyResult(error=str(out["error"])[:200])
    pages = out.get("pages") or []
    requests = len(pages) + len(out.get("robots") or [])
    gates = sorted(
        {r["class"] for r in (out.get("blocked") or []) + (out.get("environment_blocked") or []) if r.get("class")}
    )
    stack = sorted({s for p in pages for s in (p.get("stack") or [])})[:8]
    facts = {
        "http_status": pages[0]["status"] if pages else None,
        "title_present": bool(pages and pages[0].get("title")),
        "looks_like_search": any(p.get("looks_like_search") for p in pages),
        "form_fields": sorted({f for p in pages for fm in (p.get("forms") or []) for f in (fm.get("fields") or [])})[:30],
    }
    res = VerifyResult(gate_classes=gates, stack=stack, requests=max(requests, 1), facts=facts)
    if out.get("halted_hosts"):
        res.stop_host = True
        res.gate_classes = sorted(set(gates) | {"rate_limit"})
        res.status = "blocked"
        res.notes = "rate limited (429/Retry-After); stopped"
        return res
    if out.get("environment_blocked"):
        # Unknown, not walled: keep the endpoint unverified, stop the host for this run.
        res.stop_host = True
        res.status = DEFAULT_STATUS
        res.notes = "environment_blocked: unknown - re-run from another network"
        return res
    if out.get("blocked"):
        res.stop_host = bool(set(gates) & _HOST_STOP_CLASSES)
        res.status = "blocked"
        res.notes = "gate: " + ",".join(gates)
        return res
    if out.get("robots_disallowed") and not pages:
        res.status = "blocked"
        res.notes = "robots.txt disallows this URL; not fetched"
        res.requests = max(requests, 1)
        return res
    if not pages:
        res.error = "no response"
        return res
    first = pages[0]
    code = int(first.get("status") or 0)
    if code in (404, 410):
        res.status = "dead"
        res.notes = f"http {code}"
    elif 200 <= code < 300:
        res.status = "needs_browser" if first.get("needs_browser") else "verified"
        if first.get("needs_browser"):
            res.notes = "needs browser: " + str(first.get("needs_browser_reason") or "client-rendered")
    else:
        res.error = f"http {code}"
        res.notes = f"http {code}"
    return res


# ----------------------------------------------------------------- runner


class CatalogRunner:
    """Polite, resumable, budgeted iteration over a catalog's endpoints.

    * per-host delay between live requests (across endpoints, not just within one);
    * ``max_requests`` / ``max_endpoints`` budgets, then a clean stop;
    * resumable: the catalog is saved after every endpoint, and endpoints already
      checked within ``recheck_after_s`` (default: any prior check) are skipped
      unless ``force``;
    * stops on gates per ``docs/gate-policy.md``: a captcha, bot wall, login,
      paywall, rate limit or environment block ends work on that host for the run.
      It never retries a challenged URL and never evades anything.
    """

    def __init__(
        self,
        catalog: Catalog,
        adapter: TargetAdapter | None = None,
        *,
        path: str | os.PathLike[str] | None = None,
        confirm: bool = False,
        delay_s: float = 1.0,
        max_requests: int = 100,
        max_endpoints: int | None = None,
        recheck_after_s: float | None = None,
        force: bool = False,
        run_discover: bool = False,
        client: Any = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], float] = time.time,
    ) -> None:
        self.catalog = catalog
        self.adapter = adapter or DefaultAdapter()
        self.path = path
        self.confirm = confirm
        self.delay_s = max(0.0, float(delay_s))
        self.max_requests = max(0, int(max_requests))
        self.max_endpoints = max_endpoints
        self.recheck_after_s = recheck_after_s
        self.force = force
        self.run_discover = run_discover
        self.client = client
        self._sleep, self._clock, self._wall = sleep, clock, wall_clock
        self._last_hit: dict[str, float] = {}

    def _due(self, e: Endpoint) -> bool:
        if self.force or not e.last_checked:
            return True
        if self.recheck_after_s is None:
            return False
        try:
            ts = datetime.strptime(e.last_checked, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            return True
        return self._wall() - ts >= self.recheck_after_s

    def _persist(self) -> None:
        if self.path:
            save(self.catalog, self.path)

    def run(self, **filters: Any) -> dict[str, Any]:
        """Verify every due endpoint matching ``filters`` (see :meth:`Catalog.select`)."""
        if not self.confirm:
            return {
                "error": "catalog verify performs live GET requests: pass confirm=True",
                "planned": self.plan(**filters),
            }
        report: dict[str, Any] = {
            "checked": 0, "skipped_recent": 0, "requests": 0, "stopped": None,
            "stopped_hosts": {}, "results": [], "discovered": 0, "errors": [],
        }
        halted: dict[str, str] = report["stopped_hosts"]
        if self.run_discover:
            for t in self.catalog.select(**{k: v for k, v in filters.items() if k not in ("role", "status")}):
                try:
                    found = self.adapter.discover(t)
                except Exception as exc:  # noqa: BLE001
                    report["errors"].append({"target": t.id, "error": f"discover: {type(exc).__name__}"})
                    continue
                for ep in found:
                    ep.url = clean_endpoint_url(ep.url)
                self.catalog.upsert(Target(id=t.id, endpoints=list(found)))
                report["discovered"] += len(found)
            self._persist()

        for target, ep in list(self.catalog.endpoints(**filters)):
            if not self._due(ep):
                report["skipped_recent"] += 1
                continue
            host = ep.host
            if host in halted:
                continue
            if self.max_endpoints is not None and report["checked"] >= self.max_endpoints:
                report["stopped"] = "max_endpoints"
                break
            if report["requests"] >= self.max_requests:
                report["stopped"] = "max_requests"
                break
            wait = self.delay_s - (self._clock() - self._last_hit.get(host, -1e9))
            if wait > 0:
                self._sleep(wait)
            try:
                check_url(ep.url)
                res = self.adapter.verify(
                    ep, target=target, confirm=True, delay_s=self.delay_s, client=self.client
                )
            except HostNotAllowed:
                res = VerifyResult(error="host_not_allowed")
            except Exception as exc:  # noqa: BLE001
                res = VerifyResult(error=type(exc).__name__)
            self._last_hit[host] = self._clock()
            report["requests"] += max(res.requests, 0)
            row = {"target": target.id, "role": ep.role, "url": ep.url}
            if res.error:
                # Transient/unknown: record the attempt, leave status alone.
                ep.last_checked = utc_now()
                if res.notes:
                    ep.notes = redact_string(res.notes)
                row.update(status=ep.status, error=res.error)
                report["errors"].append({"target": target.id, "role": ep.role, "error": res.error})
            else:
                ep.status = res.status if res.status in STATUSES else DEFAULT_STATUS
                ep.last_checked = utc_now()
                ep.gate_classes = sorted(set(res.gate_classes))
                ep.stack = list(res.stack)
                if res.kind and not ep.kind and res.kind in KINDS:
                    ep.kind = res.kind
                if res.notes:
                    ep.notes = redact_string(res.notes)
                row.update(status=ep.status, gate_classes=ep.gate_classes, stack=ep.stack)
            report["checked"] += 1
            report["results"].append(row)
            self._persist()
            if res.stop_host:
                halted[host] = ",".join(res.gate_classes) or "stopped"
        report["summary"] = self.catalog.summary()["by_status"]
        report["next"] = _runner_next(report)
        if any(e.get("error") == "host_not_allowed" for e in report["errors"]):
            report["next"].append(default_hint())
        return report

    def plan(self, **filters: Any) -> dict[str, Any]:
        """What a run would touch (no traffic)."""
        due = [(t.id, e) for t, e in self.catalog.endpoints(**filters) if self._due(e)]
        hosts = sorted({e.host for _, e in due})
        out: dict[str, Any] = {"endpoints": len(due), "hosts": hosts, "delay_s": self.delay_s,
                               "max_requests": self.max_requests}
        blocked = []
        for t, e in due:
            why = blocked_reason(e.url)
            if why:
                blocked.append({"target": t, "role": e.role, "code": "host_not_allowed", "reason": why})
        if blocked:
            out["blocked"] = blocked
            out["hint"] = default_hint()
        return out


def _runner_next(report: dict[str, Any]) -> list[str]:
    nxt: list[str] = []
    if report["stopped_hosts"]:
        nxt.append(
            "host(s) stopped on a gate/limit/environment block: do not retry or evade; "
            "hand to a person (interactive capture) or drop the target. See docs/gate-policy.md."
        )
    if report["stopped"]:
        nxt.append(f"stopped on {report['stopped']}; re-run later to resume (checked endpoints are skipped).")
    if report["errors"]:
        nxt.append("some endpoints errored (status left unchanged); re-run later.")
    return nxt
