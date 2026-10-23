"""Live view of HTTP transfers: what is being fetched, how far along, how it ended.

:class:`vulnscan.debuglog.Client` publishes a :class:`Transfer` snapshot when a request
starts, when the response headers arrive, as the body streams in and when it finishes
or fails. Anything, such as the TUI's activity panel, can :func:`subscribe`. Observers
are called on the thread that performs the request and must return quickly.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from dataclasses import dataclass
from itertools import count
from urllib.parse import parse_qs, unquote, urlsplit

log = logging.getLogger("vulnscan.activity")

_lock = threading.Lock()
_observers: list[Observer] = []
_ids = count(1)

_DOCKER_HUB_HOSTS = frozenset({"registry-1.docker.io", "index.docker.io", "docker.io"})
_UNITS = ("B", "kB", "MB", "GB", "TB")


@dataclass(frozen=True)
class Transfer:
    """One HTTP exchange as seen from outside: immutable, replaced on every change."""

    id: int
    method: str
    url: str
    started: float
    total: int | None = None
    """Bytes the server announced (``Content-Length``), or None when unknown."""
    received: int = 0
    status: int | None = None
    error: str | None = None
    finished: float | None = None

    @property
    def done(self) -> bool:
        """Whether the exchange is over, successfully or not."""
        return self.finished is not None

    @property
    def failed(self) -> bool:
        """Whether it ended with a transport error."""
        return self.error is not None

    @property
    def fraction(self) -> float | None:
        """Share of the body received, 0 to 1, or None when the size is unknown."""
        if not self.total:
            return None
        return min(1.0, self.received / self.total)


Observer = Callable[[Transfer], None]


def subscribe(observer: Observer) -> None:
    """Start receiving every :class:`Transfer` snapshot."""
    with _lock:
        if observer not in _observers:
            _observers.append(observer)


def unsubscribe(observer: Observer) -> None:
    """Stop receiving snapshots; unknown observers are ignored."""
    with _lock:
        try:
            _observers.remove(observer)
        except ValueError:
            pass


def reset() -> None:
    """Drop every observer (for tests)."""
    with _lock:
        _observers.clear()


def next_id() -> int:
    """A process-wide unique transfer id."""
    with _lock:
        return next(_ids)


def publish(transfer: Transfer) -> None:
    """Hand a snapshot to every observer; an observer that raises is skipped."""
    with _lock:
        observers = list(_observers)
    for observer in observers:
        try:
            observer(transfer)
        except Exception:  # noqa: BLE001 - a broken observer must not break the request
            log.debug("activity observer failed", exc_info=True)


def describe(method: str, url: str) -> str:
    """A short human label for a request: ``PyPI requests``, ``Wordfence feed``.

    Known advisory sources and registries get a name and the package, advisory or
    image they are asked about; anything else is ``METHOD host/path``.
    """
    parts = urlsplit(url)
    host = parts.netloc.lower()
    segments = [unquote(s) for s in parts.path.split("/") if s]
    query = parse_qs(parts.query)
    if host == "api.osv.dev":
        if segments[:2] == ["v1", "vulns"] and len(segments) >= 3:
            return f"OSV {segments[2]}"
        if len(segments) >= 2:
            return f"OSV {segments[1]}"
        return "OSV"
    if host == "pypi.org" and segments[:1] == ["pypi"] and len(segments) >= 2:
        return f"PyPI {segments[1]}"
    if host == "registry.npmjs.org" and segments:
        return "npm " + "/".join(segments)
    if host == "repo.packagist.org" and segments[:1] == ["p2"] and len(segments) >= 2:
        return "Packagist " + "/".join(segments[1:]).removesuffix(".json")
    if host == "api.wordpress.org":
        slug = query.get("slug")
        return f"wordpress.org {slug[0]}" if slug else "wordpress.org " + "/".join(segments)
    if host.endswith("wordfence.com"):
        return "Wordfence feed"
    if host == "services.nvd.nist.gov":
        match = query.get("virtualMatchString")
        if match:
            return "NVD " + match[0].removeprefix("cpe:2.3:a:")
        return "NVD"
    if segments[:1] == ["v2"] and segments[-2:] == ["tags", "list"]:
        registry = "Docker Hub" if host in _DOCKER_HUB_HOSTS else host
        return f"{registry} {'/'.join(segments[1:-2])} tags"
    if segments and segments[-1] == "token":
        return f"{host} token"
    return f"{method.upper()} {host}{parts.path or '/'}"


def format_bytes(count: int) -> str:
    """``46 B``, ``12.4 kB``, ``73.2 MB``."""
    value = float(count)
    for unit in _UNITS:
        if value < 1000 or unit == _UNITS[-1]:
            break
        value /= 1000
    if unit == "B":
        return f"{count} B"
    return f"{value:.1f} {unit}"
