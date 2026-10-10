"""Shared notification machinery behind ``--ntfy`` and ``--msteams``.

A :class:`Notification` describes one dependency and the advisories that have not yet
been sent to a channel, enriched with what the package registry says about fixes: the
lowest fixed version above the installed one, whether it has actually been published,
and the smallest upgrade that clears every advisory. Channels (``vulnscan.ntfy``,
``vulnscan.msteams``) only render and deliver it.

Each (dependency, advisory) pair has a stable id (the same one used for feed entries).
Every channel keeps its own state file of sent ids, written only after a delivery was
accepted, so a failed push is retried on the next cycle and a channel added later
receives everything on its first run.
"""

from __future__ import annotations

import json
import logging
import os
import signal
import threading
from collections.abc import Callable, Collection, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from vulnscan.config import Settings
from vulnscan.feeds import entry_guid
from vulnscan.models import (
    NPM,
    PACKAGIST,
    PYPI,
    WORDPRESS,
    Declaration,
    Dependency,
    Finding,
    ScanResult,
    Vulnerability,
    normalize_severity,
    severity_rank,
)
from vulnscan.osv import OSVError
from vulnscan.registry import RegistryError
from vulnscan.remediate import plan_remediation
from vulnscan.scanner import scan
from vulnscan.versioncmp import compare_versions, sort_versions
from vulnscan.wordfence import WordfenceError

log = logging.getLogger("vulnscan.notify")

SCAN_ERRORS = (OSVError, WordfenceError)

VersionsFn = Callable[[Dependency], list[str]]


_REGISTRY_NAMES = {PYPI: "PyPI", PACKAGIST: "Packagist", WORDPRESS: "wordpress.org", NPM: "npm"}


def registry_name(ecosystem: str) -> str:
    """Human name of the registry that publishes an ecosystem's packages."""
    return _REGISTRY_NAMES.get(ecosystem, "the registry")


class NotificationError(Exception):
    """Raised when a channel cannot deliver a notification."""


@dataclass(frozen=True)
class AdvisoryNote:
    """One advisory as presented in a notification.

    ``lowest_fix`` is the smallest fixed version above the installed one (``None`` when
    no fix is listed or none is above it). ``fix_available`` says whether that version
    exists on the registry; ``None`` means the registry was not consulted or failed.
    """

    guid: str
    id: str
    summary: str
    details: str
    severity: str
    cvss: str | None
    cve_ids: tuple[str, ...]
    url: str
    fixed_versions: tuple[str, ...]
    lowest_fix: str | None
    fix_available: bool | None
    published: datetime | None
    references: tuple[str, ...]


@dataclass(frozen=True)
class Notification:
    """One dependency with its newly seen advisories and upgrade advice.

    ``severity`` is the worst among *these* advisories. ``nearest_safe`` is the smallest
    published version above the installed one that none of the dependency's advisories
    affect; ``latest`` / ``latest_is_safe`` describe the newest release. All three are
    ``None`` when ``versions_checked`` is false.
    """

    project: str
    package: str
    ecosystem: str
    kind: str
    version: str | None
    version_source: str
    declared_in: tuple[Declaration, ...]
    severity: str
    advisories: tuple[AdvisoryNote, ...]
    nearest_safe: str | None
    latest: str | None
    latest_is_safe: bool | None
    versions_checked: bool

    @property
    def guids(self) -> tuple[str, ...]:
        """Ids of the advisories this notification covers."""
        return tuple(a.guid for a in self.advisories)

    @property
    def source_files(self) -> list[str]:
        """Distinct manifests declaring the package, in declaration order."""
        return list(dict.fromkeys(d.source_file for d in self.declared_in))

    @property
    def declared_in_text(self) -> str:
        """``file as constraint`` for every declaration, ``;`` separated."""
        return "; ".join(
            f"{d.source_file} as {d.constraint or 'any version'}" for d in self.declared_in
        )


class Channel(Protocol):
    """Something that can deliver a :class:`Notification`."""

    name: str

    def send(self, notification: Notification) -> None:
        """Deliver it, raising :class:`NotificationError` on failure."""

    def send_test(self, project: str) -> None:
        """Deliver a short test message, raising :class:`NotificationError` on failure."""


@dataclass(frozen=True)
class Target:
    """A channel together with the file recording what it has already received."""

    channel: Channel
    state_path: Path


@dataclass(frozen=True)
class NotifyReport:
    """What one :func:`notify` call did for one channel."""

    channel: str
    messages_sent: int
    guids_sent: tuple[str, ...]
    messages_failed: int
    errors: tuple[str, ...]


# --- building ---------------------------------------------------------------------------------


def _lowest_fix(vuln: Vulnerability, current: str | None, ecosystem: str) -> str | None:
    ordered = sort_versions(list(dict.fromkeys(vuln.fixed_versions)), ecosystem)
    if current is not None:
        ordered = [v for v in ordered if compare_versions(v, current, ecosystem) > 0]
    return ordered[0] if ordered else None


def _is_published(version: str | None, versions: list[str] | None, ecosystem: str) -> bool | None:
    if version is None or versions is None:
        return None
    return any(compare_versions(version, v, ecosystem) == 0 for v in versions)


def _note(
    guid: str, vuln: Vulnerability, dep: Dependency, versions: list[str] | None
) -> AdvisoryNote:
    lowest = _lowest_fix(vuln, dep.version, dep.ecosystem)
    return AdvisoryNote(
        guid=guid,
        id=vuln.id,
        summary=vuln.summary,
        details=vuln.details,
        severity=normalize_severity(vuln.severity),
        cvss=vuln.cvss,
        cve_ids=tuple(vuln.cve_ids),
        url=vuln.url,
        fixed_versions=tuple(dict.fromkeys(vuln.fixed_versions)),
        lowest_fix=lowest,
        fix_available=_is_published(lowest, versions, dep.ecosystem),
        published=vuln.published,
        references=tuple(vuln.references),
    )


class _VersionCache:
    """Memoises registry lookups per dependency; a failure is remembered as ``None``."""

    def __init__(self, versions_fn: VersionsFn | None) -> None:
        self._fn = versions_fn
        self._seen: dict[tuple, list[str] | None] = {}

    def get(self, dep: Dependency) -> list[str] | None:
        if self._fn is None:
            return None
        if dep.key not in self._seen:
            try:
                self._seen[dep.key] = list(self._fn(dep))
            except RegistryError as exc:
                log.warning("could not list versions of %s: %s", dep.name, exc)
                self._seen[dep.key] = None
        return self._seen[dep.key]


def _notification(
    project: str, finding: Finding, new: list[tuple[str, Vulnerability]], cache: _VersionCache
) -> Notification:
    dep = finding.dependency
    versions = cache.get(dep)
    notes = tuple(_note(guid, vuln, dep, versions) for guid, vuln in new)
    worst = min((n.severity for n in notes), key=severity_rank)
    nearest_safe = latest = latest_is_safe = None
    if versions is not None:
        plan = plan_remediation(finding, versions)
        nearest_safe, latest, latest_is_safe = plan.nearest_safe, plan.latest, plan.latest_is_safe
    return Notification(
        project=project,
        package=dep.name,
        ecosystem=dep.ecosystem,
        kind=dep.kind,
        version=dep.version,
        version_source=dep.version_source,
        declared_in=tuple(dep.declared_in),
        severity=worst,
        advisories=notes,
        nearest_safe=nearest_safe,
        latest=latest,
        latest_is_safe=latest_is_safe,
        versions_checked=versions is not None,
    )


def build_notifications(
    result: ScanResult, already_sent: Collection[str], versions_fn: VersionsFn | None = None
) -> list[Notification]:
    """One notification per dependency with at least one advisory not in ``already_sent``.

    ``versions_fn`` lists the versions published for a dependency (see
    :class:`vulnscan.registry.RegistryClient`); it is called at most once per dependency
    and a :class:`RegistryError` only leaves the upgrade advice blank.
    """
    return _build(result, already_sent, _VersionCache(versions_fn))


def _build(result: ScanResult, already_sent: Collection[str], cache: _VersionCache):
    project = result.project_path.name or "project"
    notifications: list[Notification] = []
    for finding in result.findings:
        new = [
            (guid, vuln)
            for vuln in finding.vulnerabilities
            if (guid := entry_guid(project, finding.dependency, vuln)) not in already_sent
        ]
        if new:
            notifications.append(_notification(project, finding, new, cache))
    return notifications


# --- state and delivery -----------------------------------------------------------------------


def load_sent(path: Path) -> dict[str, str]:
    """Read a sent-state file: guid -> ISO timestamp. Missing or corrupt files are empty."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {str(k): str(v) for k, v in data.items() if isinstance(v, str)}


def save_sent(path: Path, sent: dict[str, str]) -> None:
    """Atomically write a sent-state file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(sent, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(tmp, path)


def _deliver(
    result: ScanResult, target: Target, resend: bool, cache: _VersionCache, now: datetime
) -> NotifyReport:
    sent = load_sent(target.state_path)
    notifications = _build(result, set() if resend else set(sent), cache)
    delivered: list[str] = []
    errors: list[str] = []
    for notification in notifications:
        try:
            target.channel.send(notification)
        except NotificationError as exc:
            errors.append(f"{notification.package} {notification.version or ''}: {exc}".strip())
            continue
        stamp = now.isoformat()
        for guid in notification.guids:
            sent.setdefault(guid, stamp)
        delivered.extend(notification.guids)
    if delivered or resend:
        save_sent(target.state_path, sent)
    return NotifyReport(
        channel=target.channel.name,
        messages_sent=len(notifications) - len(errors),
        guids_sent=tuple(delivered),
        messages_failed=len(errors),
        errors=tuple(errors),
    )


def notify(
    result: ScanResult,
    target: Target,
    resend: bool = False,
    versions_fn: VersionsFn | None = None,
    now: datetime | None = None,
) -> NotifyReport:
    """Send every finding the target has not yet received (all of them when ``resend``).

    The state file is updated after each successful delivery, so a failure part-way
    through loses nothing.
    """
    return _deliver(result, target, resend, _VersionCache(versions_fn), now or datetime.now(UTC))


def notify_all(
    result: ScanResult,
    targets: Sequence[Target],
    resend: bool = False,
    versions_fn: VersionsFn | None = None,
    now: datetime | None = None,
) -> list[NotifyReport]:
    """:func:`notify` every target, sharing one registry lookup per dependency."""
    cache = _VersionCache(versions_fn)
    now = now or datetime.now(UTC)
    return [_deliver(result, target, resend, cache, now) for target in targets]


# --- watch loop -------------------------------------------------------------------------------


class WatchControl:
    """Thread- and signal-safe flags that steer :func:`run_watch`."""

    def __init__(self) -> None:
        self._wake = threading.Event()
        self._stop = False
        self._resend = False

    @property
    def stop_requested(self) -> bool:
        """Whether :meth:`request_stop` has been called."""
        return self._stop

    def request_stop(self) -> None:
        """Ask the loop to exit, waking it if it is sleeping."""
        self._stop = True
        self._wake.set()

    def request_resend(self) -> None:
        """Ask the loop to re-send every current finding on its next cycle, waking it."""
        self._resend = True
        self._wake.set()

    def take_resend(self) -> bool:
        """Return whether a resend was requested, clearing the request."""
        requested, self._resend = self._resend, False
        return requested

    def wait(self, seconds: float) -> None:
        """Sleep for ``seconds`` unless a stop or resend request arrives first."""
        if self._stop:
            return
        self._wake.wait(timeout=seconds)
        self._wake.clear()


def install_signal_handlers(control: WatchControl) -> None:
    """SIGUSR1 re-sends everything; SIGINT and SIGTERM stop the loop cleanly."""

    def stop(signum, _frame) -> None:
        log.info("received %s, stopping", signal.Signals(signum).name)
        control.request_stop()

    def resend(_signum, _frame) -> None:
        log.info("received SIGUSR1, re-sending every current finding")
        control.request_resend()

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    if hasattr(signal, "SIGUSR1"):
        signal.signal(signal.SIGUSR1, resend)


def run_watch(
    settings: Settings,
    control: WatchControl,
    targets: Sequence[Target],
    scan_fn: Callable[[Settings], ScanResult] | None = None,
    versions_fn: VersionsFn | None = None,
    resend_first: bool = False,
    once: bool = False,
) -> int:
    """Scan, notify every target, sleep ``settings.interval_minutes``, repeat until stopped.

    Scan and delivery failures are logged and the loop carries on. With ``once`` a single
    cycle runs and the exit code reflects whether that cycle's scan succeeded.
    """
    scan_fn = scan_fn or scan
    interval = max(settings.interval_minutes, 0.0) * 60
    resend = resend_first
    while True:
        log.info("scanning %s", settings.project_path)
        try:
            result = scan_fn(settings)
        except SCAN_ERRORS as exc:
            log.error("scan failed: %s", exc)
            if once:
                return 1
        else:
            for warning in result.warnings:
                log.warning("%s", warning)
            reports = notify_all(result, targets, resend=resend, versions_fn=versions_fn)
            for report in reports:
                for error in report.errors:
                    log.error("%s: could not deliver %s", report.channel, error)
                log.info(
                    "%s: %d vulnerable of %d dependencies; sent %d notification(s), %d failed",
                    report.channel,
                    len(result.findings),
                    len(result.dependencies),
                    report.messages_sent,
                    report.messages_failed,
                )
        if once:
            return 0
        resend = False
        control.wait(interval)
        if control.stop_requested:
            return 0
        if control.take_resend():
            resend = True
