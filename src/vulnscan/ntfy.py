"""Push notifications for new findings to an `ntfy <https://ntfy.sh>`_ topic, and the
continuous watch loop behind ``vulnscan --ntfy``.

Each (dependency, advisory) pair has a stable id (the same one used for feed entries).
Ids are recorded in a state file only after a notification was accepted by the server,
so nothing is lost when a push fails: it is simply retried on the next cycle.
"""

from __future__ import annotations

import json
import logging
import os
import signal
import threading
from collections.abc import Callable, Collection
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import httpx

from vulnscan.config import Settings
from vulnscan.feeds import entry_guid
from vulnscan.models import Finding, ScanResult, Vulnerability, normalize_severity, severity_rank
from vulnscan.osv import OSVError
from vulnscan.scanner import scan
from vulnscan.wordfence import WordfenceError

log = logging.getLogger("vulnscan.ntfy")

SCAN_ERRORS = (OSVError, WordfenceError)

_PRIORITY = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "UNKNOWN": 3}
_EMOJI = {
    "CRITICAL": "rotating_light",
    "HIGH": "warning",
    "MEDIUM": "warning",
    "LOW": "information_source",
    "UNKNOWN": "question",
}


class NtfyError(Exception):
    """Raised when a notification cannot be published."""


@dataclass(frozen=True)
class NtfyMessage:
    """One notification, covering the advisories identified by ``guids``."""

    title: str
    body: str
    priority: int
    tags: tuple[str, ...]
    click: str | None
    guids: tuple[str, ...]


@dataclass(frozen=True)
class NotifyReport:
    """What one :func:`notify` call did."""

    messages_sent: int
    guids_sent: tuple[str, ...]
    messages_failed: int
    errors: tuple[str, ...]


class NtfyClient:
    """Publish messages to one topic on an ntfy server using the JSON publishing API.

    Authentication is a bearer ``token`` or a ``user``/``password`` pair; the token wins
    if both are given. ``transport`` is for tests.
    """

    def __init__(
        self,
        server: str,
        topic: str,
        token: str = "",
        user: str = "",
        password: str = "",
        timeout: float = 30.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.server = server.rstrip("/")
        self.topic = topic
        headers = {"User-Agent": "vulnscan"}
        auth = None
        if token:
            headers["Authorization"] = f"Bearer {token}"
        elif user:
            auth = (user, password)
        self._client = httpx.Client(
            base_url=self.server + "/",
            headers=headers,
            auth=auth,
            timeout=timeout,
            transport=transport,
        )

    def publish(self, message: NtfyMessage) -> None:
        """POST the message; raise :class:`NtfyError` unless the server answers 2xx."""
        payload: dict[str, object] = {
            "topic": self.topic,
            "title": message.title,
            "message": message.body,
            "priority": message.priority,
            "tags": list(message.tags),
        }
        if message.click:
            payload["click"] = message.click
        try:
            response = self._client.post("/", json=payload)
        except httpx.HTTPError as exc:
            raise NtfyError(f"could not reach {self.server}: {exc}") from exc
        if response.status_code >= 300:
            raise NtfyError(
                f"{self.server} answered {response.status_code} for topic {self.topic!r}: "
                f"{response.text[:200]}"
            )


def severity_priority(severity: str) -> int:
    """Map a severity label to ntfy's 1 (min) to 5 (urgent) scale."""
    return _PRIORITY[normalize_severity(severity)]


def _plural(count: int, singular: str, plural: str) -> str:
    return f"{count} {singular if count == 1 else plural}"


def _advisory_lines(vuln: Vulnerability) -> list[str]:
    head = vuln.id
    if vuln.cve_ids and vuln.id not in vuln.cve_ids:
        head += f" ({', '.join(vuln.cve_ids)})"
    head += f" [{normalize_severity(vuln.severity)}]"
    if vuln.summary:
        head += f": {vuln.summary}"
    lines = [head]
    lines.append(f"  fixed in: {', '.join(vuln.fixed_versions) or 'no fix listed'}")
    return lines


def _message_for(
    project: str, finding: Finding, new: list[tuple[str, Vulnerability]]
) -> NtfyMessage:
    dep = finding.dependency
    vulns = [v for _, v in new]
    worst = min((normalize_severity(v.severity) for v in vulns), key=severity_rank)
    title = (
        f"{dep.name} {dep.version or '(unknown version)'}: "
        f"{_plural(len(vulns), 'new advisory', 'new advisories')}"
    )
    body_lines = [f"Project: {project}", f"Severity: {worst}", ""]
    for vuln in vulns:
        body_lines.extend(_advisory_lines(vuln))
    body_lines += ["", f"Declared in: {', '.join(dep.source_files)}"]
    return NtfyMessage(
        title=title,
        body="\n".join(body_lines),
        priority=severity_priority(worst),
        tags=(_EMOJI[worst], worst.lower()),
        click=vulns[0].url,
        guids=tuple(guid for guid, _ in new),
    )


def build_messages(result: ScanResult, already_sent: Collection[str]) -> list[NtfyMessage]:
    """One message per dependency that has at least one advisory not in ``already_sent``."""
    project = result.project_path.name or "project"
    messages: list[NtfyMessage] = []
    for finding in result.findings:
        new = [
            (guid, vuln)
            for vuln in finding.vulnerabilities
            if (guid := entry_guid(project, finding.dependency, vuln)) not in already_sent
        ]
        if new:
            messages.append(_message_for(project, finding, new))
    return messages


def load_sent(path: Path) -> dict[str, str]:
    """Read the sent-state file: guid -> ISO timestamp. Missing or corrupt files are empty."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {str(k): str(v) for k, v in data.items() if isinstance(v, str)}


def save_sent(path: Path, sent: dict[str, str]) -> None:
    """Atomically write the sent-state file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(sent, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(tmp, path)


def notify(
    result: ScanResult,
    settings: Settings,
    client: NtfyClient,
    resend: bool = False,
    now: datetime | None = None,
) -> NotifyReport:
    """Push every finding not yet sent for this project (all of them when ``resend``).

    The state file is updated after each successful publish, so a failure part-way
    through loses nothing.
    """
    now = now or datetime.now(UTC)
    sent = load_sent(settings.ntfy_state_path)
    messages = build_messages(result, set() if resend else set(sent))
    delivered: list[str] = []
    errors: list[str] = []
    for message in messages:
        try:
            client.publish(message)
        except NtfyError as exc:
            errors.append(f"{message.title}: {exc}")
            continue
        stamp = now.isoformat()
        for guid in message.guids:
            sent.setdefault(guid, stamp)
        delivered.extend(message.guids)
    if delivered or resend:
        save_sent(settings.ntfy_state_path, sent)
    return NotifyReport(
        messages_sent=len(messages) - len(errors),
        guids_sent=tuple(delivered),
        messages_failed=len(errors),
        errors=tuple(errors),
    )


class WatchControl:
    """Thread- and signal-safe flags that steer :func:`run_watch`."""

    def __init__(self) -> None:
        self._wake = threading.Event()
        self._stop = False
        self._resend = False

    @property
    def stop_requested(self) -> bool:
        return self._stop

    def request_stop(self) -> None:
        self._stop = True
        self._wake.set()

    def request_resend(self) -> None:
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
    client: NtfyClient,
    scan_fn: Callable[[Settings], ScanResult] | None = None,
    resend_first: bool = False,
    once: bool = False,
) -> int:
    """Scan, notify, sleep, repeat until ``control`` asks to stop.

    Scan and publish failures are logged and the loop carries on. With ``once`` a single
    cycle runs and the exit code reflects whether that cycle's scan succeeded.
    """
    scan_fn = scan_fn or scan
    interval = max(settings.ntfy_interval_minutes, 0.0) * 60
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
            report = notify(result, settings, client, resend=resend)
            for error in report.errors:
                log.error("could not publish: %s", error)
            log.info(
                "%d vulnerable of %d dependencies; sent %d notification(s), %d failed",
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
