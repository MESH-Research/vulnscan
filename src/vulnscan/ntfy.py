"""ntfy channel: plain-text push notifications to an `ntfy <https://ntfy.sh>`_ topic.

The watch loop and sent-state bookkeeping live in :mod:`vulnscan.notify`.
"""

from __future__ import annotations

from dataclasses import dataclass

import httpx

from vulnscan.models import normalize_severity
from vulnscan.notify import AdvisoryNote, Notification, NotificationError, registry_name

_PRIORITY = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "UNKNOWN": 3}
_EMOJI = {
    "CRITICAL": "rotating_light",
    "HIGH": "warning",
    "MEDIUM": "warning",
    "LOW": "information_source",
    "UNKNOWN": "question",
}


@dataclass(frozen=True)
class NtfyMessage:
    """One notification as ntfy sees it, covering the advisories identified by ``guids``."""

    title: str
    body: str
    priority: int
    tags: tuple[str, ...]
    click: str | None
    guids: tuple[str, ...]


class NtfyClient:
    """Notification channel publishing to one topic on an ntfy server via its JSON API.

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

    name = "ntfy"

    def send(self, notification: Notification) -> None:
        """Render the notification as text and publish it."""
        self.publish(render_ntfy(notification))

    def publish(self, message: NtfyMessage) -> None:
        """POST the message; raise :class:`NotificationError` unless the server answers 2xx."""
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
            raise NotificationError(f"could not reach {self.server}: {exc}") from exc
        if response.status_code >= 300:
            raise NotificationError(
                f"{self.server} answered {response.status_code} for topic {self.topic!r}: "
                f"{response.text[:200]}"
            )


def severity_priority(severity: str) -> int:
    """Map a severity label to ntfy's 1 (min) to 5 (urgent) scale."""
    return _PRIORITY[normalize_severity(severity)]


def _plural(count: int, singular: str, plural: str) -> str:
    return f"{count} {singular if count == 1 else plural}"


def _fix_text(note: AdvisoryNote, registry: str) -> str:
    if note.lowest_fix is None:
        return (
            "no fix listed"
            if not note.fixed_versions
            else ("fixed only in " + ", ".join(note.fixed_versions))
        )
    if note.fix_available is True:
        return f"{note.lowest_fix} (available on {registry})"
    if note.fix_available is False:
        return f"{note.lowest_fix} (not yet available on {registry})"
    return note.lowest_fix


def _upgrade_text(notification: Notification, registry: str) -> str:
    if not notification.versions_checked:
        return f"Upgrade to: unknown (could not check {registry} for available versions)"
    if notification.nearest_safe:
        return f"Upgrade to: {notification.nearest_safe} (available on {registry}, clears all)"
    if notification.latest:
        return (
            f"Upgrade to: no safe version available yet on {registry} "
            f"(latest {notification.latest} is still affected)"
        )
    return f"Upgrade to: no newer version found on {registry}"


def render_ntfy(notification: Notification) -> NtfyMessage:
    """Turn a notification into an ntfy title, body, priority, tags and click URL."""
    registry = registry_name(notification.ecosystem)
    count = _plural(len(notification.advisories), "new advisory", "new advisories")
    title = f"{notification.package} {notification.version or '(unknown version)'}: {count}"
    lines = [
        f"Project: {notification.project}",
        f"Severity: {notification.severity}",
        _upgrade_text(notification, registry),
        "",
    ]
    for note in notification.advisories:
        head = note.id
        if note.cve_ids and note.id not in note.cve_ids:
            head += f" ({', '.join(note.cve_ids)})"
        head += f" [{note.severity}]"
        if note.summary:
            head += f": {note.summary}"
        lines += [head, f"  fixed in: {_fix_text(note, registry)}"]
    lines += ["", f"Declared in: {', '.join(notification.source_files)}"]
    return NtfyMessage(
        title=title,
        body="\n".join(lines),
        priority=severity_priority(notification.severity),
        tags=(_EMOJI[notification.severity], notification.severity.lower()),
        click=notification.advisories[0].url if notification.advisories else None,
        guids=notification.guids,
    )
