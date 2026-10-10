"""Microsoft Teams channel: Adaptive Cards posted to an incoming webhook.

The webhook is the URL of a Teams *Workflows* flow ("When a Teams webhook request is
received"), which also accepts the format of the retired Microsoft 365 connectors. Each
notification becomes one message carrying a single Adaptive Card, kept under the 28 KB
message limit, and consecutive posts are paced to stay under the four-per-second
throttle.
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Callable

import httpx

from vulnscan import __version__
from vulnscan.models import severity_rank
from vulnscan.notify import AdvisoryNote, Notification, NotificationError, registry_name

MAX_PAYLOAD_BYTES = 28 * 1024
SCHEMA = "http://adaptivecards.io/schemas/adaptive-card.json"
CARD_CONTENT_TYPE = "application/vnd.microsoft.card.adaptive"
NVD_URL = "https://nvd.nist.gov/vuln/detail/{cve}"
MIN_SECONDS_BETWEEN_POSTS = 0.3
MAX_ACTIONS = 3
MAX_LISTED = 6
SUMMARY_CHARS = 140

_COLOUR = {
    "CRITICAL": "Attention",
    "HIGH": "Attention",
    "MEDIUM": "Warning",
    "LOW": "Good",
    "UNKNOWN": "Default",
}
_MARKDOWN_LINK = re.compile(r"\[([^\]]*)\]\([^)]*\)")
_MARKDOWN_NOISE = re.compile(r"[#*_`~\[\]()<>|\\]+")
_WHITESPACE = re.compile(r"\s+")


def _plural(count: int, singular: str, plural: str) -> str:
    return f"{count} {singular if count == 1 else plural}"


def _plain(text: str, limit: int = SUMMARY_CHARS) -> str:
    """One line of plain text: Markdown control characters stripped, whitespace collapsed.

    Teams renders Markdown inside text blocks, so a summary containing ``###`` or
    backticks would otherwise change size or become code.
    """
    cleaned = _MARKDOWN_NOISE.sub("", _MARKDOWN_LINK.sub(r"\1", text))
    cleaned = _WHITESPACE.sub(" ", cleaned).strip()
    if len(cleaned) > limit:
        cleaned = cleaned[: limit - 1].rstrip() + "…"
    return cleaned


def _text(text: str, **attrs: object) -> dict:
    return {"type": "TextBlock", "text": text, "wrap": True, **attrs}


def _facts(pairs: list[tuple[str, str]]) -> dict:
    return {"type": "FactSet", "facts": [{"title": k, "value": v} for k, v in pairs]}


def _upgrade_fact(notification: Notification, registry: str) -> str:
    if not notification.versions_checked:
        return f"unknown ({registry} could not be checked)"
    if notification.nearest_safe:
        return f"{notification.nearest_safe} (available on {registry}; clears every advisory)"
    if notification.latest:
        return f"no safe version on {registry} yet"
    return f"no newer version found on {registry}"


def _latest_fact(notification: Notification) -> str:
    if not notification.latest:
        return "unknown"
    state = "not affected" if notification.latest_is_safe else "still affected"
    return f"{notification.latest} ({state})"


def _fix_text(note: AdvisoryNote) -> str:
    if note.lowest_fix is None:
        return "no fix listed"
    if note.fix_available is False:
        return f"fixed in {note.lowest_fix} (not yet published)"
    return f"fixed in {note.lowest_fix}"


def _advisory_line(note: AdvisoryNote) -> dict:
    """``**HIGH** [GHSA-x](url) · [CVE-y](url): summary · fixed in 1.2.3``, one line."""
    parts = [f"**{note.severity}**", f"[{note.id}]({note.url})"]
    parts += [f"[{cve}]({NVD_URL.format(cve=cve)})" for cve in note.cve_ids[:2]]
    line = " · ".join(parts)
    summary = _plain(note.summary)
    if summary:
        line += f": {summary}"
    line += f" · {_fix_text(note)}"
    return _text(line, spacing="Small")


def _card(notification: Notification, listed: int) -> dict:
    registry = registry_name(notification.ecosystem)
    count = _plural(len(notification.advisories), "new advisory", "new advisories")
    version = notification.version or "(unknown version)"
    headline = (
        f"New vulnerability on {notification.project}: {notification.package} {version}: {count}"
    )
    kind = (
        f"{notification.ecosystem} {notification.kind}"
        if notification.kind
        else notification.ecosystem
    )
    files = ", ".join(notification.source_files)
    installed = notification.version or "unknown"
    if notification.version:
        installed += f" (from {notification.version_source})"
    body: list[dict] = [
        _text(headline, size="Large", weight="Bolder", color=_COLOUR[notification.severity]),
        _text(
            f"{notification.severity} severity · {kind} · declared in {files}",
            isSubtle=True,
            spacing="None",
        ),
        _facts(
            [
                ("Installed", installed),
                ("Upgrade to", _upgrade_fact(notification, registry)),
                ("Latest release", _latest_fact(notification)),
            ]
        ),
    ]
    ordered = sorted(notification.advisories, key=lambda n: severity_rank(n.severity))
    shown = ordered[:listed]
    body.append(_text("Advisories", weight="Bolder", spacing="Medium", separator=True))
    body += [_advisory_line(note) for note in shown]
    left_out = len(notification.advisories) - len(shown)
    if left_out:
        body.append(
            _text(
                f"…and {left_out} more. See the full report or feed for the complete list.",
                isSubtle=True,
                spacing="Small",
            )
        )
    actions = [
        {"type": "Action.OpenUrl", "title": f"Open {note.id}", "url": note.url}
        for note in shown[:MAX_ACTIONS]
    ]
    return {
        "$schema": SCHEMA,
        "type": "AdaptiveCard",
        "version": "1.4",
        "msteams": {"width": "Full"},
        "body": body,
        "actions": actions,
    }


def _envelope(card: dict) -> dict:
    return {
        "type": "message",
        "attachments": [{"contentType": CARD_CONTENT_TYPE, "contentUrl": None, "content": card}],
    }


def _size(payload: dict) -> int:
    return len(json.dumps(payload, ensure_ascii=False).encode("utf-8"))


def render_card(notification: Notification) -> dict:
    """Build the Adaptive Card announcing a notification.

    The card is deliberately short: a headline, three facts and one line per advisory
    (at most :data:`MAX_LISTED`, each with links to the advisory and its CVE). Advisory
    descriptions are never included. If the card still exceeds the Teams size limit, fewer
    advisories are listed.
    """
    listed = min(len(notification.advisories), MAX_LISTED)
    while True:
        card = _card(notification, listed)
        if _size(_envelope(card)) <= MAX_PAYLOAD_BYTES or listed <= 1:
            return card
        listed = max(1, listed // 2)


def render_payload(notification: Notification) -> dict:
    """The JSON body to POST: a Teams message with one Adaptive Card attachment."""
    return _envelope(render_card(notification))


def render_test_card(project: str) -> dict:
    """A small Adaptive Card confirming that vulnscan can post here, for ``--test``."""
    return {
        "$schema": SCHEMA,
        "type": "AdaptiveCard",
        "version": "1.4",
        "msteams": {"width": "Full"},
        "body": [
            _text(f"vulnscan test message for {project}", size="Large", weight="Bolder"),
            _text(
                f"vulnscan {__version__} can post to this channel. Notifications for "
                f"{project} will arrive here when a new advisory affects one of its "
                "dependencies. Nothing was scanned and nothing was recorded.",
                spacing="Small",
            ),
        ],
        "actions": [],
    }


class TeamsClient:
    """Notification channel that posts Adaptive Cards to a Teams incoming webhook.

    ``transport`` and ``sleep`` are for tests.
    """

    name = "msteams"

    def __init__(
        self,
        webhook_url: str,
        timeout: float = 30.0,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] | None = None,
    ) -> None:
        self.webhook_url = webhook_url
        self._sleep = sleep or time.sleep
        self._last_post = 0.0
        self._client = httpx.Client(
            timeout=timeout, transport=transport, headers={"User-Agent": "vulnscan"}
        )

    def _pace(self) -> None:
        if self._last_post:
            gap = MIN_SECONDS_BETWEEN_POSTS - (time.monotonic() - self._last_post)
            if gap > 0:
                self._sleep(gap)
        self._last_post = time.monotonic()

    def send_test(self, project: str) -> None:
        """POST a single test card so the webhook can be checked."""
        self._post(_envelope(render_test_card(project)))

    def send(self, notification: Notification) -> None:
        """POST the card; raise :class:`NotificationError` unless the webhook answers 2xx."""
        self._post(render_payload(notification))

    def _post(self, payload: dict) -> None:
        self._pace()
        try:
            response = self._client.post(self.webhook_url, json=payload)
        except httpx.HTTPError as exc:
            raise NotificationError(f"could not reach the Teams webhook: {exc}") from exc
        if response.status_code >= 300:
            raise NotificationError(
                f"Teams webhook answered {response.status_code}: {response.text[:200]}"
            )
