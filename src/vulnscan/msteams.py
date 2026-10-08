"""Microsoft Teams channel: Adaptive Cards posted to an incoming webhook.

The webhook is the URL of a Teams *Workflows* flow ("When a Teams webhook request is
received"), which also accepts the format of the retired Microsoft 365 connectors. Each
notification becomes one message carrying a single Adaptive Card, kept under the 28 KB
message limit, and consecutive posts are paced to stay under the four-per-second
throttle.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable

import httpx

from vulnscan.notify import AdvisoryNote, Notification, NotificationError, registry_name

MAX_PAYLOAD_BYTES = 28 * 1024
SCHEMA = "http://adaptivecards.io/schemas/adaptive-card.json"
CARD_CONTENT_TYPE = "application/vnd.microsoft.card.adaptive"
NVD_URL = "https://nvd.nist.gov/vuln/detail/{cve}"
MIN_SECONDS_BETWEEN_POSTS = 0.3
MAX_ACTIONS = 6
DETAILS_CHARS = 700

_COLOUR = {
    "CRITICAL": "Attention",
    "HIGH": "Attention",
    "MEDIUM": "Warning",
    "LOW": "Good",
    "UNKNOWN": "Default",
}
_EMOJI = {"CRITICAL": "🚨", "HIGH": "⚠️", "MEDIUM": "⚠️", "LOW": "ℹ️", "UNKNOWN": "❔"}


def _plural(count: int, singular: str, plural: str) -> str:
    return f"{count} {singular if count == 1 else plural}"


def _text(text: str, **attrs: object) -> dict:
    return {"type": "TextBlock", "text": text, "wrap": True, **attrs}


def _facts(pairs: list[tuple[str, str]]) -> dict:
    return {"type": "FactSet", "facts": [{"title": k, "value": v} for k, v in pairs]}


def _upgrade_fact(notification: Notification, registry: str) -> str:
    if not notification.versions_checked:
        return f"Unknown: could not check {registry} for available versions"
    if notification.nearest_safe:
        return f"{notification.nearest_safe} (available on {registry}; clears every advisory)"
    if notification.latest:
        return f"No safe version is available on {registry} yet"
    return f"No newer version found on {registry}"


def _latest_fact(notification: Notification) -> str:
    if not notification.latest:
        return "unknown"
    state = "not affected" if notification.latest_is_safe else "still affected"
    return f"{notification.latest} ({state})"


def _fix_fact(note: AdvisoryNote, registry: str) -> str:
    if note.lowest_fix is None:
        if note.fixed_versions:
            return "No fix above the installed version; fixed only in " + ", ".join(
                note.fixed_versions
            )
        return "No fix listed"
    if note.fix_available is True:
        return f"{note.lowest_fix} (available on {registry})"
    if note.fix_available is False:
        return f"{note.lowest_fix} (not yet available on {registry})"
    return note.lowest_fix


def _advisory_section(note: AdvisoryNote, registry: str, details_chars: int) -> dict:
    heading = f"[{note.id}]({note.url})"
    if note.summary:
        heading += f": {note.summary}"
    severity = note.severity + (f" ({note.cvss})" if note.cvss else "")
    cves = ", ".join(f"[{cve}]({NVD_URL.format(cve=cve)})" for cve in note.cve_ids) or "none"
    facts = [("Severity", severity), ("CVE", cves), ("Fixed in", _fix_fact(note, registry))]
    if note.published:
        facts.append(("Published", f"{note.published:%Y-%m-%d}"))
    items = [_text(heading, weight="Bolder"), _facts(facts)]
    details = " ".join(note.details.split())
    if details and details_chars > 0:
        if len(details) > details_chars:
            details = details[: details_chars - 1].rstrip() + "…"
        items.append(_text(details, isSubtle=True, spacing="Small"))
    return {"type": "Container", "separator": True, "spacing": "Medium", "items": items}


def _card(notification: Notification, limit: int, details_chars: int) -> dict:
    registry = registry_name(notification.ecosystem)
    package = notification.package
    if notification.kind:
        package += f" ({notification.ecosystem} {notification.kind})"
    else:
        package += f" ({notification.ecosystem})"
    count = _plural(len(notification.advisories), "new advisory", "new advisories")
    installed = notification.version or "unknown"
    if notification.version:
        installed += f" (from {notification.version_source})"
    body = [
        _text(
            f"{_EMOJI[notification.severity]} {notification.package} "
            f"{notification.version or '(unknown version)'}: {count}",
            size="Large",
            weight="Bolder",
            color=_COLOUR[notification.severity],
        ),
        _facts(
            [
                ("Severity", f"{notification.severity} (worst of the new advisories)"),
                ("Project", notification.project),
                ("Package", package),
                ("Installed", installed),
                ("Upgrade to", _upgrade_fact(notification, registry)),
                ("Latest release", _latest_fact(notification)),
                ("Declared in", notification.declared_in_text),
            ]
        ),
    ]
    shown = notification.advisories[:limit]
    body += [_advisory_section(note, registry, details_chars) for note in shown]
    left_out = len(notification.advisories) - len(shown)
    if left_out:
        body.append(
            _text(
                f"…and {_plural(left_out, 'more advisory', 'more advisories')} not shown here; "
                "see the full report or feed.",
                isSubtle=True,
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
    """Build the Adaptive Card for a notification, trimmed to fit the Teams size limit.

    Details are shortened first, then dropped, then advisories are cut from the end
    (with a line saying how many were left out) until the message fits.
    """
    total = len(notification.advisories)
    for details_chars in (DETAILS_CHARS, 250, 0):
        card = _card(notification, total, details_chars)
        if _size(_envelope(card)) <= MAX_PAYLOAD_BYTES:
            return card
    limit = total
    while limit > 1:
        limit = max(1, limit // 2)
        card = _card(notification, limit, 0)
        if _size(_envelope(card)) <= MAX_PAYLOAD_BYTES:
            return card
    return card


def render_payload(notification: Notification) -> dict:
    """The JSON body to POST: a Teams message with one Adaptive Card attachment."""
    return _envelope(render_card(notification))


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

    def send(self, notification: Notification) -> None:
        """POST the card; raise :class:`NotificationError` unless the webhook answers 2xx."""
        payload = render_payload(notification)
        self._pace()
        try:
            response = self._client.post(self.webhook_url, json=payload)
        except httpx.HTTPError as exc:
            raise NotificationError(f"could not reach the Teams webhook: {exc}") from exc
        if response.status_code >= 300:
            raise NotificationError(
                f"Teams webhook answered {response.status_code}: {response.text[:200]}"
            )
