import json
from datetime import UTC, datetime

import httpx
import pytest

from vulnscan.models import PYPI, WORDPRESS, Declaration
from vulnscan.msteams import MAX_PAYLOAD_BYTES, TeamsClient, render_card, render_payload
from vulnscan.notify import AdvisoryNote, Notification, NotificationError

CARD_TYPE = "application/vnd.microsoft.card.adaptive"


def _note(**kwargs) -> AdvisoryNote:
    base = dict(
        guid="g1",
        id="GHSA-A1",
        summary="JWT confusion",
        details="Long description of the problem.",
        severity="HIGH",
        cvss="CVSS:3.1/AV:N",
        cve_ids=("CVE-2025-1",),
        url="https://osv.dev/vulnerability/GHSA-A1",
        fixed_versions=("1.3.1",),
        lowest_fix="1.3.1",
        fix_available=True,
        published=datetime(2025, 3, 1, tzinfo=UTC),
        references=("https://example.com/a1",),
    )
    base.update(kwargs)
    return AdvisoryNote(**base)


def _notification(**kwargs) -> Notification:
    base = dict(
        project="mysite",
        package="authlib",
        ecosystem=PYPI,
        kind="",
        version="1.2.0",
        version_source="lock",
        declared_in=(
            Declaration("requirements/base.txt", "==1.2.0"),
            Declaration("requirements/production.txt", ">=1.2"),
        ),
        severity="CRITICAL",
        advisories=(
            _note(),
            _note(guid="g2", id="GHSA-A2", summary="Second", severity="CRITICAL", cve_ids=()),
        ),
        nearest_safe="1.4.0",
        latest="1.6.12",
        latest_is_safe=True,
        versions_checked=True,
    )
    base.update(kwargs)
    return Notification(**base)


def _texts(node) -> list[str]:
    """Every string anywhere in the card, for content assertions."""
    if isinstance(node, dict):
        return [t for v in node.values() for t in _texts(v)]
    if isinstance(node, list):
        return [t for v in node for t in _texts(v)]
    return [node] if isinstance(node, str) else []


def _facts(card) -> dict[str, str]:
    facts = {}
    for element in card["body"]:
        if element.get("type") == "FactSet":
            for fact in element["facts"]:
                facts[fact["title"]] = fact["value"]
    return facts


def test_payload_is_a_teams_message_with_one_adaptive_card_attachment():
    payload = render_payload(_notification())
    assert payload["type"] == "message"
    assert len(payload["attachments"]) == 1
    attachment = payload["attachments"][0]
    assert attachment["contentType"] == CARD_TYPE
    assert attachment["contentUrl"] is None
    card = attachment["content"]
    assert card["type"] == "AdaptiveCard"
    assert card["$schema"] == "http://adaptivecards.io/schemas/adaptive-card.json"
    assert card["version"] == "1.4"
    assert isinstance(card["body"], list) and card["body"]


def test_card_headline_names_package_version_count_and_severity():
    card = render_card(_notification())
    headline = card["body"][0]
    assert headline["type"] == "TextBlock"
    assert "authlib" in headline["text"] and "1.2.0" in headline["text"]
    assert "2 new advisories" in headline["text"]
    assert headline["weight"] == "Bolder"
    assert headline["color"] == "Attention"
    facts = _facts(card)
    assert facts["Severity"].startswith("CRITICAL")
    assert "mysite" in facts["Project"]
    assert "1.2.0" in facts["Installed"] and "lock" in facts["Installed"]
    assert "requirements/base.txt" in facts["Declared in"]
    assert "requirements/production.txt" in facts["Declared in"]


def test_card_colour_follows_severity():
    assert render_card(_notification(severity="HIGH"))["body"][0]["color"] == "Attention"
    assert render_card(_notification(severity="MEDIUM"))["body"][0]["color"] == "Warning"
    assert render_card(_notification(severity="LOW"))["body"][0]["color"] == "Good"
    assert render_card(_notification(severity="UNKNOWN"))["body"][0]["color"] == "Default"


def test_card_states_the_upgrade_that_fixes_everything_and_its_availability():
    facts = _facts(render_card(_notification()))
    assert facts["Upgrade to"].startswith("1.4.0")
    assert "available" in facts["Upgrade to"].lower()
    assert "1.6.12" in facts["Latest release"]

    none_yet = _facts(
        render_card(_notification(nearest_safe=None, latest="1.2.1", latest_is_safe=False))
    )
    assert "no" in none_yet["Upgrade to"].lower()
    assert "1.2.1" in none_yet["Latest release"]
    assert "affected" in none_yet["Latest release"].lower()

    unchecked = _facts(
        render_card(
            _notification(
                versions_checked=False, nearest_safe=None, latest=None, latest_is_safe=None
            )
        )
    )
    assert (
        "could not" in unchecked["Upgrade to"].lower()
        or "unknown" in unchecked["Upgrade to"].lower()
    )


def test_card_describes_each_advisory_with_links_fix_and_severity():
    card = render_card(_notification())
    text = "\n".join(_texts(card))
    assert "[GHSA-A1](https://osv.dev/vulnerability/GHSA-A1)" in text
    assert "JWT confusion" in text
    assert "Long description of the problem." in text
    assert "[CVE-2025-1](https://nvd.nist.gov/vuln/detail/CVE-2025-1)" in text
    assert "CVSS:3.1/AV:N" in text
    assert "2025-03-01" in text
    assert "GHSA-A2" in text and "Second" in text
    sections = [e for e in card["body"] if e.get("type") == "Container"]
    assert len(sections) == 2
    first_facts = {
        f["title"]: f["value"]
        for e in sections[0]["items"]
        if e.get("type") == "FactSet"
        for f in e["facts"]
    }
    assert first_facts["Severity"].startswith("HIGH")
    assert first_facts["Fixed in"].startswith("1.3.1")
    assert "available" in first_facts["Fixed in"].lower()
    actions = card["actions"]
    assert [a["type"] for a in actions] == ["Action.OpenUrl", "Action.OpenUrl"]
    assert actions[0]["url"] == "https://osv.dev/vulnerability/GHSA-A1"
    assert "GHSA-A1" in actions[0]["title"]


def test_card_explains_missing_and_unavailable_fixes():
    card = render_card(
        _notification(
            advisories=(
                _note(fixed_versions=(), lowest_fix=None, fix_available=None),
                _note(guid="g2", id="GHSA-A2", fix_available=False),
                _note(guid="g3", id="GHSA-A3", fix_available=None),
            )
        )
    )
    values = [
        f["value"]
        for e in card["body"]
        if e.get("type") == "Container"
        for i in e["items"]
        if i.get("type") == "FactSet"
        for f in i["facts"]
        if f["title"] == "Fixed in"
    ]
    assert "no fix" in values[0].lower()
    assert "not" in values[1].lower() and "available" in values[1].lower()
    assert "1.3.1" in values[2] and "available" not in values[2].lower()


def test_card_for_wordpress_plugin_mentions_kind():
    card = render_card(
        _notification(package="wp-plugin/elementor", ecosystem=WORDPRESS, kind="plugin")
    )
    assert "plugin" in "\n".join(_texts(card)).lower()


def test_card_stays_under_the_teams_size_limit():
    many = tuple(
        _note(guid=f"g{i}", id=f"GHSA-{i:04d}", details="x" * 3000, summary=f"Issue {i}")
        for i in range(60)
    )
    payload = render_payload(_notification(advisories=many))
    encoded = json.dumps(payload).encode("utf-8")
    assert len(encoded) <= MAX_PAYLOAD_BYTES
    text = "\n".join(_texts(payload))
    assert "GHSA-0000" in text
    assert "more" in text.lower()  # tells the reader some advisories were left out


# --- client ---------------------------------------------------------------------------------


def _capture_transport(status: int = 202):
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(status, text="")

    return seen, httpx.MockTransport(handler)


def test_client_posts_the_card_as_json():
    seen, transport = _capture_transport()
    client = TeamsClient("https://example.webhook.office.com/abc", transport=transport)
    assert client.name == "msteams"
    client.send(_notification())
    assert len(seen) == 1
    request = seen[0]
    assert request.method == "POST"
    assert str(request.url) == "https://example.webhook.office.com/abc"
    assert request.headers["content-type"].startswith("application/json")
    payload = json.loads(request.content)
    assert payload["type"] == "message"
    assert payload["attachments"][0]["contentType"] == CARD_TYPE


def test_client_accepts_any_2xx():
    for status in (200, 202):
        _seen, transport = _capture_transport(status)
        TeamsClient("https://hook.test/x", transport=transport).send(_notification())


def test_client_raises_on_http_error():
    _seen, transport = _capture_transport(400)
    with pytest.raises(NotificationError, match="400"):
        TeamsClient("https://hook.test/x", transport=transport).send(_notification())


def test_client_raises_on_connection_failure():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    client = TeamsClient("https://hook.test/x", transport=httpx.MockTransport(handler))
    with pytest.raises(NotificationError):
        client.send(_notification())


def test_client_spaces_out_consecutive_sends():
    """Teams throttles at four requests a second, so back-to-back sends are paced."""
    _seen, transport = _capture_transport()
    pauses: list[float] = []
    client = TeamsClient("https://hook.test/x", transport=transport, sleep=pauses.append)
    client.send(_notification())
    client.send(_notification())
    client.send(_notification())
    assert len(pauses) >= 2
    assert all(p >= 0.25 for p in pauses)
