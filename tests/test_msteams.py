import json
import re
from datetime import UTC, datetime

import httpx
import pytest

from vulnscan.models import PYPI, WORDPRESS, Declaration
from vulnscan.msteams import (
    MAX_LISTED,
    MAX_PAYLOAD_BYTES,
    TeamsClient,
    render_card,
    render_payload,
)
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


def _text_blocks(card) -> list[dict]:
    found = []

    def walk(node):
        if isinstance(node, dict):
            if node.get("type") == "TextBlock":
                found.append(node)
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(card["body"])
    return found


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


def test_headline_names_project_package_version_and_count():
    card = render_card(_notification())
    headline = _text_blocks(card)[0]
    assert headline["text"] == "New vulnerability on mysite: authlib 1.2.0: 2 new advisories"
    assert headline["weight"] == "Bolder"
    assert headline["size"] == "Large"
    assert headline["color"] == "Attention"
    single = render_card(_notification(advisories=(_note(),)))
    assert _text_blocks(single)[0]["text"].endswith("authlib 1.2.0: 1 new advisory")


def test_headline_colour_follows_severity():
    for severity, colour in (
        ("CRITICAL", "Attention"),
        ("HIGH", "Attention"),
        ("MEDIUM", "Warning"),
        ("LOW", "Good"),
        ("UNKNOWN", "Default"),
    ):
        assert _text_blocks(render_card(_notification(severity=severity)))[0]["color"] == colour


def test_card_summarises_severity_ecosystem_and_declaring_files():
    text = "\n".join(_texts(render_card(_notification())))
    assert "CRITICAL" in text
    assert "PyPI" in text
    assert "requirements/base.txt" in text
    assert "requirements/production.txt" in text


def test_card_states_installed_upgrade_and_latest():
    facts = _facts(render_card(_notification()))
    assert facts["Installed"].startswith("1.2.0")
    assert facts["Upgrade to"].startswith("1.4.0")
    assert "available" in facts["Upgrade to"].lower()
    assert "1.6.12" in facts["Latest release"]
    assert set(facts) == {"Installed", "Upgrade to", "Latest release"}

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
    assert "unknown" in unchecked["Upgrade to"].lower()


def test_each_advisory_is_one_line_with_links_severity_and_fix():
    card = render_card(_notification())
    lines = [b["text"] for b in _text_blocks(card) if "GHSA-A" in b["text"]]
    assert len(lines) == 2
    second, first = lines  # CRITICAL GHSA-A2 sorts above HIGH GHSA-A1
    assert "[GHSA-A1](https://osv.dev/vulnerability/GHSA-A1)" in first
    assert "[CVE-2025-1](https://nvd.nist.gov/vuln/detail/CVE-2025-1)" in first
    assert "HIGH" in first
    assert "JWT confusion" in first
    assert "1.3.1" in first
    assert "CRITICAL" in second and "Second" in second
    # No descriptions, CVSS vectors or dates: this is an announcement.
    text = "\n".join(_texts(card))
    assert "Long description" not in text
    assert "CVSS:" not in text
    assert "2025-03-01" not in text


def test_advisory_lines_have_consistent_size_and_no_markdown_from_sources():
    noisy = _note(summary="### Details `script` **bold** [x](y) stolen")
    card = render_card(_notification(advisories=(noisy,)))
    blocks = _text_blocks(card)
    assert all(b.get("size", "Default") in ("Default", "Small") for b in blocks[1:])
    line = next(b["text"] for b in blocks if "stolen" in b["text"])
    assert "###" not in line
    assert "`" not in line
    assert "**bold**" not in line
    assert "[x](y)" not in line
    assert "Details script bold x stolen" in line


def test_advisory_line_explains_missing_and_unavailable_fixes():
    card = render_card(
        _notification(
            advisories=(
                _note(fixed_versions=(), lowest_fix=None, fix_available=None),
                _note(guid="g2", id="GHSA-A2", fix_available=False),
                _note(guid="g3", id="GHSA-A3", fix_available=None),
            )
        )
    )
    lines = {
        re.search(r"\[(GHSA-A\d)\]", b["text"]).group(1): b["text"]
        for b in _text_blocks(card)
        if "GHSA-A" in b["text"]
    }
    assert "no fix" in lines["GHSA-A1"].lower()
    assert "not yet" in lines["GHSA-A2"].lower()
    assert "1.3.1" in lines["GHSA-A3"]


def test_card_for_wordpress_plugin_mentions_kind():
    card = render_card(
        _notification(package="wp-plugin/elementor", ecosystem=WORDPRESS, kind="plugin")
    )
    assert "plugin" in "\n".join(_texts(card)).lower()


def test_card_lists_at_most_a_few_advisories_and_says_how_many_more():
    many = tuple(
        _note(guid=f"g{i}", id=f"GHSA-{i:04d}", details="x" * 3000, summary=f"Issue {i}")
        for i in range(60)
    )
    payload = render_payload(_notification(advisories=many))
    assert len(json.dumps(payload).encode("utf-8")) <= MAX_PAYLOAD_BYTES
    card = payload["attachments"][0]["content"]
    listed = [b for b in _text_blocks(card) if "GHSA-" in b["text"]]
    assert 1 < len(listed) <= MAX_LISTED
    text = "\n".join(_texts(card))
    assert "GHSA-0000" in text
    assert f"{60 - len(listed)} more" in text


def test_actions_open_the_first_advisories():
    actions = render_card(_notification())["actions"]
    assert [a["type"] for a in actions] == ["Action.OpenUrl", "Action.OpenUrl"]
    assert {a["url"] for a in actions} == {"https://osv.dev/vulnerability/GHSA-A1"}
    assert [a["title"] for a in actions] == ["Open GHSA-A2", "Open GHSA-A1"]
    many = tuple(_note(guid=f"g{i}", id=f"GHSA-{i}") for i in range(10))
    assert len(render_card(_notification(advisories=many))["actions"]) <= 3


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


def test_advisories_are_listed_most_severe_first():
    notes = (
        _note(guid="g1", id="GHSA-LOW", severity="LOW"),
        _note(guid="g2", id="GHSA-CRIT", severity="CRITICAL"),
        _note(guid="g3", id="GHSA-MED", severity="MEDIUM"),
        _note(guid="g4", id="GHSA-HIGH", severity="HIGH"),
    )
    card = render_card(_notification(advisories=notes))
    ids = [
        re.search(r"\[(GHSA-\w+)\]", b["text"]).group(1)
        for b in _text_blocks(card)
        if "[GHSA-" in b["text"]
    ]
    assert ids == ["GHSA-CRIT", "GHSA-HIGH", "GHSA-MED", "GHSA-LOW"]
    assert card["actions"][0]["title"] == "Open GHSA-CRIT"


# --- test card --------------------------------------------------------------------------------


def test_render_test_card_is_a_small_adaptive_card_naming_the_project():
    from vulnscan.msteams import render_test_card

    card = render_test_card("mysite")
    assert card["type"] == "AdaptiveCard"
    assert card["body"]
    assert "mysite" in json.dumps(card)
    assert len(json.dumps(card).encode()) < MAX_PAYLOAD_BYTES


def test_client_send_test_posts_one_card():
    seen, transport = _capture_transport()
    TeamsClient("https://hook.test/x", transport=transport).send_test("mysite")
    assert len(seen) == 1
    payload = json.loads(seen[0].content)
    assert payload["type"] == "message"
    assert payload["attachments"][0]["contentType"] == CARD_TYPE
    assert payload["attachments"][0]["content"]["type"] == "AdaptiveCard"


def test_client_send_test_raises_on_http_error():
    _seen, transport = _capture_transport(400)
    with pytest.raises(NotificationError, match="400"):
        TeamsClient("https://hook.test/x", transport=transport).send_test("mysite")
