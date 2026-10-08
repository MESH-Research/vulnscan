import base64
import json
from datetime import UTC, datetime

import httpx
import pytest

from vulnscan.models import PYPI, Declaration
from vulnscan.notify import AdvisoryNote, Notification, NotificationError
from vulnscan.ntfy import NtfyClient, NtfyMessage, render_ntfy, severity_priority


def _note(**kwargs) -> AdvisoryNote:
    base = dict(
        guid="g1",
        id="GHSA-A1",
        summary="JWT confusion",
        details="Long description.",
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


def test_severity_priority_maps_to_ntfy_scale():
    assert severity_priority("CRITICAL") == 5
    assert severity_priority("HIGH") == 4
    assert severity_priority("MEDIUM") == 3
    assert severity_priority("LOW") == 2
    assert severity_priority("UNKNOWN") == 3
    assert severity_priority("moderate") == 3


def test_render_ntfy_summarises_the_notification():
    message = render_ntfy(_notification())
    assert "authlib" in message.title and "1.2.0" in message.title
    assert "2 new advisories" in message.title
    assert "mysite" in message.body
    assert "CRITICAL" in message.body
    assert "1.4.0" in message.body  # the upgrade that clears everything
    assert "GHSA-A1" in message.body and "CVE-2025-1" in message.body
    assert "JWT confusion" in message.body
    assert "1.3.1" in message.body
    assert "requirements/base.txt" in message.body
    assert "requirements/production.txt" in message.body
    assert message.priority == 5
    assert "critical" in message.tags
    assert message.click == "https://osv.dev/vulnerability/GHSA-A1"
    assert message.guids == ("g1", "g2")


def test_render_ntfy_explains_missing_or_unavailable_fixes():
    unavailable = render_ntfy(
        _notification(
            nearest_safe=None,
            latest="1.2.1",
            latest_is_safe=False,
            advisories=(_note(fix_available=False),),
        )
    ).body.lower()
    assert "not" in unavailable and "available" in unavailable
    unknown = render_ntfy(
        _notification(
            versions_checked=False,
            nearest_safe=None,
            latest=None,
            latest_is_safe=None,
            advisories=(_note(fix_available=None),),
        )
    ).body.lower()
    assert "could not" in unknown or "unknown" in unknown
    nofix = render_ntfy(
        _notification(advisories=(_note(fixed_versions=(), lowest_fix=None, fix_available=None),))
    ).body.lower()
    assert "no fix" in nofix


# --- client ---------------------------------------------------------------------------------


def _capture_transport(status: int = 200):
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(status, json={"id": "x"})

    return seen, httpx.MockTransport(handler)


def _message() -> NtfyMessage:
    return NtfyMessage(
        title="authlib 1.2.0: 1 new advisory",
        body="GHSA-A1 ...",
        priority=4,
        tags=("warning", "high"),
        click="https://osv.dev/vulnerability/GHSA-A1",
        guids=("g1",),
    )


def test_client_publishes_json_with_bearer_token():
    seen, transport = _capture_transport()
    client = NtfyClient("https://ntfy.test/", "alerts", token="tk_secret", transport=transport)
    client.publish(_message())
    assert len(seen) == 1
    request = seen[0]
    assert request.method == "POST"
    assert str(request.url) == "https://ntfy.test/"
    assert request.headers["authorization"] == "Bearer tk_secret"
    payload = json.loads(request.content)
    assert payload["topic"] == "alerts"
    assert payload["title"] == "authlib 1.2.0: 1 new advisory"
    assert payload["message"] == "GHSA-A1 ..."
    assert payload["priority"] == 4
    assert payload["tags"] == ["warning", "high"]
    assert payload["click"] == "https://osv.dev/vulnerability/GHSA-A1"


def test_client_send_renders_a_notification():
    seen, transport = _capture_transport()
    client = NtfyClient("https://ntfy.test", "alerts", transport=transport)
    assert client.name == "ntfy"
    client.send(_notification())
    payload = json.loads(seen[0].content)
    assert "authlib" in payload["title"]
    assert payload["priority"] == 5


def test_client_uses_basic_auth_when_given_a_user():
    seen, transport = _capture_transport()
    client = NtfyClient("https://ntfy.test", "t", user="me", password="pw", transport=transport)
    client.publish(_message())
    expected = "Basic " + base64.b64encode(b"me:pw").decode()
    assert seen[0].headers["authorization"] == expected


def test_client_sends_no_authorization_without_credentials():
    seen, transport = _capture_transport()
    NtfyClient("https://ntfy.test", "t", transport=transport).publish(_message())
    assert "authorization" not in seen[0].headers


def test_client_raises_on_http_error():
    _seen, transport = _capture_transport(status=403)
    client = NtfyClient("https://ntfy.test", "t", transport=transport)
    with pytest.raises(NotificationError, match="403"):
        client.publish(_message())


def test_client_raises_on_connection_failure():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    client = NtfyClient("https://ntfy.test", "t", transport=httpx.MockTransport(handler))
    with pytest.raises(NotificationError):
        client.publish(_message())
