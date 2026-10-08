import base64
import json
import os
import signal
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest

from vulnscan.config import Settings
from vulnscan.feeds import entry_guid
from vulnscan.models import PYPI, Declaration, Dependency, Finding, ScanResult, Vulnerability
from vulnscan.ntfy import (
    NtfyClient,
    NtfyError,
    NtfyMessage,
    WatchControl,
    build_messages,
    install_signal_handlers,
    load_sent,
    notify,
    run_watch,
    save_sent,
    severity_priority,
)
from vulnscan.osv import OSVError

NOW = datetime(2026, 10, 8, 9, 0, tzinfo=UTC)


def settings_for(tmp_path: Path, **kwargs) -> Settings:
    base = dict(
        project_path=tmp_path / "proj",
        feed_dir=tmp_path / "feeds",
        rss_filename="r.xml",
        atom_filename="a.xml",
        state_filename="s.json",
        feed_title="t",
        feed_link="",
        feed_description="d",
        osv_base_url="https://osv.test",
        request_timeout=1.0,
        include_dev=True,
        query_unknown_versions=False,
        ntfy_server="https://ntfy.test",
        ntfy_topic="alerts",
        ntfy_interval_minutes=1.0,
    )
    base.update(kwargs)
    return Settings(**base)


def _result(tmp_path: Path, findings=None) -> ScanResult:
    authlib = Dependency(
        "authlib",
        PYPI,
        "==1.2.0",
        "1.2.0",
        "pinned",
        "requirements/base.txt",
        declarations=(
            Declaration("requirements/base.txt", "==1.2.0"),
            Declaration("requirements/production.txt", ">=1.2"),
        ),
    )
    requests = Dependency("requests", PYPI, "==2.30.0", "2.30.0", "pinned", "requirements.txt")
    a1 = Vulnerability(
        "GHSA-A1",
        "JWT confusion",
        "d",
        aliases=["CVE-2025-1"],
        severity="HIGH",
        fixed_versions=["1.3.1"],
    )
    a2 = Vulnerability("GHSA-A2", "Second", "d", severity="CRITICAL", fixed_versions=["1.4.0"])
    r1 = Vulnerability("GHSA-R1", "Proxy leak", "d", severity="MEDIUM", fixed_versions=["2.31.0"])
    if findings is None:
        findings = [Finding(authlib, [a1, a2]), Finding(requests, [r1])]
    return ScanResult(tmp_path / "proj", [authlib, requests], findings, [], NOW)


def _guid(result: ScanResult, finding_index: int, vuln_index: int) -> str:
    finding = result.findings[finding_index]
    return entry_guid(
        result.project_path.name, finding.dependency, finding.vulnerabilities[vuln_index]
    )


class FakeClient:
    def __init__(self, fail_titles: set[str] | None = None):
        self.published: list[NtfyMessage] = []
        self.fail_titles = fail_titles or set()

    def publish(self, message: NtfyMessage) -> None:
        if any(t in message.title for t in self.fail_titles):
            raise NtfyError("boom")
        self.published.append(message)


# --- priorities and message building ----------------------------------------------------------


def test_severity_priority_maps_to_ntfy_scale():
    assert severity_priority("CRITICAL") == 5
    assert severity_priority("HIGH") == 4
    assert severity_priority("MEDIUM") == 3
    assert severity_priority("LOW") == 2
    assert severity_priority("UNKNOWN") == 3
    assert severity_priority("moderate") == 3


def test_build_messages_groups_unsent_advisories_per_dependency(tmp_path: Path):
    result = _result(tmp_path)
    messages = build_messages(result, already_sent={_guid(result, 0, 1)})
    assert [len(m.guids) for m in messages] == [1, 1]
    authlib, requests = messages
    assert authlib.guids == (_guid(result, 0, 0),)
    assert "authlib" in authlib.title and "1.2.0" in authlib.title
    assert "GHSA-A1" in authlib.body
    assert "CVE-2025-1" in authlib.body
    assert "JWT confusion" in authlib.body
    assert "1.3.1" in authlib.body
    assert "GHSA-A2" not in authlib.body
    assert "requirements/base.txt" in authlib.body
    assert "requirements/production.txt" in authlib.body
    assert "proj" in authlib.body
    assert authlib.priority == 4  # HIGH, the only *new* advisory, not CRITICAL
    assert authlib.click == "https://osv.dev/vulnerability/GHSA-A1"
    assert "high" in authlib.tags
    assert requests.priority == 3
    assert requests.guids == (_guid(result, 1, 0),)


def test_build_messages_skips_dependencies_with_nothing_new(tmp_path: Path):
    result = _result(tmp_path)
    everything = {_guid(result, 0, 0), _guid(result, 0, 1), _guid(result, 1, 0)}
    assert build_messages(result, already_sent=everything) == []
    assert build_messages(_result(tmp_path, findings=[]), already_sent=set()) == []


def test_build_messages_with_nothing_sent_covers_every_advisory(tmp_path: Path):
    result = _result(tmp_path)
    messages = build_messages(result, already_sent=set())
    assert [m.priority for m in messages] == [5, 3]
    assert sorted(g for m in messages for g in m.guids) == sorted(
        [_guid(result, 0, 0), _guid(result, 0, 1), _guid(result, 1, 0)]
    )


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
    with pytest.raises(NtfyError, match="403"):
        client.publish(_message())


def test_client_raises_on_connection_failure():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    client = NtfyClient("https://ntfy.test", "t", transport=httpx.MockTransport(handler))
    with pytest.raises(NtfyError):
        client.publish(_message())


# --- state and notify -------------------------------------------------------------------------


def test_sent_state_round_trips(tmp_path: Path):
    path = tmp_path / "deep" / "ntfy-state.json"
    assert load_sent(path) == {}
    save_sent(path, {"g1": NOW.isoformat()})
    assert load_sent(path) == {"g1": NOW.isoformat()}
    path.write_text("not json")
    assert load_sent(path) == {}


def test_notify_sends_everything_first_time_then_only_new(tmp_path: Path):
    settings = settings_for(tmp_path)
    client = FakeClient()
    first = notify(_result(tmp_path), settings, client, now=NOW)
    assert first.messages_sent == 2
    assert first.messages_failed == 0
    assert len(first.guids_sent) == 3
    assert set(load_sent(settings.ntfy_state_path)) == set(first.guids_sent)

    second = notify(_result(tmp_path), settings, client, now=NOW)
    assert second.messages_sent == 0
    assert second.guids_sent == ()
    assert len(client.published) == 2

    result = _result(tmp_path)
    result.findings[1].vulnerabilities.append(
        Vulnerability("GHSA-R2", "Brand new", "d", severity="LOW")
    )
    third = notify(result, settings, client, now=NOW)
    assert third.messages_sent == 1
    assert "GHSA-R2" in client.published[-1].body
    assert "GHSA-R1" not in client.published[-1].body
    assert len(load_sent(settings.ntfy_state_path)) == 4


def test_notify_resend_pushes_every_current_finding_again(tmp_path: Path):
    settings = settings_for(tmp_path)
    client = FakeClient()
    notify(_result(tmp_path), settings, client, now=NOW)
    report = notify(_result(tmp_path), settings, client, resend=True, now=NOW)
    assert report.messages_sent == 2
    assert len(client.published) == 4
    assert len(load_sent(settings.ntfy_state_path)) == 3


def test_notify_keeps_failed_messages_unsent_for_next_time(tmp_path: Path):
    settings = settings_for(tmp_path)
    client = FakeClient(fail_titles={"authlib"})
    report = notify(_result(tmp_path), settings, client, now=NOW)
    assert report.messages_sent == 1
    assert report.messages_failed == 1
    assert any("authlib" in e for e in report.errors)
    sent = load_sent(settings.ntfy_state_path)
    assert set(sent) == {_guid(_result(tmp_path), 1, 0)}

    client.fail_titles = set()
    again = notify(_result(tmp_path), settings, client, now=NOW)
    assert again.messages_sent == 1
    assert "authlib" in client.published[-1].title
    assert len(load_sent(settings.ntfy_state_path)) == 3


# --- control and watch loop -------------------------------------------------------------------


def test_watch_control_flags():
    control = WatchControl()
    assert control.stop_requested is False
    assert control.take_resend() is False
    control.request_resend()
    assert control.take_resend() is True
    assert control.take_resend() is False
    control.request_stop()
    assert control.stop_requested is True
    control.wait(10)  # returns immediately because a stop was requested


def test_watch_control_wait_returns_early_when_woken():
    control = WatchControl()
    started = datetime.now()
    control.request_resend()
    control.wait(5)
    assert (datetime.now() - started).total_seconds() < 1


class StoppingControl(WatchControl):
    """Stops after a fixed number of waits; optionally asks for a resend on one of them."""

    def __init__(self, waits_before_stop: int, resend_on_wait: int | None = None):
        super().__init__()
        self.waits = 0
        self.waits_before_stop = waits_before_stop
        self.resend_on_wait = resend_on_wait
        self.sleeps: list[float] = []

    def wait(self, seconds: float) -> None:
        self.waits += 1
        self.sleeps.append(seconds)
        if self.resend_on_wait == self.waits:
            self.request_resend()
        if self.waits >= self.waits_before_stop:
            self.request_stop()


def test_run_watch_scans_every_interval_until_stopped(tmp_path: Path):
    settings = settings_for(tmp_path, ntfy_interval_minutes=2.0)
    client = FakeClient()
    scans = []

    def scan_fn(s):
        scans.append(s)
        return _result(tmp_path)

    control = StoppingControl(waits_before_stop=3)
    code = run_watch(settings, control, client, scan_fn=scan_fn)
    assert code == 0
    assert len(scans) == 3
    assert control.sleeps == [120.0, 120.0, 120.0]
    assert len(client.published) == 2  # only the first cycle had anything new


def test_run_watch_resend_request_sends_everything_again(tmp_path: Path):
    settings = settings_for(tmp_path)
    client = FakeClient()
    control = StoppingControl(waits_before_stop=2, resend_on_wait=1)
    run_watch(settings, control, client, scan_fn=lambda s: _result(tmp_path))
    assert len(client.published) == 4


def test_run_watch_resend_first_flag(tmp_path: Path):
    settings = settings_for(tmp_path)
    client = FakeClient()
    notify(_result(tmp_path), settings, client, now=NOW)
    control = StoppingControl(waits_before_stop=1)
    run_watch(settings, control, client, scan_fn=lambda s: _result(tmp_path), resend_first=True)
    assert len(client.published) == 4


def test_run_watch_once_runs_a_single_cycle(tmp_path: Path):
    settings = settings_for(tmp_path)
    client = FakeClient()
    control = StoppingControl(waits_before_stop=99)
    code = run_watch(settings, control, client, scan_fn=lambda s: _result(tmp_path), once=True)
    assert code == 0
    assert control.waits == 0
    assert len(client.published) == 2


def test_run_watch_keeps_going_after_a_scan_failure(tmp_path: Path):
    settings = settings_for(tmp_path)
    client = FakeClient()
    calls = []

    def scan_fn(s):
        calls.append(1)
        if len(calls) == 1:
            raise OSVError("osv down")
        return _result(tmp_path)

    control = StoppingControl(waits_before_stop=2)
    code = run_watch(settings, control, client, scan_fn=scan_fn)
    assert code == 0
    assert len(calls) == 2
    assert len(client.published) == 2


def test_run_watch_once_reports_scan_failure(tmp_path: Path):
    def scan_fn(s):
        raise OSVError("osv down")

    code = run_watch(settings_for(tmp_path), StoppingControl(9), FakeClient(), scan_fn, once=True)
    assert code == 1


@pytest.mark.skipif(not hasattr(signal, "SIGUSR1"), reason="no SIGUSR1 on this platform")
def test_signal_handlers_drive_the_control():
    control = WatchControl()
    previous = {
        sig: signal.getsignal(sig) for sig in (signal.SIGUSR1, signal.SIGINT, signal.SIGTERM)
    }
    try:
        install_signal_handlers(control)
        os.kill(os.getpid(), signal.SIGUSR1)
        assert control.take_resend() is True
        assert control.stop_requested is False
        os.kill(os.getpid(), signal.SIGTERM)
        assert control.stop_requested is True
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
