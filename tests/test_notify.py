import os
import signal
from datetime import UTC, datetime
from pathlib import Path

import pytest

from vulnscan.config import Settings
from vulnscan.feeds import entry_guid
from vulnscan.models import (
    PACKAGIST,
    PYPI,
    Declaration,
    Dependency,
    Finding,
    ScanResult,
    VersionRange,
    Vulnerability,
)
from vulnscan.notify import (
    Notification,
    NotificationError,
    Target,
    WatchControl,
    build_notifications,
    install_signal_handlers,
    load_sent,
    notify,
    notify_all,
    run_watch,
    save_sent,
)
from vulnscan.osv import OSVError
from vulnscan.registry import RegistryError

NOW = datetime(2026, 10, 9, 9, 0, tzinfo=UTC)


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
        interval_minutes=1.0,
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
        "Long description of A1.",
        aliases=["CVE-2025-1"],
        severity="HIGH",
        cvss="CVSS:3.1/AV:N/AC:L",
        fixed_versions=["1.3.1"],
        affected_ranges=[VersionRange(lower="0", upper="1.3.1")],
        published=datetime(2025, 3, 1, tzinfo=UTC),
        references=["https://example.com/a1"],
    )
    a2 = Vulnerability(
        "GHSA-A2",
        "Second",
        "d",
        severity="CRITICAL",
        fixed_versions=["0.9.9", "1.4.0"],
        affected_ranges=[VersionRange(lower="1.0.0", upper="1.4.0")],
    )
    r1 = Vulnerability(
        "GHSA-R1",
        "Proxy leak",
        "d",
        severity="MEDIUM",
        fixed_versions=["2.31.0"],
        affected_ranges=[VersionRange(lower="0", upper="2.31.0")],
    )
    if findings is None:
        findings = [Finding(authlib, [a1, a2]), Finding(requests, [r1])]
    return ScanResult(tmp_path / "proj", [authlib, requests], findings, [], NOW)


def _guid(result: ScanResult, finding_index: int, vuln_index: int) -> str:
    finding = result.findings[finding_index]
    return entry_guid(
        result.project_path.name, finding.dependency, finding.vulnerabilities[vuln_index]
    )


VERSIONS = {
    "authlib": ["1.0.0", "1.2.0", "1.3.0", "1.3.1", "1.4.0", "1.6.12"],
    "requests": ["2.30.0", "2.31.0", "2.32.4"],
}


def versions_fn(dep: Dependency) -> list[str]:
    return VERSIONS[dep.name]


class FakeChannel:
    def __init__(self, name: str = "fake", fail_packages: set[str] | None = None):
        self.name = name
        self.sent: list[Notification] = []
        self.fail_packages = fail_packages or set()

    def send(self, notification: Notification) -> None:
        if notification.package in self.fail_packages:
            raise NotificationError("boom")
        self.sent.append(notification)


# --- building notifications -------------------------------------------------------------------


def test_build_groups_unsent_advisories_per_dependency(tmp_path: Path):
    result = _result(tmp_path)
    notes = build_notifications(result, already_sent={_guid(result, 0, 1)}, versions_fn=versions_fn)
    assert [n.package for n in notes] == ["authlib", "requests"]
    authlib, requests = notes
    assert authlib.guids == (_guid(result, 0, 0),)
    assert authlib.project == "proj"
    assert authlib.version == "1.2.0"
    assert authlib.ecosystem == PYPI
    assert [d.source_file for d in authlib.declared_in] == [
        "requirements/base.txt",
        "requirements/production.txt",
    ]
    assert authlib.severity == "HIGH"  # worst among the *new* advisories only
    assert [a.id for a in authlib.advisories] == ["GHSA-A1"]
    note = authlib.advisories[0]
    assert note.summary == "JWT confusion"
    assert note.details == "Long description of A1."
    assert note.cve_ids == ("CVE-2025-1",)
    assert note.severity == "HIGH"
    assert note.cvss == "CVSS:3.1/AV:N/AC:L"
    assert note.url == "https://osv.dev/vulnerability/GHSA-A1"
    assert note.published == datetime(2025, 3, 1, tzinfo=UTC)
    assert requests.guids == (_guid(result, 1, 0),)
    assert requests.severity == "MEDIUM"


def test_build_reports_lowest_fix_above_current_and_whether_it_is_available(tmp_path: Path):
    result = _result(tmp_path)
    authlib = build_notifications(result, already_sent=set(), versions_fn=versions_fn)[0]
    a1, a2 = authlib.advisories
    assert a1.lowest_fix == "1.3.1"
    assert a1.fix_available is True
    assert a2.fixed_versions == ("0.9.9", "1.4.0")
    assert a2.lowest_fix == "1.4.0"  # 0.9.9 is below the installed 1.2.0
    assert a2.fix_available is True
    assert authlib.nearest_safe == "1.4.0"  # clears both advisories
    assert authlib.latest == "1.6.12"
    assert authlib.latest_is_safe is True
    assert authlib.versions_checked is True


def test_build_marks_fix_unavailable_when_registry_lacks_it(tmp_path: Path):
    result = _result(tmp_path)
    notes = build_notifications(
        result, already_sent=set(), versions_fn=lambda dep: ["1.0.0", "1.2.0", "1.2.1"]
    )
    authlib = notes[0]
    assert authlib.advisories[0].lowest_fix == "1.3.1"
    assert authlib.advisories[0].fix_available is False
    assert authlib.nearest_safe is None
    assert authlib.latest == "1.2.1"
    assert authlib.latest_is_safe is False


def test_build_tolerates_registry_failure_and_no_lookup(tmp_path: Path):
    result = _result(tmp_path)

    def failing(dep):
        raise RegistryError("down")

    for fn in (failing, None):
        authlib = build_notifications(result, already_sent=set(), versions_fn=fn)[0]
        assert authlib.versions_checked is False
        assert authlib.nearest_safe is None
        assert authlib.latest is None
        assert authlib.latest_is_safe is None
        assert authlib.advisories[0].lowest_fix == "1.3.1"
        assert authlib.advisories[0].fix_available is None


def test_build_looks_up_each_dependency_once(tmp_path: Path):
    result = _result(tmp_path)
    calls = []

    def counting(dep):
        calls.append(dep.name)
        return VERSIONS[dep.name]

    build_notifications(result, already_sent=set(), versions_fn=counting)
    assert sorted(calls) == ["authlib", "requests"]


def test_build_skips_dependencies_with_nothing_new(tmp_path: Path):
    result = _result(tmp_path)
    everything = {_guid(result, 0, 0), _guid(result, 0, 1), _guid(result, 1, 0)}
    assert build_notifications(result, already_sent=everything) == []
    assert build_notifications(_result(tmp_path, findings=[]), already_sent=set()) == []


def test_build_handles_unknown_version_and_no_fix(tmp_path: Path):
    dep = Dependency("monolog/monolog", PACKAGIST, "^1", None, "unknown", "composer.json")
    vuln = Vulnerability("GHSA-M", "s", "d")
    result = ScanResult(tmp_path / "proj", [dep], [Finding(dep, [vuln])], [], NOW)
    note = build_notifications(result, already_sent=set(), versions_fn=lambda d: ["1.0", "2.0"])[0]
    assert note.version is None
    assert note.severity == "UNKNOWN"
    assert note.advisories[0].lowest_fix is None
    assert note.advisories[0].fix_available is None


# --- state and notify -------------------------------------------------------------------------


def test_sent_state_round_trips(tmp_path: Path):
    path = tmp_path / "deep" / "state.json"
    assert load_sent(path) == {}
    save_sent(path, {"g1": NOW.isoformat()})
    assert load_sent(path) == {"g1": NOW.isoformat()}
    path.write_text("not json")
    assert load_sent(path) == {}


def test_notify_sends_everything_first_time_then_only_new(tmp_path: Path):
    target = Target(FakeChannel(), tmp_path / "state.json")
    first = notify(_result(tmp_path), target, now=NOW)
    assert first.channel == "fake"
    assert first.messages_sent == 2
    assert first.messages_failed == 0
    assert len(first.guids_sent) == 3
    assert set(load_sent(target.state_path)) == set(first.guids_sent)

    second = notify(_result(tmp_path), target, now=NOW)
    assert second.messages_sent == 0
    assert second.guids_sent == ()
    assert len(target.channel.sent) == 2

    result = _result(tmp_path)
    result.findings[1].vulnerabilities.append(Vulnerability("GHSA-R2", "Brand new", "d"))
    third = notify(result, target, now=NOW)
    assert third.messages_sent == 1
    assert [a.id for a in target.channel.sent[-1].advisories] == ["GHSA-R2"]
    assert len(load_sent(target.state_path)) == 4


def test_notify_resend_pushes_every_current_finding_again(tmp_path: Path):
    target = Target(FakeChannel(), tmp_path / "state.json")
    notify(_result(tmp_path), target, now=NOW)
    report = notify(_result(tmp_path), target, resend=True, now=NOW)
    assert report.messages_sent == 2
    assert len(target.channel.sent) == 4
    assert len(load_sent(target.state_path)) == 3


def test_notify_keeps_failed_messages_unsent_for_next_time(tmp_path: Path):
    channel = FakeChannel(fail_packages={"authlib"})
    target = Target(channel, tmp_path / "state.json")
    report = notify(_result(tmp_path), target, now=NOW)
    assert report.messages_sent == 1
    assert report.messages_failed == 1
    assert any("authlib" in e for e in report.errors)
    assert set(load_sent(target.state_path)) == {_guid(_result(tmp_path), 1, 0)}

    channel.fail_packages = set()
    again = notify(_result(tmp_path), target, now=NOW)
    assert again.messages_sent == 1
    assert channel.sent[-1].package == "authlib"
    assert len(load_sent(target.state_path)) == 3


def test_notify_all_keeps_separate_state_per_channel(tmp_path: Path):
    ntfy = Target(FakeChannel("ntfy"), tmp_path / "ntfy.json")
    teams = Target(FakeChannel("msteams"), tmp_path / "teams.json")
    notify_all(_result(tmp_path), [ntfy], now=NOW)
    reports = notify_all(_result(tmp_path), [ntfy, teams], now=NOW)
    assert [(r.channel, r.messages_sent) for r in reports] == [("ntfy", 0), ("msteams", 2)]
    assert len(load_sent(ntfy.state_path)) == 3
    assert len(load_sent(teams.state_path)) == 3


def test_notify_all_looks_up_versions_once_for_every_channel(tmp_path: Path):
    calls = []

    def counting(dep):
        calls.append(dep.name)
        return VERSIONS[dep.name]

    targets = [
        Target(FakeChannel("a"), tmp_path / "a.json"),
        Target(FakeChannel("b"), tmp_path / "b.json"),
    ]
    notify_all(_result(tmp_path), targets, versions_fn=counting, now=NOW)
    assert sorted(calls) == ["authlib", "requests"]
    assert targets[0].channel.sent[0].nearest_safe == "1.4.0"
    assert targets[1].channel.sent[0].nearest_safe == "1.4.0"


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


def _targets(tmp_path: Path, *names: str) -> list[Target]:
    return [Target(FakeChannel(n), tmp_path / f"{n}.json") for n in names]


def test_run_watch_scans_every_interval_and_notifies_every_target(tmp_path: Path):
    settings = settings_for(tmp_path, interval_minutes=2.0)
    targets = _targets(tmp_path, "ntfy", "msteams")
    scans = []

    def scan_fn(s):
        scans.append(s)
        return _result(tmp_path)

    control = StoppingControl(waits_before_stop=3)
    code = run_watch(settings, control, targets, scan_fn=scan_fn, versions_fn=versions_fn)
    assert code == 0
    assert len(scans) == 3
    assert control.sleeps == [120.0, 120.0, 120.0]
    assert [len(t.channel.sent) for t in targets] == [2, 2]  # only the first cycle was new
    assert targets[1].channel.sent[0].nearest_safe == "1.4.0"


def test_run_watch_resend_request_sends_everything_again(tmp_path: Path):
    targets = _targets(tmp_path, "ntfy")
    control = StoppingControl(waits_before_stop=2, resend_on_wait=1)
    run_watch(settings_for(tmp_path), control, targets, scan_fn=lambda s: _result(tmp_path))
    assert len(targets[0].channel.sent) == 4


def test_run_watch_resend_first_flag(tmp_path: Path):
    targets = _targets(tmp_path, "ntfy")
    notify(_result(tmp_path), targets[0], now=NOW)
    control = StoppingControl(waits_before_stop=1)
    run_watch(
        settings_for(tmp_path),
        control,
        targets,
        scan_fn=lambda s: _result(tmp_path),
        resend_first=True,
    )
    assert len(targets[0].channel.sent) == 4


def test_run_watch_once_runs_a_single_cycle(tmp_path: Path):
    targets = _targets(tmp_path, "ntfy")
    control = StoppingControl(waits_before_stop=99)
    code = run_watch(
        settings_for(tmp_path), control, targets, scan_fn=lambda s: _result(tmp_path), once=True
    )
    assert code == 0
    assert control.waits == 0
    assert len(targets[0].channel.sent) == 2


def test_run_watch_keeps_going_after_a_scan_failure(tmp_path: Path):
    targets = _targets(tmp_path, "ntfy")
    calls = []

    def scan_fn(s):
        calls.append(1)
        if len(calls) == 1:
            raise OSVError("osv down")
        return _result(tmp_path)

    control = StoppingControl(waits_before_stop=2)
    assert run_watch(settings_for(tmp_path), control, targets, scan_fn=scan_fn) == 0
    assert len(calls) == 2
    assert len(targets[0].channel.sent) == 2


def test_run_watch_once_reports_scan_failure(tmp_path: Path):
    def scan_fn(s):
        raise OSVError("osv down")

    code = run_watch(
        settings_for(tmp_path), StoppingControl(9), _targets(tmp_path, "x"), scan_fn, once=True
    )
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
