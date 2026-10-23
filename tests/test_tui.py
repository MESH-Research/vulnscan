from datetime import UTC, datetime
from pathlib import Path

import pytest
from textual.widgets import DataTable, Markdown

from vulnscan.config import Settings
from vulnscan.models import (
    PACKAGIST,
    PYPI,
    Declaration,
    Dependency,
    Finding,
    ScanResult,
    Vulnerability,
)
from vulnscan.tui import VulnScanApp, vulnerability_markdown


def settings_for(tmp_path: Path) -> Settings:
    return Settings(
        project_path=tmp_path / "proj",
        feed_dir=tmp_path / "feeds",
        rss_filename="vulns.rss.xml",
        atom_filename="vulns.atom.xml",
        state_filename="state.json",
        feed_title="t",
        feed_link="",
        feed_description="d",
        osv_base_url="https://osv.test",
        request_timeout=1.0,
        include_dev=True,
        query_unknown_versions=False,
    )


def sample_result(path: Path) -> ScanResult:
    requests = Dependency("requests", PYPI, "==2.30.0", "2.30.0", "pinned", "requirements.txt")
    monolog = Dependency("monolog/monolog", PACKAGIST, "^1.0", "1.0.0", "lock", "composer.json")
    safe = Dependency("flask", PYPI, "==3.0.0", "3.0.0", "pinned", "requirements.txt")
    v1 = Vulnerability(
        "GHSA-j8r2-6x86-q33q",
        "Proxy-Authorization leak",
        "Requests leaks the header on redirect.",
        aliases=["CVE-2023-32681"],
        severity="MEDIUM",
        fixed_versions=["2.31.0"],
        references=["https://nvd.nist.gov/vuln/detail/CVE-2023-32681"],
    )
    v2 = Vulnerability("GHSA-other", "Second issue", "More details.", severity="LOW")
    v3 = Vulnerability(
        "GHSA-mono",
        "Monolog bug",
        "Monolog details.",
        severity="CRITICAL",
        fixed_versions=["1.0.1"],
    )
    return ScanResult(
        path,
        [requests, monolog, safe],
        [Finding(monolog, [v3]), Finding(requests, [v1, v2])],
        ["flask: could not determine a version"],
        datetime.now(UTC),
    )


async def settle(app: VulnScanApp, pilot) -> None:
    await app.workers.wait_for_complete()
    await pilot.pause()
    await pilot.pause()


async def test_dependency_table_lists_findings(tmp_path: Path):
    settings = settings_for(tmp_path)
    app = VulnScanApp(settings, scan_fn=lambda s: sample_result(s.project_path))
    async with app.run_test() as pilot:
        await settle(app, pilot)
        table = app.query_one("#deps", DataTable)
        assert table.row_count == 2
        first_row = [str(c) for c in table.get_row_at(0)]
        assert any("monolog/monolog" in c for c in first_row)
        assert any("CRITICAL" in c for c in first_row)


async def test_selecting_dependency_shows_its_advisories(tmp_path: Path):
    settings = settings_for(tmp_path)
    app = VulnScanApp(settings, scan_fn=lambda s: sample_result(s.project_path))
    async with app.run_test() as pilot:
        await settle(app, pilot)
        vulns = app.query_one("#vulns", DataTable)
        assert vulns.row_count == 1  # first finding (monolog) is selected by default
        deps = app.query_one("#deps", DataTable)
        deps.move_cursor(row=1)
        await settle(app, pilot)
        assert vulns.row_count == 2
        ids = {str(vulns.get_row_at(i)[0]) for i in range(vulns.row_count)}
        assert ids == {"GHSA-j8r2-6x86-q33q", "GHSA-other"}


async def test_detail_panel_shows_cve_and_fix(tmp_path: Path):
    settings = settings_for(tmp_path)
    app = VulnScanApp(settings, scan_fn=lambda s: sample_result(s.project_path))
    async with app.run_test() as pilot:
        await settle(app, pilot)
        app.query_one("#deps", DataTable).move_cursor(row=1)
        await settle(app, pilot)
        detail = app.query_one("#detail", Markdown).source
        assert "GHSA-j8r2-6x86-q33q" in detail
        assert "CVE-2023-32681" in detail
        assert "2.31.0" in detail
        assert "https://nvd.nist.gov/vuln/detail/CVE-2023-32681" in detail
        assert "Requests leaks the header on redirect." in detail
        app.query_one("#vulns", DataTable).move_cursor(row=1)
        await settle(app, pilot)
        detail = app.query_one("#detail", Markdown).source
        assert "GHSA-other" in detail
        assert "More details." in detail


async def test_status_shows_counts_and_warnings(tmp_path: Path):
    settings = settings_for(tmp_path)
    app = VulnScanApp(settings, scan_fn=lambda s: sample_result(s.project_path))
    async with app.run_test() as pilot:
        await settle(app, pilot)
        status = app.status_text
        assert "3" in status  # dependencies
        assert "2" in status  # vulnerable
        assert "1 warning" in status


async def test_status_spins_while_scan_is_in_progress(tmp_path: Path):
    import threading

    from textual.widgets import Static

    from vulnscan.tui import _SPINNER_FRAMES

    settings = settings_for(tmp_path)
    started = threading.Event()
    release = threading.Event()

    def slow_scan(s: Settings) -> ScanResult:
        started.set()
        release.wait(timeout=5)
        return sample_result(s.project_path)

    app = VulnScanApp(settings, scan_fn=slow_scan)
    async with app.run_test() as pilot:
        for _ in range(50):
            if started.is_set():
                break
            await pilot.pause(0.05)
        assert started.is_set()
        await pilot.pause(0.25)
        rendered = str(app.query_one("#status", Static).content)
        assert any(frame in rendered for frame in _SPINNER_FRAMES)
        assert "Scanning" in rendered
        assert app.status_text.startswith("Scanning")
        assert app._busy_message is not None
        release.set()
        await settle(app, pilot)
        assert "vulnerable" in app.status_text
        assert app._busy_message is None
        assert not any(frame in app.status_text for frame in _SPINNER_FRAMES)


async def test_write_feeds_key_writes_files(tmp_path: Path):
    settings = settings_for(tmp_path)
    app = VulnScanApp(settings, scan_fn=lambda s: sample_result(s.project_path))
    async with app.run_test() as pilot:
        await settle(app, pilot)
        await pilot.press("f")
        await settle(app, pilot)
        assert settings.rss_path.is_file()
        assert settings.atom_path.is_file()


async def test_rescan_key_refreshes_table(tmp_path: Path):
    settings = settings_for(tmp_path)
    results = iter(
        [
            sample_result(settings.project_path),
            ScanResult(settings.project_path, [], [], [], datetime.now(UTC)),
        ]
    )
    app = VulnScanApp(settings, scan_fn=lambda s: next(results))
    async with app.run_test() as pilot:
        await settle(app, pilot)
        assert app.query_one("#deps", DataTable).row_count == 2
        await pilot.press("r")
        await settle(app, pilot)
        assert app.query_one("#deps", DataTable).row_count == 0
        assert app.query_one("#vulns", DataTable).row_count == 0


async def test_scan_failure_is_reported_not_raised(tmp_path: Path):
    settings = settings_for(tmp_path)

    def failing(s):
        raise RuntimeError("OSV exploded")

    app = VulnScanApp(settings, scan_fn=failing)
    async with app.run_test() as pilot:
        await settle(app, pilot)
        assert "OSV exploded" in app.status_text
        assert app.query_one("#deps", DataTable).row_count == 0


async def test_quit_key_exits(tmp_path: Path):
    settings = settings_for(tmp_path)
    app = VulnScanApp(settings, scan_fn=lambda s: sample_result(s.project_path))
    async with app.run_test() as pilot:
        await settle(app, pilot)
        await pilot.press("q")
        await pilot.pause()
    assert app.return_code == 0 or app.return_code is None


def test_current_vulnerability_none_before_scan(tmp_path: Path):
    app = VulnScanApp(settings_for(tmp_path), scan_fn=lambda s: sample_result(s.project_path))
    assert app.current_vulnerability is None


@pytest.mark.parametrize("attr", ["status_text", "current_vulnerability"])
def test_app_exposes_inspection_properties(tmp_path: Path, attr):
    app = VulnScanApp(settings_for(tmp_path), scan_fn=lambda s: sample_result(s.project_path))
    assert hasattr(app, attr)


async def test_export_key_writes_markdown_and_text(tmp_path: Path):
    settings = settings_for(tmp_path)
    app = VulnScanApp(settings, scan_fn=lambda s: sample_result(s.project_path))
    async with app.run_test() as pilot:
        await settle(app, pilot)
        await pilot.press("e")
        await settle(app, pilot)
        assert settings.markdown_path.is_file()
        assert settings.text_path.is_file()
        assert "monolog/monolog" in settings.markdown_path.read_text()


def test_detail_markdown_includes_wordfence_attribution():
    from vulnscan.tui import vulnerability_markdown
    from vulnscan.wordfence import WORDFENCE_COPYRIGHT

    dep = Dependency("wp-plugin/elementor", PACKAGIST, "3.13.4", "3.13.4", "lock", "composer.json")
    wf = Vulnerability("CVE-1", "s", "d", link="https://www.wordfence.com/x", source="wordfence")
    osv = Vulnerability("GHSA-1", "s", "d")
    assert WORDFENCE_COPYRIGHT in vulnerability_markdown(Finding(dep, [wf]), wf)
    assert WORDFENCE_COPYRIGHT not in vulnerability_markdown(Finding(dep, [osv]), osv)


def _monolog_remediate_scan(path: Path) -> ScanResult:
    result = sample_result(path)
    from vulnscan.models import VersionRange

    result.findings[0].vulnerabilities[0].affected_ranges = [VersionRange(lower="0", upper="1.0.1")]
    return result


async def test_remediate_key_offers_options_and_applies_choice(tmp_path: Path):
    settings = settings_for(tmp_path)
    project = settings.project_path
    project.mkdir()
    (project / "composer.json").write_text(
        '{\n  "require": {\n    "monolog/monolog": "^1.0"\n  }\n}\n'
    )

    def fake_versions(dep):
        assert dep.name == "monolog/monolog"
        return ["1.0.0", "1.0.1", "1.5.0", "2.9.1"]

    app = VulnScanApp(
        settings,
        scan_fn=lambda s: _monolog_remediate_scan(s.project_path),
        versions_fn=fake_versions,
    )
    async with app.run_test() as pilot:
        await settle(app, pilot)
        await pilot.press("u")
        await settle(app, pilot)
        screen = app.screen
        assert screen.__class__.__name__ == "RemediateScreen"
        text = screen.query_one("#remediate-options").render_str if False else None  # noqa: F841
        from textual.widgets import OptionList

        options = screen.query_one("#remediate-options", OptionList)
        assert options.option_count == 2
        prompts = [str(options.get_option_at_index(i).prompt) for i in range(options.option_count)]
        assert any("1.0.1" in p for p in prompts)
        assert any("2.9.1" in p for p in prompts)
        await pilot.press("enter")  # first option: nearest safe version
        await settle(app, pilot)
        assert app.screen.__class__.__name__ != "RemediateScreen"
        assert '"monolog/monolog": "^1.0.1"' in (project / "composer.json").read_text()
        assert "composer update monolog/monolog" in app.status_text


async def test_status_spins_while_remediation_applies(tmp_path: Path, monkeypatch):
    import threading

    from textual.widgets import Static

    from vulnscan import remediate as remediate_mod
    from vulnscan.tui import _SPINNER_FRAMES

    settings = settings_for(tmp_path)
    project = settings.project_path
    project.mkdir()
    (project / "composer.json").write_text(
        '{\n  "require": {\n    "monolog/monolog": "^1.0"\n  }\n}\n'
    )
    started = threading.Event()
    release = threading.Event()
    real_apply = remediate_mod.apply_remediation

    def slow_apply(*args, **kwargs):
        started.set()
        release.wait(timeout=5)
        return real_apply(*args, **kwargs)

    monkeypatch.setattr("vulnscan.tui.apply_remediation", slow_apply)

    app = VulnScanApp(
        settings,
        scan_fn=lambda s: _monolog_remediate_scan(s.project_path),
        versions_fn=lambda d: ["1.0.0", "1.0.1", "1.5.0", "2.9.1"],
    )
    async with app.run_test() as pilot:
        await settle(app, pilot)
        await pilot.press("u")
        await settle(app, pilot)
        assert app.screen.__class__.__name__ == "RemediateScreen"
        await pilot.press("enter")
        for _ in range(50):
            if started.is_set():
                break
            await pilot.pause(0.05)
        assert started.is_set()
        await pilot.pause(0.25)
        rendered = str(app.query_one("#status", Static).content)
        assert any(frame in rendered for frame in _SPINNER_FRAMES)
        assert "Updating" in rendered and "1.0.1" in rendered
        release.set()
        await settle(app, pilot)
        assert "composer update monolog/monolog" in app.status_text
        assert app._busy_message is None


async def test_remediate_escape_cancels(tmp_path: Path):
    settings = settings_for(tmp_path)
    project = settings.project_path
    project.mkdir()
    original = '{"require": {"monolog/monolog": "^1.0"}}'
    (project / "composer.json").write_text(original)
    app = VulnScanApp(
        settings,
        scan_fn=lambda s: sample_result(s.project_path),
        versions_fn=lambda d: ["1.0.0", "2.0.0"],
    )
    async with app.run_test() as pilot:
        await settle(app, pilot)
        await pilot.press("u")
        await settle(app, pilot)
        assert app.screen.__class__.__name__ == "RemediateScreen"
        await pilot.press("escape")
        await settle(app, pilot)
        assert app.screen.__class__.__name__ != "RemediateScreen"
        assert (project / "composer.json").read_text() == original


async def test_remediate_reports_registry_failure(tmp_path: Path):
    from vulnscan.registry import RegistryError

    settings = settings_for(tmp_path)

    def failing(dep):
        raise RegistryError("registry down")

    app = VulnScanApp(
        settings, scan_fn=lambda s: sample_result(s.project_path), versions_fn=failing
    )
    async with app.run_test() as pilot:
        await settle(app, pilot)
        await pilot.press("u")
        await settle(app, pilot)
        assert app.screen.__class__.__name__ != "RemediateScreen"
        assert "registry down" in app.status_text


def _remediable_app(tmp_path: Path):
    """App whose first finding (monolog) can be upgraded to 1.0.1 against a real composer.json."""
    settings = settings_for(tmp_path)
    project = settings.project_path
    project.mkdir()
    (project / "composer.json").write_text('{"require": {"monolog/monolog": "^1.0"}}')

    def scan_fn(s):
        from vulnscan.models import VersionRange

        result = sample_result(s.project_path)
        result.findings[0].vulnerabilities[0].affected_ranges = [
            VersionRange(lower="0", upper="1.0.1")
        ]
        return result

    return VulnScanApp(settings, scan_fn=scan_fn, versions_fn=lambda d: ["1.0.0", "1.0.1", "2.9.1"])


def _row_text(table: DataTable, row: int) -> list[str]:
    return [str(c) for c in table.get_row_at(row)]


async def test_remediated_dependency_row_is_ticked_and_green(tmp_path: Path):
    from rich.text import Text

    app = _remediable_app(tmp_path)
    async with app.run_test() as pilot:
        await settle(app, pilot)
        deps = app.query_one("#deps", DataTable)
        assert "✔" not in "".join(_row_text(deps, 0))
        await pilot.press("u")
        await settle(app, pilot)
        await pilot.press("enter")
        await settle(app, pilot)
        cells = deps.get_row_at(0)
        assert "✔" in str(cells[0])
        assert any("monolog/monolog" in str(c) for c in cells)
        styled = [c for c in cells if isinstance(c, Text) and "green" in str(c.style)]
        assert len(styled) == len(cells)
        # The untouched second row stays unstyled.
        assert "✔" not in "".join(_row_text(deps, 1))
        assert not any(isinstance(c, Text) and "green" in str(c.style) for c in deps.get_row_at(1))
        assert app.remediated == {("Packagist", "monolog/monolog"): "^1.0.1"}


async def test_remediated_advisory_rows_are_marked(tmp_path: Path):
    app = _remediable_app(tmp_path)
    async with app.run_test() as pilot:
        await settle(app, pilot)
        await pilot.press("u")
        await settle(app, pilot)
        await pilot.press("enter")
        await settle(app, pilot)
        vulns = app.query_one("#vulns", DataTable)
        assert vulns.row_count == 1
        assert "✔" in "".join(_row_text(vulns, 0))
        # Moving to another dependency shows unmarked advisories; coming back shows marked ones.
        deps = app.query_one("#deps", DataTable)
        deps.move_cursor(row=1)
        await settle(app, pilot)
        assert "✔" not in "".join(_row_text(vulns, 0))
        deps.move_cursor(row=0)
        await settle(app, pilot)
        assert "✔" in "".join(_row_text(vulns, 0))


async def test_remediation_mark_survives_rescan(tmp_path: Path):
    app = _remediable_app(tmp_path)
    async with app.run_test() as pilot:
        await settle(app, pilot)
        await pilot.press("u")
        await settle(app, pilot)
        await pilot.press("enter")
        await settle(app, pilot)
        await pilot.press("r")
        await settle(app, pilot)
        deps = app.query_one("#deps", DataTable)
        assert "✔" in str(deps.get_row_at(0)[0])
        assert "✔" not in "".join(_row_text(deps, 1))


async def test_cancelled_remediation_leaves_row_unmarked(tmp_path: Path):
    app = _remediable_app(tmp_path)
    async with app.run_test() as pilot:
        await settle(app, pilot)
        await pilot.press("u")
        await settle(app, pilot)
        await pilot.press("escape")
        await settle(app, pilot)
        deps = app.query_one("#deps", DataTable)
        assert "✔" not in "".join(_row_text(deps, 0))
        assert app.remediated == {}


def _multi_file_app(tmp_path: Path) -> VulnScanApp:
    from vulnscan.models import VersionRange

    project = tmp_path / "proj"
    project.mkdir()
    (project / "requirements.txt").write_text("requests==2.30.0\n")
    (project / "requirements-prod.txt").write_text("requests>=2.30\n")
    dep = Dependency(
        "requests",
        PYPI,
        "==2.30.0",
        "2.30.0",
        "pinned",
        "requirements.txt",
        declarations=(
            Declaration("requirements.txt", "==2.30.0"),
            Declaration("requirements-prod.txt", ">=2.30"),
        ),
    )
    vuln = Vulnerability(
        "GHSA-1",
        "s",
        "d",
        severity="HIGH",
        affected_ranges=[VersionRange(lower="0", upper="2.31.0")],
    )

    def scan_fn(s):
        return ScanResult(project, [dep], [Finding(dep, [vuln])], [], datetime.now(UTC))

    return VulnScanApp(
        settings_for(tmp_path), scan_fn=scan_fn, versions_fn=lambda d: ["2.30.0", "2.31.0"]
    )


async def test_dependency_table_lists_every_declaring_file(tmp_path: Path):
    app = _multi_file_app(tmp_path)
    async with app.run_test() as pilot:
        await settle(app, pilot)
        row = "".join(_row_text(app.query_one("#deps", DataTable), 0))
        assert "requirements.txt" in row
        assert "requirements-prod.txt" in row
        finding = app.result.findings[0]
        detail = vulnerability_markdown(finding, finding.vulnerabilities[0])
        assert "requirements.txt" in detail
        assert "requirements-prod.txt" in detail
        assert ">=2.30" in detail


async def test_remediation_updates_every_declaring_file(tmp_path: Path):
    app = _multi_file_app(tmp_path)
    async with app.run_test() as pilot:
        await settle(app, pilot)
        await pilot.press("u")
        await settle(app, pilot)
        await pilot.press("enter")
        await settle(app, pilot)
        assert (tmp_path / "proj" / "requirements.txt").read_text() == "requests==2.31.0\n"
        assert (tmp_path / "proj" / "requirements-prod.txt").read_text() == "requests>=2.31.0\n"
        assert "requirements-prod.txt" in app.status_text
        assert app.remediated == {("PyPI", "requests"): "requests==2.31.0"}


# -- outdated mode -----------------------------------------------------------------------------


OUTDATED_VERSIONS = {
    "flask": ["2.3.0", "3.0.0", "3.0.3", "3.1.0"],
    "requests": ["2.30.0", "2.31.0", "2.32.4"],
    "monolog/monolog": ["1.0.0", "2.9.1"],
    "click": ["8.1.7"],
}


def _outdated_scan(path: Path) -> ScanResult:
    result = sample_result(path)
    result.dependencies.append(
        Dependency("click", PYPI, "==8.1.7", "8.1.7", "pinned", "requirements.txt")
    )
    return result


def _outdated_app(tmp_path: Path, versions_fn=None) -> VulnScanApp:
    settings = settings_for(tmp_path)
    project = settings.project_path
    project.mkdir()
    (project / "requirements.txt").write_text("flask==3.0.0\nrequests==2.30.0\nclick==8.1.7\n")
    (project / "composer.json").write_text('{"require": {"monolog/monolog": "^1.0"}}')
    return VulnScanApp(
        settings,
        scan_fn=lambda s: _outdated_scan(s.project_path),
        versions_fn=versions_fn or (lambda d: OUTDATED_VERSIONS[d.name]),
        outdated=True,
    )


def _column(table: DataTable, row: int, header: str) -> str:
    from vulnscan.tui import OUTDATED_COLUMNS

    return str(table.get_row_at(row)[OUTDATED_COLUMNS.index(header)])


async def test_outdated_mode_lists_packages_with_newer_releases(tmp_path: Path):
    app = _outdated_app(tmp_path)
    async with app.run_test() as pilot:
        await settle(app, pilot)
        deps = app.query_one("#deps", DataTable)
        assert deps.row_count == 3  # click is up to date
        names = [_column(deps, i, "Package") for i in range(deps.row_count)]
        assert names == ["flask", "monolog/monolog", "requests"]
        assert _column(deps, 0, "Installed") == "3.0.0"
        assert _column(deps, 0, "Series update") == "3.0.3"
        assert _column(deps, 0, "Latest") == "3.1.0"
        assert _column(deps, 1, "Series update") == "-"
        assert _column(deps, 1, "Latest") == "2.9.1"


async def test_outdated_mode_shows_advisory_counts_per_package(tmp_path: Path):
    app = _outdated_app(tmp_path)
    async with app.run_test() as pilot:
        await settle(app, pilot)
        deps = app.query_one("#deps", DataTable)
        assert _column(deps, 0, "Advisories") == "none"
        assert _column(deps, 1, "Advisories") == "1"
        assert _column(deps, 2, "Advisories") == "2"


async def test_outdated_mode_clearly_marks_updates_as_non_security(tmp_path: Path):
    from textual.widgets import Static

    app = _outdated_app(tmp_path)
    async with app.run_test() as pilot:
        await settle(app, pilot)
        assert "not security" in app.sub_title.lower()
        banner = str(app.query_one("#mode-banner", Static).content).lower()
        assert "not security" in banner
        assert "update" in app.status_text
        assert "4" in app.status_text  # dependencies scanned
        assert "3" in app.status_text  # with updates


async def test_normal_mode_has_no_outdated_banner(tmp_path: Path):
    from textual.css.query import NoMatches
    from textual.widgets import Static

    app = VulnScanApp(settings_for(tmp_path), scan_fn=lambda s: sample_result(s.project_path))
    async with app.run_test() as pilot:
        await settle(app, pilot)
        with pytest.raises(NoMatches):
            app.query_one("#mode-banner", Static)
        assert "not security" not in app.sub_title.lower()


async def test_outdated_mode_detail_pane_describes_the_update(tmp_path: Path):
    app = _outdated_app(tmp_path)
    async with app.run_test() as pilot:
        await settle(app, pilot)
        detail = app.query_one("#detail", Markdown).source
        assert "flask" in detail
        assert "3.0.3" in detail
        assert "3.1.0" in detail
        assert "not a security" in detail.lower()
        assert "requirements.txt" in detail
        assert app.query_one("#vulns", DataTable).row_count == 0


async def test_outdated_mode_shows_advisories_for_a_vulnerable_package(tmp_path: Path):
    app = _outdated_app(tmp_path)
    async with app.run_test() as pilot:
        await settle(app, pilot)
        deps = app.query_one("#deps", DataTable)
        deps.move_cursor(row=2)  # requests
        await settle(app, pilot)
        vulns = app.query_one("#vulns", DataTable)
        assert vulns.row_count == 2
        detail = app.query_one("#detail", Markdown).source
        assert "2.32.4" in detail
        assert "GHSA-j8r2-6x86-q33q" in detail
        vulns.focus()  # as with Tab: move into the advisory table, then down
        vulns.move_cursor(row=1)
        await settle(app, pilot)
        assert "GHSA-other" in app.query_one("#detail", Markdown).source


async def test_outdated_mode_upgrade_offers_series_and_latest(tmp_path: Path):
    from textual.widgets import OptionList, Static

    app = _outdated_app(tmp_path)
    async with app.run_test() as pilot:
        await settle(app, pilot)
        await pilot.press("u")
        await settle(app, pilot)
        screen = app.screen
        assert screen.__class__.__name__ == "UpgradeScreen"
        summary = str(screen.query_one("#remediate-summary", Static).content).lower()
        assert "not a security" in summary
        options = screen.query_one("#remediate-options", OptionList)
        assert options.option_count == 2
        prompts = [str(options.get_option_at_index(i).prompt) for i in range(2)]
        assert "3.0.3" in prompts[0]
        assert "3.1.0" in prompts[1]
        assert not options.get_option_at_index(0).disabled
        await pilot.press("enter")  # first option: newest release in the 3.0 series
        await settle(app, pilot)
        assert app.screen.__class__.__name__ != "UpgradeScreen"
        text = (tmp_path / "proj" / "requirements.txt").read_text()
        assert "flask==3.0.3" in text
        assert "requests==2.30.0" in text
        assert app.remediated == {("PyPI", "flask"): "flask==3.0.3"}


async def test_outdated_mode_latest_option_applies_newest_release(tmp_path: Path):
    app = _outdated_app(tmp_path)
    async with app.run_test() as pilot:
        await settle(app, pilot)
        await pilot.press("u")
        await settle(app, pilot)
        await pilot.press("down")
        await pilot.press("enter")
        await settle(app, pilot)
        assert "flask==3.1.0" in (tmp_path / "proj" / "requirements.txt").read_text()


async def test_outdated_mode_series_option_disabled_without_a_series_release(tmp_path: Path):
    from textual.widgets import OptionList

    app = _outdated_app(tmp_path)
    async with app.run_test() as pilot:
        await settle(app, pilot)
        app.query_one("#deps", DataTable).move_cursor(row=1)  # monolog 1.0.0 -> only 2.9.1
        await settle(app, pilot)
        await pilot.press("u")
        await settle(app, pilot)
        options = app.screen.query_one("#remediate-options", OptionList)
        assert options.get_option_at_index(0).disabled
        assert not options.get_option_at_index(1).disabled
        await pilot.press("enter")
        await settle(app, pilot)
        assert '"monolog/monolog": "^2.9.1"' in (tmp_path / "proj" / "composer.json").read_text()


async def test_outdated_mode_escape_cancels_upgrade(tmp_path: Path):
    app = _outdated_app(tmp_path)
    original = (tmp_path / "proj" / "requirements.txt").read_text()
    async with app.run_test() as pilot:
        await settle(app, pilot)
        await pilot.press("u")
        await settle(app, pilot)
        await pilot.press("escape")
        await settle(app, pilot)
        assert (tmp_path / "proj" / "requirements.txt").read_text() == original
        assert app.remediated == {}


async def test_outdated_mode_upgraded_row_is_ticked(tmp_path: Path):
    app = _outdated_app(tmp_path)
    async with app.run_test() as pilot:
        await settle(app, pilot)
        deps = app.query_one("#deps", DataTable)
        assert "✔" not in "".join(_row_text(deps, 0))
        await pilot.press("u")
        await settle(app, pilot)
        await pilot.press("enter")
        await settle(app, pilot)
        assert "✔" in str(deps.get_row_at(0)[0])
        assert "✔" not in "".join(_row_text(deps, 1))


async def test_outdated_mode_registry_failure_is_a_warning(tmp_path: Path):
    from vulnscan.registry import RegistryError

    def versions(dep):
        if dep.name == "requests":
            raise RegistryError("registry down")
        return OUTDATED_VERSIONS[dep.name]

    app = _outdated_app(tmp_path, versions_fn=versions)
    async with app.run_test() as pilot:
        await settle(app, pilot)
        deps = app.query_one("#deps", DataTable)
        assert deps.row_count == 2
        assert "requests" in app.status_text
        assert "registry down" in app.status_text


async def test_outdated_mode_scan_failure_is_reported(tmp_path: Path):
    def failing(s):
        raise RuntimeError("OSV exploded")

    app = VulnScanApp(settings_for(tmp_path), scan_fn=failing, outdated=True)
    async with app.run_test() as pilot:
        await settle(app, pilot)
        assert "OSV exploded" in app.status_text
        assert app.query_one("#deps", DataTable).row_count == 0


def test_upgrade_markdown_states_it_is_not_a_security_update():
    from vulnscan.outdated import UpgradeOptions
    from vulnscan.tui import upgrade_markdown

    dep = Dependency("flask", PYPI, "==3.0.0", "3.0.0", "pinned", "requirements.txt")
    options = UpgradeOptions("3.0.0", "3.0", "3.0.3", "3.1.0")
    text = upgrade_markdown(dep, options, None)
    assert "not a security" in text.lower()
    assert "3.0.3" in text
    assert "3.1.0" in text
    assert "requirements.txt" in text
    v = Vulnerability("GHSA-x", "s", "d", severity="HIGH")
    with_finding = upgrade_markdown(dep, options, Finding(dep, [v]))
    assert "GHSA-x" in with_finding


# -- transitive dependencies ---------------------------------------------------------------


def _transitive_result(path: Path) -> ScanResult:
    httpx = Dependency("httpx", PYPI, ">=0.27", "0.27.0", "constraint", "pyproject.toml")
    certifi = Dependency(
        "certifi",
        PYPI,
        "",
        "2024.2.2",
        "lock",
        "uv.lock",
        transitive=True,
        required_by=("httpx",),
    )
    v = Vulnerability("GHSA-C", "s", "d", severity="HIGH", fixed_versions=["2026.10.19"])
    return ScanResult(path, [httpx, certifi], [Finding(certifi, [v])], [], datetime.now(UTC))


async def test_transitive_dependency_row_is_marked(tmp_path: Path):
    app = VulnScanApp(settings_for(tmp_path), scan_fn=lambda s: _transitive_result(s.project_path))
    async with app.run_test() as pilot:
        await settle(app, pilot)
        deps = app.query_one("#deps", DataTable)
        row = _row_text(deps, 0)
        assert any("certifi" in c for c in row)
        assert any("transitive" in c for c in row)
        detail = app.query_one("#detail", Markdown).source
        assert "transitive" in detail
        assert "httpx" in detail


def _transitive_project(tmp_path: Path):
    settings = settings_for(tmp_path)
    settings.project_path.mkdir()
    (settings.project_path / "uv.lock").write_text(
        '[[package]]\nname="certifi"\nversion="2024.2.2"\n'
    )
    (settings.project_path / "pyproject.toml").write_text(
        '[project]\nname = "x"\ndependencies = [\n    "httpx>=0.27",\n]\n'
    )
    return settings


async def test_upgrade_key_confirms_then_pins_a_transitive_dependency(tmp_path: Path):
    from textual.widgets import OptionList, Static

    settings = _transitive_project(tmp_path)
    app = VulnScanApp(
        settings,
        scan_fn=lambda s: _transitive_result(s.project_path),
        versions_fn=lambda d: ["2024.2.2", "2026.10.19", "2027.1.1"],
    )
    async with app.run_test() as pilot:
        await settle(app, pilot)
        await pilot.press("u")
        await settle(app, pilot)
        screen = app.screen
        assert screen.__class__.__name__ == "PinScreen"
        widget = screen.query_one("#remediate-summary", Static)
        summary = str(widget.content)
        assert "transitive" in summary
        assert "httpx" in summary
        assert "pyproject.toml" in summary
        assert "[project]" in widget.render().plain  # square brackets are not markup
        options = screen.query_one("#remediate-options", OptionList)
        prompts = [str(options.get_option_at_index(i).prompt) for i in range(options.option_count)]
        assert any("certifi>=2026.10.19" in p for p in prompts)
        assert any("certifi>=2027.1.1" in p for p in prompts)
        await pilot.press("enter")  # nearest safe version
        await settle(app, pilot)
        assert app.screen.__class__.__name__ != "PinScreen"
        text = (settings.project_path / "pyproject.toml").read_text()
        assert '    "certifi>=2026.10.19",\n    "httpx>=0.27",' in text
        assert "Added certifi>=2026.10.19 to pyproject.toml" in app.status_text
        assert "uv lock" in app.status_text
        assert app.remediated == {("PyPI", "certifi"): "certifi>=2026.10.19"}
        assert "✔" in str(app.query_one("#deps", DataTable).get_row_at(0)[0])


async def test_pin_dialog_escape_leaves_the_manifest_alone(tmp_path: Path):
    settings = _transitive_project(tmp_path)
    original = (settings.project_path / "pyproject.toml").read_text()
    app = VulnScanApp(
        settings,
        scan_fn=lambda s: _transitive_result(s.project_path),
        versions_fn=lambda d: ["2024.2.2", "2026.10.19"],
    )
    async with app.run_test() as pilot:
        await settle(app, pilot)
        await pilot.press("u")
        await settle(app, pilot)
        assert app.screen.__class__.__name__ == "PinScreen"
        await pilot.press("escape")
        await settle(app, pilot)
        assert (settings.project_path / "pyproject.toml").read_text() == original
        assert app.remediated == {}


async def test_upgrade_key_explains_transitive_dependency_without_a_manifest(tmp_path: Path):
    settings = settings_for(tmp_path)
    settings.project_path.mkdir()
    (settings.project_path / "uv.lock").write_text(
        '[[package]]\nname="certifi"\nversion="2024.2.2"\n'
    )
    app = VulnScanApp(
        settings,
        scan_fn=lambda s: _transitive_result(s.project_path),
        versions_fn=lambda d: ["2024.2.2", "2026.10.19"],
    )
    async with app.run_test() as pilot:
        await settle(app, pilot)
        await pilot.press("u")
        await settle(app, pilot)
        assert app.screen.__class__.__name__ not in (
            "RemediateScreen",
            "UpgradeScreen",
            "PinScreen",
        )
        assert "transitive" in app.status_text
        assert "certifi>=2026.10.19" in app.status_text
        assert app.remediated == {}


async def test_outdated_mode_pins_transitive_dependency_to_series_or_latest(tmp_path: Path):
    from textual.widgets import OptionList

    settings = _transitive_project(tmp_path)
    app = VulnScanApp(
        settings,
        scan_fn=lambda s: _transitive_result(s.project_path),
        versions_fn=lambda d: {"certifi": ["2024.2.2", "2024.2.5", "2026.10.19"]}.get(
            d.name, ["0.27.0"]
        ),
        outdated=True,
    )
    async with app.run_test() as pilot:
        await settle(app, pilot)
        deps = app.query_one("#deps", DataTable)
        assert [_column(deps, i, "Package") for i in range(deps.row_count)] == ["certifi"]
        await pilot.press("u")
        await settle(app, pilot)
        assert app.screen.__class__.__name__ == "PinScreen"
        options = app.screen.query_one("#remediate-options", OptionList)
        prompts = [str(options.get_option_at_index(i).prompt) for i in range(options.option_count)]
        assert "certifi>=2024.2.5" in prompts[0]
        assert "certifi>=2026.10.19" in prompts[1]
        await pilot.press("down")
        await pilot.press("enter")
        await settle(app, pilot)
        assert '"certifi>=2026.10.19"' in (settings.project_path / "pyproject.toml").read_text()


# --- HTTP activity panel ------------------------------------------------------------------


def _transfer(**kwargs):
    from vulnscan.activity import Transfer

    base = {
        "id": 1,
        "method": "GET",
        "url": "https://pypi.org/pypi/requests/json",
        "started": 100.0,
    }
    base.update(kwargs)
    return Transfer(**base)


def test_render_activity_is_empty_when_nothing_happened():
    from vulnscan.tui import render_activity

    assert render_activity([], now=100.0) == ""


def test_render_activity_shows_label_progress_and_sizes_for_a_download_in_flight():
    from vulnscan.tui import render_activity

    text = render_activity(
        [_transfer(status=200, total=120_000_000, received=73_200_000)], now=101.0
    )
    assert "PyPI requests" in text
    assert "61%" in text
    assert "73.2 MB" in text
    assert "120.0 MB" in text


def test_render_activity_shows_bytes_without_a_percentage_when_size_is_unknown():
    from vulnscan.tui import render_activity

    text = render_activity([_transfer(status=200, received=12_400)], now=101.0)
    assert "12.4 kB" in text
    assert "%" not in text


def test_render_activity_marks_a_request_that_is_still_waiting_for_an_answer():
    from vulnscan.tui import render_activity

    text = render_activity([_transfer()], now=101.0)
    assert "PyPI requests" in text
    assert "waiting" in text.lower()


def test_render_activity_keeps_a_finished_transfer_briefly_then_drops_it():
    from vulnscan.tui import LINGER_SECONDS, render_activity

    done = _transfer(status=200, total=46, received=46, finished=101.0)
    assert "PyPI requests" in render_activity([done], now=101.0 + LINGER_SECONDS / 2)
    assert "200" in render_activity([done], now=101.0 + LINGER_SECONDS / 2)
    assert render_activity([done], now=101.0 + LINGER_SECONDS + 1) == ""


def test_render_activity_says_when_a_transfer_failed():
    from vulnscan.tui import render_activity

    failed = _transfer(error="connection refused", finished=101.0)
    text = render_activity([failed], now=101.5)
    assert "failed" in text.lower()
    assert "connection refused" in text


def test_render_activity_summarises_the_session_and_in_flight_count():
    from vulnscan.tui import render_activity

    rows = [
        _transfer(id=1, status=200, total=1000, received=1000, finished=100.5),
        _transfer(
            id=2, url="https://registry.npmjs.org/lodash", status=200, total=5000, received=2000
        ),
    ]
    text = render_activity(rows, now=101.0, session_requests=14, session_bytes=73_300_000)
    assert "14 requests" in text
    assert "73.3 MB" in text
    assert "1 in flight" in text


def test_render_activity_limits_the_rows_and_counts_the_rest():
    from vulnscan.tui import ACTIVITY_MAX_ROWS, render_activity

    rows = [
        _transfer(id=i, url=f"https://pypi.org/pypi/pkg{i}/json", status=200, received=1)
        for i in range(ACTIVITY_MAX_ROWS + 3)
    ]
    text = render_activity(rows, now=101.0)
    assert text.count("PyPI pkg") == ACTIVITY_MAX_ROWS
    assert "3 more" in text


def test_render_activity_lists_transfers_in_flight_before_finished_ones():
    from vulnscan.tui import render_activity

    rows = [
        _transfer(id=1, status=200, total=10, received=10, finished=100.9),
        _transfer(id=2, url="https://registry.npmjs.org/lodash", status=200, total=50, received=5),
    ]
    text = render_activity(rows, now=101.0)
    assert text.index("npm lodash") < text.index("PyPI requests")


async def test_activity_panel_shows_requests_while_a_scan_runs(tmp_path: Path):
    import threading
    import time

    from textual.widgets import Static

    from vulnscan import activity

    settings = settings_for(tmp_path)
    published = threading.Event()
    release = threading.Event()

    def scanning(s: Settings) -> ScanResult:
        activity.publish(
            activity.Transfer(
                id=activity.next_id(),
                method="GET",
                url="https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production",
                started=time.monotonic(),
                status=200,
                total=1000,
                received=400,
            )
        )
        published.set()
        release.wait(timeout=5)
        return sample_result(s.project_path)

    app = VulnScanApp(settings, scan_fn=scanning)
    async with app.run_test() as pilot:
        for _ in range(50):
            if published.is_set():
                break
            await pilot.pause(0.05)
        assert published.is_set()
        await pilot.pause(0.3)
        panel = app.query_one("#activity", Static)
        assert panel.display is True
        rendered = str(panel.content)
        assert "Wordfence feed" in rendered
        assert "40%" in rendered
        release.set()
        await settle(app, pilot)
        assert "vulnerable" in app.status_text
