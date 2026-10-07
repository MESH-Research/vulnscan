from datetime import UTC, datetime
from pathlib import Path

import pytest
from textual.widgets import DataTable, Markdown

from vulnscan.config import Settings
from vulnscan.models import PACKAGIST, PYPI, Dependency, Finding, ScanResult, Vulnerability
from vulnscan.tui import VulnScanApp


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

    def scan_fn(s):
        result = sample_result(s.project_path)
        # make monolog's single advisory carry range data so planning can work
        from vulnscan.models import VersionRange

        result.findings[0].vulnerabilities[0].affected_ranges = [
            VersionRange(lower="0", upper="1.0.1")
        ]
        return result

    app = VulnScanApp(settings, scan_fn=scan_fn, versions_fn=fake_versions)
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
