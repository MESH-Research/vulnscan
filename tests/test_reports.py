from datetime import UTC, datetime
from pathlib import Path

from vulnscan.config import Settings
from vulnscan.models import (
    PYPI,
    WORDPRESS,
    Declaration,
    Dependency,
    Finding,
    ScanResult,
    Vulnerability,
)
from vulnscan.reports import render_markdown, render_text, write_reports

NOW = datetime(2026, 10, 7, 12, 0, tzinfo=UTC)


def settings_for(tmp_path: Path) -> Settings:
    return Settings(
        project_path=tmp_path / "proj",
        feed_dir=tmp_path / "out",
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
    )


def sample(tmp_path: Path) -> ScanResult:
    requests = Dependency("requests", PYPI, "==2.30.0", "2.30.0", "pinned", "requirements.txt")
    elementor = Dependency(
        "wp-plugin/elementor",
        WORDPRESS,
        "3.13.4",
        "3.13.4",
        "lock",
        "composer.json",
        kind="plugin",
        slug="elementor",
    )
    v1 = Vulnerability(
        "GHSA-j8r2-6x86-q33q",
        "Proxy-Authorization leak",
        "Details with <angle> brackets & stuff.",
        aliases=["CVE-2023-32681"],
        severity="MEDIUM",
        cvss="CVSS:3.1/AV:N",
        published=datetime(2023, 5, 26, tzinfo=UTC),
        fixed_versions=["2.31.0"],
        references=["https://nvd.nist.gov/vuln/detail/CVE-2023-32681"],
    )
    v2 = Vulnerability(
        "CVE-2023-1234",
        "Elementor XSS",
        "XSS details.",
        severity="HIGH",
        fixed_versions=["3.13.5"],
        link="https://www.wordfence.com/threat-intel/vulnerabilities/id/abc",
    )
    return ScanResult(
        tmp_path / "proj",
        [requests, elementor],
        [Finding(elementor, [v2]), Finding(requests, [v1])],
        ["flask: could not determine a version"],
        NOW,
    )


def test_markdown_contains_summary_table_and_details(tmp_path: Path):
    md = render_markdown(sample(tmp_path))
    assert md.startswith("# ")
    assert "proj" in md
    assert "2026-10-07" in md
    assert "| wp-plugin/elementor |" in md or "| `wp-plugin/elementor` |" in md
    assert "3.13.4" in md and "3.13.5" in md
    assert "HIGH" in md and "MEDIUM" in md
    assert "CVE-2023-1234" in md
    assert "GHSA-j8r2-6x86-q33q" in md
    assert "CVE-2023-32681" in md
    assert "https://nvd.nist.gov/vuln/detail/CVE-2023-32681" in md
    assert "https://www.wordfence.com/threat-intel/vulnerabilities/id/abc" in md
    assert "Details with <angle> brackets & stuff." in md
    assert "flask: could not determine a version" in md
    assert "2 of 2" in md or "2 dependencies" in md


def test_markdown_orders_findings_as_given(tmp_path: Path):
    md = render_markdown(sample(tmp_path))
    assert md.index("wp-plugin/elementor") < md.index("requests")


def test_text_report_is_plain(tmp_path: Path):
    text = render_text(sample(tmp_path))
    assert "**" not in text and "|" not in text and "# " not in text.splitlines()[0]
    assert "wp-plugin/elementor" in text and "3.13.4" in text and "3.13.5" in text
    assert "CVE-2023-1234" in text and "GHSA-j8r2-6x86-q33q" in text
    assert "HIGH" in text and "MEDIUM" in text
    assert "https://nvd.nist.gov/vuln/detail/CVE-2023-32681" in text
    assert "flask: could not determine a version" in text


def test_reports_with_no_findings(tmp_path: Path):
    result = ScanResult(tmp_path / "proj", [], [], [], NOW)
    assert "No known vulnerabilities" in render_markdown(result)
    assert "No known vulnerabilities" in render_text(result)


def test_write_reports_default_paths(tmp_path: Path):
    settings = settings_for(tmp_path)
    md, txt = write_reports(sample(tmp_path), settings)
    assert md == settings.markdown_path and txt == settings.text_path
    assert md.read_text().startswith("# ")
    assert "wp-plugin/elementor" in txt.read_text()


def test_write_reports_explicit_paths(tmp_path: Path):
    settings = settings_for(tmp_path)
    md, txt = write_reports(
        sample(tmp_path), settings, markdown_path=tmp_path / "a" / "r.md", text_path=None
    )
    assert md == tmp_path / "a" / "r.md" and md.is_file()
    assert txt is None
    assert not settings.text_path.exists()


def wordfence_result(tmp_path: Path) -> ScanResult:
    elementor = Dependency(
        "wp-plugin/elementor",
        WORDPRESS,
        "3.13.4",
        "3.13.4",
        "lock",
        "composer.json",
        kind="plugin",
        slug="elementor",
    )
    v = Vulnerability(
        "CVE-2023-1234",
        "Elementor XSS",
        "XSS details.",
        severity="HIGH",
        link="https://www.wordfence.com/threat-intel/vulnerabilities/id/abc",
        source="wordfence",
    )
    return ScanResult(tmp_path / "proj", [elementor], [Finding(elementor, [v])], [], NOW)


def test_reports_include_wordfence_attribution_only_when_used(tmp_path: Path):
    from vulnscan.wordfence import WORDFENCE_COPYRIGHT, WORDFENCE_LICENSE_URL

    with_wf = wordfence_result(tmp_path)
    for render in (render_markdown, render_text):
        out = render(with_wf)
        assert WORDFENCE_COPYRIGHT in out
        assert WORDFENCE_LICENSE_URL in out
        assert WORDFENCE_COPYRIGHT not in render(sample(tmp_path))


def _multi_declared(tmp_path: Path) -> ScanResult:
    dep = Dependency(
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
    vuln = Vulnerability("GHSA-A", "summary", "details", severity="HIGH")
    return ScanResult(tmp_path / "proj", [dep], [Finding(dep, [vuln])], [], NOW)


def test_markdown_lists_every_declaring_file(tmp_path: Path):
    text = render_markdown(_multi_declared(tmp_path))
    summary_row = next(line for line in text.splitlines() if line.startswith("| authlib"))
    assert "requirements/base.txt" in summary_row
    assert "requirements/production.txt" in summary_row
    assert "requirements/production.txt as >=1.2" in text


def test_text_report_lists_every_declaring_file(tmp_path: Path):
    text = render_text(_multi_declared(tmp_path))
    assert "requirements/base.txt as ==1.2.0" in text
    assert "requirements/production.txt as >=1.2" in text
