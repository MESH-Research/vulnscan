import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from vulnscan.config import Settings
from vulnscan.models import PYPI, Dependency, Vulnerability
from vulnscan.osv import OSVError
from vulnscan.scanner import scan


def settings_for(tmp_path: Path, **kwargs) -> Settings:
    base = dict(
        project_path=tmp_path,
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
    )
    base.update(kwargs)
    return Settings(**base)


class FakeClient:
    """Stands in for OSVClient. `table` maps (name, version) -> list of Vulnerability."""

    def __init__(self, table: dict, error: Exception | None = None):
        self.table = table
        self.error = error
        self.seen: list[Dependency] = []

    def find_vulnerabilities(self, deps, include_unknown_versions=False):
        if self.error:
            raise self.error
        deps = list(deps)
        self.seen.extend(deps)
        result = {}
        for d in deps:
            if d.version is None and not include_unknown_versions:
                continue
            vulns = self.table.get((d.name, d.version), [])
            if vulns:
                result[d] = vulns
        return result


def vuln(id_, severity="UNKNOWN"):
    return Vulnerability(id_, "summary " + id_, "details", severity=severity)


def write_project(tmp_path: Path):
    (tmp_path / "requirements.txt").write_text("requests==2.30.0\nflask==3.0.0\n")
    (tmp_path / "requirements-dev.txt").write_text("pytest==7.0.0\n")
    (tmp_path / "composer.json").write_text(json.dumps({"require": {"monolog/monolog": "1.0.0"}}))


def test_scan_builds_findings_sorted_by_severity_then_name(tmp_path: Path):
    write_project(tmp_path)
    client = FakeClient(
        {
            ("requests", "2.30.0"): [vuln("GHSA-R", "LOW")],
            ("monolog/monolog", "1.0.0"): [vuln("GHSA-M1", "LOW"), vuln("GHSA-M2", "CRITICAL")],
            ("pytest", "7.0.0"): [vuln("GHSA-P", "LOW")],
        }
    )
    result = scan(settings_for(tmp_path), client=client)
    assert [f.dependency.name for f in result.findings] == ["monolog/monolog", "pytest", "requests"]
    assert result.findings[0].worst_severity == "CRITICAL"
    assert {d.name for d in result.dependencies} == {
        "requests",
        "flask",
        "pytest",
        "monolog/monolog",
    }
    assert result.project_path == tmp_path
    assert result.scanned_at.tzinfo is not None
    assert result.scanned_at <= datetime.now(UTC)


def test_scan_excludes_dev_dependencies_when_configured(tmp_path: Path):
    write_project(tmp_path)
    client = FakeClient({("pytest", "7.0.0"): [vuln("GHSA-P")]})
    result = scan(settings_for(tmp_path, include_dev=False), client=client)
    assert result.findings == []
    assert "pytest" not in {d.name for d in result.dependencies}


def test_scan_collapses_duplicate_dependencies(tmp_path: Path):
    (tmp_path / "requirements.txt").write_text("requests==2.30.0\n")
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname="x"\ndependencies=["requests==2.30.0"]\n'
    )
    client = FakeClient({("requests", "2.30.0"): [vuln("GHSA-R")]})
    result = scan(settings_for(tmp_path), client=client)
    assert len(result.findings) == 1
    assert len([d for d in result.dependencies if d.name == "requests"]) == 1


def test_scan_reports_unknown_versions_as_warnings_and_does_not_query_them(tmp_path: Path):
    (tmp_path / "requirements.txt").write_text("flask\n")
    client = FakeClient({})
    result = scan(settings_for(tmp_path), client=client)
    assert result.findings == []
    assert any("flask" in w for w in result.warnings)
    assert [d.version for d in result.dependencies] == [None]


def test_scan_queries_unknown_versions_when_enabled(tmp_path: Path):
    (tmp_path / "requirements.txt").write_text("flask\n")
    client = FakeClient({("flask", None): [vuln("GHSA-F")]})
    result = scan(settings_for(tmp_path, query_unknown_versions=True), client=client)
    assert [f.dependency.name for f in result.findings] == ["flask"]


def test_scan_warns_when_no_manifests(tmp_path: Path):
    result = scan(settings_for(tmp_path), client=FakeClient({}))
    assert result.findings == []
    assert result.warnings


def test_scan_propagates_osv_errors(tmp_path: Path):
    write_project(tmp_path)
    with pytest.raises(OSVError):
        scan(settings_for(tmp_path), client=FakeClient({}, error=OSVError("down")))


def test_scan_with_no_vulnerabilities(tmp_path: Path):
    write_project(tmp_path)
    result = scan(settings_for(tmp_path), client=FakeClient({}))
    assert result.findings == []
    assert len(result.dependencies) == 4


def test_scan_uses_default_client_when_none_given(tmp_path: Path, monkeypatch):
    """Without a client, scan must build one from settings; we stop it reaching the network."""
    import vulnscan.scanner as scanner_module

    created = {}

    class Recording(FakeClient):
        def __init__(self, base_url, timeout):
            super().__init__({})
            created["base_url"] = base_url
            created["timeout"] = timeout

    monkeypatch.setattr(scanner_module, "OSVClient", Recording)
    write_project(tmp_path)
    scan(settings_for(tmp_path, osv_base_url="https://osv.example", request_timeout=7.0))
    assert created == {"base_url": "https://osv.example", "timeout": 7.0}


def test_scan_dependency_ecosystem_preserved(tmp_path: Path):
    write_project(tmp_path)
    result = scan(settings_for(tmp_path), client=FakeClient({}))
    assert {d.ecosystem for d in result.dependencies} == {PYPI, "Packagist"}
