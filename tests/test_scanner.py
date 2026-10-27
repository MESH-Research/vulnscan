import json
from datetime import UTC, datetime
from pathlib import Path

from vulnscan.config import Settings
from vulnscan.models import CONTAINER, NPM, PYPI, Dependency, Vulnerability
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


class EmptyRegistry:
    """Avoid forward-check network / extra OSV queries in unit tests."""

    def available_versions(self, dep):
        return []


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
    result = scan(settings_for(tmp_path), client=client, registry=EmptyRegistry())
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
    result = scan(
        settings_for(tmp_path, include_dev=False),
        client=client,
        registry=EmptyRegistry(),
    )
    assert result.findings == []
    assert "pytest" not in {d.name for d in result.dependencies}


def test_scan_collapses_duplicate_dependencies(tmp_path: Path):
    (tmp_path / "requirements.txt").write_text("requests==2.30.0\n")
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname="x"\ndependencies=["requests==2.30.0"]\n'
    )
    client = FakeClient({("requests", "2.30.0"): [vuln("GHSA-R")]})
    result = scan(settings_for(tmp_path), client=client, registry=EmptyRegistry())
    assert len(result.findings) == 1
    assert len([d for d in result.dependencies if d.name == "requests"]) == 1


def test_scan_lists_every_file_declaring_a_collapsed_dependency(tmp_path: Path):
    (tmp_path / "requirements").mkdir()
    (tmp_path / "requirements" / "base.txt").write_text("authlib==1.2.0\n")
    (tmp_path / "requirements" / "production.txt").write_text("-r base.txt\nAuthLib==1.2.0\n")
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname="x"\ndependencies=["authlib==1.2.0"]\n'
    )
    client = FakeClient({("authlib", "1.2.0"): [vuln("GHSA-A")]})
    result = scan(settings_for(tmp_path), client=client, registry=EmptyRegistry())
    assert len(result.findings) == 1
    dep = result.findings[0].dependency
    assert dep.source_files == [
        "pyproject.toml",
        "requirements/base.txt",
        "requirements/production.txt",
    ]
    assert len(client.seen) == 1


def test_scan_reports_unknown_versions_as_warnings_and_does_not_query_them(tmp_path: Path):
    (tmp_path / "requirements.txt").write_text("flask\n")
    client = FakeClient({})
    result = scan(settings_for(tmp_path), client=client, registry=EmptyRegistry())
    assert result.findings == []
    assert any("flask" in w for w in result.warnings)
    assert [d.version for d in result.dependencies] == [None]


def test_scan_queries_unknown_versions_when_enabled(tmp_path: Path):
    (tmp_path / "requirements.txt").write_text("flask\n")
    client = FakeClient({("flask", None): [vuln("GHSA-F")]})
    result = scan(
        settings_for(tmp_path, query_unknown_versions=True),
        client=client,
        registry=EmptyRegistry(),
    )
    assert [f.dependency.name for f in result.findings] == ["flask"]


def test_scan_warns_when_no_manifests(tmp_path: Path):
    result = scan(settings_for(tmp_path), client=FakeClient({}), registry=EmptyRegistry())
    assert result.findings == []
    assert result.warnings


def test_scan_carries_on_when_osv_fails(tmp_path: Path):
    write_project(tmp_path)
    result = scan(
        settings_for(tmp_path),
        client=FakeClient({}, error=OSVError("OSV returned HTTP 503 for /v1/querybatch")),
        registry=EmptyRegistry(),
    )
    assert result.findings == []
    assert len(result.dependencies) == 4
    assert any("OSV returned HTTP 503" in line for line in result.source_errors)
    assert any("not checked" in line for line in result.source_errors)


def test_scan_with_no_vulnerabilities(tmp_path: Path):
    write_project(tmp_path)
    result = scan(settings_for(tmp_path), client=FakeClient({}), registry=EmptyRegistry())
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
    scan(
        settings_for(tmp_path, osv_base_url="https://osv.example", request_timeout=7.0),
        registry=EmptyRegistry(),
    )
    assert created == {"base_url": "https://osv.example", "timeout": 7.0}


def test_scan_dependency_ecosystem_preserved(tmp_path: Path):
    write_project(tmp_path)
    result = scan(settings_for(tmp_path), client=FakeClient({}), registry=EmptyRegistry())
    assert {d.ecosystem for d in result.dependencies} == {PYPI, "Packagist"}


from vulnscan.models import WORDPRESS  # noqa: E402


class FakeWordpressClient(FakeClient):
    def __init__(self, table, warnings=None):
        super().__init__(table)
        self.warnings = warnings or []


def write_wordpress_project(tmp_path: Path):
    (tmp_path / "composer.json").write_text(
        json.dumps({"require": {"wp-plugin/elementor": "3.13.4", "monolog/monolog": "1.0.0"}})
    )


def test_scan_routes_wordpress_dependencies_to_wordpress_client(tmp_path: Path):
    write_wordpress_project(tmp_path)
    osv = FakeClient({("monolog/monolog", "1.0.0"): [vuln("GHSA-M", "LOW")]})
    wp = FakeWordpressClient({("wp-plugin/elementor", "3.13.4"): [vuln("CVE-2023-1234", "HIGH")]})
    result = scan(
        settings_for(tmp_path, wordfence_api_key="k"),
        client=osv,
        wordpress_client=wp,
        registry=EmptyRegistry(),
    )
    assert [d.name for d in osv.seen] == ["monolog/monolog"]
    assert [d.name for d in wp.seen] == ["wp-plugin/elementor"]
    assert [(f.dependency.name, f.worst_severity) for f in result.findings] == [
        ("wp-plugin/elementor", "HIGH"),
        ("monolog/monolog", "LOW"),
    ]
    assert result.findings[0].dependency.ecosystem == WORDPRESS


def test_scan_warns_when_wordpress_dependencies_but_no_api_key(tmp_path: Path):
    write_wordpress_project(tmp_path)
    result = scan(
        settings_for(tmp_path, wordfence_api_key=""),
        client=FakeClient({}),
        registry=EmptyRegistry(),
    )
    assert result.findings == []
    assert any("WORDFENCE_API_KEY" in w and "1" in w for w in result.warnings)


def test_scan_builds_wordfence_client_from_settings(tmp_path: Path, monkeypatch):
    import vulnscan.scanner as scanner_module

    created = {}

    class Recording(FakeWordpressClient):
        def __init__(self, api_key, base_url, timeout, cache_path, ttl_hours, min_interval_minutes):
            super().__init__({})
            created.update(
                api_key=api_key,
                base_url=base_url,
                timeout=timeout,
                cache_path=cache_path,
                ttl_hours=ttl_hours,
                min_interval_minutes=min_interval_minutes,
            )

    monkeypatch.setattr(scanner_module, "WordfenceClient", Recording)
    write_wordpress_project(tmp_path)
    settings = settings_for(
        tmp_path,
        wordfence_api_key="k",
        wordfence_url="https://wf.example/v3",
        cache_dir=tmp_path / "cache",
        wordfence_ttl_hours=6.0,
        wordfence_min_interval_minutes=15.0,
        request_timeout=9.0,
    )
    scan(settings, client=FakeClient({}), registry=EmptyRegistry())
    assert created == {
        "api_key": "k",
        "base_url": "https://wf.example/v3",
        "timeout": 9.0,
        "cache_path": tmp_path / "cache" / "wordfence-production.json",
        "ttl_hours": 6.0,
        "min_interval_minutes": 15.0,
    }


def test_scan_does_not_build_wordfence_client_without_wordpress_deps(tmp_path: Path, monkeypatch):
    import vulnscan.scanner as scanner_module

    def boom(*args, **kwargs):
        raise AssertionError("should not be constructed")

    monkeypatch.setattr(scanner_module, "WordfenceClient", boom)
    write_project(tmp_path)
    scan(
        settings_for(tmp_path, wordfence_api_key="k"),
        client=FakeClient({}),
        registry=EmptyRegistry(),
    )


def test_scan_collects_client_warnings(tmp_path: Path):
    write_wordpress_project(tmp_path)
    wp = FakeWordpressClient({}, warnings=["Using stale Wordfence cache"])
    result = scan(
        settings_for(tmp_path, wordfence_api_key="k"),
        client=FakeClient({}),
        wordpress_client=wp,
        registry=EmptyRegistry(),
    )
    assert "Using stale Wordfence cache" in result.warnings


def test_scan_warns_about_custom_source_packages(tmp_path: Path):
    (tmp_path / "composer.json").write_text(json.dumps({"require": {"acme/private": "1.0.0"}}))
    (tmp_path / "composer.lock").write_text(
        json.dumps({"packages": [{"name": "acme/private", "version": "1.0.0", "type": "library"}]})
    )
    result = scan(settings_for(tmp_path), client=FakeClient({}), registry=EmptyRegistry())
    assert any("acme/private" in w and "custom" in w.lower() for w in result.warnings)


def test_scan_passes_ignore_dirs(tmp_path: Path):
    (tmp_path / "legacy").mkdir()
    (tmp_path / "legacy" / "requirements.txt").write_text("old==1.0\n")
    (tmp_path / "requirements.txt").write_text("new==1.0\n")
    result = scan(
        settings_for(tmp_path, ignore_dirs=("legacy",)),
        client=FakeClient({}),
        registry=EmptyRegistry(),
    )
    assert [d.name for d in result.dependencies] == ["new"]


def test_scan_queries_npm_dependencies_through_osv(tmp_path: Path):
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"lodash": "4.17.20"}}))
    client = FakeClient({("lodash", "4.17.20"): [vuln("GHSA-L", "HIGH")]})
    result = scan(settings_for(tmp_path), client=client, registry=EmptyRegistry())
    assert [(f.dependency.name, f.dependency.ecosystem) for f in result.findings] == [
        ("lodash", NPM)
    ]
    assert [d.ecosystem for d in client.seen] == [NPM]


def test_scan_includes_transitive_lock_packages_when_configured(tmp_path: Path):
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
    (tmp_path / "uv.lock").write_text(
        '[[package]]\nname="requests"\nversion="2.31.0"\ndependencies=[{name="urllib3"}]\n\n'
        '[[package]]\nname="urllib3"\nversion="2.0.0"\n'
    )
    client = FakeClient({("urllib3", "2.0.0"): [vuln("GHSA-U", "HIGH")]})
    result = scan(
        settings_for(tmp_path, include_transitive=True),
        client=client,
        registry=EmptyRegistry(),
    )
    assert {d.name for d in result.dependencies} == {"requests", "urllib3"}
    assert [f.dependency.name for f in result.findings] == ["urllib3"]
    assert result.findings[0].dependency.transitive is True
    assert result.findings[0].dependency.required_by == ("requests",)


def test_scan_leaves_transitive_packages_out_by_default(tmp_path: Path):
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
    (tmp_path / "uv.lock").write_text(
        '[[package]]\nname="requests"\nversion="2.31.0"\n\n[[package]]\nname="urllib3"\nversion="2.0.0"\n'
    )
    client = FakeClient({("urllib3", "2.0.0"): [vuln("GHSA-U", "HIGH")]})
    result = scan(settings_for(tmp_path), client=client, registry=EmptyRegistry())
    assert {d.name for d in result.dependencies} == {"requests"}
    assert result.findings == []


# --- container images -----------------------------------------------------------------------


class FakeNVDClient(FakeClient):
    def __init__(self, table: dict, warnings: list[str] | None = None):
        super().__init__(table)
        self.warnings = warnings or []


def write_container_project(tmp_path: Path):
    (tmp_path / "Dockerfile").write_text("FROM php:8.2.19-fpm\n")
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n  proxy:\n    image: traefik:v2.10.7\n  app:\n    image: php:8.2.19-fpm\n"
    )
    (tmp_path / "requirements.txt").write_text("requests==2.30.0\n")


def test_scan_routes_container_images_to_the_nvd_client(tmp_path: Path):
    write_container_project(tmp_path)
    osv = FakeClient({("requests", "2.30.0"): [vuln("GHSA-R", "LOW")]})
    nvd = FakeNVDClient(
        {
            ("php", "8.2.19"): [vuln("CVE-2024-4577", "CRITICAL")],
            ("traefik", "2.10.7"): [vuln("CVE-2024-45410", "HIGH")],
        },
        warnings=["nvd note"],
    )
    result = scan(
        settings_for(tmp_path),
        client=osv,
        nvd_client=nvd,
        registry=EmptyRegistry(),
    )
    assert [d.name for d in osv.seen] == ["requests"]
    assert sorted(d.name for d in nvd.seen) == ["php", "traefik"]
    assert [(f.dependency.name, f.worst_severity) for f in result.findings] == [
        ("php", "CRITICAL"),
        ("traefik", "HIGH"),
        ("requests", "LOW"),
    ]
    php = result.findings[0].dependency
    assert php.ecosystem == CONTAINER
    assert php.source_files == ["Dockerfile", "docker-compose.yml"]
    assert "nvd note" in result.warnings


def test_scan_builds_nvd_client_from_settings(tmp_path: Path, monkeypatch):
    import vulnscan.scanner as scanner_module

    created = {}

    class Recording(FakeNVDClient):
        def __init__(self, api_key, base_url, timeout, cache_dir, ttl_hours, image_products):
            super().__init__({})
            created.update(
                api_key=api_key,
                base_url=base_url,
                timeout=timeout,
                cache_dir=cache_dir,
                ttl_hours=ttl_hours,
                image_products=image_products,
            )

    monkeypatch.setattr(scanner_module, "NVDClient", Recording)
    write_container_project(tmp_path)
    settings = settings_for(
        tmp_path,
        nvd_api_key="k",
        nvd_url="https://nvd.example/cves",
        nvd_ttl_hours=6.0,
        cache_dir=tmp_path / "cache",
        image_products=("myorg/app=myorg:app",),
        request_timeout=9.0,
    )
    scan(settings, client=FakeClient({}), registry=EmptyRegistry())
    assert created == {
        "api_key": "k",
        "base_url": "https://nvd.example/cves",
        "timeout": 9.0,
        "cache_dir": tmp_path / "cache",
        "ttl_hours": 6.0,
        "image_products": {"myorg/app": "myorg:app"},
    }


def test_scan_does_not_build_nvd_client_without_images(tmp_path: Path, monkeypatch):
    import vulnscan.scanner as scanner_module

    def boom(*args, **kwargs):
        raise AssertionError("should not be constructed")

    monkeypatch.setattr(scanner_module, "NVDClient", boom)
    write_project(tmp_path)
    scan(settings_for(tmp_path), client=FakeClient({}), registry=EmptyRegistry())


def test_scan_carries_on_when_nvd_fails(tmp_path: Path):
    from vulnscan.nvd import NVDError

    write_container_project(tmp_path)
    nvd = FakeNVDClient({})
    nvd.error = NVDError("NVD down")
    result = scan(
        settings_for(tmp_path),
        client=FakeClient({("requests", "2.30.0"): [vuln("GHSA-R", "LOW")]}),
        nvd_client=nvd,
        registry=EmptyRegistry(),
    )
    assert [f.dependency.name for f in result.findings] == ["requests"]
    assert any("NVD down" in line for line in result.source_errors)


def test_scan_reports_the_nvd_clients_own_error_lines(tmp_path: Path):
    write_container_project(tmp_path)
    nvd = FakeNVDClient({("php", "8.2.19"): [vuln("CVE-2024-4577", "CRITICAL")]})
    nvd.error_lines = lambda: ["NVD: HTTP 429; not checked: traefik 2.10.7"]
    result = scan(
        settings_for(tmp_path), client=FakeClient({}), nvd_client=nvd, registry=EmptyRegistry()
    )
    assert [f.dependency.name for f in result.findings] == ["php"]
    assert result.source_errors == ["NVD: HTTP 429; not checked: traefik 2.10.7"]


def test_scan_carries_on_when_wordfence_fails(tmp_path: Path):
    from vulnscan.wordfence import WordfenceError

    write_wordpress_project(tmp_path)
    wp = FakeWordpressClient({})
    wp.error = WordfenceError("Wordfence rate limit hit (HTTP 429)")
    result = scan(
        settings_for(tmp_path, wordfence_api_key="k"),
        client=FakeClient({("monolog/monolog", "1.0.0"): [vuln("GHSA-M", "LOW")]}),
        wordpress_client=wp,
        registry=EmptyRegistry(),
    )
    assert [f.dependency.name for f in result.findings] == ["monolog/monolog"]
    assert any("Wordfence rate limit hit" in line for line in result.source_errors)
    assert any("WordPress" in line for line in result.source_errors)


def test_forward_check_source_failure_is_a_warning_not_an_abort(tmp_path: Path):
    from vulnscan.nvd import NVDError

    class FlakyNVD(FakeNVDClient):
        def find_vulnerabilities(self, deps, include_unknown_versions=False):
            if self.seen:  # the first call (the scan itself) succeeds, forward-checks fail
                raise NVDError("NVD down")
            return super().find_vulnerabilities(deps, include_unknown_versions)

    write_container_project(tmp_path)
    nvd = FlakyNVD({("php", "8.2.19"): [vuln("CVE-2024-4577", "CRITICAL")]})
    result = scan(
        settings_for(tmp_path),
        client=FakeClient({}),
        nvd_client=nvd,
        registry=ListingRegistry({"php": ["8.2.19", "8.2.20", "8.3.0"]}),
    )
    assert [f.dependency.name for f in result.findings] == ["php"]
    assert result.findings[0].upgrade_plan is not None
    assert any("NVD down" in w for w in result.warnings + result.source_errors)


class ListingRegistry:
    """Registry fake that lists versions for named packages and knows no release times."""

    def __init__(self, versions: dict[str, list[str]]):
        self.versions = versions

    def available_versions(self, dep):
        return list(self.versions.get(dep.name, []))

    def release_info(self, dep):
        return {}


def test_forward_check_scores_container_candidates_through_nvd_not_osv(tmp_path: Path):
    write_container_project(tmp_path)
    osv = FakeClient({})
    nvd = FakeNVDClient(
        {
            ("php", "8.2.19"): [vuln("CVE-OLD", "HIGH")],
            ("php", "8.2.20"): [vuln("CVE-NEW", "HIGH")],
        }
    )
    registry = ListingRegistry({"php": ["8.2.19", "8.2.20", "8.2.21"]})
    result = scan(settings_for(tmp_path), client=osv, nvd_client=nvd, registry=registry)
    assert all(d.ecosystem != CONTAINER for d in osv.seen)
    assert ("php", "8.2.20") in {(d.name, d.version) for d in nvd.seen}
    php = next(f for f in result.findings if f.dependency.name == "php")
    assert php.upgrade_plan.nearest_safe == "8.2.21"
    assert any("8.2.20" in w for w in php.upgrade_plan.warnings)
