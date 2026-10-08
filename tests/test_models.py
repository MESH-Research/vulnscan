from datetime import UTC, datetime

from vulnscan.models import (
    PACKAGIST,
    PYPI,
    Declaration,
    Dependency,
    Finding,
    Vulnerability,
    merge_declarations,
    normalize_name,
    severity_rank,
)


def make_dep(**kwargs) -> Dependency:
    base = dict(
        name="requests",
        ecosystem=PYPI,
        constraint="==2.0.0",
        version="2.0.0",
        version_source="pinned",
        source_file="requirements.txt",
    )
    base.update(kwargs)
    return Dependency(**base)


def make_vuln(**kwargs) -> Vulnerability:
    base = dict(id="GHSA-xxxx-yyyy-zzzz", summary="Bad thing", details="Long text")
    base.update(kwargs)
    return Vulnerability(**base)


def test_normalize_name_pypi_canonicalises():
    assert normalize_name("Django_Rest.Framework", PYPI) == "django-rest-framework"


def test_normalize_name_packagist_lowercases():
    assert normalize_name("Monolog/Monolog", PACKAGIST) == "monolog/monolog"


def test_dependency_key_uses_normalised_name():
    dep = make_dep(name="Requests")
    assert dep.key == (PYPI, "requests")


def test_cve_ids_come_from_aliases_and_id():
    vuln = make_vuln(id="CVE-2024-0001", aliases=["GHSA-aaaa-bbbb-cccc", "CVE-2024-0002"])
    assert vuln.cve_ids == ["CVE-2024-0001", "CVE-2024-0002"]


def test_cve_ids_empty_when_no_cve():
    vuln = make_vuln(id="PYSEC-2024-1", aliases=["GHSA-aaaa-bbbb-cccc"])
    assert vuln.cve_ids == []


def test_vulnerability_url_points_at_osv():
    assert (
        make_vuln(id="GHSA-abcd-1234-efgh").url
        == "https://osv.dev/vulnerability/GHSA-abcd-1234-efgh"
    )


def test_severity_rank_orders_critical_before_unknown():
    assert severity_rank("CRITICAL") < severity_rank("HIGH") < severity_rank("LOW")
    assert severity_rank("LOW") < severity_rank("UNKNOWN")
    assert severity_rank("nonsense") == severity_rank("UNKNOWN")
    assert severity_rank("moderate") == severity_rank("MEDIUM")


def test_finding_worst_severity_picks_highest():
    finding = Finding(
        make_dep(),
        [make_vuln(severity="LOW"), make_vuln(id="X", severity="HIGH"), make_vuln(id="Y")],
    )
    assert finding.worst_severity == "HIGH"


def test_finding_worst_severity_unknown_when_none():
    assert Finding(make_dep(), []).worst_severity == "UNKNOWN"


def test_finding_fixed_versions_are_deduplicated_and_sorted():
    finding = Finding(
        make_dep(),
        [
            make_vuln(fixed_versions=["2.31.0", "2.20.0"]),
            make_vuln(id="X", fixed_versions=["2.20.0", "3.0.0"]),
        ],
    )
    assert finding.fixed_versions == ["2.20.0", "2.31.0", "3.0.0"]


def test_vulnerability_defaults():
    vuln = make_vuln(published=datetime(2024, 1, 1, tzinfo=UTC))
    assert vuln.aliases == []
    assert vuln.fixed_versions == []
    assert vuln.severity == "UNKNOWN"


def test_normalize_name_wordpress_lowercases():
    from vulnscan.models import WORDPRESS

    assert normalize_name("WP-Plugin/Elementor", WORDPRESS) == "wp-plugin/elementor"


def test_dependency_optional_fields_default():
    dep = make_dep()
    assert dep.kind == ""
    assert dep.slug == ""
    assert dep.custom_source is False


def test_vulnerability_url_prefers_explicit_link():
    vuln = make_vuln(link="https://www.wordfence.com/threat-intel/vulnerabilities/id/abc")
    assert vuln.url == "https://www.wordfence.com/threat-intel/vulnerabilities/id/abc"


from vulnscan.models import PACKAGIST as _PACKAGIST  # noqa: E402
from vulnscan.models import VersionRange  # noqa: E402


def test_version_range_osv_style_half_open():
    rng = VersionRange(lower="2.3.0", upper="2.31.0")
    assert rng.contains("2.3.0", PYPI) is True
    assert rng.contains("2.30.0", PYPI) is True
    assert rng.contains("2.31.0", PYPI) is False
    assert rng.contains("2.2.9", PYPI) is False


def test_version_range_inclusive_upper_and_unbounded():
    rng = VersionRange(lower=None, upper="3.16.4", upper_inclusive=True)
    assert rng.contains("3.16.4", _PACKAGIST) is True
    assert rng.contains("3.16.5", _PACKAGIST) is False
    unbounded = VersionRange(lower="0", upper=None)
    assert unbounded.contains("999", PYPI) is True


def test_version_range_handles_prerelease_ordering_for_pypi():
    rng = VersionRange(lower="0", upper="2.31.0")
    assert rng.contains("2.31.0rc1", PYPI) is True
    assert rng.contains("2.31.0.post1", PYPI) is False


def test_vulnerability_affects_uses_ranges_and_explicit_versions():
    vuln = make_vuln(
        affected_ranges=[VersionRange(lower="1.0", upper="1.5")], affected_versions=["2.0"]
    )
    assert vuln.affects("1.2", PYPI) is True
    assert vuln.affects("1.5", PYPI) is False
    assert vuln.affects("2.0", PYPI) is True
    assert vuln.affects("2.1", PYPI) is False


def test_vulnerability_affects_nothing_without_range_data():
    assert make_vuln().affects("1.0", PYPI) is False


# --- multiple declarations --------------------------------------------------------------------


def _dep(name, constraint, source_file, version="1.2.0", dev=False, ecosystem=PYPI):
    return Dependency(name, ecosystem, constraint, version, "pinned", source_file, dev=dev)


def test_declared_in_defaults_to_the_primary_location():
    dep = _dep("authlib", "==1.2.0", "requirements/base.txt")
    assert dep.declared_in == [Declaration("requirements/base.txt", "==1.2.0", False)]
    assert dep.source_files == ["requirements/base.txt"]


def test_declared_in_lists_every_declaration_primary_first():
    dep = Dependency(
        "authlib",
        PYPI,
        "==1.2.0",
        "1.2.0",
        "pinned",
        "requirements/base.txt",
        declarations=(
            Declaration("requirements/base.txt", "==1.2.0", False),
            Declaration("requirements/production.txt", ">=1.2", False),
            Declaration("pyproject.toml", "authlib>=1.2", True),
        ),
    )
    assert [d.source_file for d in dep.declared_in] == [
        "requirements/base.txt",
        "requirements/production.txt",
        "pyproject.toml",
    ]
    assert dep.source_files == [
        "requirements/base.txt",
        "requirements/production.txt",
        "pyproject.toml",
    ]
    text = dep.declared_in_text
    assert "requirements/base.txt as ==1.2.0" in text
    assert "requirements/production.txt as >=1.2" in text
    assert "pyproject.toml" in text


def test_declared_in_text_describes_unconstrained_declarations():
    dep = _dep("flask", "", "requirements.txt")
    assert dep.declared_in_text == "requirements.txt as any version"


def test_merge_declarations_collapses_same_package_and_version_across_files():
    deps = [
        _dep("AuthLib", "==1.2.0", "requirements/base.txt"),
        _dep("requests", "==2.30.0", "requirements/base.txt"),
        _dep("authlib", ">=1.2", "requirements/production.txt"),
        _dep("authlib", "==1.2.0", "requirements/test.txt", dev=True),
    ]
    merged = merge_declarations(deps)
    assert [d.name for d in merged] == ["AuthLib", "requests"]
    authlib = merged[0]
    assert authlib.source_file == "requirements/base.txt"
    assert authlib.constraint == "==1.2.0"
    assert authlib.source_files == [
        "requirements/base.txt",
        "requirements/production.txt",
        "requirements/test.txt",
    ]
    assert [d.constraint for d in authlib.declared_in] == ["==1.2.0", ">=1.2", "==1.2.0"]
    assert authlib.dev is False
    assert merged[1].declared_in == [Declaration("requirements/base.txt", "==2.30.0", False)]


def test_merge_declarations_keeps_different_versions_apart():
    deps = [
        _dep("authlib", "==1.2.0", "requirements/base.txt", version="1.2.0"),
        _dep("authlib", "==1.3.0", "requirements/production.txt", version="1.3.0"),
    ]
    merged = merge_declarations(deps)
    assert [(d.version, d.source_files) for d in merged] == [
        ("1.2.0", ["requirements/base.txt"]),
        ("1.3.0", ["requirements/production.txt"]),
    ]


def test_merge_declarations_is_dev_only_when_every_declaration_is_dev():
    deps = [
        _dep("pytest", "==7.0", "requirements/test.txt", dev=True),
        _dep("pytest", "==7.0", "pyproject.toml", dev=True),
    ]
    assert merge_declarations(deps)[0].dev is True


def test_merge_declarations_keeps_ecosystems_apart():
    deps = [
        _dep("monolog", "1.0", "composer.json", version="1.0", ecosystem=PACKAGIST),
        _dep("monolog", "==1.0", "requirements.txt", version="1.0"),
    ]
    assert len(merge_declarations(deps)) == 2


def test_merge_declarations_does_not_repeat_identical_locations():
    deps = [
        _dep("authlib", "==1.2.0", "requirements/base.txt"),
        _dep("authlib", "==1.2.0", "requirements/base.txt"),
    ]
    assert merge_declarations(deps)[0].source_files == ["requirements/base.txt"]
