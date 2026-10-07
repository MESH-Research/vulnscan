from datetime import UTC, datetime

from vulnscan.models import (
    PACKAGIST,
    PYPI,
    Dependency,
    Finding,
    Vulnerability,
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
