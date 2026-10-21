import pytest

from vulnscan.models import NPM, PACKAGIST, PYPI, WORDPRESS, Dependency
from vulnscan.outdated import UpgradeOptions, find_outdated, plan_upgrade, release_series
from vulnscan.registry import RegistryError


def dep(name: str, version: str | None, ecosystem: str = PYPI) -> Dependency:
    return Dependency(
        name, ecosystem, f"=={version}" if version else "", version, "pinned", "r.txt"
    )


@pytest.mark.parametrize(
    ("version", "ecosystem", "series"),
    [
        ("2.6.1", PYPI, "2.6"),
        ("v2.6.1", PACKAGIST, "2.6"),
        ("6.4", WORDPRESS, "6.4"),
        ("5", WORDPRESS, "5"),
        ("1.2.3-beta.1", NPM, "1.2"),
        ("1!2.0.1", PYPI, "2.0"),
        ("2.6.1.post1", PYPI, "2.6"),
        ("trunk", WORDPRESS, None),
        ("", PYPI, None),
    ],
)
def test_release_series(version, ecosystem, series):
    assert release_series(version, ecosystem) == series


def test_plan_upgrade_offers_newest_in_series_and_newest_overall():
    options = plan_upgrade(
        dep("pkg", "2.6.1"), ["2.5.0", "2.6.0", "2.6.1", "2.6.2", "2.7.0", "2.7.2", "3.0.0"]
    )
    assert options == UpgradeOptions(
        current="2.6.1", series="2.6", series_latest="2.6.2", latest="3.0.0"
    )
    assert options.is_outdated


def test_plan_upgrade_without_a_newer_series_release():
    options = plan_upgrade(dep("pkg", "2.6.2"), ["2.6.1", "2.6.2", "2.7.2"])
    assert options.series == "2.6"
    assert options.series_latest is None
    assert options.latest == "2.7.2"
    assert options.is_outdated


def test_plan_upgrade_series_release_may_also_be_the_latest():
    options = plan_upgrade(dep("pkg", "2.6.1"), ["2.6.1", "2.6.2"])
    assert options.series_latest == "2.6.2"
    assert options.latest == "2.6.2"


def test_plan_upgrade_up_to_date_package_is_not_outdated():
    options = plan_upgrade(dep("pkg", "2.7.2"), ["2.6.1", "2.7.2"])
    assert options.series_latest is None
    assert options.latest is None
    assert not options.is_outdated


def test_plan_upgrade_ignores_order_and_duplicates():
    options = plan_upgrade(
        dep("pkg", "1.0.0"), ["1.2.0", "1.0.2", "1.0.0", "1.10.0", "1.0.2", "1.2.0", "0.9.0"]
    )
    assert options.series_latest == "1.0.2"
    assert options.latest == "1.10.0"


def test_plan_upgrade_unknown_current_version_is_not_outdated():
    options = plan_upgrade(dep("pkg", None), ["1.0.0", "2.0.0"])
    assert options.current is None
    assert options.latest is None
    assert not options.is_outdated


def test_plan_upgrade_with_no_versions():
    options = plan_upgrade(dep("pkg", "1.0.0"), [])
    assert options.latest is None
    assert not options.is_outdated


def test_plan_upgrade_uses_ecosystem_comparison():
    # npm build metadata is ignored; the loose comparison handles two-part WordPress versions.
    npm = plan_upgrade(dep("left-pad", "1.0.0", NPM), ["1.0.0+build.1", "1.0.1", "1.1.0"])
    assert npm.series_latest == "1.0.1"
    assert npm.latest == "1.1.0"
    wp = plan_upgrade(dep("wordpress", "6.4", WORDPRESS), ["6.4", "6.4.2", "6.5"])
    assert wp.series_latest == "6.4.2"
    assert wp.latest == "6.5"


def test_find_outdated_returns_only_outdated_packages_sorted_by_name():
    deps = [dep("requests", "2.30.0"), dep("Flask", "3.0.0"), dep("click", "8.1.7")]
    versions = {
        "requests": ["2.30.0", "2.31.0", "2.32.4"],
        "Flask": ["3.0.0", "3.0.3", "3.1.0"],
        "click": ["8.1.7"],
    }
    outdated, warnings = find_outdated(deps, lambda d: versions[d.name])
    assert [o.dependency.name for o in outdated] == ["Flask", "requests"]
    assert outdated[0].options.series_latest == "3.0.3"
    assert outdated[0].options.latest == "3.1.0"
    assert outdated[1].options.latest == "2.32.4"
    assert warnings == []


def test_find_outdated_turns_registry_failures_into_warnings():
    deps = [dep("requests", "2.30.0"), dep("broken", "1.0.0")]

    def versions(d):
        if d.name == "broken":
            raise RegistryError("registry down")
        return ["2.30.0", "2.31.0"]

    outdated, warnings = find_outdated(deps, versions)
    assert [o.dependency.name for o in outdated] == ["requests"]
    assert len(warnings) == 1
    assert "broken" in warnings[0]
    assert "registry down" in warnings[0]


def test_find_outdated_skips_dependencies_with_unknown_versions():
    deps = [dep("mystery", None), dep("requests", "2.30.0")]
    outdated, warnings = find_outdated(deps, lambda d: ["2.30.0", "2.31.0"])
    assert [o.dependency.name for o in outdated] == ["requests"]
    assert len(warnings) == 1
    assert "mystery" in warnings[0]


def test_find_outdated_with_no_dependencies():
    assert find_outdated([], lambda d: []) == ([], [])
