import pytest

from vulnscan.models import PACKAGIST, PYPI, Dependency
from vulnscan.parsers.versions import (
    exact_version_from_composer,
    exact_version_from_pep508,
    minimum_version_from_composer,
    minimum_version_from_pep508,
    normalize_version,
    resolve_dependency,
)


@pytest.mark.parametrize(
    "raw,expected", [("v1.2.3", "1.2.3"), (" 1.2.3 ", "1.2.3"), ("V2.0", "2.0"), ("1.0", "1.0")]
)
def test_normalize_version_strips_prefix_and_whitespace(raw, expected):
    assert normalize_version(raw) == expected


@pytest.mark.parametrize(
    "spec,expected",
    [
        ("==2.31.0", "2.31.0"),
        ("===2.31.0", "2.31.0"),
        (" == 2.31.0 ", "2.31.0"),
        ("==2.31.*", None),
        (">=2.0", None),
        ("", None),
        ("==2.0,<3", None),
    ],
)
def test_exact_version_from_pep508(spec, expected):
    assert exact_version_from_pep508(spec) == expected


@pytest.mark.parametrize(
    "spec,expected",
    [
        ("==2.31.0", "2.31.0"),
        (">=2.0,<3", "2.0"),
        ("~=1.4.2", "1.4.2"),
        (">1.0", "1.0"),
        ("<3", None),
        ("", None),
        ("!=1.0", None),
        ("==2.31.*", "2.31.0"),
        ("<3,>=1.5", "1.5"),
    ],
)
def test_minimum_version_from_pep508(spec, expected):
    assert minimum_version_from_pep508(spec) == expected


@pytest.mark.parametrize(
    "constraint,expected",
    [
        ("1.2.3", "1.2.3"),
        ("v1.2.3", "1.2.3"),
        ("1.2.3-beta1", "1.2.3-beta1"),
        ("^1.2.3", None),
        ("~1.2", None),
        ("*", None),
        ("dev-main", None),
        ("1.2.*", None),
    ],
)
def test_exact_version_from_composer(constraint, expected):
    assert exact_version_from_composer(constraint) == expected


@pytest.mark.parametrize(
    "constraint,expected",
    [
        ("^1.2.3", "1.2.3"),
        ("^2", "2"),
        ("~1.2", "1.2"),
        (">=1.4 <2.0", "1.4"),
        (">=1.4, <2.0", "1.4"),
        ("1.2.*", "1.2.0"),
        ("1.*", "1.0"),
        ("1.2.3", "1.2.3"),
        ("v3.1.0", "3.1.0"),
        ("^1.0 || ^2.0", "1.0"),
        (">1.0", "1.0"),
        ("<2.0", None),
        ("*", None),
        ("dev-main", None),
        ("^1.2@dev", "1.2"),
        ("2.0.x", "2.0.0"),
    ],
)
def test_minimum_version_from_composer(constraint, expected):
    assert minimum_version_from_composer(constraint) == expected


def dep(name, ecosystem, constraint):
    return Dependency(
        name=name,
        ecosystem=ecosystem,
        constraint=constraint,
        version=None,
        version_source="unknown",
        source_file="x",
    )


def test_resolve_prefers_lock_version():
    resolved = resolve_dependency(dep("Requests", PYPI, "==2.0.0"), {(PYPI, "requests"): "2.5.0"})
    assert resolved.version == "2.5.0"
    assert resolved.version_source == "lock"


def test_resolve_uses_exact_pin_when_no_lock():
    resolved = resolve_dependency(dep("requests", PYPI, "==2.0.0"), {})
    assert resolved.version == "2.0.0"
    assert resolved.version_source == "pinned"


def test_resolve_falls_back_to_constraint_minimum():
    resolved = resolve_dependency(dep("requests", PYPI, ">=2.0,<3"), {})
    assert resolved.version == "2.0"
    assert resolved.version_source == "constraint"


def test_resolve_unknown_when_no_lower_bound():
    resolved = resolve_dependency(dep("requests", PYPI, ""), {})
    assert resolved.version is None
    assert resolved.version_source == "unknown"


def test_resolve_composer_exact_and_caret():
    exact = resolve_dependency(dep("monolog/monolog", PACKAGIST, "2.0.0"), {})
    assert (exact.version, exact.version_source) == ("2.0.0", "pinned")
    caret = resolve_dependency(dep("monolog/monolog", PACKAGIST, "^2.0"), {})
    assert (caret.version, caret.version_source) == ("2.0", "constraint")


def test_resolve_lock_version_is_normalised():
    resolved = resolve_dependency(
        dep("Monolog/Monolog", PACKAGIST, "^2.0"), {(PACKAGIST, "monolog/monolog"): "v2.3.4"}
    )
    assert resolved.version == "2.3.4"


def test_resolve_keeps_other_fields():
    original = Dependency("a", PYPI, "==1.0", None, "unknown", "req.txt", dev=True)
    resolved = resolve_dependency(original, {})
    assert resolved.name == "a"
    assert resolved.source_file == "req.txt"
    assert resolved.dev is True
    assert resolved.constraint == "==1.0"


from vulnscan.models import WORDPRESS  # noqa: E402
from vulnscan.parsers.versions import compare_versions, version_in_range  # noqa: E402


@pytest.mark.parametrize(
    "a,b,expected",
    [
        ("1.0", "1.0.1", -1),
        ("1.0.1", "1.1", -1),
        ("1.0", "1.0.0", 0),
        ("3.13.4", "3.13.10", -1),
        ("3.13.10", "3.13.4", 1),
        ("1.0-RC1", "1.0", -1),
        ("1.0-beta", "1.0-RC1", -1),
        ("2.0.0", "2.0.0", 0),
        ("6.5.2", "6.5", 1),
        ("1.0-RC12.20251103", "1.0", -1),
        ("1.3-alpha.20241204", "1.3", -1),
        ("10.5.62", "9.6.33", 1),
        ("v2.3.4", "2.3.4", 0),
    ],
)
def test_compare_versions(a, b, expected):
    assert compare_versions(a, b) == expected


@pytest.mark.parametrize(
    "version,frm,frm_inc,to,to_inc,expected",
    [
        ("3.13.4", "*", True, "3.13.4", True, True),
        ("3.13.4", "*", True, "3.13.4", False, False),
        ("3.13.5", "*", True, "3.13.4", True, False),
        ("2.9", "3.0.0", True, "3.5", True, False),
        ("3.0.0", "3.0.0", True, "3.5", True, True),
        ("3.0.0", "3.0.0", False, "3.5", True, False),
        ("1.0", "*", True, "*", True, True),
        ("4.1", "4.0", True, "*", True, True),
    ],
)
def test_version_in_range(version, frm, frm_inc, to, to_inc, expected):
    assert version_in_range(version, frm, frm_inc, to, to_inc) is expected


def test_resolve_wordpress_dependency_uses_composer_lock_entry():
    wp = Dependency(
        "wp-plugin/elementor",
        WORDPRESS,
        "^3.13",
        None,
        "unknown",
        "composer.json",
        kind="plugin",
        slug="elementor",
    )
    resolved = resolve_dependency(wp, {(PACKAGIST, "wp-plugin/elementor"): "3.13.4"})
    assert resolved.version == "3.13.4"
    assert resolved.version_source == "lock"
    assert resolved.kind == "plugin"
    assert resolved.slug == "elementor"


def test_resolve_wordpress_dependency_uses_composer_style_constraints():
    pinned = Dependency(
        "wp-plugin/elementor",
        WORDPRESS,
        "3.13.4",
        None,
        "unknown",
        "composer.json",
        kind="plugin",
        slug="elementor",
    )
    assert (
        resolve_dependency(pinned, {}).version,
        resolve_dependency(pinned, {}).version_source,
    ) == ("3.13.4", "pinned")
    caret = Dependency(
        "wp-theme/astra",
        WORDPRESS,
        "^4.1",
        None,
        "unknown",
        "composer.json",
        kind="theme",
        slug="astra",
    )
    assert (
        resolve_dependency(caret, {}).version,
        resolve_dependency(caret, {}).version_source,
    ) == ("4.1", "constraint")
