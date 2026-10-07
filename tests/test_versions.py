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
