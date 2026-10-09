"""Resolve exact or minimum versions from dependency constraints."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import replace

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from vulnscan.models import NPM, PACKAGIST, WORDPRESS, Dependency, normalize_name
from vulnscan.versioncmp import (  # noqa: F401  (re-exported for callers)
    compare_versions,
    normalize_version,
    version_in_range,
)


def _parse_specifiers(specifier: str) -> SpecifierSet | None:
    try:
        return SpecifierSet(specifier.strip())
    except InvalidSpecifier:
        return None


def exact_version_from_pep508(specifier: str) -> str | None:
    """The pinned version when the specifier is a single ``==``/``===`` without a wildcard.

    Anything else, including invalid specifiers, gives ``None``.
    """
    specs = _parse_specifiers(specifier)
    if specs is None or len(specs) != 1:
        return None
    spec = next(iter(specs))
    if spec.operator in ("==", "===") and not spec.version.endswith(".*"):
        return spec.version
    return None


def _pep440_key(version: str) -> Version | None:
    try:
        return Version(version)
    except InvalidVersion:
        return None


def minimum_version_from_pep508(specifier: str) -> str | None:
    """The lowest version a PEP 508 specifier can resolve to, or ``None``.

    Taken from the highest lower bound among ``==``, ``===``, ``>=``, ``>`` and ``~=``
    clauses; a wildcard such as ``1.2.*`` reads as ``1.2.0``. ``None`` when the
    specifier is invalid or has no lower bound.
    """
    specs = _parse_specifiers(specifier)
    if specs is None:
        return None
    candidates: list[str] = []
    for spec in specs:
        if spec.operator in ("==", "===", ">=", ">", "~="):
            version = spec.version
            if version.endswith(".*"):
                version = version[:-2] + ".0"
            candidates.append(version)
    if not candidates:
        return None
    parsed = [(v, _pep440_key(v)) for v in candidates]
    valid = [(v, k) for v, k in parsed if k is not None]
    if valid:
        return max(valid, key=lambda item: item[1])[0]
    return candidates[0]


_COMPOSER_EXACT = re.compile(r"^v?(\d+(?:\.\d+)*(?:[-+.][0-9A-Za-z.-]+)?)$")
_COMPOSER_LOWER = re.compile(r"^(?:\^|~|>=|>)?\s*v?(\d+(?:\.\d+)*)(?P<wild>(?:\.[x*])+)?$")


def exact_version_from_composer(constraint: str) -> str | None:
    """The version when a Composer constraint is a bare, optionally ``v``-prefixed, version."""
    text = constraint.strip()
    match = _COMPOSER_EXACT.match(text)
    if not match:
        return None
    return match.group(1)


def minimum_version_from_composer(constraint: str) -> str | None:
    """The lower bound of a Composer constraint, or ``None``.

    Alternatives (``||``) are tried in order and the first ``^``, ``~``, ``>=``, ``>``
    or bare version wins; ``<``/``!=`` parts are ignored, ``1.2.*`` reads as ``1.2.0``
    and a stability flag (``@dev``) is dropped.
    """
    text = constraint.split("@", 1)[0].strip()
    # Alternatives: take the first branch that yields a lower bound.
    for branch in re.split(r"\|\|?", text):
        parts = [p for p in re.split(r"[\s,]+", branch.strip()) if p]
        for part in parts:
            if part.startswith("<") or part.startswith("!="):
                continue
            match = _COMPOSER_LOWER.match(part)
            if not match:
                continue
            version = match.group(1)
            if match.group("wild"):
                version = version + ".0"
            return version
    return None


_NPM_EXACT = re.compile(r"^=?\s*v?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)(?:\+[0-9A-Za-z.-]+)?$")
_NPM_LOWER = re.compile(
    r"^(?:\^|~>?|>=|>|=)?\s*v?(?P<major>\d+)(?:\.(?P<minor>\d+|[xX*]))?(?:\.(?P<patch>\d+|[xX*]))?"
    r"(?:-(?P<pre>[0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$"
)


def exact_version_from_npm(constraint: str) -> str | None:
    """The version when an npm range is one full version: ``1.2.3``, ``=1.2.3`` or ``v1.2.3``."""
    match = _NPM_EXACT.match(constraint.strip())
    return match.group(1) if match else None


def minimum_version_from_npm(constraint: str) -> str | None:
    """The lower bound of an npm semver range, or ``None``.

    ``||`` alternatives are tried in order; within one, the first ``^``, ``~``, ``>=``,
    ``>``, ``=`` or bare version wins and ``<``/``!`` parts are ignored. A hyphen range
    ``a - b`` reads as ``a``; ``x``/``*`` components read as ``0``. ``*``, ``latest``,
    ``x`` and an empty range have no lower bound.
    """
    text = constraint.strip()
    if not text or text.lower() in ("*", "x", "latest"):
        return None
    for branch in text.split("||"):
        branch = branch.strip()
        if " - " in branch:
            branch = branch.split(" - ", 1)[0].strip()
        for part in branch.split():
            if part.startswith(("<", "!")):
                continue
            match = _NPM_LOWER.match(part)
            if not match:
                continue
            numbers = [match.group("major")]
            for name in ("minor", "patch"):
                value = match.group(name)
                numbers.append(value if value and value.isdigit() else "0")
            version = ".".join(numbers)
            if match.group("pre"):
                version += "-" + match.group("pre")
            return version
    return None


def resolve_dependency(dep: Dependency, lock_versions: Mapping[tuple[str, str], str]) -> Dependency:
    """Fill in an exact version from a lock file, a pin, or the constraint's lower bound."""
    locked = lock_versions.get(dep.key)
    if not locked and dep.ecosystem == WORDPRESS:
        # WordPress packages are recorded in composer.lock under their Composer name.
        locked = lock_versions.get((PACKAGIST, normalize_name(dep.name, PACKAGIST)))
    if locked:
        return replace(dep, version=normalize_version(locked), version_source="lock")
    if dep.ecosystem in (PACKAGIST, WORDPRESS):
        exact = exact_version_from_composer(dep.constraint)
        minimum = minimum_version_from_composer(dep.constraint)
    elif dep.ecosystem == NPM:
        exact = exact_version_from_npm(dep.constraint)
        minimum = minimum_version_from_npm(dep.constraint)
    else:
        exact = exact_version_from_pep508(dep.constraint)
        minimum = minimum_version_from_pep508(dep.constraint)
    if exact:
        return replace(dep, version=normalize_version(exact), version_source="pinned")
    if minimum:
        return replace(dep, version=normalize_version(minimum), version_source="constraint")
    return replace(dep, version=None, version_source="unknown")
