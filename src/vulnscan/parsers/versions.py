"""Resolve exact or minimum versions from dependency constraints."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import replace

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from vulnscan.models import PACKAGIST, Dependency


def normalize_version(version: str) -> str:
    text = version.strip()
    if text[:1] in ("v", "V") and text[1:2].isdigit():
        text = text[1:]
    return text


def _parse_specifiers(specifier: str) -> SpecifierSet | None:
    try:
        return SpecifierSet(specifier.strip())
    except InvalidSpecifier:
        return None


def exact_version_from_pep508(specifier: str) -> str | None:
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
    text = constraint.strip()
    match = _COMPOSER_EXACT.match(text)
    if not match:
        return None
    return match.group(1)


def minimum_version_from_composer(constraint: str) -> str | None:
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


def resolve_dependency(dep: Dependency, lock_versions: Mapping[tuple[str, str], str]) -> Dependency:
    """Fill in an exact version from a lock file, a pin, or the constraint's lower bound."""
    locked = lock_versions.get(dep.key)
    if locked:
        return replace(dep, version=normalize_version(locked), version_source="lock")
    if dep.ecosystem == PACKAGIST:
        exact = exact_version_from_composer(dep.constraint)
        minimum = minimum_version_from_composer(dep.constraint)
    else:
        exact = exact_version_from_pep508(dep.constraint)
        minimum = minimum_version_from_pep508(dep.constraint)
    if exact:
        return replace(dep, version=normalize_version(exact), version_source="pinned")
    if minimum:
        return replace(dep, version=normalize_version(minimum), version_source="constraint")
    return replace(dep, version=None, version_source="unknown")
