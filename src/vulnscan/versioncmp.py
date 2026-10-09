"""Ecosystem-aware version comparison with no other vulnscan imports.

PyPI versions follow PEP 440 and are compared with `packaging` when possible. Everything else
(Composer, WordPress, npm) uses a loose, PHP `version_compare`-style tokenisation that also
serves as the fallback for strings `packaging` rejects. For npm, semver build metadata
(``+build.5``) is ignored and any hyphenated suffix counts as a pre-release.
"""

from __future__ import annotations

import re
from functools import cmp_to_key

from packaging.version import InvalidVersion, Version

PYPI_ECOSYSTEM = "PyPI"
NPM_ECOSYSTEM = "npm"

_PRERELEASE_RANK = {
    "dev": 0,
    "alpha": 1,
    "a": 1,
    "beta": 2,
    "b": 2,
    "rc": 3,
    "c": 3,
    "pre": 3,
    "pl": 5,
    "p": 5,
}
_PRERELEASE_WORDS = re.compile(
    r"(?:^|[.\-_+])(dev|alpha|beta|rc|pre|snapshot|a|b)\d*(?:$|[.\-_+])", re.I
)


def normalize_version(version: str) -> str:
    """Strip surrounding whitespace and a leading ``v``/``V`` that precedes a digit."""
    text = version.strip()
    if text[:1] in ("v", "V") and text[1:2].isdigit():
        text = text[1:]
    return text


def _version_tokens(version: str) -> list[tuple[int, int | str]]:
    tokens: list[tuple[int, int | str]] = []
    for part in re.findall(r"\d+|[a-z]+", normalize_version(version).lower()):
        if part.isdigit():
            tokens.append((1, int(part)))
        else:
            tokens.append((0, _PRERELEASE_RANK.get(part, 4)))
    return tokens


def _loose_compare(a: str, b: str) -> int:
    left, right = _version_tokens(a), _version_tokens(b)
    width = max(len(left), len(right))
    left += [(1, 0)] * (width - len(left))
    right += [(1, 0)] * (width - len(right))
    return (left > right) - (left < right)


def _pep440(version: str) -> Version | None:
    try:
        return Version(normalize_version(version))
    except InvalidVersion:
        return None


def _strip_build_metadata(version: str) -> str:
    return version.split("+", 1)[0]


def compare_versions(a: str, b: str, ecosystem: str | None = None) -> int:
    """Return -1, 0 or 1 comparing a to b."""
    if ecosystem == NPM_ECOSYSTEM:
        return _loose_compare(_strip_build_metadata(a), _strip_build_metadata(b))
    if ecosystem == PYPI_ECOSYSTEM:
        left, right = _pep440(a), _pep440(b)
        if left is not None and right is not None:
            return (left > right) - (left < right)
    return _loose_compare(a, b)


def sort_versions(versions: list[str], ecosystem: str | None = None) -> list[str]:
    """Sort versions ascending using :func:`compare_versions` for the ecosystem."""
    return sorted(versions, key=cmp_to_key(lambda x, y: compare_versions(x, y, ecosystem)))


def is_prerelease(version: str, ecosystem: str | None = None) -> bool:
    """Whether a version is a pre-release or development build.

    ``dev-`` prefixes and ``-dev`` suffixes always count. PyPI versions use PEP 440
    when they parse; otherwise the string is searched for markers such as ``alpha``,
    ``beta``, ``rc`` or ``snapshot``.
    """
    text = normalize_version(version)
    if text.startswith("dev-") or text.endswith("-dev"):
        return True
    if ecosystem == NPM_ECOSYSTEM:
        return "-" in _strip_build_metadata(text)
    if ecosystem == PYPI_ECOSYSTEM:
        parsed = _pep440(text)
        if parsed is not None:
            return parsed.is_prerelease or parsed.is_devrelease
    return bool(_PRERELEASE_WORDS.search(text))


def version_in_range(
    version: str,
    from_version: str,
    from_inclusive: bool,
    to_version: str,
    to_inclusive: bool,
    ecosystem: str | None = None,
) -> bool:
    """Whether ``version`` lies between the bounds; an empty or ``*`` bound is open."""
    if from_version and from_version != "*":
        cmp = compare_versions(version, from_version, ecosystem)
        if cmp < 0 or (cmp == 0 and not from_inclusive):
            return False
    if to_version and to_version != "*":
        cmp = compare_versions(version, to_version, ecosystem)
        if cmp > 0 or (cmp == 0 and not to_inclusive):
            return False
    return True
