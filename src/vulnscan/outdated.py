"""Find dependencies with newer releases available, regardless of security advisories.

This powers the ``--outdated`` TUI mode. Unlike :mod:`vulnscan.remediate`, nothing here
looks at advisories: a package is simply *outdated* when a newer stable release exists.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from packaging.version import InvalidVersion, Version

from vulnscan.models import PYPI, Dependency
from vulnscan.registry import RegistryError
from vulnscan.versioncmp import compare_versions, normalize_version, sort_versions

VersionsFn = Callable[[Dependency], list[str]]

_NUMBERS = re.compile(r"\d+")


@dataclass(frozen=True)
class UpgradeOptions:
    """The two upgrade targets offered for one dependency in outdated mode.

    ``current`` is the version in use (``None`` if unknown). ``series`` is the current
    release series (``major.minor``, e.g. ``2.6`` for ``2.6.1``). ``series_latest`` is the
    newest release above ``current`` that stays within that series, or ``None`` when there
    is none. ``latest`` is the newest release above ``current``, or ``None`` when the
    package is up to date.
    """

    current: str | None
    series: str | None
    series_latest: str | None
    latest: str | None

    @property
    def is_outdated(self) -> bool:
        """Whether a newer release than the known current version exists."""
        return self.current is not None and self.latest is not None


@dataclass(frozen=True)
class OutdatedPackage:
    """A dependency together with its upgrade options."""

    dependency: Dependency
    options: UpgradeOptions


def release_series(version: str, ecosystem: str | None = None) -> str | None:
    """The ``major.minor`` series of ``version`` (``2.6`` for ``2.6.1``), or None if unparseable.

    A version with a single numeric component (``5``) is its own series. PyPI versions
    use PEP 440 parsing when they are valid, so epochs and post-releases are handled;
    everything else takes the first two runs of digits.
    """
    text = normalize_version(version)
    if ecosystem == PYPI:
        try:
            parts = [str(p) for p in Version(text).release[:2]]
        except InvalidVersion:
            parts = _NUMBERS.findall(text)[:2]
    else:
        parts = _NUMBERS.findall(text)[:2]
    return ".".join(parts) if parts else None


def plan_upgrade(dep: Dependency, versions: list[str]) -> UpgradeOptions:
    """Work out the newest same-series release and the newest release above ``dep.version``.

    With an unknown current version nothing can be said, so both targets are ``None``.
    """
    current = dep.version
    if current is None:
        return UpgradeOptions(None, None, None, None)
    series = release_series(current, dep.ecosystem)
    ordered = sort_versions(list(dict.fromkeys(versions)), dep.ecosystem)
    newer = [v for v in ordered if compare_versions(v, current, dep.ecosystem) > 0]
    in_series = [v for v in newer if release_series(v, dep.ecosystem) == series]
    return UpgradeOptions(
        current=current,
        series=series,
        series_latest=in_series[-1] if in_series else None,
        latest=newer[-1] if newer else None,
    )


def find_outdated(
    deps: list[Dependency], versions_fn: VersionsFn, workers: int = 8
) -> tuple[list[OutdatedPackage], list[str]]:
    """Look up every dependency's versions and return those with a newer release, plus warnings.

    Lookups run on up to ``workers`` threads. A dependency whose version is unknown, or
    whose registry lookup fails, is left out and explained in the warnings. The result is
    sorted by package name.
    """
    warnings: list[str] = []
    known = []
    for dep in deps:
        if dep.version is None:
            warnings.append(f"{dep.name}: version unknown, cannot tell whether it is outdated")
        else:
            known.append(dep)
    if not known:
        return [], warnings

    def lookup(dep: Dependency) -> UpgradeOptions | RegistryError:
        try:
            return plan_upgrade(dep, versions_fn(dep))
        except RegistryError as exc:
            return exc

    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(known)))) as pool:
        outcomes = list(pool.map(lookup, known))

    outdated = []
    for dep, outcome in zip(known, outcomes, strict=True):
        if isinstance(outcome, RegistryError):
            warnings.append(f"{dep.name}: could not look up versions: {outcome}")
        elif outcome.is_outdated:
            outdated.append(OutdatedPackage(dep, outcome))
    outdated.sort(key=lambda o: (o.dependency.name.lower(), o.dependency.ecosystem))
    return outdated, warnings
