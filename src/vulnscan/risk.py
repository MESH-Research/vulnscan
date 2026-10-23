"""Score exact package versions for advisories, malware, freshness and yank status.

Used by forward-checked remediation planning and by ``--preflight``.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum

from vulnscan.models import (
    Dependency,
    Vulnerability,
    normalize_name,
    normalize_severity,
)
from vulnscan.osv import OSVClient
from vulnscan.registry import RegistryClient, RegistryError, ReleaseInfo


class RiskKind(StrEnum):
    """Kinds of risk attached to one package version."""

    ADVISORY = "advisory"
    MALWARE = "malware"
    FRESH = "fresh"
    YANKED = "yanked"


@dataclass(frozen=True)
class VersionRisk:
    """One risk signal for a concrete package version."""

    kind: RiskKind
    detail: str
    advisory_id: str | None = None
    url: str | None = None
    severity: str | None = None
    published_at: datetime | None = None


@dataclass(frozen=True)
class VersionScore:
    """All risk signals for one package@version."""

    version: str
    risks: tuple[VersionRisk, ...] = ()

    @property
    def has_blocking(self) -> bool:
        """Whether advisory, malware or yanked risks are present (freshness excluded)."""
        blocking = {RiskKind.ADVISORY, RiskKind.MALWARE, RiskKind.YANKED}
        return any(r.kind in blocking for r in self.risks)

    @property
    def is_fresh(self) -> bool:
        """Whether a freshness warning is present."""
        return any(r.kind == RiskKind.FRESH for r in self.risks)

    def blocking(self) -> tuple[VersionRisk, ...]:
        """Risks that disqualify a remediation candidate."""
        blocking = {RiskKind.ADVISORY, RiskKind.MALWARE, RiskKind.YANKED}
        return tuple(r for r in self.risks if r.kind in blocking)


def is_malware_advisory(vuln: Vulnerability, raw: dict | None = None) -> bool:
    """Whether an OSV (or similar) record should be treated as malware / malicious package.

    Args:
        vuln: Parsed vulnerability.
        raw: Optional raw OSV JSON for ``database_specific`` inspection.
    """
    if vuln.id.upper().startswith("MAL-"):
        return True
    blob = f"{vuln.summary}\n{vuln.details}".lower()
    if "malicious package" in blob or "malware" in blob:
        return True
    if raw and isinstance(raw.get("database_specific"), dict):
        specific = raw["database_specific"]
        for key in ("malicious", "is_malware", "malware"):
            if specific.get(key) is True:
                return True
        for key in ("type", "category", "advisory_type"):
            value = str(specific.get(key) or "").lower()
            if value in {"malware", "malicious", "malicious_package"}:
                return True
    return False


def _score_key(dep: Dependency, version: str) -> tuple[str, str, str]:
    return (dep.ecosystem, normalize_name(dep.name, dep.ecosystem), version)


def score_versions(
    deps: Iterable[Dependency],
    *,
    osv: OSVClient,
    registry: RegistryClient,
    fresh_hours: float = 24.0,
    now: datetime | None = None,
) -> dict[tuple[str, str, str], VersionScore]:
    """Score each dependency's exact ``version`` for advisory/malware/fresh/yanked risks.

    Dependencies without a version are skipped. Registry lookup failures omit freshness
    and yank signals for that package (OSV advisories are still queried).

    Args:
        deps: Dependencies with exact versions to score.
        osv: OSV client (injected for tests).
        registry: Registry client for publish times / yank.
        fresh_hours: Versions newer than this many hours get a ``fresh`` risk.
        now: Clock for freshness (defaults to UTC now).

    Returns:
        Map of ``(ecosystem, canonical_name, version)`` to :class:`VersionScore`.
    """
    clock = now or datetime.now(UTC)
    if clock.tzinfo is None:
        clock = clock.replace(tzinfo=UTC)
    fresh_delta = timedelta(hours=fresh_hours)

    queryable = [d for d in deps if d.version]
    if not queryable:
        return {}

    # One stub dependency per unique package@version for OSV batching.
    unique: dict[tuple[str, str, str], Dependency] = {}
    for dep in queryable:
        key = _score_key(dep, dep.version or "")
        if key not in unique:
            unique[key] = replace(dep, version=dep.version)

    stubs = list(unique.values())
    found = osv.find_vulnerabilities(stubs, include_unknown_versions=False)

    release_cache: dict[tuple[str, str], dict[str, ReleaseInfo] | None] = {}

    def releases_for(dep: Dependency) -> dict[str, ReleaseInfo] | None:
        pkg_key = (dep.ecosystem, normalize_name(dep.name, dep.ecosystem))
        if pkg_key not in release_cache:
            try:
                release_cache[pkg_key] = registry.release_info(dep)
            except RegistryError:
                release_cache[pkg_key] = None
        return release_cache[pkg_key]

    scores: dict[tuple[str, str, str], VersionScore] = {}
    for stub in stubs:
        version = stub.version or ""
        key = _score_key(stub, version)
        risks: list[VersionRisk] = []
        for vuln in found.get(stub, []):
            raw = getattr(osv, "_raw_cache", {}).get(vuln.id)
            kind = RiskKind.MALWARE if is_malware_advisory(vuln, raw) else RiskKind.ADVISORY
            risks.append(
                VersionRisk(
                    kind=kind,
                    detail=vuln.summary or vuln.id,
                    advisory_id=vuln.id,
                    url=vuln.url,
                    severity=normalize_severity(vuln.severity),
                    published_at=vuln.published,
                )
            )
        info_map = releases_for(stub)
        if info_map is not None:
            # Match version key flexibly (registry may normalize differently).
            info = info_map.get(version)
            if info is None:
                for cand, meta in info_map.items():
                    if cand == version or cand.lstrip("v") == version.lstrip("v"):
                        info = meta
                        break
            if info is not None:
                if info.yanked:
                    risks.append(
                        VersionRisk(
                            kind=RiskKind.YANKED,
                            detail=f"{stub.name} {version} is yanked/unpublished on the registry",
                        )
                    )
                if info.published_at is not None and clock - info.published_at < fresh_delta:
                    age = clock - info.published_at
                    hours = max(0, int(age.total_seconds() // 3600))
                    risks.append(
                        VersionRisk(
                            kind=RiskKind.FRESH,
                            detail=(
                                f"{stub.name} {version} was published {hours}h ago "
                                f"(within {fresh_hours:g}h)"
                            ),
                            published_at=info.published_at,
                        )
                    )
        scores[key] = VersionScore(version=version, risks=tuple(risks))
    return scores


def score_for(
    scores: dict[tuple[str, str, str], VersionScore],
    dep: Dependency,
    version: str,
) -> VersionScore | None:
    """Look up a score by dependency identity and version."""
    return scores.get(_score_key(replace(dep, version=version), version))
