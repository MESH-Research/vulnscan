"""Data models shared across vulnscan."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from packaging.utils import canonicalize_name

PYPI = "PyPI"
PACKAGIST = "Packagist"

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
_SEVERITY_ALIASES = {"MODERATE": "MEDIUM", "IMPORTANT": "HIGH"}


def normalize_name(name: str, ecosystem: str) -> str:
    """Return the canonical package name used for comparisons."""
    if ecosystem == PYPI:
        return canonicalize_name(name)
    return name.strip().lower()


def normalize_severity(label: str | None) -> str:
    upper = (label or "UNKNOWN").strip().upper()
    upper = _SEVERITY_ALIASES.get(upper, upper)
    return upper if upper in SEVERITY_ORDER else "UNKNOWN"


def severity_rank(label: str) -> int:
    """Lower is more severe. Unknown labels sort last."""
    return SEVERITY_ORDER.index(normalize_severity(label))


@dataclass(frozen=True)
class Dependency:
    """A direct dependency declared in a manifest."""

    name: str
    ecosystem: str
    constraint: str
    version: str | None
    version_source: str
    source_file: str
    dev: bool = False

    @property
    def key(self) -> tuple[str, str]:
        return (self.ecosystem, normalize_name(self.name, self.ecosystem))


@dataclass
class Vulnerability:
    """A single advisory as reported by OSV."""

    id: str
    summary: str
    details: str
    aliases: list[str] = field(default_factory=list)
    severity: str = "UNKNOWN"
    cvss: str | None = None
    published: datetime | None = None
    modified: datetime | None = None
    fixed_versions: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)

    @property
    def cve_ids(self) -> list[str]:
        return [i for i in [self.id, *self.aliases] if i.upper().startswith("CVE-")]

    @property
    def url(self) -> str:
        return f"https://osv.dev/vulnerability/{self.id}"


@dataclass
class Finding:
    """A dependency together with the advisories that affect it."""

    dependency: Dependency
    vulnerabilities: list[Vulnerability]

    @property
    def worst_severity(self) -> str:
        if not self.vulnerabilities:
            return "UNKNOWN"
        return min(
            (normalize_severity(v.severity) for v in self.vulnerabilities), key=severity_rank
        )

    @property
    def fixed_versions(self) -> list[str]:
        return sorted(
            {fv for v in self.vulnerabilities for fv in v.fixed_versions}, key=version_sort_key
        )


def version_sort_key(version: str) -> tuple:
    from packaging.version import InvalidVersion, Version

    try:
        return (0, Version(version), version)
    except InvalidVersion:
        return (1, None, version)


@dataclass
class ScanResult:
    project_path: Path
    dependencies: list[Dependency]
    findings: list[Finding]
    warnings: list[str]
    scanned_at: datetime
