"""Scan orchestration: parse manifests, resolve versions, query OSV, build findings."""

from __future__ import annotations

from datetime import UTC, datetime

from vulnscan.config import Settings
from vulnscan.models import Dependency, Finding, ScanResult, severity_rank
from vulnscan.osv import OSVClient
from vulnscan.parsers import parse_project


def _unique(deps: list[Dependency]) -> list[Dependency]:
    seen: dict[tuple, Dependency] = {}
    for dep in deps:
        seen.setdefault((dep.key, dep.version), dep)
    return list(seen.values())


def scan(settings: Settings, client: OSVClient | None = None) -> ScanResult:
    """Scan the configured project. Raises OSVError if advisories cannot be fetched."""
    if client is None:
        client = OSVClient(base_url=settings.osv_base_url, timeout=settings.request_timeout)
    deps, warnings = parse_project(settings.project_path)
    if not settings.include_dev:
        deps = [d for d in deps if not d.dev]
    deps = _unique(deps)
    found = client.find_vulnerabilities(
        deps, include_unknown_versions=settings.query_unknown_versions
    )
    findings = [Finding(dep, vulns) for dep, vulns in found.items() if vulns]
    findings.sort(key=lambda f: (severity_rank(f.worst_severity), f.dependency.name.lower()))
    return ScanResult(
        project_path=settings.project_path,
        dependencies=deps,
        findings=findings,
        warnings=warnings,
        scanned_at=datetime.now(UTC),
    )
