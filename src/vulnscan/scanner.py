"""Scan orchestration: parse manifests, resolve versions, query advisory sources."""

from __future__ import annotations

from datetime import UTC, datetime

from vulnscan.config import Settings
from vulnscan.models import WORDPRESS, Dependency, Finding, ScanResult, severity_rank
from vulnscan.osv import OSVClient
from vulnscan.parsers import parse_project
from vulnscan.wordfence import WordfenceClient

WORDFENCE_CACHE_FILENAME = "wordfence-production.json"


def _unique(deps: list[Dependency]) -> list[Dependency]:
    seen: dict[tuple, Dependency] = {}
    for dep in deps:
        seen.setdefault((dep.key, dep.version), dep)
    return list(seen.values())


def _plural(count: int, singular: str, plural: str) -> str:
    return f"{count} {singular if count == 1 else plural}"


def scan(
    settings: Settings,
    client: OSVClient | None = None,
    wordpress_client: WordfenceClient | None = None,
) -> ScanResult:
    """Scan the configured project. Raises OSVError / WordfenceError if a source fails."""
    if client is None:
        client = OSVClient(base_url=settings.osv_base_url, timeout=settings.request_timeout)
    deps, warnings = parse_project(settings.project_path, ignore_dirs=settings.ignore_dirs)
    if not settings.include_dev:
        deps = [d for d in deps if not d.dev]
    deps = _unique(deps)

    for dep in deps:
        if dep.custom_source:
            warnings.append(
                f"{dep.name} ({dep.source_file}): installed from a custom source rather than "
                "Packagist or wordpress.org; advisories may be missing or may not apply"
            )

    wordpress_deps = [d for d in deps if d.ecosystem == WORDPRESS]
    other_deps = [d for d in deps if d.ecosystem != WORDPRESS]

    found = client.find_vulnerabilities(
        other_deps, include_unknown_versions=settings.query_unknown_versions
    )

    if wordpress_deps:
        if wordpress_client is None and settings.wordfence_api_key:
            wordpress_client = WordfenceClient(
                api_key=settings.wordfence_api_key,
                base_url=settings.wordfence_url,
                timeout=settings.request_timeout,
                cache_path=settings.cache_dir / WORDFENCE_CACHE_FILENAME,
                ttl_hours=settings.wordfence_ttl_hours,
                min_interval_minutes=settings.wordfence_min_interval_minutes,
            )
        if wordpress_client is None:
            warnings.append(
                f"{_plural(len(wordpress_deps), 'WordPress package', 'WordPress packages')} "
                "(plugins, themes, core) not checked: set VULNSCAN_WORDFENCE_API_KEY to a "
                "Wordfence Intelligence API key (free at wordfence.com)"
            )
        else:
            found.update(
                wordpress_client.find_vulnerabilities(
                    wordpress_deps, include_unknown_versions=settings.query_unknown_versions
                )
            )
            warnings.extend(getattr(wordpress_client, "warnings", []))

    findings = [Finding(dep, vulns) for dep, vulns in found.items() if vulns]
    findings.sort(key=lambda f: (severity_rank(f.worst_severity), f.dependency.name.lower()))
    return ScanResult(
        project_path=settings.project_path,
        dependencies=deps,
        findings=findings,
        warnings=warnings,
        scanned_at=datetime.now(UTC),
    )
