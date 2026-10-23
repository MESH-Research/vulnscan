"""Scan orchestration: parse manifests, resolve versions, query advisory sources."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime

from vulnscan.config import Settings
from vulnscan.invenio import (
    WebpackMergeIndex,
    build_webpack_merge_index,
    detect_invenio_webpack,
)
from vulnscan.models import (
    CONTAINER,
    NPM,
    WORDPRESS,
    Finding,
    ScanResult,
    merge_declarations,
    severity_rank,
)
from vulnscan.nvd import NVDClient, parse_image_products
from vulnscan.osv import OSVClient
from vulnscan.parsers import load_ignore_file, parse_project
from vulnscan.registry import RegistryClient, RegistryError
from vulnscan.remediate import plan_remediation
from vulnscan.risk import RiskKind, VersionRisk, VersionScore, score_versions
from vulnscan.versioncmp import compare_versions, sort_versions
from vulnscan.wordfence import WordfenceClient

WORDFENCE_CACHE_FILENAME = "wordfence-production.json"


def _plural(count: int, singular: str, plural: str) -> str:
    return f"{count} {singular if count == 1 else plural}"


def _annotate_webpack_merge(
    settings: Settings, findings: list[Finding], warnings: list[str]
) -> WebpackMergeIndex | None:
    """Run one in-memory pywebpack merge pass; attach blocks and warnings."""
    root = settings.project_path
    discovered = [
        p
        for p in root.rglob("webpack.py")
        if ".venv" not in p.parts
        and "site-packages" not in p.parts
        and "node_modules" not in p.parts
    ]
    if not detect_invenio_webpack(root, settings.invenio_webpack, discovered_webpack=discovered):
        return None
    patterns = tuple(settings.ignore_dirs) + load_ignore_file(root)
    index = build_webpack_merge_index(root, ignore_patterns=patterns)
    warnings.extend(index.warning_lines())
    for finding in findings:
        if finding.dependency.ecosystem != NPM:
            continue
        name = finding.dependency.name
        finding.upstream_constraints_text = index.upstream_constraints_text(name)
        limit = index.upgrade_limit_for(name, finding.fixed_versions)
        if limit:
            finding.webpack_merge_block = limit
            finding.upgrade_limit = limit
    return index


def _local_candidate_versions(finding: Finding, versions: list[str]) -> list[str]:
    """Newer versions that clear the finding's current advisories (local range math only)."""
    dep = finding.dependency
    ordered = sort_versions(list(dict.fromkeys(versions)), dep.ecosystem)
    out = []
    for version in ordered:
        if dep.version is not None and compare_versions(version, dep.version, dep.ecosystem) <= 0:
            continue
        if any(v.affects(version, dep.ecosystem) for v in finding.vulnerabilities):
            continue
        out.append(version)
    if ordered:
        latest = ordered[-1]
        if latest not in out:
            out.append(latest)
    return out


def _wordpress_scores(
    finding: Finding,
    versions: list[str],
    wordpress_client: WordfenceClient,
) -> dict[str, VersionScore]:
    """Score WordPress candidate versions via Wordfence (blocking advisories only)."""
    scores: dict[str, VersionScore] = {}
    dep = finding.dependency
    stubs = [replace(dep, version=v) for v in versions]
    if not stubs:
        return scores
    found = wordpress_client.find_vulnerabilities(stubs, include_unknown_versions=False)
    for stub in stubs:
        version = stub.version or ""
        risks: list[VersionRisk] = []
        for vuln in found.get(stub, []):
            risks.append(
                VersionRisk(
                    kind=RiskKind.ADVISORY,
                    detail=vuln.summary or vuln.id,
                    advisory_id=vuln.id,
                    url=vuln.url,
                    severity=vuln.severity,
                    published_at=vuln.published,
                )
            )
        scores[version] = VersionScore(version=version, risks=tuple(risks))
    return scores


def enrich_findings(
    findings: list[Finding],
    *,
    settings: Settings,
    osv: OSVClient,
    registry: RegistryClient | None = None,
    wordpress_client: WordfenceClient | None = None,
    webpack_merge: object | None = None,
) -> list[str]:
    """Attach forward-checked ``upgrade_plan`` to each finding. Returns extra warnings."""
    warnings: list[str] = []
    if not findings:
        return warnings
    if registry is None:
        registry = RegistryClient(timeout=settings.request_timeout)

    def enrich_one(finding: Finding) -> list[str]:
        local_warnings: list[str] = []
        dep = finding.dependency
        try:
            versions = registry.available_versions(dep)
        except RegistryError as exc:
            local_warnings.append(f"{dep.name}: could not list versions for forward-check: {exc}")
            finding.upgrade_plan = plan_remediation(finding, [], webpack_merge=webpack_merge)
            finding.candidate_warnings = tuple(local_warnings)
            return local_warnings

        candidates = _local_candidate_versions(finding, versions)
        scores_by_version: dict[str, VersionScore] = {}
        if dep.ecosystem == WORDPRESS:
            if wordpress_client is not None and candidates:
                scores_by_version = _wordpress_scores(finding, candidates, wordpress_client)
        elif candidates:
            from vulnscan.risk import score_for

            stubs = [replace(dep, version=v) for v in candidates]
            keyed = score_versions(
                stubs,
                osv=osv,
                registry=registry,
                fresh_hours=settings.fresh_hours,
            )
            for stub in stubs:
                version = stub.version or ""
                score = score_for(keyed, stub, version)
                if score is not None:
                    scores_by_version[version] = score

        plan = plan_remediation(
            finding,
            versions,
            webpack_merge=webpack_merge,
            scores=scores_by_version or None,
        )
        finding.upgrade_plan = plan
        finding.candidate_warnings = tuple(plan.warnings)
        return local_warnings

    workers = min(8, max(1, len(findings)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for extra in pool.map(enrich_one, findings):
            warnings.extend(extra)
    return warnings


def scan(
    settings: Settings,
    client: OSVClient | None = None,
    wordpress_client: WordfenceClient | None = None,
    nvd_client: NVDClient | None = None,
    registry: RegistryClient | None = None,
) -> ScanResult:
    """Scan the configured project.

    PyPI, Packagist and npm packages go to OSV, WordPress packages to Wordfence and
    container images to NVD. Raises OSVError, WordfenceError or NVDError if a source
    fails.
    """
    if client is None:
        client = OSVClient(base_url=settings.osv_base_url, timeout=settings.request_timeout)
    deps, warnings = parse_project(
        settings.project_path,
        ignore_dirs=settings.ignore_dirs,
        include_transitive=settings.include_transitive,
    )
    if not settings.include_dev:
        deps = [d for d in deps if not d.dev]
    deps = merge_declarations(deps)

    for dep in deps:
        if dep.custom_source:
            warnings.append(
                f"{dep.name} ({dep.source_file}): installed from a custom source rather than "
                "Packagist or wordpress.org; advisories may be missing or may not apply"
            )

    wordpress_deps = [d for d in deps if d.ecosystem == WORDPRESS]
    image_deps = [d for d in deps if d.ecosystem == CONTAINER]
    other_deps = [d for d in deps if d.ecosystem not in (WORDPRESS, CONTAINER)]

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

    if image_deps:
        if nvd_client is None:
            nvd_client = NVDClient(
                api_key=settings.nvd_api_key,
                base_url=settings.nvd_url,
                timeout=settings.request_timeout,
                cache_dir=settings.cache_dir,
                ttl_hours=settings.nvd_ttl_hours,
                image_products=parse_image_products(settings.image_products),
            )
        found.update(
            nvd_client.find_vulnerabilities(
                image_deps, include_unknown_versions=settings.query_unknown_versions
            )
        )
        warnings.extend(getattr(nvd_client, "warnings", []))

    findings = [Finding(dep, vulns) for dep, vulns in found.items() if vulns]
    findings.sort(key=lambda f: (severity_rank(f.worst_severity), f.dependency.name.lower()))
    webpack_merge = _annotate_webpack_merge(settings, findings, warnings)
    if registry is None:
        registry = RegistryClient(timeout=settings.request_timeout)
    warnings.extend(
        enrich_findings(
            findings,
            settings=settings,
            osv=client,
            registry=registry,
            wordpress_client=wordpress_client,
            webpack_merge=webpack_merge,
        )
    )
    return ScanResult(
        project_path=settings.project_path,
        dependencies=deps,
        findings=findings,
        warnings=warnings,
        scanned_at=datetime.now(UTC),
        webpack_merge=webpack_merge,
    )
