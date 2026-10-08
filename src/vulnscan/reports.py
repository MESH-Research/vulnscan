"""Markdown and plain-text reports of scan results."""

from __future__ import annotations

from pathlib import Path

from vulnscan.config import Settings
from vulnscan.models import Finding, ScanResult, Vulnerability
from vulnscan.wordfence import SOURCE as WORDFENCE_SOURCE
from vulnscan.wordfence import wordfence_attribution


def _uses_wordfence(result: ScanResult) -> bool:
    return any(v.source == WORDFENCE_SOURCE for f in result.findings for v in f.vulnerabilities)


def _header_line(result: ScanResult) -> str:
    return (
        f"Scanned {len(result.dependencies)} dependencies; "
        f"{len(result.findings)} have known advisories. "
        f"Generated {result.scanned_at:%Y-%m-%d %H:%M} UTC from {result.project_path}."
    )


def _vuln_facts(vuln: Vulnerability) -> list[tuple[str, str]]:
    facts = [
        ("Severity", vuln.severity + (f" ({vuln.cvss})" if vuln.cvss else "")),
        ("CVE", ", ".join(vuln.cve_ids) or "none assigned"),
        ("Aliases", ", ".join(vuln.aliases) or "none"),
        ("Fixed in", ", ".join(vuln.fixed_versions) or "no fix listed"),
    ]
    if vuln.published:
        facts.append(("Published", f"{vuln.published:%Y-%m-%d}"))
    if vuln.modified:
        facts.append(("Updated", f"{vuln.modified:%Y-%m-%d}"))
    return facts


def _dep_facts(finding: Finding) -> list[tuple[str, str]]:
    dep = finding.dependency
    return [
        ("Ecosystem", dep.ecosystem + (f" {dep.kind}" if dep.kind else "")),
        ("Version", f"{dep.version or 'unknown'} (from {dep.version_source})"),
        ("Declared in", dep.declared_in_text),
        ("Fixed in", ", ".join(finding.fixed_versions) or "no fix listed"),
    ]


def render_markdown(result: ScanResult) -> str:
    """Render a Markdown report: summary table, per-advisory details, warnings, attribution.

    The attribution section appears only when a Wordfence advisory is present.
    """
    lines = [f"# Vulnerability report: {result.project_path.name or result.project_path}", ""]
    lines += [_header_line(result), ""]
    if not result.findings:
        lines += ["No known vulnerabilities in direct dependencies.", ""]
    else:
        lines += [
            "## Summary",
            "",
            "| Package | Ecosystem | Version | Severity | Advisories | Fixed in | Declared in |",
            "|---|---|---|---|---|---|---|",
        ]
        for finding in result.findings:
            dep = finding.dependency
            ids = ", ".join(v.id for v in finding.vulnerabilities)
            lines.append(
                f"| {dep.name} | {dep.ecosystem} | {dep.version or '?'} | {finding.worst_severity} "
                f"| {ids} | {', '.join(finding.fixed_versions) or '-'} "
                f"| {', '.join(dep.source_files)} |"
            )
        lines += ["", "## Details", ""]
        for finding in result.findings:
            dep = finding.dependency
            lines += [f"### {dep.name} {dep.version or ''}".rstrip(), ""]
            lines += [f"- **{k}:** {v}" for k, v in _dep_facts(finding)]
            lines.append("")
            for vuln in finding.vulnerabilities:
                title = f"#### {vuln.id}" + (f": {vuln.summary}" if vuln.summary else "")
                lines += [title, ""]
                lines += [f"- **{k}:** {v}" for k, v in _vuln_facts(vuln)]
                lines += [f"- **Link:** <{vuln.url}>", ""]
                if vuln.details:
                    lines += [vuln.details.strip(), ""]
                if vuln.references:
                    lines += ["References:", ""]
                    lines += [f"- <{url}>" for url in vuln.references]
                    lines.append("")
    if result.warnings:
        lines += ["## Warnings", ""]
        lines += [f"- {w}" for w in result.warnings]
        lines.append("")
    if _uses_wordfence(result):
        lines += ["## Attribution", "", wordfence_attribution(), ""]
    return "\n".join(lines).rstrip() + "\n"


def render_text(result: ScanResult) -> str:
    """Render the same report as :func:`render_markdown` in plain text."""
    title = f"Vulnerability report: {result.project_path.name or result.project_path}"
    lines = [title, "=" * len(title), "", _header_line(result), ""]
    if not result.findings:
        lines += ["No known vulnerabilities in direct dependencies.", ""]
    for finding in result.findings:
        dep = finding.dependency
        heading = f"{dep.name} {dep.version or ''}".rstrip() + f"  [{finding.worst_severity}]"
        lines += [heading, "-" * len(heading)]
        lines += [f"  {k}: {v}" for k, v in _dep_facts(finding)]
        lines.append("")
        for vuln in finding.vulnerabilities:
            lines.append(f"  * {vuln.id}" + (f": {vuln.summary}" if vuln.summary else ""))
            lines += [f"      {k}: {v}" for k, v in _vuln_facts(vuln)]
            lines.append(f"      Link: {vuln.url}")
            if vuln.details:
                lines += ["", *("      " + line for line in vuln.details.strip().splitlines())]
            if vuln.references:
                lines += ["", "      References:"]
                lines += [f"        {url}" for url in vuln.references]
            lines.append("")
    if result.warnings:
        lines += ["Warnings", "--------"]
        lines += [f"  - {w}" for w in result.warnings]
        lines.append("")
    if _uses_wordfence(result):
        lines += ["Attribution", "-----------", wordfence_attribution(), ""]
    return "\n".join(lines).rstrip() + "\n"


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def write_reports(
    result: ScanResult,
    settings: Settings,
    markdown_path: Path | None = None,
    text_path: Path | None = None,
) -> tuple[Path | None, Path | None]:
    """Write reports. With no explicit paths, both go into the feed directory."""
    if markdown_path is None and text_path is None:
        markdown_path, text_path = settings.markdown_path, settings.text_path
    if markdown_path is not None:
        _write(markdown_path, render_markdown(result))
    if text_path is not None:
        _write(text_path, render_text(result))
    return markdown_path, text_path
