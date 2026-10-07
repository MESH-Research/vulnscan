"""Client for the OSV.dev vulnerability API."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import replace
from datetime import datetime

import httpx

from vulnscan import __version__
from vulnscan.models import (
    Dependency,
    Vulnerability,
    normalize_name,
    normalize_severity,
    severity_rank,
    version_sort_key,
)
from vulnscan.parsers.versions import normalize_version

BATCH_SIZE = 1000


class OSVError(Exception):
    """Raised when OSV cannot be queried."""


def _parse_datetime(text: object) -> datetime | None:
    if not isinstance(text, str) or not text:
        return None
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def _dedupe_keep_order(items: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            out.append(item)
    return out


def parse_osv_vulnerability(data: dict, package_name: str, ecosystem: str) -> Vulnerability:
    """Convert an OSV vulnerability record into our model, scoped to one package."""
    wanted = normalize_name(package_name, ecosystem)
    fixed: list[str] = []
    severity_label = (data.get("database_specific") or {}).get("severity")
    for affected in data.get("affected") or []:
        pkg = affected.get("package") or {}
        if str(pkg.get("ecosystem", "")).lower() != ecosystem.lower():
            continue
        if normalize_name(str(pkg.get("name", "")), ecosystem) != wanted:
            continue
        for rng in affected.get("ranges") or []:
            if str(rng.get("type", "")).upper() == "GIT":
                continue  # commit hashes are not installable versions
            for event in rng.get("events") or []:
                if isinstance(event, dict) and event.get("fixed"):
                    fixed.append(normalize_version(str(event["fixed"])))
        if not severity_label:
            severity_label = (affected.get("ecosystem_specific") or {}).get("severity")

    cvss = None
    for entry in data.get("severity") or []:
        if isinstance(entry, dict) and entry.get("score"):
            cvss = str(entry["score"])
            break

    details = str(data.get("details") or "")
    summary = str(data.get("summary") or "").strip()
    if not summary and details:
        summary = next((line.strip() for line in details.splitlines() if line.strip()), "")

    references = [
        str(ref["url"])
        for ref in data.get("references") or []
        if isinstance(ref, dict) and ref.get("url")
    ]

    return Vulnerability(
        id=str(data.get("id", "")),
        summary=summary,
        details=details,
        aliases=[str(a) for a in data.get("aliases") or []],
        severity=normalize_severity(severity_label if isinstance(severity_label, str) else None),
        cvss=cvss,
        published=_parse_datetime(data.get("published")),
        modified=_parse_datetime(data.get("modified")),
        fixed_versions=_dedupe_keep_order(fixed),
        references=_dedupe_keep_order(references),
    )


def _primary_rank(vuln: Vulnerability) -> tuple[int, str]:
    prefix_order = ["GHSA-", "CVE-"]
    for i, prefix in enumerate(prefix_order):
        if vuln.id.upper().startswith(prefix):
            return (i, vuln.id)
    return (len(prefix_order), vuln.id)


def dedupe_vulnerabilities(vulns: list[Vulnerability]) -> list[Vulnerability]:
    """Merge records that describe the same advisory (linked via aliases)."""
    groups: list[list[Vulnerability]] = []
    group_ids: list[set[str]] = []
    for vuln in vulns:
        ids = {vuln.id, *vuln.aliases}
        matching = [i for i, known in enumerate(group_ids) if known & ids]
        if not matching:
            groups.append([vuln])
            group_ids.append(ids)
            continue
        target = matching[0]
        groups[target].append(vuln)
        group_ids[target] |= ids
        # Merge any further groups now connected through this record.
        for extra in sorted(matching[1:], reverse=True):
            groups[target].extend(groups.pop(extra))
            group_ids[target] |= group_ids.pop(extra)

    merged: list[Vulnerability] = []
    for members in groups:
        primary = min(members, key=_primary_rank)
        all_ids = _dedupe_keep_order(i for m in members for i in [m.id, *m.aliases])
        severities = [m.severity for m in members if normalize_severity(m.severity) != "UNKNOWN"]
        published = [m.published for m in members if m.published]
        modified = [m.modified for m in members if m.modified]
        merged.append(
            replace(
                primary,
                summary=primary.summary or next((m.summary for m in members if m.summary), ""),
                details=primary.details or next((m.details for m in members if m.details), ""),
                aliases=[i for i in all_ids if i != primary.id],
                severity=min(severities, key=severity_rank) if severities else "UNKNOWN",
                cvss=primary.cvss or next((m.cvss for m in members if m.cvss), None),
                published=min(published) if published else None,
                modified=max(modified) if modified else None,
                fixed_versions=sorted(
                    {fv for m in members for fv in m.fixed_versions}, key=version_sort_key
                ),
                references=_dedupe_keep_order(r for m in members for r in m.references),
            )
        )
    return merged


class OSVClient:
    def __init__(
        self,
        base_url: str = "https://api.osv.dev",
        timeout: float = 30.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._http = httpx.Client(
            base_url=self.base_url,
            timeout=timeout,
            transport=transport,
            headers={"User-Agent": f"vulnscan/{__version__}"},
        )
        self._raw_cache: dict[str, dict] = {}

    def _request(self, method: str, path: str, payload: dict | None = None) -> dict:
        try:
            response = self._http.request(method, path, json=payload)
        except httpx.HTTPError as exc:
            raise OSVError(f"OSV request failed: {exc}") from exc
        if response.status_code >= 400:
            raise OSVError(f"OSV returned HTTP {response.status_code} for {path}")
        try:
            data = response.json()
        except ValueError as exc:
            raise OSVError(f"OSV returned invalid JSON for {path}") from exc
        return data if isinstance(data, dict) else {}

    @staticmethod
    def _query_for(dep: Dependency) -> dict:
        query: dict = {"package": {"name": dep.name, "ecosystem": dep.ecosystem}}
        if dep.version:
            query["version"] = dep.version
        return query

    def query_batch(self, deps: list[Dependency]) -> list[list[str]]:
        """Return the advisory ids affecting each dependency, aligned with the input."""
        results: list[list[str]] = [[] for _ in deps]
        for start in range(0, len(deps), BATCH_SIZE):
            chunk = deps[start : start + BATCH_SIZE]
            queries = [self._query_for(dep) for dep in chunk]
            data = self._request("POST", "/v1/querybatch", {"queries": queries})
            for offset, result in enumerate(data.get("results") or []):
                if offset >= len(chunk):
                    break
                result = result or {}
                ids = [str(v["id"]) for v in result.get("vulns") or [] if v.get("id")]
                token = result.get("next_page_token")
                while token:
                    page = self._request(
                        "POST", "/v1/query", {**queries[offset], "page_token": token}
                    )
                    ids.extend(str(v["id"]) for v in page.get("vulns") or [] if v.get("id"))
                    token = page.get("next_page_token")
                results[start + offset] = ids
        return results

    def get_vulnerability(self, vuln_id: str, package_name: str, ecosystem: str) -> Vulnerability:
        if vuln_id not in self._raw_cache:
            self._raw_cache[vuln_id] = self._request("GET", f"/v1/vulns/{vuln_id}")
        return parse_osv_vulnerability(self._raw_cache[vuln_id], package_name, ecosystem)

    def find_vulnerabilities(
        self, deps: Iterable[Dependency], include_unknown_versions: bool = False
    ) -> dict[Dependency, list[Vulnerability]]:
        """Map each affected dependency to its (deduplicated) advisories."""
        queryable = [d for d in deps if d.version or include_unknown_versions]
        if not queryable:
            return {}
        found: dict[Dependency, list[Vulnerability]] = {}
        for dep, ids in zip(queryable, self.query_batch(queryable), strict=True):
            if not ids:
                continue
            vulns = [self.get_vulnerability(i, dep.name, dep.ecosystem) for i in ids]
            found[dep] = dedupe_vulnerabilities(vulns)
        return found
