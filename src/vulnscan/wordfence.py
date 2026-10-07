"""Client for the Wordfence Intelligence vulnerability feed (WordPress core, plugins, themes).

The v3 production feed is a single JSON document covering every known WordPress
vulnerability. It needs a (free) API key and is large, so it is cached on disk.
"""

from __future__ import annotations

import json
import os
import time
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path

import httpx

from vulnscan import __version__
from vulnscan.models import WORDPRESS, Dependency, VersionRange, Vulnerability, normalize_severity
from vulnscan.parsers.versions import version_in_range

FEED_PATH = "/vulnerabilities/production"
VULNERABILITY_URL = "https://www.wordfence.com/threat-intel/vulnerabilities/id/{id}"
SOURCE = "wordfence"

# Wordfence Intelligence Community Edition terms: copies of a record must link to it and
# reproduce Defiant's copyright designation and license.
WORDFENCE_COPYRIGHT = "Copyright 2012-2026 Defiant Inc."
WORDFENCE_LICENSE_URL = "https://www.wordfence.com/wordfence-intelligence-terms-and-conditions/"
WORDFENCE_LICENSE = (
    "Defiant hereby grants you a perpetual, worldwide, non-exclusive, no-charge, royalty-free, "
    "irrevocable copyright license to reproduce, prepare derivative works of, publicly display, "
    "publicly perform, sublicense, and distribute this software vulnerability information. Any "
    "copy of the software vulnerability information you make for such purposes is authorized "
    "provided that you include a hyperlink to this vulnerability record and reproduce Defiant's "
    "copyright designation and this license in any such copy."
)

# Record fields that are not needed for matching or display; dropped from the on-disk cache.
_SLIM_DROP = ("copyrights", "researchers")


def wordfence_attribution() -> str:
    return (
        f"WordPress vulnerability data provided by Wordfence Intelligence. {WORDFENCE_COPYRIGHT} "
        f"{WORDFENCE_LICENSE} License: {WORDFENCE_LICENSE_URL}"
    )


def slim_feed(feed: dict) -> dict:
    """Drop bulky per-record boilerplate; keep the notice once under a `_meta` key."""
    slim: dict = {}
    notice = None
    for key, record in feed.items():
        if not isinstance(record, dict):
            continue
        if notice is None and isinstance(record.get("copyrights"), dict):
            notice = record["copyrights"]
        slim[key] = {k: v for k, v in record.items() if k not in _SLIM_DROP}
    slim["_meta"] = {"source": "Wordfence Intelligence", "copyrights": notice}
    return slim


class WordfenceError(Exception):
    """Raised when the Wordfence feed cannot be obtained."""


def _parse_datetime(text: object) -> datetime | None:
    if not isinstance(text, str) or not text:
        return None
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def parse_wordfence_record(record: dict, software: dict) -> Vulnerability:
    """Convert one feed record, scoped to one of its software entries, into our model."""
    wordfence_id = str(record.get("id") or "")
    cve = record.get("cve") if isinstance(record.get("cve"), str) else None
    cvss = record.get("cvss") if isinstance(record.get("cvss"), dict) else {}

    details_parts = [str(record.get("description") or "").strip()]
    remediation = str(software.get("remediation") or "").strip()
    if remediation:
        details_parts.append(f"Remediation: {remediation}")
    if not software.get("patched", True):
        details_parts.append("No patched version is available.")

    references: list[str] = []
    for url in [record.get("cve_link"), *(record.get("references") or [])]:
        if isinstance(url, str) and url and url not in references:
            references.append(url)

    fixed = [str(v) for v in software.get("patched_versions") or [] if v]
    ranges: list[VersionRange] = []
    affected = software.get("affected_versions") or {}
    for rng in affected.values() if isinstance(affected, dict) else []:
        if not isinstance(rng, dict):
            continue
        lower = str(rng.get("from_version", "*"))
        upper = str(rng.get("to_version", "*"))
        ranges.append(
            VersionRange(
                lower=None if lower in ("*", "") else lower,
                lower_inclusive=bool(rng.get("from_inclusive", True)),
                upper=None if upper in ("*", "") else upper,
                upper_inclusive=bool(rng.get("to_inclusive", True)),
            )
        )
    return Vulnerability(
        id=cve or wordfence_id,
        summary=str(record.get("title") or "").strip(),
        details="\n\n".join(p for p in details_parts if p),
        aliases=[wordfence_id] if cve and wordfence_id else [],
        severity=normalize_severity(cvss.get("rating") if cvss else None),
        cvss=str(cvss["vector"]) if cvss and cvss.get("vector") else None,
        published=_parse_datetime(record.get("published")),
        modified=_parse_datetime(record.get("updated")),
        fixed_versions=fixed if software.get("patched", True) else [],
        references=references,
        link=VULNERABILITY_URL.format(id=wordfence_id) if wordfence_id else None,
        source=SOURCE,
        affected_ranges=ranges,
    )


def software_matches(software: dict, kind: str, slug: str, version: str | None) -> bool:
    """Does this software entry cover the given plugin/theme/core slug at this version?"""
    if version is None:
        return False
    if str(software.get("type", "")).lower() != kind.lower():
        return False
    if str(software.get("slug", "")).lower() != slug.lower():
        return False
    ranges = software.get("affected_versions") or {}
    for rng in ranges.values() if isinstance(ranges, dict) else []:
        if not isinstance(rng, dict):
            continue
        if version_in_range(
            version,
            str(rng.get("from_version", "*")),
            bool(rng.get("from_inclusive", True)),
            str(rng.get("to_version", "*")),
            bool(rng.get("to_inclusive", True)),
        ):
            return True
    return False


class WordfenceClient:
    def __init__(
        self,
        api_key: str,
        base_url: str = "https://www.wordfence.com/api/intelligence/v3",
        timeout: float = 120.0,
        cache_path: Path | None = None,
        ttl_hours: float = 24.0,
        min_interval_minutes: float = 30.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.cache_path = cache_path
        self.ttl_hours = ttl_hours
        self.min_interval_minutes = min_interval_minutes
        self._transport = transport
        self.warnings: list[str] = []
        self._index: dict[tuple[str, str], list[tuple[dict, dict]]] | None = None

    # -- feed acquisition --------------------------------------------------------

    def _cache_age_seconds(self) -> float | None:
        if self.cache_path is None or not self.cache_path.is_file():
            return None
        return time.time() - self.cache_path.stat().st_mtime

    def _attempt_marker(self) -> Path | None:
        if self.cache_path is None:
            return None
        return self.cache_path.with_name(self.cache_path.name + ".last-attempt")

    def _seconds_since_last_attempt(self) -> float | None:
        marker = self._attempt_marker()
        if marker is None or not marker.is_file():
            return None
        return time.time() - marker.stat().st_mtime

    def _record_attempt(self) -> None:
        marker = self._attempt_marker()
        if marker is None:
            return
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text(datetime.now(UTC).isoformat(), encoding="utf-8")

    def _read_cache(self) -> dict:
        assert self.cache_path is not None
        data = json.loads(self.cache_path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("cached feed is not a JSON object")
        return data

    def _cached_validators(self) -> dict[str, str]:
        """ETag / Last-Modified saved with the cache, for conditional requests."""
        try:
            meta = self._read_cache().get("_meta") or {}
        except (OSError, ValueError, AssertionError):
            return {}
        headers = {}
        if isinstance(meta.get("etag"), str):
            headers["If-None-Match"] = meta["etag"]
        if isinstance(meta.get("last_modified"), str):
            headers["If-Modified-Since"] = meta["last_modified"]
        return headers

    def _download(self, cached_age: float | None) -> dict:
        """Fetch the feed. Every call to the API is throttled by `min_interval_minutes`."""
        since = self._seconds_since_last_attempt()
        if since is not None and since < self.min_interval_minutes * 60:
            wait = self.min_interval_minutes - since / 60
            raise WordfenceError(
                f"Wordfence feed was last requested {since / 60:.0f} minutes ago; not "
                f"contacting the API again for {max(wait, 1):.0f} more minute(s)"
            )
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "User-Agent": f"vulnscan/{__version__}",
            "Accept": "application/json",
        }
        if cached_age is not None:
            headers.update(self._cached_validators())
        self._record_attempt()
        try:
            with httpx.Client(timeout=self.timeout, transport=self._transport) as http:
                response = http.get(self.base_url + FEED_PATH, headers=headers)
        except httpx.HTTPError as exc:
            raise WordfenceError(f"Wordfence feed download failed: {exc}") from exc
        if response.status_code == 304 and cached_age is not None and self.cache_path:
            os.utime(self.cache_path, None)  # unchanged upstream: cache is fresh again
            return self._read_cache()
        if response.status_code == 429:
            raise WordfenceError("Wordfence rate limit hit (HTTP 429); using cache if available")
        if response.status_code in (401, 403):
            raise WordfenceError(
                f"Wordfence rejected the API key (HTTP {response.status_code}). Check "
                "VULNSCAN_WORDFENCE_API_KEY; keys are issued free at wordfence.com"
            )
        if response.status_code >= 400:
            raise WordfenceError(f"Wordfence returned HTTP {response.status_code}")
        try:
            data = response.json()
        except ValueError as exc:
            raise WordfenceError("Wordfence returned invalid JSON") from exc
        if not isinstance(data, dict):
            raise WordfenceError("Wordfence feed has an unexpected shape")
        data = slim_feed(data)
        data["_meta"]["etag"] = response.headers.get("ETag")
        data["_meta"]["last_modified"] = response.headers.get("Last-Modified")
        data["_meta"]["downloaded_at"] = datetime.now(UTC).isoformat()
        if self.cache_path is not None:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.cache_path.with_name(self.cache_path.name + ".tmp")
            tmp.write_text(json.dumps(data, separators=(",", ":")), encoding="utf-8")
            os.replace(tmp, self.cache_path)
        return data

    def load_feed(self) -> dict:
        """Return the feed, from a fresh cache, a new download, or a stale cache as last resort."""
        age = self._cache_age_seconds()
        if age is not None and age < self.ttl_hours * 3600:
            try:
                return self._read_cache()
            except (OSError, ValueError):
                pass
        try:
            return self._download(age)
        except WordfenceError as exc:
            if age is None:
                raise
            try:
                data = self._read_cache()
            except (OSError, ValueError):
                raise exc from None
            self.warnings.append(
                f"{exc}; using stale cached Wordfence feed from {age / 3600:.0f} hours ago"
            )
            return data

    # -- matching ------------------------------------------------------------------

    def _build_index(self) -> dict[tuple[str, str], list[tuple[dict, dict]]]:
        index: dict[tuple[str, str], list[tuple[dict, dict]]] = {}
        for key, record in self.load_feed().items():
            if str(key).startswith("_") or not isinstance(record, dict):
                continue
            if record.get("informational"):
                continue
            for software in record.get("software") or []:
                if not isinstance(software, dict):
                    continue
                key = (str(software.get("type", "")).lower(), str(software.get("slug", "")).lower())
                index.setdefault(key, []).append((record, software))
        return index

    def find_vulnerabilities(
        self, deps: Iterable[Dependency], include_unknown_versions: bool = False
    ) -> dict[Dependency, list[Vulnerability]]:
        """Match WordPress dependencies against the feed. Unknown versions cannot be matched."""
        candidates = [d for d in deps if d.ecosystem == WORDPRESS and d.version and d.slug]
        if not candidates:
            return {}
        if self._index is None:
            self._index = self._build_index()
        found: dict[Dependency, list[Vulnerability]] = {}
        for dep in candidates:
            vulns: list[Vulnerability] = []
            seen: set[str] = set()
            for record, software in self._index.get((dep.kind.lower(), dep.slug.lower()), []):
                if software_matches(software, dep.kind, dep.slug, dep.version):
                    vuln = parse_wordfence_record(record, software)
                    if vuln.id not in seen:
                        seen.add(vuln.id)
                        vulns.append(vuln)
            if vulns:
                found[dep] = vulns
        return found
