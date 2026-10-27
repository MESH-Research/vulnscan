"""Client for the NVD (National Vulnerability Database) CVE API, used for container images.

A container image tag names a version of one piece of software: ``php:8.2.19`` is
PHP 8.2.19, ``traefik:v2.10`` is Traefik 2.10. NVD records which CVEs apply to a
product version through CPE names, so each image is mapped to a CPE
``vendor:product`` pair (see :data:`IMAGE_PRODUCTS`) and NVD is asked for the CVEs
whose applicability statements match that product at the image's version.

NVD allows 5 requests per 30 seconds without an API key and 50 with one, so each
``(product, version)`` answer is cached on disk and requests are spaced out.
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from pathlib import Path

import httpx

from vulnscan import __version__, debuglog
from vulnscan.models import (
    CONTAINER,
    Dependency,
    VersionRange,
    Vulnerability,
    normalize_severity,
    version_sort_key,
)
from vulnscan.parsers.containers import OS_IMAGES, canonical_image_name
from vulnscan.versioncmp import normalize_version

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_DETAIL_URL = "https://nvd.nist.gov/vuln/detail/{id}"
PAGE_SIZE = 2000
PUBLIC_INTERVAL_SECONDS = 6.0
"""Spacing between requests without an API key (5 requests per rolling 30 seconds)."""
KEYED_INTERVAL_SECONDS = 0.6
"""Spacing between requests with an API key (50 requests per rolling 30 seconds)."""
RATE_LIMIT_WINDOW_SECONDS = 30.0
"""Length of NVD's rolling rate-limit window; a refused request waits this long and retries."""

IMAGE_PRODUCTS: dict[str, str] = {
    # Languages and runtimes
    "php": "php:php",
    "python": "python:python",
    "node": "nodejs:node.js",
    "ruby": "ruby-lang:ruby",
    "golang": "golang:go",
    "openjdk": "oracle:openjdk",
    "eclipse-temurin": "eclipse:temurin",
    "perl": "perl:perl",
    "rust": "rust-lang:rust",
    "erlang": "erlang:erlang\\/otp",
    "elixir": "elixir-lang:elixir",
    "ghcr.io/astral-sh/uv": "astral:uv",
    # Web servers and proxies
    "nginx": "f5:nginx",
    "httpd": "apache:http_server",
    "traefik": "traefik:traefik",
    "caddy": "caddyserver:caddy",
    "haproxy": "haproxy:haproxy",
    "varnish": "varnish-software:varnish_cache",
    "tomcat": "apache:tomcat",
    "envoyproxy/envoy": "envoyproxy:envoy",
    # Databases and caches
    "postgres": "postgresql:postgresql",
    "mysql": "oracle:mysql",
    "mariadb": "mariadb:mariadb",
    "mongo": "mongodb:mongodb",
    "redis": "redis:redis",
    "valkey/valkey": "valkey:valkey",
    "memcached": "memcached:memcached",
    "elasticsearch": "elastic:elasticsearch",
    "docker.elastic.co/elasticsearch/elasticsearch": "elastic:elasticsearch",
    "opensearchproject/opensearch": "amazon:opensearch",
    "solr": "apache:solr",
    "couchdb": "apache:couchdb",
    "neo4j": "neo4j:neo4j",
    "influxdb": "influxdata:influxdb",
    "clickhouse/clickhouse-server": "clickhouse:clickhouse",
    # Messaging and workflow
    "rabbitmq": "vmware:rabbitmq",
    "confluentinc/cp-kafka": "apache:kafka",
    "apache/kafka": "apache:kafka",
    "nats": "nats:nats-server",
    "apache/airflow": "apache:airflow",
    # Applications and platforms
    "wordpress": "wordpress:wordpress",
    "drupal": "drupal:drupal",
    "nextcloud": "nextcloud:nextcloud_server",
    "ghost": "ghost:ghost",
    "gitea/gitea": "gitea:gitea",
    "gitlab/gitlab-ce": "gitlab:gitlab",
    "gitlab/gitlab-ee": "gitlab:gitlab",
    "jenkins/jenkins": "jenkins:jenkins",
    "sonarqube": "sonarsource:sonarqube",
    "matomo": "matomo:matomo",
    "mattermost/mattermost-team-edition": "mattermost:mattermost_server",
    "minio/minio": "minio:minio",
    "quay.io/minio/minio": "minio:minio",
    "grafana/grafana": "grafana:grafana",
    "grafana/loki": "grafana:loki",
    "prom/prometheus": "prometheus:prometheus",
    "quay.io/prometheus/prometheus": "prometheus:prometheus",
    "prom/alertmanager": "prometheus:alertmanager",
    "quay.io/keycloak/keycloak": "keycloak:keycloak",
    "jboss/keycloak": "keycloak:keycloak",
    "hashicorp/vault": "hashicorp:vault",
    "hashicorp/consul": "hashicorp:consul",
    "vault": "hashicorp:vault",
    "consul": "hashicorp:consul",
    "portainer/portainer-ce": "portainer:portainer",
    "registry": "docker:registry",
    "zookeeper": "apache:zookeeper",
    "apache/superset": "apache:superset",
    "metabase/metabase": "metabase:metabase",
    "ollama/ollama": "ollama:ollama",
    "jupyter/base-notebook": "jupyter:jupyterlab",
    "quay.io/jupyter/base-notebook": "jupyter:jupyterlab",
    "mailhog/mailhog": "mailhog:mailhog",
    "adminer": "adminer:adminer",
    "phpmyadmin": "phpmyadmin:phpmyadmin",
    "phpmyadmin/phpmyadmin": "phpmyadmin:phpmyadmin",
    "ghcr.io/invenio/invenio": "cern:invenio",
    "opensearchproject/opensearch-dashboards": "amazon:opensearch_dashboards",
    "kibana": "elastic:kibana",
    "docker.elastic.co/kibana/kibana": "elastic:kibana",
    "logstash": "elastic:logstash",
    "docker.elastic.co/logstash/logstash": "elastic:logstash",
}
"""Built-in map of canonical image name to CPE ``vendor:product``."""


log = logging.getLogger("vulnscan.nvd")


class NVDError(Exception):
    """Raised when NVD cannot be queried."""


# --- image to product mapping --------------------------------------------------------------

_PRODUCT = re.compile(r"^[^\s:]+:[^\s:]+$")


def parse_image_products(entries: Iterable[str]) -> dict[str, str]:
    """Turn ``image=vendor:product`` entries into a mapping.

    Blank entries are skipped; anything without ``=`` or without a ``vendor:product``
    value raises ``ValueError``.
    """
    products: dict[str, str] = {}
    for entry in entries:
        text = entry.strip()
        if not text:
            continue
        image, eq, product = text.partition("=")
        product = product.strip()
        if not eq or not image.strip() or not _PRODUCT.match(product):
            raise ValueError(
                f"VULNSCAN_IMAGE_PRODUCTS entries look like image=vendor:product (got {text!r})"
            )
        products[canonical_image_name(image)] = product
    return products


def product_for_image(name: str, overrides: dict[str, str] | None = None) -> str | None:
    """The CPE ``vendor:product`` for an image name, overrides first, or ``None``."""
    canonical = canonical_image_name(name)
    if overrides and canonical in overrides:
        return overrides[canonical]
    return IMAGE_PRODUCTS.get(canonical)


def query_version(version: str) -> str:
    """Version string sent to NVD: numeric components padded to at least three.

    A floating tag such as ``8.2`` means "8.2 or later in the series"; its lower
    bound ``8.2.0`` is what NVD compares against its version ranges.
    """
    text = normalize_version(version)
    numbers, sep, rest = text.partition("-")
    parts = numbers.split(".")
    if all(p.isdigit() for p in parts):
        while len(parts) < 3:
            parts.append("0")
        numbers = ".".join(parts)
    return numbers + sep + rest


# --- record parsing -----------------------------------------------------------------------------

_METRIC_KEYS = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")


def _parse_datetime(text: object) -> datetime | None:
    if not isinstance(text, str) or not text:
        return None
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def _severity_and_vector(metrics: dict) -> tuple[str | None, str | None]:
    """Newest CVSS version first; within one, the NVD "Primary" entry wins."""
    for key in _METRIC_KEYS:
        entries = [e for e in metrics.get(key) or [] if isinstance(e, dict)]
        if not entries:
            continue
        entries.sort(key=lambda e: 0 if str(e.get("type", "")).lower() == "primary" else 1)
        entry = entries[0]
        data = entry.get("cvssData") if isinstance(entry.get("cvssData"), dict) else {}
        severity = data.get("baseSeverity") or entry.get("baseSeverity")
        vector = data.get("vectorString")
        return (
            str(severity) if severity else None,
            str(vector) if vector else None,
        )
    return None, None


def _cpe_version(criteria: str) -> tuple[str, str] | None:
    """``(vendor:product, version)`` from a CPE 2.3 name; the update field is appended."""
    parts = criteria.split(":")
    if len(parts) < 6 or parts[0] != "cpe" or parts[1] != "2.3":
        return None
    product = f"{parts[3]}:{parts[4]}"
    version = parts[5]
    update = parts[6] if len(parts) > 6 else "*"
    if update not in ("*", "-", ""):
        version = f"{version}-{update}"
    return product, version


def _iter_cpe_matches(configurations: object):
    for config in configurations or []:
        if not isinstance(config, dict):
            continue
        for node in config.get("nodes") or []:
            if not isinstance(node, dict):
                continue
            for entry in node.get("cpeMatch") or []:
                if isinstance(entry, dict):
                    yield entry


def parse_nvd_record(data: dict, product: str) -> Vulnerability:
    """Convert one NVD CVE record into our model, scoped to ``vendor:product``.

    Vulnerable CPE match entries for the product become affected ranges (from the
    ``versionStart``/``versionEnd`` bounds) or explicit affected versions (from a
    concrete version in the CPE name); every ``versionEndExcluding`` is a fixed version.
    """
    ranges: list[VersionRange] = []
    explicit: list[str] = []
    fixed: list[str] = []
    wanted = product.lower()
    for entry in _iter_cpe_matches(data.get("configurations")):
        if not entry.get("vulnerable", True):
            continue
        parsed = _cpe_version(str(entry.get("criteria", "")))
        if parsed is None or parsed[0].lower() != wanted:
            continue
        _, version = parsed
        if version not in ("*", "-", ""):
            explicit.append(normalize_version(version))
            continue
        lower = entry.get("versionStartIncluding") or entry.get("versionStartExcluding")
        upper = entry.get("versionEndExcluding") or entry.get("versionEndIncluding")
        rng = VersionRange(
            lower=normalize_version(str(lower)) if lower else None,
            lower_inclusive=not entry.get("versionStartExcluding"),
            upper=normalize_version(str(upper)) if upper else None,
            upper_inclusive=bool(entry.get("versionEndIncluding"))
            and not entry.get("versionEndExcluding"),
        )
        ranges.append(rng)
        if entry.get("versionEndExcluding"):
            fixed.append(normalize_version(str(entry["versionEndExcluding"])))

    descriptions = [
        str(d.get("value", ""))
        for d in data.get("descriptions") or []
        if isinstance(d, dict) and d.get("lang", "en") == "en"
    ]
    details = descriptions[0].strip() if descriptions else ""
    summary = next((line.strip() for line in details.splitlines() if line.strip()), "")
    severity, vector = _severity_and_vector(
        data.get("metrics") if isinstance(data.get("metrics"), dict) else {}
    )
    references: list[str] = []
    for ref in data.get("references") or []:
        if isinstance(ref, dict) and ref.get("url") and str(ref["url"]) not in references:
            references.append(str(ref["url"]))
    vuln_id = str(data.get("id", ""))
    return Vulnerability(
        id=vuln_id,
        summary=summary,
        details=details,
        aliases=[],
        severity=normalize_severity(severity),
        cvss=vector,
        published=_parse_datetime(data.get("published")),
        modified=_parse_datetime(data.get("lastModified")),
        fixed_versions=sorted(set(fixed), key=version_sort_key),
        references=references,
        link=NVD_DETAIL_URL.format(id=vuln_id),
        source="nvd",
        affected_ranges=ranges,
        affected_versions=list(dict.fromkeys(explicit)),
    )


def slim_record(data: dict) -> dict:
    """Only the fields :func:`parse_nvd_record` reads, for a compact cache."""
    return {
        "id": data.get("id"),
        "published": data.get("published"),
        "lastModified": data.get("lastModified"),
        "vulnStatus": data.get("vulnStatus"),
        "descriptions": [
            d
            for d in data.get("descriptions") or []
            if isinstance(d, dict) and d.get("lang") == "en"
        ],
        "metrics": data.get("metrics") or {},
        "configurations": data.get("configurations") or [],
        "references": [
            {"url": r.get("url")} for r in data.get("references") or [] if isinstance(r, dict)
        ],
    }


# --- client -----------------------------------------------------------------------------------


class NVDClient:
    """Query NVD for the CVEs affecting container images, with an on-disk cache.

    ``image_products`` extends :data:`IMAGE_PRODUCTS`. ``transport`` and ``sleep`` are
    for tests. Warnings about images that cannot be checked accumulate in ``warnings``.

    A failed lookup never raises out of :meth:`find_vulnerabilities`: the first failure
    is recorded in ``errors``, the client stops going to the network for the rest of
    the run (cached answers are still served) and every image it could not check is
    listed in ``unchecked``. :meth:`error_lines` summarises both for the user. Requests
    are serialised with a lock so concurrent callers share one rate limit.
    """

    def __init__(
        self,
        api_key: str = "",
        base_url: str = NVD_API_URL,
        timeout: float = 30.0,
        cache_dir: Path | None = None,
        ttl_hours: float = 24.0,
        image_products: dict[str, str] | None = None,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] | None = None,
    ) -> None:
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.cache_dir = Path(cache_dir) / "nvd" if cache_dir is not None else None
        self.ttl_hours = ttl_hours
        self.image_products = dict(image_products or {})
        self.warnings: list[str] = []
        self._transport = transport
        self._sleep = sleep or time.sleep
        self._last_request: float | None = None
        self._memory: dict[tuple[str, str], list[dict]] = {}
        self.errors: list[str] = []
        self.unchecked: list[str] = []
        self._unavailable: str | None = None
        self._lock = threading.Lock()

    def error_lines(self) -> list[str]:
        """Prominent one-line summaries of why lookups failed and which images were skipped."""
        if not self.errors:
            return []
        skipped = ", ".join(self.unchecked) or "none"
        return [f"NVD unavailable: {self.errors[0]}. Container images not checked: {skipped}"]

    # -- cache ---------------------------------------------------------------------

    def _cache_path(self, product: str, version: str) -> Path | None:
        if self.cache_dir is None:
            return None
        safe = re.sub(r"[^A-Za-z0-9._-]+", "_", f"{product}__{version}")
        return self.cache_dir / f"{safe}.json"

    @staticmethod
    def _cache_age(path: Path | None) -> float | None:
        if path is None or not path.is_file():
            return None
        return time.time() - path.stat().st_mtime

    @staticmethod
    def _read_cache(path: Path) -> list[dict]:
        data = json.loads(path.read_text(encoding="utf-8"))
        records = data.get("records") if isinstance(data, dict) else None
        if not isinstance(records, list):
            raise ValueError("cached NVD answer has an unexpected shape")
        return [r for r in records if isinstance(r, dict)]

    def _write_cache(self, path: Path, records: list[dict]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"fetched_at": datetime.now(UTC).isoformat(), "records": records}
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(json.dumps(payload, separators=(",", ":")), encoding="utf-8")
        os.replace(tmp, path)

    # -- HTTP ----------------------------------------------------------------------

    def _throttle(self) -> None:
        interval = KEYED_INTERVAL_SECONDS if self.api_key else PUBLIC_INTERVAL_SECONDS
        if self._last_request is not None:
            elapsed = time.monotonic() - self._last_request
            if elapsed < interval:
                log.info("NVD: waiting %.1f s to respect the rate limit", interval - elapsed)
                self._sleep(interval - elapsed)
        self._last_request = time.monotonic()

    def _request(self, params: dict[str, str], headers: dict[str, str]) -> httpx.Response:
        self._throttle()
        try:
            with debuglog.Client(timeout=self.timeout, transport=self._transport) as http:
                return http.get(self.base_url, params=params, headers=headers)
        except httpx.HTTPError as exc:
            raise NVDError(f"NVD request failed: {exc}") from exc

    def _get_page(self, match: str, start: int) -> dict:
        headers = {"User-Agent": f"vulnscan/{__version__}", "Accept": "application/json"}
        if self.api_key:
            headers["apiKey"] = self.api_key
        params = {
            "virtualMatchString": match,
            "resultsPerPage": str(PAGE_SIZE),
            "startIndex": str(start),
        }
        response = self._request(params, headers)
        if response.status_code in (403, 429):
            # NVD answers 403 or 429 when the rolling window is exhausted; one full
            # window later the limit has reset, so wait it out and try once more.
            log.warning(
                "NVD refused the request (HTTP %d); waiting %.0f s for the rate-limit "
                "window to reset before retrying once",
                response.status_code,
                RATE_LIMIT_WINDOW_SECONDS,
            )
            self._sleep(RATE_LIMIT_WINDOW_SECONDS)
            response = self._request(params, headers)
        if response.status_code in (403, 429):
            raise NVDError(
                f"NVD refused the request (HTTP {response.status_code}): the public rate "
                "limit is 5 requests per 30 seconds. Set VULNSCAN_NVD_API_KEY to a free key "
                "from nvd.nist.gov/developers/request-an-api-key for a higher limit"
            )
        if response.status_code >= 400:
            raise NVDError(f"NVD returned HTTP {response.status_code}")
        try:
            data = response.json()
        except ValueError as exc:
            raise NVDError("NVD returned invalid JSON") from exc
        if not isinstance(data, dict):
            raise NVDError("NVD returned an unexpected response")
        return data

    def _download(self, product: str, version: str) -> list[dict]:
        if self._unavailable is not None:
            raise NVDError(self._unavailable)
        vendor, name = product.split(":", 1)
        match = f"cpe:2.3:a:{vendor}:{name}:{version}"
        records: list[dict] = []
        start = 0
        while True:
            log.info("NVD: fetching %s from index %d", match, start)
            page = self._get_page(match, start)
            for item in page.get("vulnerabilities") or []:
                cve = item.get("cve") if isinstance(item, dict) else None
                if isinstance(cve, dict):
                    records.append(slim_record(cve))
            total = int(page.get("totalResults") or 0)
            got = int(page.get("resultsPerPage") or len(records))
            start += got
            if start >= total or got <= 0:
                break
        return records

    def _records_for(self, product: str, version: str) -> list[dict]:
        """Cached records for one ``(product, version)``, from memory, disk or NVD.

        Serialised across threads so that concurrent forward-checks queue behind one
        rate limit rather than each racing to the network.
        """
        with self._lock:
            return self._records_for_locked(product, version)

    def _records_for_locked(self, product: str, version: str) -> list[dict]:
        key = (product, version)
        if key in self._memory:
            log.debug("NVD: %s %s served from memory", product, version)
            return self._memory[key]
        path = self._cache_path(product, version)
        age = self._cache_age(path)
        if path is not None and age is not None and age < self.ttl_hours * 3600:
            try:
                records = self._read_cache(path)
            except (OSError, ValueError):
                log.info("NVD: cached answer for %s %s unreadable", product, version, exc_info=True)
                records = None
            if records is not None:
                log.info("NVD: %s %s from cache (%.1f h old)", product, version, age / 3600)
                self._memory[key] = records
                return records
        try:
            records = self._download(product, version)
        except NVDError as exc:
            log.info("NVD: download for %s %s failed: %s", product, version, exc)
            if path is None or age is None:
                raise
            try:
                records = self._read_cache(path)
            except (OSError, ValueError):
                raise exc from None
            self.warnings.append(
                f"{exc}; using stale cached NVD answer for {product} {version} from "
                f"{age / 3600:.0f} hours ago"
            )
        else:
            if path is not None:
                try:
                    self._write_cache(path, records)
                except OSError:
                    pass
        self._memory[key] = records
        return records

    # -- matching ------------------------------------------------------------------

    def _record_failure(self, dep: Dependency, exc: NVDError) -> None:
        label = f"{dep.name} {dep.version}"
        if self._unavailable is None:
            self._unavailable = str(exc)
            self.errors.append(str(exc))
            log.warning("NVD: %s; remaining uncached lookups this run are skipped", exc)
        else:
            log.info("NVD: %s not checked (NVD unavailable)", label)
        if label not in self.unchecked:
            self.unchecked.append(label)

    def _warn_unmapped(self, dep: Dependency) -> None:
        self.warnings.append(
            f"{dep.name} ({dep.source_file}): no advisory source is known for this image; map "
            f"it to a CPE product with VULNSCAN_IMAGE_PRODUCTS={dep.name}=vendor:product"
        )

    def find_vulnerabilities(
        self, deps: Iterable[Dependency], include_unknown_versions: bool = False
    ) -> dict[Dependency, list[Vulnerability]]:
        """Map each affected image to its CVEs.

        Images without a version cannot be matched and are skipped whatever
        ``include_unknown_versions`` says; images with no known product produce a
        warning. NVD's own matching is filtered again against the parsed ranges, so a
        version at or above a ``versionEndExcluding`` bound is never reported. An image
        whose lookup fails is left out of the result and recorded (see
        :meth:`error_lines`) rather than raising.
        """
        found: dict[Dependency, list[Vulnerability]] = {}
        warned: set[str] = set()
        for dep in deps:
            if dep.ecosystem != CONTAINER or not dep.version:
                continue
            product = product_for_image(dep.name, self.image_products)
            if product is None:
                canonical = canonical_image_name(dep.name)
                if canonical not in OS_IMAGES and canonical not in warned:
                    warned.add(canonical)
                    self._warn_unmapped(dep)
                continue
            try:
                records = self._records_for(product, query_version(dep.version))
            except NVDError as exc:
                self._record_failure(dep, exc)
                continue
            vulns: list[Vulnerability] = []
            for record in records:
                if str(record.get("vulnStatus", "")).lower() == "rejected":
                    continue
                vuln = parse_nvd_record(record, product)
                scoped = vuln.affected_ranges or vuln.affected_versions
                if scoped and not vuln.affects(dep.version, CONTAINER):
                    continue
                vulns.append(vuln)
            if vulns:
                found[dep] = vulns
        return found
