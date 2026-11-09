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
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from vulnscan import __version__, debuglog
from vulnscan.models import (
    CONTAINER,
    NPM,
    PACKAGIST,
    PYPI,
    Dependency,
    VersionRange,
    Vulnerability,
    normalize_name,
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


@dataclass(frozen=True)
class CNASource:
    """Where a product's own CNA files its CVEs and how it names the product there."""

    source: str
    vendor: str
    product: str


CNA_SOURCES: dict[str, CNASource] = {
    "python:python": CNASource("cna@python.org", "Python Software Foundation", "CPython"),
    "php:php": CNASource("security@php.net", "PHP Group", "PHP"),
    "f5:nginx": CNASource("f5sirt@f5.com", "F5", "NGINX Open Source"),
}
"""Products whose own CNA files their CVEs, keyed by CPE ``vendor:product``.

A CVE filed by the product's CNA carries the CNA's affected-version ranges from the
day it is published, long before NVD adds CPE configurations. Vendor and product are
the names the CNA uses in its ``affected`` block, which need not match the CPE names.
"""


def parse_cna_sources(entries: Iterable[str]) -> dict[str, CNASource]:
    """Turn ``vendor:product=source;Vendor Name;Product Name`` entries into a mapping.

    Blank entries are skipped; anything without ``=``, without a ``vendor:product``
    key or without all three ``;``-separated parts raises ``ValueError``.
    """
    sources: dict[str, CNASource] = {}
    for entry in entries:
        text = entry.strip()
        if not text:
            continue
        product, eq, rest = text.partition("=")
        product = product.strip()
        parts = [part.strip() for part in rest.split(";")]
        if not eq or not _PRODUCT.match(product) or len(parts) != 3 or not all(parts):
            raise ValueError(
                "VULNSCAN_CNA_SOURCES entries look like "
                f"vendor:product=source;Vendor Name;Product Name (got {text!r})"
            )
        sources[product] = CNASource(*parts)
    return sources


def _cna_affected_entries(data: dict, source: CNASource):
    vendor, product = source.vendor.lower(), source.product.lower()
    for block in data.get("affected") or []:
        if not isinstance(block, dict):
            continue
        for entry in block.get("affectedData") or []:
            if not isinstance(entry, dict):
                continue
            if str(entry.get("vendor", "")).lower() != vendor:
                continue
            if str(entry.get("product", "")).lower() != product:
                continue
            yield entry


def _affected_versions(entry: dict) -> tuple[list[VersionRange], list[str], list[str]]:
    """``(ranges, explicit versions, fixed versions)`` from one ``affectedData`` entry.

    Each ``affected`` version with a ``lessThan``/``lessThanOrEqual`` bound becomes a
    range (``0`` as the start means unbounded below) and every ``lessThan`` is a fixed
    version; a bare version is an explicit affected version. Git commit ranges are
    ignored, as are entries marked ``unaffected`` or ``unknown``.
    """
    ranges: list[VersionRange] = []
    explicit: list[str] = []
    fixed: list[str] = []
    for item in entry.get("versions") or []:
        if not isinstance(item, dict) or item.get("status", "affected") != "affected":
            continue
        if str(item.get("versionType", "")).lower() == "git":
            continue
        start = str(item.get("version", "") or "")
        upper_excl = item.get("lessThan")
        upper_incl = item.get("lessThanOrEqual")
        if not upper_excl and not upper_incl:
            if start:
                explicit.append(normalize_version(start))
            continue
        lower = None if start in ("", "0") else normalize_version(start)
        upper = str(upper_excl or upper_incl)
        ranges.append(
            VersionRange(
                lower=lower,
                lower_inclusive=True,
                upper=normalize_version(upper),
                upper_inclusive=not upper_excl,
            )
        )
        if upper_excl:
            fixed.append(normalize_version(upper))
    return ranges, explicit, fixed


def parse_cna_record(data: dict, source: CNASource) -> Vulnerability:
    """Convert an NVD record into our model from the CNA's ``affected`` block.

    Only entries naming the source's vendor and product count; see
    :func:`_affected_versions` for how each entry's versions are read.
    """
    ranges: list[VersionRange] = []
    explicit: list[str] = []
    fixed: list[str] = []
    for entry in _cna_affected_entries(data, source):
        more_ranges, more_explicit, more_fixed = _affected_versions(entry)
        ranges.extend(more_ranges)
        explicit.extend(more_explicit)
        fixed.extend(more_fixed)
    return _vulnerability(data, ranges, explicit, fixed)


# --- registry packages (PyPI, npm, Packagist) via CNA affected data ------------------------------

DSF_SOURCE = "6a34fbeb-21d4-45e7-8e0a-62b95bc12c92"
"""The Django Software Foundation's NVD source identifier (a UUID, not an address)."""

REGISTRY_CNAS: tuple[str, ...] = (DSF_SOURCE, "cna@python.org")
"""CNAs known to tag the ``affected`` block of their CVEs with a package registry URL."""


REGISTRY_ECOSYSTEMS = frozenset({PYPI, NPM, PACKAGIST})
"""Ecosystems whose packages the registry CNA check covers (the ones OSV indexes)."""

_REGISTRY_HOSTS: dict[str, str] = {
    "pypi.org": PYPI,
    "pypi.python.org": PYPI,
    "npmjs.com": NPM,
    "npmjs.org": NPM,
    "registry.npmjs.org": NPM,
    "packagist.org": PACKAGIST,
    "repo.packagist.org": PACKAGIST,
    "drupal.org": PACKAGIST,
}
"""``collectionURL`` hosts (without ``www.``) and the ecosystem each one identifies."""

_PACKAGE_PATH_PREFIXES = ("/project/", "/package/", "/packages/")
"""Path segments after which a registry URL names the package itself."""


def _collection_host(collection_url: str) -> str:
    try:
        host = urlsplit(str(collection_url).strip()).hostname or ""
    except ValueError:
        return ""
    host = host.lower()
    return host[4:] if host.startswith("www.") else host


def registry_ecosystem(collection_url: str) -> str | None:
    """The vulnscan ecosystem a CNA ``collectionURL`` points at, or ``None``.

    pypi.org is PyPI, npmjs.com and registry.npmjs.org are npm, packagist.org is
    Packagist, and drupal.org projects are Packagist too (as ``drupal/<project>``).
    """
    return _REGISTRY_HOSTS.get(_collection_host(collection_url))


def _package_from_path(collection_url: str) -> str | None:
    try:
        path = urlsplit(str(collection_url).strip()).path
    except ValueError:
        return None
    for prefix in _PACKAGE_PATH_PREFIXES:
        if prefix in path:
            name = path.split(prefix, 1)[1].strip("/")
            return name or None
    return None


def registry_package(entry: dict) -> tuple[str, str] | None:
    """``(ecosystem, canonical package name)`` for one CNA ``affectedData`` entry, or ``None``.

    The ecosystem comes from the ``collectionURL`` host and the name from
    ``packageName``, falling back to the project named in the URL path (the PSF files
    pip as ``https://pypi.org/project/pip`` with no package name). Entries without a
    registry URL, or with a bare registry URL and no name, cannot be matched.
    """
    if not isinstance(entry, dict):
        return None
    url = str(entry.get("collectionURL") or "")
    ecosystem = registry_ecosystem(url)
    if ecosystem is None:
        return None
    name = str(entry.get("packageName") or "").strip() or _package_from_path(url)
    if not name:
        return None
    if _collection_host(url) == "drupal.org" and "/" not in name:
        name = f"drupal/{name}"
    return ecosystem, normalize_name(name, ecosystem)


def _registry_packages_in(data: dict) -> set[tuple[str, str]]:
    """Every registry package an NVD record's CNA ``affected`` block names."""
    packages: set[tuple[str, str]] = set()
    for block in data.get("affected") or []:
        if not isinstance(block, dict):
            continue
        for entry in block.get("affectedData") or []:
            package = registry_package(entry)
            if package is not None:
                packages.add(package)
    return packages


def parse_registry_record(data: dict, package_name: str, ecosystem: str) -> Vulnerability:
    """Convert an NVD record into our model from the CNA's ``affected`` block for one package.

    Only entries whose registry URL and package name identify ``package_name`` in
    ``ecosystem`` count; see :func:`_affected_versions` for how their versions are read.
    """
    wanted = (ecosystem, normalize_name(package_name, ecosystem))
    ranges: list[VersionRange] = []
    explicit: list[str] = []
    fixed: list[str] = []
    for block in data.get("affected") or []:
        if not isinstance(block, dict):
            continue
        for entry in block.get("affectedData") or []:
            if registry_package(entry) != wanted:
                continue
            more_ranges, more_explicit, more_fixed = _affected_versions(entry)
            ranges.extend(more_ranges)
            explicit.extend(more_explicit)
            fixed.extend(more_fixed)
    return _vulnerability(data, ranges, explicit, fixed)


def _dedupe_sources(sources: Iterable[str]) -> tuple[str, ...]:
    seen: list[str] = []
    for source in sources:
        text = str(source).strip()
        if text and text not in seen:
            seen.append(text)
    return tuple(seen)


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


def record_targets_product(data: dict, product: str) -> bool:
    """Whether an NVD record's configurations name ``vendor:product`` as vulnerable.

    A record with no configuration data at all (one still awaiting analysis) counts
    as targeting the product, since NVD returned it for the product's CPE and there
    is nothing to say otherwise. A record whose configurations mention the product
    only as a non-vulnerable platform (``vulnerable: false``, the "running with
    Python 3.6+" half of an AND node) does not.
    """
    wanted = product.lower()
    seen_any = False
    for entry in _iter_cpe_matches(data.get("configurations")):
        seen_any = True
        parsed = _cpe_version(str(entry.get("criteria", "")))
        if parsed is None or parsed[0].lower() != wanted:
            continue
        if entry.get("vulnerable", True):
            return True
    return not seen_any


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
    return _vulnerability(data, ranges, explicit, fixed)


def _vulnerability(
    data: dict, ranges: list[VersionRange], explicit: list[str], fixed: list[str]
) -> Vulnerability:
    """Our model for an NVD record with the affected versions already worked out."""
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
    """Only the fields :func:`parse_nvd_record` and :func:`parse_cna_record` read."""
    return {
        "id": data.get("id"),
        "published": data.get("published"),
        "lastModified": data.get("lastModified"),
        "vulnStatus": data.get("vulnStatus"),
        "sourceIdentifier": data.get("sourceIdentifier"),
        "affected": data.get("affected") or [],
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
        cna_sources: dict[str, CNASource] | None = None,
        registry_cnas: Iterable[str] | None = None,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] | None = None,
    ) -> None:
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.cache_dir = Path(cache_dir) / "nvd" if cache_dir is not None else None
        self.ttl_hours = ttl_hours
        self.image_products = dict(image_products or {})
        self.cna_sources = dict(cna_sources or {})
        self.registry_cnas = _dedupe_sources([*REGISTRY_CNAS, *(registry_cnas or [])])
        self.warnings: list[str] = []
        self._transport = transport
        self._sleep = sleep or time.sleep
        self._last_request: float | None = None
        self._memory: dict[str, list[dict]] = {}
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

    def _cache_path(self, name: str) -> Path | None:
        if self.cache_dir is None:
            return None
        safe = re.sub(r"[^A-Za-z0-9._-]+", "_", name)
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

    def _get_page(self, query: dict[str, str], start: int) -> dict:
        headers = {"User-Agent": f"vulnscan/{__version__}", "Accept": "application/json"}
        if self.api_key:
            headers["apiKey"] = self.api_key
        params = {**query, "resultsPerPage": str(PAGE_SIZE), "startIndex": str(start)}
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

    def _download(self, query: dict[str, str], label: str) -> list[dict]:
        if self._unavailable is not None:
            raise NVDError(self._unavailable)
        records: list[dict] = []
        start = 0
        while True:
            log.info("NVD: fetching %s from index %d", label, start)
            page = self._get_page(query, start)
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
        """Cached records whose CPE configurations match ``product`` at ``version``."""
        vendor, name = product.split(":", 1)
        match = f"cpe:2.3:a:{vendor}:{name}:{version}"
        return self._cached(
            f"{product}__{version}", f"{product} {version}", {"virtualMatchString": match}
        )

    def _cna_records_for(self, source: CNASource) -> list[dict]:
        """Cached records filed by one CNA, whatever product they concern."""
        return self._records_filed_by(source.source)

    def _records_filed_by(self, source: str) -> list[dict]:
        """Cached records filed by the CNA with NVD source identifier ``source``."""
        return self._cached(f"cna__{source}", f"CNA {source}", {"sourceIdentifier": source})

    def _cached(self, name: str, label: str, query: dict[str, str]) -> list[dict]:
        """Records for one query, from memory, disk or NVD.

        Serialised across threads so that concurrent forward-checks queue behind one
        rate limit rather than each racing to the network.
        """
        with self._lock:
            return self._cached_locked(name, label, query)

    def _cached_locked(self, name: str, label: str, query: dict[str, str]) -> list[dict]:
        if name in self._memory:
            log.debug("NVD: %s served from memory", label)
            return self._memory[name]
        path = self._cache_path(name)
        age = self._cache_age(path)
        if path is not None and age is not None and age < self.ttl_hours * 3600:
            try:
                records = self._read_cache(path)
            except (OSError, ValueError):
                log.info("NVD: cached answer for %s unreadable", label, exc_info=True)
                records = None
            if records is not None:
                log.info("NVD: %s from cache (%.1f h old)", label, age / 3600)
                self._memory[name] = records
                return records
        try:
            records = self._download(query, label)
        except NVDError as exc:
            log.info("NVD: download for %s failed: %s", label, exc)
            if path is None or age is None:
                raise
            try:
                records = self._read_cache(path)
            except (OSError, ValueError):
                raise exc from None
            self.warnings.append(
                f"{exc}; using stale cached NVD answer for {label} from {age / 3600:.0f} hours ago"
            )
        else:
            if path is not None:
                try:
                    self._write_cache(path, records)
                except OSError:
                    pass
        self._memory[name] = records
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
        warning. NVD's own matching is filtered again: records that name the image's
        product only as a non-vulnerable platform are dropped, and the rest are checked
        against the parsed ranges, so a version at or above a ``versionEndExcluding``
        bound is never reported. An image whose lookup fails is left out of the result
        and recorded (see :meth:`error_lines`) rather than raising.

        For a product with a known CNA (see :data:`CNA_SOURCES`) the CVEs that CNA
        filed are fetched as well, and those NVD has not analysed yet (no
        configurations at all) are matched against the CNA's own affected ranges.
        NVD's configurations stay authoritative once they exist. A failed CNA lookup
        only costs a warning; the CPE answer still stands.
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
                if not record_targets_product(record, product):
                    # NVD's match string also hits the non-vulnerable platform half of
                    # an AND configuration ("Odoo, when running with Python 3.6+"), so
                    # a record that only names the image as a platform is not about it.
                    continue
                vuln = parse_nvd_record(record, product)
                scoped = vuln.affected_ranges or vuln.affected_versions
                if scoped and not vuln.affects(dep.version, CONTAINER):
                    continue
                vulns.append(vuln)
            vulns.extend(self._cna_vulnerabilities(dep, product, {v.id for v in vulns}))
            if vulns:
                found[dep] = vulns
        return found

    def find_registry_vulnerabilities(
        self,
        deps: Iterable[Dependency],
        known: dict[Dependency, list[Vulnerability]] | None = None,
    ) -> dict[Dependency, list[Vulnerability]]:
        """Map registry packages (PyPI, npm, Packagist) to CVEs their CNAs filed.

        Every CNA in ``registry_cnas`` is asked once for all the CVEs it filed (cached
        for the TTL, shared with the container image path) and each record's
        ``affected`` block is matched against the packages by registry URL and package
        name, then against the version by the CNA's own ranges. Advisories already in
        ``known`` for the same package (by id or alias, as OSV reports them) are left
        out, so a CVE both sources carry is reported once. Packages outside these
        ecosystems or without a version are skipped. A CNA that cannot be fetched
        costs a warning; the other CNAs' records still count.
        """
        wanted = [d for d in deps if d.ecosystem in REGISTRY_ECOSYSTEMS and d.version]
        if not wanted:
            return {}
        index: dict[tuple[str, str], list[dict]] = {}
        for source in self.registry_cnas:
            try:
                records = self._records_filed_by(source)
            except NVDError as exc:
                self.warnings.append(f"NVD: could not fetch the CVEs filed by {source}: {exc}")
                continue
            for record in records:
                if str(record.get("vulnStatus", "")).lower() == "rejected":
                    continue
                for package in _registry_packages_in(record):
                    index.setdefault(package, []).append(record)
        found: dict[Dependency, list[Vulnerability]] = {}
        for dep in wanted:
            already = {i.upper() for v in (known or {}).get(dep, []) for i in (v.id, *v.aliases)}
            vulns: list[Vulnerability] = []
            for record in index.get(dep.key, []):
                if str(record.get("id", "")).upper() in already:
                    continue
                vuln = parse_registry_record(record, dep.name, dep.ecosystem)
                if not (vuln.affected_ranges or vuln.affected_versions):
                    continue
                if vuln.affects(dep.version, dep.ecosystem):
                    vulns.append(vuln)
            if vulns:
                found[dep] = vulns
        return found

    def _cna_vulnerabilities(
        self, dep: Dependency, product: str, seen: set[str]
    ) -> list[Vulnerability]:
        """CVEs the product's CNA filed that NVD has not analysed and that affect ``dep``."""
        source = self.cna_sources.get(product) or CNA_SOURCES.get(product)
        if source is None or not dep.version:
            return []
        try:
            records = self._cna_records_for(source)
        except NVDError as exc:
            self.warnings.append(
                f"NVD: could not fetch the CVEs filed by {source.source} for {dep.name}: {exc}"
            )
            return []
        vulns: list[Vulnerability] = []
        for record in records:
            if str(record.get("id", "")) in seen:
                continue
            if str(record.get("vulnStatus", "")).lower() == "rejected":
                continue
            if any(True for _ in _iter_cpe_matches(record.get("configurations"))):
                continue  # analysed: the CPE query already gave NVD's verdict
            vuln = parse_cna_record(record, source)
            if not (vuln.affected_ranges or vuln.affected_versions):
                continue
            if vuln.affects(dep.version, CONTAINER):
                vulns.append(vuln)
        return vulns
