import json
import os
import time
from datetime import datetime
from pathlib import Path

import httpx
import pytest

from vulnscan.models import CONTAINER, Dependency
from vulnscan.nvd import (
    IMAGE_PRODUCTS,
    OS_IMAGES,
    NVDClient,
    parse_image_products,
    parse_nvd_record,
    product_for_image,
    query_version,
    record_targets_product,
)


def cpe_match(criteria: str, **bounds) -> dict:
    entry = {"vulnerable": True, "criteria": criteria, "matchCriteriaId": "X"}
    entry.update(bounds)
    return entry


RECORD = {
    "id": "CVE-2024-4577",
    "sourceIdentifier": "security@php.net",
    "published": "2024-06-09T20:15:09.550",
    "lastModified": "2025-03-25T15:35:18.820",
    "vulnStatus": "Analyzed",
    "descriptions": [
        {
            "lang": "en",
            "value": "In PHP versions 8.1.* before 8.1.29, 8.2.* before 8.2.20, "
            "8.3.* before 8.3.8, when using Apache and PHP-CGI on Windows, Best-Fit "
            "behaviour may let an attacker pass options to the PHP binary.",
        },
        {"lang": "es", "value": "En las versiones de PHP ..."},
    ],
    "metrics": {
        "cvssMetricV31": [
            {
                "source": "security@php.net",
                "type": "Secondary",
                "cvssData": {
                    "version": "3.1",
                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "baseScore": 9.8,
                    "baseSeverity": "CRITICAL",
                },
            },
            {
                "source": "nvd@nist.gov",
                "type": "Primary",
                "cvssData": {
                    "version": "3.1",
                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "baseScore": 9.8,
                    "baseSeverity": "CRITICAL",
                },
            },
        ],
        "cvssMetricV2": [
            {
                "source": "nvd@nist.gov",
                "type": "Primary",
                "cvssData": {"version": "2.0", "vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P"},
                "baseSeverity": "HIGH",
            }
        ],
    },
    "configurations": [
        {
            "operator": "AND",
            "nodes": [
                {
                    "operator": "OR",
                    "negate": False,
                    "cpeMatch": [
                        cpe_match(
                            "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*",
                            versionStartIncluding="8.1.0",
                            versionEndExcluding="8.1.29",
                        ),
                        cpe_match(
                            "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*",
                            versionStartIncluding="8.2.0",
                            versionEndExcluding="8.2.20",
                        ),
                        cpe_match(
                            "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*",
                            versionStartIncluding="8.3.0",
                            versionEndExcluding="8.3.8",
                        ),
                    ],
                },
                {
                    "operator": "OR",
                    "negate": False,
                    "cpeMatch": [
                        {
                            "vulnerable": False,
                            "criteria": "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*",
                            "matchCriteriaId": "W",
                        }
                    ],
                },
            ],
        },
        {
            "nodes": [
                {
                    "operator": "OR",
                    "negate": False,
                    "cpeMatch": [cpe_match("cpe:2.3:o:fedoraproject:fedora:40:*:*:*:*:*:*:*")],
                }
            ]
        },
    ],
    "references": [
        {"url": "https://github.com/php/php-src/security/advisories/GHSA-3qgc-jrrr-25jv"},
        {"url": "https://www.php.net/ChangeLog-8.php#8.2.20"},
        {"url": "https://www.php.net/ChangeLog-8.php#8.2.20"},
    ],
}


def test_parse_nvd_record_extracts_ranges_fixes_severity_and_links():
    vuln = parse_nvd_record(RECORD, "php:php")
    assert vuln.id == "CVE-2024-4577"
    assert vuln.source == "nvd"
    assert vuln.severity == "CRITICAL"
    assert vuln.cvss == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert vuln.fixed_versions == ["8.1.29", "8.2.20", "8.3.8"]
    assert vuln.link == "https://nvd.nist.gov/vuln/detail/CVE-2024-4577"
    assert vuln.url == vuln.link
    assert vuln.cve_ids == ["CVE-2024-4577"]
    assert vuln.published == datetime(2024, 6, 9, 20, 15, 9, 550000)
    assert vuln.modified == datetime(2025, 3, 25, 15, 35, 18, 820000)
    assert vuln.references == [
        "https://github.com/php/php-src/security/advisories/GHSA-3qgc-jrrr-25jv",
        "https://www.php.net/ChangeLog-8.php#8.2.20",
    ]
    assert vuln.summary.startswith("In PHP versions 8.1.* before 8.1.29")
    assert "Best-Fit" in vuln.details
    assert vuln.affects("8.2.19", CONTAINER)
    assert vuln.affects("8.2", CONTAINER)
    assert not vuln.affects("8.2.20", CONTAINER)
    assert not vuln.affects("8.0.30", CONTAINER)
    assert vuln.affects("8.3.0", CONTAINER)


def test_parse_nvd_record_ignores_other_products_and_non_vulnerable_entries():
    vuln = parse_nvd_record(RECORD, "fedoraproject:fedora")
    assert vuln.affects("40", CONTAINER)
    assert not vuln.affects("8.2.19", CONTAINER)
    assert vuln.fixed_versions == []
    windows = parse_nvd_record(RECORD, "microsoft:windows")
    assert not windows.affects("10", CONTAINER)


def test_parse_nvd_record_exact_versions_and_update_field():
    record = {
        "id": "CVE-2020-1",
        "descriptions": [{"lang": "en", "value": "Something bad.\nMore text."}],
        "configurations": [
            {
                "nodes": [
                    {
                        "operator": "OR",
                        "cpeMatch": [
                            cpe_match("cpe:2.3:a:traefik:traefik:2.10.0:*:*:*:*:*:*:*"),
                            cpe_match("cpe:2.3:a:traefik:traefik:3.0.0:rc1:*:*:*:*:*:*"),
                            cpe_match(
                                "cpe:2.3:a:traefik:traefik:*:*:*:*:*:*:*:*",
                                versionStartExcluding="1.0.0",
                                versionEndIncluding="1.7.34",
                            ),
                        ],
                    }
                ]
            }
        ],
    }
    vuln = parse_nvd_record(record, "traefik:traefik")
    assert vuln.affected_versions == ["2.10.0", "3.0.0-rc1"]
    assert vuln.affects("2.10.0", CONTAINER)
    assert not vuln.affects("2.10.1", CONTAINER)
    assert vuln.affects("1.7.34", CONTAINER)
    assert not vuln.affects("1.0.0", CONTAINER)
    assert vuln.severity == "UNKNOWN"
    assert vuln.cvss is None
    assert vuln.summary == "Something bad."
    assert vuln.fixed_versions == []


def test_parse_nvd_record_unbounded_range_affects_everything():
    record = {
        "id": "CVE-2020-2",
        "descriptions": [],
        "configurations": [
            {"nodes": [{"cpeMatch": [cpe_match("cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*")]}]}
        ],
    }
    vuln = parse_nvd_record(record, "nginx:nginx")
    assert vuln.affects("1.25.4", CONTAINER)


def test_parse_nvd_record_severity_prefers_newest_cvss_then_primary_source():
    record = {
        "id": "CVE-2020-3",
        "descriptions": [],
        "metrics": {
            "cvssMetricV2": [
                {
                    "source": "nvd@nist.gov",
                    "type": "Primary",
                    "cvssData": {"vectorString": "AV:N"},
                    "baseSeverity": "LOW",
                }
            ],
            "cvssMetricV31": [
                {
                    "source": "vendor",
                    "type": "Secondary",
                    "cvssData": {"vectorString": "CVSS:3.1/S", "baseSeverity": "MEDIUM"},
                },
                {
                    "source": "nvd@nist.gov",
                    "type": "Primary",
                    "cvssData": {"vectorString": "CVSS:3.1/P", "baseSeverity": "HIGH"},
                },
            ],
            "cvssMetricV40": [
                {
                    "source": "vendor",
                    "type": "Secondary",
                    "cvssData": {"vectorString": "CVSS:4.0/X", "baseSeverity": "CRITICAL"},
                }
            ],
        },
        "configurations": [],
    }
    vuln = parse_nvd_record(record, "x:y")
    assert vuln.severity == "CRITICAL"
    assert vuln.cvss == "CVSS:4.0/X"
    del record["metrics"]["cvssMetricV40"]
    vuln = parse_nvd_record(record, "x:y")
    assert vuln.severity == "HIGH"
    assert vuln.cvss == "CVSS:3.1/P"
    del record["metrics"]["cvssMetricV31"]
    assert parse_nvd_record(record, "x:y").severity == "LOW"


# --- image to product mapping --------------------------------------------------------------


def test_builtin_products_cover_common_images():
    assert product_for_image("php") == "php:php"
    assert product_for_image("traefik") == "traefik:traefik"
    assert product_for_image("nginx") == "f5:nginx"
    assert product_for_image("node") == "nodejs:node.js"
    assert product_for_image("python") == "python:python"
    assert product_for_image("postgres") == "postgresql:postgresql"
    assert product_for_image("mysql") == "oracle:mysql"
    assert product_for_image("mariadb") == "mariadb:mariadb"
    assert product_for_image("redis") == "redis:redis"
    assert product_for_image("httpd") == "apache:http_server"
    assert product_for_image("wordpress") == "wordpress:wordpress"
    assert product_for_image("grafana/grafana") == "grafana:grafana"
    assert product_for_image("ghcr.io/astral-sh/uv") == "astral:uv"
    assert product_for_image("no/such-image") is None
    assert all(":" in v and " " not in v for v in IMAGE_PRODUCTS.values())


def test_os_images_are_known_but_have_no_product():
    for name in ("debian", "ubuntu", "alpine", "busybox", "fedora", "rockylinux"):
        assert name in OS_IMAGES
        assert product_for_image(name) is None


def test_product_for_image_overrides_and_case():
    overrides = {"myorg/app": "myorg:app", "php": "custom:php"}
    assert product_for_image("myorg/app", overrides) == "myorg:app"
    assert product_for_image("php", overrides) == "custom:php"
    assert product_for_image("MyOrg/App", overrides) == "myorg:app"
    assert product_for_image("traefik", overrides) == "traefik:traefik"


def test_parse_image_products():
    assert parse_image_products(["myorg/app=myorg:app", " ghcr.io/x/y = x:y "]) == {
        "myorg/app": "myorg:app",
        "ghcr.io/x/y": "x:y",
    }
    assert parse_image_products([]) == {}
    assert parse_image_products(["", "  "]) == {}
    with pytest.raises(ValueError):
        parse_image_products(["myorg/app"])
    with pytest.raises(ValueError):
        parse_image_products(["myorg/app=noproduct"])


@pytest.mark.parametrize(
    ("version", "expected"),
    [
        ("8.2.19", "8.2.19"),
        ("8.2", "8.2.0"),
        ("8", "8.0.0"),
        ("3.0.0-rc1", "3.0.0-rc1"),
        ("2024.1", "2024.1.0"),
        ("1.2.3.4", "1.2.3.4"),
    ],
)
def test_query_version_pads_to_three_components(version, expected):
    assert query_version(version) == expected


# --- client -----------------------------------------------------------------------------------


def image(name: str, version: str | None, tag: str | None = None) -> Dependency:
    return Dependency(
        name,
        CONTAINER,
        tag if tag is not None else (version or "latest"),
        version,
        "pinned" if version else "unknown",
        "Dockerfile",
        kind="image",
    )


class Recorder:
    """A MockTransport handler that records requests and serves canned pages."""

    def __init__(self, pages: dict[str, list[dict]] | None = None, status: int = 200):
        self.requests: list[httpx.Request] = []
        self.pages = pages or {}
        self.status = status

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.status != 200:
            return httpx.Response(self.status, text="nope")
        match = request.url.params.get("virtualMatchString", "")
        start = int(request.url.params.get("startIndex", "0"))
        records = self.pages.get(match, [])
        page = records[start : start + 2000]
        return httpx.Response(
            200,
            json={
                "resultsPerPage": len(page),
                "startIndex": start,
                "totalResults": len(records),
                "vulnerabilities": [{"cve": r} for r in page],
            },
        )


def make_client(handler, tmp_path: Path, **kwargs) -> NVDClient:
    kwargs.setdefault("sleep", lambda seconds: None)
    return NVDClient(
        base_url="https://nvd.test/cves",
        timeout=1.0,
        cache_dir=tmp_path / "cache",
        transport=httpx.MockTransport(handler),
        **kwargs,
    )


def test_find_vulnerabilities_queries_cpe_for_version_and_filters_locally(tmp_path: Path):
    handler = Recorder({"cpe:2.3:a:php:php:8.2.19": [RECORD]})
    client = make_client(handler, tmp_path)
    php = image("php", "8.2.19")
    found = client.find_vulnerabilities([php])
    assert [v.id for v in found[php]] == ["CVE-2024-4577"]
    assert found[php][0].fixed_versions == ["8.1.29", "8.2.20", "8.3.8"]
    request = handler.requests[0]
    assert request.url.host == "nvd.test"
    assert request.url.params["virtualMatchString"] == "cpe:2.3:a:php:php:8.2.19"
    assert request.url.params["resultsPerPage"] == "2000"
    assert "apiKey" not in request.headers


def test_find_vulnerabilities_drops_records_our_ranges_say_are_fixed(tmp_path: Path):
    handler = Recorder({"cpe:2.3:a:php:php:8.2.20": [RECORD]})
    client = make_client(handler, tmp_path)
    assert client.find_vulnerabilities([image("php", "8.2.20")]) == {}


def test_find_vulnerabilities_pads_floating_versions_for_the_query(tmp_path: Path):
    handler = Recorder({"cpe:2.3:a:php:php:8.2.0": [RECORD]})
    client = make_client(handler, tmp_path)
    php = image("php", "8.2", "8.2-fpm")
    found = client.find_vulnerabilities([php])
    assert [v.id for v in found[php]] == ["CVE-2024-4577"]


def test_find_vulnerabilities_skips_rejected_and_unmatched_records(tmp_path: Path):
    rejected = dict(RECORD, id="CVE-2024-9999", vulnStatus="Rejected")
    handler = Recorder({"cpe:2.3:a:php:php:8.2.19": [RECORD, rejected]})
    client = make_client(handler, tmp_path)
    php = image("php", "8.2.19")
    assert [v.id for v in client.find_vulnerabilities([php])[php]] == ["CVE-2024-4577"]


def test_find_vulnerabilities_keeps_records_without_parseable_product_ranges(tmp_path: Path):
    bare = {"id": "CVE-2024-1", "descriptions": [], "configurations": [], "vulnStatus": "Analyzed"}
    handler = Recorder({"cpe:2.3:a:php:php:8.2.19": [bare]})
    client = make_client(handler, tmp_path)
    php = image("php", "8.2.19")
    assert [v.id for v in client.find_vulnerabilities([php])[php]] == ["CVE-2024-1"]


def test_find_vulnerabilities_skips_unknown_versions_and_unmapped_images(tmp_path: Path):
    handler = Recorder({"cpe:2.3:a:php:php:8.2.19": [RECORD]})
    client = make_client(handler, tmp_path)
    found = client.find_vulnerabilities(
        [image("php", None), image("no/such-image", "1.0.0"), image("debian", "12")],
        include_unknown_versions=True,
    )
    assert found == {}
    assert handler.requests == []
    assert any("no/such-image" in w and "VULNSCAN_IMAGE_PRODUCTS" in w for w in client.warnings)
    assert not any("debian" in w for w in client.warnings)
    assert not any("php" in w for w in client.warnings)


def test_find_vulnerabilities_honours_image_product_overrides(tmp_path: Path):
    record = {
        "id": "CVE-2024-2",
        "descriptions": [],
        "vulnStatus": "Analyzed",
        "configurations": [
            {"nodes": [{"cpeMatch": [cpe_match("cpe:2.3:a:myorg:app:1.0.0:*:*:*:*:*:*:*")]}]}
        ],
    }
    handler = Recorder({"cpe:2.3:a:myorg:app:1.0.0": [record]})
    client = make_client(handler, tmp_path, image_products={"myorg/app": "myorg:app"})
    app = image("myorg/app", "1.0.0")
    assert [v.id for v in client.find_vulnerabilities([app])[app]] == ["CVE-2024-2"]


def test_find_vulnerabilities_follows_pagination(tmp_path: Path):
    records = [dict(RECORD, id=f"CVE-2024-{i}") for i in range(2001)]
    handler = Recorder({"cpe:2.3:a:php:php:8.2.19": records})
    client = make_client(handler, tmp_path)
    php = image("php", "8.2.19")
    found = client.find_vulnerabilities([php])
    assert len(found[php]) == 2001
    assert [r.url.params["startIndex"] for r in handler.requests] == ["0", "2000"]


def test_find_vulnerabilities_sends_api_key_header(tmp_path: Path):
    handler = Recorder({"cpe:2.3:a:php:php:8.2.19": [RECORD]})
    client = make_client(handler, tmp_path, api_key="secret")
    client.find_vulnerabilities([image("php", "8.2.19")])
    assert handler.requests[0].headers["apiKey"] == "secret"


def test_requests_are_spaced_for_the_public_rate_limit(tmp_path: Path):
    slept: list[float] = []
    handler = Recorder({"cpe:2.3:a:php:php:8.2.19": [RECORD], "cpe:2.3:a:php:php:8.3.0": []})
    client = make_client(handler, tmp_path, sleep=slept.append)
    client.find_vulnerabilities([image("php", "8.2.19"), image("php", "8.3")])
    assert len(handler.requests) == 2
    assert slept and sum(slept) >= 5.5  # the remainder of the 6 s window after request time
    slept.clear()
    client = make_client(handler, tmp_path / "other", sleep=slept.append, api_key="k")
    client.find_vulnerabilities([image("php", "8.2.19"), image("php", "8.3")])
    assert sum(slept) < 6.0


def test_results_are_cached_on_disk_until_the_ttl_expires(tmp_path: Path):
    handler = Recorder({"cpe:2.3:a:php:php:8.2.19": [RECORD]})
    client = make_client(handler, tmp_path, ttl_hours=1)
    php = image("php", "8.2.19")
    client.find_vulnerabilities([php])
    assert len(handler.requests) == 1
    cached = list((tmp_path / "cache").rglob("*.json"))
    assert cached, "expected a cache file"

    again = make_client(handler, tmp_path, ttl_hours=1)
    assert [v.id for v in again.find_vulnerabilities([php])[php]] == ["CVE-2024-4577"]
    assert len(handler.requests) == 1

    old = time.time() - 2 * 3600
    for path in cached:
        os.utime(path, (old, old))
    stale = make_client(handler, tmp_path, ttl_hours=1)
    stale.find_vulnerabilities([php])
    assert len(handler.requests) == 2


def test_errors_are_recorded_without_cache_and_fall_back_to_stale_cache(tmp_path: Path):
    good = Recorder({"cpe:2.3:a:php:php:8.2.19": [RECORD]})
    php = image("php", "8.2.19")
    make_client(good, tmp_path).find_vulnerabilities([php])
    for path in (tmp_path / "cache").rglob("*.json"):
        old = time.time() - 48 * 3600
        os.utime(path, (old, old))

    broken = Recorder(status=503)
    client = make_client(broken, tmp_path)
    found = client.find_vulnerabilities([php])
    assert [v.id for v in found[php]] == ["CVE-2024-4577"]
    assert any("stale" in w.lower() for w in client.warnings)
    assert client.error_lines() == []

    fresh = make_client(broken, tmp_path / "empty")
    assert fresh.find_vulnerabilities([php]) == {}
    assert any("503" in line and "php 8.2.19" in line for line in fresh.error_lines())


def test_rate_limit_and_forbidden_responses_explain_the_api_key(tmp_path: Path):
    for status in (403, 429):
        client = make_client(Recorder(status=status), tmp_path / str(status))
        assert client.find_vulnerabilities([image("php", "8.2.19")]) == {}
        assert any("VULNSCAN_NVD_API_KEY" in line for line in client.error_lines())


def test_bad_json_is_recorded_as_an_error(tmp_path: Path):
    def garbage(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>")

    client = make_client(garbage, tmp_path / "b")
    assert client.find_vulnerabilities([image("php", "8.2.19")]) == {}
    assert any("JSON" in line for line in client.error_lines())


def test_cache_file_is_valid_json_and_does_not_hold_the_api_key(tmp_path: Path):
    handler = Recorder({"cpe:2.3:a:php:php:8.2.19": [RECORD]})
    make_client(handler, tmp_path, api_key="secret").find_vulnerabilities([image("php", "8.2.19")])
    for path in (tmp_path / "cache").rglob("*.json"):
        text = path.read_text()
        json.loads(text)
        assert "secret" not in text


# --- carrying on after failures ----------------------------------------------------------


def test_rate_limited_request_waits_a_full_window_and_retries_once(tmp_path: Path):
    statuses = iter([429])
    good = Recorder({"cpe:2.3:a:php:php:8.2.19": [RECORD]})

    def handler(request: httpx.Request) -> httpx.Response:
        status = next(statuses, 200)
        if status != 200:
            good.requests.append(request)
            return httpx.Response(status, text="slow down")
        return good(request)

    slept: list[float] = []
    client = make_client(handler, tmp_path, sleep=slept.append)
    php = image("php", "8.2.19")
    found = client.find_vulnerabilities([php])
    assert [v.id for v in found[php]] == ["CVE-2024-4577"]
    assert len(good.requests) == 2
    assert max(slept) >= 30.0
    assert client.error_lines() == []


def test_persistent_failure_is_reported_and_later_images_are_skipped(tmp_path: Path):
    traefik_record = dict(
        RECORD,
        configurations=[
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            cpe_match(
                                "cpe:2.3:a:traefik:traefik:*:*:*:*:*:*:*:*",
                                versionStartIncluding="2.10.0",
                                versionEndExcluding="2.10.8",
                            )
                        ]
                    }
                ]
            }
        ],
    )
    good = Recorder({"cpe:2.3:a:traefik:traefik:2.10.7": [traefik_record]})
    traefik = image("traefik", "2.10.7")
    make_client(good, tmp_path).find_vulnerabilities([traefik])

    broken = Recorder(status=429)
    client = make_client(broken, tmp_path, sleep=lambda seconds: None)
    php = image("php", "8.2.19")
    nginx = image("nginx", "1.25.0")
    found = client.find_vulnerabilities([php, nginx, traefik])

    assert [v.id for v in found[traefik]] == ["CVE-2024-4577"]  # fresh cache still answers
    assert php not in found and nginx not in found
    assert len(broken.requests) <= 2  # one attempt plus one retry, then no more network
    lines = client.error_lines()
    assert lines
    joined = " ".join(lines)
    assert "429" in joined
    assert "php 8.2.19" in joined and "nginx 1.25.0" in joined
    assert "traefik" not in joined


def test_connection_failure_does_not_raise(tmp_path: Path):
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down", request=request)

    client = make_client(boom, tmp_path)
    assert client.find_vulnerabilities([image("php", "8.2.19")]) == {}
    assert any("down" in line for line in client.error_lines())


def test_requests_never_overlap_across_threads(tmp_path: Path):
    import threading

    lock = threading.Lock()
    in_flight = 0
    peak = 0
    pages = {f"cpe:2.3:a:php:php:8.2.{n}": [] for n in range(8)}
    inner = Recorder(pages)

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal in_flight, peak
        with lock:
            in_flight += 1
            peak = max(peak, in_flight)
        time.sleep(0.02)
        try:
            return inner(request)
        finally:
            with lock:
                in_flight -= 1

    client = make_client(handler, tmp_path)
    threads = [
        threading.Thread(target=client.find_vulnerabilities, args=([image("php", f"8.2.{n}")],))
        for n in range(8)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(inner.requests) == 8
    assert peak == 1


# --- platform-only matches ----------------------------------------------------------------------


def platform_record(cve_id: str, product_cpe: str, platform_cpe: str, **platform_bounds) -> dict:
    """A record whose vulnerable product is one thing and whose platform is another."""
    platform = {"vulnerable": False, "criteria": platform_cpe, "matchCriteriaId": "P"}
    platform.update(platform_bounds)
    return {
        "id": cve_id,
        "descriptions": [{"lang": "en", "value": f"{cve_id} in something else"}],
        "vulnStatus": "Analyzed",
        "configurations": [
            {
                "operator": "AND",
                "nodes": [
                    {
                        "operator": "OR",
                        "negate": False,
                        "cpeMatch": [
                            cpe_match(
                                product_cpe,
                                versionStartIncluding="11.0",
                                versionEndIncluding="13.0",
                            )
                        ],
                    },
                    {"operator": "OR", "negate": False, "cpeMatch": [platform]},
                ],
            }
        ],
    }


ODOO_ON_PYTHON = platform_record(
    "CVE-2020-29396",
    "cpe:2.3:a:odoo:odoo:*:*:*:*:community:*:*:*",
    "cpe:2.3:a:python:python:*:*:*:*:*:*:*:*",
    versionStartIncluding="3.6.0",
)
DJANGO_ON_PYTHON = platform_record(
    "CVE-2021-32052",
    "cpe:2.3:a:djangoproject:django:*:*:*:*:*:*:*:*",
    "cpe:2.3:a:python:python:*:*:*:*:*:*:*:*",
    versionStartIncluding="3.9.5",
)
PYTHON_ITSELF = {
    "id": "CVE-2025-1",
    "descriptions": [{"lang": "en", "value": "Python bug"}],
    "vulnStatus": "Analyzed",
    "configurations": [
        {
            "nodes": [
                {
                    "cpeMatch": [
                        cpe_match(
                            "cpe:2.3:a:python:python:*:*:*:*:*:*:*:*",
                            versionStartIncluding="3.14.0",
                            versionEndExcluding="3.14.10",
                        )
                    ]
                }
            ]
        }
    ],
}


def test_record_targets_product_true_for_vulnerable_entry():
    assert record_targets_product(RECORD, "php:php") is True
    assert record_targets_product(PYTHON_ITSELF, "python:python") is True


def test_record_targets_product_false_when_only_a_platform():
    assert record_targets_product(ODOO_ON_PYTHON, "python:python") is False
    assert record_targets_product(DJANGO_ON_PYTHON, "python:python") is False
    # The platform CPE is non-vulnerable even in the record for the vulnerable product.
    assert record_targets_product(RECORD, "microsoft:windows") is False


def test_record_targets_product_true_for_the_actually_vulnerable_product():
    assert record_targets_product(ODOO_ON_PYTHON, "odoo:odoo") is True
    assert record_targets_product(DJANGO_ON_PYTHON, "djangoproject:django") is True


def test_record_targets_product_true_without_configurations():
    bare = {"id": "CVE-2024-1", "descriptions": [], "configurations": [], "vulnStatus": "Analyzed"}
    assert record_targets_product(bare, "php:php") is True
    assert record_targets_product({"id": "CVE-2024-2"}, "php:php") is True


def test_record_targets_product_is_case_insensitive():
    assert record_targets_product(PYTHON_ITSELF, "Python:Python") is True


def test_find_vulnerabilities_drops_records_where_the_image_is_only_the_platform(tmp_path: Path):
    handler = Recorder(
        {"cpe:2.3:a:python:python:3.14.9": [ODOO_ON_PYTHON, DJANGO_ON_PYTHON, PYTHON_ITSELF]}
    )
    client = make_client(handler, tmp_path)
    python = image("python", "3.14.9")
    found = client.find_vulnerabilities([python])
    assert [v.id for v in found[python]] == ["CVE-2025-1"]


def test_find_vulnerabilities_omits_image_when_every_match_is_platform_only(tmp_path: Path):
    handler = Recorder({"cpe:2.3:a:python:python:3.14.9": [ODOO_ON_PYTHON, DJANGO_ON_PYTHON]})
    client = make_client(handler, tmp_path)
    assert client.find_vulnerabilities([image("python", "3.14.9")]) == {}
