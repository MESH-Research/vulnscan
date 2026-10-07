import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest

from vulnscan.models import PACKAGIST, WORDPRESS, Dependency
from vulnscan.wordfence import (
    WordfenceClient,
    WordfenceError,
    parse_wordfence_record,
    software_matches,
)

RECORD = {
    "id": "0f1a2b3c-0000-4000-8000-000000000001",
    "title": "Elementor <= 3.13.4 - Authenticated (Contributor+) Stored Cross-Site Scripting",
    "description": "The Elementor plugin is vulnerable to Stored XSS.",
    "software": [
        {
            "type": "plugin",
            "name": "Elementor Website Builder",
            "slug": "elementor",
            "affected_versions": {
                "* - 3.13.4": {
                    "from_version": "*",
                    "from_inclusive": True,
                    "to_version": "3.13.4",
                    "to_inclusive": True,
                }
            },
            "patched": True,
            "patched_versions": ["3.13.5"],
            "remediation": "Update to version 3.13.5, or a newer patched version",
        }
    ],
    "informational": False,
    "references": ["https://plugins.trac.wordpress.org/changeset/2900000/elementor"],
    "cwe": {"id": 79, "name": "XSS", "description": "..."},
    "cvss": {
        "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N",
        "score": 6.4,
        "rating": "Medium",
    },
    "cve": "CVE-2023-1234",
    "cve_link": "https://www.cve.org/CVERecord?id=CVE-2023-1234",
    "researchers": ["Someone"],
    "published": "2023-06-01T00:00:00.000000Z",
    "updated": "2024-01-15T10:00:00.000000Z",
    "copyrights": {
        "message": "...",
        "wordfence": {"notice": "...", "license": "...", "license_url": "..."},
    },
}

THEME_RECORD = {
    "id": "0f1a2b3c-0000-4000-8000-000000000002",
    "title": "Astra < 4.1.6 - Something",
    "description": "Theme bug.",
    "software": [
        {
            "type": "theme",
            "name": "Astra",
            "slug": "astra",
            "affected_versions": {
                "* - 4.1.5": {
                    "from_version": "*",
                    "from_inclusive": True,
                    "to_version": "4.1.5",
                    "to_inclusive": True,
                }
            },
            "patched": True,
            "patched_versions": ["4.1.6"],
            "remediation": "Update to 4.1.6",
        }
    ],
    "references": [],
    "cvss": None,
    "cve": None,
    "published": "2023-07-01T00:00:00.000000Z",
}

INFORMATIONAL = {
    "id": "0f1a2b3c-0000-4000-8000-000000000003",
    "title": "Elementor - closed by wordpress.org",
    "description": "",
    "software": [
        {
            "type": "plugin",
            "name": "Elementor",
            "slug": "elementor",
            "affected_versions": {
                "*": {
                    "from_version": "*",
                    "from_inclusive": True,
                    "to_version": "*",
                    "to_inclusive": True,
                }
            },
            "patched": False,
            "patched_versions": [],
            "remediation": "",
        }
    ],
    "informational": True,
    "references": [],
    "published": "2023-07-01T00:00:00.000000Z",
}

FEED = {RECORD["id"]: RECORD, THEME_RECORD["id"]: THEME_RECORD, INFORMATIONAL["id"]: INFORMATIONAL}


def wp_dep(name, kind, slug, version):
    return Dependency(
        name, WORDPRESS, version, version, "lock", "composer.json", kind=kind, slug=slug
    )


def test_parse_wordfence_record_core_fields():
    vuln = parse_wordfence_record(RECORD, RECORD["software"][0])
    assert vuln.id == "CVE-2023-1234"
    assert RECORD["id"] in vuln.aliases
    assert vuln.cve_ids == ["CVE-2023-1234"]
    assert vuln.summary == RECORD["title"]
    assert "Stored XSS" in vuln.details
    assert "3.13.5" in vuln.details  # remediation text included
    assert vuln.severity == "MEDIUM"
    assert vuln.cvss == "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N"
    assert vuln.fixed_versions == ["3.13.5"]
    assert vuln.published == datetime(2023, 6, 1, tzinfo=UTC)
    assert vuln.modified == datetime(2024, 1, 15, 10, 0, tzinfo=UTC)
    assert vuln.url == f"https://www.wordfence.com/threat-intel/vulnerabilities/id/{RECORD['id']}"
    assert "https://plugins.trac.wordpress.org/changeset/2900000/elementor" in vuln.references
    assert "https://www.cve.org/CVERecord?id=CVE-2023-1234" in vuln.references


def test_parse_wordfence_record_without_cve_uses_wordfence_id():
    vuln = parse_wordfence_record(THEME_RECORD, THEME_RECORD["software"][0])
    assert vuln.id == THEME_RECORD["id"]
    assert vuln.cve_ids == []
    assert vuln.severity == "UNKNOWN"
    assert vuln.cvss is None
    assert vuln.modified is None


def test_software_matches_by_type_slug_and_version_range():
    software = RECORD["software"][0]
    assert software_matches(software, "plugin", "elementor", "3.13.4") is True
    assert software_matches(software, "plugin", "elementor", "3.13.5") is False
    assert software_matches(software, "theme", "elementor", "3.13.4") is False
    assert software_matches(software, "plugin", "Elementor", "3.0") is True
    assert software_matches(software, "plugin", "astra", "3.0") is False


def test_software_matches_unknown_version_matches_nothing():
    assert software_matches(RECORD["software"][0], "plugin", "elementor", None) is False


def feed_handler(
    feed: dict, expected_key: str = "KEY", status: int = 200, calls: list | None = None
):
    def handler(request: httpx.Request) -> httpx.Response:
        if calls is not None:
            calls.append(request)
        if request.headers.get("Authorization") != f"Bearer {expected_key}":
            return httpx.Response(
                401, json={"errors": [{"status": 401, "detail": "API key must be supplied"}]}
            )
        if status != 200:
            return httpx.Response(status, text="error")
        assert request.url.path.endswith("/vulnerabilities/production")
        return httpx.Response(200, json=feed)

    return handler


def make_client(handler, tmp_path: Path, api_key="KEY", ttl_hours=24.0) -> WordfenceClient:
    return WordfenceClient(
        api_key=api_key,
        base_url="https://wf.test/api/intelligence/v3",
        timeout=1.0,
        cache_path=tmp_path / "cache" / "wordfence.json",
        ttl_hours=ttl_hours,
        transport=httpx.MockTransport(handler),
    )


def test_find_vulnerabilities_matches_plugins_themes_and_skips_informational(tmp_path: Path):
    client = make_client(feed_handler(FEED), tmp_path)
    elementor = wp_dep("wp-plugin/elementor", "plugin", "elementor", "3.13.4")
    astra_ok = wp_dep("wp-theme/astra", "theme", "astra", "4.1.6")
    core = wp_dep("roots/wordpress", "core", "wordpress", "6.5.2")
    not_wp = Dependency("monolog/monolog", PACKAGIST, "^3", "3.3.1", "lock", "composer.json")
    found = client.find_vulnerabilities([elementor, astra_ok, core, not_wp])
    assert set(found) == {elementor}
    assert [v.id for v in found[elementor]] == ["CVE-2023-1234"]


def test_find_vulnerabilities_matches_theme(tmp_path: Path):
    client = make_client(feed_handler(FEED), tmp_path)
    astra = wp_dep("wp-theme/astra", "theme", "astra", "4.1.0")
    found = client.find_vulnerabilities([astra])
    assert [v.id for v in found[astra]] == [THEME_RECORD["id"]]
    assert found[astra][0].fixed_versions == ["4.1.6"]


def test_find_vulnerabilities_skips_unknown_versions(tmp_path: Path):
    client = make_client(feed_handler(FEED), tmp_path)
    unknown = Dependency(
        "wp-plugin/elementor",
        WORDPRESS,
        "dev-trunk",
        None,
        "unknown",
        "composer.json",
        kind="plugin",
        slug="elementor",
    )
    assert client.find_vulnerabilities([unknown]) == {}


def test_find_vulnerabilities_empty_input_does_not_download(tmp_path: Path):
    calls: list = []
    client = make_client(feed_handler(FEED, calls=calls), tmp_path)
    assert client.find_vulnerabilities([]) == {}
    assert calls == []


def test_feed_is_cached_on_disk_and_reused_while_fresh(tmp_path: Path):
    first = make_client(feed_handler(FEED), tmp_path)
    first.find_vulnerabilities([wp_dep("wp-plugin/elementor", "plugin", "elementor", "3.13.4")])
    cache = tmp_path / "cache" / "wordfence.json"
    assert cache.is_file()

    def failing(request):
        raise httpx.ConnectError("offline")

    second = make_client(failing, tmp_path)
    elementor = wp_dep("wp-plugin/elementor", "plugin", "elementor", "3.13.4")
    found = second.find_vulnerabilities([elementor])
    assert set(found) == {elementor}
    assert second.warnings == []


def test_stale_cache_is_used_with_warning_when_download_fails(tmp_path: Path):
    cache = tmp_path / "cache" / "wordfence.json"
    cache.parent.mkdir(parents=True)
    cache.write_text(json.dumps(FEED))
    old = (datetime.now(UTC) - timedelta(days=3)).timestamp()
    import os

    os.utime(cache, (old, old))

    def failing(request):
        raise httpx.ConnectError("offline")

    client = make_client(failing, tmp_path)
    elementor = wp_dep("wp-plugin/elementor", "plugin", "elementor", "3.13.4")
    found = client.find_vulnerabilities([elementor])
    assert set(found) == {elementor}
    assert any("stale" in w.lower() or "cached" in w.lower() for w in client.warnings)


def test_expired_cache_is_refreshed(tmp_path: Path):
    cache = tmp_path / "cache" / "wordfence.json"
    cache.parent.mkdir(parents=True)
    cache.write_text(json.dumps({}))
    old = (datetime.now(UTC) - timedelta(days=3)).timestamp()
    import os

    os.utime(cache, (old, old))
    client = make_client(feed_handler(FEED), tmp_path)
    elementor = wp_dep("wp-plugin/elementor", "plugin", "elementor", "3.13.4")
    assert set(client.find_vulnerabilities([elementor])) == {elementor}
    assert set(json.loads(cache.read_text())) >= set(FEED)


def test_download_failure_without_cache_raises(tmp_path: Path):
    def failing(request):
        raise httpx.ConnectError("offline")

    client = make_client(failing, tmp_path)
    with pytest.raises(WordfenceError):
        client.find_vulnerabilities(
            [wp_dep("wp-plugin/elementor", "plugin", "elementor", "3.13.4")]
        )


def test_bad_api_key_raises_helpful_error(tmp_path: Path):
    client = make_client(feed_handler(FEED, expected_key="OTHER"), tmp_path)
    with pytest.raises(WordfenceError) as exc:
        client.find_vulnerabilities(
            [wp_dep("wp-plugin/elementor", "plugin", "elementor", "3.13.4")]
        )
    assert "API key" in str(exc.value)


def test_server_error_raises(tmp_path: Path):
    client = make_client(feed_handler(FEED, status=503), tmp_path)
    with pytest.raises(WordfenceError):
        client.find_vulnerabilities(
            [wp_dep("wp-plugin/elementor", "plugin", "elementor", "3.13.4")]
        )


def test_authorization_header_sent(tmp_path: Path):
    calls: list = []
    client = make_client(
        feed_handler(FEED, expected_key="abc123", calls=calls), tmp_path, api_key="abc123"
    )
    client.find_vulnerabilities([wp_dep("wp-plugin/elementor", "plugin", "elementor", "3.13.4")])
    assert calls[0].headers["Authorization"] == "Bearer abc123"
    assert calls[0].url == "https://wf.test/api/intelligence/v3/vulnerabilities/production"


def test_parse_wordfence_record_naive_timestamps_are_utc():
    record = dict(RECORD, published="2020-01-29 00:00:00", updated="2024-01-22 19:56:02")
    vuln = parse_wordfence_record(record, record["software"][0])
    assert vuln.published == datetime(2020, 1, 29, tzinfo=UTC)
    assert vuln.modified == datetime(2024, 1, 22, 19, 56, 2, tzinfo=UTC)


def test_parsed_record_is_marked_as_wordfence_sourced():
    assert parse_wordfence_record(RECORD, RECORD["software"][0]).source == "wordfence"


def test_cache_is_slimmed_but_still_matches(tmp_path: Path):
    client = make_client(feed_handler(FEED), tmp_path)
    elementor = wp_dep("wp-plugin/elementor", "plugin", "elementor", "3.13.4")
    client.find_vulnerabilities([elementor])
    cached = json.loads((tmp_path / "cache" / "wordfence.json").read_text())
    assert RECORD["id"] in cached
    assert "copyrights" not in cached[RECORD["id"]]
    assert "researchers" not in cached[RECORD["id"]]
    assert cached[RECORD["id"]]["software"][0]["patched_versions"] == ["3.13.5"]
    # A second client reading the slim cache still matches and parses fully.
    again = make_client(lambda r: httpx.Response(500), tmp_path)
    found = again.find_vulnerabilities([elementor])
    assert found[elementor][0].id == "CVE-2023-1234"
    assert found[elementor][0].fixed_versions == ["3.13.5"]


# --- rate limiting: never hit the API more than once per minimum interval ------------------


def make_guarded_client(handler, tmp_path: Path, min_interval_minutes=30.0, ttl_hours=24.0):
    return WordfenceClient(
        api_key="KEY",
        base_url="https://wf.test/api/intelligence/v3",
        timeout=1.0,
        cache_path=tmp_path / "cache" / "wordfence.json",
        ttl_hours=ttl_hours,
        min_interval_minutes=min_interval_minutes,
        transport=httpx.MockTransport(handler),
    )


def test_failed_download_is_not_retried_within_minimum_interval(tmp_path: Path):
    calls: list = []

    def failing(request):
        calls.append(request)
        raise httpx.ConnectError("offline")

    elementor = wp_dep("wp-plugin/elementor", "plugin", "elementor", "3.13.4")
    with pytest.raises(WordfenceError):
        make_guarded_client(failing, tmp_path).find_vulnerabilities([elementor])
    assert len(calls) == 1
    with pytest.raises(WordfenceError) as exc:
        make_guarded_client(failing, tmp_path).find_vulnerabilities([elementor])
    assert len(calls) == 1  # second client did not touch the API
    assert "minute" in str(exc.value).lower()


def test_rejected_key_is_not_retried_within_minimum_interval(tmp_path: Path):
    calls: list = []
    handler = feed_handler(FEED, expected_key="OTHER", calls=calls)
    elementor = wp_dep("wp-plugin/elementor", "plugin", "elementor", "3.13.4")
    with pytest.raises(WordfenceError):
        make_guarded_client(handler, tmp_path).find_vulnerabilities([elementor])
    with pytest.raises(WordfenceError):
        make_guarded_client(handler, tmp_path).find_vulnerabilities([elementor])
    assert len(calls) == 1


def test_stale_cache_used_without_api_call_within_minimum_interval(tmp_path: Path):
    calls: list = []

    def failing(request):
        calls.append(request)
        raise httpx.ConnectError("offline")

    cache = tmp_path / "cache" / "wordfence.json"
    cache.parent.mkdir(parents=True)
    cache.write_text(json.dumps(FEED))
    old = (datetime.now(UTC) - timedelta(days=3)).timestamp()
    import os

    os.utime(cache, (old, old))
    elementor = wp_dep("wp-plugin/elementor", "plugin", "elementor", "3.13.4")
    first = make_guarded_client(failing, tmp_path)
    assert set(first.find_vulnerabilities([elementor])) == {elementor}
    second = make_guarded_client(failing, tmp_path)
    assert set(second.find_vulnerabilities([elementor])) == {elementor}
    assert len(calls) == 1
    assert second.warnings


def test_attempts_are_allowed_again_after_interval(tmp_path: Path):
    calls: list = []

    def failing(request):
        calls.append(request)
        raise httpx.ConnectError("offline")

    elementor = wp_dep("wp-plugin/elementor", "plugin", "elementor", "3.13.4")
    with pytest.raises(WordfenceError):
        make_guarded_client(failing, tmp_path, min_interval_minutes=0).find_vulnerabilities(
            [elementor]
        )
    with pytest.raises(WordfenceError):
        make_guarded_client(failing, tmp_path, min_interval_minutes=0).find_vulnerabilities(
            [elementor]
        )
    assert len(calls) == 2


def test_fresh_cache_never_contacts_api_even_with_rescans(tmp_path: Path):
    calls: list = []
    handler = feed_handler(FEED, calls=calls)
    elementor = wp_dep("wp-plugin/elementor", "plugin", "elementor", "3.13.4")
    for _ in range(5):
        client = make_guarded_client(handler, tmp_path)
        client.find_vulnerabilities([elementor])
        client.find_vulnerabilities([elementor])
    assert len(calls) == 1


# --- conditional requests: a refresh after the TTL should be a 304 when nothing changed ------


def etag_handler(feed: dict, etag: str, calls: list):
    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if request.headers.get("Authorization") != "Bearer KEY":
            return httpx.Response(401)
        if request.headers.get("If-None-Match") == etag:
            return httpx.Response(304)
        return httpx.Response(
            200, json=feed, headers={"ETag": etag, "Last-Modified": "Tue, 06 Oct 2026 10:00:00 GMT"}
        )

    return handler


def test_refresh_uses_etag_and_accepts_304(tmp_path: Path):
    calls: list = []
    handler = etag_handler(FEED, '"abc123"', calls)
    elementor = wp_dep("wp-plugin/elementor", "plugin", "elementor", "3.13.4")
    make_guarded_client(handler, tmp_path).find_vulnerabilities([elementor])
    cache = tmp_path / "cache" / "wordfence.json"
    old = (datetime.now(UTC) - timedelta(days=3)).timestamp()
    import os

    os.utime(cache, (old, old))
    client = make_guarded_client(handler, tmp_path, min_interval_minutes=0)
    found = client.find_vulnerabilities([elementor])
    assert set(found) == {elementor}
    assert len(calls) == 2
    assert calls[1].headers.get("If-None-Match") == '"abc123"'
    assert calls[1].headers.get("If-Modified-Since") == "Tue, 06 Oct 2026 10:00:00 GMT"
    assert client.warnings == []
    # The 304 refreshed the cache's freshness: a third client needs no request at all.
    make_guarded_client(handler, tmp_path).find_vulnerabilities([elementor])
    assert len(calls) == 2


def test_parse_wordfence_record_records_affected_ranges():
    vuln = parse_wordfence_record(RECORD, RECORD["software"][0])
    assert len(vuln.affected_ranges) == 1
    assert vuln.affects("3.13.4", WORDPRESS) is True
    assert vuln.affects("3.13.5", WORDPRESS) is False
