import json
from datetime import UTC, datetime

import httpx
import pytest

from vulnscan.models import PACKAGIST, PYPI, Dependency, Vulnerability
from vulnscan.osv import OSVClient, OSVError, dedupe_vulnerabilities, parse_osv_vulnerability

GHSA = {
    "id": "GHSA-j8r2-6x86-q33q",
    "summary": "Unintended leak of Proxy-Authorization header in requests",
    "details": "Long description.",
    "aliases": ["CVE-2023-32681", "PYSEC-2023-74"],
    "published": "2023-05-26T19:30:00Z",
    "modified": "2024-02-01T10:00:00.123456Z",
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"}],
    "database_specific": {"severity": "MODERATE"},
    "references": [
        {"type": "ADVISORY", "url": "https://nvd.nist.gov/vuln/detail/CVE-2023-32681"},
        {"type": "WEB", "url": "https://github.com/psf/requests/releases/tag/v2.31.0"},
    ],
    "affected": [
        {
            "package": {"ecosystem": "PyPI", "name": "Requests"},
            "ranges": [
                {"type": "ECOSYSTEM", "events": [{"introduced": "2.3.0"}, {"fixed": "2.31.0"}]}
            ],
        },
        {
            "package": {"ecosystem": "PyPI", "name": "other-package"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "9.9.9"}]}],
        },
    ],
}


def test_parse_osv_vulnerability_core_fields():
    vuln = parse_osv_vulnerability(GHSA, "requests", PYPI)
    assert vuln.id == "GHSA-j8r2-6x86-q33q"
    assert vuln.summary.startswith("Unintended leak")
    assert vuln.details == "Long description."
    assert vuln.aliases == ["CVE-2023-32681", "PYSEC-2023-74"]
    assert vuln.cve_ids == ["CVE-2023-32681"]
    assert vuln.severity == "MEDIUM"
    assert vuln.cvss == "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"
    assert vuln.published == datetime(2023, 5, 26, 19, 30, tzinfo=UTC)
    assert vuln.modified == datetime(2024, 2, 1, 10, 0, 0, 123456, tzinfo=UTC)
    assert vuln.references == [
        "https://nvd.nist.gov/vuln/detail/CVE-2023-32681",
        "https://github.com/psf/requests/releases/tag/v2.31.0",
    ]


def test_parse_osv_vulnerability_fixed_versions_only_for_matching_package():
    vuln = parse_osv_vulnerability(GHSA, "requests", PYPI)
    assert vuln.fixed_versions == ["2.31.0"]


def test_parse_osv_vulnerability_packagist_fixed_versions_normalised():
    data = {
        "id": "GHSA-1",
        "affected": [
            {
                "package": {"ecosystem": "Packagist", "name": "Monolog/Monolog"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "v1.0.1"}]},
                    {"type": "ECOSYSTEM", "events": [{"introduced": "2.0.0"}, {"fixed": "2.0.2"}]},
                ],
            }
        ],
    }
    vuln = parse_osv_vulnerability(data, "monolog/monolog", PACKAGIST)
    assert vuln.fixed_versions == ["1.0.1", "2.0.2"]


def test_parse_osv_vulnerability_tolerates_missing_fields():
    vuln = parse_osv_vulnerability({"id": "PYSEC-2024-1"}, "x", PYPI)
    assert vuln.summary == ""
    assert vuln.details == ""
    assert vuln.severity == "UNKNOWN"
    assert vuln.cvss is None
    assert vuln.published is None
    assert vuln.fixed_versions == []
    assert vuln.references == []


def test_parse_osv_vulnerability_severity_from_ecosystem_specific():
    data = {
        "id": "PYSEC-2024-1",
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "x"},
                "ecosystem_specific": {"severity": "high"},
            }
        ],
    }
    assert parse_osv_vulnerability(data, "x", PYPI).severity == "HIGH"


def test_parse_osv_vulnerability_summary_falls_back_to_first_line_of_details():
    data = {"id": "PYSEC-2024-1", "details": "First line.\n\nMore."}
    assert parse_osv_vulnerability(data, "x", PYPI).summary == "First line."


def test_dedupe_vulnerabilities_merges_entries_sharing_aliases():
    ghsa = Vulnerability(
        "GHSA-1",
        "s",
        "d",
        aliases=["CVE-2024-1", "PYSEC-1"],
        severity="HIGH",
        fixed_versions=["1.1"],
    )
    pysec = Vulnerability(
        "PYSEC-1", "", "d2", aliases=["CVE-2024-1", "GHSA-1"], fixed_versions=["1.1", "1.0.5"]
    )
    other = Vulnerability("GHSA-2", "s2", "d", aliases=["CVE-2024-2"])
    result = dedupe_vulnerabilities([pysec, ghsa, other])
    assert [v.id for v in result] == ["GHSA-1", "GHSA-2"]
    merged = result[0]
    assert merged.severity == "HIGH"
    assert set(merged.aliases) >= {"CVE-2024-1", "PYSEC-1"}
    assert merged.fixed_versions == ["1.0.5", "1.1"]


def test_dedupe_vulnerabilities_keeps_unrelated_entries():
    a = Vulnerability("GHSA-1", "s", "d")
    b = Vulnerability("GHSA-2", "s", "d")
    assert [v.id for v in dedupe_vulnerabilities([a, b])] == ["GHSA-1", "GHSA-2"]


def dep(name="requests", ecosystem=PYPI, version="2.30.0"):
    return Dependency(name, ecosystem, f"=={version}", version, "pinned", "requirements.txt")


def make_client(handler) -> OSVClient:
    return OSVClient("https://osv.test", timeout=1.0, transport=httpx.MockTransport(handler))


def osv_handler(batch_results, vulns: dict, query_pages: dict | None = None):
    """Build a fake OSV API. batch_results: list of result dicts in query order."""

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/v1/querybatch":
            body = json.loads(request.content)
            n = len(body["queries"])
            assert n <= 1000
            # Return results keyed by package name so chunking order does not matter.
            results = []
            for q in body["queries"]:
                results.append(batch_results.get(q["package"]["name"], {}))
            return httpx.Response(200, json={"results": results})
        if path == "/v1/query":
            body = json.loads(request.content)
            token = body.get("page_token")
            page = (query_pages or {})[token]
            return httpx.Response(200, json=page)
        if path.startswith("/v1/vulns/"):
            vuln_id = path.rsplit("/", 1)[1]
            if vuln_id in vulns:
                return httpx.Response(200, json=vulns[vuln_id])
            return httpx.Response(404, json={"code": 5, "message": "not found"})
        return httpx.Response(404)

    return handler


def test_query_batch_returns_ids_aligned_with_dependencies():
    handler = osv_handler(
        {
            "requests": {"vulns": [{"id": "GHSA-A", "modified": "2024-01-01T00:00:00Z"}]},
            "flask": {},
        },
        {},
    )
    client = make_client(handler)
    assert client.query_batch([dep("requests"), dep("flask", version="3.0.0")]) == [["GHSA-A"], []]


def test_query_batch_sends_version_and_ecosystem():
    captured = {}

    def handler(request):
        captured.update(json.loads(request.content))
        return httpx.Response(200, json={"results": [{}]})

    make_client(handler).query_batch([dep("monolog/monolog", PACKAGIST, "2.0.0")])
    assert captured["queries"][0] == {
        "package": {"name": "monolog/monolog", "ecosystem": "Packagist"},
        "version": "2.0.0",
    }


def test_query_batch_handles_more_than_one_thousand_dependencies():
    names = [f"pkg{i}" for i in range(1500)]
    handler = osv_handler(
        {"pkg7": {"vulns": [{"id": "GHSA-7"}]}, "pkg1400": {"vulns": [{"id": "GHSA-1400"}]}}, {}
    )
    results = make_client(handler).query_batch([dep(n) for n in names])
    assert len(results) == 1500
    assert results[7] == ["GHSA-7"]
    assert results[1400] == ["GHSA-1400"]
    assert results[0] == []


def test_query_batch_follows_pagination():
    handler = osv_handler(
        {"requests": {"vulns": [{"id": "GHSA-A"}], "next_page_token": "p2"}},
        {},
        query_pages={
            "p2": {"vulns": [{"id": "GHSA-B"}], "next_page_token": "p3"},
            "p3": {"vulns": [{"id": "GHSA-C"}]},
        },
    )
    assert make_client(handler).query_batch([dep("requests")]) == [["GHSA-A", "GHSA-B", "GHSA-C"]]


def test_query_batch_raises_on_http_error():
    client = make_client(lambda request: httpx.Response(500, text="boom"))
    with pytest.raises(OSVError):
        client.query_batch([dep()])


def test_query_batch_raises_on_connection_error():
    def handler(request):
        raise httpx.ConnectError("no network")

    with pytest.raises(OSVError):
        make_client(handler).query_batch([dep()])


def test_query_batch_empty_input():
    client = make_client(lambda request: httpx.Response(500))
    assert client.query_batch([]) == []


def test_get_vulnerability_parses_response():
    client = make_client(osv_handler({}, {"GHSA-j8r2-6x86-q33q": GHSA}))
    vuln = client.get_vulnerability("GHSA-j8r2-6x86-q33q", "requests", PYPI)
    assert vuln.id == "GHSA-j8r2-6x86-q33q"
    assert vuln.fixed_versions == ["2.31.0"]


def test_get_vulnerability_raises_on_missing():
    client = make_client(osv_handler({}, {}))
    with pytest.raises(OSVError):
        client.get_vulnerability("GHSA-nope", "requests", PYPI)


def test_find_vulnerabilities_groups_by_dependency_and_dedupes():
    pysec = {
        "id": "PYSEC-2023-74",
        "aliases": ["CVE-2023-32681", "GHSA-j8r2-6x86-q33q"],
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "requests"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.31.0"}]}
                ],
            }
        ],
    }
    other = {"id": "GHSA-zzzz", "summary": "Other", "affected": []}
    handler = osv_handler(
        {
            "requests": {
                "vulns": [
                    {"id": "GHSA-j8r2-6x86-q33q"},
                    {"id": "PYSEC-2023-74"},
                    {"id": "GHSA-zzzz"},
                ]
            },
            "flask": {},
        },
        {"GHSA-j8r2-6x86-q33q": GHSA, "PYSEC-2023-74": pysec, "GHSA-zzzz": other},
    )
    requests_dep, flask_dep = dep("requests"), dep("flask", version="3.0.0")
    found = make_client(handler).find_vulnerabilities([requests_dep, flask_dep])
    assert set(found) == {requests_dep}
    assert [v.id for v in found[requests_dep]] == ["GHSA-j8r2-6x86-q33q", "GHSA-zzzz"]
    assert found[requests_dep][0].fixed_versions == ["2.31.0"]


def test_find_vulnerabilities_skips_dependencies_without_version():
    captured = []

    def handler(request):
        captured.append(json.loads(request.content))
        return httpx.Response(
            200, json={"results": [{} for _ in json.loads(request.content)["queries"]]}
        )

    unknown = Dependency("flask", PYPI, "", None, "unknown", "requirements.txt")
    assert make_client(handler).find_vulnerabilities([unknown]) == {}
    assert captured == []


def test_find_vulnerabilities_queries_unknown_versions_when_asked():
    captured = []

    def handler(request):
        body = json.loads(request.content)
        captured.extend(body["queries"])
        return httpx.Response(200, json={"results": [{} for _ in body["queries"]]})

    unknown = Dependency("flask", PYPI, "", None, "unknown", "requirements.txt")
    make_client(handler).find_vulnerabilities([unknown], include_unknown_versions=True)
    assert captured == [{"package": {"name": "flask", "ecosystem": "PyPI"}}]


def test_parse_osv_vulnerability_ignores_git_commit_ranges():
    data = {
        "id": "GHSA-git",
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "requests"},
                "ranges": [
                    {
                        "type": "GIT",
                        "repo": "https://github.com/psf/requests",
                        "events": [
                            {"introduced": "0"},
                            {"fixed": "74ea7cf7a6a27a4eeb2ae24e162bcc942a6706d5"},
                        ],
                    },
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.32.4"}]},
                ],
            }
        ],
    }
    assert parse_osv_vulnerability(data, "requests", PYPI).fixed_versions == ["2.32.4"]


def test_parse_osv_vulnerability_records_affected_ranges_and_versions():
    data = {
        "id": "GHSA-r",
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "requests"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "2.3.0"}, {"fixed": "2.31.0"}]},
                    {
                        "type": "GIT",
                        "repo": "x",
                        "events": [{"introduced": "0"}, {"fixed": "abcdef"}],
                    },
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "3.0.0"}, {"last_affected": "3.0.5"}],
                    },
                ],
                "versions": ["2.3.0", "2.30.0"],
            }
        ],
    }
    vuln = parse_osv_vulnerability(data, "requests", PYPI)
    assert len(vuln.affected_ranges) == 2
    assert vuln.affected_versions == ["2.3.0", "2.30.0"]
    assert vuln.affects("2.30.0", PYPI) is True
    assert vuln.affects("2.31.0", PYPI) is False
    assert vuln.affects("3.0.5", PYPI) is True
    assert vuln.affects("3.0.6", PYPI) is False
