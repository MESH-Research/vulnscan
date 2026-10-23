"""Tests for vulnscan.risk scoring."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import httpx

from vulnscan.models import PYPI, Dependency, Vulnerability
from vulnscan.osv import OSVClient
from vulnscan.registry import RegistryClient
from vulnscan.risk import RiskKind, is_malware_advisory, score_for, score_versions


def test_is_malware_advisory_mal_prefix():
    vuln = Vulnerability("MAL-2024-1234", "bad", "details")
    assert is_malware_advisory(vuln) is True


def test_is_malware_advisory_database_specific():
    vuln = Vulnerability("GHSA-xxxx", "summary", "details")
    assert is_malware_advisory(vuln, {"database_specific": {"malicious": True}}) is True


def test_score_versions_advisory_and_fresh():
    now = datetime(2024, 6, 1, 12, 0, tzinfo=UTC)
    published = now - timedelta(hours=3)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "api.osv.dev" and request.url.path == "/v1/querybatch":
            return httpx.Response(
                200,
                json={"results": [{"vulns": [{"id": "GHSA-test"}]}]},
            )
        if request.url.host == "api.osv.dev" and request.url.path == "/v1/vulns/GHSA-test":
            return httpx.Response(
                200,
                json={
                    "id": "GHSA-test",
                    "summary": "A vuln",
                    "affected": [
                        {
                            "package": {"ecosystem": "PyPI", "name": "demo"},
                            "ranges": [
                                {
                                    "type": "ECOSYSTEM",
                                    "events": [{"introduced": "0"}, {"fixed": "2.0.0"}],
                                }
                            ],
                        }
                    ],
                },
            )
        if request.url.host == "pypi.org":
            return httpx.Response(
                200,
                json={
                    "releases": {
                        "1.0.0": [
                            {
                                "yanked": False,
                                "upload_time_iso_8601": published.isoformat().replace(
                                    "+00:00", "Z"
                                ),
                            }
                        ]
                    }
                },
            )
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    osv = OSVClient(base_url="https://api.osv.dev", timeout=1.0, transport=transport)
    registry = RegistryClient(timeout=1.0, transport=transport)
    dep = Dependency("demo", PYPI, "==1.0.0", "1.0.0", "pinned", "pyproject.toml")
    scores = score_versions([dep], osv=osv, registry=registry, fresh_hours=24, now=now)
    score = score_for(scores, dep, "1.0.0")
    assert score is not None
    kinds = {r.kind for r in score.risks}
    assert RiskKind.ADVISORY in kinds
    assert RiskKind.FRESH in kinds
    assert score.has_blocking is True
    assert score.is_fresh is True


def test_score_versions_malware_mal_id():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/querybatch":
            return httpx.Response(200, json={"results": [{"vulns": [{"id": "MAL-2024-1"}]}]})
        if request.url.path == "/v1/vulns/MAL-2024-1":
            return httpx.Response(
                200,
                json={
                    "id": "MAL-2024-1",
                    "summary": "malicious package",
                    "affected": [
                        {
                            "package": {"ecosystem": "PyPI", "name": "evil"},
                            "versions": ["1.0.0"],
                        }
                    ],
                },
            )
        if request.url.host == "pypi.org":
            return httpx.Response(
                200,
                json={
                    "releases": {
                        "1.0.0": [
                            {
                                "yanked": False,
                                "upload_time_iso_8601": "2020-01-01T00:00:00Z",
                            }
                        ]
                    }
                },
            )
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    osv = OSVClient(base_url="https://api.osv.dev", timeout=1.0, transport=transport)
    registry = RegistryClient(timeout=1.0, transport=transport)
    dep = Dependency("evil", PYPI, "==1.0.0", "1.0.0", "pinned", "pyproject.toml")
    scores = score_versions([dep], osv=osv, registry=registry, fresh_hours=24)
    score = score_for(scores, dep, "1.0.0")
    assert score is not None
    assert any(r.kind == RiskKind.MALWARE for r in score.risks)


def test_score_versions_never_sends_container_images_to_osv():
    from vulnscan.models import CONTAINER
    from vulnscan.registry import RegistryError

    class RefusingOSV:
        def find_vulnerabilities(self, deps, include_unknown_versions=False):
            offenders = [d.name for d in deps if d.ecosystem != PYPI]
            assert not offenders, f"sent to OSV although it cannot index them: {offenders}"
            return {}

    class OfflineRegistry:
        def release_info(self, dep):
            raise RegistryError("offline")

    image = Dependency("php", CONTAINER, "8.2.20", "8.2.20", "pinned", "Dockerfile", kind="image")
    package = Dependency("demo", PYPI, "==1.0.0", "1.0.0", "pinned", "requirements.txt")
    scores = score_versions([image, package], osv=RefusingOSV(), registry=OfflineRegistry())
    image_score = score_for(scores, image, "8.2.20")
    assert image_score is not None
    assert image_score.risks == ()
    assert score_for(scores, package, "1.0.0") is not None
