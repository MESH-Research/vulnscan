import pytest

from vulnscan import activity
from vulnscan.activity import Transfer


@pytest.fixture(autouse=True)
def _clean():
    activity.reset()
    yield
    activity.reset()


def _transfer(**kwargs) -> Transfer:
    base = {"id": 1, "method": "GET", "url": "https://pypi.org/pypi/requests/json", "started": 10.0}
    base.update(kwargs)
    return Transfer(**base)


def test_transfer_is_not_done_until_finished_is_set():
    assert _transfer().done is False
    assert _transfer(finished=11.0).done is True


def test_transfer_failed_only_when_an_error_is_recorded():
    assert _transfer(finished=11.0, status=200).failed is False
    assert _transfer(finished=11.0, error="boom").failed is True


def test_fraction_is_received_over_total_capped_at_one():
    assert _transfer(total=200, received=50).fraction == 0.25
    assert _transfer(total=200, received=300).fraction == 1.0


def test_fraction_is_unknown_without_a_total():
    assert _transfer(received=50).fraction is None
    assert _transfer(total=0, received=0).fraction is None


def test_subscribers_receive_published_snapshots_until_unsubscribed():
    seen = []
    activity.subscribe(seen.append)
    first = _transfer()
    activity.publish(first)
    activity.unsubscribe(seen.append)
    activity.publish(_transfer(id=2))
    assert seen == [first]


def test_unsubscribing_an_unknown_observer_is_harmless():
    activity.unsubscribe(lambda transfer: None)


def test_an_observer_that_raises_does_not_stop_the_others():
    seen = []

    def bad(transfer):
        raise RuntimeError("observer broke")

    activity.subscribe(bad)
    activity.subscribe(seen.append)
    activity.publish(_transfer())
    assert len(seen) == 1


def test_ids_are_unique_and_increasing():
    a, b = activity.next_id(), activity.next_id()
    assert b > a


@pytest.mark.parametrize(
    ("method", "url", "expected"),
    [
        ("POST", "https://api.osv.dev/v1/querybatch", "OSV querybatch"),
        ("POST", "https://api.osv.dev/v1/query", "OSV query"),
        ("GET", "https://api.osv.dev/v1/vulns/GHSA-j8r2-6x86-q33q", "OSV GHSA-j8r2-6x86-q33q"),
        ("GET", "https://pypi.org/pypi/requests/json", "PyPI requests"),
        ("GET", "https://registry.npmjs.org/%40babel%2Fcore", "npm @babel/core"),
        ("GET", "https://registry.npmjs.org/lodash", "npm lodash"),
        ("GET", "https://repo.packagist.org/p2/monolog/monolog.json", "Packagist monolog/monolog"),
        (
            "GET",
            "https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&slug=elementor",
            "wordpress.org elementor",
        ),
        (
            "GET",
            "https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production",
            "Wordfence feed",
        ),
        (
            "GET",
            "https://services.nvd.nist.gov/rest/json/cves/2.0?virtualMatchString=cpe%3A2.3%3Aa%3Aphp%3Aphp%3A8.2.19&resultsPerPage=2000&startIndex=0",
            "NVD php:php:8.2.19",
        ),
        (
            "GET",
            "https://registry-1.docker.io/v2/library/php/tags/list?n=1000",
            "Docker Hub library/php tags",
        ),
        ("GET", "https://ghcr.io/v2/astral-sh/uv/tags/list?n=1000", "ghcr.io astral-sh/uv tags"),
        (
            "GET",
            "https://auth.docker.io/token?service=registry.docker.io&scope=x",
            "auth.docker.io token",
        ),
        ("POST", "https://ntfy.sh/", "POST ntfy.sh/"),
        ("GET", "https://example.test/some/path?k=v", "GET example.test/some/path"),
    ],
)
def test_describe_gives_short_labels(method, url, expected):
    assert activity.describe(method, url) == expected


@pytest.mark.parametrize(
    ("count", "expected"),
    [
        (0, "0 B"),
        (46, "46 B"),
        (12_400, "12.4 kB"),
        (73_200_000, "73.2 MB"),
        (2_500_000_000, "2.5 GB"),
    ],
)
def test_format_bytes(count, expected):
    assert activity.format_bytes(count) == expected
