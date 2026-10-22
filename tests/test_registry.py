import httpx
import pytest

from vulnscan.models import CONTAINER, NPM, PACKAGIST, PYPI, WORDPRESS, Dependency
from vulnscan.registry import RegistryClient, RegistryError


def make_client(handler) -> RegistryClient:
    return RegistryClient(timeout=1.0, transport=httpx.MockTransport(handler))


def pypi_handler(request: httpx.Request) -> httpx.Response:
    assert request.url.host == "pypi.org"
    if request.url.path == "/pypi/requests/json":
        return httpx.Response(
            200,
            json={
                "info": {"version": "2.32.4"},
                "releases": {
                    "2.30.0": [{"yanked": False}],
                    "2.31.0": [{"yanked": False}],
                    "2.32.0": [{"yanked": True}],
                    "2.32.4": [{"yanked": False}],
                    "2.33.0rc1": [{"yanked": False}],
                    "2.9.2": [{"yanked": False}],
                    "3.0.0.dev1": [{"yanked": False}],
                    "2.0.0": [],
                },
            },
        )
    return httpx.Response(404, json={"message": "Not Found"})


def test_pypi_versions_sorted_stable_unyanked():
    dep = Dependency("Requests", PYPI, "==2.30.0", "2.30.0", "pinned", "requirements.txt")
    assert make_client(pypi_handler).available_versions(dep) == [
        "2.9.2",
        "2.30.0",
        "2.31.0",
        "2.32.4",
    ]


def test_pypi_missing_package_raises():
    dep = Dependency("nope", PYPI, "", None, "unknown", "requirements.txt")
    with pytest.raises(RegistryError):
        make_client(pypi_handler).available_versions(dep)


def packagist_handler(request: httpx.Request) -> httpx.Response:
    assert request.url.host == "repo.packagist.org"
    if request.url.path == "/p2/monolog/monolog.json":
        return httpx.Response(
            200,
            json={
                "packages": {
                    "monolog/monolog": [
                        {"version": "3.3.1", "version_normalized": "3.3.1.0"},
                        {"version": "3.4.0-RC1", "version_normalized": "3.4.0.0-RC1"},
                        {"version": "v2.9.1", "version_normalized": "2.9.1.0"},
                        {"version": "3.10.0", "version_normalized": "3.10.0.0"},
                        {"version": "dev-main", "version_normalized": "dev-main"},
                    ]
                }
            },
        )
    return httpx.Response(404)


def test_packagist_versions_sorted_stable():
    dep = Dependency("Monolog/Monolog", PACKAGIST, "^3", "3.3.1", "lock", "composer.json")
    assert make_client(packagist_handler).available_versions(dep) == ["2.9.1", "3.3.1", "3.10.0"]


def test_packagist_missing_package_raises():
    dep = Dependency("acme/nope", PACKAGIST, "^1", "1.0", "lock", "composer.json")
    with pytest.raises(RegistryError):
        make_client(packagist_handler).available_versions(dep)


def wordpress_handler(request: httpx.Request) -> httpx.Response:
    assert request.url.host == "api.wordpress.org"
    params = dict(request.url.params)
    if request.url.path.startswith("/plugins/info/"):
        if params.get("request[slug]") == "elementor":
            return httpx.Response(
                200,
                json={
                    "slug": "elementor",
                    "version": "3.20.0",
                    "versions": {
                        "3.13.4": "u",
                        "3.16.5": "u",
                        "3.20.0": "u",
                        "3.9.1": "u",
                        "trunk": "u",
                    },
                },
            )
        return httpx.Response(200, json={"error": "Plugin not found."})
    if request.url.path.startswith("/themes/info/"):
        if params.get("request[slug]") == "astra":
            return httpx.Response(
                200,
                json={
                    "slug": "astra",
                    "version": "4.8.0",
                    "versions": {"4.1.5": "u", "4.8.0": "u"},
                },
            )
        return httpx.Response(200, json={"error": "Theme not found"})
    if request.url.path.startswith("/core/version-check/"):
        return httpx.Response(
            200,
            json={
                "offers": [
                    {"response": "upgrade", "version": "7.1.3"},
                    {"response": "autoupdate", "version": "7.0.7"},
                ]
            },
        )
    return httpx.Response(404)


def test_wordpress_plugin_versions():
    dep = Dependency(
        "wp-plugin/elementor",
        WORDPRESS,
        "3.13.4",
        "3.13.4",
        "lock",
        "composer.json",
        kind="plugin",
        slug="elementor",
    )
    assert make_client(wordpress_handler).available_versions(dep) == [
        "3.9.1",
        "3.13.4",
        "3.16.5",
        "3.20.0",
    ]


def test_wordpress_theme_versions():
    dep = Dependency(
        "wp-theme/astra",
        WORDPRESS,
        "^4.1",
        "4.1.5",
        "lock",
        "composer.json",
        kind="theme",
        slug="astra",
    )
    assert make_client(wordpress_handler).available_versions(dep) == ["4.1.5", "4.8.0"]


def test_wordpress_core_versions():
    dep = Dependency(
        "roots/wordpress",
        WORDPRESS,
        "7.0.6",
        "7.0.6",
        "lock",
        "composer.json",
        kind="core",
        slug="wordpress",
    )
    assert make_client(wordpress_handler).available_versions(dep) == ["7.0.7", "7.1.3"]


def test_wordpress_missing_plugin_raises():
    dep = Dependency(
        "wp-plugin/nope",
        WORDPRESS,
        "1.0",
        "1.0",
        "lock",
        "composer.json",
        kind="plugin",
        slug="nope",
    )
    with pytest.raises(RegistryError):
        make_client(wordpress_handler).available_versions(dep)


def test_network_error_raises():
    def failing(request):
        raise httpx.ConnectError("offline")

    dep = Dependency("requests", PYPI, "", "1", "pinned", "requirements.txt")
    with pytest.raises(RegistryError):
        make_client(failing).available_versions(dep)


def test_unknown_ecosystem_raises():
    dep = Dependency("x", "Cargo", "", "1", "pinned", "Cargo.toml")
    with pytest.raises(RegistryError):
        make_client(lambda r: httpx.Response(500)).available_versions(dep)


# --- npm ----------------------------------------------------------------------------------


def npm_handler(request: httpx.Request) -> httpx.Response:
    assert request.url.host == "registry.npmjs.org"
    if request.url.path == "/express":
        return httpx.Response(
            200,
            json={
                "name": "express",
                "dist-tags": {"latest": "4.19.2", "next": "5.0.0-beta.3"},
                "versions": {
                    "4.18.2": {"version": "4.18.2"},
                    "4.19.0": {"version": "4.19.0", "deprecated": "use 4.19.2"},
                    "4.19.2": {"version": "4.19.2"},
                    "5.0.0-beta.3": {"version": "5.0.0-beta.3"},
                    "4.9.0": {"version": "4.9.0"},
                },
            },
        )
    if request.url.path in ("/@babel%2Fcore", "/@babel/core"):
        return httpx.Response(
            200, json={"name": "@babel/core", "versions": {"7.23.0": {}, "7.23.5": {}}}
        )
    return httpx.Response(404, json={"error": "Not found"})


def test_npm_versions_sorted_stable():
    dep = Dependency("express", NPM, "^4.18.2", "4.18.2", "constraint", "package.json")
    assert make_client(npm_handler).available_versions(dep) == [
        "4.9.0",
        "4.18.2",
        "4.19.0",
        "4.19.2",
    ]


def test_npm_scoped_package_is_url_encoded():
    dep = Dependency("@babel/core", NPM, "^7.23.0", "7.23.0", "constraint", "package.json")
    assert make_client(npm_handler).available_versions(dep) == ["7.23.0", "7.23.5"]


def test_npm_missing_package_raises():
    dep = Dependency("nope", NPM, "", None, "unknown", "package.json")
    with pytest.raises(RegistryError):
        make_client(npm_handler).available_versions(dep)


# --- container images -----------------------------------------------------------------------


def docker_handler(request: httpx.Request) -> httpx.Response:
    """Docker Hub style: a 401 challenge, an anonymous token, then one page of tags."""
    host = request.url.host
    if host == "auth.docker.io":
        assert request.url.params["service"] == "registry.docker.io"
        assert request.url.params["scope"] == "repository:library/php:pull"
        return httpx.Response(200, json={"token": "anon-token"})
    if host == "registry-1.docker.io":
        if request.headers.get("Authorization") != "Bearer anon-token":
            return httpx.Response(
                401,
                headers={
                    "WWW-Authenticate": 'Bearer realm="https://auth.docker.io/token",'
                    'service="registry.docker.io",scope="repository:library/php:pull"'
                },
                json={"errors": [{"code": "UNAUTHORIZED"}]},
            )
        assert request.url.path == "/v2/library/php/tags/list"
        return httpx.Response(
            200,
            json={
                "name": "library/php",
                "tags": [
                    "latest",
                    "8.2-fpm-bookworm",
                    "8.2.19-fpm-bookworm",
                    "8.2.20-fpm-bookworm",
                    "8.2.20-fpm",
                    "8.2.20RC1-fpm-bookworm",
                    "8.3.8-fpm-bookworm",
                    "8.3.9-fpm-bookworm",
                    "8.2.9-fpm-bookworm",
                    "8.4.0-rc1-fpm-bookworm",
                    "8.2.20-cli",
                    "fpm-bookworm",
                ],
            },
        )
    return httpx.Response(404)


def test_docker_hub_tags_filtered_to_the_same_variant_and_sorted():
    dep = Dependency(
        "php", CONTAINER, "8.2.19-fpm-bookworm", "8.2.19", "pinned", "Dockerfile", kind="image"
    )
    assert make_client(docker_handler).available_versions(dep) == [
        "8.2.9",
        "8.2.19",
        "8.2.20",
        "8.3.8",
        "8.3.9",
    ]


def test_docker_hub_tags_for_an_untagged_variant():
    dep = Dependency("php", CONTAINER, "8.2-fpm", "8.2", "constraint", "Dockerfile", kind="image")
    assert make_client(docker_handler).available_versions(dep) == ["8.2.20"]


def ghcr_handler(request: httpx.Request) -> httpx.Response:
    """ghcr.io style: token endpoint on the same host and Link-header pagination."""
    assert request.url.host == "ghcr.io"
    if request.url.path == "/token":
        return httpx.Response(200, json={"token": "ghcr-token"})
    if request.headers.get("Authorization") != "Bearer ghcr-token":
        return httpx.Response(
            401,
            headers={
                "WWW-Authenticate": 'Bearer realm="https://ghcr.io/token",service="ghcr.io",'
                'scope="repository:astral-sh/uv:pull"'
            },
        )
    assert request.url.path == "/v2/astral-sh/uv/tags/list"
    if request.url.params.get("last") == "0.5.8":
        return httpx.Response(200, json={"name": "astral-sh/uv", "tags": ["0.5.9", "0.6.0"]})
    return httpx.Response(
        200,
        headers={"Link": '</v2/astral-sh/uv/tags/list?n=1000&last=0.5.8>; rel="next"'},
        json={"name": "astral-sh/uv", "tags": ["latest", "0.5.7", "0.5.8", "0.5.8-bookworm"]},
    )


def test_ghcr_tags_follow_link_pagination():
    dep = Dependency(
        "ghcr.io/astral-sh/uv", CONTAINER, "0.5.8", "0.5.8", "pinned", "Dockerfile", kind="image"
    )
    assert make_client(ghcr_handler).available_versions(dep) == [
        "0.5.7",
        "0.5.8",
        "0.5.9",
        "0.6.0",
    ]


def test_docker_registry_errors_raise():
    def missing(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"errors": [{"code": "NAME_UNKNOWN"}]})

    dep = Dependency("nope", CONTAINER, "1.0", "1.0", "constraint", "Dockerfile", kind="image")
    with pytest.raises(RegistryError):
        make_client(missing).available_versions(dep)

    def no_token(request: httpx.Request) -> httpx.Response:
        if request.url.host == "auth.docker.io":
            return httpx.Response(500)
        return httpx.Response(
            401,
            headers={
                "WWW-Authenticate": 'Bearer realm="https://auth.docker.io/token",'
                'service="registry.docker.io",scope="repository:library/nope:pull"'
            },
        )

    with pytest.raises(RegistryError):
        make_client(no_token).available_versions(dep)


def test_docker_image_without_a_version_led_tag_raises():
    dep = Dependency("php", CONTAINER, "latest", None, "unknown", "Dockerfile", kind="image")
    with pytest.raises(RegistryError):
        make_client(docker_handler).available_versions(dep)
