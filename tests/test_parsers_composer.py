import json
from pathlib import Path

import pytest

from vulnscan.models import PACKAGIST
from vulnscan.parsers.composer import parse_composer_json


def test_composer_json(tmp_path: Path):
    cj = tmp_path / "composer.json"
    cj.write_text(
        json.dumps(
            {
                "name": "acme/app",
                "require": {
                    "php": ">=8.1",
                    "ext-json": "*",
                    "lib-curl": "*",
                    "composer-plugin-api": "^2",
                    "monolog/monolog": "^2.0",
                    "symfony/http-kernel": "v5.4.0",
                },
                "require-dev": {"phpunit/phpunit": "^10"},
            }
        )
    )
    deps = {d.name: d for d in parse_composer_json(cj, tmp_path)}
    assert set(deps) == {"monolog/monolog", "symfony/http-kernel", "phpunit/phpunit"}
    assert deps["monolog/monolog"].constraint == "^2.0"
    assert deps["monolog/monolog"].ecosystem == PACKAGIST
    assert deps["monolog/monolog"].version is None
    assert deps["monolog/monolog"].dev is False
    assert deps["phpunit/phpunit"].dev is True
    assert deps["symfony/http-kernel"].source_file == "composer.json"


def test_composer_json_nested_source_path(tmp_path: Path):
    sub = tmp_path / "backend"
    sub.mkdir()
    cj = sub / "composer.json"
    cj.write_text(json.dumps({"require": {"vendor/pkg": "1.0.0"}}))
    assert parse_composer_json(cj, tmp_path)[0].source_file == "backend/composer.json"


def test_composer_json_without_require(tmp_path: Path):
    cj = tmp_path / "composer.json"
    cj.write_text(json.dumps({"name": "acme/lib"}))
    assert parse_composer_json(cj, tmp_path) == []


def test_composer_json_invalid_returns_empty(tmp_path: Path):
    cj = tmp_path / "composer.json"
    cj.write_text("{not json")
    assert parse_composer_json(cj, tmp_path) == []


from vulnscan.models import WORDPRESS  # noqa: E402
from vulnscan.parsers.composer import classify_composer_package  # noqa: E402


@pytest.mark.parametrize(
    "name,lock_type,expected",
    [
        ("wp-plugin/elementor", None, (WORDPRESS, "plugin", "elementor")),
        ("wpackagist-plugin/akismet", None, (WORDPRESS, "plugin", "akismet")),
        ("wp-theme/astra", None, (WORDPRESS, "theme", "astra")),
        ("wpackagist-theme/twentytwentyfour", None, (WORDPRESS, "theme", "twentytwentyfour")),
        ("roots/wordpress", None, (WORDPRESS, "core", "wordpress")),
        ("roots/wordpress-no-content", None, (WORDPRESS, "core", "wordpress")),
        ("johnpbloch/wordpress", None, (WORDPRESS, "core", "wordpress")),
        ("johnpbloch/wordpress-core", None, (WORDPRESS, "core", "wordpress")),
        (
            "mesh-research/buddypress-followers",
            "wordpress-plugin",
            (WORDPRESS, "plugin", "buddypress-followers"),
        ),
        ("acme/my-theme", "wordpress-theme", (WORDPRESS, "theme", "my-theme")),
        ("acme/mu", "wordpress-muplugin", (WORDPRESS, "plugin", "mu")),
        ("monolog/monolog", "library", (PACKAGIST, "", "")),
        ("monolog/monolog", None, (PACKAGIST, "", "")),
    ],
)
def test_classify_composer_package(name, lock_type, expected):
    assert classify_composer_package(name, lock_type) == expected


def test_composer_json_classifies_wordpress_packages(tmp_path: Path):
    cj = tmp_path / "composer.json"
    cj.write_text(
        json.dumps(
            {
                "require": {
                    "wp-plugin/elementor": "3.13.4",
                    "wp-theme/astra": "^4.1",
                    "roots/wordpress": "6.5.2",
                    "monolog/monolog": "^3",
                }
            }
        )
    )
    deps = {d.name: d for d in parse_composer_json(cj, tmp_path)}
    assert (deps["wp-plugin/elementor"].ecosystem, deps["wp-plugin/elementor"].kind) == (
        WORDPRESS,
        "plugin",
    )
    assert deps["wp-plugin/elementor"].slug == "elementor"
    assert deps["wp-theme/astra"].kind == "theme"
    assert deps["roots/wordpress"].slug == "wordpress"
    assert deps["roots/wordpress"].kind == "core"
    assert deps["monolog/monolog"].ecosystem == PACKAGIST


def test_composer_json_uses_lock_types_and_marks_custom_sources(tmp_path: Path):
    cj = tmp_path / "composer.json"
    cj.write_text(
        json.dumps(
            {
                "require": {
                    "mesh-research/buddypress-followers": "1.3",
                    "acme/private-lib": "^1.0",
                    "monolog/monolog": "^3",
                    "wp-plugin/elementor": "3.13.4",
                }
            }
        )
    )
    (tmp_path / "composer.lock").write_text(
        json.dumps(
            {
                "packages": [
                    {
                        "name": "mesh-research/buddypress-followers",
                        "version": "1.3",
                        "type": "wordpress-plugin",
                        "source": {"type": "git", "url": "https://github.com/x/y.git"},
                    },
                    {"name": "acme/private-lib", "version": "1.0.0", "type": "library"},
                    {
                        "name": "monolog/monolog",
                        "version": "3.3.1",
                        "type": "library",
                        "notification-url": "https://packagist.org/downloads/",
                    },
                    {
                        "name": "wp-plugin/elementor",
                        "version": "3.13.4",
                        "type": "wordpress-plugin",
                        "notification-url": "https://wp-packages.org/downloads",
                    },
                ]
            }
        )
    )
    deps = {d.name: d for d in parse_composer_json(cj, tmp_path)}
    followers = deps["mesh-research/buddypress-followers"]
    assert (followers.ecosystem, followers.kind, followers.slug) == (
        WORDPRESS,
        "plugin",
        "buddypress-followers",
    )
    assert followers.custom_source is True
    assert deps["acme/private-lib"].custom_source is True
    assert deps["acme/private-lib"].ecosystem == PACKAGIST
    assert deps["monolog/monolog"].custom_source is False
    assert deps["wp-plugin/elementor"].custom_source is False
