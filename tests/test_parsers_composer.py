import json
from pathlib import Path

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
