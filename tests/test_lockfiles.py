import json
from pathlib import Path

from vulnscan.models import PACKAGIST, PYPI
from vulnscan.parsers.lockfiles import (
    load_lock_versions,
    parse_composer_lock,
    parse_pipfile_lock,
    parse_poetry_lock,
    parse_uv_lock,
)


def test_composer_lock(tmp_path: Path):
    lock = tmp_path / "composer.lock"
    lock.write_text(
        json.dumps(
            {
                "packages": [{"name": "Monolog/Monolog", "version": "2.9.1"}],
                "packages-dev": [{"name": "phpunit/phpunit", "version": "v10.5.0"}],
            }
        )
    )
    assert parse_composer_lock(lock) == {"monolog/monolog": "2.9.1", "phpunit/phpunit": "10.5.0"}


def test_uv_lock(tmp_path: Path):
    lock = tmp_path / "uv.lock"
    lock.write_text(
        """
version = 1

[[package]]
name = "demo"
version = "0.1.0"
source = { editable = "." }

[[package]]
name = "Requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }
"""
    )
    assert parse_uv_lock(lock) == {"demo": "0.1.0", "requests": "2.31.0"}


def test_poetry_lock(tmp_path: Path):
    lock = tmp_path / "poetry.lock"
    lock.write_text(
        """
[[package]]
name = "requests"
version = "2.31.0"

[[package]]
name = "Django"
version = "4.2.7"
"""
    )
    assert parse_poetry_lock(lock) == {"requests": "2.31.0", "django": "4.2.7"}


def test_pipfile_lock(tmp_path: Path):
    lock = tmp_path / "Pipfile.lock"
    lock.write_text(
        json.dumps(
            {
                "_meta": {},
                "default": {"requests": {"version": "==2.31.0"}, "local": {"path": "."}},
                "develop": {"pytest": {"version": "==8.0.0"}},
            }
        )
    )
    assert parse_pipfile_lock(lock) == {"requests": "2.31.0", "pytest": "8.0.0"}


def test_load_lock_versions_merges_all_lock_files(tmp_path: Path):
    (tmp_path / "composer.lock").write_text(
        json.dumps({"packages": [{"name": "a/b", "version": "1.0.0"}]})
    )
    (tmp_path / "uv.lock").write_text('[[package]]\nname = "requests"\nversion = "2.31.0"\n')
    versions = load_lock_versions(tmp_path)
    assert versions == {(PACKAGIST, "a/b"): "1.0.0", (PYPI, "requests"): "2.31.0"}


def test_load_lock_versions_empty_dir(tmp_path: Path):
    assert load_lock_versions(tmp_path) == {}


def test_load_lock_versions_ignores_corrupt_file(tmp_path: Path):
    (tmp_path / "composer.lock").write_text("{nope")
    (tmp_path / "poetry.lock").write_text('[[package]]\nname = "x"\nversion = "1.0"\n')
    assert load_lock_versions(tmp_path) == {(PYPI, "x"): "1.0"}
