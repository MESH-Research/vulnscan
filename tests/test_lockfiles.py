import json
from pathlib import Path

from vulnscan.models import NPM, PACKAGIST, PYPI
from vulnscan.parsers.lockfiles import (
    load_lock_versions,
    parse_composer_lock,
    parse_package_lock,
    parse_pipfile_lock,
    parse_pnpm_lock,
    parse_poetry_lock,
    parse_uv_lock,
    parse_yarn_lock,
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


def test_composer_lock_packages_metadata(tmp_path: Path):
    from vulnscan.parsers.lockfiles import composer_lock_packages

    lock = tmp_path / "composer.lock"
    lock.write_text(
        json.dumps(
            {
                "packages": [
                    {
                        "name": "wp-plugin/elementor",
                        "version": "3.13.4",
                        "type": "wordpress-plugin",
                        "notification-url": "https://wp-packages.org/downloads",
                        "dist": {
                            "url": "https://downloads.wordpress.org/plugin/elementor.3.13.4.zip"
                        },
                    },
                    {
                        "name": "monolog/monolog",
                        "version": "3.3.1",
                        "type": "library",
                        "notification-url": "https://packagist.org/downloads/",
                    },
                    {"name": "acme/private", "version": "dev-main", "type": "wordpress-plugin"},
                ],
                "packages-dev": [
                    {"name": "phpunit/phpunit", "version": "v9.6.0", "type": "library"}
                ],
            }
        )
    )
    packages = composer_lock_packages(lock)
    assert packages["wp-plugin/elementor"] == {
        "version": "3.13.4",
        "type": "wordpress-plugin",
        "notification_url": "https://wp-packages.org/downloads",
        "dist_url": "https://downloads.wordpress.org/plugin/elementor.3.13.4.zip",
    }
    assert packages["monolog/monolog"]["notification_url"] == "https://packagist.org/downloads/"
    assert packages["acme/private"]["notification_url"] is None
    assert packages["acme/private"]["dist_url"] is None
    assert packages["phpunit/phpunit"]["version"] == "9.6.0"


def test_composer_lock_packages_missing_file(tmp_path: Path):
    from vulnscan.parsers.lockfiles import composer_lock_packages

    assert composer_lock_packages(tmp_path / "composer.lock") == {}


# --- node ---------------------------------------------------------------------------------


def test_package_lock_v3_reads_top_level_packages_only(tmp_path: Path):
    lock = tmp_path / "package-lock.json"
    lock.write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "my-app", "version": "1.0.0"},
                    "node_modules/express": {"version": "4.18.2"},
                    "node_modules/@babel/core": {"version": "7.23.0", "dev": True},
                    "node_modules/express/node_modules/debug": {"version": "2.6.9"},
                    "node_modules/debug": {"version": "4.3.4"},
                },
            }
        )
    )
    assert parse_package_lock(lock) == {
        "express": "4.18.2",
        "@babel/core": "7.23.0",
        "debug": "4.3.4",
    }


def test_package_lock_v1_reads_dependencies(tmp_path: Path):
    lock = tmp_path / "package-lock.json"
    lock.write_text(
        json.dumps(
            {
                "lockfileVersion": 1,
                "dependencies": {
                    "express": {
                        "version": "4.18.2",
                        "dependencies": {"debug": {"version": "2.6.9"}},
                    },
                    "@babel/core": {"version": "7.23.0"},
                },
            }
        )
    )
    assert parse_package_lock(lock) == {"express": "4.18.2", "@babel/core": "7.23.0"}


def test_yarn_lock_classic(tmp_path: Path):
    lock = tmp_path / "yarn.lock"
    lock.write_text(
        """# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.
# yarn lockfile v1


"@babel/core@^7.23.0", "@babel/core@^7.22.0":
  version "7.23.5"
  resolved "https://registry.yarnpkg.com/@babel/core/-/core-7.23.5.tgz"

express@^4.18.2:
  version "4.18.2"
  dependencies:
    debug "2.6.9"

debug@2.6.9:
  version "2.6.9"
"""
    )
    assert parse_yarn_lock(lock) == {"@babel/core": "7.23.5", "express": "4.18.2", "debug": "2.6.9"}


def test_yarn_lock_berry(tmp_path: Path):
    lock = tmp_path / "yarn.lock"
    lock.write_text(
        """# This file is generated by running "yarn install" inside your project.

__metadata:
  version: 8
  cacheKey: 10

"@babel/core@npm:^7.23.0":
  version: 7.23.5
  resolution: "@babel/core@npm:7.23.5"
  languageName: node
  linkType: hard

"express@npm:^4.18.2, express@npm:^4.17.0":
  version: 4.18.2
  resolution: "express@npm:4.18.2"

"my-app@workspace:.":
  version: 0.0.0-use.local
  resolution: "my-app@workspace:."
"""
    )
    assert parse_yarn_lock(lock) == {
        "@babel/core": "7.23.5",
        "express": "4.18.2",
        "my-app": "0.0.0-use.local",
    }


def test_pnpm_lock_reads_root_importer(tmp_path: Path):
    lock = tmp_path / "pnpm-lock.yaml"
    lock.write_text(
        """lockfileVersion: '9.0'

settings:
  autoInstallPeers: true

importers:

  .:
    dependencies:
      express:
        specifier: ^4.18.2
        version: 4.18.2
      '@babel/core':
        specifier: ^7.23.0
        version: 7.23.5(@babel/preset-env@7.23.5)
    devDependencies:
      jest:
        specifier: ~29.7.0
        version: 29.7.0

  packages/other:
    dependencies:
      lodash:
        specifier: ^4.17.21
        version: 4.17.21

packages:

  express@4.18.2:
    resolution: {integrity: sha512-xxx}
"""
    )
    assert parse_pnpm_lock(lock) == {
        "express": "4.18.2",
        "@babel/core": "7.23.5",
        "jest": "29.7.0",
    }


def test_pnpm_lock_old_format_without_importers(tmp_path: Path):
    lock = tmp_path / "pnpm-lock.yaml"
    lock.write_text(
        """lockfileVersion: 5.4

specifiers:
  express: ^4.18.2

dependencies:
  express: 4.18.2
  debug: 4.3.4_supports-color@9.0.0

packages:
  /express/4.18.2:
    resolution: {integrity: sha512-xxx}
"""
    )
    assert parse_pnpm_lock(lock) == {"express": "4.18.2", "debug": "4.3.4"}


def test_load_lock_versions_reads_node_lock_files(tmp_path: Path):
    (tmp_path / "package-lock.json").write_text(
        json.dumps(
            {"lockfileVersion": 3, "packages": {"node_modules/express": {"version": "4.18.2"}}}
        )
    )
    (tmp_path / "yarn.lock").write_text('lodash@^4:\n  version "4.17.21"\n')
    assert load_lock_versions(tmp_path) == {(NPM, "express"): "4.18.2", (NPM, "lodash"): "4.17.21"}
