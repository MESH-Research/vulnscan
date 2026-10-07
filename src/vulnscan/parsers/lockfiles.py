"""Lock file readers. These only resolve versions of direct dependencies."""

from __future__ import annotations

import json
import tomllib
from collections.abc import Callable
from pathlib import Path

from vulnscan.models import PACKAGIST, PYPI, normalize_name
from vulnscan.parsers.versions import normalize_version


def composer_lock_packages(path: Path) -> dict[str, dict]:
    """Per-package metadata from composer.lock: version, type, notification_url, dist_url."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeDecodeError):
        return {}
    if not isinstance(data, dict):
        return {}
    packages: dict[str, dict] = {}
    for section in ("packages", "packages-dev"):
        for pkg in data.get(section) or []:
            if not isinstance(pkg, dict):
                continue
            name, version = pkg.get("name"), pkg.get("version")
            if not (isinstance(name, str) and isinstance(version, str)):
                continue
            dist = pkg.get("dist") if isinstance(pkg.get("dist"), dict) else {}
            packages[normalize_name(name, PACKAGIST)] = {
                "version": normalize_version(version),
                "type": pkg.get("type") if isinstance(pkg.get("type"), str) else None,
                "notification_url": pkg.get("notification-url")
                if isinstance(pkg.get("notification-url"), str)
                else None,
                "dist_url": dist.get("url") if isinstance(dist.get("url"), str) else None,
            }
    return packages


def parse_composer_lock(path: Path) -> dict[str, str]:
    data = json.loads(path.read_text(encoding="utf-8"))  # raise on corrupt input
    if not isinstance(data, dict):
        return {}
    return {name: meta["version"] for name, meta in composer_lock_packages(path).items()}


def _toml_packages(path: Path) -> dict[str, str]:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    versions: dict[str, str] = {}
    for pkg in data.get("package") or []:
        name, version = pkg.get("name"), pkg.get("version")
        if isinstance(name, str) and isinstance(version, str):
            versions[normalize_name(name, PYPI)] = normalize_version(version)
    return versions


def parse_uv_lock(path: Path) -> dict[str, str]:
    return _toml_packages(path)


def parse_poetry_lock(path: Path) -> dict[str, str]:
    return _toml_packages(path)


def parse_pipfile_lock(path: Path) -> dict[str, str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    versions: dict[str, str] = {}
    for section in ("default", "develop"):
        for name, spec in (data.get(section) or {}).items():
            version = spec.get("version") if isinstance(spec, dict) else None
            if isinstance(version, str):
                versions[normalize_name(name, PYPI)] = normalize_version(version.lstrip("="))
    return versions


LOCK_PARSERS: dict[str, tuple[str, Callable[[Path], dict[str, str]]]] = {
    "composer.lock": (PACKAGIST, parse_composer_lock),
    "uv.lock": (PYPI, parse_uv_lock),
    "poetry.lock": (PYPI, parse_poetry_lock),
    "Pipfile.lock": (PYPI, parse_pipfile_lock),
}


def load_lock_versions(directory: Path) -> dict[tuple[str, str], str]:
    """Collect (ecosystem, name) -> version from every lock file in a directory."""
    versions: dict[tuple[str, str], str] = {}
    for filename, (ecosystem, parser) in LOCK_PARSERS.items():
        path = directory / filename
        if not path.is_file():
            continue
        try:
            parsed = parser(path)
        except (ValueError, OSError, UnicodeDecodeError, AttributeError):
            continue
        for name, version in parsed.items():
            versions[(ecosystem, name)] = version
    return versions
