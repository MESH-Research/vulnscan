"""Parser for composer.json, including WordPress plugins, themes and core."""

from __future__ import annotations

import json
from pathlib import Path

from vulnscan.models import PACKAGIST, WORDPRESS, Dependency
from vulnscan.parsers.lockfiles import composer_lock_packages

_PLATFORM_PREFIXES = ("ext-", "lib-")
_PLATFORM_NAMES = {"php", "hhvm", "composer", "composer-plugin-api", "composer-runtime-api"}

_WP_CORE_PACKAGES = {
    "roots/wordpress",
    "roots/wordpress-no-content",
    "roots/wordpress-full",
    "johnpbloch/wordpress",
    "johnpbloch/wordpress-core",
    "wordpress/wordpress",
}
_WP_PLUGIN_VENDORS = {"wp-plugin", "wpackagist-plugin"}
_WP_THEME_VENDORS = {"wp-theme", "wpackagist-theme"}
_WP_LOCK_TYPES = {
    "wordpress-plugin": "plugin",
    "wordpress-muplugin": "plugin",
    "wordpress-theme": "theme",
    "wordpress-core": "core",
}
_TRUSTED_SOURCES = ("packagist.org", "wp-packages.org", "wpackagist.org", "wordpress.org")


def is_platform_package(name: str) -> bool:
    lowered = name.lower()
    return (
        lowered in _PLATFORM_NAMES or lowered.startswith(_PLATFORM_PREFIXES) or "/" not in lowered
    )


def classify_composer_package(name: str, lock_type: str | None = None) -> tuple[str, str, str]:
    """Return (ecosystem, kind, slug) for a Composer package name.

    WordPress plugins, themes and core are reported under the WordPress ecosystem with the
    wordpress.org slug so they can be matched against WordPress advisory databases.
    """
    lowered = name.lower()
    vendor, _, project = lowered.partition("/")
    if lowered in _WP_CORE_PACKAGES:
        return WORDPRESS, "core", "wordpress"
    if vendor in _WP_PLUGIN_VENDORS:
        return WORDPRESS, "plugin", project
    if vendor in _WP_THEME_VENDORS:
        return WORDPRESS, "theme", project
    kind = _WP_LOCK_TYPES.get((lock_type or "").lower())
    if kind == "core":
        return WORDPRESS, "core", "wordpress"
    if kind:
        return WORDPRESS, kind, project
    return PACKAGIST, "", ""


def _is_custom_source(meta: dict | None) -> bool:
    if meta is None:
        return False
    for url in (meta.get("notification_url"), meta.get("dist_url")):
        if isinstance(url, str) and any(host in url for host in _TRUSTED_SOURCES):
            return False
    return True


def parse_composer_json(path: Path, root: Path) -> list[Dependency]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError, UnicodeDecodeError):
        return []
    if not isinstance(data, dict):
        return []
    try:
        source_file = path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        source_file = path.as_posix()
    lock = composer_lock_packages(path.parent / "composer.lock")
    deps: list[Dependency] = []
    for section, dev in (("require", False), ("require-dev", True)):
        table = data.get(section) or {}
        if not isinstance(table, dict):
            continue
        for name, constraint in table.items():
            if is_platform_package(name) or not isinstance(constraint, str):
                continue
            meta = lock.get(name.lower())
            ecosystem, kind, slug = classify_composer_package(name, meta["type"] if meta else None)
            deps.append(
                Dependency(
                    name=name,
                    ecosystem=ecosystem,
                    constraint=constraint.strip(),
                    version=None,
                    version_source="unknown",
                    source_file=source_file,
                    dev=dev,
                    kind=kind,
                    slug=slug,
                    custom_source=_is_custom_source(meta),
                )
            )
    return deps
