"""Lock file readers.

:func:`load_lock_versions` resolves the versions of direct dependencies;
:func:`load_lock_packages` lists every package a lock records, with what requires it.

``yarn.lock`` and ``pnpm-lock.yaml`` are read with small line-based parsers rather than a
YAML library; they cover the regular structure those tools emit."""

from __future__ import annotations

import json
import re
import tomllib
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from vulnscan.models import NPM, PACKAGIST, PYPI, normalize_name
from vulnscan.parsers.versions import normalize_version


@dataclass(frozen=True)
class LockedPackage:
    """One package recorded in a lock file.

    ``name`` is canonical for the ecosystem, ``requires`` lists the canonical names of the
    packages it depends on (empty when the lock format does not say), ``dev`` whether
    the lock marks it as a development-only install and ``lock_type`` the package type a
    composer.lock records (``wordpress-plugin`` ...), otherwise ``None``.
    """

    ecosystem: str
    name: str
    version: str
    lock_file: str
    requires: tuple[str, ...] = ()
    dev: bool = False
    lock_type: str | None = None


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
    """Canonical name -> version for every package in a composer.lock.

    Raises ``ValueError`` or ``OSError`` on corrupt or unreadable input; a document
    that is not a JSON object gives ``{}``.
    """
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
    """Canonical name -> version from the ``[[package]]`` tables of a uv.lock."""
    return _toml_packages(path)


def parse_poetry_lock(path: Path) -> dict[str, str]:
    """Canonical name -> version from the ``[[package]]`` tables of a poetry.lock."""
    return _toml_packages(path)


def parse_pipfile_lock(path: Path) -> dict[str, str]:
    """Canonical name -> version from the ``default`` and ``develop`` sections of a Pipfile.lock."""
    data = json.loads(path.read_text(encoding="utf-8"))
    versions: dict[str, str] = {}
    for section in ("default", "develop"):
        for name, spec in (data.get(section) or {}).items():
            version = spec.get("version") if isinstance(spec, dict) else None
            if isinstance(version, str):
                versions[normalize_name(name, PYPI)] = normalize_version(version.lstrip("="))
    return versions


_NODE_MODULES = "node_modules/"


def parse_package_lock(path: Path) -> dict[str, str]:
    """Name -> version of the top-level packages in a package-lock.json / npm-shrinkwrap.json.

    Lockfile v2 and v3 list ``packages`` keyed by path, of which only ``node_modules/<name>``
    (not nested copies) are the project's own installs; v1 lists ``dependencies`` by name.
    Raises ``ValueError`` or ``OSError`` on corrupt or unreadable input.
    """
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        return {}
    versions: dict[str, str] = {}
    packages = data.get("packages")
    if isinstance(packages, dict):
        for key, meta in packages.items():
            if not (isinstance(key, str) and key.startswith(_NODE_MODULES)):
                continue
            name = key[len(_NODE_MODULES) :]
            if _NODE_MODULES in name or not isinstance(meta, dict):
                continue
            version = meta.get("version")
            if isinstance(version, str):
                versions[normalize_name(name, NPM)] = normalize_version(version)
        return versions
    for name, meta in (data.get("dependencies") or {}).items():
        version = meta.get("version") if isinstance(meta, dict) else None
        if isinstance(version, str):
            versions[normalize_name(str(name), NPM)] = normalize_version(version)
    return versions


def _unquote(text: str) -> str:
    text = text.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        return text[1:-1]
    return text


def _yarn_selector_name(selector: str) -> str | None:
    """``@babel/core@npm:^7`` -> ``@babel/core``; ``express@^4`` -> ``express``."""
    selector = selector.strip().strip("\"'")
    cut = selector.find("@", 1)
    name = selector[:cut] if cut > 0 else selector
    return name or None


_YARN_VERSION = re.compile(r"^\s+version:?\s+(.+?)\s*$")


def parse_yarn_lock(path: Path) -> dict[str, str]:
    """Name -> version from a yarn.lock, classic (v1) or Berry.

    Every unindented ``selector, selector:`` header starts an entry whose indented
    ``version`` line applies to each selector's package name. When a package appears in
    several entries (nested copies at different versions), the first one is kept.
    """
    versions: dict[str, str] = {}
    names: list[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if not raw[0].isspace():
            header = raw.rstrip()
            if not header.endswith(":"):
                names = []
                continue
            names = [
                n
                for n in (_yarn_selector_name(s) for s in header[:-1].split(","))
                if n and n != "__metadata"
            ]
            continue
        match = _YARN_VERSION.match(raw)
        if match and names:
            version = normalize_version(_unquote(match.group(1)))
            for name in names:
                versions.setdefault(normalize_name(name, NPM), version)
    return versions


def _yaml_lines(text: str):
    """Yield (indent, key, inline value or None) for each ``key: value`` line."""
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        key, sep, value = stripped.partition(":")
        if not sep:
            continue
        if value and not value.startswith(" "):
            # A quoted key containing ':' such as '@scope/name': handle by re-splitting.
            if stripped[0] in "\"'":
                end = stripped.find(stripped[0], 1)
                key, value = stripped[: end + 1], stripped[end + 1 :].lstrip(":")
        yield indent, _unquote(key), (_unquote(value) if value.strip() else None)


_PNPM_SECTIONS = ("dependencies", "devDependencies", "optionalDependencies")
_PNPM_VERSION_SUFFIX = re.compile(r"[(_].*$")


def _pnpm_version(value: str) -> str:
    """``4.18.2(peer@1)`` or ``4.3.4_supports-color@9`` -> ``4.18.2`` / ``4.3.4``."""
    return normalize_version(_PNPM_VERSION_SUFFIX.sub("", value.strip()))


def parse_pnpm_lock(path: Path) -> dict[str, str]:
    """Name -> version of the root importer's dependencies in a pnpm-lock.yaml.

    Handles the ``importers`` layout (lockfile v6 and later, with ``specifier``/``version``
    pairs or inline versions) and the older top-level ``dependencies`` sections. Other
    workspace importers are ignored. Peer-dependency suffixes on versions are dropped.
    """
    versions: dict[str, str] = {}
    stack: list[tuple[int, str]] = []
    for indent, key, value in _yaml_lines(path.read_text(encoding="utf-8")):
        while stack and stack[-1][0] >= indent:
            stack.pop()
        stack.append((indent, key))
        keys = [k for _, k in stack]
        if keys[:2] == ["importers", "."]:
            keys = keys[2:]
        elif keys[0] == "importers":
            continue
        if len(keys) == 2 and keys[0] in _PNPM_SECTIONS and value is not None:
            versions[normalize_name(keys[1], NPM)] = _pnpm_version(value)
        elif len(keys) == 3 and keys[0] in _PNPM_SECTIONS and keys[2] == "version" and value:
            versions[normalize_name(keys[1], NPM)] = _pnpm_version(value)
    return versions


LOCK_PARSERS: dict[str, tuple[str, Callable[[Path], dict[str, str]]]] = {
    "composer.lock": (PACKAGIST, parse_composer_lock),
    "uv.lock": (PYPI, parse_uv_lock),
    "poetry.lock": (PYPI, parse_poetry_lock),
    "Pipfile.lock": (PYPI, parse_pipfile_lock),
    "package-lock.json": (NPM, parse_package_lock),
    "npm-shrinkwrap.json": (NPM, parse_package_lock),
    "yarn.lock": (NPM, parse_yarn_lock),
    "pnpm-lock.yaml": (NPM, parse_pnpm_lock),
}


def _names(items: object, ecosystem: str) -> tuple[str, ...]:
    """Canonical, sorted, distinct names from a dependency list (uv) or mapping (poetry, npm)."""
    found: set[str] = set()
    if isinstance(items, dict):
        found = {normalize_name(str(k), ecosystem) for k in items}
    elif isinstance(items, list):
        for item in items:
            if isinstance(item, dict) and isinstance(item.get("name"), str):
                found.add(normalize_name(item["name"], ecosystem))
            elif isinstance(item, str):
                found.add(normalize_name(item, ecosystem))
    return tuple(sorted(found))


def _toml_entries(path: Path, lock_file: str) -> list[LockedPackage]:
    """uv.lock and poetry.lock packages; the project itself (editable/virtual) is skipped."""
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    entries: list[LockedPackage] = []
    for pkg in data.get("package") or []:
        if not isinstance(pkg, dict):
            continue
        name, version = pkg.get("name"), pkg.get("version")
        if not (isinstance(name, str) and isinstance(version, str)):
            continue
        source = pkg.get("source") if isinstance(pkg.get("source"), dict) else {}
        if "editable" in source or "virtual" in source:
            continue
        entries.append(
            LockedPackage(
                PYPI,
                normalize_name(name, PYPI),
                normalize_version(version),
                lock_file,
                requires=_names(pkg.get("dependencies"), PYPI),
                dev=str(pkg.get("category", "")).lower() == "dev",
            )
        )
    return entries


def _composer_entries(path: Path, lock_file: str) -> list[LockedPackage]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        return []
    entries: list[LockedPackage] = []
    for section, dev in (("packages", False), ("packages-dev", True)):
        for pkg in data.get(section) or []:
            if not isinstance(pkg, dict):
                continue
            name, version = pkg.get("name"), pkg.get("version")
            if not (isinstance(name, str) and isinstance(version, str)):
                continue
            require = pkg.get("require") if isinstance(pkg.get("require"), dict) else {}
            # Platform requirements (php, ext-*, lib-*) have no vendor prefix.
            packages = {k: v for k, v in require.items() if "/" in str(k)}
            entries.append(
                LockedPackage(
                    PACKAGIST,
                    normalize_name(name, PACKAGIST),
                    normalize_version(version),
                    lock_file,
                    requires=_names(packages, PACKAGIST),
                    dev=dev,
                    lock_type=pkg.get("type") if isinstance(pkg.get("type"), str) else None,
                )
            )
    return entries


def _pipfile_entries(path: Path, lock_file: str) -> list[LockedPackage]:
    data = json.loads(path.read_text(encoding="utf-8"))
    entries: list[LockedPackage] = []
    for section, dev in (("default", False), ("develop", True)):
        for name, spec in (data.get(section) or {}).items():
            version = spec.get("version") if isinstance(spec, dict) else None
            if isinstance(version, str):
                entries.append(
                    LockedPackage(
                        PYPI,
                        normalize_name(name, PYPI),
                        normalize_version(version.lstrip("=")),
                        lock_file,
                        dev=dev,
                    )
                )
    return entries


def _package_lock_entries(path: Path, lock_file: str) -> list[LockedPackage]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        return []
    entries: list[LockedPackage] = []
    packages = data.get("packages")
    if isinstance(packages, dict):
        for key, meta in packages.items():
            if not (isinstance(key, str) and key.startswith(_NODE_MODULES)):
                continue
            name = key[len(_NODE_MODULES) :]
            if _NODE_MODULES in name or not isinstance(meta, dict):
                continue
            version = meta.get("version")
            if not isinstance(version, str):
                continue
            requires = {
                **(meta.get("dependencies") if isinstance(meta.get("dependencies"), dict) else {}),
                **(
                    meta.get("optionalDependencies")
                    if isinstance(meta.get("optionalDependencies"), dict)
                    else {}
                ),
            }
            entries.append(
                LockedPackage(
                    NPM,
                    normalize_name(name, NPM),
                    normalize_version(version),
                    lock_file,
                    requires=_names(requires, NPM),
                    dev=bool(meta.get("dev")),
                )
            )
        return entries
    for name, meta in (data.get("dependencies") or {}).items():
        version = meta.get("version") if isinstance(meta, dict) else None
        if isinstance(version, str):
            entries.append(
                LockedPackage(
                    NPM,
                    normalize_name(str(name), NPM),
                    normalize_version(version),
                    lock_file,
                    requires=_names(meta.get("requires"), NPM),
                    dev=bool(meta.get("dev")),
                )
            )
    return entries


def _flat_entries(parser: Callable[[Path], dict[str, str]], ecosystem: str):
    """Entries for formats whose requirers are not read (yarn.lock, pnpm-lock.yaml)."""

    def read(path: Path, lock_file: str) -> list[LockedPackage]:
        return [LockedPackage(ecosystem, n, v, lock_file) for n, v in parser(path).items()]

    return read


_LOCK_ENTRY_PARSERS: dict[str, Callable[[Path, str], list[LockedPackage]]] = {
    "composer.lock": _composer_entries,
    "uv.lock": _toml_entries,
    "poetry.lock": _toml_entries,
    "Pipfile.lock": _pipfile_entries,
    "package-lock.json": _package_lock_entries,
    "npm-shrinkwrap.json": _package_lock_entries,
    "yarn.lock": _flat_entries(parse_yarn_lock, NPM),
    "pnpm-lock.yaml": _flat_entries(parse_pnpm_lock, NPM),
}


def load_lock_packages(directory: Path) -> list[LockedPackage]:
    """Every package recorded by every lock file in a directory, with what requires it.

    Corrupt or unreadable lock files are skipped, as in :func:`load_lock_versions`.
    """
    entries: list[LockedPackage] = []
    for filename, parser in _LOCK_ENTRY_PARSERS.items():
        path = directory / filename
        if not path.is_file():
            continue
        try:
            entries.extend(parser(path, filename))
        except (ValueError, OSError, UnicodeDecodeError, AttributeError):
            continue
    return entries


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
