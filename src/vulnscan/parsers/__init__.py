"""Manifest discovery and project-level parsing."""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from pathlib import Path

from vulnscan.models import Dependency
from vulnscan.parsers.composer import parse_composer_json
from vulnscan.parsers.lockfiles import load_lock_versions
from vulnscan.parsers.python import (
    parse_pipfile,
    parse_pyproject,
    parse_requirements_txt,
    parse_setup_cfg,
)
from vulnscan.parsers.versions import resolve_dependency

IGNORED_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "vendor",
    "__pycache__",
    "site-packages",
    ".tox",
    ".nox",
    "build",
    "dist",
}

# WordPress core directories: never contain the project's own manifests.
WP_CORE_DIRS = {"wp-admin", "wp-includes"}

Parser = Callable[[Path, Path], list[Dependency]]


def composer_ignored_dirs(composer_json: Path) -> set[Path]:
    """Directories Composer installs *into* (vendor dir, installer paths, WordPress core)."""
    try:
        data = json.loads(composer_json.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeDecodeError):
        return set()
    if not isinstance(data, dict):
        return set()
    base = composer_json.parent
    targets: list[str] = []
    config = data.get("config") if isinstance(data.get("config"), dict) else {}
    targets.append(str(config.get("vendor-dir") or "vendor"))
    extra = data.get("extra") if isinstance(data.get("extra"), dict) else {}
    paths = extra.get("installer-paths") if isinstance(extra.get("installer-paths"), dict) else {}
    for pattern in paths:
        prefix = str(pattern).split("{$", 1)[0]
        if prefix.strip("/"):
            targets.append(prefix)
    install_dir = extra.get("wordpress-install-dir")
    if isinstance(install_dir, str):
        targets.append(install_dir)
    elif isinstance(install_dir, dict):
        targets.extend(str(v) for v in install_dir.values())
    return {(base / t.strip("/")).resolve() for t in targets if t.strip("/")}


_EXACT_NAMES: dict[str, Parser] = {
    "composer.json": parse_composer_json,
    "pyproject.toml": parse_pyproject,
    "pipfile": parse_pipfile,
    "setup.cfg": parse_setup_cfg,
}


def _parser_for(path: Path) -> Parser | None:
    name = path.name
    lowered = name.lower()
    if lowered in _EXACT_NAMES:
        return _EXACT_NAMES[lowered]
    if lowered.endswith(".txt") and (
        "requirements" in lowered or path.parent.name.lower() == "requirements"
    ):
        return parse_requirements_txt
    return None


def is_manifest(path: Path) -> bool:
    return _parser_for(path) is not None


def discover_manifests(root: Path, ignore_dirs: tuple[str, ...] = ()) -> list[Path]:
    if root.is_file():
        return [root] if is_manifest(root) else []
    ignored_names = IGNORED_DIRS | WP_CORE_DIRS | set(ignore_dirs)
    ignored_paths: set[Path] = set()
    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        here = Path(dirpath)
        if "composer.json" in filenames:
            ignored_paths |= composer_ignored_dirs(here / "composer.json")
        dirnames[:] = sorted(
            d
            for d in dirnames
            if d not in ignored_names
            and not d.startswith(".")
            and (here / d).resolve() not in ignored_paths
        )
        for filename in sorted(filenames):
            path = Path(dirpath) / filename
            if is_manifest(path):
                found.append(path)
    return found


def parse_manifest(path: Path, root: Path) -> list[Dependency]:
    parser = _parser_for(path)
    if parser is None:
        return []
    return parser(path, root)


def parse_project(
    root: Path, ignore_dirs: tuple[str, ...] = ()
) -> tuple[list[Dependency], list[str]]:
    """Parse every manifest under root and resolve versions using adjacent lock files."""
    warnings: list[str] = []
    manifests = discover_manifests(root, ignore_dirs=ignore_dirs)
    if not manifests:
        warnings.append(f"No dependency manifests found under {root}")
        return [], warnings
    deps: list[Dependency] = []
    lock_cache: dict[Path, dict[tuple[str, str], str]] = {}
    for manifest in manifests:
        directory = manifest.parent
        if directory not in lock_cache:
            lock_cache[directory] = load_lock_versions(directory)
        for dep in parse_manifest(manifest, root):
            resolved = resolve_dependency(dep, lock_cache[directory])
            if resolved.version is None:
                warnings.append(
                    f"{resolved.name} ({resolved.source_file}): could not determine a version "
                    f"from constraint {resolved.constraint!r}; not queried"
                )
            deps.append(resolved)
    return deps, warnings
