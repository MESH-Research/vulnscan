"""Manifest discovery and project-level parsing."""

from __future__ import annotations

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

Parser = Callable[[Path, Path], list[Dependency]]

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
    if lowered.endswith(".txt") and "requirements" in lowered:
        return parse_requirements_txt
    return None


def is_manifest(path: Path) -> bool:
    return _parser_for(path) is not None


def discover_manifests(root: Path) -> list[Path]:
    if root.is_file():
        return [root] if is_manifest(root) else []
    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in IGNORED_DIRS and not d.startswith("."))
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


def parse_project(root: Path) -> tuple[list[Dependency], list[str]]:
    """Parse every manifest under root and resolve versions using adjacent lock files."""
    warnings: list[str] = []
    manifests = discover_manifests(root)
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
