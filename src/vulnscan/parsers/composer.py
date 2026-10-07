"""Parser for composer.json."""

from __future__ import annotations

import json
from pathlib import Path

from vulnscan.models import PACKAGIST, Dependency

_PLATFORM_PREFIXES = ("ext-", "lib-")
_PLATFORM_NAMES = {"php", "hhvm", "composer", "composer-plugin-api", "composer-runtime-api"}


def is_platform_package(name: str) -> bool:
    lowered = name.lower()
    return (
        lowered in _PLATFORM_NAMES or lowered.startswith(_PLATFORM_PREFIXES) or "/" not in lowered
    )


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
    deps: list[Dependency] = []
    for section, dev in (("require", False), ("require-dev", True)):
        table = data.get(section) or {}
        if not isinstance(table, dict):
            continue
        for name, constraint in table.items():
            if is_platform_package(name) or not isinstance(constraint, str):
                continue
            deps.append(
                Dependency(name, PACKAGIST, constraint.strip(), None, "unknown", source_file, dev)
            )
    return deps
