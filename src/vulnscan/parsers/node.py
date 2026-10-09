"""Parser for package.json (npm, yarn and pnpm projects)."""

from __future__ import annotations

import json
from pathlib import Path

from vulnscan.models import NPM, Dependency

# Specs that do not name a registry package: local paths, git, tarballs, workspaces.
_SKIP_PREFIXES = (
    "file:",
    "link:",
    "portal:",
    "patch:",
    "workspace:",
    "git:",
    "git+",
    "github:",
    "gitlab:",
    "bitbucket:",
    "gist:",
    "http:",
    "https:",
)

_SECTIONS = (
    ("dependencies", False),
    ("optionalDependencies", False),
    ("devDependencies", True),
)


def _registry_spec(name: str, spec: object) -> tuple[str, str] | None:
    """(package name, range) for a registry dependency, or None for anything else.

    ``npm:other@range`` aliases resolve to the aliased package. Anything containing a
    ``/`` (``user/repo`` shorthand, URLs, paths) is not a semver range and is skipped.
    """
    if not isinstance(spec, str):
        return None
    text = spec.strip()
    if text.lower().startswith("npm:"):
        rest = text[4:]
        cut = rest.find("@", 1)
        if cut > 0:
            return rest[:cut], rest[cut + 1 :].strip()
        return rest, ""
    if text.lower().startswith(_SKIP_PREFIXES) or "/" in text:
        return None
    return name, text


def parse_package_json(path: Path, root: Path) -> list[Dependency]:
    """Read ``dependencies``, ``optionalDependencies`` and ``devDependencies``.

    ``peerDependencies`` are left out: they describe what the consumer must provide, not
    what this project installs. Returns ``[]`` when the file is missing, unreadable or
    not a JSON object.
    """
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
    for section, dev in _SECTIONS:
        table = data.get(section) or {}
        if not isinstance(table, dict):
            continue
        for name, spec in table.items():
            resolved = _registry_spec(str(name), spec)
            if resolved is None:
                continue
            package, constraint = resolved
            deps.append(
                Dependency(
                    name=package,
                    ecosystem=NPM,
                    constraint=constraint,
                    version=None,
                    version_source="unknown",
                    source_file=source_file,
                    dev=dev,
                )
            )
    return deps
