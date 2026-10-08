"""Parsers for Python dependency manifests."""

from __future__ import annotations

import configparser
import re
import tomllib
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement

from vulnscan.models import PYPI, Dependency

_DEV_HINTS = ("dev", "test", "lint", "doc", "ci")


def _relative(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def _is_dev_requirements_file(path: Path) -> bool:
    """Treat requirements-dev.txt, dev-requirements.txt, requirements/test.txt etc. as dev."""
    name = path.name.lower()
    if name == "requirements.txt":
        return False
    if path.parent.name.lower() == "requirements":
        return True
    return any(hint in name for hint in _DEV_HINTS)


def _requirement_to_dependency(
    text: str, source_file: str, dev: bool, skip_urls: bool = True
) -> Dependency | None:
    try:
        req = Requirement(text)
    except InvalidRequirement:
        return None
    if skip_urls and req.url:
        return None
    return Dependency(
        name=req.name,
        ecosystem=PYPI,
        constraint=str(req.specifier),
        version=None,
        version_source="unknown",
        source_file=source_file,
        dev=dev,
    )


def _strip_comment(line: str) -> str:
    # pip treats " #" (comment preceded by whitespace) or a leading "#" as a comment.
    return re.split(r"(^|\s)#", line, maxsplit=1)[0].strip()


def parse_requirements_txt(
    path: Path, root: Path, _seen: set[Path] | None = None
) -> list[Dependency]:
    """Parse a pip requirements file, following ``-r``/``--requirement`` includes.

    Includes are resolved relative to the including file and each file is read once,
    so cycles are safe. Other option lines (``-e``, ``--index-url`` ...), comments and
    URL requirements are skipped. Dependencies are marked dev when the file name or
    directory looks like a dev/test/lint/doc/ci requirements file. A missing file gives
    ``[]``.
    """
    seen = _seen if _seen is not None else set()
    resolved = path.resolve()
    if resolved in seen or not path.is_file():
        return []
    seen.add(resolved)
    source_file = _relative(path, root)
    dev = _is_dev_requirements_file(path)
    deps: list[Dependency] = []
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = _strip_comment(raw)
        if not line:
            continue
        if line.startswith(("-r ", "--requirement ")):
            include = path.parent / line.split(None, 1)[1].strip()
            deps.extend(parse_requirements_txt(include, root, seen))
            continue
        if line.startswith("-"):
            continue
        dep = _requirement_to_dependency(line, source_file, dev)
        if dep is not None:
            deps.append(dep)
    return deps


def _load_toml(path: Path) -> dict | None:
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, OSError, UnicodeDecodeError):
        return None


def _poetry_constraint(spec: object) -> str | None:
    """Return the constraint string for a Poetry dependency value, or None if not a PyPI dep."""
    if isinstance(spec, str):
        return "" if spec.strip() == "*" else spec.strip()
    if isinstance(spec, list):
        for item in spec:
            constraint = _poetry_constraint(item)
            if constraint is not None:
                return constraint
        return None
    if isinstance(spec, dict):
        if any(k in spec for k in ("path", "git", "url", "file")):
            return None
        version = spec.get("version")
        if version is None:
            return None
        return _poetry_constraint(version)
    return None


def _poetry_dependencies(table: dict, source_file: str, dev: bool) -> list[Dependency]:
    deps: list[Dependency] = []
    for name, spec in table.items():
        if name.lower() == "python":
            continue
        constraint = _poetry_constraint(spec)
        if constraint is None:
            continue
        deps.append(Dependency(name, PYPI, constraint, None, "unknown", source_file, dev))
    return deps


def parse_pyproject(path: Path, root: Path) -> list[Dependency]:
    """Collect dependencies from PEP 621, PEP 735 and Poetry tables in a pyproject.toml.

    ``project.dependencies`` and Poetry's main ``dependencies`` are runtime; optional
    dependencies, ``dependency-groups``, Poetry ``dev-dependencies`` and groups are
    marked dev. Path, git and URL dependencies and the ``python`` entry are skipped.
    Returns ``[]`` when the file is unreadable or not valid TOML.
    """
    data = _load_toml(path)
    if not data:
        return []
    source_file = _relative(path, root)
    deps: list[Dependency] = []

    project = data.get("project", {})
    if isinstance(project, dict):
        for text in project.get("dependencies", []) or []:
            if isinstance(text, str):
                dep = _requirement_to_dependency(text, source_file, dev=False)
                if dep:
                    deps.append(dep)
        for _group, items in (project.get("optional-dependencies", {}) or {}).items():
            for text in items or []:
                if isinstance(text, str):
                    dep = _requirement_to_dependency(text, source_file, dev=True)
                    if dep:
                        deps.append(dep)

    for _group, items in (data.get("dependency-groups", {}) or {}).items():
        for item in items or []:
            if isinstance(item, str):
                dep = _requirement_to_dependency(item, source_file, dev=True)
                if dep:
                    deps.append(dep)

    poetry = data.get("tool", {}).get("poetry", {}) if isinstance(data.get("tool"), dict) else {}
    if isinstance(poetry, dict):
        deps.extend(_poetry_dependencies(poetry.get("dependencies", {}) or {}, source_file, False))
        deps.extend(
            _poetry_dependencies(poetry.get("dev-dependencies", {}) or {}, source_file, True)
        )
        for _name, group in (poetry.get("group", {}) or {}).items():
            if isinstance(group, dict):
                deps.extend(
                    _poetry_dependencies(group.get("dependencies", {}) or {}, source_file, True)
                )
    return deps


def parse_pipfile(path: Path, root: Path) -> list[Dependency]:
    """Parse ``packages`` (runtime) and ``dev-packages`` (dev) from a Pipfile.

    Returns ``[]`` when the file is unreadable or not valid TOML.
    """
    data = _load_toml(path)
    if not data:
        return []
    source_file = _relative(path, root)
    deps: list[Dependency] = []
    for section, dev in (("packages", False), ("dev-packages", True)):
        table = data.get(section, {}) or {}
        if not isinstance(table, dict):
            continue
        deps.extend(_poetry_dependencies(table, source_file, dev))
    return deps


def parse_setup_cfg(path: Path, root: Path) -> list[Dependency]:
    """Parse ``install_requires`` (runtime) and ``extras_require`` (dev) from a setup.cfg.

    Returns ``[]`` when the file is unreadable or malformed.
    """
    parser = configparser.ConfigParser(interpolation=None)
    try:
        parser.read_string(path.read_text(encoding="utf-8"))
    except (configparser.Error, OSError, UnicodeDecodeError):
        return []
    source_file = _relative(path, root)
    deps: list[Dependency] = []

    def add_lines(block: str, dev: bool) -> None:
        for line in block.splitlines():
            text = _strip_comment(line)
            if text:
                dep = _requirement_to_dependency(text, source_file, dev)
                if dep:
                    deps.append(dep)

    if parser.has_option("options", "install_requires"):
        add_lines(parser.get("options", "install_requires"), dev=False)
    if parser.has_section("options.extras_require"):
        for _extra, block in parser.items("options.extras_require"):
            add_lines(block, dev=True)
    return deps
