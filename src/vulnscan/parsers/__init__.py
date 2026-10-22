"""Manifest discovery and project-level parsing."""

from __future__ import annotations

import fnmatch
import json
import os
from collections.abc import Callable
from pathlib import Path

from vulnscan.models import CONTAINER, PACKAGIST, Dependency
from vulnscan.parsers.composer import classify_composer_package, parse_composer_json
from vulnscan.parsers.containers import (
    CI_DIRECTORIES,
    OS_IMAGES,
    canonical_image_name,
    is_compose_file,
    is_dockerfile,
    is_github_workflow,
    is_gitlab_ci_file,
    parse_compose_file,
    parse_dockerfile,
    parse_github_workflow,
    parse_gitlab_ci,
)
from vulnscan.parsers.lockfiles import LockedPackage, load_lock_packages, load_lock_versions
from vulnscan.parsers.node import parse_package_json
from vulnscan.parsers.python import (
    parse_pipfile,
    parse_pyproject,
    parse_requirements_txt,
    parse_setup_cfg,
)
from vulnscan.parsers.versions import resolve_dependency
from vulnscan.parsers.webpack import parse_webpack_py

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
    "package.json": parse_package_json,
    "pyproject.toml": parse_pyproject,
    "pipfile": parse_pipfile,
    "setup.cfg": parse_setup_cfg,
    "webpack.py": parse_webpack_py,
}


def is_requirements_file(path: Path) -> bool:
    """``requirements*.txt``, ``*requirements*.txt`` or any ``*.txt`` in a ``requirements/`` dir."""
    lowered = path.name.lower()
    return lowered.endswith(".txt") and (
        "requirements" in lowered or path.parent.name.lower() == "requirements"
    )


def _parser_for(path: Path) -> Parser | None:
    lowered = path.name.lower()
    if lowered in _EXACT_NAMES:
        return _EXACT_NAMES[lowered]
    if is_requirements_file(path):
        return parse_requirements_txt
    if is_dockerfile(path):
        return parse_dockerfile
    if is_compose_file(path):
        return parse_compose_file
    if is_github_workflow(path):
        return parse_github_workflow
    if is_gitlab_ci_file(path):
        return parse_gitlab_ci
    return None


IGNORE_FILENAME = ".vulnscanignore"


def load_ignore_file(root: Path) -> tuple[str, ...]:
    """Patterns from ``<root>/.vulnscanignore``: one per line, blank lines and ``#`` comments
    skipped. Returns an empty tuple when the file is absent or unreadable."""
    path = root / IGNORE_FILENAME
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return ()
    patterns = []
    for line in lines:
        text = line.strip()
        if text and not text.startswith("#"):
            patterns.append(text)
    return tuple(patterns)


def _normalise_pattern(pattern: str) -> str:
    text = pattern.strip().replace("\\", "/")
    while text.startswith("./"):
        text = text[2:]
    return text.strip("/")


def matches_ignore(rel_path: str, patterns: tuple[str, ...]) -> bool:
    """Does the project-relative directory ``rel_path`` match any ignore pattern?

    A pattern without ``/`` matches the directory's own name anywhere in the tree; one
    with ``/`` matches the whole project-relative path. Both accept shell wildcards.
    Blank patterns and ``#`` comments never match.
    """
    rel = rel_path.strip("/")
    name = rel.rsplit("/", 1)[-1]
    for raw in patterns:
        pattern = _normalise_pattern(raw)
        if not pattern or pattern.startswith("#"):
            continue
        subject = rel if "/" in pattern else name
        if fnmatch.fnmatchcase(subject, pattern):
            return True
    return False


def is_manifest(path: Path) -> bool:
    """Whether ``path`` is a manifest vulnscan can parse, judged by its file name.

    Recognised: ``composer.json``, ``package.json``, ``pyproject.toml``, ``Pipfile``,
    ``setup.cfg``, requirements files (see :func:`is_requirements_file`), Dockerfiles and
    Containerfiles (see :func:`~vulnscan.parsers.containers.is_dockerfile`) and Compose
    files (see :func:`~vulnscan.parsers.containers.is_compose_file`).
    """
    return _parser_for(path) is not None


def _is_ci_directory(rel_path: str) -> bool:
    """Whether a project-relative hidden directory leads to CI configuration."""
    return any(ci == rel_path or ci.startswith(rel_path + "/") for ci in CI_DIRECTORIES)


def discover_manifests(root: Path, ignore_dirs: tuple[str, ...] = ()) -> list[Path]:
    """Find every manifest under ``root``, walking directories and file names in sorted order.

    Skipped: VCS, virtualenv, build and vendor directories, hidden directories (except
    the CI configuration directories ``.github/workflows`` and ``.gitlab/ci``), WordPress
    core, directories Composer installs into, and any directory matching ``ignore_dirs``
    or ``<root>/.vulnscanignore``. A file ``root`` yields ``[root]`` when
    it is itself a manifest, otherwise an empty list.
    """
    if root.is_file():
        return [root] if is_manifest(root) else []
    ignored_names = IGNORED_DIRS | WP_CORE_DIRS
    patterns = tuple(ignore_dirs) + load_ignore_file(root)
    ignored_paths: set[Path] = set()
    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        here = Path(dirpath)
        if "composer.json" in filenames:
            ignored_paths |= composer_ignored_dirs(here / "composer.json")
        try:
            prefix = here.relative_to(root).as_posix()
        except ValueError:
            prefix = ""
        prefix = "" if prefix in ("", ".") else prefix + "/"
        inside_hidden = prefix.startswith(".")
        dirnames[:] = sorted(
            d
            for d in dirnames
            if d not in ignored_names
            and ((not d.startswith(".") and not inside_hidden) or _is_ci_directory(prefix + d))
            and (here / d).resolve() not in ignored_paths
            and not matches_ignore(prefix + d, patterns)
        )
        for filename in sorted(filenames):
            path = Path(dirpath) / filename
            if is_manifest(path):
                found.append(path)
    return found


def parse_manifest(path: Path, root: Path) -> list[Dependency]:
    """Parse one manifest with the parser for its file name; unrecognised files give ``[]``.

    Versions are not resolved here; see :func:`parse_project`.
    """
    parser = _parser_for(path)
    if parser is None:
        return []
    return parser(path, root)


def parse_project(
    root: Path, ignore_dirs: tuple[str, ...] = (), include_transitive: bool = False
) -> tuple[list[Dependency], list[str]]:
    """Parse every manifest under root and resolve versions using adjacent lock files.

    With ``include_transitive`` every package a lock file records that no manifest in
    that directory declares is added as a transitive dependency.

    Invenio ``webpack.py`` theme bundles feed the project-root ``package.json``;
    their versions are resolved from the **root** lock files so they merge with the
    generated manifest declaration instead of standing alone on a constraint lower
    bound (there is usually no lock next to ``webpack.py``).
    """
    warnings: list[str] = []
    manifests = discover_manifests(root, ignore_dirs=ignore_dirs)
    if not manifests:
        warnings.append(f"No dependency manifests found under {root}")
        return [], warnings
    deps: list[Dependency] = []
    lock_cache: dict[Path, dict[tuple[str, str], str]] = {}
    root_locks = load_lock_versions(root)
    lock_cache[root] = root_locks
    for manifest in manifests:
        directory = manifest.parent
        if directory not in lock_cache:
            lock_cache[directory] = load_lock_versions(directory)
        # Theme bundles → project-root install; otherwise the adjacent lock.
        locks = (
            root_locks if manifest.name == "webpack.py" and root_locks else lock_cache[directory]
        )
        for dep in parse_manifest(manifest, root):
            resolved = resolve_dependency(dep, locks)
            if resolved.version is None:
                warning = _unknown_version_warning(resolved)
                if warning:
                    warnings.append(warning)
            deps.append(resolved)
    if include_transitive:
        deps.extend(_transitive_dependencies(root, list(lock_cache), deps))
    return deps, warnings


def _unknown_version_warning(dep: Dependency) -> str | None:
    """Why a dependency will not be queried; ``None`` for OS base images, which never are."""
    if dep.ecosystem == CONTAINER:
        if canonical_image_name(dep.name) in OS_IMAGES:
            return None
        return (
            f"{dep.name} ({dep.source_file}): tag {dep.constraint or 'latest'!r} does not name "
            "a version; pin a versioned tag so the image can be checked"
        )
    return (
        f"{dep.name} ({dep.source_file}): could not determine a version from constraint "
        f"{dep.constraint!r}; not queried"
    )


def _transitive_dependency(
    pkg: LockedPackage, source_file: str, required_by: tuple[str, ...]
) -> Dependency:
    ecosystem, kind, slug = pkg.ecosystem, "", ""
    if pkg.ecosystem == PACKAGIST:
        ecosystem, kind, slug = classify_composer_package(pkg.name, pkg.lock_type)
    return Dependency(
        name=pkg.name,
        ecosystem=ecosystem,
        constraint="",
        version=pkg.version,
        version_source="lock",
        source_file=source_file,
        dev=pkg.dev,
        kind=kind,
        slug=slug,
        transitive=True,
        required_by=required_by,
    )


def _transitive_dependencies(
    root: Path, directories: list[Path], direct: list[Dependency]
) -> list[Dependency]:
    """Lock-only packages from each manifest directory, skipping anything declared directly."""
    direct_keys = {d.key for d in direct}
    found: list[Dependency] = []
    for directory in directories:
        packages = load_lock_packages(directory)
        requirers: dict[str, set[str]] = {}
        for pkg in packages:
            for needed in pkg.requires:
                requirers.setdefault(needed, set()).add(pkg.name)
        for pkg in packages:
            required_by = tuple(sorted(requirers.get(pkg.name, ())))
            try:
                source_file = (directory / pkg.lock_file).relative_to(root).as_posix()
            except ValueError:
                source_file = (directory / pkg.lock_file).as_posix()
            dep = _transitive_dependency(pkg, source_file, required_by)
            if dep.key in direct_keys:
                continue
            found.append(dep)
    return found
