"""Pin-float preflight: mock-lock each manifest in isolation and score the result.

Lockfiles are **not** used as resolve inputs. For each supported manifest we build a
tiny temp project from that file alone (registry constraints only), run a fresh
``uv lock`` / ``npm|pnpm`` lockfile-only / ``composer update --no-install`` resolve,
then compare would-be versions to the project's current tree and score bumps / risks.
Each package is tagged with the **build process** that produced it (``uv``, ``npm``,
``invenio-assets``, or ``composer``).

In Invenio mode, npm is not mock-locked per on-disk ``package.json``. Instead we build
one virtual assets ``package.json`` from the same webpack merge sources as
``invenio webpack create`` (theme ``webpack.py`` files, entry points, invenio-assets
base templates) and resolve that.
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
import tempfile
import tomllib
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from fnmatch import fnmatch
from pathlib import Path

from vulnscan.config import Settings
from vulnscan.invenio import (
    build_virtual_assets_package_json,
    detect_invenio_webpack,
    webpack_uses_pnpm,
)
from vulnscan.models import NPM, PACKAGIST, PYPI, Dependency, normalize_name
from vulnscan.osv import OSVClient
from vulnscan.parsers import (
    discover_manifests,
    is_requirements_file,
    load_ignore_file,
    load_lock_versions,
    parse_manifest,
    parse_project,
)
from vulnscan.registry import RegistryClient
from vulnscan.risk import RiskKind, VersionScore, score_versions

log = logging.getLogger("vulnscan.preflight")


def _load_toml(path: Path) -> dict:
    """Read a TOML file; return ``{}`` on failure."""
    try:
        with path.open("rb") as fh:
            data = tomllib.load(fh)
    except (OSError, tomllib.TOMLDecodeError, UnicodeDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


RunFn = Callable[[Sequence[str], Path], subprocess.CompletedProcess[str]]

_SKIP_MANIFEST_NAMES = frozenset(
    {
        "webpack.py",
    }
)

# Labels for the TUI / JSON "build process" column.
BUILD_UV = "uv"
BUILD_NPM = "npm"
BUILD_INVENIO_ASSETS = "invenio-assets"
BUILD_COMPOSER = "composer"

# uv.sources keys that mean "not a registry package for float resolve".
_NON_REGISTRY_SOURCE_KEYS = frozenset({"path", "git", "url", "workspace"})


@dataclass(frozen=True)
class PreflightPackage:
    """One package in the would-be resolve, with optional bump and risks."""

    dependency: Dependency
    current: str | None
    would_be: str
    would_bump: bool
    build_process: str = ""
    resolve_from: str = ""
    upstream_constraints_text: str | None = None
    """Invenio npm: which ``webpack.py`` / template files set which constraint (scan-parity)."""
    score: VersionScore | None = None
    ignored: bool = False


@dataclass
class PreflightReport:
    """Outcome of one ``--preflight`` run."""

    project_path: Path
    resolve_ok: bool
    packages: list[PreflightPackage] = field(default_factory=list)
    ignored: list[PreflightPackage] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    scanned_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    ecosystems: tuple[str, ...] = ()

    @property
    def summary(self) -> dict[str, int]:
        """Counts used in JSON / CI summaries."""
        packages = self.packages
        return {
            "would_bump": sum(1 for p in packages if p.would_bump),
            "advisory": sum(
                1
                for p in packages
                if p.score and any(r.kind == RiskKind.ADVISORY for r in p.score.risks)
            ),
            "malware": sum(
                1
                for p in packages
                if p.score and any(r.kind == RiskKind.MALWARE for r in p.score.risks)
            ),
            "fresh": sum(
                1
                for p in packages
                if p.score and any(r.kind == RiskKind.FRESH for r in p.score.risks)
            ),
            "yanked": sum(
                1
                for p in packages
                if p.score and any(r.kind == RiskKind.YANKED for r in p.score.risks)
            ),
        }

    def has_blocking(self) -> bool:
        """Advisory / malware / yanked on any non-ignored package."""
        return any(p.score and p.score.has_blocking for p in self.packages)

    def has_fresh(self) -> bool:
        """Freshness risk on any non-ignored package."""
        return any(p.score and p.score.is_fresh for p in self.packages)

    def exit_code(self, *, strict_fresh: bool) -> int:
        """CI exit code: 0 clean, 1 blocking/resolve fail, 2 freshness-only when strict."""
        if not self.resolve_ok or self.has_blocking():
            return 1
        if strict_fresh and self.has_fresh():
            return 2
        return 0

    @property
    def ok(self) -> bool:
        """Whether a default (non-strict-fresh) run would exit 0."""
        return self.exit_code(strict_fresh=False) == 0


@dataclass(frozen=True)
class _MockLockResult:
    """Versions produced by one per-manifest mock lock."""

    ok: bool
    ecosystem: str
    versions: dict[tuple[str, str], str]  # (ecosystem, normalized_name) -> version
    build_process: str
    resolve_from: str = ""
    detail: str = ""
    webpack_merge: object | None = None


def _tag_resolve_from(result: _MockLockResult, resolve_from: str) -> _MockLockResult:
    """Attach the project-relative mock-lock site (manifest path or virtual label)."""
    return replace(result, resolve_from=resolve_from)


def load_preflight_ignore_file(root: Path) -> tuple[str, ...]:
    """Read ``.vulnscan-preflight-ignore`` from the project root."""
    path = root / ".vulnscan-preflight-ignore"
    if not path.is_file():
        return ()
    patterns: list[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        patterns.append(line)
    return tuple(patterns)


def parse_exclude_spec(spec: str) -> tuple[str | None, str]:
    """Split ``ecosystem:name`` or bare ``name`` into ``(ecosystem|None, name_pattern)``."""
    text = spec.strip()
    if not text:
        return None, ""
    if text.lower().startswith("npm:"):
        return NPM, text[4:].strip()
    if ":" in text:
        eco, _, name = text.partition(":")
        eco = eco.strip()
        mapping = {
            "pypi": PYPI,
            "npm": NPM,
            "packagist": "Packagist",
            "wordpress": "WordPress",
        }
        return mapping.get(eco.lower(), eco), name.strip()
    return None, text


def is_excluded(dep: Dependency, patterns: Sequence[str]) -> bool:
    """Whether ``dep`` matches any preflight exclude pattern."""
    canon = normalize_name(dep.name, dep.ecosystem)
    for pattern in patterns:
        eco, name_pat = parse_exclude_spec(pattern)
        if not name_pat:
            continue
        if eco is not None and eco.lower() != dep.ecosystem.lower():
            continue
        name_match = normalize_name(name_pat, dep.ecosystem) if "*" not in name_pat else name_pat
        if fnmatch(canon, name_match):
            return True
        if fnmatch(dep.name, name_pat) or fnmatch(canon, name_pat):
            return True
    return False


# Shell convention for "command not found"; keeps a missing tool distinct from a
# resolver that ran and failed.
_EXIT_COMMAND_NOT_FOUND = 127


def _launch_failure(argv: Sequence[str], exc: OSError) -> subprocess.CompletedProcess[str]:
    """Turn a failure to *start* a resolver into a failed result the callers already handle.

    A missing ``npm``/``uv``/``composer`` binary must only fail that manifest's mock
    lock, not abort the whole preflight run.
    """
    tool = argv[0] if argv else "<unknown>"
    if isinstance(exc, FileNotFoundError):
        reason = f"{tool}: command not found (is it installed and on PATH?)"
    else:
        reason = f"{tool}: could not be started ({exc.strerror or exc})"
    return subprocess.CompletedProcess(list(argv), _EXIT_COMMAND_NOT_FOUND, "", reason)


def _default_run(argv: Sequence[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            list(argv),
            cwd=cwd,
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError as exc:
        return _launch_failure(argv, exc)


def _logged_run(run_fn: RunFn) -> RunFn:
    """Wrap a runner so every resolver invocation and its outcome reach the debug log.

    Also guards injected runners: an ``OSError`` raised while launching the tool
    becomes a failed result rather than propagating out of ``run_preflight``.
    """

    def run(argv: Sequence[str], cwd: Path) -> subprocess.CompletedProcess[str]:
        log.info("preflight: running %s in %s", " ".join(argv), cwd)
        try:
            result = run_fn(argv, cwd)
        except OSError as exc:
            result = _launch_failure(argv, exc)
        log.info("preflight: %s exited %d", argv[0], result.returncode)
        if result.stdout:
            log.debug("preflight: %s stdout:\n%s", argv[0], result.stdout.rstrip())
        if result.stderr:
            log.debug("preflight: %s stderr:\n%s", argv[0], result.stderr.rstrip())
        return result

    return run


def _assert_safe_argv(argv: Sequence[str]) -> None:
    """Refuse upgrade-beyond-range or non-dry project installs."""
    lowered = [a.lower() for a in argv]
    forbidden = ("--upgrade-package", "npm update", "pnpm update")
    joined = " ".join(lowered)
    for token in forbidden:
        if token in joined:
            raise ValueError(f"refusing unsafe preflight argv containing {token!r}: {argv}")
    if "install" in lowered and "--frozen-lockfile" in lowered:
        raise ValueError("preflight float resolve must not use --frozen-lockfile")
    if "ci" in lowered:
        raise ValueError("preflight float resolve must not use npm ci")


def _rel(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return str(path)


def _requirement_line(dep: Dependency) -> str:
    """Rebuild a PEP 508-ish requirement from a parsed dependency."""
    spec = (dep.constraint or "").strip()
    if not spec:
        return dep.name
    if spec[0] in "=<>!~":
        return f"{dep.name}{spec}"
    return f"{dep.name}{spec}"


def _uv_sources_table(data: dict) -> dict:
    tool = data.get("tool")
    if not isinstance(tool, dict):
        return {}
    uv = tool.get("uv")
    if not isinstance(uv, dict):
        return {}
    sources = uv.get("sources")
    return sources if isinstance(sources, dict) else {}


def _non_registry_uv_source_names(data: dict) -> set[str]:
    """Package names pinned to path/git/url/workspace (or editable) in ``tool.uv.sources``."""
    drop: set[str] = set()
    for name, spec in _uv_sources_table(data).items():
        if not isinstance(spec, dict):
            continue
        if any(k in spec for k in _NON_REGISTRY_SOURCE_KEYS):
            drop.add(str(name))
            continue
        # ``{ editable = true }`` without path is still non-registry.
        if spec.get("editable") is True:
            drop.add(str(name))
    return drop


def _path_uv_sources(data: dict, manifest_dir: Path) -> list[tuple[str, Path]]:
    """``(package_name, resolved_directory)`` for path / editable path sources."""
    out: list[tuple[str, Path]] = []
    for name, spec in _uv_sources_table(data).items():
        if not isinstance(spec, dict):
            continue
        raw = spec.get("path")
        if not isinstance(raw, str) or not raw.strip():
            continue
        path = Path(raw.strip())
        resolved = (manifest_dir / path).resolve() if not path.is_absolute() else path.resolve()
        out.append((str(name), resolved))
    return out


def _poetry_tables(data: dict) -> list[dict]:
    """Poetry dependency tables (main, legacy dev, and groups)."""
    tool = data.get("tool")
    if not isinstance(tool, dict):
        return []
    poetry = tool.get("poetry")
    if not isinstance(poetry, dict):
        return []
    tables: list[dict] = []
    for key in ("dependencies", "dev-dependencies"):
        table = poetry.get(key)
        if isinstance(table, dict):
            tables.append(table)
    groups = poetry.get("group")
    if isinstance(groups, dict):
        for group in groups.values():
            if isinstance(group, dict):
                deps = group.get("dependencies")
                if isinstance(deps, dict):
                    tables.append(deps)
    return tables


def _path_poetry_sources(data: dict, manifest_dir: Path) -> list[tuple[str, Path]]:
    """``(package_name, resolved_directory)`` for Poetry path dependencies."""
    out: list[tuple[str, Path]] = []
    seen: set[str] = set()
    for table in _poetry_tables(data):
        for name, spec in table.items():
            if not isinstance(spec, dict):
                continue
            raw = spec.get("path")
            if not isinstance(raw, str) or not raw.strip():
                continue
            key = str(name)
            if key in seen:
                continue
            seen.add(key)
            path = Path(raw.strip())
            resolved = (manifest_dir / path).resolve() if not path.is_absolute() else path.resolve()
            out.append((key, resolved))
    return out


def _local_package_dirs(data: dict, manifest_dir: Path) -> list[tuple[str, Path]]:
    """Union of uv path/editable and Poetry path package directories."""
    by_name: dict[str, Path] = {}
    for name, path in _path_uv_sources(data, manifest_dir):
        by_name[name] = path
    for name, path in _path_poetry_sources(data, manifest_dir):
        by_name.setdefault(name, path)
    return list(by_name.items())


def _find_local_manifest(package_dir: Path) -> Path | None:
    """Prefer ``pyproject.toml``, else ``setup.cfg``, under a local package path."""
    pyproject = package_dir / "pyproject.toml"
    if pyproject.is_file():
        return pyproject
    setup_cfg = package_dir / "setup.cfg"
    if setup_cfg.is_file():
        return setup_cfg
    return None


def _build_system_requirement_lines(data: dict) -> list[str]:
    """PEP 517 ``build-system.requires`` entries (as requirement strings)."""
    build = data.get("build-system")
    if not isinstance(build, dict):
        return []
    raw = build.get("requires") or []
    if not isinstance(raw, list):
        return []
    lines: list[str] = []
    for item in raw:
        if isinstance(item, str) and item.strip():
            lines.append(item.strip())
    return lines


def _uv_table(data: dict) -> dict:
    tool = data.get("tool")
    if not isinstance(tool, dict):
        return {}
    uv = tool.get("uv")
    return uv if isinstance(uv, dict) else {}


def _uv_requirement_list(data: dict, key: str) -> list[str]:
    """``tool.uv.constraint-dependencies`` / ``override-dependencies`` entries."""
    raw = _uv_table(data).get(key) or []
    if not isinstance(raw, list):
        return []
    return [item.strip() for item in raw if isinstance(item, str) and item.strip()]


def _uv_indexes(data: dict) -> list[dict[str, object]]:
    """``[[tool.uv.index]]`` tables from a pyproject."""
    raw = _uv_table(data).get("index") or []
    if not isinstance(raw, list):
        return []
    out: list[dict[str, object]] = []
    for item in raw:
        if isinstance(item, dict) and item:
            out.append(dict(item))
    return out


def _dedupe_requirement_lines(lines: Sequence[str]) -> list[str]:
    """Stable unique list; identical strings collapse, different specs for one name all kept."""
    seen: set[str] = set()
    out: list[str] = []
    for line in lines:
        key = line.strip()
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(key)
    return out


def _dedupe_indexes(indexes: Sequence[dict[str, object]]) -> list[dict[str, object]]:
    """Keep first index per URL (or per entire mapping when URL missing)."""
    seen: set[str] = set()
    out: list[dict[str, object]] = []
    for index in indexes:
        url = index.get("url")
        key = str(url) if url else repr(sorted(index.items()))
        if key in seen:
            continue
        seen.add(key)
        out.append(index)
    return out


@dataclass
class _FloatRequirements:
    """Registry constraints collected for one mock ``uv lock``."""

    project_reqs: list[str] = field(default_factory=list)
    build_reqs: list[str] = field(default_factory=list)
    constraints: list[str] = field(default_factory=list)
    overrides: list[str] = field(default_factory=list)
    indexes: list[dict[str, object]] = field(default_factory=list)
    requires_python: str | None = None


def _collect_setup_cfg_requirements(
    manifest: Path,
    root: Path,
    *,
    warnings: list[str],
) -> list[str]:
    """PyPI requirement lines from a ``setup.cfg`` (no uv/poetry path recursion)."""
    declared = parse_manifest(manifest, root)
    return [_requirement_line(dep) for dep in declared if dep.ecosystem == PYPI]


def _collect_pyproject_float_requirements(
    manifest: Path,
    root: Path,
    *,
    visited: set[Path] | None = None,
    warnings: list[str] | None = None,
) -> _FloatRequirements:
    """Collect PyPI requirement lines for a mock lock of ``manifest``.

    Includes this file's registry deps (PEP 621, Poetry, dependency-groups),
    ``build-system.requires``, ``tool.uv`` constraints/overrides/indexes, plus the
    same from path/editable local packages (recursively via ``pyproject.toml`` or
    ``setup.cfg``). The local package names themselves are never added as
    requirements.
    """
    warn = warnings if warnings is not None else []
    seen = visited if visited is not None else set()
    try:
        manifest_resolved = manifest.resolve()
    except OSError:
        manifest_resolved = manifest
    if manifest_resolved in seen:
        return _FloatRequirements()
    seen.add(manifest_resolved)

    rel = _rel(manifest, root)
    collected = _FloatRequirements()

    if manifest.name == "setup.cfg":
        collected.project_reqs = _collect_setup_cfg_requirements(manifest, root, warnings=warn)
        return collected

    data = _load_toml(manifest) or {}
    drop = _non_registry_uv_source_names(data)
    # Poetry path deps are already omitted by parse_manifest; still exclude by name.
    poetry_path_names = {name for name, _ in _path_poetry_sources(data, manifest.parent)}
    drop |= poetry_path_names
    drop_norm = {normalize_name(n, PYPI) for n in drop}

    collected.build_reqs = _build_system_requirement_lines(data)
    collected.constraints = _uv_requirement_list(data, "constraint-dependencies")
    collected.overrides = _uv_requirement_list(data, "override-dependencies")
    collected.indexes = _uv_indexes(data)

    declared = parse_manifest(manifest, root)
    for dep in declared:
        if dep.ecosystem != PYPI:
            continue
        if normalize_name(dep.name, PYPI) in drop_norm or dep.name in drop:
            continue
        collected.project_reqs.append(_requirement_line(dep))

    project = data.get("project")
    if isinstance(project, dict):
        rp = project.get("requires-python")
        if isinstance(rp, str) and rp.strip():
            collected.requires_python = rp.strip()
    if collected.requires_python is None:
        tool = data.get("tool")
        poetry = tool.get("poetry", {}) if isinstance(tool, dict) else {}
        if isinstance(poetry, dict):
            deps = poetry.get("dependencies")
            if isinstance(deps, dict):
                py = deps.get("python")
                if isinstance(py, str) and py.strip() and py.strip() != "*":
                    collected.requires_python = py.strip()

    for name, package_dir in _local_package_dirs(data, manifest.parent):
        nested = _find_local_manifest(package_dir)
        if nested is None:
            warn.append(
                f"preflight: {rel}: editable/path {name!r} at {package_dir} "
                "has no pyproject.toml or setup.cfg; cannot import its PyPI requirements"
            )
            continue
        nested_collected = _collect_pyproject_float_requirements(
            nested,
            root,
            visited=seen,
            warnings=warn,
        )
        collected.project_reqs.extend(nested_collected.project_reqs)
        collected.build_reqs.extend(nested_collected.build_reqs)
        collected.constraints.extend(nested_collected.constraints)
        collected.overrides.extend(nested_collected.overrides)
        collected.indexes.extend(nested_collected.indexes)

    # Git/url/workspace sources: dropped from the graph, nothing to import from disk.
    for name, spec in _uv_sources_table(data).items():
        if not isinstance(spec, dict) or "path" in spec:
            continue
        if any(k in spec for k in ("git", "url", "workspace")) or spec.get("editable") is True:
            kinds = ", ".join(sorted(k for k in spec if k != "editable"))
            warn.append(
                f"preflight: {rel}: dropping non-path source {name!r} ({kinds or 'editable'}); "
                "cannot import its requirements from disk"
            )

    collected.project_reqs = _dedupe_requirement_lines(collected.project_reqs)
    collected.build_reqs = _dedupe_requirement_lines(collected.build_reqs)
    collected.constraints = _dedupe_requirement_lines(collected.constraints)
    collected.overrides = _dedupe_requirement_lines(collected.overrides)
    collected.indexes = _dedupe_indexes(collected.indexes)
    return collected


def _toml_string(value: str) -> str:
    esc = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{esc}"'


def _toml_literal(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)
    return _toml_string(str(value))


def _write_minimal_pyproject(
    dest: Path,
    *,
    project_name: str,
    requirements: list[str],
    build_requires: list[str],
    requires_python: str | None,
    constraints: Sequence[str] = (),
    overrides: Sequence[str] = (),
    indexes: Sequence[dict[str, object]] = (),
) -> None:
    """Write a tiny PEP 621 pyproject (no path sources, no prior lock)."""
    safe = re.sub(r"[^a-zA-Z0-9._-]+", "-", project_name).strip("-") or "preflight-mock"
    lines: list[str] = []
    if build_requires:
        lines.append("[build-system]")
        lines.append("requires = [")
        for req in build_requires:
            lines.append(f"  {_toml_string(req)},")
        lines.append("]")
        lines.append('build-backend = "setuptools.build_meta"')
        lines.append("")
    lines.extend(
        [
            "[project]",
            f"name = {_toml_string(safe)}",
            'version = "0.0.0"',
        ]
    )
    if requires_python:
        lines.append(f"requires-python = {_toml_string(requires_python)}")
    lines.append("dependencies = [")
    for req in requirements:
        lines.append(f"  {_toml_string(req)},")
    lines.append("]")
    lines.append("")

    if constraints or overrides or indexes:
        lines.append("[tool.uv]")
        if constraints:
            lines.append("constraint-dependencies = [")
            for req in constraints:
                lines.append(f"  {_toml_string(req)},")
            lines.append("]")
        if overrides:
            lines.append("override-dependencies = [")
            for req in overrides:
                lines.append(f"  {_toml_string(req)},")
            lines.append("]")
        lines.append("")
        for index in indexes:
            lines.append("[[tool.uv.index]]")
            for key in sorted(index.keys(), key=lambda k: str(k)):
                lines.append(f"{key} = {_toml_literal(index[key])}")
            lines.append("")

    dest.write_text("\n".join(lines), encoding="utf-8")


def _mock_lock_pyproject(
    manifest: Path,
    root: Path,
    run_fn: RunFn,
) -> tuple[_MockLockResult, list[str]]:
    """Fresh ``uv lock`` from registry deps (+ build-system / editable PyPI constraints)."""
    warnings: list[str] = []
    rel = _rel(manifest, root)
    data = _load_toml(manifest) or {}
    drop = _non_registry_uv_source_names(data)
    poetry_paths = {name for name, _ in _path_poetry_sources(data, manifest.parent)}
    dropped = sorted(drop | poetry_paths)
    if dropped:
        warnings.append(
            f"preflight: {rel}: dropping path/editable/git sources: " + ", ".join(dropped)
        )

    collected = _collect_pyproject_float_requirements(manifest, root, warnings=warnings)
    # Build-system pins also constrain the float lock (e.g. setuptools>=83).
    all_deps = _dedupe_requirement_lines([*collected.project_reqs, *collected.build_reqs])

    if not all_deps and not collected.constraints and not collected.overrides:
        warnings.append(f"preflight: {rel}: no registry PyPI deps left to mock-lock")
        return (
            _MockLockResult(
                ok=False,
                ecosystem=PYPI,
                versions={},
                build_process=BUILD_UV,
                detail="empty",
            ),
            warnings,
        )

    with tempfile.TemporaryDirectory(prefix="vulnscan-preflight-py-") as tmp:
        temp = Path(tmp)
        _write_minimal_pyproject(
            temp / "pyproject.toml",
            project_name=f"preflight-{manifest.stem}",
            requirements=all_deps,
            build_requires=collected.build_reqs,
            requires_python=collected.requires_python,
            constraints=collected.constraints,
            overrides=collected.overrides,
            indexes=collected.indexes,
        )
        argv = ["uv", "lock"]
        _assert_safe_argv(argv)
        result = run_fn(argv, temp)
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "").strip()
            warnings.append(
                f"preflight: {rel}: uv lock failed" + (f": {detail[:400]}" if detail else "")
            )
            return (
                _MockLockResult(
                    ok=False,
                    ecosystem=PYPI,
                    versions={},
                    build_process=BUILD_UV,
                    detail=detail,
                ),
                warnings,
            )
        versions = {key: ver for key, ver in load_lock_versions(temp).items() if key[0] == PYPI}
    return (
        _MockLockResult(
            ok=True,
            ecosystem=PYPI,
            versions=versions,
            build_process=BUILD_UV,
        ),
        warnings,
    )


def _npm_non_registry(spec: object) -> bool:
    if not isinstance(spec, str):
        return True
    s = spec.strip().lower()
    return (
        s.startswith("file:")
        or s.startswith("link:")
        or s.startswith("workspace:")
        or s.startswith("git+")
        or s.startswith("github:")
        or s.startswith("http:")
        or s.startswith("https:")
    )


def _package_manager_argv(*, prefer_pnpm: bool) -> list[str]:
    """Lockfile-only argv: pnpm when preferred, otherwise npm (the default)."""
    if prefer_pnpm:
        return ["pnpm", "install", "--lockfile-only", "--ignore-scripts"]
    return ["npm", "install", "--package-lock-only", "--ignore-scripts"]


def _read_root_package_manager(root: Path) -> str | None:
    path = root / "package.json"
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    if isinstance(data, dict) and isinstance(data.get("packageManager"), str):
        return data["packageManager"]
    return None


def _prefer_pnpm(root: Path, package_json: dict | None = None) -> bool:
    """Whether mock-lock should use pnpm.

    Order:
    1. ``WEBPACKEXT_NPM_PKG_CLS`` in ``invenio.cfg`` naming ``PNPMPackage``
    2. ``packageManager`` on the document / root ``package.json`` starting with ``pnpm@``
    3. otherwise npm (default)
    """
    if webpack_uses_pnpm(root):
        return True
    pm = None
    if isinstance(package_json, dict) and isinstance(package_json.get("packageManager"), str):
        pm = package_json["packageManager"]
    else:
        pm = _read_root_package_manager(root)
    return isinstance(pm, str) and pm.lower().startswith("pnpm@")


def _iter_package_json_paths(root: Path) -> list[Path]:
    """Shallow-ish ``package.json`` paths under ``root`` (skip venv / node_modules)."""
    skip = {".venv", "node_modules", ".git", "dist", "build", "var"}
    found: list[Path] = []
    root_pkg = root / "package.json"
    if root_pkg.is_file():
        found.append(root_pkg)
    root_resolved = root.resolve()
    for path in root.rglob("package.json"):
        if path == root_pkg:
            continue
        try:
            relative_parts = path.resolve().relative_to(root_resolved).parts
        except ValueError:
            continue
        if any(part in skip for part in relative_parts):
            continue
        found.append(path)
        if len(found) >= 40:
            break
    return found


def _discover_pnpm_package_manager(root: Path) -> str:
    """Best ``packageManager`` string for a pnpm project (Corepack-style)."""
    existing = _read_root_package_manager(root)
    if isinstance(existing, str) and existing.lower().startswith("pnpm@"):
        return existing
    for path in _iter_package_json_paths(root):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        if not isinstance(data, dict):
            continue
        pm = data.get("packageManager")
        if isinstance(pm, str) and pm.lower().startswith("pnpm@"):
            return pm
    return "pnpm@"


def _resolve_package_manager_field(root: Path) -> str | None:
    """``packageManager`` value to stamp on a virtual assets package.json."""
    if webpack_uses_pnpm(root):
        return _discover_pnpm_package_manager(root)
    return _read_root_package_manager(root)


def restore_missing_package_manager(root: Path) -> list[str]:
    """Write ``packageManager`` into root ``package.json`` when Invenio cfg requires pnpm.

    If ``WEBPACKEXT_NPM_PKG_CLS`` selects pnpm and the on-disk root ``package.json``
    is missing a ``pnpm@…`` ``packageManager`` field, restore it (preferring a
    version found in another in-tree ``package.json``). No-op when the field is
    already correct, the file is absent, or webpack is not configured for pnpm.
    """
    if not webpack_uses_pnpm(root):
        return []
    path = root / "package.json"
    if not path.is_file():
        return []
    try:
        raw = path.read_text(encoding="utf-8")
        data = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return []
    if not isinstance(data, dict):
        return []
    current = data.get("packageManager")
    if isinstance(current, str) and current.lower().startswith("pnpm@"):
        return []
    desired = _discover_pnpm_package_manager(root)
    data["packageManager"] = desired
    # Keep engines aligned when the assets template still lists npm only.
    engines = data.get("engines")
    if isinstance(engines, dict):
        engines = dict(engines)
        if "pnpm" not in engines:
            engines["pnpm"] = ">=10.0.0"
        engines.pop("npm", None)
        data["engines"] = engines
    try:
        path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    except OSError as exc:
        return [f"preflight: could not restore packageManager in package.json ({exc})"]
    return [
        f"preflight: restored packageManager={desired!r} in package.json "
        f"(WEBPACKEXT_NPM_PKG_CLS uses PNPMPackage)"
    ]


def _mock_lock_npm_document(
    document: dict,
    *,
    label: str,
    run_fn: RunFn,
    build_process: str = BUILD_NPM,
    prefer_pnpm: bool = False,
) -> tuple[_MockLockResult, list[str]]:
    """Lockfile-only resolve for an in-memory npm package document (no prior lock)."""
    warnings: list[str] = []
    if not any(
        document.get(s) for s in ("dependencies", "devDependencies", "optionalDependencies")
    ):
        warnings.append(f"preflight: {label}: no registry npm deps left to mock-lock")
        return (
            _MockLockResult(
                ok=False,
                ecosystem=NPM,
                versions={},
                build_process=build_process,
                detail="empty",
            ),
            warnings,
        )

    argv = _package_manager_argv(prefer_pnpm=prefer_pnpm)
    with tempfile.TemporaryDirectory(prefix="vulnscan-preflight-npm-") as tmp:
        temp = Path(tmp)
        (temp / "package.json").write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
        _assert_safe_argv(argv)
        result = run_fn(argv, temp)
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "").strip()
            warnings.append(
                f"preflight: {label}: {' '.join(argv)} failed"
                + (f": {detail[:400]}" if detail else "")
            )
            return (
                _MockLockResult(
                    ok=False,
                    ecosystem=NPM,
                    versions={},
                    build_process=build_process,
                    detail=detail,
                ),
                warnings,
            )
        versions = {key: ver for key, ver in load_lock_versions(temp).items() if key[0] == NPM}
    return (
        _MockLockResult(
            ok=True,
            ecosystem=NPM,
            versions=versions,
            build_process=build_process,
        ),
        warnings,
    )


def _mock_lock_package_json(
    manifest: Path,
    root: Path,
    run_fn: RunFn,
) -> tuple[_MockLockResult, list[str]]:
    """Fresh npm/pnpm lockfile-only resolve from one package.json (no prior lock)."""
    warnings: list[str] = []
    rel = _rel(manifest, root)
    try:
        data = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        warnings.append(f"preflight: {rel}: cannot read package.json ({exc})")
        return (
            _MockLockResult(
                ok=False,
                ecosystem=NPM,
                versions={},
                build_process=BUILD_NPM,
                detail=str(exc),
            ),
            warnings,
        )
    if not isinstance(data, dict):
        warnings.append(f"preflight: {rel}: package.json root must be an object")
        return (
            _MockLockResult(
                ok=False,
                ecosystem=NPM,
                versions={},
                build_process=BUILD_NPM,
            ),
            warnings,
        )

    cleaned = {
        "name": data.get("name") or "preflight-mock",
        "version": data.get("version") or "0.0.0",
        "private": True,
    }
    dropped: list[str] = []
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        raw = data.get(section)
        if not isinstance(raw, dict) or not raw:
            continue
        kept: dict[str, str] = {}
        for name, spec in raw.items():
            if _npm_non_registry(spec):
                dropped.append(str(name))
                continue
            kept[str(name)] = str(spec)
        if kept:
            cleaned[section] = kept
    if dropped:
        warnings.append(
            f"preflight: {rel}: dropping non-registry deps: " + ", ".join(sorted(dropped))
        )
    if isinstance(data.get("packageManager"), str):
        cleaned["packageManager"] = data["packageManager"]
    result, extra = _mock_lock_npm_document(
        cleaned,
        label=rel,
        run_fn=run_fn,
        prefer_pnpm=_prefer_pnpm(root, cleaned),
    )
    warnings.extend(extra)
    return result, warnings


def _mock_lock_invenio_assets(
    root: Path,
    *,
    ignore_dirs: tuple[str, ...],
    run_fn: RunFn,
    include_environment: bool = True,
) -> tuple[_MockLockResult, list[str]]:
    """Mock-lock the virtual assets package.json (full Invenio webpack merge tree)."""
    warnings: list[str] = []
    warnings.extend(restore_missing_package_manager(root))
    patterns = tuple(ignore_dirs) + load_ignore_file(root)
    document, merge_index, build_warnings = build_virtual_assets_package_json(
        root,
        ignore_patterns=patterns,
        include_environment=include_environment,
        package_manager=_resolve_package_manager_field(root),
    )
    warnings.extend(build_warnings)
    deps = document.get("dependencies") or {}
    if not deps:
        warnings.append(
            "preflight: Invenio virtual assets package.json has no mergeable npm dependencies"
        )
        return (
            _MockLockResult(
                ok=False,
                ecosystem=NPM,
                versions={},
                build_process=BUILD_INVENIO_ASSETS,
                detail="empty",
                webpack_merge=merge_index,
            ),
            warnings,
        )
    warnings.append(
        f"preflight: Invenio mode — mock-locking virtual assets package.json "
        f"({len(deps)} merged dependencies)"
    )
    result, extra = _mock_lock_npm_document(
        document,
        label="invenio-assets (virtual)",
        run_fn=run_fn,
        build_process=BUILD_INVENIO_ASSETS,
        prefer_pnpm=_prefer_pnpm(root, document),
    )
    warnings.extend(extra)
    return replace(result, webpack_merge=merge_index), warnings


def _mock_lock_requirements(
    manifest: Path,
    root: Path,
    run_fn: RunFn,
) -> tuple[_MockLockResult, list[str]]:
    """Treat a requirements file as a one-shot PyPI mock lock via a minimal pyproject."""
    warnings: list[str] = []
    rel = _rel(manifest, root)
    declared = parse_manifest(manifest, root)
    requirements = [_requirement_line(d) for d in declared if d.ecosystem == PYPI]
    if not requirements:
        warnings.append(f"preflight: {rel}: no PyPI requirements to mock-lock")
        return (
            _MockLockResult(
                ok=False,
                ecosystem=PYPI,
                versions={},
                build_process=BUILD_UV,
                detail="empty",
            ),
            warnings,
        )

    with tempfile.TemporaryDirectory(prefix="vulnscan-preflight-req-") as tmp:
        temp = Path(tmp)
        _write_minimal_pyproject(
            temp / "pyproject.toml",
            project_name=f"preflight-{manifest.stem}",
            requirements=requirements,
            requires_python=None,
        )
        argv = ["uv", "lock"]
        _assert_safe_argv(argv)
        result = run_fn(argv, temp)
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "").strip()
            warnings.append(
                f"preflight: {rel}: uv lock failed" + (f": {detail[:400]}" if detail else "")
            )
            return (
                _MockLockResult(
                    ok=False,
                    ecosystem=PYPI,
                    versions={},
                    build_process=BUILD_UV,
                    detail=detail,
                ),
                warnings,
            )
        versions = {key: ver for key, ver in load_lock_versions(temp).items() if key[0] == PYPI}
    return (
        _MockLockResult(
            ok=True,
            ecosystem=PYPI,
            versions=versions,
            build_process=BUILD_UV,
        ),
        warnings,
    )


def _mock_lock_setup_or_pipfile(
    manifest: Path,
    root: Path,
    run_fn: RunFn,
) -> tuple[_MockLockResult, list[str]]:
    """Extract PyPI deps from setup.cfg / Pipfile into a minimal mock pyproject."""
    return _mock_lock_requirements(manifest, root, run_fn)


_COMPOSER_NON_REGISTRY_REPO_TYPES = frozenset({"path", "vcs", "git", "artifact", "pear"})


def _composer_repositories(data: dict) -> list[dict]:
    """Normalize ``repositories`` to a list of dicts."""
    raw = data.get("repositories")
    if isinstance(raw, list):
        return [r for r in raw if isinstance(r, dict)]
    if isinstance(raw, dict):
        return [r for r in raw.values() if isinstance(r, dict)]
    return []


def _path_repo_package_names(manifest: Path, repos: list[dict]) -> set[str]:
    """Best-effort package names declared under path repositories."""
    names: set[str] = set()
    root = manifest.parent
    for repo in repos:
        if str(repo.get("type", "")).lower() != "path":
            continue
        url = repo.get("url")
        if not isinstance(url, str) or not url.strip():
            continue
        candidate = (root / url).resolve() / "composer.json"
        if not candidate.is_file():
            continue
        try:
            nested = json.loads(candidate.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        if isinstance(nested, dict) and isinstance(nested.get("name"), str):
            names.add(nested["name"])
    return names


def _mock_lock_composer(
    manifest: Path,
    root: Path,
    run_fn: RunFn,
) -> tuple[_MockLockResult, list[str]]:
    """Fresh ``composer update --no-install`` from one composer.json (no prior lock)."""
    warnings: list[str] = []
    rel = _rel(manifest, root)
    try:
        data = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        warnings.append(f"preflight: {rel}: cannot read composer.json ({exc})")
        return (
            _MockLockResult(
                ok=False,
                ecosystem=PACKAGIST,
                versions={},
                build_process=BUILD_COMPOSER,
                detail=str(exc),
            ),
            warnings,
        )
    if not isinstance(data, dict):
        warnings.append(f"preflight: {rel}: composer.json root must be an object")
        return (
            _MockLockResult(
                ok=False,
                ecosystem=PACKAGIST,
                versions={},
                build_process=BUILD_COMPOSER,
            ),
            warnings,
        )

    repos = _composer_repositories(data)
    path_names = _path_repo_package_names(manifest, repos)
    dropped_repos = [
        r for r in repos if str(r.get("type", "")).lower() in _COMPOSER_NON_REGISTRY_REPO_TYPES
    ]
    kept_repos = [
        r for r in repos if str(r.get("type", "")).lower() not in _COMPOSER_NON_REGISTRY_REPO_TYPES
    ]
    if dropped_repos:
        warnings.append(
            f"preflight: {rel}: dropping non-registry composer repositories: "
            + ", ".join(sorted({str(r.get("url") or r.get("type") or "?") for r in dropped_repos}))
        )

    cleaned: dict = {
        "name": data.get("name") or "vulnscan/preflight-mock",
        "description": "vulnscan preflight mock lock",
        "require": {},
        "require-dev": {},
    }
    if kept_repos:
        cleaned["repositories"] = kept_repos
    # Preserve packagist disable / config that affects resolve, but not scripts.
    if isinstance(data.get("config"), dict):
        cfg = {
            k: v
            for k, v in data["config"].items()
            if k in {"secure-http", "use-github-api", "gitlab-domains", "github-protocols"}
        }
        if cfg:
            cleaned["config"] = cfg
    if isinstance(data.get("minimum-stability"), str):
        cleaned["minimum-stability"] = data["minimum-stability"]
    if isinstance(data.get("prefer-stable"), bool):
        cleaned["prefer-stable"] = data["prefer-stable"]

    dropped_pkgs: list[str] = []
    for section in ("require", "require-dev"):
        raw = data.get(section)
        if not isinstance(raw, dict) or not raw:
            continue
        kept: dict[str, str] = {}
        for name, spec in raw.items():
            pkg = str(name)
            if pkg.lower() == "php" or pkg.lower().startswith("ext-"):
                kept[pkg] = str(spec)
                continue
            if pkg in path_names:
                dropped_pkgs.append(pkg)
                continue
            kept[pkg] = str(spec)
        cleaned[section] = kept
    if dropped_pkgs:
        warnings.append(
            f"preflight: {rel}: dropping path-repo packages: "
            + ", ".join(sorted(set(dropped_pkgs)))
        )

    has_pkgs = any(
        n.lower() != "php" and not n.lower().startswith("ext-")
        for section in ("require", "require-dev")
        for n in (cleaned.get(section) or {})
    )
    if not has_pkgs:
        warnings.append(f"preflight: {rel}: no Packagist deps left to mock-lock")
        return (
            _MockLockResult(
                ok=False,
                ecosystem=PACKAGIST,
                versions={},
                build_process=BUILD_COMPOSER,
                detail="empty",
            ),
            warnings,
        )

    argv = [
        "composer",
        "update",
        "--no-install",
        "--no-interaction",
        "--ignore-platform-reqs",
        "--no-scripts",
        "--no-plugins",
    ]
    with tempfile.TemporaryDirectory(prefix="vulnscan-preflight-composer-") as tmp:
        temp = Path(tmp)
        (temp / "composer.json").write_text(json.dumps(cleaned, indent=2) + "\n", encoding="utf-8")
        _assert_safe_argv(argv)
        result = run_fn(argv, temp)
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "").strip()
            warnings.append(
                f"preflight: {rel}: composer update --no-install failed"
                + (f": {detail[:400]}" if detail else "")
            )
            return (
                _MockLockResult(
                    ok=False,
                    ecosystem=PACKAGIST,
                    versions={},
                    build_process=BUILD_COMPOSER,
                    detail=detail,
                ),
                warnings,
            )
        versions = {
            key: ver for key, ver in load_lock_versions(temp).items() if key[0] == PACKAGIST
        }
    return (
        _MockLockResult(
            ok=True,
            ecosystem=PACKAGIST,
            versions=versions,
            build_process=BUILD_COMPOSER,
        ),
        warnings,
    )


def mock_lock_manifest(
    manifest: Path,
    root: Path,
    run_fn: RunFn,
) -> tuple[_MockLockResult | None, list[str]]:
    """Run one isolated mock lock for ``manifest``, or skip with warnings.

    Returns:
        ``(None, warnings)`` when the manifest kind is skipped; otherwise a result.
    """
    name = manifest.name
    if name in _SKIP_MANIFEST_NAMES:
        return None, [f"preflight: skipping {_rel(manifest, root)} (not a registry float target)"]
    if name == "pyproject.toml":
        result, warnings = _mock_lock_pyproject(manifest, root, run_fn)
        return _tag_resolve_from(result, _rel(manifest, root)), warnings
    if name == "package.json":
        result, warnings = _mock_lock_package_json(manifest, root, run_fn)
        return _tag_resolve_from(result, _rel(manifest, root)), warnings
    if name == "composer.json":
        result, warnings = _mock_lock_composer(manifest, root, run_fn)
        return _tag_resolve_from(result, _rel(manifest, root)), warnings
    if is_requirements_file(manifest):
        result, warnings = _mock_lock_requirements(manifest, root, run_fn)
        return _tag_resolve_from(result, _rel(manifest, root)), warnings
    if name in {"setup.cfg", "Pipfile"}:
        result, warnings = _mock_lock_setup_or_pipfile(manifest, root, run_fn)
        return _tag_resolve_from(result, _rel(manifest, root)), warnings
    return None, [f"preflight: skipping {_rel(manifest, root)} (unsupported for mock lock)"]


def _deps_by_key(deps: list[Dependency]) -> dict[tuple[str, str], Dependency]:
    out: dict[tuple[str, str], Dependency] = {}
    for dep in deps:
        out[dep.key] = dep
    return out


def run_preflight(
    settings: Settings,
    *,
    osv: OSVClient | None = None,
    registry: RegistryClient | None = None,
    run: RunFn | None = None,
    extra_ignores: Sequence[str] = (),
) -> PreflightReport:
    """Mock-lock each manifest in a temp dir, score would-be versions, never touch the project.

    Args:
        settings: Project path and freshness / ignore settings.
        osv: Optional OSV client.
        registry: Optional registry client.
        run: Injectable subprocess runner ``(argv, cwd) -> CompletedProcess``.
        extra_ignores: Extra exclude specs (CLI ``--preflight-ignore``).
    """
    project = settings.project_path
    run_fn = _logged_run(run or _default_run)
    warnings: list[str] = []
    log.info("preflight: starting for %s", project)
    ignore_patterns = tuple(settings.preflight_ignore) + load_preflight_ignore_file(project)
    ignore_patterns = ignore_patterns + tuple(extra_ignores)

    current_deps, parse_warnings = parse_project(
        project,
        ignore_dirs=settings.ignore_dirs,
        include_transitive=True,
    )
    # Keep parse warnings that are not the usual "unknown version" noise from
    # unconstrained leaves — those clutter preflight when we only care about resolve.
    for w in parse_warnings:
        if "could not determine a version" in w:
            continue
        warnings.append(w)
    current_by_key = _deps_by_key(current_deps)

    manifests = discover_manifests(project, ignore_dirs=settings.ignore_dirs)
    discovered_webpack = [p for p in manifests if p.name == "webpack.py"]
    invenio_mode = detect_invenio_webpack(
        project,
        settings.invenio_webpack,
        discovered_webpack=discovered_webpack,
    )
    log.info(
        "preflight: %d manifests, invenio_mode=%s, ignore patterns %s",
        len(manifests),
        invenio_mode,
        list(ignore_patterns),
    )
    would_versions: dict[tuple[str, str], str] = {}
    would_process: dict[tuple[str, str], str] = {}
    would_resolve_from: dict[tuple[str, str], str] = {}
    ecosystems: list[str] = []
    attempted = 0
    succeeded = 0
    webpack_merge = None

    def _absorb(result: _MockLockResult) -> None:
        nonlocal attempted, succeeded, webpack_merge
        attempted += 1
        if result.webpack_merge is not None:
            webpack_merge = result.webpack_merge
        if not result.ok:
            return
        succeeded += 1
        ecosystems.append(result.ecosystem)
        for key, ver in result.versions.items():
            would_versions[key] = ver
            would_process[key] = result.build_process
            if result.resolve_from:
                would_resolve_from[key] = result.resolve_from

    if invenio_mode:
        result, mw = _mock_lock_invenio_assets(
            project,
            ignore_dirs=settings.ignore_dirs,
            run_fn=run_fn,
        )
        warnings.extend(mw)
        _absorb(_tag_resolve_from(result, "invenio-assets (virtual)"))

    for manifest in manifests:
        if invenio_mode and manifest.name == "package.json":
            warnings.append(
                f"preflight: skipping {_rel(manifest, project)} "
                "(Invenio mode uses virtual assets package.json)"
            )
            continue
        log.info("preflight: mock-locking %s", _rel(manifest, project))
        result, mw = mock_lock_manifest(manifest, project, run_fn)
        warnings.extend(mw)
        if result is None:
            continue
        log.info(
            "preflight: %s %s with %d versions",
            _rel(manifest, project),
            "resolved" if result.ok else "failed",
            len(result.versions),
        )
        _absorb(result)

    resolve_ok = succeeded > 0
    log.info("preflight: %d of %d mock locks succeeded", succeeded, attempted)
    if attempted == 0:
        warnings.append(
            "preflight: no resolvable manifests "
            "(need pyproject.toml, package.json / Invenio assets merge, "
            "composer.json, requirements, setup.cfg, or Pipfile)"
        )
    elif succeeded == 0:
        warnings.append("preflight: every mock-lock attempt failed")
    if osv is None:
        osv = OSVClient(base_url=settings.osv_base_url, timeout=settings.request_timeout)
    if registry is None:
        registry = RegistryClient(timeout=settings.request_timeout)

    to_score: list[Dependency] = []
    packages: list[PreflightPackage] = []
    ignored: list[PreflightPackage] = []

    for (ecosystem, norm_name), would_be in sorted(would_versions.items()):
        # Recover a display name from the current tree when possible.
        current = None
        display_name = norm_name
        for key, dep in current_by_key.items():
            if key[0] == ecosystem and normalize_name(dep.name, ecosystem) == norm_name:
                current = dep
                display_name = dep.name
                break
        current_ver = current.version if current else None
        would_bump = current_ver is None or current_ver != would_be
        dep = Dependency(
            display_name,
            ecosystem,
            current.constraint if current else "",
            would_be,
            "preflight",
            current.source_file if current else "(mock lock)",
            current.dev if current else False,
        )
        process = would_process.get((ecosystem, norm_name), "")
        resolve_from = would_resolve_from.get((ecosystem, norm_name), "")
        upstream = None
        if webpack_merge is not None and ecosystem == NPM:
            upstream = webpack_merge.upstream_constraints_text(display_name)
        entry = PreflightPackage(
            dependency=dep,
            current=current_ver,
            would_be=would_be,
            would_bump=would_bump,
            build_process=process,
            resolve_from=resolve_from,
            upstream_constraints_text=upstream,
        )
        if is_excluded(dep, ignore_patterns):
            ignored.append(
                PreflightPackage(
                    dependency=dep,
                    current=current_ver,
                    would_be=would_be,
                    would_bump=would_bump,
                    build_process=process,
                    resolve_from=resolve_from,
                    upstream_constraints_text=upstream,
                    ignored=True,
                )
            )
            continue
        to_score.append(dep)
        packages.append(entry)

    for pattern in ignore_patterns:
        if not any(is_excluded(p.dependency, (pattern,)) for p in packages + ignored):
            warnings.append(f"preflight exclude {pattern!r} matched no package")

    scores = score_versions(to_score, osv=osv, registry=registry, fresh_hours=settings.fresh_hours)
    from vulnscan.risk import score_for

    scored_packages: list[PreflightPackage] = []
    for entry in packages:
        score = score_for(scores, entry.dependency, entry.would_be)
        interesting = entry.would_bump or (score is not None and bool(score.risks))
        if not interesting:
            continue
        scored_packages.append(
            PreflightPackage(
                dependency=entry.dependency,
                current=entry.current,
                would_be=entry.would_be,
                would_bump=entry.would_bump,
                build_process=entry.build_process,
                resolve_from=entry.resolve_from,
                upstream_constraints_text=entry.upstream_constraints_text,
                score=score,
            )
        )

    return PreflightReport(
        project_path=project,
        resolve_ok=resolve_ok,
        packages=scored_packages,
        ignored=ignored,
        warnings=warnings,
        ecosystems=tuple(dict.fromkeys(ecosystems)),
    )


def report_to_json(report: PreflightReport, *, strict_fresh: bool) -> dict:
    """Build the versioned JSON document for CI."""

    def pkg_dict(p: PreflightPackage, *, ignored: bool = False) -> dict:
        data: dict = {
            "name": p.dependency.name,
            "ecosystem": p.dependency.ecosystem,
            "current": p.current,
            "would_be": p.would_be,
            "would_bump": p.would_bump,
            "build_process": p.build_process,
            "resolve_from": p.resolve_from,
        }
        if p.upstream_constraints_text is not None:
            data["upstream_constraints"] = p.upstream_constraints_text
        if ignored:
            data["reason"] = "excluded"
            return data
        risks = []
        if p.score:
            for r in p.score.risks:
                risks.append(
                    {
                        "kind": str(r.kind),
                        "id": r.advisory_id,
                        "severity": r.severity,
                        "summary": r.detail,
                        "url": r.url,
                    }
                )
        data["risks"] = risks
        return data

    exit_code = report.exit_code(strict_fresh=strict_fresh)
    return {
        "schema_version": 1,
        "mode": "preflight",
        "scanned_at": report.scanned_at.isoformat(),
        "project_path": str(report.project_path),
        "resolve_ok": report.resolve_ok,
        "strict_fresh": strict_fresh,
        "summary": report.summary,
        "ok": exit_code == 0,
        "exit_code": exit_code,
        "packages": [pkg_dict(p) for p in report.packages],
        "ignored": [pkg_dict(p, ignored=True) for p in report.ignored],
        "warnings": list(report.warnings),
    }


def render_preflight_text(report: PreflightReport) -> str:
    """Human-readable preflight summary."""
    lines = [
        f"Preflight for {report.project_path}",
        f"Resolve: {'ok' if report.resolve_ok else 'FAILED'}",
        (
            f"Summary: bumps={report.summary['would_bump']} "
            f"advisory={report.summary['advisory']} malware={report.summary['malware']} "
            f"fresh={report.summary['fresh']} yanked={report.summary['yanked']}"
        ),
        "",
    ]
    for p in report.packages:
        bump = f"{p.current or '?'} → {p.would_be}" if p.would_bump else f"{p.would_be} (unchanged)"
        kinds = ",".join(sorted({str(r.kind) for r in (p.score.risks if p.score else ())})) or "-"
        process = p.build_process or "-"
        site = p.resolve_from or "-"
        lines.append(
            f"- {p.dependency.name} ({p.dependency.ecosystem}, {process} @ {site}): "
            f"{bump} [{kinds}]"
        )
    if report.ignored:
        lines.append("")
        lines.append("Ignored:")
        for p in report.ignored:
            lines.append(f"- {p.dependency.name} ({p.dependency.ecosystem})")
    if report.warnings:
        lines.append("")
        lines.append("Warnings:")
        for w in report.warnings:
            lines.append(f"- {w}")
    return "\n".join(lines) + "\n"


def write_json_report(report: PreflightReport, path: Path | None, *, strict_fresh: bool) -> str:
    """Serialize JSON to ``path`` (``None`` or ``-`` → return string only for stdout)."""
    payload = json.dumps(report_to_json(report, strict_fresh=strict_fresh), indent=2) + "\n"
    if path is not None and str(path) != "-":
        path.write_text(payload, encoding="utf-8")
    return payload
