"""Detect Invenio/RDM apps and locate the site overlay ``webpack.py``.

Also checks whether a proposed npm bump would break pywebpack's same-major
``merge_deps`` rule, using an in-memory merge of entry-point bundle constraints
(no Flask app, no ``webpack create``).
"""

from __future__ import annotations

import ast
import json
import re
from dataclasses import dataclass
from importlib import metadata
from importlib.machinery import PathFinder
from pathlib import Path

from vulnscan.models import NPM, Dependency, normalize_name
from vulnscan.parsers.webpack import BUNDLE_NAME, extract_theme_dependencies

# Match pywebpack.helpers.SEM_VER closely enough for major extraction.
_SEM_MAJOR = re.compile(
    r"^\D*(?P<major>0|[1-9]\d*)"
    r"(?:\.(?P<minor>0|[1-9]\d*))?"
    r"(?:\.(?P<patch>0|[1-9]\d*))?"
)

_INVENIO_MARKERS = (
    "invenio-assets",
    "invenio_assets",
    "invenio-app-rdm",
    "invenio_app_rdm",
    "invenio_assets.webpack",
)


def npm_major(constraint_or_version: str) -> int | None:
    """Major number from an npm version or simple range (``^1.2``, ``~2``, ``>=3.0.0``).

    Returns ``None`` when no major can be read (empty, ``*``, complex unions, etc.).
    """
    text = constraint_or_version.strip()
    if not text or text in {"*", "x", "X", "latest"}:
        return None
    # Take the first clause of simple unions / spaces.
    first = re.split(r"[\s|,]+", text, maxsplit=1)[0]
    match = _SEM_MAJOR.match(first)
    if not match:
        return None
    return int(match.group("major"))


def file_has_webpack_theme_bundle(path: Path) -> bool:
    """Whether ``path`` parses and contains a ``WebpackThemeBundle`` call."""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, SyntaxError):
        return False
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name) and func.id == BUNDLE_NAME:
            return True
        if isinstance(func, ast.Attribute) and func.attr == BUNDLE_NAME:
            return True
    return False


def _text_has_invenio_marker(text: str) -> bool:
    lowered = text.lower()
    return any(marker in lowered for marker in _INVENIO_MARKERS)


def project_has_invenio_signal(root: Path) -> bool:
    """Cheap markers: pyproject / setup.cfg mentions Invenio assets/app-rdm, or site webpack."""
    for rel in ("pyproject.toml", "setup.cfg", "setup.py"):
        path = root / rel
        if path.is_file():
            try:
                if _text_has_invenio_marker(path.read_text(encoding="utf-8")):
                    return True
            except (OSError, UnicodeDecodeError):
                pass
    site = root / "site"
    if site.is_dir():
        for child in site.iterdir():
            if not child.is_dir():
                continue
            webpack = child / "webpack.py"
            if webpack.is_file() and file_has_webpack_theme_bundle(webpack):
                return True
            for rel in ("pyproject.toml", "setup.cfg"):
                cfg = child / rel
                if cfg.is_file():
                    try:
                        if _text_has_invenio_marker(cfg.read_text(encoding="utf-8")):
                            return True
                    except (OSError, UnicodeDecodeError):
                        pass
    return False


def discover_theme_webpack_files(root: Path, paths: list[Path]) -> list[Path]:
    """Filter discovered ``webpack.py`` paths that define a theme bundle."""
    return [p for p in paths if p.name == "webpack.py" and file_has_webpack_theme_bundle(p)]


def detect_invenio_webpack(
    root: Path,
    mode: str,
    discovered_webpack: list[Path] | None = None,
) -> bool:
    """Whether Invenio webpack remediation/parsing extras should be active.

    ``mode`` is ``auto``, ``on``, or ``off``. In ``auto``, both a theme-bundle
    ``webpack.py`` and an Invenio project signal are required.
    """
    if mode == "off":
        return False
    if mode == "on":
        return True
    bundles = discovered_webpack
    if bundles is None:
        bundles = [
            p
            for p in root.rglob("webpack.py")
            if ".venv" not in p.parts
            and "site-packages" not in p.parts
            and "node_modules" not in p.parts
            and file_has_webpack_theme_bundle(p)
        ]
    else:
        bundles = discover_theme_webpack_files(root, bundles)
    return bool(bundles) and project_has_invenio_signal(root)


def resolve_overlay(root: Path, override: Path | None) -> Path:
    """Site overlay ``webpack.py`` path.

    Raises:
        ValueError: when the overlay cannot be determined uniquely.
    """
    if override is not None:
        path = override if override.is_absolute() else (root / override)
        path = path.expanduser().resolve()
        if not path.is_file():
            raise ValueError(f"Invenio webpack overlay does not exist: {path}")
        if not file_has_webpack_theme_bundle(path):
            raise ValueError(f"Invenio webpack overlay is not a WebpackThemeBundle: {path}")
        return path
    site = root / "site"
    candidates: list[Path] = []
    if site.is_dir():
        for child in sorted(site.iterdir()):
            webpack = child / "webpack.py"
            if webpack.is_file() and file_has_webpack_theme_bundle(webpack):
                candidates.append(webpack.resolve())
    if len(candidates) == 1:
        return candidates[0]
    if not candidates:
        raise ValueError(
            "No site/*/webpack.py WebpackThemeBundle found; set "
            "VULNSCAN_INVENIO_WEBPACK_OVERLAY or --invenio-webpack-overlay"
        )
    listed = ", ".join(p.relative_to(root).as_posix() for p in candidates)
    raise ValueError(
        f"Multiple site overlay webpack.py files ({listed}); set "
        "VULNSCAN_INVENIO_WEBPACK_OVERLAY or --invenio-webpack-overlay"
    )


def package_root_for_webpack(webpack_path: Path, project_root: Path) -> Path | None:
    """Nearest ancestor under ``project_root`` that looks like a Python package root."""
    root = project_root.resolve()
    cur = webpack_path.resolve().parent
    while True:
        if any((cur / name).is_file() for name in ("pyproject.toml", "setup.cfg", "setup.py")):
            try:
                cur.relative_to(root)
            except ValueError:
                return None
            return cur
        if cur == root or cur.parent == cur:
            return None
        cur = cur.parent


def collect_npm_constraints_for_package(
    project_root: Path, package: str, webpack_files: list[Path]
) -> list[tuple[str, str]]:
    """``(source_file, constraint)`` for ``package`` across theme ``webpack.py`` files."""
    needle = normalize_name(package, NPM)
    found: list[tuple[str, str]] = []
    for path in webpack_files:
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        deps = extract_theme_dependencies(text)
        for name, constraint in deps.items():
            if normalize_name(name, NPM) == needle:
                try:
                    rel = path.resolve().relative_to(project_root.resolve()).as_posix()
                except ValueError:
                    rel = path.as_posix()
                found.append((rel, constraint))
                break
    return found


def major_conflict_message(
    package: str,
    new_version: str,
    constraints: list[tuple[str, str]],
) -> str | None:
    """Human-readable block reason if ``new_version`` conflicts with any constraint major.

    pywebpack ``merge_deps`` refuses different majors for the same package.
    """
    new_major = npm_major(new_version)
    if new_major is None:
        return None
    conflicts: list[str] = []
    for source, constraint in constraints:
        other = npm_major(constraint)
        if other is not None and other != new_major:
            conflicts.append(f"{source} has {constraint!r} (major {other})")
    if not conflicts:
        return None
    return (
        f"pywebpack cannot merge {package!r} at {new_version!r} (major {new_major}) with "
        f"existing constraints: " + "; ".join(conflicts)
    )


def dependency_mentions_package(dep: Dependency, package: str) -> bool:
    return normalize_name(dep.name, dep.ecosystem) == normalize_name(package, dep.ecosystem)


@dataclass(frozen=True)
class WebpackMergeConflict:
    """One npm package with incompatible majors across webpack constraint sources."""

    package: str
    entries: tuple[tuple[str, str], ...]  # (source, constraint)

    def message(self) -> str:
        detail = "; ".join(f"{src} has {constraint!r}" for src, constraint in self.entries)
        return f"pywebpack merge conflict for {self.package!r}: {detail}"


def format_constraint_entries(entries: tuple[tuple[str, str], ...] | list[tuple[str, str]]) -> str:
    """``src as constraint`` joined with ``; ``, or ``none`` when empty."""
    if not entries:
        return "none"
    parts: list[str] = []
    for source, constraint in entries:
        if constraint:
            parts.append(f"{source} as {constraint}")
        else:
            parts.append(f"{source}; no version constraint")
    return "; ".join(parts)


@dataclass(frozen=True)
class WebpackMergeIndex:
    """All npm constraints that pywebpack would merge, keyed by canonical package name.

    Built once per scan from in-tree ``webpack.py`` files, ``invenio_assets.webpack``
    entry points in the project environment, and the invenio-assets base
    ``package.json``. Used to flag conflicts and to decide whether a candidate
    upgrade is mergeable (same major as every other source).
    """

    by_package: dict[str, tuple[tuple[str, str], ...]]
    conflicts: tuple[WebpackMergeConflict, ...]

    def entries_for(self, package: str) -> tuple[tuple[str, str], ...]:
        """``(source, constraint)`` pairs for ``package``, or an empty tuple."""
        return self.by_package.get(normalize_name(package, NPM), ())

    def upstream_constraints_text(self, package: str) -> str:
        """Formatted merge-tree constraints for reports, or ``none``."""
        return format_constraint_entries(self.entries_for(package))

    def allows(self, package: str, version: str) -> bool:
        """Whether ``version`` can merge with every recorded constraint for ``package``."""
        return self.blocks(package, version) is None

    def blocks(self, package: str, version: str) -> str | None:
        """Reason ``version`` cannot merge, or ``None`` if it can."""
        return major_conflict_message(package, version, list(self.entries_for(package)))

    def conflict_for(self, package: str) -> WebpackMergeConflict | None:
        needle = normalize_name(package, NPM)
        for conflict in self.conflicts:
            if normalize_name(conflict.package, NPM) == needle:
                return conflict
        return None

    def upgrade_limit_for(self, package: str, fixed_versions: list[str]) -> str | None:
        """Human-readable upgrade limit, or ``None`` when nothing blocks a mergeable fix.

        Covers existing major disagreements across sources, and the case where every
        advisory fixed version would require a different major than the merge tree.
        """
        conflict = self.conflict_for(package)
        if conflict is not None:
            return conflict.message()
        if not fixed_versions:
            return None
        if any(self.allows(package, ver) for ver in fixed_versions):
            return None
        entries = self.entries_for(package)
        constraint_majors = sorted(
            {m for _, c in entries if (m := npm_major(c)) is not None}
        )
        fixed_majors = sorted({m for ver in fixed_versions if (m := npm_major(ver)) is not None})
        if constraint_majors and fixed_majors and set(constraint_majors).isdisjoint(fixed_majors):
            held = ", ".join(f"major {m}" for m in constraint_majors)
            needed = ", ".join(f"{m}.x" for m in fixed_majors)
            return (
                f"pywebpack same-major ({held}); advisory fixes only at {needed} — "
                "major bump required"
            )
        detail = format_constraint_entries(entries)
        return (
            f"no advisory fixed version of {package!r} is compatible with "
            f"pywebpack merge ({detail})"
        )

    def warning_lines(self) -> list[str]:
        return [c.message() for c in self.conflicts]


def find_project_site_packages(project_root: Path) -> Path | None:
    """``site-packages`` under ``project_root/.venv``, if present."""
    root = project_root / ".venv"
    if not root.is_dir():
        return None
    for pattern in ("lib/python*/site-packages", "Lib/site-packages"):
        matches = sorted(root.glob(pattern))
        if matches:
            return matches[-1]
    return None


def _editable_search_paths(site_packages: Path) -> list[Path]:
    """``site-packages`` plus directories named in ``.pth`` / ``.egg-link`` (editables)."""
    paths: list[Path] = [site_packages]
    seen = {site_packages.resolve()}
    for pth in site_packages.glob("*.pth"):
        try:
            lines = pth.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError):
            continue
        for line in lines:
            text = line.strip()
            if not text or text.startswith("#") or text.startswith("import "):
                continue
            candidate = Path(text)
            if candidate.is_dir():
                resolved = candidate.resolve()
                if resolved not in seen:
                    seen.add(resolved)
                    paths.append(candidate)
    for egg in site_packages.glob("*.egg-link"):
        try:
            first = egg.read_text(encoding="utf-8").splitlines()[0].strip()
        except (OSError, UnicodeDecodeError, IndexError):
            continue
        candidate = Path(first)
        if candidate.is_dir():
            resolved = candidate.resolve()
            if resolved not in seen:
                seen.add(resolved)
                paths.append(candidate)
    return paths


def _module_to_webpack_path(search_paths: list[Path], module: str) -> Path | None:
    """Best-effort filesystem path for an entry-point module's ``webpack.py``."""
    parts = module.split(".")
    for root in search_paths:
        candidates = [
            root.joinpath(*parts).with_suffix(".py"),
            root.joinpath(*parts, "__init__.py"),
        ]
        for path in candidates:
            if not path.is_file():
                continue
            if path.name == "__init__.py":
                sibling = path.parent / "webpack.py"
                if sibling.is_file():
                    return sibling
            return path
    return None


def _resolve_module_file(search_paths: list[Path], module: str) -> Path | None:
    """Locate a module file without importing it or mutating ``sys.path``."""
    path_args = [str(p) for p in search_paths]
    try:
        spec = PathFinder.find_spec(module, path_args)
    except (ModuleNotFoundError, ValueError, AttributeError):
        spec = None
    if spec and spec.origin and spec.origin not in {"built-in", "frozen"}:
        origin = Path(spec.origin)
        if origin.name == "__init__.py":
            sibling = origin.parent / "webpack.py"
            if sibling.is_file():
                return sibling
        if origin.is_file():
            return origin
    return _module_to_webpack_path(search_paths, module)


def _label_for_path(project_root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(project_root.resolve()).as_posix()
    except ValueError:
        pass
    # Prefer a stable label under site-packages when outside the project.
    parts = path.resolve().parts
    if "site-packages" in parts:
        idx = parts.index("site-packages")
        return "site-packages/" + "/".join(parts[idx + 1 :])
    return path.as_posix()


def _collect_entry_point_sources(
    project_root: Path, site_packages: Path
) -> list[tuple[str, dict[str, str]]]:
    """Constraint maps from ``invenio_assets.webpack`` entry points (AST only).

    Uses only ``importlib.metadata`` against the project venv and filesystem
    resolution via :class:`PathFinder`. Does **not** mutate ``sys.path`` or
    import application modules (safe to run in a Textual worker thread).
    """
    sources: list[tuple[str, dict[str, str]]] = []
    site_str = str(site_packages)
    eps: list[metadata.EntryPoint] = []
    try:
        for dist in metadata.distributions(path=[site_str]):
            for ep in dist.entry_points:
                if ep.group == "invenio_assets.webpack":
                    eps.append(ep)
    except Exception:
        return sources

    search_paths = _editable_search_paths(site_packages)
    seen_files: set[Path] = set()
    for ep in eps:
        module = getattr(ep, "module", None) or ep.value.split(":", 1)[0]
        path = _resolve_module_file(search_paths, module)
        if path is None or not path.is_file():
            continue
        resolved = path.resolve()
        if resolved in seen_files:
            continue
        seen_files.add(resolved)
        try:
            deps = extract_theme_dependencies(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError):
            continue
        if deps:
            sources.append((_label_for_path(project_root, path), deps))
    return sources


def _collect_base_package_json(
    project_root: Path, site_packages: Path
) -> list[tuple[str, dict[str, str]]]:
    """Constraints from invenio-assets template ``package.json`` files."""
    sources: list[tuple[str, dict[str, str]]] = []
    assets = site_packages / "invenio_assets" / "assets"
    for name in ("package.json", "rspack-package.json"):
        path = assets / name
        if not path.is_file():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        if not isinstance(data, dict):
            continue
        merged: dict[str, str] = {}
        for section in ("dependencies", "devDependencies", "peerDependencies"):
            table = data.get(section) or {}
            if not isinstance(table, dict):
                continue
            for pkg, spec in table.items():
                if isinstance(spec, str) and spec.strip():
                    merged[str(pkg)] = spec.strip()
        if merged:
            sources.append((_label_for_path(project_root, path), merged))
    return sources


def _collect_intree_webpack(
    project_root: Path, ignore_patterns: tuple[str, ...] = ()
) -> list[tuple[str, dict[str, str]]]:
    from vulnscan.parsers import matches_ignore

    sources: list[tuple[str, dict[str, str]]] = []
    for path in project_root.rglob("webpack.py"):
        if any(
            part in {".venv", "site-packages", "node_modules", "__pycache__"} for part in path.parts
        ):
            continue
        if ignore_patterns:
            try:
                rel = path.resolve().relative_to(project_root.resolve())
            except ValueError:
                continue
            parts = rel.parts[:-1]
            accum: list[str] = []
            skipped = False
            for part in parts:
                accum.append(part)
                if matches_ignore("/".join(accum), ignore_patterns):
                    skipped = True
                    break
            if skipped:
                continue
        if not file_has_webpack_theme_bundle(path):
            continue
        try:
            deps = extract_theme_dependencies(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError):
            continue
        if deps:
            sources.append((_label_for_path(project_root, path), deps))
    return sources


def build_webpack_merge_index(
    project_root: Path,
    *,
    ignore_patterns: tuple[str, ...] = (),
    include_environment: bool = True,
) -> WebpackMergeIndex:
    """Collect every webpack npm constraint source and index conflicts.

    In-tree paths matching ``ignore_patterns`` are skipped on the walk. Installed
    ``invenio_assets.webpack`` entry points (including editables under an ignore
    path) are still collected from the project ``.venv``, which matches what
    ``webpack create`` loads.
    """
    sources: list[tuple[str, dict[str, str]]] = []
    sources.extend(_collect_intree_webpack(project_root, ignore_patterns))
    if include_environment:
        site = find_project_site_packages(project_root)
        if site is not None:
            sources.extend(_collect_entry_point_sources(project_root, site))
            sources.extend(_collect_base_package_json(project_root, site))

    by_package: dict[str, list[tuple[str, str]]] = {}
    seen_pair: set[tuple[str, str, str]] = set()
    for source, deps in sources:
        for name, constraint in deps.items():
            key = normalize_name(name, NPM)
            pair = (key, source, constraint)
            if pair in seen_pair:
                continue
            seen_pair.add(pair)
            by_package.setdefault(key, []).append((source, constraint))

    frozen = {k: tuple(v) for k, v in by_package.items()}
    conflicts: list[WebpackMergeConflict] = []
    for package, entries in sorted(frozen.items()):
        majors: dict[int, list[tuple[str, str]]] = {}
        for source, constraint in entries:
            major = npm_major(constraint)
            if major is None:
                continue
            majors.setdefault(major, []).append((source, constraint))
        if len(majors) > 1:
            # Flatten all entries that participate in the disagreement.
            flat = tuple((s, c) for group in majors.values() for s, c in group)
            conflicts.append(WebpackMergeConflict(package, flat))
    return WebpackMergeIndex(frozen, tuple(conflicts))
