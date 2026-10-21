"""Plan and apply dependency upgrades directly in manifests.

Edits are textual and minimal: only the constraint of the chosen package changes, so the
rest of the file (ordering, comments, indentation) is untouched.
"""

from __future__ import annotations

import ast
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.utils import canonicalize_name

from vulnscan.invenio import (
    collect_npm_constraints_for_package,
    detect_invenio_webpack,
    major_conflict_message,
    package_root_for_webpack,
    resolve_overlay,
)
from vulnscan.models import NPM, PACKAGIST, PYPI, WORDPRESS, Dependency, Finding, normalize_name
from vulnscan.parsers import is_requirements_file, load_ignore_file, matches_ignore
from vulnscan.parsers.webpack import (
    THEME_NAME,
    extract_theme_dependencies,
    find_theme_dependencies_node,
    mapping_pairs,
)
from vulnscan.versioncmp import compare_versions, sort_versions

if TYPE_CHECKING:
    from vulnscan.config import Settings


class RemediationError(Exception):
    """Raised when a manifest cannot be updated."""


@dataclass(frozen=True)
class RemediationPlan:
    """Upgrade options for one finding.

    ``current`` is the version in use (``None`` if unknown), ``nearest_safe`` the smallest
    newer version no advisory affects, ``latest`` the newest release and
    ``latest_is_safe`` whether that release is clear of advisories.
    """

    current: str | None
    nearest_safe: str | None
    latest: str | None
    latest_is_safe: bool


@dataclass(frozen=True)
class RemediationChange:
    """One manifest rewritten by :func:`apply_remediation`."""

    path: Path
    source_file: str
    old_constraint: str
    new_constraint: str
    authoritative: bool = True


@dataclass(frozen=True)
class RemediationResult:
    """Every manifest edit made for one dependency, plus the command to run afterwards."""

    changes: tuple[RemediationChange, ...]
    hint: str
    warnings: tuple[str, ...] = ()

    @property
    def path(self) -> Path:
        """Path of the primary manifest edited."""
        return self.changes[0].path

    @property
    def old_constraint(self) -> str:
        """Constraint the primary manifest had before the edit."""
        return self.changes[0].old_constraint

    @property
    def new_constraint(self) -> str:
        """Constraint written to the primary manifest."""
        return self.changes[0].new_constraint

    @property
    def authoritative_changes(self) -> tuple[RemediationChange, ...]:
        """Edits that gate remediation success (Invenio ``webpack.py`` writes)."""
        return tuple(c for c in self.changes if c.authoritative)


# --- planning ---------------------------------------------------------------------------------


def plan_remediation(
    finding: Finding,
    versions: list[str],
    webpack_merge: object | None = None,
) -> RemediationPlan:
    """Choose the smallest upgrade that clears every known advisory, and the newest release.

    When ``webpack_merge`` is a :class:`~vulnscan.invenio.WebpackMergeIndex` (or the
    finding already carries ``webpack_merge_block``), candidate versions that would
    break pywebpack's same-major merge are excluded from ``nearest_safe``.
    """
    dep = finding.dependency
    ordered = sort_versions(list(dict.fromkeys(versions)), dep.ecosystem)
    if not ordered:
        return RemediationPlan(dep.version, None, None, False)

    def is_safe(version: str) -> bool:
        return not any(v.affects(version, dep.ecosystem) for v in finding.vulnerabilities)

    def is_mergeable(version: str) -> bool:
        if finding.webpack_merge_block:
            return False
        if webpack_merge is None or dep.ecosystem != NPM:
            return True
        allows = getattr(webpack_merge, "allows", None)
        if allows is None:
            return True
        return bool(allows(dep.name, version))

    candidates = [
        v
        for v in ordered
        if dep.version is None or compare_versions(v, dep.version, dep.ecosystem) > 0
    ]
    safe = [v for v in candidates if is_safe(v) and is_mergeable(v)]
    latest = ordered[-1]
    return RemediationPlan(
        current=dep.version,
        nearest_safe=safe[0] if safe else None,
        latest=latest,
        latest_is_safe=is_safe(latest) and is_mergeable(latest),
    )


# --- constraint rewriting ---------------------------------------------------------------------

_COMPOSER_EXACT = re.compile(r"^(v?)(\d[\w.\-+]*)$")
_COMPOSER_SINGLE_OP = re.compile(r"^(\^|~|>=)\s*v?\d[\w.\-+]*$")


def rewrite_composer_constraint(old: str, new_version: str) -> str:
    """Keep the operator style (exact, ^, ~, >=) and swap the version.

    Anything more complex (ranges, wildcards, alternatives) becomes a caret constraint.
    """
    text = old.strip()
    if text.startswith("dev-") or "@dev" in text or text.endswith("-dev"):
        raise RemediationError(f"constraint {old!r} tracks a development branch; change it by hand")
    exact = _COMPOSER_EXACT.match(text)
    if exact:
        return exact.group(1) + new_version
    single = _COMPOSER_SINGLE_OP.match(text)
    if single:
        return single.group(1) + new_version
    return "^" + new_version


_NPM_EXACT = re.compile(r"^v?\d+\.\d+\.\d+(?:[-+][\w.\-]+)?$")
_NPM_SINGLE_OP = re.compile(r"^(\^|~|>=|=)\s*v?\d[\w.\-+]*$")


def rewrite_npm_range(old: str, new_version: str) -> str:
    """Keep the operator style (exact, ``=``, ``^``, ``~``, ``>=``) and swap the version.

    Anything more complex (``x`` ranges, ``*``, hyphen ranges, alternatives) becomes a
    caret range.
    """
    text = old.strip()
    if _NPM_EXACT.match(text):
        return new_version
    single = _NPM_SINGLE_OP.match(text)
    if single:
        return single.group(1) + new_version
    return "^" + new_version


def rewrite_pep508_specifier(old: str, new_version: str) -> str:
    """Raise the lower bound to new_version, keeping compatible upper bounds and exclusions."""
    try:
        specs = list(SpecifierSet(old.strip()))
    except InvalidSpecifier:
        specs = []
    if len(specs) == 1:
        spec = specs[0]
        if spec.operator in ("==", "===", "~=") and not spec.version.endswith(".*"):
            return spec.operator + new_version
        if spec.operator in (">=", ">"):
            return ">=" + new_version
    keep_other = sorted(str(s) for s in specs if s.operator == "!=")
    keep_upper = []
    for spec in sorted(specs, key=str):
        if spec.operator == "<" and compare_versions(new_version, spec.version, PYPI) < 0:
            keep_upper.append(str(spec))
        elif spec.operator == "<=" and compare_versions(new_version, spec.version, PYPI) <= 0:
            keep_upper.append(str(spec))
    return ",".join([">=" + new_version, *keep_other, *keep_upper])


_REQ_LINE = re.compile(
    r"^(?P<pre>\s*[A-Za-z0-9][A-Za-z0-9._-]*(?:\s*\[[^\]]*\])?)(?P<spec>[^;#]*?)(?P<post>\s*(?:[;#].*)?)$"
)


def _requirement_name(text: str) -> str | None:
    body = re.split(r"(^|\s)#", text, maxsplit=1)[0].strip()
    if not body or body.startswith("-"):
        return None
    try:
        return canonicalize_name(Requirement(body).name)
    except InvalidRequirement:
        return None


def _rewrite_requirement_text(text: str, name: str, new_version: str) -> str | None:
    """Rewrite one PEP 508 requirement string (a requirements line or a TOML string)."""
    if _requirement_name(text) != canonicalize_name(name):
        return None
    match = _REQ_LINE.match(text)
    if not match:
        return None
    new_spec = rewrite_pep508_specifier(match.group("spec"), new_version)
    return match.group("pre") + new_spec + match.group("post")


# --- manifest editing -------------------------------------------------------------------------


def _name_pattern(name: str) -> str:
    """Regex matching a package name with -, _ and . treated as interchangeable."""
    return "".join("[-_.]" if ch in "-_." else re.escape(ch) for ch in name)


def _edit_json_constraint(
    text: str, dep: Dependency, new_version: str, source_file: str, rewrite
) -> tuple[str, str, str]:
    pattern = re.compile(r'("' + re.escape(dep.name) + r'"\s*:\s*")([^"]*)(")', re.IGNORECASE)
    match = pattern.search(text)
    if not match:
        raise RemediationError(f"{dep.name} not found in {source_file}")
    old = match.group(2)
    new = rewrite(old, new_version)
    return text[: match.start(2)] + new + text[match.end(2) :], old, new


def _edit_composer(
    text: str, dep: Dependency, new_version: str, source_file: str
) -> tuple[str, str, str]:
    return _edit_json_constraint(text, dep, new_version, source_file, rewrite_composer_constraint)


def _edit_package_json(
    text: str, dep: Dependency, new_version: str, source_file: str
) -> tuple[str, str, str]:
    return _edit_json_constraint(text, dep, new_version, source_file, rewrite_npm_range)


def _edit_requirement_lines(
    text: str, dep: Dependency, new_version: str, source_file: str
) -> tuple[str, str, str]:
    lines = text.splitlines(keepends=True)
    for i, raw in enumerate(lines):
        line = raw.rstrip("\r\n")
        rewritten = _rewrite_requirement_text(line, dep.name, new_version)
        if rewritten is not None and rewritten != line:
            lines[i] = rewritten + raw[len(line) :]
            return "".join(lines), line.strip(), rewritten.strip()
        if rewritten is not None:
            return text, line.strip(), line.strip()
    raise RemediationError(f"{dep.name} not found in {source_file}")


_TOML_STRING = re.compile(r'"([^"\\]*)"|\'([^\']*)\'')
_TOML_HEADER = re.compile(r"^\s*\[\[?\s*([^\]]+?)\s*\]\]?\s*(?:#.*)?$")
_TOML_KEY = re.compile(r"^\s*((?:\"[^\"]*\"|'[^']*'|[A-Za-z0-9_.\-])+)\s*=")

# PEP 508 requirement strings live only under these (table, key) pairs; a key of "*" means
# any key in the table.
_REQUIREMENT_CONTEXTS = {
    ("project", "dependencies"),
    ("project", "optional-dependencies"),
    ("project.optional-dependencies", "*"),
    ("dependency-groups", "*"),
    ("build-system", "requires"),
    ("tool.uv", "dev-dependencies"),
    ("tool.uv", "constraint-dependencies"),
    ("tool.uv", "override-dependencies"),
}


def _toml_line_contexts(text: str) -> list[tuple[int, str, str]]:
    """(line start offset, table, key) for every line of a TOML document.

    Tracks bracket depth outside strings so that lines inside multi-line arrays keep the
    key that opened them, and table headers are only recognised at depth zero.
    """
    contexts: list[tuple[int, str, str]] = []
    table = key = ""
    depth = offset = 0
    for line in text.splitlines(keepends=True):
        stripped = line.strip()
        if depth == 0 and not stripped.startswith("#"):
            header = _TOML_HEADER.match(line)
            if header:
                table, key = header.group(1).strip().strip("\"'"), ""
            else:
                match = _TOML_KEY.match(line)
                if match:
                    key = match.group(1).strip("\"'")
        contexts.append((offset, table, key))
        bare = _TOML_STRING.sub('""', line).split("#", 1)[0]
        depth += bare.count("[") + bare.count("{") - bare.count("]") - bare.count("}")
        depth = max(depth, 0)
        offset += len(line)
    return contexts


def _context_at(contexts: list[tuple[int, str, str]], offset: int) -> tuple[str, str]:
    table = key = ""
    for start, table_here, key_here in contexts:
        if start > offset:
            break
        table, key = table_here, key_here
    return table, key


def _holds_requirements(table: str, key: str) -> bool:
    return (table, key) in _REQUIREMENT_CONTEXTS or (table, "*") in _REQUIREMENT_CONTEXTS


def _is_poetry_dependency_table(table: str) -> bool:
    return table.startswith("tool.poetry") and table.endswith("dependencies")


def _edit_pyproject(
    text: str, dep: Dependency, new_version: str, source_file: str
) -> tuple[str, str, str]:
    """Rewrite the dependency in the tables that declare dependencies, and nowhere else.

    Strings elsewhere (``[tool.djlint] profile = "django"``) may well parse as a
    requirement, so only PEP 621 / PEP 735 / uv arrays and Poetry dependency tables are
    considered.
    """
    contexts = _toml_line_contexts(text)
    # PEP 621 / dependency-group style: a quoted PEP 508 requirement string.
    for match in _TOML_STRING.finditer(text):
        table, key = _context_at(contexts, match.start())
        if not _holds_requirements(table, key):
            continue
        line_before = text[text.rfind("\n", 0, match.start()) + 1 : match.start()]
        if re.search(r"include-group\s*=\s*$", line_before):
            continue
        literal = match.group(1) if match.group(1) is not None else match.group(2)
        rewritten = _rewrite_requirement_text(literal, dep.name, new_version)
        if rewritten is not None:
            start, end = match.start() + 1, match.end() - 1
            return text[:start] + rewritten + text[end:], literal, rewritten
    # Poetry style: `name = "^1.2"` or `name = { version = "^1.2", ... }`.
    name = _name_pattern(dep.name)
    for pattern in (
        re.compile(r"^(\s*" + name + r'\s*=\s*")([^"]*)(")', re.IGNORECASE | re.MULTILINE),
        re.compile(
            r"^(\s*" + name + r'\s*=\s*\{[^}\n]*?version\s*=\s*")([^"]*)(")',
            re.IGNORECASE | re.MULTILINE,
        ),
    ):
        for match in pattern.finditer(text):
            table, _key = _context_at(contexts, match.start())
            if not _is_poetry_dependency_table(table):
                continue
            old = match.group(2)
            new = (
                rewrite_composer_constraint(old, new_version)
                if old.strip() != "*"
                else "^" + new_version
            )
            return text[: match.start(2)] + new + text[match.end(2) :], old, new
    raise RemediationError(f"{dep.name} not found in {source_file}")


_PIPFILE_TABLES = {"packages", "dev-packages"}


def _edit_pipfile(
    text: str, dep: Dependency, new_version: str, source_file: str
) -> tuple[str, str, str]:
    """Rewrite the dependency under ``[packages]`` or ``[dev-packages]`` only."""
    contexts = _toml_line_contexts(text)
    name = _name_pattern(dep.name)
    for pattern in (
        re.compile(r'^(\s*"?' + name + r'"?\s*=\s*")([^"]*)(")', re.IGNORECASE | re.MULTILINE),
        re.compile(
            r'^(\s*"?' + name + r'"?\s*=\s*\{[^}\n]*?version\s*=\s*")([^"]*)(")',
            re.IGNORECASE | re.MULTILINE,
        ),
    ):
        for match in pattern.finditer(text):
            table, _key = _context_at(contexts, match.start())
            if table not in _PIPFILE_TABLES:
                continue
            old = match.group(2)
            new = rewrite_pep508_specifier("" if old.strip() == "*" else old, new_version)
            return text[: match.start(2)] + new + text[match.end(2) :], old, new
    raise RemediationError(f"{dep.name} not found in {source_file}")


def follow_up_hint(
    project_root: Path,
    dep: Dependency,
    source_file: str | None = None,
    *,
    invenio: bool = False,
) -> str:
    """The command that makes the change to ``source_file`` (default: the primary) take effect."""
    if invenio and dep.ecosystem == NPM:
        return (
            "Run `invenio webpack clean create` (then install/build as usual) so the "
            "generated package.json picks up the webpack.py overrides."
        )
    manifest = Path(source_file or dep.source_file)
    directory = (project_root / manifest).parent
    where = manifest.parent.as_posix()
    where = "" if where in ("", ".") else f" (in {where})"
    name = manifest.name.lower()
    if name == "composer.json":
        command = f"composer update {dep.name} --with-dependencies"
    elif name == "package.json":
        if (directory / "pnpm-lock.yaml").is_file():
            command = "pnpm install"
        elif (directory / "yarn.lock").is_file():
            command = "yarn install"
        else:
            command = "npm install"
    elif name == "pyproject.toml":
        if (directory / "poetry.lock").is_file():
            command = "poetry lock && poetry install"
        else:
            command = "uv lock && uv sync"
    elif name == "pipfile":
        command = "pipenv lock && pipenv sync"
    elif name == "setup.cfg":
        command = "pip install -e ."
    elif (directory / "uv.lock").is_file():
        command = "uv lock && uv sync"
    else:
        command = f"pip install -r {manifest.name}"
    return f"Run `{command}`{where} to apply it."


def _quote_style(segment: str) -> str:
    if len(segment) >= 2 and segment[0] == segment[-1] and segment[0] in "'\"":
        return segment[0]
    return '"'


def _edit_invenio_npm_dependency(
    text: str,
    package: str,
    new_version: str,
    source_file: str,
    *,
    insert: bool,
) -> tuple[str, str, str]:
    """Update or insert ``package`` under ``semantic-ui`` ``dependencies`` in a ``webpack.py``.

    When ``insert`` is false the key must already exist. When true and the key is missing,
    a new ``"name": "^version"`` entry is appended inside the dependencies mapping.
    """
    try:
        tree = ast.parse(text)
    except SyntaxError as exc:
        raise RemediationError(f"{source_file} is not valid Python: {exc}") from exc
    deps_node = find_theme_dependencies_node(tree, THEME_NAME)
    if deps_node is None:
        raise RemediationError(
            f"{source_file} has no WebpackThemeBundle themes[{THEME_NAME!r}].dependencies"
        )
    needle = normalize_name(package, NPM)
    existing = extract_theme_dependencies(text)
    current_key = next((name for name in existing if normalize_name(name, NPM) == needle), None)
    if current_key is not None:
        # Locate the value AST node for this key and rewrite its string literal.
        for name, value in mapping_pairs(deps_node):
            if name is None or normalize_name(name, NPM) != needle:
                continue
            if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
                raise RemediationError(
                    f"{package} constraint in {source_file} is not a string literal"
                )
            segment = ast.get_source_segment(text, value)
            if segment is None:
                raise RemediationError(f"cannot locate {package} constraint in {source_file}")
            old = value.value
            new = rewrite_npm_range(old, new_version)
            quote = _quote_style(segment)
            replacement = quote + new + quote
            start = _ast_offset(text, value)
            end = start + len(segment)
            return text[:start] + replacement + text[end:], old, new
        raise RemediationError(f"{package} not found in {source_file}")
    if not insert:
        raise RemediationError(f"{package} not found in {source_file}")
    new = "^" + new_version
    quote = '"'
    for _name, value in mapping_pairs(deps_node):
        segment = ast.get_source_segment(text, value) if value is not None else None
        if segment:
            quote = _quote_style(segment)
            break
    entry = f"{quote}{package}{quote}: {quote}{new}{quote}"
    inserted = _insert_into_mapping(text, deps_node, entry, source_file)
    return inserted, "", new


def _ast_offset(text: str, node: ast.AST) -> int:
    """Byte/char offset of ``node`` in ``text`` (1-based lineno/col_offset)."""
    if not hasattr(node, "lineno") or not hasattr(node, "col_offset"):
        raise RemediationError("AST node lacks source location")
    lines = text.splitlines(keepends=True)
    offset = sum(len(lines[i]) for i in range(node.lineno - 1))
    return offset + node.col_offset


def _insert_into_mapping(text: str, mapping: ast.AST, entry: str, source_file: str) -> str:
    """Insert ``entry`` as a new item before the closing of a dict / ``dict(...)`` call."""
    if not hasattr(mapping, "lineno") or not hasattr(mapping, "end_lineno"):
        raise RemediationError(f"cannot insert into dependencies in {source_file}")
    lines = text.splitlines(keepends=True)
    indent = "                "
    if isinstance(mapping, ast.Dict) and mapping.keys:
        first = mapping.keys[0]
        if first is not None and hasattr(first, "col_offset"):
            indent = " " * first.col_offset
    elif isinstance(mapping, ast.Call) and mapping.keywords:
        indent = " " * (mapping.col_offset + 4)

    end_lineno = mapping.end_lineno
    end_col = mapping.end_col_offset
    if end_lineno is None or end_col is None:
        raise RemediationError(f"cannot insert into dependencies in {source_file}")
    close_offset = sum(len(lines[i]) for i in range(end_lineno - 1)) + end_col - 1
    before = text[:close_offset].rstrip()
    nonempty = (isinstance(mapping, ast.Dict) and bool(mapping.keys)) or (
        isinstance(mapping, ast.Call) and bool(mapping.keywords)
    )
    needs_comma = nonempty and not before.endswith(",")
    prefix = "," if needs_comma else ""
    # Leave the closing brace/paren where it is; put the new entry on its own line.
    brace_indent = " " * max((mapping.col_offset if hasattr(mapping, "col_offset") else 0), 0)
    injection = f"{prefix}\n{indent}{entry},\n{brace_indent}"
    return text[:close_offset] + injection + text[close_offset:]


def _rel(project_root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(project_root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def _invenio_active(project_root: Path, settings: Settings | None) -> bool:
    if settings is None:
        return False
    discovered = [
        p
        for p in project_root.rglob("webpack.py")
        if ".venv" not in p.parts
        and "site-packages" not in p.parts
        and "node_modules" not in p.parts
        and "__pycache__" not in p.parts
    ]
    return detect_invenio_webpack(
        project_root, settings.invenio_webpack, discovered_webpack=discovered
    )


def _ignore_patterns(project_root: Path, settings: Settings) -> tuple[str, ...]:
    return tuple(settings.ignore_dirs) + load_ignore_file(project_root)


def _webpack_path_ignored(project_root: Path, path: Path, patterns: tuple[str, ...]) -> bool:
    """Whether any directory prefix of ``path`` matches ignore patterns (forks, etc.)."""
    if not patterns:
        return False
    try:
        rel = path.resolve().relative_to(project_root.resolve())
    except ValueError:
        return False
    parts = rel.parts[:-1] if rel.suffix or path.is_file() else rel.parts
    accum: list[str] = []
    for part in parts:
        accum.append(part)
        if matches_ignore("/".join(accum), patterns):
            return True
    return False


def _iter_project_webpack_py(project_root: Path):
    for path in project_root.rglob("webpack.py"):
        if (
            ".venv" in path.parts
            or "site-packages" in path.parts
            or "node_modules" in path.parts
            or "__pycache__" in path.parts
        ):
            continue
        if path.is_file():
            yield path.resolve()


def plan_invenio_npm_writes(
    project_root: Path,
    dep: Dependency,
    new_version: str,
    settings: Settings,
    webpack_merge: object | None = None,
) -> tuple[list[tuple[Path, bool]], list[Path], list[str]]:
    """Return ``(required_webpack, companion_package_json, preflight_errors)``.

    Each required entry is ``(path, insert)`` where ``insert`` is true only for the
    overlay when the package is not yet listed. Companion paths are existing
    ``package.json`` files to bump when they already declare the package.

    Paths under ``.vulnscanignore`` / ``ignore_dirs`` are never written, but their
    constraints still participate in the pywebpack major-version check (they may
    still be loaded at ``webpack create`` time).
    """
    errors: list[str] = []
    try:
        overlay = resolve_overlay(project_root, settings.invenio_webpack_overlay)
    except ValueError as exc:
        return [], [], [str(exc)]

    patterns = _ignore_patterns(project_root, settings)
    writable_webpack: list[Path] = []
    all_declaring: list[Path] = []
    seen: set[Path] = set()

    def consider(path: Path) -> None:
        resolved = path.resolve()
        if resolved in seen or not resolved.is_file() or resolved.name != "webpack.py":
            return
        try:
            deps_map = extract_theme_dependencies(resolved.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError):
            return
        if normalize_name(dep.name, NPM) not in {normalize_name(n, NPM) for n in deps_map}:
            return
        seen.add(resolved)
        all_declaring.append(resolved)
        if not _webpack_path_ignored(project_root, resolved, patterns):
            writable_webpack.append(resolved)

    for source_file in dep.source_files:
        consider(project_root / source_file)
    for path in _iter_project_webpack_py(project_root):
        consider(path)

    constraints = collect_npm_constraints_for_package(
        project_root, dep.name, all_declaring + [overlay]
    )
    # Include package.json constraints from declarations for major check.
    for source_file in dep.source_files:
        if Path(source_file).name.lower() != "package.json":
            continue
        path = project_root / source_file
        if not path.is_file():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        if not isinstance(data, dict):
            continue
        for section in ("dependencies", "devDependencies", "optionalDependencies"):
            table = data.get(section) or {}
            if not isinstance(table, dict):
                continue
            for name, spec in table.items():
                if normalize_name(str(name), NPM) == normalize_name(dep.name, NPM) and isinstance(
                    spec, str
                ):
                    constraints.append((source_file, spec))

    if webpack_merge is not None and hasattr(webpack_merge, "blocks"):
        conflict = webpack_merge.blocks(dep.name, new_version)
    else:
        conflict = major_conflict_message(dep.name, new_version, constraints)
    if conflict:
        return [], [], [conflict]

    overlay_resolved = overlay.resolve()
    overlay_has = normalize_name(dep.name, NPM) in {
        normalize_name(n, NPM)
        for n in extract_theme_dependencies(overlay.read_text(encoding="utf-8"))
    }
    required: list[tuple[Path, bool]] = [(overlay_resolved, not overlay_has)]
    for path in writable_webpack:
        if path.resolve() == overlay_resolved:
            continue
        required.append((path.resolve(), False))

    companion: list[Path] = []
    companion_seen: set[Path] = set()

    def add_companion(path: Path) -> None:
        resolved = path.resolve()
        if resolved in companion_seen or not resolved.is_file():
            return
        try:
            data = json.loads(resolved.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return
        if not isinstance(data, dict):
            return
        for section in ("dependencies", "devDependencies", "optionalDependencies"):
            table = data.get(section) or {}
            if isinstance(table, dict) and any(
                normalize_name(str(n), NPM) == normalize_name(dep.name, NPM) for n in table
            ):
                companion.append(resolved)
                companion_seen.add(resolved)
                return

    for source_file in dep.source_files:
        if Path(source_file).name.lower() == "package.json":
            add_companion(project_root / source_file)

    for path, _insert in required:
        if path == overlay_resolved:
            continue
        pkg_root = package_root_for_webpack(path, project_root)
        if pkg_root is not None:
            add_companion(pkg_root / "package.json")

    return required, companion, errors


def _editor_for(path: Path, dep: Dependency, source_file: str):
    name = path.name.lower()
    if name == "composer.json" and dep.ecosystem in (PACKAGIST, WORDPRESS):
        return _edit_composer
    if name == "package.json" and dep.ecosystem == NPM:
        return _edit_package_json
    if name == "pyproject.toml":
        return _edit_pyproject
    if name == "pipfile":
        return _edit_pipfile
    if name == "setup.cfg" or is_requirements_file(path):
        return _edit_requirement_lines
    raise RemediationError(f"Don't know how to edit {source_file}")


def _apply_invenio_npm(
    project_root: Path,
    dep: Dependency,
    new_version: str,
    settings: Settings,
    webpack_merge: object | None = None,
) -> RemediationResult:
    required, companion, errors = plan_invenio_npm_writes(
        project_root, dep, new_version, settings, webpack_merge=webpack_merge
    )
    if errors:
        raise RemediationError(errors[0])
    if not required:
        raise RemediationError("no Invenio webpack.py targets to update")

    pending_required: list[tuple[Path, str, str, RemediationChange]] = []
    for path, insert in required:
        source_file = _rel(project_root, path)
        text = path.read_text(encoding="utf-8")
        new_text, old, new = _edit_invenio_npm_dependency(
            text, dep.name, new_version, source_file, insert=insert
        )
        pending_required.append(
            (
                path,
                text,
                new_text,
                RemediationChange(path, source_file, old, new, authoritative=True),
            )
        )

    # All-or-nothing for required webpack.py files.
    for path, text, new_text, _change in pending_required:
        if new_text != text:
            path.write_text(new_text, encoding="utf-8")

    warnings: list[str] = []
    companion_changes: list[RemediationChange] = []
    for path in companion:
        source_file = _rel(project_root, path)
        try:
            text = path.read_text(encoding="utf-8")
            new_text, old, new = _edit_package_json(text, dep, new_version, source_file)
            if new_text != text:
                path.write_text(new_text, encoding="utf-8")
            companion_changes.append(
                RemediationChange(path, source_file, old, new, authoritative=False)
            )
        except (OSError, UnicodeDecodeError, RemediationError) as exc:
            warnings.append(f"could not update companion {source_file}: {exc}")

    changes = tuple(c for *_, c in pending_required) + tuple(companion_changes)
    hint = follow_up_hint(project_root, dep, invenio=True)
    return RemediationResult(changes, hint, tuple(warnings))


def apply_remediation(
    project_root: Path,
    dep: Dependency,
    new_version: str,
    settings: Settings | None = None,
    webpack_merge: object | None = None,
) -> RemediationResult:
    """Rewrite the dependency's constraint to require ``new_version`` in every manifest
    that declares it.

    For npm dependencies in an Invenio/RDM app (see ``settings.invenio_webpack``), updates
    the site overlay ``webpack.py`` (insert or bump), every in-tree ``webpack.py`` that
    already declares the package, and companion ``package.json`` files. Required
    ``webpack.py`` edits are computed before any of them are written; companion
    ``package.json`` failures become warnings and do not roll back webpack writes.

    For other ecosystems (and npm outside Invenio mode), every rewrite is computed before
    any file is written, so a manifest that cannot be edited leaves all of them untouched.
    """
    if dep.ecosystem == NPM and settings is not None and _invenio_active(project_root, settings):
        return _apply_invenio_npm(
            project_root, dep, new_version, settings, webpack_merge=webpack_merge
        )

    source_files = [sf for sf in dep.source_files if Path(sf).name != "webpack.py"]
    if not source_files:
        raise RemediationError(
            f"no editable manifests for {dep.name} (webpack.py requires Invenio webpack mode)"
        )
    pending: list[tuple[Path, str, str, RemediationChange]] = []
    for source_file in source_files:
        path = project_root / source_file
        if not path.is_file():
            raise RemediationError(f"{source_file} does not exist under {project_root}")
        editor = _editor_for(path, dep, source_file)
        text = path.read_text(encoding="utf-8")
        new_text, old, new = editor(text, dep, new_version, source_file)
        pending.append((path, text, new_text, RemediationChange(path, source_file, old, new)))
    for path, text, new_text, _change in pending:
        if new_text != text:
            path.write_text(new_text, encoding="utf-8")
    hints = dict.fromkeys(follow_up_hint(project_root, dep, sf) for sf in source_files)
    return RemediationResult(tuple(c for *_, c in pending), " ".join(hints))


def display_name(dep: Dependency) -> str:
    """Canonical package name used when referring to a dependency in messages."""
    return normalize_name(dep.name, dep.ecosystem)
