"""Plan and apply dependency upgrades directly in manifests.

Edits are textual and minimal: only the constraint of the chosen package changes, so the
rest of the file (ordering, comments, indentation) is untouched.
"""

from __future__ import annotations

import ast
import json
import logging
import re
from collections.abc import Mapping
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
from vulnscan.models import (
    CONTAINER,
    NPM,
    PACKAGIST,
    PYPI,
    WORDPRESS,
    Dependency,
    Finding,
    normalize_name,
)
from vulnscan.parsers import is_requirements_file, load_ignore_file, matches_ignore
from vulnscan.parsers.containers import (
    DOCKER_URI_PREFIX,
    compose_images,
    dockerfile_images,
    github_workflow_images,
    gitlab_ci_images,
    is_compose_file,
    is_dockerfile,
    is_github_workflow,
    is_gitlab_ci_file,
    parse_image_reference,
    substitute_variables,
    tag_for_version,
    version_from_tag,
)
from vulnscan.parsers.invenio_webpack import (
    THEME_NAME,
    extract_theme_dependencies,
    find_theme_dependencies_node,
    mapping_pairs,
)
from vulnscan.versioncmp import compare_versions, sort_versions

if TYPE_CHECKING:
    from vulnscan.config import Settings


log = logging.getLogger("vulnscan.remediate")


class RemediationError(Exception):
    """Raised when a manifest cannot be updated."""


@dataclass(frozen=True)
class RemediationPlan:
    """Upgrade options for one finding.

    ``current`` is the version in use (``None`` if unknown), ``nearest_safe`` the smallest
    newer version that clears current advisories and forward-check blocking risks,
    ``latest`` the newest release and ``latest_is_safe`` whether that release is clear.
    ``warnings`` carries non-blocking notes (e.g. freshness).
    """

    current: str | None
    nearest_safe: str | None
    latest: str | None
    latest_is_safe: bool
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True)
class RemediationChange:
    """One manifest rewritten by :func:`apply_remediation`."""

    path: Path
    source_file: str
    old_constraint: str
    new_constraint: str
    authoritative: bool = True
    added: bool = False
    """The constraint was inserted (a transitive dependency pinned) rather than rewritten."""


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


def _blocking_summary(blocking) -> str:
    """Compact ``kind: id, id; kind: detail`` text for the risks that disqualified a version.

    Advisories are named by identifier rather than quoting their descriptions, which for
    NVD-sourced advisories can run to many lines each.
    """
    by_kind: dict[str, list[str]] = {}
    for risk in blocking:
        kind = str(getattr(risk, "kind", "risk"))
        label = getattr(risk, "advisory_id", None) or str(getattr(risk, "detail", risk))
        if label not in by_kind.setdefault(kind, []):
            by_kind[kind].append(label)
    return "; ".join(f"{kind}: {', '.join(labels)}" for kind, labels in by_kind.items()) or (
        "blocking risk"
    )


def plan_remediation(
    finding: Finding,
    versions: list[str],
    webpack_merge: object | None = None,
    scores: Mapping[str, object] | None = None,
) -> RemediationPlan:
    """Choose the smallest upgrade that clears every known advisory, and the newest release.

    When ``webpack_merge`` is a :class:`~vulnscan.invenio.WebpackMergeIndex` (or the
    finding already carries ``webpack_merge_block``), candidate versions that would
    break pywebpack's same-major merge are excluded from ``nearest_safe``.

    When ``scores`` maps version strings to objects with ``has_blocking`` / ``is_fresh``
    (typically :class:`~vulnscan.risk.VersionScore`), candidates with blocking risks are
    skipped; freshness becomes a warning on the plan rather than a disqualification.
    ``scores=None`` preserves local-only safety (unit tests).
    """
    dep = finding.dependency
    ordered = sort_versions(list(dict.fromkeys(versions)), dep.ecosystem)
    if not ordered:
        return RemediationPlan(dep.version, None, None, False)

    def is_locally_safe(version: str) -> bool:
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

    def forward_ok(version: str) -> bool:
        if scores is None:
            return True
        score = scores.get(version)
        if score is None:
            return True
        return not bool(getattr(score, "has_blocking", False))

    def is_safe(version: str) -> bool:
        return is_locally_safe(version) and is_mergeable(version) and forward_ok(version)

    candidates = [
        v
        for v in ordered
        if dep.version is None or compare_versions(v, dep.version, dep.ecosystem) > 0
    ]
    safe = [v for v in candidates if is_safe(v)]
    latest = ordered[-1]
    warnings: list[str] = []
    nearest = safe[0] if safe else None
    for version in [nearest, latest] if nearest or latest else []:
        if version is None or scores is None:
            continue
        score = scores.get(version)
        if score is not None and getattr(score, "is_fresh", False):
            warnings.append(f"{dep.name} {version} was published within the freshness window")
    # Explain first blocked local-safe candidate when nearest had to walk past it.
    if scores is not None:
        for version in candidates:
            if not is_locally_safe(version) or not is_mergeable(version):
                continue
            score = scores.get(version)
            if score is not None and getattr(score, "has_blocking", False):
                blocking = getattr(score, "blocking", lambda: ())()
                warnings.append(f"skipped {version} ({_blocking_summary(blocking)})")
                break
    log.info(
        "plan: %s %s: %d candidates above current, %d safe; nearest %s, latest %s%s",
        dep.name,
        dep.version or "?",
        len(candidates),
        len(safe),
        nearest or "none",
        latest,
        "" if is_safe(latest) else " (not safe)",
    )
    return RemediationPlan(
        current=dep.version,
        nearest_safe=nearest,
        latest=latest,
        latest_is_safe=is_safe(latest),
        warnings=tuple(dict.fromkeys(warnings)),
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
    if dep.ecosystem == CONTAINER and (is_github_workflow(manifest) or is_gitlab_ci_file(manifest)):
        return "Commit and push the change; the next pipeline run uses the new image."
    if dep.ecosystem == CONTAINER and is_compose_file(manifest):
        command = "docker compose pull && docker compose up -d"
    elif dep.ecosystem == CONTAINER and is_dockerfile(manifest):
        return (
            f"Rebuild the image from {manifest.as_posix()} (docker build / docker compose build)."
        )
    elif name == "composer.json":
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


# --- container images -------------------------------------------------------------------------

_IMAGE_VARIABLE = re.compile(r"\$(?:\{(?P<braced>[^}]*)\}|(?P<bare>[A-Za-z_][A-Za-z0-9_]*))")


def _split_tag(reference: str) -> tuple[str, str, str]:
    """``(name part, tag, digest)`` of a literal reference as written."""
    digest = ""
    if "@" in reference:
        reference, digest = reference.split("@", 1)
    colon = reference.rfind(":")
    if colon > reference.rfind("/"):
        return reference[:colon], reference[colon + 1 :], digest
    return reference, "", digest


def _new_tag(dep: Dependency, new_version: str) -> str:
    """The tag naming ``new_version`` in the same style as the dependency's current tag."""
    _current, variant = version_from_tag(dep.constraint)
    tag = tag_for_version(new_version, variant)
    if dep.constraint.startswith("v") and not new_version.startswith("v"):
        tag = "v" + tag
    return tag


def _replace_version(value: str, dep: Dependency, new_version: str) -> str | None:
    """Rewrite the version inside ``value`` (an ARG default or inline default), or None."""
    if dep.constraint and dep.constraint in value:
        return value.replace(dep.constraint, _new_tag(dep, new_version), 1)
    if not dep.version:
        return None
    match = re.search(r"(?<![\w.])v?" + re.escape(dep.version) + r"(?![\w.])", value)
    if match is None:
        return None
    prefix = "v" if match.group(0).startswith("v") else ""
    return value[: match.start()] + prefix + new_version + value[match.end() :]


def _rewrite_reference_text(
    raw: str, dep: Dependency, new_version: str, lookup_arg, source_file: str
) -> tuple[str | None, list[tuple[str, str]]]:
    """How to rewrite one reference as written.

    Returns the new reference text (None when the reference itself is unchanged) and
    ``(variable, new default)`` pairs for ``ARG`` lines that must change instead.
    """
    if "$" not in raw:
        name_part, _tag, _digest = _split_tag(raw)
        return f"{name_part}:{_new_tag(dep, new_version)}", []
    text = raw
    arg_edits: list[tuple[str, str]] = []
    for match in list(_IMAGE_VARIABLE.finditer(raw)):
        if match.group("bare") is not None:
            name, default = match.group("bare"), None
        else:
            inner = match.group("braced")
            name, default = inner, None
            for sep in (":-", "-"):
                if sep in inner:
                    name, default = inner.split(sep, 1)
                    break
        if default is not None:
            replaced = _replace_version(default, dep, new_version)
            if replaced is not None:
                text = text.replace(match.group(0), match.group(0).replace(default, replaced, 1), 1)
                return text, arg_edits
        current = lookup_arg(name)
        if current is None:
            continue
        replaced = _replace_version(current, dep, new_version)
        if replaced is not None:
            arg_edits.append((name, replaced))
            return None, arg_edits
    raise RemediationError(
        f"{dep.name} in {source_file} takes its tag from a variable ({raw}) whose value is "
        "not set in that file; update the variable where it is defined"
    )


def _replace_token(segment: str, token: str, replacement: str) -> str:
    """Replace whitespace-delimited occurrences of ``token`` in ``segment``."""
    return re.sub(r"(?<!\S)" + re.escape(token) + r"(?!\S)", lambda _m: replacement, segment)


def _logical_lines(text: str) -> list[tuple[int, int, str]]:
    """``(start, end, joined)`` for each Dockerfile instruction, continuation lines merged."""
    spans: list[tuple[int, int, str]] = []
    offset = 0
    start = None
    joined = ""
    for raw in text.splitlines(keepends=True):
        line = raw.rstrip("\r\n")
        stripped = line.strip()
        if start is None:
            if not stripped or stripped.startswith("#"):
                offset += len(raw)
                continue
            start = offset
        if stripped.endswith("\\"):
            joined += stripped[:-1] + " "
            offset += len(raw)
            continue
        if stripped.startswith("#"):
            offset += len(raw)
            continue
        joined += stripped
        spans.append((start, offset + len(line), joined))
        start, joined = None, ""
        offset += len(raw)
    return spans


def _edit_dockerfile(
    text: str, dep: Dependency, new_version: str, source_file: str
) -> tuple[str, str, str]:
    """Rewrite the tag of every ``FROM`` naming the dependency, or the ``ARG`` it comes from.

    A ``@sha256:`` digest on the rewritten reference is dropped, since it pinned the old
    tag's content.
    """
    args: dict[str, str] = {}
    arg_lines: dict[str, tuple[int, int, str]] = {}
    for start, end, joined in _logical_lines(text):
        head, _, rest = joined.partition(" ")
        if head.upper() == "ARG":
            name, eq, value = rest.strip().partition("=")
            if eq:
                args[name.strip()] = value.strip().strip("\"'")
                arg_lines[name.strip()] = (start, end, joined)
    wanted = [
        raw
        for raw, expanded in dockerfile_images(text)
        if (ref := parse_image_reference(expanded)) is not None
        and ref.name == normalize_name(dep.name, CONTAINER)
        and ref.tag == dep.constraint
    ]
    if not wanted:
        raise RemediationError(f"{dep.name}:{dep.constraint} not found in {source_file}")
    edits: list[tuple[int, int, str]] = []
    arg_edits: dict[str, str] = {}
    for start, end, joined in _logical_lines(text):
        head, _, rest = joined.partition(" ")
        if head.upper() != "FROM":
            continue
        segment = text[start:end]
        for raw in wanted:
            if not re.search(r"(?<!\S)" + re.escape(raw) + r"(?!\S)", segment):
                continue
            replacement, for_args = _rewrite_reference_text(
                raw, dep, new_version, args.get, source_file
            )
            for name, value in for_args:
                arg_edits[name] = value
            if replacement is not None:
                segment = _replace_token(segment, raw, replacement)
        if segment != text[start:end]:
            edits.append((start, end, segment))
    for name, value in arg_edits.items():
        start, end, _joined = arg_lines[name]
        segment = text[start:end]
        old_value = args[name]
        edits.append((start, end, segment.replace(old_value, value, 1)))
    new_text = text
    for start, end, segment in sorted(edits, reverse=True):
        new_text = new_text[:start] + segment + new_text[end:]
    return new_text, dep.constraint, _new_tag(dep, new_version)


def _edit_yaml_images(
    text: str, dep: Dependency, new_version: str, source_file: str, images_fn
) -> tuple[str, str, str]:
    """Rewrite the image references ``images_fn`` finds in a YAML file, line by line.

    Only the lines the parser identified as images change, so a look-alike value
    elsewhere (an environment variable, a script line) is left alone. Quotes and
    comments on the line are kept.
    """
    lines = text.splitlines(keepends=True)
    changed = False
    for written in images_fn(text):
        number = getattr(written, "line", -1)
        if number < 0 or number >= len(lines):
            continue
        prefix = DOCKER_URI_PREFIX if written.startswith(DOCKER_URI_PREFIX) else ""
        scalar = written[len(prefix) :]
        # Defaults are expanded; variables without one become a placeholder so the
        # image name still parses and the missing value can be reported by name.
        ref = parse_image_reference(_IMAGE_VARIABLE.sub("unset", substitute_variables(scalar, {})))
        if ref is None or ref.name != normalize_name(dep.name, CONTAINER):
            continue
        if ref.tag != dep.constraint and "unset" not in ref.tag:
            continue
        replacement, _args = _rewrite_reference_text(
            scalar, dep, new_version, lambda _name: None, source_file
        )
        if replacement is None:
            continue
        raw = lines[number]
        at = raw.rfind(str(written))
        if at < 0:
            continue
        lines[number] = raw[:at] + prefix + replacement + raw[at + len(written) :]
        changed = True
    if not changed:
        raise RemediationError(f"{dep.name}:{dep.constraint} not found in {source_file}")
    return "".join(lines), dep.constraint, _new_tag(dep, new_version)


def _edit_compose(
    text: str, dep: Dependency, new_version: str, source_file: str
) -> tuple[str, str, str]:
    """Rewrite every service ``image:`` naming the dependency, keeping quotes and comments."""
    return _edit_yaml_images(text, dep, new_version, source_file, compose_images)


def _edit_github_workflow(
    text: str, dep: Dependency, new_version: str, source_file: str
) -> tuple[str, str, str]:
    """Rewrite job ``container``, ``services`` and ``uses: docker://`` images."""
    return _edit_yaml_images(text, dep, new_version, source_file, github_workflow_images)


def _edit_gitlab_ci(
    text: str, dep: Dependency, new_version: str, source_file: str
) -> tuple[str, str, str]:
    """Rewrite ``image``, ``image.name`` and ``services`` entries."""
    return _edit_yaml_images(text, dep, new_version, source_file, gitlab_ci_images)


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
    if dep.ecosystem == CONTAINER and is_dockerfile(path):
        return _edit_dockerfile
    if dep.ecosystem == CONTAINER and is_compose_file(path):
        return _edit_compose
    if dep.ecosystem == CONTAINER and is_github_workflow(path):
        return _edit_github_workflow
    if dep.ecosystem == CONTAINER and is_gitlab_ci_file(path):
        return _edit_gitlab_ci
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
    log.info(
        "remediate: %s %s -> %s in %s", dep.name, dep.version or "?", new_version, project_root
    )
    if dep.transitive:
        return apply_pin(project_root, dep, new_version, settings=settings)
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
    for path, text, new_text, change in pending:
        if new_text != text:
            log.info(
                "remediate: writing %s (%s -> %s)",
                change.source_file,
                change.old_constraint,
                change.new_constraint,
            )
            path.write_text(new_text, encoding="utf-8")
        else:
            log.info("remediate: %s unchanged", change.source_file)
    hints = dict.fromkeys(follow_up_hint(project_root, dep, sf) for sf in source_files)
    return RemediationResult(tuple(c for *_, c in pending), " ".join(hints))


def display_name(dep: Dependency) -> str:
    """Canonical package name used when referring to a dependency in messages."""
    return normalize_name(dep.name, dep.ecosystem)


@dataclass(frozen=True)
class PinPlan:
    """Where and how a transitive dependency would be pinned to a version.

    ``path`` / ``source_file`` name the manifest next to the lock file that recorded the
    dependency, ``section`` the part of it that receives the entry (for people), and
    ``entry`` the exact text that will be inserted, such as ``certifi>=2026.10.19`` or
    ``"cookie": "^0.6.0"``. ``replaces`` is the existing value when the section already
    names the package.
    """

    path: Path
    source_file: str
    section: str
    entry: str
    replaces: str | None = None
    method: str = ""
    """Writing style: ``json``, ``pep621``, ``poetry``, ``pipfile`` or ``requirements``."""
    keys: tuple[str, ...] = ()
    """For ``json``: the path of the object that receives the entry (``("pnpm", "overrides")``)."""


# package.json section that forces a transitive version, by the lock file that sits next to it
_NPM_PIN_KEYS: dict[str, tuple[str, ...]] = {
    "package-lock.json": ("overrides",),
    "npm-shrinkwrap.json": ("overrides",),
    "yarn.lock": ("resolutions",),
    "pnpm-lock.yaml": ("pnpm", "overrides"),
}


def _skip_string(text: str, i: int) -> int:
    """Index just past the JSON string that opens at ``text[i]``."""
    i += 1
    while i < len(text):
        if text[i] == "\\":
            i += 2
            continue
        if text[i] == '"':
            return i + 1
        i += 1
    return i


def _match_bracket(text: str, i: int) -> int:
    """Index of the bracket closing the one at ``text[i]``, skipping strings."""
    depth = 0
    j = i
    while j < len(text):
        char = text[j]
        if char == '"':
            j = _skip_string(text, j)
            continue
        if char in "{[":
            depth += 1
        elif char in "}]":
            depth -= 1
            if depth == 0:
                return j
        j += 1
    raise RemediationError("unbalanced brackets in JSON manifest")


def _json_members(text: str, open_: int, close: int):
    """Yield ``(key, value_start, value_end)`` for each direct member of a JSON object."""
    i = open_ + 1
    while True:
        while i < close and text[i] in " \t\r\n,":
            i += 1
        if i >= close:
            return
        if text[i] != '"':
            raise RemediationError("unexpected content in JSON manifest")
        key_end = _skip_string(text, i)
        key = json.loads(text[i:key_end])
        i = key_end
        while text[i] in " \t\r\n":
            i += 1
        if text[i] != ":":
            raise RemediationError("unexpected content in JSON manifest")
        i += 1
        while text[i] in " \t\r\n":
            i += 1
        start = i
        if text[i] in "{[":
            end = _match_bracket(text, i) + 1
        elif text[i] == '"':
            end = _skip_string(text, i)
        else:
            end = i
            while end < close and text[end] != ",":
                end += 1
            while text[end - 1] in " \t\r\n":
                end -= 1
        yield key, start, end
        i = end


def _json_indent_unit(text: str) -> str:
    for line in text.splitlines():
        match = re.match(r'^([ \t]+)"', line)
        if match:
            return match.group(1)
    return "  "


def _render_json_value(value: str | dict, indent: str, unit: str) -> str:
    if isinstance(value, str):
        return json.dumps(value)
    inner = indent + unit
    members = [
        f"{inner}{json.dumps(k)}: {_render_json_value(v, inner, unit)}" for k, v in value.items()
    ]
    return "{\n" + ",\n".join(members) + "\n" + indent + "}"


def _json_insert_member(
    text: str, open_: int, close: int, key: str, value: str | dict, last: bool
) -> str:
    """Insert ``key: value`` into the object spanning ``text[open_:close + 1]``, keeping style."""
    unit = _json_indent_unit(text)
    line_start = text.rfind("\n", 0, open_) + 1
    outer = re.match(r"[ \t]*", text[line_start:open_]).group()
    inner = outer + unit
    body = text[open_ + 1 : close]
    member = f"{json.dumps(key)}: {_render_json_value(value, inner, unit)}"
    if not body.strip():
        return text[: open_ + 1] + "\n" + inner + member + "\n" + outer + text[close:]
    if last:
        end = close
        while text[end - 1] in " \t\r\n":
            end -= 1
        return text[:end] + ",\n" + inner + member + "\n" + outer + text[close:]
    if body.lstrip(" \t").startswith(("\n", "\r")):
        return text[: open_ + 1] + "\n" + inner + member + "," + text[open_ + 1 :]
    return text[: open_ + 1] + member + ", " + text[open_ + 1 :].lstrip(" ")


def _json_find(text: str, keys: tuple[str, ...]) -> tuple[int, int, int]:
    """``(open, close, found)`` of the deepest existing object along ``keys``.

    ``found`` is how many keys resolved to an object; the span is that object's.
    """
    open_ = text.index("{")
    close = _match_bracket(text, open_)
    found = 0
    for key in keys:
        hit = None
        for name, start, end in _json_members(text, open_, close):
            if name == key:
                if text[start] != "{":
                    raise RemediationError(f"{'.'.join(keys)} is not a JSON object")
                hit = (start, end - 1)
                break
        if hit is None:
            break
        open_, close = hit
        found += 1
    return open_, close, found


def _json_existing(text: str, keys: tuple[str, ...], name: str) -> str | None:
    """Current string value of ``name`` inside the object at ``keys``, if any."""
    try:
        open_, close, found = _json_find(text, keys)
    except (ValueError, RemediationError):
        return None
    if found != len(keys):
        return None
    for member, start, end in _json_members(text, open_, close):
        if member == name and text[start] == '"':
            return json.loads(text[start:end])
    return None


def _json_pin(text: str, keys: tuple[str, ...], name: str, value: str) -> str:
    """Set ``name: value`` inside the object at ``keys``, creating missing objects."""
    open_, close, found = _json_find(text, keys)
    if found < len(keys):
        # Build the missing objects from the inside out: {name: value} wrapped in each
        # absent key, then appended so new sections do not jump ahead of name/version.
        nested: dict = {name: value}
        for key in reversed(keys[found + 1 :]):
            nested = {key: nested}
        return _json_insert_member(text, open_, close, keys[found], nested, last=True)
    for member, start, end in _json_members(text, open_, close):
        if member == name:
            return text[:start] + json.dumps(value) + text[end:]
    return _json_insert_member(text, open_, close, name, value, last=False)


def _toml_table_line(text: str, table: str) -> int | None:
    """Index of the line holding the ``[table]`` header."""
    for idx, line in enumerate(text.splitlines(keepends=True)):
        header = _TOML_HEADER.match(line)
        if header and header.group(1).strip().strip("\"'") == table:
            return idx
    return None


def _toml_pep621_pin(text: str, requirement: str) -> str:
    """Add ``requirement`` to ``[project] dependencies``, creating the array if needed."""
    contexts = _toml_line_contexts(text)
    lines = text.splitlines(keepends=True)
    for idx, line in enumerate(lines):
        _offset, table, key = contexts[idx]
        match = _TOML_KEY.match(line)
        if not (table == "project" and key == "dependencies" and match):
            continue
        if match.group(1).strip("\"'") != "dependencies" or "[" not in line:
            continue
        bracket = line.index("[", match.end())
        rest = line[bracket + 1 :]
        if rest.strip() == "":
            following = next((ln for ln in lines[idx + 1 :] if ln.strip()), "")
            indent = re.match(r"[ \t]*", following).group() if following.strip() != "]" else ""
            indent = indent or "    "
            lines.insert(idx + 1, f'{indent}"{requirement}",\n')
        elif rest.strip().startswith("]"):
            lines[idx] = line[: bracket + 1] + f'\n    "{requirement}",\n' + rest.lstrip()
        else:
            lines[idx] = line[: bracket + 1] + f'"{requirement}", ' + rest.lstrip(" ")
        return "".join(lines)
    header = _toml_table_line(text, "project")
    if header is None:
        raise RemediationError("pyproject.toml has no [project] table")
    lines.insert(header + 1, f'dependencies = [\n    "{requirement}",\n]\n')
    return "".join(lines)


def _toml_table_pin(text: str, table: str, entry: str, create: bool) -> str:
    """Insert ``entry`` as the first line under ``[table]``."""
    header = _toml_table_line(text, table)
    lines = text.splitlines(keepends=True)
    if header is None:
        if not create:
            raise RemediationError(f"no [{table}] table to add {entry} to")
        joiner = "" if not text or text.endswith("\n") else "\n"
        return text + joiner + f"\n[{table}]\n{entry}\n"
    lines.insert(header + 1, entry + "\n")
    return "".join(lines)


def plan_pin(
    project_root: Path, dep: Dependency, version: str, settings: Settings | None = None
) -> PinPlan:
    """Work out which manifest would receive a constraint pinning ``dep`` to ``version``.

    The manifest is the one next to the lock file that recorded the dependency:
    ``package.json`` (``overrides``, ``resolutions`` or ``pnpm.overrides`` depending on
    the lock), ``composer.json`` (``require``), ``pyproject.toml`` (``[project]
    dependencies`` or the Poetry table), ``Pipfile`` (``[packages]``) or, failing a
    ``pyproject.toml``, ``requirements.txt``. Raises :class:`RemediationError` carrying
    :func:`transitive_hint` when nothing suitable exists.
    """
    name = display_name(dep)
    lock = Path(dep.source_file)
    directory = project_root / lock.parent
    hint = transitive_hint(dep, version)

    def plan(path: Path, section: str, entry: str, method: str, **extra) -> PinPlan:
        if not path.is_file():
            raise RemediationError(f"{hint} ({path.name} not found next to {lock.name}.)")
        return PinPlan(path, _rel(project_root, path), section, entry, method=method, **extra)

    if dep.ecosystem == NPM:
        if _invenio_active(project_root, settings):
            raise RemediationError(
                f"{hint} (Invenio webpack mode: package.json is generated, so it was not edited.)"
            )
        keys = _NPM_PIN_KEYS.get(lock.name, ("overrides",))
        path = directory / "package.json"
        existing = (
            _json_existing(path.read_text(encoding="utf-8"), keys, name) if path.is_file() else None
        )
        return plan(
            path,
            f'"{".".join(keys)}" in package.json',
            f'"{name}": "^{version}"',
            "json",
            keys=keys,
            replaces=existing,
        )
    if dep.ecosystem in (PACKAGIST, WORDPRESS):
        path = directory / "composer.json"
        existing = (
            _json_existing(path.read_text(encoding="utf-8"), ("require",), name)
            if path.is_file()
            else None
        )
        return plan(
            path,
            '"require" in composer.json',
            f'"{name}": "^{version}"',
            "json",
            keys=("require",),
            replaces=existing,
        )
    if lock.name == "Pipfile.lock":
        return plan(
            directory / "Pipfile", "[packages] in Pipfile", f'{name} = ">={version}"', "pipfile"
        )
    pyproject = directory / "pyproject.toml"
    if pyproject.is_file():
        text = pyproject.read_text(encoding="utf-8")
        if _toml_table_line(text, "project") is not None:
            return plan(
                pyproject,
                "[project] dependencies in pyproject.toml",
                f"{name}>={version}",
                "pep621",
            )
        if _toml_table_line(text, "tool.poetry.dependencies") is not None:
            return plan(
                pyproject,
                "[tool.poetry.dependencies] in pyproject.toml",
                f'{name} = ">={version}"',
                "poetry",
            )
        raise RemediationError(
            f"{hint} (pyproject.toml has neither a [project] nor a "
            "[tool.poetry.dependencies] table.)"
        )
    requirements = directory / "requirements.txt"
    if requirements.is_file():
        return plan(
            requirements, "a new line in requirements.txt", f"{name}>={version}", "requirements"
        )
    raise RemediationError(hint)


def apply_pin(
    project_root: Path, dep: Dependency, version: str, settings: Settings | None = None
) -> RemediationResult:
    """Insert the constraint from :func:`plan_pin` into its manifest and return the change."""
    pin = plan_pin(project_root, dep, version, settings=settings)
    name = display_name(dep)
    text = pin.path.read_text(encoding="utf-8")
    if pin.method == "json":
        new_text = _json_pin(text, pin.keys, name, f"^{version}")
    elif pin.method == "pep621":
        new_text = _toml_pep621_pin(text, pin.entry)
    elif pin.method == "poetry":
        new_text = _toml_table_pin(text, "tool.poetry.dependencies", pin.entry, create=False)
    elif pin.method == "pipfile":
        new_text = _toml_table_pin(text, "packages", pin.entry, create=True)
    else:
        joiner = "" if not text or text.endswith("\n") else "\n"
        new_text = text + joiner + pin.entry + "\n"
    pin.path.write_text(new_text, encoding="utf-8")
    change = RemediationChange(
        pin.path, pin.source_file, pin.replaces or "", pin.entry, added=pin.replaces is None
    )
    return RemediationResult((change,), follow_up_hint(project_root, dep, pin.source_file))


def transitive_hint(dep: Dependency, version: str) -> str:
    """Explain how to move a transitive dependency to ``version``.

    Nothing declares the package, so no manifest can be rewritten in place; the hint names
    the constraint to add by hand and the packages that pull the dependency in.
    """
    name = display_name(dep)
    if dep.ecosystem == PYPI:
        add = f"add {name}>={version} to your dependencies (pyproject.toml or a requirements file)"
    elif dep.ecosystem == NPM:
        add = f'add "{name}": "^{version}" under "overrides" in package.json'
    else:
        add = f'add "{name}": "^{version}" to "require" in composer.json'
    via = ""
    upgrade = ""
    if dep.required_by:
        requirers = ", ".join(dep.required_by)
        via = f" required by {requirers}"
        upgrade = f", or upgrade {requirers} to a release that needs {name} {version} or newer"
    return (
        f"{dep.name} is a transitive dependency{via}; it is not declared in any manifest. "
        f"To move to {version}, {add}{upgrade}, then reinstall."
    )
