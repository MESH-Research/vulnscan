"""Plan and apply dependency upgrades directly in manifests.

Edits are textual and minimal: only the constraint of the chosen package changes, so the
rest of the file (ordering, comments, indentation) is untouched.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.utils import canonicalize_name

from vulnscan.models import PACKAGIST, PYPI, WORDPRESS, Dependency, Finding, normalize_name
from vulnscan.versioncmp import compare_versions, sort_versions


class RemediationError(Exception):
    """Raised when a manifest cannot be updated."""


@dataclass(frozen=True)
class RemediationPlan:
    current: str | None
    nearest_safe: str | None
    latest: str | None
    latest_is_safe: bool


@dataclass(frozen=True)
class RemediationResult:
    path: Path
    old_constraint: str
    new_constraint: str
    hint: str


# --- planning ---------------------------------------------------------------------------------


def plan_remediation(finding: Finding, versions: list[str]) -> RemediationPlan:
    """Choose the smallest upgrade that clears every known advisory, and the newest release."""
    dep = finding.dependency
    ordered = sort_versions(list(dict.fromkeys(versions)), dep.ecosystem)
    if not ordered:
        return RemediationPlan(dep.version, None, None, False)

    def is_safe(version: str) -> bool:
        return not any(v.affects(version, dep.ecosystem) for v in finding.vulnerabilities)

    candidates = [
        v
        for v in ordered
        if dep.version is None or compare_versions(v, dep.version, dep.ecosystem) > 0
    ]
    safe = [v for v in candidates if is_safe(v)]
    latest = ordered[-1]
    return RemediationPlan(
        current=dep.version,
        nearest_safe=safe[0] if safe else None,
        latest=latest,
        latest_is_safe=is_safe(latest),
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


def _edit_composer(text: str, dep: Dependency, new_version: str) -> tuple[str, str, str]:
    pattern = re.compile(r'("' + re.escape(dep.name) + r'"\s*:\s*")([^"]*)(")', re.IGNORECASE)
    match = pattern.search(text)
    if not match:
        raise RemediationError(f"{dep.name} not found in composer.json")
    old = match.group(2)
    new = rewrite_composer_constraint(old, new_version)
    return text[: match.start(2)] + new + text[match.end(2) :], old, new


def _edit_requirement_lines(text: str, dep: Dependency, new_version: str) -> tuple[str, str, str]:
    lines = text.splitlines(keepends=True)
    for i, raw in enumerate(lines):
        line = raw.rstrip("\r\n")
        rewritten = _rewrite_requirement_text(line, dep.name, new_version)
        if rewritten is not None and rewritten != line:
            lines[i] = rewritten + raw[len(line) :]
            return "".join(lines), line.strip(), rewritten.strip()
        if rewritten is not None:
            return text, line.strip(), line.strip()
    raise RemediationError(f"{dep.name} not found in {dep.source_file}")


_TOML_STRING = re.compile(r'"([^"\\]*)"|\'([^\']*)\'')


def _edit_pyproject(text: str, dep: Dependency, new_version: str) -> tuple[str, str, str]:
    # PEP 621 / dependency-group style: a quoted PEP 508 requirement string.
    for match in _TOML_STRING.finditer(text):
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
        match = pattern.search(text)
        if match:
            old = match.group(2)
            new = (
                rewrite_composer_constraint(old, new_version)
                if old.strip() != "*"
                else "^" + new_version
            )
            return text[: match.start(2)] + new + text[match.end(2) :], old, new
    raise RemediationError(f"{dep.name} not found in {dep.source_file}")


def _edit_pipfile(text: str, dep: Dependency, new_version: str) -> tuple[str, str, str]:
    name = _name_pattern(dep.name)
    for pattern in (
        re.compile(r'^(\s*"?' + name + r'"?\s*=\s*")([^"]*)(")', re.IGNORECASE | re.MULTILINE),
        re.compile(
            r'^(\s*"?' + name + r'"?\s*=\s*\{[^}\n]*?version\s*=\s*")([^"]*)(")',
            re.IGNORECASE | re.MULTILINE,
        ),
    ):
        match = pattern.search(text)
        if match:
            old = match.group(2)
            new = rewrite_pep508_specifier("" if old.strip() == "*" else old, new_version)
            return text[: match.start(2)] + new + text[match.end(2) :], old, new
    raise RemediationError(f"{dep.name} not found in Pipfile")


def follow_up_hint(project_root: Path, dep: Dependency) -> str:
    """The command that makes the manifest change take effect."""
    manifest = Path(dep.source_file)
    directory = (project_root / manifest).parent
    where = manifest.parent.as_posix()
    where = "" if where in ("", ".") else f" (in {where})"
    name = manifest.name.lower()
    if name == "composer.json":
        command = f"composer update {dep.name} --with-dependencies"
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


def apply_remediation(project_root: Path, dep: Dependency, new_version: str) -> RemediationResult:
    """Rewrite the dependency's constraint in its manifest to require new_version."""
    path = project_root / dep.source_file
    if not path.is_file():
        raise RemediationError(f"{dep.source_file} does not exist under {project_root}")
    name = path.name.lower()
    if name == "composer.json" and dep.ecosystem in (PACKAGIST, WORDPRESS):
        editor = _edit_composer
    elif name == "pyproject.toml":
        editor = _edit_pyproject
    elif name == "pipfile":
        editor = _edit_pipfile
    elif name == "setup.cfg" or (name.endswith(".txt") and "requirements" in name):
        editor = _edit_requirement_lines
    else:
        raise RemediationError(f"Don't know how to edit {dep.source_file}")
    text = path.read_text(encoding="utf-8")
    new_text, old, new = editor(text, dep, new_version)
    if new_text != text:
        path.write_text(new_text, encoding="utf-8")
    return RemediationResult(path, old, new, follow_up_hint(project_root, dep))


def display_name(dep: Dependency) -> str:
    return normalize_name(dep.name, dep.ecosystem)
