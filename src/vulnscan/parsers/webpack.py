"""Parser for Invenio ``webpack.py`` theme bundles (``WebpackThemeBundle``).

These files declare npm constraints under ``themes["semantic-ui"]["dependencies"]``.
Parsing is AST-only; the module is never executed.
"""

from __future__ import annotations

import ast
from pathlib import Path

from vulnscan.models import NPM, Dependency

THEME_NAME = "semantic-ui"
BUNDLE_NAME = "WebpackThemeBundle"


def _const_str(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _is_bundle_call(node: ast.Call) -> bool:
    func = node.func
    if isinstance(func, ast.Name) and func.id == BUNDLE_NAME:
        return True
    return isinstance(func, ast.Attribute) and func.attr == BUNDLE_NAME


def mapping_pairs(node: ast.AST) -> list[tuple[str | None, ast.AST]]:
    """Key/value pairs from a dict literal or ``dict(...)`` call.

    Keys that are not string constants are returned as ``None`` (skipped by callers
    that need names).
    """
    if isinstance(node, ast.Dict):
        return [(_const_str(k), v) for k, v in zip(node.keys, node.values, strict=True)]
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "dict":
        pairs: list[tuple[str | None, ast.AST]] = []
        for kw in node.keywords:
            if kw.arg is not None:
                pairs.append((kw.arg, kw.value))
        return pairs
    return []


def _lookup(mapping: ast.AST, key: str) -> ast.AST | None:
    for name, value in mapping_pairs(mapping):
        if name == key:
            return value
    return None


def extract_theme_dependencies(text: str, theme: str = THEME_NAME) -> dict[str, str]:
    """Return ``{package: constraint}`` from the first ``WebpackThemeBundle`` in ``text``.

    Looks under ``themes[theme]["dependencies"]`` (brace dict or ``dict(...)``). Returns
    an empty dict when the file has no usable bundle or the theme/dependencies are
    missing. Non-string entries are skipped.
    """
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not _is_bundle_call(node):
            continue
        themes_node: ast.AST | None = None
        for kw in node.keywords:
            if kw.arg == "themes":
                themes_node = kw.value
                break
        if themes_node is None and len(node.args) >= 4:
            themes_node = node.args[3]
        if themes_node is None:
            continue
        theme_node = _lookup(themes_node, theme)
        if theme_node is None:
            continue
        deps_node = _lookup(theme_node, "dependencies")
        if deps_node is None:
            continue
        result: dict[str, str] = {}
        for name, value in mapping_pairs(deps_node):
            constraint = _const_str(value)
            if name and constraint is not None:
                result[name] = constraint
        return result
    return {}


def find_theme_dependencies_node(tree: ast.AST, theme: str = THEME_NAME) -> ast.AST | None:
    """AST node for ``themes[theme]["dependencies"]``, or ``None``."""
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not _is_bundle_call(node):
            continue
        themes_node: ast.AST | None = None
        for kw in node.keywords:
            if kw.arg == "themes":
                themes_node = kw.value
                break
        if themes_node is None and len(node.args) >= 4:
            themes_node = node.args[3]
        if themes_node is None:
            continue
        theme_node = _lookup(themes_node, theme)
        if theme_node is None:
            continue
        return _lookup(theme_node, "dependencies")
    return None


def parse_webpack_py(path: Path, root: Path) -> list[Dependency]:
    """Parse npm dependencies from an Invenio ``webpack.py`` theme bundle.

    Returns ``[]`` when the file is unreadable, not a theme bundle, or has no
    ``semantic-ui`` dependencies.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []
    deps_map = extract_theme_dependencies(text)
    if not deps_map:
        return []
    try:
        source_file = path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        source_file = path.as_posix()
    return [
        Dependency(
            name=name,
            ecosystem=NPM,
            constraint=constraint,
            version=None,
            version_source="unknown",
            source_file=source_file,
            kind="invenio-webpack",
        )
        for name, constraint in deps_map.items()
    ]
