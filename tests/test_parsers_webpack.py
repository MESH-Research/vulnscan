import json
from pathlib import Path

from vulnscan.models import merge_declarations
from vulnscan.parsers import discover_manifests, parse_project
from vulnscan.parsers.webpack import extract_theme_dependencies, parse_webpack_py

BRACE_WEBPACK = """\
from invenio_assets.webpack import WebpackThemeBundle

theme = WebpackThemeBundle(
    __name__,
    "assets",
    default="semantic-ui",
    themes={
        "semantic-ui": {
            "entry": {"app": "./js/app.js"},
            "dependencies": {
                "axios": "^1.20.0",
                "yup": "^0.32.11",
            },
        },
    },
)
"""

DICT_WEBPACK = """\
from invenio_assets.webpack import WebpackThemeBundle

theme = WebpackThemeBundle(
    __name__,
    "assets",
    default="semantic-ui",
    themes={
        "semantic-ui": dict(
            entry={"app": "./js/app.js"},
            dependencies={
                "i18next": "^20.3.0",
                "@babel/runtime": "^7.9.0",
            },
        ),
    },
)
"""


def test_extract_brace_and_dict_forms():
    assert extract_theme_dependencies(BRACE_WEBPACK) == {
        "axios": "^1.20.0",
        "yup": "^0.32.11",
    }
    assert extract_theme_dependencies(DICT_WEBPACK) == {
        "i18next": "^20.3.0",
        "@babel/runtime": "^7.9.0",
    }


def test_extract_returns_empty_without_bundle():
    assert extract_theme_dependencies("x = 1\n") == {}
    assert extract_theme_dependencies("not python") == {}


def test_parse_webpack_py_emits_npm_deps(tmp_path: Path):
    path = tmp_path / "webpack.py"
    path.write_text(BRACE_WEBPACK)
    deps = parse_webpack_py(path, tmp_path)
    assert {(d.name, d.constraint, d.source_file, d.ecosystem) for d in deps} == {
        ("axios", "^1.20.0", "webpack.py", "npm"),
        ("yup", "^0.32.11", "webpack.py", "npm"),
    }


def test_discover_includes_webpack_py(tmp_path: Path):
    (tmp_path / "webpack.py").write_text(BRACE_WEBPACK)
    found = [p.relative_to(tmp_path).as_posix() for p in discover_manifests(tmp_path)]
    assert found == ["webpack.py"]


def test_discover_respects_vulnscanignore_for_fork_webpack(tmp_path: Path):
    controlled = tmp_path / "site" / "app" / "dependencies" / "ours"
    fork = tmp_path / "site" / "app" / "dependencies" / "fork"
    controlled.mkdir(parents=True)
    fork.mkdir(parents=True)
    (controlled / "webpack.py").write_text(BRACE_WEBPACK)
    (fork / "webpack.py").write_text(DICT_WEBPACK)
    (tmp_path / ".vulnscanignore").write_text("site/app/dependencies/fork\n")
    found = sorted(p.relative_to(tmp_path).as_posix() for p in discover_manifests(tmp_path))
    assert found == ["site/app/dependencies/ours/webpack.py"]


def test_parse_project_merges_webpack_constraints(tmp_path: Path):
    (tmp_path / "webpack.py").write_text(BRACE_WEBPACK)
    deps, warnings = parse_project(tmp_path)
    assert not warnings
    names = {d.name for d in deps}
    assert "axios" in names and "yup" in names


def test_webpack_py_uses_root_lock_and_merges_with_package_json(tmp_path: Path):
    """Invenio: theme-bundle constraints share the project-root installed version."""
    site = tmp_path / "site" / "app"
    site.mkdir(parents=True)
    (site / "webpack.py").write_text(BRACE_WEBPACK)
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"axios": "^1.20.0", "yup": "^0.32.11"}})
    )
    (tmp_path / "package-lock.json").write_text(
        json.dumps(
            {
                "lockfileVersion": 2,
                "packages": {
                    "": {"dependencies": {"axios": "^1.20.0", "yup": "^0.32.11"}},
                    "node_modules/axios": {"version": "1.8.2"},
                    "node_modules/yup": {"version": "0.32.11"},
                },
            }
        )
    )
    deps, _warnings = parse_project(tmp_path)
    merged = merge_declarations(deps)
    axios = next(d for d in merged if d.name == "axios")
    assert axios.version == "1.8.2"
    assert axios.version_source == "lock"
    assert "package.json" in axios.source_files
    assert "site/app/webpack.py" in axios.source_files
    assert any(d.constraint == "^1.20.0" for d in axios.declared_in)
