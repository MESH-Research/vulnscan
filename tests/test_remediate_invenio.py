import json
from pathlib import Path

import pytest

from vulnscan.config import load_settings
from vulnscan.models import NPM, Declaration, Dependency
from vulnscan.parsers.webpack import extract_theme_dependencies
from vulnscan.remediate import (
    RemediationError,
    _edit_invenio_npm_dependency,
    apply_remediation,
)

OVERLAY = """\
from invenio_assets.webpack import WebpackThemeBundle

theme = WebpackThemeBundle(
    __name__,
    "assets",
    default="semantic-ui",
    themes={
        "semantic-ui": {
            "entry": {},
            "dependencies": {
                "axios": "^1.7.0",
            },
        },
    },
)
"""

SUBMODULE = """\
from invenio_assets.webpack import WebpackThemeBundle

theme = WebpackThemeBundle(
    __name__,
    "assets",
    default="semantic-ui",
    themes={
        "semantic-ui": dict(
            entry={},
            dependencies={
                "axios": "^1.7.0",
                "lodash": "^4.17.0",
            },
        ),
    },
)
"""

OTHER_SUBMODULE = """\
from invenio_assets.webpack import WebpackThemeBundle

theme = WebpackThemeBundle(
    __name__,
    "assets",
    default="semantic-ui",
    themes={
        "semantic-ui": {
            "dependencies": {
                "react": "^16.13.0",
            },
        },
    },
)
"""


def _settings(root: Path, **overrides):
    return load_settings(
        env={"VULNSCAN_PROJECT_PATH": str(root), "VULNSCAN_INVENIO_WEBPACK": "on"},
        dotenv_path=root / "none.env",
        overrides=overrides,
    )


def _tree(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    """overlay, controlled submodule webpack, other submodule webpack, submodule package.json."""
    overlay_dir = tmp_path / "site" / "kcworks"
    controlled = tmp_path / "site" / "kcworks" / "dependencies" / "ours" / "pkg"
    other = tmp_path / "site" / "kcworks" / "dependencies" / "other" / "pkg"
    overlay_dir.mkdir(parents=True)
    controlled.mkdir(parents=True)
    other.mkdir(parents=True)
    overlay = overlay_dir / "webpack.py"
    sub_wp = controlled / "webpack.py"
    other_wp = other / "webpack.py"
    overlay.write_text(OVERLAY)
    sub_wp.write_text(SUBMODULE)
    other_wp.write_text(OTHER_SUBMODULE)
    # Python package root one level up from pkg/
    pkg_root = controlled.parent
    (pkg_root / "pyproject.toml").write_text(
        '[project]\nname = "ours"\ndependencies = ["invenio-assets"]\n'
    )
    pkg_json = pkg_root / "package.json"
    pkg_json.write_text(json.dumps({"dependencies": {"axios": "^1.7.0", "jest": "^29.0.0"}}))
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "app"\ndependencies = ["invenio-app-rdm"]\n'
    )
    return overlay, sub_wp, other_wp, pkg_json


def test_edit_invenio_updates_existing():
    new_text, old, new = _edit_invenio_npm_dependency(
        OVERLAY, "axios", "1.20.0", "webpack.py", insert=False
    )
    assert old == "^1.7.0"
    assert new == "^1.20.0"
    assert extract_theme_dependencies(new_text)["axios"] == "^1.20.0"


def test_edit_invenio_inserts_when_missing():
    new_text, old, new = _edit_invenio_npm_dependency(
        OVERLAY, "lodash", "4.17.21", "webpack.py", insert=True
    )
    assert old == ""
    assert new == "^4.17.21"
    assert extract_theme_dependencies(new_text)["lodash"] == "^4.17.21"
    assert extract_theme_dependencies(new_text)["axios"] == "^1.7.0"


def test_apply_invenio_updates_overlay_and_declaring_submodule(tmp_path: Path):
    overlay, sub_wp, other_wp, pkg_json = _tree(tmp_path)
    dep = Dependency(
        "axios",
        NPM,
        "^1.7.0",
        "1.7.0",
        "lock",
        "site/kcworks/webpack.py",
        declarations=(
            Declaration("site/kcworks/webpack.py", "^1.7.0"),
            Declaration("site/kcworks/dependencies/ours/pkg/webpack.py", "^1.7.0"),
            Declaration("site/kcworks/dependencies/ours/package.json", "^1.7.0"),
        ),
    )
    settings = _settings(tmp_path)
    result = apply_remediation(tmp_path, dep, "1.20.0", settings=settings)
    assert extract_theme_dependencies(overlay.read_text())["axios"] == "^1.20.0"
    assert extract_theme_dependencies(sub_wp.read_text())["axios"] == "^1.20.0"
    # Submodule that did not declare axios is untouched.
    assert "axios" not in extract_theme_dependencies(other_wp.read_text())
    assert json.loads(pkg_json.read_text())["dependencies"]["axios"] == "^1.20.0"
    assert all(c.authoritative for c in result.authoritative_changes)
    assert any(not c.authoritative for c in result.changes)
    assert "webpack clean create" in result.hint


def test_apply_invenio_inserts_into_overlay_only(tmp_path: Path):
    overlay, sub_wp, other_wp, _pkg_json = _tree(tmp_path)
    dep = Dependency(
        "left-pad",
        NPM,
        "^1.0.0",
        "1.0.0",
        "lock",
        "package.json",
        declarations=(Declaration("package.json", "^1.0.0"),),
    )
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"left-pad": "^1.0.0"}}))
    settings = _settings(tmp_path)
    apply_remediation(tmp_path, dep, "1.3.0", settings=settings)
    assert extract_theme_dependencies(overlay.read_text())["left-pad"] == "^1.3.0"
    assert "left-pad" not in extract_theme_dependencies(sub_wp.read_text())
    assert "left-pad" not in extract_theme_dependencies(other_wp.read_text())


def test_apply_invenio_blocks_major_conflict(tmp_path: Path):
    _tree(tmp_path)
    dep = Dependency(
        "axios",
        NPM,
        "^1.7.0",
        "1.7.0",
        "lock",
        "site/kcworks/webpack.py",
        declarations=(Declaration("site/kcworks/webpack.py", "^1.7.0"),),
    )
    settings = _settings(tmp_path)
    with pytest.raises(RemediationError, match="pywebpack"):
        apply_remediation(tmp_path, dep, "2.0.0", settings=settings)
    # Overlay unchanged.
    assert (
        extract_theme_dependencies((tmp_path / "site/kcworks/webpack.py").read_text())["axios"]
        == "^1.7.0"
    )


def test_ignored_fork_webpack_not_written_but_blocks_major(tmp_path: Path):
    overlay, _sub_wp, _other_wp, _pkg = _tree(tmp_path)
    fork = tmp_path / "site" / "kcworks" / "dependencies" / "fork" / "pkg"
    fork.mkdir(parents=True)
    (fork / "webpack.py").write_text(
        """\
from invenio_assets.webpack import WebpackThemeBundle
theme = WebpackThemeBundle(
    __name__, "assets", default="semantic-ui",
    themes={"semantic-ui": {"dependencies": {"axios": "^1.9.0"}}},
)
"""
    )
    (tmp_path / ".vulnscanignore").write_text("site/kcworks/dependencies/fork\n")
    dep = Dependency(
        "axios",
        NPM,
        "^1.7.0",
        "1.7.0",
        "lock",
        "site/kcworks/webpack.py",
        declarations=(Declaration("site/kcworks/webpack.py", "^1.7.0"),),
    )
    settings = _settings(tmp_path)
    apply_remediation(tmp_path, dep, "1.20.0", settings=settings)
    assert extract_theme_dependencies(overlay.read_text())["axios"] == "^1.20.0"
    assert extract_theme_dependencies((fork / "webpack.py").read_text())["axios"] == "^1.9.0"
    overlay.write_text(OVERLAY)
    (fork / "webpack.py").write_text(
        """\
from invenio_assets.webpack import WebpackThemeBundle
theme = WebpackThemeBundle(
    __name__, "assets", default="semantic-ui",
    themes={"semantic-ui": {"dependencies": {"axios": "^2.0.0"}}},
)
"""
    )
    with pytest.raises(RemediationError, match="pywebpack"):
        apply_remediation(tmp_path, dep, "1.20.0", settings=settings)
