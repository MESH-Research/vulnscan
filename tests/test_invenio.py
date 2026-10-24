from pathlib import Path

import pytest

from vulnscan.invenio import (
    detect_invenio_webpack,
    major_conflict_message,
    npm_major,
    resolve_overlay,
    webpack_uses_pnpm,
)

BUNDLE = """\
from invenio_assets.webpack import WebpackThemeBundle
theme = WebpackThemeBundle(
    __name__, "assets", default="semantic-ui",
    themes={"semantic-ui": {"dependencies": {"axios": "^1.7.0"}}},
)
"""


def test_npm_major():
    assert npm_major("^1.20.0") == 1
    assert npm_major("~2.4.0") == 2
    assert npm_major(">=3.0.0") == 3
    assert npm_major("7.23.5") == 7
    assert npm_major("*") is None


def test_major_conflict_message_blocks_different_majors():
    msg = major_conflict_message(
        "axios",
        "2.0.0",
        [("site/app/webpack.py", "^1.7.0"), ("pkg/webpack.py", "^1.9.0")],
    )
    assert msg is not None
    assert "major 2" in msg
    assert "major 1" in msg
    assert major_conflict_message("axios", "1.20.0", [("a", "^1.7.0")]) is None


def test_resolve_overlay_single_site_package(tmp_path: Path):
    site = tmp_path / "site" / "kcworks"
    site.mkdir(parents=True)
    webpack = site / "webpack.py"
    webpack.write_text(BUNDLE)
    assert resolve_overlay(tmp_path, None) == webpack.resolve()


def test_resolve_overlay_override(tmp_path: Path):
    custom = tmp_path / "overlay.py"
    custom.write_text(BUNDLE)
    assert resolve_overlay(tmp_path, custom) == custom.resolve()


def test_resolve_overlay_errors_when_ambiguous(tmp_path: Path):
    for name in ("a", "b"):
        d = tmp_path / "site" / name
        d.mkdir(parents=True)
        (d / "webpack.py").write_text(BUNDLE)
    with pytest.raises(ValueError, match="Multiple"):
        resolve_overlay(tmp_path, None)


def test_detect_auto_requires_signal_and_bundle(tmp_path: Path):
    site = tmp_path / "site" / "app"
    site.mkdir(parents=True)
    (site / "webpack.py").write_text(BUNDLE)
    assert detect_invenio_webpack(tmp_path, "auto") is True
    # Bundle alone without site/ or invenio markers elsewhere is still True via site webpack.
    plain = tmp_path / "plain"
    plain.mkdir()
    (plain / "webpack.py").write_text(BUNDLE)
    assert detect_invenio_webpack(plain, "auto") is False
    (plain / "pyproject.toml").write_text('dependencies = ["invenio-assets>=1"]\n')
    assert detect_invenio_webpack(plain, "auto") is True
    assert detect_invenio_webpack(plain, "off") is False
    assert detect_invenio_webpack(plain, "on") is True


def test_webpack_uses_pnpm_defaults_false(tmp_path: Path):
    assert webpack_uses_pnpm(tmp_path) is False
    (tmp_path / "invenio.cfg").write_text('WEBPACKEXT_NPM_PKG_CLS = "pynpm.package:NPMPackage"\n')
    assert webpack_uses_pnpm(tmp_path) is False


def test_webpack_uses_pnpm_reads_pnpmpackage(tmp_path: Path):
    (tmp_path / "invenio.cfg").write_text(
        '# comment\nWEBPACKEXT_NPM_PKG_CLS = "pynpm.package:PNPMPackage"\n'
    )
    assert webpack_uses_pnpm(tmp_path) is True
