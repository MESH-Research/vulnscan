from pathlib import Path

from tests.test_scanner import FakeClient, settings_for, vuln
from vulnscan.invenio import WebpackMergeIndex, build_webpack_merge_index, npm_major
from vulnscan.models import NPM, Dependency, Finding, Vulnerability
from vulnscan.remediate import plan_remediation
from vulnscan.reports import render_markdown
from vulnscan.scanner import scan

BUNDLE_A = """\
from invenio_assets.webpack import WebpackThemeBundle
theme = WebpackThemeBundle(
    __name__, "assets", default="semantic-ui",
    themes={"semantic-ui": {"dependencies": {"axios": "^1.7.0"}}},
)
"""

BUNDLE_B = """\
from invenio_assets.webpack import WebpackThemeBundle
theme = WebpackThemeBundle(
    __name__, "assets", default="semantic-ui",
    themes={"semantic-ui": {"dependencies": {"axios": "^2.0.0"}}},
)
"""


def test_build_index_does_not_mutate_sys_path(tmp_path: Path):
    import sys

    site = tmp_path / "site" / "app"
    site.mkdir(parents=True)
    (site / "webpack.py").write_text(BUNDLE_A)
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname="x"\ndependencies=["invenio-assets"]\n'
    )
    before = list(sys.path)
    build_webpack_merge_index(tmp_path, include_environment=False)
    assert sys.path == before


def test_build_index_detects_major_conflict(tmp_path: Path):
    a = tmp_path / "site" / "app"
    b = tmp_path / "pkg"
    a.mkdir(parents=True)
    b.mkdir()
    (a / "webpack.py").write_text(BUNDLE_A)
    (b / "webpack.py").write_text(BUNDLE_B)
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname="x"\ndependencies=["invenio-assets"]\n'
    )
    index = build_webpack_merge_index(tmp_path, include_environment=False)
    assert index.conflict_for("axios") is not None
    assert not index.allows("axios", "1.20.0")
    assert not index.allows("axios", "2.1.0")
    assert any("axios" in w for w in index.warning_lines())


def test_plan_remediation_clears_nearest_safe_when_blocked():
    dep = Dependency("axios", NPM, "^1.7.0", "1.7.0", "lock", "webpack.py")
    finding = Finding(
        dep,
        [Vulnerability("X", "s", "d")],
        webpack_merge_block="pywebpack merge conflict for 'axios'",
    )
    plan = plan_remediation(finding, ["1.7.0", "1.8.0", "1.9.0"])
    assert plan.nearest_safe is None


def test_plan_remediation_filters_by_merge_index():
    dep = Dependency("axios", NPM, "^1.7.0", "1.7.0", "lock", "webpack.py")
    finding = Finding(dep, [Vulnerability("X", "s", "d")])
    index = WebpackMergeIndex(
        by_package={"axios": (("site-packages/other/webpack.py", "^1.9.0"),)},
        conflicts=(),
    )
    # Advisory-affecting: pretend all < 2.0 are affected — use empty vulns so all safe
    plan = plan_remediation(finding, ["1.7.0", "1.8.0", "2.0.0"], webpack_merge=index)
    assert plan.nearest_safe == "1.8.0"
    assert plan.latest == "2.0.0"
    assert plan.latest_is_safe is False  # major 2 blocked by merge


def test_scan_annotates_findings_and_report(tmp_path: Path):
    site = tmp_path / "site" / "kcworks"
    other = tmp_path / "other"
    site.mkdir(parents=True)
    other.mkdir()
    (site / "webpack.py").write_text(BUNDLE_A)
    (other / "webpack.py").write_text(BUNDLE_B)
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname="app"\ndependencies=["invenio-app-rdm"]\n'
    )
    (tmp_path / "package.json").write_text('{"dependencies": {"axios": "1.7.0"}}')
    client = FakeClient({("axios", "1.7.0"): [vuln("GHSA-A", "HIGH")]})
    result = scan(
        settings_for(tmp_path, invenio_webpack="on"),
        client=client,
    )
    assert result.webpack_merge is not None
    assert any("axios" in w for w in result.warnings)
    finding = next(f for f in result.findings if f.dependency.name == "axios")
    assert finding.webpack_merge_block
    assert finding.upstream_constraints_text is not None
    assert "webpack.py" in finding.upstream_constraints_text
    assert finding.upgrade_limit
    md = render_markdown(result)
    assert "Nearest safe" in md
    assert "| none |" in md or "none" in md
    assert "Webpack merge conflicts" in md
    assert "Upstream constraints" in md
    assert "Upgrade limit" in md
    assert npm_major("^1.7.0") == 1


def test_upgrade_limit_for_major_bump():
    index = WebpackMergeIndex(
        by_package={"axios": (("site/app/webpack.py", "^1.7.0"),)},
        conflicts=(),
    )
    msg = index.upgrade_limit_for("axios", ["2.0.0", "2.1.0"])
    assert msg is not None
    assert "major bump required" in msg
    assert "1" in msg and "2.x" in msg
    assert index.upgrade_limit_for("axios", ["1.8.0"]) is None
    assert index.upstream_constraints_text("missing") == "none"
