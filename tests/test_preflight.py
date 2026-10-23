"""Tests for pin-float preflight helpers (per-manifest mock lock)."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import httpx

from vulnscan.config import load_settings
from vulnscan.models import PYPI, Dependency
from vulnscan.osv import OSVClient
from vulnscan.preflight import (
    is_excluded,
    load_preflight_ignore_file,
    report_to_json,
    run_preflight,
)
from vulnscan.registry import RegistryClient


def _transport() -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        if "osv" in request.url.host and request.url.path == "/v1/querybatch":
            return httpx.Response(200, json={"results": [{}]})
        if request.url.host == "pypi.org":
            return httpx.Response(
                200,
                json={
                    "releases": {
                        "1.2.0": [
                            {
                                "yanked": False,
                                "upload_time_iso_8601": "2020-01-01T00:00:00Z",
                            }
                        ],
                        "1.0.0": [
                            {
                                "yanked": False,
                                "upload_time_iso_8601": "2019-01-01T00:00:00Z",
                            }
                        ],
                    }
                },
            )
        return httpx.Response(404)

    return httpx.MockTransport(handler)


def test_is_excluded_ecosystem_and_wildcard():
    dep = Dependency("requests", PYPI, "==1", "1", "pinned", "req.txt")
    assert is_excluded(dep, ("requests",))
    assert is_excluded(dep, ("PyPI:requests",))
    assert not is_excluded(dep, ("npm:requests",))
    assert is_excluded(dep, ("req*",))


def test_load_preflight_ignore_file(tmp_path: Path):
    (tmp_path / ".vulnscan-preflight-ignore").write_text("# c\nrequests\n\nPyPI:flask\n")
    assert load_preflight_ignore_file(tmp_path) == ("requests", "PyPI:flask")


def test_run_preflight_mock_locks_manifest_without_using_project_lock(tmp_path: Path):
    """Mock lock is built from the manifest alone; project uv.lock is not an input."""
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname="demo"\nversion="0.1.0"\ndependencies=["demo-pkg==1.0.0"]\n'
    )
    # Stale project lock — preflight must not copy or seed from this.
    (tmp_path / "uv.lock").write_text(
        'version = 1\nrevision = 1\nrequires-python = ">=3.12"\n\n'
        '[[package]]\nname = "demo-pkg"\nversion = "1.0.0"\n'
    )

    seen_cwds: list[Path] = []

    def fake_run(argv, cwd: Path):
        seen_cwds.append(cwd)
        assert argv[:2] == ["uv", "lock"]
        # Temp tree must not start from the project's lock.
        assert not (cwd / "uv.lock").exists()
        assert (cwd / "pyproject.toml").is_file()
        text = (cwd / "pyproject.toml").read_text(encoding="utf-8")
        assert "demo-pkg" in text
        (cwd / "uv.lock").write_text(
            'version = 1\nrevision = 1\nrequires-python = ">=3.12"\n\n'
            '[[package]]\nname = "demo-pkg"\nversion = "1.2.0"\n'
        )
        return subprocess.CompletedProcess(argv, 0, "", "")

    transport = _transport()
    settings = load_settings(env={"VULNSCAN_PROJECT_PATH": str(tmp_path)})
    osv = OSVClient(base_url="https://api.osv.dev", timeout=1.0, transport=transport)
    registry = RegistryClient(timeout=1.0, transport=transport)
    report = run_preflight(settings, osv=osv, registry=registry, run=fake_run)
    assert seen_cwds
    assert all(c != tmp_path for c in seen_cwds)
    assert report.resolve_ok
    assert any(p.dependency.name == "demo-pkg" and p.would_be == "1.2.0" for p in report.packages)
    bumped = next(p for p in report.packages if p.dependency.name == "demo-pkg")
    assert bumped.current == "1.0.0"
    assert bumped.would_bump is True
    payload = report_to_json(report, strict_fresh=False)
    assert payload["schema_version"] == 1
    assert payload["mode"] == "preflight"
    assert payload["ok"] is True
    assert report.exit_code(strict_fresh=False) == 0


def test_run_preflight_drops_uv_path_sources(tmp_path: Path):
    (tmp_path / "pyproject.toml").write_text(
        "\n".join(
            [
                "[project]",
                'name = "demo"',
                'version = "0.1.0"',
                'dependencies = ["demo-pkg>=1.0", "local-thing"]',
                "",
                "[tool.uv.sources]",
                'local-thing = { path = "./vendor/local-thing", editable = true }',
                "",
            ]
        )
    )

    def fake_run(argv, cwd: Path):
        text = (cwd / "pyproject.toml").read_text(encoding="utf-8")
        assert "demo-pkg" in text
        assert "local-thing" not in text
        (cwd / "uv.lock").write_text(
            'version = 1\nrevision = 1\nrequires-python = ">=3.12"\n\n'
            '[[package]]\nname = "demo-pkg"\nversion = "1.2.0"\n'
        )
        return subprocess.CompletedProcess(argv, 0, "", "")

    transport = _transport()
    settings = load_settings(env={"VULNSCAN_PROJECT_PATH": str(tmp_path)})
    report = run_preflight(
        settings,
        osv=OSVClient(base_url="https://api.osv.dev", timeout=1.0, transport=transport),
        registry=RegistryClient(timeout=1.0, transport=transport),
        run=fake_run,
    )
    assert report.resolve_ok
    assert any(
        "dropping path/editable/git sources" in w and "local-thing" in w for w in report.warnings
    )
    assert any(
        "has no pyproject.toml or setup.cfg" in w and "local-thing" in w for w in report.warnings
    )
    assert any(p.dependency.name == "demo-pkg" for p in report.packages)
    assert not any(p.dependency.name == "local-thing" for p in report.packages)


def test_run_preflight_imports_build_system_and_editable_pypi_reqs(tmp_path: Path):
    """Mock lock folds build-system + nested editable PyPI pins; omits the editable name."""
    vendor = tmp_path / "vendor" / "local-thing"
    nested = tmp_path / "vendor" / "nested-lib"
    vendor.mkdir(parents=True)
    nested.mkdir(parents=True)
    (tmp_path / "pyproject.toml").write_text(
        "\n".join(
            [
                "[build-system]",
                'requires = ["setuptools>=83", "wheel"]',
                'build-backend = "setuptools.build_meta"',
                "",
                "[project]",
                'name = "demo"',
                'version = "0.1.0"',
                'requires-python = ">=3.12"',
                'dependencies = ["demo-pkg>=1.0", "local-thing"]',
                "",
                "[tool.uv.sources]",
                'local-thing = { path = "./vendor/local-thing", editable = true }',
                "",
            ]
        )
    )
    (vendor / "pyproject.toml").write_text(
        "\n".join(
            [
                "[project]",
                'name = "local-thing"',
                'version = "0.1.0"',
                'dependencies = ["urllib3>=2.0", "nested-lib"]',
                "",
                "[tool.uv.sources]",
                'nested-lib = { path = "../nested-lib", editable = true }',
                "",
            ]
        )
    )
    (nested / "pyproject.toml").write_text(
        "\n".join(
            [
                "[build-system]",
                'requires = ["setuptools>=83"]',
                "",
                "[project]",
                'name = "nested-lib"',
                'version = "0.1.0"',
                'dependencies = ["certifi>=2024"]',
                "",
            ]
        )
    )

    def fake_run(argv, cwd: Path):
        text = (cwd / "pyproject.toml").read_text(encoding="utf-8")
        assert "demo-pkg" in text
        assert "setuptools>=83" in text
        assert "urllib3>=2.0" in text
        assert "certifi>=2024" in text
        assert "local-thing" not in text.split("dependencies")[1]
        assert "nested-lib" not in text.split("dependencies")[1]
        (cwd / "uv.lock").write_text(
            'version = 1\nrevision = 1\nrequires-python = ">=3.12"\n\n'
            '[[package]]\nname = "demo-pkg"\nversion = "1.2.0"\n\n'
            '[[package]]\nname = "setuptools"\nversion = "84.0.0"\n\n'
            '[[package]]\nname = "urllib3"\nversion = "2.2.0"\n\n'
            '[[package]]\nname = "certifi"\nversion = "2024.1.0"\n'
        )
        return subprocess.CompletedProcess(argv, 0, "", "")

    transport = _transport()
    settings = load_settings(env={"VULNSCAN_PROJECT_PATH": str(tmp_path)})
    report = run_preflight(
        settings,
        osv=OSVClient(base_url="https://api.osv.dev", timeout=1.0, transport=transport),
        registry=RegistryClient(timeout=1.0, transport=transport),
        run=fake_run,
    )
    assert report.resolve_ok
    names = {p.dependency.name for p in report.packages}
    assert "demo-pkg" in names
    assert "setuptools" in names
    assert "urllib3" in names
    assert "certifi" in names
    assert "local-thing" not in names
    assert "nested-lib" not in names


def test_run_preflight_imports_setup_cfg_editable_and_uv_tool(tmp_path: Path):
    """setup.cfg editables, Poetry path deps, and tool.uv constraints/indexes fold in."""
    cfg_pkg = tmp_path / "vendor" / "cfg-lib"
    poetry_pkg = tmp_path / "vendor" / "poetry-lib"
    cfg_pkg.mkdir(parents=True)
    poetry_pkg.mkdir(parents=True)
    (tmp_path / "pyproject.toml").write_text(
        "\n".join(
            [
                "[project]",
                'name = "demo"',
                'version = "0.1.0"',
                'dependencies = ["demo-pkg>=1.0", "cfg-lib", "poetry-lib"]',
                "",
                "[tool.uv]",
                'constraint-dependencies = ["urllib3<3"]',
                'override-dependencies = ["certifi==2024.2.2"]',
                "",
                "[[tool.uv.index]]",
                'name = "internal"',
                'url = "https://example.com/simple"',
                "explicit = true",
                "",
                "[tool.uv.sources]",
                'cfg-lib = { path = "./vendor/cfg-lib", editable = true }',
                "",
                "[tool.poetry.dependencies]",
                'python = "^3.12"',
                'poetry-lib = { path = "./vendor/poetry-lib" }',
                "",
            ]
        )
    )
    (cfg_pkg / "setup.cfg").write_text(
        "[metadata]\nname = cfg-lib\nversion = 0.1.0\n\n"
        "[options]\ninstall_requires =\n    idna>=3.0\n"
    )
    (poetry_pkg / "pyproject.toml").write_text(
        "\n".join(
            [
                "[tool.poetry]",
                'name = "poetry-lib"',
                'version = "0.1.0"',
                "",
                "[tool.poetry.dependencies]",
                'python = "^3.12"',
                'packaging = ">=24"',
                "",
            ]
        )
    )

    def fake_run(argv, cwd: Path):
        text = (cwd / "pyproject.toml").read_text(encoding="utf-8")
        assert "demo-pkg" in text
        assert "idna>=3.0" in text
        assert "packaging" in text
        assert "urllib3<3" in text
        assert "certifi==2024.2.2" in text
        assert "https://example.com/simple" in text
        assert "cfg-lib" not in text.split("dependencies = [")[1].split("]")[0]
        assert "poetry-lib" not in text.split("dependencies = [")[1].split("]")[0]
        (cwd / "uv.lock").write_text(
            'version = 1\nrevision = 1\nrequires-python = ">=3.12"\n\n'
            '[[package]]\nname = "demo-pkg"\nversion = "1.2.0"\n\n'
            '[[package]]\nname = "idna"\nversion = "3.7"\n\n'
            '[[package]]\nname = "packaging"\nversion = "24.1"\n'
        )
        return subprocess.CompletedProcess(argv, 0, "", "")

    transport = _transport()
    settings = load_settings(env={"VULNSCAN_PROJECT_PATH": str(tmp_path)})
    report = run_preflight(
        settings,
        osv=OSVClient(base_url="https://api.osv.dev", timeout=1.0, transport=transport),
        registry=RegistryClient(timeout=1.0, transport=transport),
        run=fake_run,
    )
    assert report.resolve_ok
    names = {p.dependency.name for p in report.packages}
    assert "idna" in names
    assert "packaging" in names
    assert "cfg-lib" not in names
    assert "poetry-lib" not in names


def test_run_preflight_resolve_failure(tmp_path: Path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname="demo"\nversion="0.1.0"\ndependencies=["demo-pkg>=1"]\n'
    )

    def fake_run(argv, cwd: Path):
        return subprocess.CompletedProcess(argv, 1, "", "boom")

    settings = load_settings(env={"VULNSCAN_PROJECT_PATH": str(tmp_path)})
    report = run_preflight(
        settings,
        osv=OSVClient(
            base_url="https://api.osv.dev",
            timeout=1.0,
            transport=httpx.MockTransport(lambda r: httpx.Response(404)),
        ),
        registry=RegistryClient(
            timeout=1.0,
            transport=httpx.MockTransport(lambda r: httpx.Response(404)),
        ),
        run=fake_run,
    )
    assert report.resolve_ok is False
    assert any("uv lock failed" in w and "boom" in w for w in report.warnings)
    assert report.exit_code(strict_fresh=False) == 1


def test_run_preflight_package_json_mock_lock(tmp_path: Path):
    (tmp_path / "package.json").write_text(
        '{"name":"app","version":"1.0.0","dependencies":{"left-pad":"1.0.0"}}\n'
    )

    def fake_run(argv, cwd: Path):
        assert "npm" in argv or "pnpm" in argv
        assert not (cwd / "package-lock.json").exists()
        assert not (cwd / "pnpm-lock.yaml").exists()
        (cwd / "package-lock.json").write_text(
            '{"name":"app","lockfileVersion":3,"packages":{'
            '"":{"dependencies":{"left-pad":"1.0.0"}},'
            '"node_modules/left-pad":{"version":"1.3.0"}'
            "}}\n"
        )
        return subprocess.CompletedProcess(argv, 0, "", "")

    transport = _transport()
    settings = load_settings(env={"VULNSCAN_PROJECT_PATH": str(tmp_path)})
    report = run_preflight(
        settings,
        osv=OSVClient(base_url="https://api.osv.dev", timeout=1.0, transport=transport),
        registry=RegistryClient(timeout=1.0, transport=transport),
        run=fake_run,
    )
    assert report.resolve_ok
    assert any(p.dependency.name == "left-pad" and p.would_be == "1.3.0" for p in report.packages)


BUNDLE_A = """\
from invenio_assets.webpack import WebpackThemeBundle
theme = WebpackThemeBundle(
    __name__, "assets", default="semantic-ui",
    themes={"semantic-ui": {"dependencies": {"axios": "^1.7.0", "lodash": "^4.17.0"}}},
)
"""

BUNDLE_B = """\
from invenio_assets.webpack import WebpackThemeBundle
theme = WebpackThemeBundle(
    __name__, "assets", default="semantic-ui",
    themes={"semantic-ui": {"dependencies": {"axios": "^1.9.0"}}},
)
"""


def test_run_preflight_invenio_uses_virtual_assets_package_json(tmp_path: Path):
    """Invenio mode mock-locks the merged webpack tree, not on-disk package.json."""
    from vulnscan.invenio import npm_max_version

    assert npm_max_version("^1.7.0", "^1.9.0") == "^1.9.0"

    site = tmp_path / "site" / "app"
    other = tmp_path / "pkg"
    site.mkdir(parents=True)
    other.mkdir()
    (site / "webpack.py").write_text(BUNDLE_A)
    (other / "webpack.py").write_text(BUNDLE_B)
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname="app"\nversion="0.1.0"\ndependencies=["invenio-app-rdm"]\n'
    )
    # On-disk package.json is test-env only — must not be the npm mock-lock input.
    (tmp_path / "package.json").write_text(
        '{"name":"app","dependencies":{"should-not-resolve":"1.0.0"}}\n'
    )

    seen_docs: list[dict] = []

    def fake_run(argv, cwd: Path):
        if argv[:2] == ["uv", "lock"]:
            (cwd / "uv.lock").write_text(
                'version = 1\nrevision = 1\nrequires-python = ">=3.12"\n\n'
                '[[package]]\nname = "invenio-app-rdm"\nversion = "13.0.0"\n'
            )
            return subprocess.CompletedProcess(argv, 0, "", "")
        doc = json.loads((cwd / "package.json").read_text(encoding="utf-8"))
        seen_docs.append(doc)
        assert "should-not-resolve" not in (doc.get("dependencies") or {})
        assert doc.get("dependencies", {}).get("axios") == "^1.9.0"
        assert doc.get("dependencies", {}).get("lodash") == "^4.17.0"
        (cwd / "package-lock.json").write_text(
            '{"name":"x","lockfileVersion":3,"packages":{'
            '"":{"dependencies":{"axios":"^1.9.0","lodash":"^4.17.0"}},'
            '"node_modules/axios":{"version":"1.9.1"},'
            '"node_modules/lodash":{"version":"4.17.21"}'
            "}}\n"
        )
        return subprocess.CompletedProcess(argv, 0, "", "")

    transport = _transport()
    settings = load_settings(
        env={
            "VULNSCAN_PROJECT_PATH": str(tmp_path),
            "VULNSCAN_INVENIO_WEBPACK": "on",
        }
    )
    report = run_preflight(
        settings,
        osv=OSVClient(base_url="https://api.osv.dev", timeout=1.0, transport=transport),
        registry=RegistryClient(timeout=1.0, transport=transport),
        run=fake_run,
    )
    assert report.resolve_ok
    assert seen_docs, "expected a virtual assets npm resolve"
    assert any("virtual assets package.json" in w for w in report.warnings)
    assert any("skipping package.json" in w for w in report.warnings)
    assert any(p.dependency.name == "axios" and p.would_be == "1.9.1" for p in report.packages)
    assert not any(p.dependency.name == "should-not-resolve" for p in report.packages)


def test_virtual_assets_dependencies_omits_major_conflicts():
    from vulnscan.invenio import (
        WebpackMergeConflict,
        WebpackMergeIndex,
        virtual_assets_dependencies,
    )

    index = WebpackMergeIndex(
        by_package={
            "axios": (
                ("a/webpack.py", "^1.7.0"),
                ("b/webpack.py", "^2.0.0"),
            ),
            "lodash": (("a/webpack.py", "^4.17.0"),),
        },
        conflicts=(
            WebpackMergeConflict(
                "axios",
                (("a/webpack.py", "^1.7.0"), ("b/webpack.py", "^2.0.0")),
            ),
        ),
    )
    deps, warnings = virtual_assets_dependencies(index)
    assert "lodash" in deps
    assert "axios" not in deps
    assert any("axios" in w for w in warnings)


def test_run_preflight_composer_mock_lock_sets_build_process(tmp_path: Path):
    """Composer.json is mock-locked; packages are tagged build_process=composer."""
    (tmp_path / "composer.json").write_text(
        json.dumps(
            {
                "name": "vulnscan/demo",
                "require": {"monolog/monolog": "^2.0"},
                "repositories": [
                    {"type": "path", "url": "./packages/local-thing"},
                ],
            }
        )
        + "\n"
    )
    local = tmp_path / "packages" / "local-thing"
    local.mkdir(parents=True)
    (local / "composer.json").write_text(
        json.dumps({"name": "acme/local-thing", "version": "1.0.0"}) + "\n"
    )

    def fake_run(argv, cwd: Path):
        assert argv[:2] == ["composer", "update"]
        assert "--no-install" in argv
        text = (cwd / "composer.json").read_text(encoding="utf-8")
        assert "monolog/monolog" in text
        assert "acme/local-thing" not in text
        assert '"type": "path"' not in text
        (cwd / "composer.lock").write_text(
            json.dumps(
                {
                    "packages": [
                        {"name": "monolog/monolog", "version": "2.9.1"},
                    ],
                    "packages-dev": [],
                }
            )
            + "\n"
        )
        return subprocess.CompletedProcess(argv, 0, "", "")

    def handler(request: httpx.Request) -> httpx.Response:
        if "osv" in request.url.host and request.url.path == "/v1/querybatch":
            return httpx.Response(200, json={"results": [{}]})
        if "packagist.org" in request.url.host:
            return httpx.Response(
                200,
                json={
                    "packages": {
                        "monolog/monolog": [
                            {
                                "version": "2.9.1",
                                "version_normalized": "2.9.1.0",
                                "time": "2020-01-01T00:00:00+00:00",
                            }
                        ]
                    }
                },
            )
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    settings = load_settings(env={"VULNSCAN_PROJECT_PATH": str(tmp_path)})
    report = run_preflight(
        settings,
        osv=OSVClient(base_url="https://api.osv.dev", timeout=1.0, transport=transport),
        registry=RegistryClient(timeout=1.0, transport=transport),
        run=fake_run,
    )
    assert report.resolve_ok
    monolog = next(p for p in report.packages if p.dependency.name == "monolog/monolog")
    assert monolog.would_be == "2.9.1"
    assert monolog.build_process == "composer"
    assert any("dropping non-registry composer repositories" in w for w in report.warnings)
    payload = report_to_json(report, strict_fresh=False)
    assert any(
        p["name"] == "monolog/monolog" and p["build_process"] == "composer"
        for p in payload["packages"]
    )


def test_run_preflight_uv_packages_set_build_process(tmp_path: Path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname="demo"\nversion="0.1.0"\ndependencies=["demo-pkg==1.0.0"]\n'
    )

    def fake_run(argv, cwd: Path):
        (cwd / "uv.lock").write_text(
            'version = 1\nrevision = 1\nrequires-python = ">=3.12"\n\n'
            '[[package]]\nname = "demo-pkg"\nversion = "1.2.0"\n'
        )
        return subprocess.CompletedProcess(argv, 0, "", "")

    transport = _transport()
    settings = load_settings(env={"VULNSCAN_PROJECT_PATH": str(tmp_path)})
    report = run_preflight(
        settings,
        osv=OSVClient(base_url="https://api.osv.dev", timeout=1.0, transport=transport),
        registry=RegistryClient(timeout=1.0, transport=transport),
        run=fake_run,
    )
    bumped = next(p for p in report.packages if p.dependency.name == "demo-pkg")
    assert bumped.build_process == "uv"
