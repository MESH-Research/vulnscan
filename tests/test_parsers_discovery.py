import json
from pathlib import Path

from vulnscan.models import PACKAGIST, PYPI
from vulnscan.parsers import discover_manifests, is_manifest, parse_manifest, parse_project


def test_is_manifest_recognises_known_files(tmp_path: Path):
    for name in [
        "composer.json",
        "pyproject.toml",
        "requirements.txt",
        "requirements-dev.txt",
        "dev-requirements.txt",
        "Pipfile",
        "setup.cfg",
    ]:
        assert is_manifest(tmp_path / name), name
    for name in ["composer.lock", "package.json", "README.md", "requirements.in", "Pipfile.lock"]:
        assert not is_manifest(tmp_path / name), name


def test_discover_manifests_recurses_and_skips_vendor_dirs(tmp_path: Path):
    (tmp_path / "composer.json").write_text("{}")
    (tmp_path / "api").mkdir()
    (tmp_path / "api" / "pyproject.toml").write_text("")
    (tmp_path / "vendor" / "x").mkdir(parents=True)
    (tmp_path / "vendor" / "x" / "composer.json").write_text("{}")
    (tmp_path / ".venv" / "lib").mkdir(parents=True)
    (tmp_path / ".venv" / "lib" / "requirements.txt").write_text("")
    (tmp_path / "node_modules" / "y").mkdir(parents=True)
    (tmp_path / "node_modules" / "y" / "pyproject.toml").write_text("")
    found = sorted(p.relative_to(tmp_path).as_posix() for p in discover_manifests(tmp_path))
    assert found == ["api/pyproject.toml", "composer.json"]


def test_discover_manifests_accepts_a_file(tmp_path: Path):
    req = tmp_path / "requirements.txt"
    req.write_text("")
    assert discover_manifests(req) == [req]


def test_parse_manifest_dispatches(tmp_path: Path):
    cj = tmp_path / "composer.json"
    cj.write_text(json.dumps({"require": {"a/b": "1.0.0"}}))
    assert [d.name for d in parse_manifest(cj, tmp_path)] == ["a/b"]
    req = tmp_path / "requirements.txt"
    req.write_text("requests==1.0\n")
    assert [d.name for d in parse_manifest(req, tmp_path)] == ["requests"]
    other = tmp_path / "README.md"
    other.write_text("")
    assert parse_manifest(other, tmp_path) == []


def test_parse_project_resolves_versions_from_adjacent_lock(tmp_path: Path):
    (tmp_path / "composer.json").write_text(json.dumps({"require": {"monolog/monolog": "^2.0"}}))
    (tmp_path / "composer.lock").write_text(
        json.dumps(
            {
                "packages": [
                    {"name": "monolog/monolog", "version": "2.9.1"},
                    {"name": "psr/log", "version": "3.0.0"},
                ]
            }
        )
    )
    deps, warnings = parse_project(tmp_path)
    assert [(d.name, d.version, d.version_source) for d in deps] == [
        ("monolog/monolog", "2.9.1", "lock")
    ]
    assert warnings == []


def test_parse_project_does_not_add_transitive_lock_entries(tmp_path: Path):
    (tmp_path / "pyproject.toml").write_text('[project]\nname="x"\ndependencies=["requests>=2"]\n')
    (tmp_path / "uv.lock").write_text(
        '[[package]]\nname="requests"\nversion="2.31.0"\n\n[[package]]\nname="urllib3"\nversion="2.0.0"\n'
    )
    deps, _ = parse_project(tmp_path)
    assert [d.name for d in deps] == ["requests"]
    assert deps[0].version == "2.31.0"


def test_parse_project_warns_about_unknown_versions(tmp_path: Path):
    (tmp_path / "requirements.txt").write_text("flask\n")
    deps, warnings = parse_project(tmp_path)
    assert deps[0].version is None
    assert len(warnings) == 1
    assert "flask" in warnings[0]


def test_parse_project_warns_when_no_manifests(tmp_path: Path):
    deps, warnings = parse_project(tmp_path)
    assert deps == []
    assert len(warnings) == 1


def test_parse_project_mixed_ecosystems(tmp_path: Path):
    (tmp_path / "composer.json").write_text(json.dumps({"require": {"a/b": "1.0.0"}}))
    (tmp_path / "requirements.txt").write_text("requests==2.0.0\n")
    deps, _ = parse_project(tmp_path)
    assert {(d.ecosystem, d.name) for d in deps} == {(PACKAGIST, "a/b"), (PYPI, "requests")}
