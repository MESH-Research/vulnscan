import json
from pathlib import Path

from vulnscan.models import PACKAGIST, PYPI
from vulnscan.parsers import (
    discover_manifests,
    is_manifest,
    load_ignore_file,
    matches_ignore,
    parse_manifest,
    parse_project,
)


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


def test_txt_files_inside_a_requirements_directory_are_manifests(tmp_path: Path):
    (tmp_path / "requirements").mkdir()
    (tmp_path / "docs").mkdir()
    (tmp_path / "requirements" / "base.txt").write_text("authlib==1.2.0\n")
    (tmp_path / "requirements" / "production.txt").write_text("-r base.txt\n")
    (tmp_path / "requirements" / "README.md").write_text("")
    (tmp_path / "docs" / "notes.txt").write_text("not a manifest")
    assert is_manifest(tmp_path / "requirements" / "base.txt")
    assert not is_manifest(tmp_path / "docs" / "notes.txt")
    found = sorted(p.relative_to(tmp_path).as_posix() for p in discover_manifests(tmp_path))
    assert found == ["requirements/base.txt", "requirements/production.txt"]
    deps, _ = parse_project(tmp_path)
    assert [(d.name, d.source_file) for d in deps] == [
        ("authlib", "requirements/base.txt"),
        ("authlib", "requirements/base.txt"),
    ]


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


def test_discover_skips_composer_installer_paths_and_core_dir(tmp_path: Path):
    (tmp_path / "composer.json").write_text(
        json.dumps(
            {
                "require": {"a/b": "1.0.0"},
                "config": {"vendor-dir": "deps"},
                "extra": {
                    "installer-paths": {
                        "site/web/app/mu-plugins/{$name}/": ["type:wordpress-muplugin"],
                        "site/web/app/plugins/{$name}/": ["type:wordpress-plugin"],
                        "site/web/app/themes/{$name}/": ["type:wordpress-theme"],
                    },
                    "wordpress-install-dir": "site/web/wp",
                },
            }
        )
    )
    for rel in [
        "site/web/app/plugins/elementor/composer.json",
        "site/web/app/themes/astra/inc/composer.json",
        "site/web/app/mu-plugins/x/composer.json",
        "site/web/wp/wp-includes/sodium_compat/composer.json",
        "deps/acme/lib/composer.json",
        "plugins/custom/composer.json",
        "site/web/app/custom-tool/requirements.txt",
    ]:
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("{}")
    found = sorted(p.relative_to(tmp_path).as_posix() for p in discover_manifests(tmp_path))
    assert found == [
        "composer.json",
        "plugins/custom/composer.json",
        "site/web/app/custom-tool/requirements.txt",
    ]


def test_discover_skips_wordpress_core_directories(tmp_path: Path):
    for rel in ["wp-includes/x/composer.json", "wp-admin/y/composer.json", "composer.json"]:
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("{}")
    assert [p.name for p in discover_manifests(tmp_path)] == ["composer.json"]


def test_discover_respects_extra_ignored_dirs(tmp_path: Path):
    (tmp_path / "legacy").mkdir()
    (tmp_path / "legacy" / "requirements.txt").write_text("")
    (tmp_path / "requirements.txt").write_text("")
    found = discover_manifests(tmp_path, ignore_dirs=("legacy",))
    assert [p.relative_to(tmp_path).as_posix() for p in found] == ["requirements.txt"]


def test_parse_project_passes_ignore_dirs(tmp_path: Path):
    (tmp_path / "legacy").mkdir()
    (tmp_path / "legacy" / "requirements.txt").write_text("old==1.0\n")
    (tmp_path / "requirements.txt").write_text("new==1.0\n")
    deps, _ = parse_project(tmp_path, ignore_dirs=("legacy",))
    assert [d.name for d in deps] == ["new"]


def test_parse_project_resolves_wordpress_plugin_version_from_composer_lock(tmp_path: Path):
    from vulnscan.models import WORDPRESS

    (tmp_path / "composer.json").write_text(
        json.dumps({"require": {"wp-plugin/elementor": "^3.13"}})
    )
    (tmp_path / "composer.lock").write_text(
        json.dumps(
            {
                "packages": [
                    {"name": "wp-plugin/elementor", "version": "3.13.4", "type": "wordpress-plugin"}
                ]
            }
        )
    )
    deps, warnings = parse_project(tmp_path)
    assert [(d.ecosystem, d.slug, d.version, d.version_source) for d in deps] == [
        (WORDPRESS, "elementor", "3.13.4", "lock")
    ]
    assert warnings == []


# --- ignore patterns --------------------------------------------------------------------------


def _touch(root: Path, *rels: str) -> None:
    for rel in rels:
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("")


def _found(root: Path, **kwargs) -> list[str]:
    return sorted(p.relative_to(root).as_posix() for p in discover_manifests(root, **kwargs))


def test_matches_ignore_by_name_anywhere_in_the_tree():
    assert matches_ignore("web/app/plugins/graveyard", ("graveyard",))
    assert matches_ignore("graveyard", ("graveyard",))
    assert not matches_ignore("web/app/plugins/graveyard-2", ("graveyard",))
    assert not matches_ignore("web/app/plugins/live", ("graveyard",))


def test_matches_ignore_by_project_relative_path():
    patterns = ("web/app/plugins/graveyard",)
    assert matches_ignore("web/app/plugins/graveyard", patterns)
    assert not matches_ignore("other/graveyard", patterns)
    assert not matches_ignore("web/app/plugins", patterns)


def test_matches_ignore_accepts_wildcards_and_sloppy_spelling():
    assert matches_ignore("web/app/plugins/graveyard", ("./web/app/plugins/grave*/",))
    assert matches_ignore("plugins/foo-old", ("*-old",))
    assert matches_ignore("web/app/plugins/graveyard", ("web/*/plugins/graveyard",))
    assert not matches_ignore("web/app/plugins/graveyard", ("", "  ", "#graveyard"))


def test_discover_ignores_a_path_only_where_it_is_given(tmp_path: Path):
    _touch(
        tmp_path,
        "composer.json",
        "web/app/plugins/graveyard/evil/composer.json",
        "web/app/plugins/live/composer.json",
        "other/graveyard/composer.json",
    )
    found = _found(tmp_path, ignore_dirs=("web/app/plugins/graveyard",))
    assert found == [
        "composer.json",
        "other/graveyard/composer.json",
        "web/app/plugins/live/composer.json",
    ]
    assert _found(tmp_path, ignore_dirs=("graveyard",)) == [
        "composer.json",
        "web/app/plugins/live/composer.json",
    ]


def test_discover_reads_vulnscanignore_from_the_project_root(tmp_path: Path):
    _touch(
        tmp_path,
        "requirements.txt",
        "legacy/requirements.txt",
        "web/app/plugins/graveyard/composer.json",
        "web/app/plugins/live/composer.json",
        "tools/scratch-old/requirements.txt",
    )
    (tmp_path / ".vulnscanignore").write_text(
        "# directories we never want scanned\n\nlegacy\nweb/app/plugins/graveyard/\n*-old\n"
    )
    assert load_ignore_file(tmp_path) == ("legacy", "web/app/plugins/graveyard/", "*-old")
    assert _found(tmp_path) == ["requirements.txt", "web/app/plugins/live/composer.json"]
    deps, _ = parse_project(tmp_path)
    assert {d.source_file for d in deps} == set()


def test_vulnscanignore_combines_with_explicit_patterns(tmp_path: Path):
    _touch(tmp_path, "a/requirements.txt", "b/requirements.txt", "c/requirements.txt")
    (tmp_path / ".vulnscanignore").write_text("a\n")
    assert _found(tmp_path, ignore_dirs=("b",)) == ["c/requirements.txt"]


def test_load_ignore_file_is_empty_without_a_file(tmp_path: Path):
    assert load_ignore_file(tmp_path) == ()
