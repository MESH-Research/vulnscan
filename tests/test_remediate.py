import json
from pathlib import Path

import pytest

from vulnscan.models import (
    PACKAGIST,
    PYPI,
    WORDPRESS,
    Declaration,
    Dependency,
    Finding,
    VersionRange,
    Vulnerability,
)
from vulnscan.remediate import (
    RemediationError,
    apply_remediation,
    follow_up_hint,
    plan_remediation,
    rewrite_composer_constraint,
    rewrite_pep508_specifier,
)


def vuln_with_ranges(*ranges, explicit=()):
    return Vulnerability(
        "X", "s", "d", affected_ranges=list(ranges), affected_versions=list(explicit)
    )


# --- planning ---------------------------------------------------------------------------------


def test_plan_picks_nearest_safe_and_latest():
    dep = Dependency("requests", PYPI, "==2.30.0", "2.30.0", "pinned", "requirements.txt")
    v1 = vuln_with_ranges(VersionRange(lower="0", upper="2.31.0"))
    v2 = vuln_with_ranges(VersionRange(lower="2.0.0", upper="2.32.4"))
    finding = Finding(dep, [v1, v2])
    versions = ["2.29.0", "2.30.0", "2.31.0", "2.32.0", "2.32.4", "2.33.0"]
    plan = plan_remediation(finding, versions)
    assert plan.current == "2.30.0"
    assert plan.nearest_safe == "2.32.4"
    assert plan.latest == "2.33.0"
    assert plan.latest_is_safe is True


def test_plan_respects_release_branches():
    """symfony/http-kernel 5.4.0: fixes in 4.4.50, 5.4.20, 6.0.20; the target is 5.4.20."""
    dep = Dependency("symfony/http-kernel", PACKAGIST, "^5.4", "5.4.0", "lock", "composer.json")
    vuln = vuln_with_ranges(
        VersionRange(lower="4.4.0", upper="4.4.50"),
        VersionRange(lower="5.0.0", upper="5.4.20"),
        VersionRange(lower="6.0.0", upper="6.0.20"),
    )
    versions = ["4.4.49", "4.4.50", "5.4.0", "5.4.19", "5.4.20", "6.0.19", "6.0.20", "6.2.6"]
    plan = plan_remediation(Finding(dep, [vuln]), versions)
    assert plan.nearest_safe == "5.4.20"
    assert plan.latest == "6.2.6"


def test_plan_when_latest_is_still_vulnerable():
    dep = Dependency("pkg", PYPI, "==1.0", "1.0", "pinned", "requirements.txt")
    vuln = vuln_with_ranges(VersionRange(lower="0", upper=None))  # unfixed
    plan = plan_remediation(Finding(dep, [vuln]), ["1.0", "1.1", "1.2"])
    assert plan.nearest_safe is None
    assert plan.latest == "1.2"
    assert plan.latest_is_safe is False


def test_plan_with_wordfence_style_inclusive_ranges():
    dep = Dependency(
        "wp-plugin/elementor",
        WORDPRESS,
        "3.13.4",
        "3.13.4",
        "lock",
        "composer.json",
        kind="plugin",
        slug="elementor",
    )
    vuln = vuln_with_ranges(VersionRange(lower=None, upper="3.16.4", upper_inclusive=True))
    plan = plan_remediation(Finding(dep, [vuln]), ["3.13.4", "3.16.4", "3.16.5", "3.20.0"])
    assert plan.nearest_safe == "3.16.5"
    assert plan.latest == "3.20.0"


def test_plan_ignores_versions_not_above_current_and_explicit_affected_versions():
    dep = Dependency("pkg", PYPI, "==1.0", "1.0", "pinned", "requirements.txt")
    vuln = vuln_with_ranges(explicit=["1.0", "1.1"])
    plan = plan_remediation(Finding(dep, [vuln]), ["0.9", "1.0", "1.1", "1.2"])
    assert plan.nearest_safe == "1.2"


def test_plan_unknown_current_version_considers_all_versions():
    dep = Dependency("pkg", PYPI, "", None, "unknown", "requirements.txt")
    vuln = vuln_with_ranges(VersionRange(lower="0", upper="1.1"))
    plan = plan_remediation(Finding(dep, [vuln]), ["1.0", "1.1", "1.2"])
    assert plan.current is None
    assert plan.nearest_safe == "1.1"


def test_plan_with_no_versions():
    dep = Dependency("pkg", PYPI, "==1.0", "1.0", "pinned", "requirements.txt")
    plan = plan_remediation(Finding(dep, []), [])
    assert plan.nearest_safe is None and plan.latest is None


# --- constraint rewriting ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "old,new,expected",
    [
        ("3.13.4", "3.16.5", "3.16.5"),
        ("v3.13.4", "3.16.5", "v3.16.5"),
        ("^12.2", "13.4", "^13.4"),
        ("~1.2", "1.9.0", "~1.9.0"),
        (">=1.4", "2.0.1", ">=2.0.1"),
        (">=1.4 <2.0", "2.0.1", "^2.0.1"),
        ("1.2.*", "1.3.0", "^1.3.0"),
        ("*", "2.0.0", "^2.0.0"),
        ("^1.0 || ^2.0", "2.5.0", "^2.5.0"),
    ],
)
def test_rewrite_composer_constraint(old, new, expected):
    assert rewrite_composer_constraint(old, new) == expected


def test_rewrite_composer_constraint_rejects_dev_branches():
    with pytest.raises(RemediationError):
        rewrite_composer_constraint("dev-trunk", "1.0")


@pytest.mark.parametrize(
    "old,new,expected",
    [
        ("==2.30.0", "2.32.4", "==2.32.4"),
        ("===2.30.0", "2.32.4", "===2.32.4"),
        ("~=1.4.2", "1.9.0", "~=1.9.0"),
        (">=4.2", "4.2.11", ">=4.2.11"),
        (">4.2", "4.2.11", ">=4.2.11"),
        (">=4.2,<5", "4.2.11", ">=4.2.11,<5"),
        (">=4.2,<5", "5.1", ">=5.1"),
        ("<5,>=4.2,!=4.2.5", "4.2.11", ">=4.2.11,!=4.2.5,<5"),
        ("==2.31.*", "2.32.4", ">=2.32.4"),
        ("", "3.1.3", ">=3.1.3"),
        ("<3", "3.1", ">=3.1"),
    ],
)
def test_rewrite_pep508_specifier(old, new, expected):
    assert rewrite_pep508_specifier(old, new) == expected


# --- applying to manifests ---------------------------------------------------------------------


def dep(name, ecosystem, constraint, source_file, version="1.0.0", **kw):
    return Dependency(name, ecosystem, constraint, version, "pinned", source_file, **kw)


def test_apply_to_composer_json_preserves_formatting(tmp_path: Path):
    original = (
        "{\n"
        '    "name": "acme/app",\n'
        '    "require": {\n'
        '        "php": ">=8.1",\n'
        '        "wp-plugin/elementor": "3.13.4",\n'
        '        "monolog/monolog": "^3.3"\n'
        "    },\n"
        '    "require-dev": {\n'
        '        "phpunit/phpunit": "^9.5"\n'
        "    }\n"
        "}\n"
    )
    (tmp_path / "composer.json").write_text(original)
    d = dep(
        "wp-plugin/elementor", WORDPRESS, "3.13.4", "composer.json", kind="plugin", slug="elementor"
    )
    result = apply_remediation(tmp_path, d, "3.16.5")
    text = (tmp_path / "composer.json").read_text()
    assert text == original.replace(
        '"wp-plugin/elementor": "3.13.4"', '"wp-plugin/elementor": "3.16.5"'
    )
    assert json.loads(text)["require"]["wp-plugin/elementor"] == "3.16.5"
    assert result.path == tmp_path / "composer.json"
    assert (result.old_constraint, result.new_constraint) == ("3.13.4", "3.16.5")
    assert "composer update" in result.hint


def test_apply_to_composer_json_require_dev_and_caret(tmp_path: Path):
    (tmp_path / "composer.json").write_text(
        json.dumps({"require-dev": {"phpunit/phpunit": "^9.5"}}, indent=2)
    )
    result = apply_remediation(
        tmp_path, dep("phpunit/phpunit", PACKAGIST, "^9.5", "composer.json", dev=True), "9.6.33"
    )
    assert (
        json.loads((tmp_path / "composer.json").read_text())["require-dev"]["phpunit/phpunit"]
        == "^9.6.33"
    )
    assert result.new_constraint == "^9.6.33"


def test_apply_to_composer_json_missing_package_raises(tmp_path: Path):
    (tmp_path / "composer.json").write_text(json.dumps({"require": {"a/b": "1.0"}}))
    with pytest.raises(RemediationError):
        apply_remediation(tmp_path, dep("c/d", PACKAGIST, "1.0", "composer.json"), "2.0")


def test_apply_to_requirements_txt(tmp_path: Path):
    original = (
        "# deps\n"
        "requests==2.30.0\n"
        "Django>=4.2,<5  # web framework\n"
        "numpy[extra]~=1.26 ; python_version < '3.13'\n"
        "flask\n"
    )
    (tmp_path / "requirements.txt").write_text(original)
    apply_remediation(tmp_path, dep("requests", PYPI, "==2.30.0", "requirements.txt"), "2.32.4")
    apply_remediation(tmp_path, dep("django", PYPI, "<5,>=4.2", "requirements.txt"), "4.2.11")
    apply_remediation(tmp_path, dep("numpy", PYPI, "~=1.26", "requirements.txt"), "1.26.5")
    result = apply_remediation(tmp_path, dep("Flask", PYPI, "", "requirements.txt"), "3.1.3")
    assert (tmp_path / "requirements.txt").read_text() == (
        "# deps\n"
        "requests==2.32.4\n"
        "Django>=4.2.11,<5  # web framework\n"
        "numpy[extra]~=1.26.5 ; python_version < '3.13'\n"
        "flask>=3.1.3\n"
    )
    assert "pip install -r requirements.txt" in result.hint


def test_apply_to_requirements_txt_in_subdirectory_with_uv_lock(tmp_path: Path):
    sub = tmp_path / "api"
    sub.mkdir()
    (sub / "requirements.txt").write_text("requests==2.30.0\n")
    (sub / "uv.lock").write_text("")
    result = apply_remediation(
        tmp_path, dep("requests", PYPI, "==2.30.0", "api/requirements.txt"), "2.32.4"
    )
    assert (sub / "requirements.txt").read_text() == "requests==2.32.4\n"
    assert "uv lock" in result.hint


def test_apply_to_pyproject_pep621_and_poetry(tmp_path: Path):
    original = (
        "[project]\n"
        'name = "demo"\n'
        "dependencies = [\n"
        '  "requests==2.30.0",\n'
        '  "Django>=4.2",\n'
        "]\n"
        "\n"
        "[project.optional-dependencies]\n"
        'docs = ["sphinx>=7"]\n'
        "\n"
        "[tool.poetry.dependencies]\n"
        'python = "^3.12"\n'
        'httpx = "^0.27"\n'
        'celery = {version = ">=5.3", extras = ["redis"]}\n'
    )
    (tmp_path / "pyproject.toml").write_text(original)
    apply_remediation(tmp_path, dep("requests", PYPI, "==2.30.0", "pyproject.toml"), "2.32.4")
    apply_remediation(tmp_path, dep("sphinx", PYPI, ">=7", "pyproject.toml", dev=True), "7.4.7")
    apply_remediation(tmp_path, dep("httpx", PYPI, "^0.27", "pyproject.toml"), "0.28.1")
    result = apply_remediation(tmp_path, dep("celery", PYPI, ">=5.3", "pyproject.toml"), "5.4.0")
    assert (tmp_path / "pyproject.toml").read_text() == (
        original.replace('"requests==2.30.0"', '"requests==2.32.4"')
        .replace('"sphinx>=7"', '"sphinx>=7.4.7"')
        .replace('httpx = "^0.27"', 'httpx = "^0.28.1"')
        .replace('version = ">=5.3"', 'version = ">=5.4.0"')
    )
    assert "uv lock" in result.hint or "poetry" in result.hint


def test_apply_to_pipfile(tmp_path: Path):
    original = (
        '[packages]\nrequests = "==2.30.0"\n'
        'django = {version = ">=4.2", extras = ["argon2"]}\nflask = "*"\n'
    )
    (tmp_path / "Pipfile").write_text(original)
    apply_remediation(tmp_path, dep("requests", PYPI, "==2.30.0", "Pipfile"), "2.32.4")
    apply_remediation(tmp_path, dep("django", PYPI, ">=4.2", "Pipfile"), "4.2.11")
    result = apply_remediation(tmp_path, dep("flask", PYPI, "", "Pipfile"), "3.1.3")
    assert (tmp_path / "Pipfile").read_text() == (
        '[packages]\nrequests = "==2.32.4"\n'
        'django = {version = ">=4.2.11", extras = ["argon2"]}\nflask = ">=3.1.3"\n'
    )
    assert "pipenv" in result.hint


def test_apply_to_setup_cfg(tmp_path: Path):
    original = "[options]\ninstall_requires =\n    requests==2.30.0\n    Django>=4.2\n"
    (tmp_path / "setup.cfg").write_text(original)
    apply_remediation(tmp_path, dep("requests", PYPI, "==2.30.0", "setup.cfg"), "2.32.4")
    assert (tmp_path / "setup.cfg").read_text() == original.replace(
        "requests==2.30.0", "requests==2.32.4"
    )


def test_apply_rejects_unknown_manifest(tmp_path: Path):
    (tmp_path / "package.json").write_text("{}")
    with pytest.raises(RemediationError):
        apply_remediation(tmp_path, dep("x", PYPI, "", "package.json"), "1.0")


def test_apply_rejects_missing_file(tmp_path: Path):
    with pytest.raises(RemediationError):
        apply_remediation(tmp_path, dep("x", PYPI, "", "requirements.txt"), "1.0")


def test_follow_up_hint_mentions_lock_tools(tmp_path: Path):
    (tmp_path / "composer.lock").write_text("{}")
    assert "composer update wp-plugin/elementor" in follow_up_hint(
        tmp_path, dep("wp-plugin/elementor", WORDPRESS, "3.13.4", "composer.json")
    )
    assert "composer update a/b" in follow_up_hint(
        tmp_path / "nolock", dep("a/b", PACKAGIST, "1", "composer.json")
    )


# --- several declaring files --------------------------------------------------------------


def _multi_dep(tmp_path: Path) -> Dependency:
    (tmp_path / "requirements").mkdir()
    (tmp_path / "requirements" / "base.txt").write_text("authlib==1.2.0\nrequests==2.30.0\n")
    (tmp_path / "requirements" / "production.txt").write_text("-r base.txt\nauthlib>=1.2\n")
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname="x"\ndependencies=["authlib==1.2.0", "flask"]\n'
    )
    return Dependency(
        "authlib",
        PYPI,
        "==1.2.0",
        "1.2.0",
        "pinned",
        "requirements/base.txt",
        declarations=(
            Declaration("requirements/base.txt", "==1.2.0"),
            Declaration("requirements/production.txt", ">=1.2"),
            Declaration("pyproject.toml", "==1.2.0"),
        ),
    )


def test_apply_remediation_rewrites_every_declaring_file(tmp_path: Path):
    d = _multi_dep(tmp_path)
    result = apply_remediation(tmp_path, d, "1.3.1")
    assert (tmp_path / "requirements" / "base.txt").read_text() == (
        "authlib==1.3.1\nrequests==2.30.0\n"
    )
    assert (tmp_path / "requirements" / "production.txt").read_text() == (
        "-r base.txt\nauthlib>=1.3.1\n"
    )
    assert '"authlib==1.3.1", "flask"' in (tmp_path / "pyproject.toml").read_text()
    assert [
        (c.path.relative_to(tmp_path).as_posix(), c.old_constraint, c.new_constraint)
        for c in result.changes
    ] == [
        ("requirements/base.txt", "authlib==1.2.0", "authlib==1.3.1"),
        ("requirements/production.txt", "authlib>=1.2", "authlib>=1.3.1"),
        ("pyproject.toml", "authlib==1.2.0", "authlib==1.3.1"),
    ]
    assert result.path == tmp_path / "requirements" / "base.txt"
    assert (result.old_constraint, result.new_constraint) == ("authlib==1.2.0", "authlib==1.3.1")
    assert "pip install -r base.txt" in result.hint
    assert "pip install -r production.txt" in result.hint
    assert "uv lock" in result.hint


def test_apply_remediation_writes_nothing_when_one_file_cannot_be_edited(tmp_path: Path):
    d = _multi_dep(tmp_path)
    (tmp_path / "requirements" / "production.txt").write_text("-r base.txt\n")
    with pytest.raises(RemediationError, match="production.txt"):
        apply_remediation(tmp_path, d, "1.3.1")
    assert (tmp_path / "requirements" / "base.txt").read_text() == (
        "authlib==1.2.0\nrequests==2.30.0\n"
    )
    assert '"authlib==1.2.0"' in (tmp_path / "pyproject.toml").read_text()


def test_apply_remediation_edits_txt_inside_requirements_directory(tmp_path: Path):
    (tmp_path / "requirements").mkdir()
    (tmp_path / "requirements" / "base.txt").write_text("authlib==1.2.0\n")
    result = apply_remediation(
        tmp_path, dep("authlib", PYPI, "==1.2.0", "requirements/base.txt"), "1.3.1"
    )
    assert (tmp_path / "requirements" / "base.txt").read_text() == "authlib==1.3.1\n"
    assert "pip install -r base.txt" in result.hint
    assert "(in requirements)" in result.hint
