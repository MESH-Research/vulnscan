import json
from pathlib import Path

import pytest

from vulnscan.models import (
    CONTAINER,
    NPM,
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


def test_plan_skips_forward_blocked_candidate():
    """Local-clear version that is malware-blocked is skipped; next clear version wins."""
    from vulnscan.risk import RiskKind, VersionRisk, VersionScore

    dep = Dependency("pkg", PYPI, "==1.0", "1.0", "pinned", "requirements.txt")
    vuln = vuln_with_ranges(VersionRange(lower="0", upper="1.1"))
    finding = Finding(dep, [vuln])
    scores = {
        "1.1": VersionScore(
            "1.1",
            (VersionRisk(RiskKind.MALWARE, "bad", advisory_id="MAL-1"),),
        ),
        "1.2": VersionScore("1.2", ()),
    }
    plan = plan_remediation(finding, ["1.0", "1.1", "1.2"], scores=scores)
    assert plan.nearest_safe == "1.2"
    assert any("skipped 1.1" in w for w in plan.warnings)


def test_plan_freshness_warns_but_does_not_block():
    from vulnscan.risk import RiskKind, VersionRisk, VersionScore

    dep = Dependency("pkg", PYPI, "==1.0", "1.0", "pinned", "requirements.txt")
    vuln = vuln_with_ranges(VersionRange(lower="0", upper="1.1"))
    finding = Finding(dep, [vuln])
    scores = {
        "1.1": VersionScore(
            "1.1",
            (VersionRisk(RiskKind.FRESH, "new"),),
        ),
    }
    plan = plan_remediation(finding, ["1.0", "1.1"], scores=scores)
    assert plan.nearest_safe == "1.1"
    assert plan.warnings


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


# --- package.json ---------------------------------------------------------------------------


def test_apply_to_package_json_preserves_formatting(tmp_path: Path):
    original = (
        "{\n"
        '  "name": "express",\n'
        '  "version": "1.0.0",\n'
        '  "dependencies": {\n'
        '    "express": "^4.18.2",\n'
        '    "@babel/core": "7.23.0"\n'
        "  },\n"
        '  "devDependencies": {\n'
        '    "jest": "~29.7.0"\n'
        "  }\n"
        "}\n"
    )
    (tmp_path / "package.json").write_text(original)
    result = apply_remediation(tmp_path, dep("express", NPM, "^4.18.2", "package.json"), "4.19.2")
    text = (tmp_path / "package.json").read_text()
    assert text == original.replace('"express": "^4.18.2"', '"express": "^4.19.2"')
    assert json.loads(text)["name"] == "express"
    assert (result.old_constraint, result.new_constraint) == ("^4.18.2", "^4.19.2")
    assert "npm install" in result.hint

    apply_remediation(tmp_path, dep("@babel/core", NPM, "7.23.0", "package.json"), "7.23.5")
    apply_remediation(tmp_path, dep("jest", NPM, "~29.7.0", "package.json", dev=True), "29.8.0")
    data = json.loads((tmp_path / "package.json").read_text())
    assert data["dependencies"]["@babel/core"] == "7.23.5"
    assert data["devDependencies"]["jest"] == "~29.8.0"


@pytest.mark.parametrize(
    "old, new, expected",
    [
        ("^4.18.2", "4.19.2", "^4.19.2"),
        ("~4.18.2", "4.19.2", "~4.19.2"),
        (">=4.18.2", "4.19.2", ">=4.19.2"),
        ("4.18.2", "4.19.2", "4.19.2"),
        ("=4.18.2", "4.19.2", "=4.19.2"),
        ("4.18.x", "4.19.2", "^4.19.2"),
        ("4.x", "4.19.2", "^4.19.2"),
        ("*", "4.19.2", "^4.19.2"),
        (">=4.18.2 <5", "4.19.2", "^4.19.2"),
    ],
)
def test_rewrite_npm_range(old, new, expected):
    from vulnscan.remediate import rewrite_npm_range

    assert rewrite_npm_range(old, new) == expected


def test_follow_up_hint_for_node_manifests(tmp_path: Path):
    d = dep("express", NPM, "^4.18.2", "package.json")
    assert "npm install" in follow_up_hint(tmp_path, d)
    (tmp_path / "yarn.lock").write_text("")
    assert "yarn install" in follow_up_hint(tmp_path, d)
    (tmp_path / "yarn.lock").unlink()
    (tmp_path / "pnpm-lock.yaml").write_text("")
    assert "pnpm install" in follow_up_hint(tmp_path, d)


# --- pyproject.toml: only dependency tables are edited ----------------------------------------


def test_pyproject_config_value_that_looks_like_a_package_is_left_alone_poetry(tmp_path: Path):
    """A `profile = "django"` setting must not be mistaken for a bare django requirement."""
    original = (
        "[tool.djlint]\n"
        'profile = "django"\n'
        "\n"
        "[tool.poetry.dependencies]\n"
        'python = "^3.12"\n'
        'django = "6.0.7"\n'
    )
    (tmp_path / "pyproject.toml").write_text(original)
    result = apply_remediation(tmp_path, dep("django", PYPI, "6.0.7", "pyproject.toml"), "6.1.2")
    assert (tmp_path / "pyproject.toml").read_text() == original.replace(
        'django = "6.0.7"', 'django = "6.1.2"'
    )
    assert (result.old_constraint, result.new_constraint) == ("6.0.7", "6.1.2")


def test_pyproject_config_value_that_looks_like_a_package_is_left_alone_pep621(tmp_path: Path):
    original = (
        "[tool.djlint]\n"
        'profile = "django"\n'
        "\n"
        "[project]\n"
        'name = "demo"\n'
        'dependencies = ["django==6.0.7"]\n'
    )
    (tmp_path / "pyproject.toml").write_text(original)
    apply_remediation(tmp_path, dep("django", PYPI, "==6.0.7", "pyproject.toml"), "6.1.2")
    assert (tmp_path / "pyproject.toml").read_text() == original.replace(
        '"django==6.0.7"', '"django==6.1.2"'
    )


def test_pyproject_bare_requirement_is_edited_not_the_lookalike_setting(tmp_path: Path):
    original = (
        "[tool.djlint]\n"
        'profile = "django"\n'
        "\n"
        "[project]\n"
        'dependencies = ["django"]\n'
        "\n"
        "[dependency-groups]\n"
        'django = [{include-group = "django"}, "pytest-django"]\n'
    )
    (tmp_path / "pyproject.toml").write_text(original)
    apply_remediation(tmp_path, dep("django", PYPI, "", "pyproject.toml"), "6.1.2")
    assert (tmp_path / "pyproject.toml").read_text() == original.replace(
        'dependencies = ["django"]', 'dependencies = ["django>=6.1.2"]'
    )


def test_pyproject_key_named_like_a_package_outside_poetry_tables_is_left_alone(tmp_path: Path):
    original = (
        "[tool.custom]\n"
        'django = "legacy"\n'
        "\n"
        "[tool.poetry.group.dev.dependencies]\n"
        'django = {version = "^6.0", extras = ["argon2"]}\n'
    )
    (tmp_path / "pyproject.toml").write_text(original)
    apply_remediation(tmp_path, dep("django", PYPI, "^6.0", "pyproject.toml", dev=True), "6.1.2")
    assert (tmp_path / "pyproject.toml").read_text() == original.replace(
        'version = "^6.0"', 'version = "^6.1.2"'
    )


def test_pyproject_requirement_outside_dependency_tables_is_not_found(tmp_path: Path):
    (tmp_path / "pyproject.toml").write_text('[tool.djlint]\nprofile = "django"\n')
    with pytest.raises(RemediationError, match="django"):
        apply_remediation(tmp_path, dep("django", PYPI, "", "pyproject.toml"), "6.1.2")


def test_pipfile_script_named_like_a_package_is_left_alone(tmp_path: Path):
    original = (
        "[scripts]\n"
        'django = "python manage.py runserver"\n'
        "\n"
        "[packages]\n"
        'django = "==6.0.7"\n'
        "\n"
        "[requires]\n"
        'python_version = "3.12"\n'
    )
    (tmp_path / "Pipfile").write_text(original)
    apply_remediation(tmp_path, dep("django", PYPI, "==6.0.7", "Pipfile"), "6.1.2")
    assert (tmp_path / "Pipfile").read_text() == original.replace(
        'django = "==6.0.7"', 'django = "==6.1.2"'
    )


# -- transitive dependencies cannot be edited in place ----------------------------------------


def _certifi(required_by=("httpx",), lock="uv.lock"):
    from vulnscan.models import PYPI, Dependency

    return Dependency(
        "certifi", PYPI, "", "2024.2.2", "lock", lock, transitive=True, required_by=required_by
    )


def test_plan_pin_targets_pyproject_next_to_uv_lock(tmp_path: Path):
    from vulnscan.remediate import plan_pin

    (tmp_path / "uv.lock").write_text('[[package]]\nname="certifi"\nversion="2024.2.2"\n')
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "x"\ndependencies = [\n]\n')
    plan = plan_pin(tmp_path, _certifi(), "2026.10.19")
    assert plan.path == tmp_path / "pyproject.toml"
    assert plan.source_file == "pyproject.toml"
    assert plan.entry == "certifi>=2026.10.19"
    assert "dependencies" in plan.section
    assert plan.replaces is None


def test_apply_pin_inserts_into_multi_line_pep621_array(tmp_path: Path):
    from vulnscan.remediate import apply_pin

    (tmp_path / "uv.lock").write_text("")
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "x"\ndependencies = [\n    "httpx>=0.27",\n]\n\n'
        "[tool.ruff]\nline-length = 100\n"
    )
    outcome = apply_pin(tmp_path, _certifi(), "2026.10.19")
    assert (tmp_path / "pyproject.toml").read_text() == (
        '[project]\nname = "x"\ndependencies = [\n    "certifi>=2026.10.19",\n'
        '    "httpx>=0.27",\n]\n'
        "\n[tool.ruff]\nline-length = 100\n"
    )
    assert outcome.new_constraint == "certifi>=2026.10.19"
    assert outcome.changes[0].added is True
    assert outcome.changes[0].source_file == "pyproject.toml"
    assert "uv lock" in outcome.hint


def test_apply_pin_inserts_into_single_line_and_empty_pep621_arrays(tmp_path: Path):
    from vulnscan.remediate import apply_pin

    (tmp_path / "uv.lock").write_text("")
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text('[project]\nname = "x"\ndependencies = ["httpx>=0.27", "rich"]\n')
    apply_pin(tmp_path, _certifi(), "2026.10.19")
    assert pyproject.read_text() == (
        '[project]\nname = "x"\ndependencies = ["certifi>=2026.10.19", "httpx>=0.27", "rich"]\n'
    )
    pyproject.write_text('[project]\nname = "x"\ndependencies = []\n')
    apply_pin(tmp_path, _certifi(), "2026.10.19")
    assert pyproject.read_text() == (
        '[project]\nname = "x"\ndependencies = [\n    "certifi>=2026.10.19",\n]\n'
    )


def test_apply_pin_adds_a_dependencies_array_when_project_has_none(tmp_path: Path):
    from vulnscan.remediate import apply_pin

    (tmp_path / "uv.lock").write_text("")
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        '[project]\nname = "x"\nversion = "1.0"\n\n[tool.uv]\ndev-dependencies = []\n'
    )
    apply_pin(tmp_path, _certifi(), "2026.10.19")
    text = pyproject.read_text()
    assert 'dependencies = [\n    "certifi>=2026.10.19",\n]\n' in text
    assert text.index("[project]") < text.index("certifi") < text.index("[tool.uv]")
    import tomllib

    assert tomllib.loads(text)["project"]["dependencies"] == ["certifi>=2026.10.19"]


def test_apply_pin_uses_poetry_table_next_to_poetry_lock(tmp_path: Path):
    from vulnscan.remediate import apply_pin

    (tmp_path / "poetry.lock").write_text("")
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        '[tool.poetry]\nname = "x"\n\n[tool.poetry.dependencies]\n'
        'python = "^3.12"\nhttpx = "^0.27"\n'
    )
    outcome = apply_pin(tmp_path, _certifi(lock="poetry.lock"), "2026.10.19")
    assert pyproject.read_text() == (
        '[tool.poetry]\nname = "x"\n\n[tool.poetry.dependencies]\ncertifi = ">=2026.10.19"\n'
        'python = "^3.12"\nhttpx = "^0.27"\n'
    )
    assert outcome.new_constraint == 'certifi = ">=2026.10.19"'
    assert "poetry lock" in outcome.hint


def test_apply_pin_appends_to_requirements_txt_without_a_pyproject(tmp_path: Path):
    from vulnscan.remediate import apply_pin

    (tmp_path / "uv.lock").write_text("")
    (tmp_path / "requirements.txt").write_text("httpx>=0.27")
    outcome = apply_pin(tmp_path, _certifi(), "2026.10.19")
    assert (tmp_path / "requirements.txt").read_text() == "httpx>=0.27\ncertifi>=2026.10.19\n"
    assert outcome.changes[0].source_file == "requirements.txt"


def test_apply_pin_inserts_into_pipfile_packages(tmp_path: Path):
    from vulnscan.remediate import apply_pin

    (tmp_path / "Pipfile.lock").write_text("{}")
    pipfile = tmp_path / "Pipfile"
    pipfile.write_text(
        '[[source]]\nurl = "https://pypi.org/simple"\n\n[packages]\nhttpx = "*"\n\n[dev-packages]\n'
    )
    apply_pin(tmp_path, _certifi(lock="Pipfile.lock"), "2026.10.19")
    assert pipfile.read_text() == (
        '[[source]]\nurl = "https://pypi.org/simple"\n\n[packages]\ncertifi = ">=2026.10.19"\n'
        'httpx = "*"\n\n[dev-packages]\n'
    )


def test_apply_pin_inserts_into_composer_require_preserving_formatting(tmp_path: Path):
    from vulnscan.models import PACKAGIST, Dependency
    from vulnscan.remediate import apply_pin

    (tmp_path / "composer.lock").write_text("{}")
    composer = tmp_path / "composer.json"
    composer.write_text(
        '{\n    "name": "acme/site",\n    "require": {\n        "monolog/monolog": "^2.0"\n    },\n'
        '    "require-dev": {}\n}\n'
    )
    dep = Dependency("psr/log", PACKAGIST, "", "2.0.0", "lock", "composer.lock", transitive=True)
    outcome = apply_pin(tmp_path, dep, "3.0.1")
    text = composer.read_text()
    assert text == (
        '{\n    "name": "acme/site",\n    "require": {\n        "psr/log": "^3.0.1",\n'
        '        "monolog/monolog": "^2.0"\n    },\n    "require-dev": {}\n}\n'
    )
    assert json.loads(text)["require"]["psr/log"] == "^3.0.1"
    assert outcome.new_constraint == '"psr/log": "^3.0.1"'
    assert "composer update psr/log" in outcome.hint


def test_apply_pin_creates_npm_overrides_when_missing(tmp_path: Path):
    from vulnscan.models import NPM, Dependency
    from vulnscan.remediate import apply_pin

    (tmp_path / "package-lock.json").write_text("{}")
    package = tmp_path / "package.json"
    package.write_text('{\n  "name": "app",\n  "dependencies": {\n    "express": "^4"\n  }\n}\n')
    dep = Dependency("cookie", NPM, "", "0.5.0", "lock", "package-lock.json", transitive=True)
    outcome = apply_pin(tmp_path, dep, "0.6.0")
    text = package.read_text()
    assert json.loads(text) == {
        "name": "app",
        "dependencies": {"express": "^4"},
        "overrides": {"cookie": "^0.6.0"},
    }
    assert '"overrides": {\n    "cookie": "^0.6.0"\n  }' in text
    assert text.endswith("}\n")
    assert outcome.new_constraint == '"cookie": "^0.6.0"'
    assert "npm install" in outcome.hint


def test_apply_pin_adds_to_existing_npm_overrides_or_replaces_the_entry(tmp_path: Path):
    from vulnscan.models import NPM, Dependency
    from vulnscan.remediate import apply_pin

    (tmp_path / "package-lock.json").write_text("{}")
    package = tmp_path / "package.json"
    package.write_text('{\n  "name": "app",\n  "overrides": {\n    "semver": "^7.5.2"\n  }\n}\n')
    dep = Dependency("cookie", NPM, "", "0.5.0", "lock", "package-lock.json", transitive=True)
    apply_pin(tmp_path, dep, "0.6.0")
    assert json.loads(package.read_text())["overrides"] == {"cookie": "^0.6.0", "semver": "^7.5.2"}
    outcome = apply_pin(tmp_path, dep, "0.7.0")
    assert json.loads(package.read_text())["overrides"] == {"cookie": "^0.7.0", "semver": "^7.5.2"}
    assert outcome.old_constraint == "^0.6.0"
    assert outcome.changes[0].added is False


def test_apply_pin_uses_resolutions_for_yarn_and_pnpm_overrides_for_pnpm(tmp_path: Path):
    from vulnscan.models import NPM, Dependency
    from vulnscan.remediate import apply_pin

    yarn = tmp_path / "yarn"
    yarn.mkdir()
    (yarn / "yarn.lock").write_text("")
    (yarn / "package.json").write_text('{\n  "name": "a"\n}\n')
    dep = Dependency("cookie", NPM, "", "0.5.0", "lock", "yarn/yarn.lock", transitive=True)
    apply_pin(tmp_path, dep, "0.6.0")
    assert json.loads((yarn / "package.json").read_text()) == {
        "name": "a",
        "resolutions": {"cookie": "^0.6.0"},
    }
    pnpm = tmp_path / "pnpm"
    pnpm.mkdir()
    (pnpm / "pnpm-lock.yaml").write_text("")
    (pnpm / "package.json").write_text(
        '{\n  "name": "b",\n  "pnpm": {\n    "onlyBuiltDependencies": []\n  }\n}\n'
    )
    dep = Dependency("cookie", NPM, "", "0.5.0", "lock", "pnpm/pnpm-lock.yaml", transitive=True)
    outcome = apply_pin(tmp_path, dep, "0.6.0")
    assert json.loads((pnpm / "package.json").read_text()) == {
        "name": "b",
        "pnpm": {"onlyBuiltDependencies": [], "overrides": {"cookie": "^0.6.0"}},
    }
    assert "pnpm install" in outcome.hint


def test_apply_remediation_pins_transitive_dependencies(tmp_path: Path):
    from vulnscan.remediate import apply_remediation

    (tmp_path / "uv.lock").write_text('[[package]]\nname="certifi"\nversion="2024.2.2"\n')
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "x"\ndependencies = [\n]\n')
    outcome = apply_remediation(tmp_path, _certifi(), "2026.10.19")
    assert outcome.changes[0].added is True
    assert '"certifi>=2026.10.19"' in (tmp_path / "pyproject.toml").read_text()
    assert (tmp_path / "uv.lock").read_text() == '[[package]]\nname="certifi"\nversion="2024.2.2"\n'


def test_apply_pin_without_a_manifest_explains_what_to_add(tmp_path: Path):
    from vulnscan.remediate import RemediationError, apply_pin, plan_pin

    (tmp_path / "uv.lock").write_text("")
    for call in (plan_pin, apply_pin):
        with pytest.raises(RemediationError) as excinfo:
            call(tmp_path, _certifi(), "2026.10.19")
        message = str(excinfo.value)
        assert "transitive" in message
        assert "httpx" in message
        assert "certifi>=2026.10.19" in message


def test_apply_pin_refuses_npm_in_invenio_mode(tmp_path: Path):
    from vulnscan.config import Settings
    from vulnscan.models import NPM, Dependency
    from vulnscan.remediate import RemediationError, apply_pin

    (tmp_path / "package-lock.json").write_text("{}")
    (tmp_path / "package.json").write_text("{}")
    settings = Settings(
        project_path=tmp_path,
        feed_dir=tmp_path,
        rss_filename="r",
        atom_filename="a",
        state_filename="s",
        feed_title="t",
        feed_link="",
        feed_description="d",
        osv_base_url="u",
        request_timeout=1.0,
        include_dev=True,
        query_unknown_versions=False,
        invenio_webpack="on",
    )
    dep = Dependency("cookie", NPM, "", "0.5.0", "lock", "package-lock.json", transitive=True)
    with pytest.raises(RemediationError) as excinfo:
        apply_pin(tmp_path, dep, "0.6.0", settings=settings)
    assert "transitive" in str(excinfo.value)
    assert (tmp_path / "package.json").read_text() == "{}"


@pytest.mark.parametrize(
    ("ecosystem", "name", "expected"),
    [
        ("PyPI", "certifi", "certifi>=2026.10.19"),
        ("Packagist", "psr/log", '"psr/log": "^2026.10.19"'),
        ("WordPress", "wpackagist-plugin/akismet", '"wpackagist-plugin/akismet": "^2026.10.19"'),
        ("npm", "cookie", '"cookie": "^2026.10.19"'),
    ],
)
def test_transitive_hint_names_the_constraint_to_add(ecosystem, name, expected):
    from vulnscan.models import Dependency
    from vulnscan.remediate import transitive_hint

    dep = Dependency(name, ecosystem, "", "1.0.0", "lock", "lock", transitive=True)
    hint = transitive_hint(dep, "2026.10.19")
    assert expected in hint
    if ecosystem == "npm":
        assert "overrides" in hint


def test_apply_pin_creates_the_whole_pnpm_section_when_missing(tmp_path: Path):
    from vulnscan.models import NPM, Dependency
    from vulnscan.remediate import apply_pin

    (tmp_path / "pnpm-lock.yaml").write_text("")
    package = tmp_path / "package.json"
    package.write_text('{\n  "name": "b",\n  "version": "1.0.0"\n}\n')
    dep = Dependency("cookie", NPM, "", "0.5.0", "lock", "pnpm-lock.yaml", transitive=True)
    apply_pin(tmp_path, dep, "0.6.0")
    text = package.read_text()
    assert json.loads(text) == {
        "name": "b",
        "version": "1.0.0",
        "pnpm": {"overrides": {"cookie": "^0.6.0"}},
    }
    assert '"pnpm": {\n    "overrides": {\n      "cookie": "^0.6.0"\n    }\n  }' in text


# --- container images -----------------------------------------------------------------------


def image(name, tag, version, source_file, **kw):
    return Dependency(name, CONTAINER, tag, version, "pinned", source_file, kind="image", **kw)


def test_plan_remediation_for_an_image_uses_registry_tags():
    dep = image("php", "8.2.19-fpm", "8.2.19", "Dockerfile")
    vuln = vuln_with_ranges(VersionRange(lower="8.2.0", upper="8.2.20"))
    plan = plan_remediation(Finding(dep, [vuln]), ["8.2.9", "8.2.19", "8.2.20", "8.3.8"])
    assert plan.nearest_safe == "8.2.20"
    assert plan.latest == "8.3.8"
    assert plan.latest_is_safe


def test_apply_to_dockerfile_rewrites_the_tag_and_keeps_the_variant(tmp_path: Path):
    original = (
        "# syntax=docker/dockerfile:1\n"
        "FROM php:8.2.19-fpm-bookworm AS base\n"
        "RUN echo php:8.2.19-fpm-bookworm > /note\n"
        "FROM --platform=linux/amd64 node:20-alpine\n"
    )
    (tmp_path / "Dockerfile").write_text(original)
    result = apply_remediation(
        tmp_path, image("php", "8.2.19-fpm-bookworm", "8.2.19", "Dockerfile"), "8.2.20"
    )
    assert (tmp_path / "Dockerfile").read_text() == original.replace(
        "FROM php:8.2.19-fpm-bookworm", "FROM php:8.2.20-fpm-bookworm"
    )
    assert result.old_constraint == "8.2.19-fpm-bookworm"
    assert result.new_constraint == "8.2.20-fpm-bookworm"
    assert "docker" in result.hint.lower() and "build" in result.hint.lower()


def test_apply_to_dockerfile_rewrites_every_stage_and_drops_a_digest(tmp_path: Path):
    (tmp_path / "Dockerfile").write_text(
        "FROM php:8.2.19@sha256:abc AS a\nFROM docker.io/library/php:8.2.19 AS b\n"
    )
    apply_remediation(tmp_path, image("php", "8.2.19", "8.2.19", "Dockerfile"), "8.2.20")
    assert (tmp_path / "Dockerfile").read_text() == (
        "FROM php:8.2.20 AS a\nFROM docker.io/library/php:8.2.20 AS b\n"
    )


def test_apply_to_dockerfile_rewrites_an_arg_default(tmp_path: Path):
    (tmp_path / "Dockerfile").write_text(
        "ARG PHP_VERSION=8.2.19\nARG VARIANT=fpm\nFROM php:${PHP_VERSION}-$VARIANT\n"
    )
    result = apply_remediation(
        tmp_path, image("php", "8.2.19-fpm", "8.2.19", "Dockerfile"), "8.2.20"
    )
    assert (tmp_path / "Dockerfile").read_text() == (
        "ARG PHP_VERSION=8.2.20\nARG VARIANT=fpm\nFROM php:${PHP_VERSION}-$VARIANT\n"
    )
    assert result.old_constraint == "8.2.19-fpm"
    assert result.new_constraint == "8.2.20-fpm"


def test_apply_to_dockerfile_rewrites_an_inline_arg_default(tmp_path: Path):
    (tmp_path / "Dockerfile").write_text("FROM traefik:${TRAEFIK_TAG:-v2.10.7}\n")
    apply_remediation(tmp_path, image("traefik", "v2.10.7", "2.10.7", "Dockerfile"), "2.11.3")
    assert (tmp_path / "Dockerfile").read_text() == "FROM traefik:${TRAEFIK_TAG:-v2.11.3}\n"


def test_apply_to_dockerfile_missing_image_raises(tmp_path: Path):
    (tmp_path / "Dockerfile").write_text("FROM nginx:1.25.4\n")
    with pytest.raises(RemediationError):
        apply_remediation(tmp_path, image("php", "8.2.19", "8.2.19", "Dockerfile"), "8.2.20")


def test_apply_to_compose_rewrites_quoted_and_bare_images(tmp_path: Path):
    original = (
        "services:\n"
        "  proxy:\n"
        "    image: traefik:v2.10.7   # edge router\n"
        "  other:\n"
        '    image: "traefik:v2.10.7"\n'
        "  db:\n"
        "    image: postgres:16.2\n"
    )
    (tmp_path / "docker-compose.yml").write_text(original)
    result = apply_remediation(
        tmp_path, image("traefik", "v2.10.7", "2.10.7", "docker-compose.yml"), "2.11.3"
    )
    assert (tmp_path / "docker-compose.yml").read_text() == original.replace(
        "traefik:v2.10.7", "traefik:v2.11.3"
    )
    assert result.old_constraint == "v2.10.7"
    assert result.new_constraint == "v2.11.3"
    assert "docker compose" in result.hint


def test_apply_to_compose_rewrites_an_interpolation_default(tmp_path: Path):
    (tmp_path / "compose.yaml").write_text(
        "services:\n  proxy:\n    image: traefik:${TRAEFIK_TAG:-v2.10.7}\n"
    )
    apply_remediation(tmp_path, image("traefik", "v2.10.7", "2.10.7", "compose.yaml"), "2.11.3")
    assert (tmp_path / "compose.yaml").read_text() == (
        "services:\n  proxy:\n    image: traefik:${TRAEFIK_TAG:-v2.11.3}\n"
    )


def test_apply_to_compose_variable_without_default_raises(tmp_path: Path):
    (tmp_path / ".env").write_text("TRAEFIK_TAG=v2.10.7\n")
    (tmp_path / "compose.yaml").write_text(
        "services:\n  proxy:\n    image: traefik:${TRAEFIK_TAG}\n"
    )
    with pytest.raises(RemediationError) as info:
        apply_remediation(tmp_path, image("traefik", "v2.10.7", "2.10.7", "compose.yaml"), "2.11.3")
    assert "TRAEFIK_TAG" in str(info.value)


def test_apply_to_image_declared_in_dockerfile_and_compose(tmp_path: Path):
    (tmp_path / "Dockerfile").write_text("FROM php:8.2.19-fpm\n")
    (tmp_path / "docker-compose.yml").write_text("services:\n  app:\n    image: php:8.2.19-fpm\n")
    d = image(
        "php",
        "8.2.19-fpm",
        "8.2.19",
        "Dockerfile",
        declarations=(
            Declaration("Dockerfile", "8.2.19-fpm"),
            Declaration("docker-compose.yml", "8.2.19-fpm"),
        ),
    )
    result = apply_remediation(tmp_path, d, "8.2.20")
    assert (tmp_path / "Dockerfile").read_text() == "FROM php:8.2.20-fpm\n"
    assert (tmp_path / "docker-compose.yml").read_text() == (
        "services:\n  app:\n    image: php:8.2.20-fpm\n"
    )
    assert [c.source_file for c in result.changes] == ["Dockerfile", "docker-compose.yml"]


def test_follow_up_hint_for_container_files(tmp_path: Path):
    d = image("php", "8.2.19", "8.2.19", "deploy/Dockerfile")
    hint = follow_up_hint(tmp_path, d)
    assert "docker" in hint.lower() and "build" in hint.lower()
    c = image("traefik", "v2.10.7", "2.10.7", "deploy/docker-compose.yml")
    hint = follow_up_hint(tmp_path, c)
    assert "docker compose" in hint and "pull" in hint


def test_apply_to_github_workflow_rewrites_container_services_and_docker_uses(tmp_path: Path):
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    original = (
        "jobs:\n"
        "  test:\n"
        "    container: php:8.2.19-cli\n"
        "    services:\n"
        "      db:\n"
        "        image: 'php:8.2.19-cli'\n"
        "      other: php:8.2.19-cli  # same image\n"
        "    steps:\n"
        "      - uses: docker://php:8.2.19-cli\n"
        "      - run: echo php:8.2.19-cli\n"
        "    env:\n"
        "      NOTE: php:8.2.19-cli\n"
    )
    (workflows / "ci.yml").write_text(original)
    result = apply_remediation(
        tmp_path, image("php", "8.2.19-cli", "8.2.19", ".github/workflows/ci.yml"), "8.2.20"
    )
    expected = original.replace("php:8.2.19-cli", "php:8.2.20-cli")
    expected = expected.replace("run: echo php:8.2.20-cli", "run: echo php:8.2.19-cli")
    expected = expected.replace("NOTE: php:8.2.20-cli", "NOTE: php:8.2.19-cli")
    assert (workflows / "ci.yml").read_text() == expected
    assert result.new_constraint == "8.2.20-cli"
    assert "commit" in result.hint.lower()


def test_apply_to_gitlab_ci_rewrites_image_name_and_service_entries(tmp_path: Path):
    original = (
        "image: php:8.2.19-cli\n"
        "default:\n"
        "  image:\n"
        "    name: php:8.2.19-cli\n"
        "    entrypoint: ['']\n"
        "test:\n"
        "  services:\n"
        "    - php:8.2.19-cli\n"
        '    - name: "php:8.2.19-cli"\n'
        "      alias: db\n"
        "  script:\n"
        "    - docker run php:8.2.19-cli\n"
    )
    (tmp_path / ".gitlab-ci.yml").write_text(original)
    result = apply_remediation(
        tmp_path, image("php", "8.2.19-cli", "8.2.19", ".gitlab-ci.yml"), "8.2.20"
    )
    expected = original.replace("php:8.2.19-cli", "php:8.2.20-cli").replace(
        "docker run php:8.2.20-cli", "docker run php:8.2.19-cli"
    )
    assert (tmp_path / ".gitlab-ci.yml").read_text() == expected
    assert result.new_constraint == "8.2.20-cli"
    assert "commit" in result.hint.lower()


def test_apply_to_gitlab_ci_variable_tag_raises_naming_the_variable(tmp_path: Path):
    (tmp_path / ".gitlab-ci.yml").write_text(
        "variables:\n  PHP_TAG: 8.2.19-cli\nimage: php:$PHP_TAG\n"
    )
    with pytest.raises(RemediationError) as info:
        apply_remediation(
            tmp_path, image("php", "8.2.19-cli", "8.2.19", ".gitlab-ci.yml"), "8.2.20"
        )
    assert "PHP_TAG" in str(info.value)


def test_apply_to_ci_file_missing_image_raises(tmp_path: Path):
    (tmp_path / ".gitlab-ci.yml").write_text("image: nginx:1.25.4\n")
    with pytest.raises(RemediationError):
        apply_remediation(tmp_path, image("php", "8.2.19", "8.2.19", ".gitlab-ci.yml"), "8.2.20")


def test_plan_skipped_warning_names_advisories_not_descriptions():
    """The skipped note lists advisory ids; it never quotes the full advisory text."""
    from vulnscan.risk import RiskKind, VersionRisk, VersionScore

    dep = Dependency("mariadb", CONTAINER, "10.11", "10.11", "image", "docker-compose.yml")
    vuln = vuln_with_ranges(VersionRange(lower="0", upper="10.11.18"))
    finding = Finding(dep, [vuln])
    description = "MariaDB server is a community developed fork of MySQL server. " * 20
    scores = {
        "11.4.10": VersionScore(
            "11.4.10",
            (
                VersionRisk(RiskKind.ADVISORY, description, advisory_id="CVE-2025-0001"),
                VersionRisk(RiskKind.ADVISORY, description, advisory_id="CVE-2025-0002"),
                VersionRisk(
                    RiskKind.YANKED, "mariadb 11.4.10 is yanked/unpublished on the registry"
                ),
            ),
        ),
        "11.4.11": VersionScore("11.4.11", ()),
    }
    plan = plan_remediation(finding, ["10.11", "11.4.10", "11.4.11"], scores=scores)
    assert plan.nearest_safe == "11.4.11"
    skipped = [w for w in plan.warnings if w.startswith("skipped 11.4.10")]
    assert len(skipped) == 1
    assert "CVE-2025-0001" in skipped[0]
    assert "CVE-2025-0002" in skipped[0]
    assert "yanked" in skipped[0]
    assert "community developed fork" not in skipped[0]
    assert len(skipped[0]) < 200
