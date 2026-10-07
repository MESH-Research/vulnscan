from pathlib import Path

from vulnscan.models import PYPI
from vulnscan.parsers.python import (
    parse_pipfile,
    parse_pyproject,
    parse_requirements_txt,
    parse_setup_cfg,
)


def by_name(deps):
    return {d.name: d for d in deps}


def test_requirements_txt_basic(tmp_path: Path):
    req = tmp_path / "requirements.txt"
    req.write_text(
        "# comment\n"
        "requests==2.31.0\n"
        "Django>=4.2,<5  # trailing comment\n"
        "flask\n"
        "\n"
        "pyyaml ; python_version < '3.13'\n"
        "-e git+https://example.com/repo.git#egg=local\n"
        "--index-url https://pypi.org/simple\n"
        "pkg @ https://example.com/pkg-1.0.tar.gz\n"
        "numpy[extra]~=1.26\n"
    )
    deps = by_name(parse_requirements_txt(req, tmp_path))
    assert set(deps) == {"requests", "Django", "flask", "pyyaml", "numpy"}
    assert deps["requests"].constraint == "==2.31.0"
    assert deps["Django"].constraint == "<5,>=4.2"
    assert deps["flask"].constraint == ""
    assert deps["numpy"].constraint == "~=1.26"
    assert all(d.ecosystem == PYPI for d in deps.values())
    assert all(d.source_file == "requirements.txt" for d in deps.values())
    assert all(d.version is None for d in deps.values())
    assert all(d.dev is False for d in deps.values())


def test_requirements_txt_follows_includes(tmp_path: Path):
    (tmp_path / "base.txt").write_text("requests==2.0.0\n")
    dev = tmp_path / "requirements-dev.txt"
    dev.write_text("-r base.txt\npytest==8.0.0\n")
    deps = by_name(parse_requirements_txt(dev, tmp_path))
    assert set(deps) == {"requests", "pytest"}
    assert deps["requests"].source_file == "base.txt"
    assert deps["pytest"].source_file == "requirements-dev.txt"


def test_requirements_txt_missing_include_is_skipped(tmp_path: Path):
    req = tmp_path / "requirements.txt"
    req.write_text("-r nope.txt\nrequests==1.0\n")
    assert [d.name for d in parse_requirements_txt(req, tmp_path)] == ["requests"]


def test_requirements_txt_ignores_unparseable_lines(tmp_path: Path):
    req = tmp_path / "requirements.txt"
    req.write_text("this is not valid ===\nrequests==1.0\n")
    assert [d.name for d in parse_requirements_txt(req, tmp_path)] == ["requests"]


def test_requirements_txt_marks_dev_files(tmp_path: Path):
    req = tmp_path / "requirements-dev.txt"
    req.write_text("pytest\n")
    assert parse_requirements_txt(req, tmp_path)[0].dev is True
    req2 = tmp_path / "dev-requirements.txt"
    req2.write_text("pytest\n")
    assert parse_requirements_txt(req2, tmp_path)[0].dev is True
    req3 = tmp_path / "requirements" / "test.txt"
    req3.parent.mkdir()
    req3.write_text("pytest\n")
    assert parse_requirements_txt(req3, tmp_path)[0].dev is True


def test_pyproject_pep621(tmp_path: Path):
    pp = tmp_path / "pyproject.toml"
    pp.write_text(
        """
[project]
name = "demo"
dependencies = [
  "requests==2.31.0",
  "Django>=4.2",
  "typing-extensions; python_version < '3.11'",
]

[project.optional-dependencies]
docs = ["sphinx>=7"]

[dependency-groups]
dev = ["pytest>=8", {include-group = "lint"}]
lint = ["ruff"]
"""
    )
    deps = parse_pyproject(pp, tmp_path)
    named = by_name(deps)
    assert set(named) == {"requests", "Django", "typing-extensions", "sphinx", "pytest", "ruff"}
    assert named["requests"].constraint == "==2.31.0"
    assert named["requests"].dev is False
    assert named["sphinx"].dev is True
    assert named["pytest"].dev is True
    assert named["ruff"].dev is True
    assert named["requests"].source_file == "pyproject.toml"


def test_pyproject_poetry(tmp_path: Path):
    pp = tmp_path / "pyproject.toml"
    pp.write_text(
        """
[tool.poetry]
name = "demo"

[tool.poetry.dependencies]
python = "^3.12"
requests = "^2.31"
django = {version = ">=4.2", optional = true}
local = {path = "../local"}
multi = [{version = ">=1.0", python = "<3.12"}, {version = ">=2.0", python = ">=3.12"}]

[tool.poetry.dev-dependencies]
black = "*"

[tool.poetry.group.test.dependencies]
pytest = "^8"
"""
    )
    named = by_name(parse_pyproject(pp, tmp_path))
    assert set(named) == {"requests", "django", "multi", "black", "pytest"}
    assert named["requests"].constraint == "^2.31"
    assert named["django"].constraint == ">=4.2"
    assert named["multi"].constraint == ">=1.0"
    assert named["black"].constraint == ""
    assert named["black"].dev is True
    assert named["pytest"].dev is True
    assert named["requests"].dev is False


def test_pyproject_without_dependencies(tmp_path: Path):
    pp = tmp_path / "pyproject.toml"
    pp.write_text('[build-system]\nrequires = ["hatchling"]\n')
    assert parse_pyproject(pp, tmp_path) == []


def test_pyproject_invalid_toml_returns_empty(tmp_path: Path):
    pp = tmp_path / "pyproject.toml"
    pp.write_text("this = [is not toml")
    assert parse_pyproject(pp, tmp_path) == []


def test_pipfile(tmp_path: Path):
    pf = tmp_path / "Pipfile"
    pf.write_text(
        """
[[source]]
url = "https://pypi.org/simple"

[packages]
requests = "==2.31.0"
django = {version = ">=4.2", extras = ["argon2"]}
flask = "*"
local = {path = "."}

[dev-packages]
pytest = "*"
"""
    )
    named = by_name(parse_pipfile(pf, tmp_path))
    assert set(named) == {"requests", "django", "flask", "pytest"}
    assert named["requests"].constraint == "==2.31.0"
    assert named["django"].constraint == ">=4.2"
    assert named["flask"].constraint == ""
    assert named["pytest"].dev is True
    assert named["requests"].dev is False


def test_setup_cfg(tmp_path: Path):
    cfg = tmp_path / "setup.cfg"
    cfg.write_text(
        """
[metadata]
name = demo

[options]
install_requires =
    requests==2.31.0
    Django>=4.2

[options.extras_require]
test =
    pytest>=8
"""
    )
    named = by_name(parse_setup_cfg(cfg, tmp_path))
    assert set(named) == {"requests", "Django", "pytest"}
    assert named["requests"].constraint == "==2.31.0"
    assert named["pytest"].dev is True
    assert named["Django"].dev is False


def test_setup_cfg_without_options(tmp_path: Path):
    cfg = tmp_path / "setup.cfg"
    cfg.write_text("[flake8]\nmax-line-length = 100\n")
    assert parse_setup_cfg(cfg, tmp_path) == []
