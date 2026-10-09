import json
from pathlib import Path

from vulnscan.models import NPM
from vulnscan.parsers.node import parse_package_json


def write(tmp_path: Path, data) -> Path:
    path = tmp_path / "package.json"
    path.write_text(json.dumps(data) if not isinstance(data, str) else data)
    return path


def test_parse_package_json_reads_prod_dev_and_optional(tmp_path: Path):
    path = write(
        tmp_path,
        {
            "name": "my-app",
            "version": "1.0.0",
            "dependencies": {"express": "^4.18.2", "@babel/core": " 7.23.0 "},
            "devDependencies": {"jest": "~29.7.0"},
            "optionalDependencies": {"fsevents": "2.3.3"},
            "peerDependencies": {"react": ">=18"},
        },
    )
    deps = parse_package_json(path, tmp_path)
    assert [(d.name, d.constraint, d.dev) for d in deps] == [
        ("express", "^4.18.2", False),
        ("@babel/core", "7.23.0", False),
        ("fsevents", "2.3.3", False),
        ("jest", "~29.7.0", True),
    ]
    assert all(d.ecosystem == NPM for d in deps)
    assert all(d.version is None and d.version_source == "unknown" for d in deps)
    assert all(d.source_file == "package.json" for d in deps)


def test_parse_package_json_skips_non_registry_specs(tmp_path: Path):
    path = write(
        tmp_path,
        {
            "dependencies": {
                "local": "file:../local",
                "linked": "link:../linked",
                "fromgit": "git+https://github.com/user/repo.git",
                "shorthand": "github:user/repo",
                "bare-shorthand": "user/repo",
                "tarball": "https://example.com/pkg.tgz",
                "ws": "workspace:*",
                "lodash": "^4.17.21",
                "weird": 42,
            }
        },
    )
    assert [d.name for d in parse_package_json(path, tmp_path)] == ["lodash"]


def test_parse_package_json_resolves_npm_aliases(tmp_path: Path):
    path = write(tmp_path, {"dependencies": {"string-width-cjs": "npm:string-width@^4.2.0"}})
    deps = parse_package_json(path, tmp_path)
    assert [(d.name, d.constraint) for d in deps] == [("string-width", "^4.2.0")]


def test_parse_package_json_handles_bad_input(tmp_path: Path):
    assert parse_package_json(write(tmp_path, "not json"), tmp_path) == []
    assert parse_package_json(write(tmp_path, "[1, 2]"), tmp_path) == []
    assert parse_package_json(tmp_path / "missing.json", tmp_path) == []


def test_parse_package_json_source_file_is_relative_to_root(tmp_path: Path):
    (tmp_path / "web" / "theme").mkdir(parents=True)
    path = tmp_path / "web" / "theme" / "package.json"
    path.write_text(json.dumps({"dependencies": {"vue": "^3.4"}}))
    assert parse_package_json(path, tmp_path)[0].source_file == "web/theme/package.json"
