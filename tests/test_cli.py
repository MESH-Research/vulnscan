import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from vulnscan import cli
from vulnscan.models import PYPI, Dependency, Finding, ScanResult, Vulnerability
from vulnscan.osv import OSVError


def fake_result(path: Path) -> ScanResult:
    d = Dependency("requests", PYPI, "==2.30.0", "2.30.0", "pinned", "requirements.txt")
    v = Vulnerability(
        "GHSA-1", "s", "d", aliases=["CVE-2024-1"], severity="HIGH", fixed_versions=["2.31.0"]
    )
    return ScanResult(path, [d], [Finding(d, [v])], ["a warning"], datetime.now(UTC))


def test_parser_defaults():
    args = cli.build_parser().parse_args([])
    assert args.update_feeds is False
    assert args.path is None
    assert args.feed_dir is None
    assert args.env_file is None


def test_parser_flags(tmp_path: Path):
    args = cli.build_parser().parse_args(
        ["--update-feeds", "--path", str(tmp_path), "--feed-dir", "out", "--env-file", ".env.prod"]
    )
    assert args.update_feeds is True
    assert args.path == str(tmp_path)
    assert args.feed_dir == "out"
    assert args.env_file == ".env.prod"


def test_update_feeds_writes_files_and_exits_zero(tmp_path: Path, monkeypatch, capsys):
    seen = {}

    def fake_scan(settings):
        seen["settings"] = settings
        return fake_result(settings.project_path)

    monkeypatch.setattr(cli, "scan", fake_scan)
    monkeypatch.setenv("VULNSCAN_FEED_TITLE", "Env title")
    code = cli.main(
        ["--update-feeds", "--path", str(tmp_path), "--feed-dir", str(tmp_path / "out")]
    )
    assert code == 0
    assert seen["settings"].project_path == tmp_path.resolve()
    assert seen["settings"].feed_title == "Env title"
    assert (tmp_path / "out" / "vulns.rss.xml").is_file()
    assert (tmp_path / "out" / "vulns.atom.xml").is_file()
    captured = capsys.readouterr()
    assert "requests" in captured.out
    assert "a warning" in captured.err


def test_update_feeds_reads_env_file(tmp_path: Path, monkeypatch):
    env_file = tmp_path / "custom.env"
    env_file.write_text(f"VULNSCAN_FEED_DIR={tmp_path / 'from-env'}\nVULNSCAN_RSS_FILE=r.xml\n")
    monkeypatch.setattr(cli, "scan", lambda settings: fake_result(settings.project_path))
    code = cli.main(["--update-feeds", "--path", str(tmp_path), "--env-file", str(env_file)])
    assert code == 0
    assert (tmp_path / "from-env" / "r.xml").is_file()


def test_update_feeds_fails_without_writing_when_scan_errors(tmp_path: Path, monkeypatch, capsys):
    def failing(settings):
        raise OSVError("OSV unavailable")

    monkeypatch.setattr(cli, "scan", failing)
    code = cli.main(
        ["--update-feeds", "--path", str(tmp_path), "--feed-dir", str(tmp_path / "out")]
    )
    assert code == 1
    assert not (tmp_path / "out").exists()
    assert "OSV unavailable" in capsys.readouterr().err


def test_update_feeds_fails_for_missing_project(tmp_path: Path, monkeypatch, capsys):
    monkeypatch.setattr(cli, "scan", lambda settings: fake_result(settings.project_path))
    code = cli.main(["--update-feeds", "--path", str(tmp_path / "missing")])
    assert code == 1
    assert "missing" in capsys.readouterr().err


def test_default_mode_launches_tui(tmp_path: Path, monkeypatch):
    launched = {}

    def fake_run_tui(settings):
        launched["settings"] = settings

    monkeypatch.setattr(cli, "run_tui", fake_run_tui)
    code = cli.main(["--path", str(tmp_path)])
    assert code == 0
    assert launched["settings"].project_path == tmp_path.resolve()


def test_update_feeds_state_file_written(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(cli, "scan", lambda settings: fake_result(settings.project_path))
    cli.main(["--update-feeds", "--path", str(tmp_path), "--feed-dir", str(tmp_path / "out")])
    state = json.loads((tmp_path / "out" / "vulnscan-state.json").read_text())
    assert len(state) == 1


@pytest.mark.parametrize("flag", ["-h", "--help"])
def test_help_exits_zero(flag, capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main([flag])
    assert exc.value.code == 0
    assert "update-feeds" in capsys.readouterr().out
