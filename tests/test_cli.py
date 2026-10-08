import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from vulnscan import cli
from vulnscan.models import PYPI, Declaration, Dependency, Finding, ScanResult, Vulnerability
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


def test_parser_export_flags(tmp_path: Path):
    args = cli.build_parser().parse_args(["--markdown", "--text", "out.txt"])
    assert args.markdown == "" and args.text == "out.txt"
    args = cli.build_parser().parse_args([])
    assert args.markdown is None and args.text is None


def test_markdown_export_writes_default_path_without_feeds(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(cli, "scan", lambda settings: fake_result(settings.project_path))
    code = cli.main(["--markdown", "--path", str(tmp_path), "--feed-dir", str(tmp_path / "out")])
    assert code == 0
    assert (tmp_path / "out" / "vulns.md").is_file()
    assert not (tmp_path / "out" / "vulns.rss.xml").exists()
    assert not (tmp_path / "out" / "vulns.txt").exists()


def test_text_export_to_explicit_file_and_stdout(tmp_path: Path, monkeypatch, capsys):
    monkeypatch.setattr(cli, "scan", lambda settings: fake_result(settings.project_path))
    code = cli.main(["--text", str(tmp_path / "r.txt"), "--path", str(tmp_path)])
    assert code == 0
    assert "GHSA-1" in (tmp_path / "r.txt").read_text()
    code = cli.main(["--text", "-", "--path", str(tmp_path)])
    assert code == 0
    assert "GHSA-1" in capsys.readouterr().out


def test_exports_combine_with_update_feeds(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(cli, "scan", lambda settings: fake_result(settings.project_path))
    code = cli.main(
        [
            "--update-feeds",
            "--markdown",
            "--text",
            "--path",
            str(tmp_path),
            "--feed-dir",
            str(tmp_path / "out"),
        ]
    )
    assert code == 0
    for name in ["vulns.rss.xml", "vulns.atom.xml", "vulns.md", "vulns.txt"]:
        assert (tmp_path / "out" / name).is_file(), name


def test_wordfence_error_fails_cleanly(tmp_path: Path, monkeypatch, capsys):
    from vulnscan.wordfence import WordfenceError

    def failing(settings):
        raise WordfenceError("Wordfence rejected the API key")

    monkeypatch.setattr(cli, "scan", failing)
    code = cli.main(
        ["--update-feeds", "--path", str(tmp_path), "--feed-dir", str(tmp_path / "out")]
    )
    assert code == 1
    assert "Wordfence rejected the API key" in capsys.readouterr().err


def test_remediate_flag_updates_manifest(tmp_path: Path, monkeypatch, capsys):
    from vulnscan.models import VersionRange

    (tmp_path / "requirements.txt").write_text("requests==2.30.0\nflask\n")

    def fake_scan(settings):
        result = fake_result(settings.project_path)
        result.findings[0].vulnerabilities[0].affected_ranges = [
            VersionRange(lower="0", upper="2.31.0")
        ]
        return result

    monkeypatch.setattr(cli, "scan", fake_scan)
    monkeypatch.setattr(cli, "fetch_versions", lambda settings, dep: ["2.30.0", "2.31.0", "2.32.4"])
    code = cli.main(["--remediate", "requests", "--path", str(tmp_path)])
    assert code == 0
    assert (tmp_path / "requirements.txt").read_text() == "requests==2.31.0\nflask\n"
    assert "pip install" in capsys.readouterr().out


def test_remediate_flag_latest_strategy(tmp_path: Path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("requests==2.30.0\n")
    monkeypatch.setattr(cli, "scan", lambda settings: fake_result(settings.project_path))
    monkeypatch.setattr(cli, "fetch_versions", lambda settings, dep: ["2.30.0", "2.31.0", "2.32.4"])
    code = cli.main(["--remediate", "requests", "--strategy", "latest", "--path", str(tmp_path)])
    assert code == 0
    assert (tmp_path / "requirements.txt").read_text() == "requests==2.32.4\n"


def test_remediate_flag_unknown_package_fails(tmp_path: Path, monkeypatch, capsys):
    monkeypatch.setattr(cli, "scan", lambda settings: fake_result(settings.project_path))
    code = cli.main(["--remediate", "nothing-here", "--path", str(tmp_path)])
    assert code == 1
    assert "nothing-here" in capsys.readouterr().err


def test_remediate_flag_without_safe_version_fails(tmp_path: Path, monkeypatch, capsys):
    from vulnscan.models import VersionRange

    (tmp_path / "requirements.txt").write_text("requests==2.30.0\n")

    def fake_scan(settings):
        result = fake_result(settings.project_path)
        result.findings[0].vulnerabilities[0].affected_ranges = [
            VersionRange(lower="0", upper=None)
        ]
        return result

    monkeypatch.setattr(cli, "scan", fake_scan)
    monkeypatch.setattr(cli, "fetch_versions", lambda settings, dep: ["2.30.0", "2.31.0"])
    code = cli.main(["--remediate", "requests", "--path", str(tmp_path)])
    assert code == 1
    assert "no" in capsys.readouterr().err.lower()
    assert (tmp_path / "requirements.txt").read_text() == "requests==2.30.0\n"


def multi_file_result(path: Path) -> ScanResult:
    d = Dependency(
        "requests",
        PYPI,
        "==2.30.0",
        "2.30.0",
        "pinned",
        "requirements.txt",
        declarations=(
            Declaration("requirements.txt", "==2.30.0"),
            Declaration("requirements-prod.txt", ">=2.30"),
        ),
    )
    v = Vulnerability("GHSA-1", "s", "d", severity="HIGH", fixed_versions=["2.31.0"])
    return ScanResult(path, [d], [Finding(d, [v])], [], datetime.now(UTC))


def test_remediate_flag_updates_every_declaring_file(tmp_path: Path, monkeypatch, capsys):
    (tmp_path / "requirements.txt").write_text("requests==2.30.0\n")
    (tmp_path / "requirements-prod.txt").write_text("requests>=2.30\n")
    monkeypatch.setattr(cli, "scan", lambda settings: multi_file_result(settings.project_path))
    monkeypatch.setattr(cli, "fetch_versions", lambda settings, dep: ["2.30.0", "2.32.4"])
    code = cli.main(["--remediate", "requests", "--strategy", "latest", "--path", str(tmp_path)])
    assert code == 0
    assert (tmp_path / "requirements.txt").read_text() == "requests==2.32.4\n"
    assert (tmp_path / "requirements-prod.txt").read_text() == "requests>=2.32.4\n"
    out = capsys.readouterr().out
    assert "requirements.txt" in out
    assert "requirements-prod.txt" in out


def test_summary_lists_every_declaring_file(tmp_path: Path, monkeypatch, capsys):
    monkeypatch.setattr(cli, "scan", lambda settings: multi_file_result(settings.project_path))
    code = cli.main(["--update-feeds", "--path", str(tmp_path), "--feed-dir", str(tmp_path / "o")])
    assert code == 0
    out = capsys.readouterr().out
    assert "requirements.txt" in out
    assert "requirements-prod.txt" in out


def test_ignore_flag_is_repeatable_and_overrides_environment(tmp_path: Path, monkeypatch):
    seen = {}

    def fake_scan(settings):
        seen["settings"] = settings
        return fake_result(settings.project_path)

    monkeypatch.setattr(cli, "scan", fake_scan)
    monkeypatch.setenv("VULNSCAN_IGNORE_DIRS", "from-env")
    code = cli.main(
        [
            "--text",
            "-",
            "--path",
            str(tmp_path),
            "--ignore",
            "legacy",
            "--ignore",
            "web/app/plugins/graveyard,*-old",
        ]
    )
    assert code == 0
    assert seen["settings"].ignore_dirs == ("legacy", "web/app/plugins/graveyard", "*-old")


def test_ignore_dirs_come_from_environment_without_the_flag(tmp_path: Path, monkeypatch):
    seen = {}

    def fake_scan(settings):
        seen["settings"] = settings
        return fake_result(settings.project_path)

    monkeypatch.setattr(cli, "scan", fake_scan)
    monkeypatch.setenv("VULNSCAN_IGNORE_DIRS", "from-env")
    assert cli.main(["--text", "-", "--path", str(tmp_path)]) == 0
    assert seen["settings"].ignore_dirs == ("from-env",)


# --- ntfy mode --------------------------------------------------------------------------------


class RecordingNtfy:
    def __init__(self):
        self.published = []

    def publish(self, message):
        self.published.append(message)


def test_parser_ntfy_flags():
    args = cli.build_parser().parse_args(["--ntfy", "--once", "--resend", "--interval", "5"])
    assert args.ntfy is True
    assert args.once is True
    assert args.resend is True
    assert args.interval == 5.0
    defaults = cli.build_parser().parse_args([])
    assert defaults.ntfy is False and defaults.once is False and defaults.resend is False
    assert defaults.interval is None


def test_ntfy_mode_requires_a_topic(tmp_path: Path, monkeypatch, capsys):
    monkeypatch.delenv("VULNSCAN_NTFY_TOPIC", raising=False)
    code = cli.main(["--ntfy", "--once", "--path", str(tmp_path), "--env-file", "/nonexistent"])
    assert code == 2
    assert "VULNSCAN_NTFY_TOPIC" in capsys.readouterr().err


def test_ntfy_once_scans_and_publishes(tmp_path: Path, monkeypatch, capsys):
    recorder = RecordingNtfy()
    monkeypatch.setattr(cli, "scan", lambda settings: multi_file_result(settings.project_path))
    monkeypatch.setattr(cli, "build_ntfy_client", lambda settings: recorder)
    monkeypatch.setenv("VULNSCAN_NTFY_TOPIC", "alerts")
    feed_dir = tmp_path / "feeds"
    code = cli.main(["--ntfy", "--once", "--path", str(tmp_path), "--feed-dir", str(feed_dir)])
    assert code == 0
    assert len(recorder.published) == 1
    assert "requests" in recorder.published[0].title
    assert (feed_dir / "ntfy-state.json").is_file()
    # A second run finds nothing new.
    assert cli.main(["--ntfy", "--once", "--path", str(tmp_path), "--feed-dir", str(feed_dir)]) == 0
    assert len(recorder.published) == 1
    # Unless a resend is requested.
    code = cli.main(
        ["--ntfy", "--once", "--resend", "--path", str(tmp_path), "--feed-dir", str(feed_dir)]
    )
    assert code == 0
    assert len(recorder.published) == 2


def test_ntfy_interval_flag_overrides_setting(tmp_path: Path, monkeypatch):
    seen = {}

    def fake_run_watch(settings, control, client, scan_fn=None, resend_first=False, once=False):
        seen["settings"] = settings
        return 0

    monkeypatch.setattr(cli, "run_watch", fake_run_watch)
    monkeypatch.setattr(cli, "build_ntfy_client", lambda settings: RecordingNtfy())
    monkeypatch.setenv("VULNSCAN_NTFY_TOPIC", "alerts")
    monkeypatch.setenv("VULNSCAN_NTFY_INTERVAL_MINUTES", "60")
    assert cli.main(["--ntfy", "--interval", "7", "--path", str(tmp_path)]) == 0
    assert seen["settings"].ntfy_interval_minutes == 7.0


def test_build_ntfy_client_uses_settings(tmp_path: Path, monkeypatch):
    from vulnscan.ntfy import NtfyClient

    monkeypatch.setenv("VULNSCAN_NTFY_TOPIC", "alerts")
    monkeypatch.setenv("VULNSCAN_NTFY_TOKEN", "tk_x")
    settings = cli.load_settings(dotenv_path=tmp_path / "none.env")
    assert isinstance(cli.build_ntfy_client(settings), NtfyClient)
