from pathlib import Path

import pytest

from vulnscan.config import Settings, load_settings


def test_defaults_when_nothing_configured(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    settings = load_settings(env={}, dotenv_path=tmp_path / "missing.env")
    assert settings.project_path == tmp_path.resolve()
    assert settings.feed_dir == (tmp_path / "feeds").resolve()
    assert settings.rss_filename == "vulns.rss.xml"
    assert settings.atom_filename == "vulns.atom.xml"
    assert settings.state_filename == "vulnscan-state.json"
    assert settings.osv_base_url == "https://api.osv.dev"
    assert settings.request_timeout == 30.0
    assert settings.include_dev is True
    assert settings.query_unknown_versions is False
    assert settings.feed_title
    assert settings.feed_description


def test_values_read_from_environment(tmp_path: Path):
    env = {
        "VULNSCAN_PROJECT_PATH": str(tmp_path / "proj"),
        "VULNSCAN_FEED_DIR": str(tmp_path / "out"),
        "VULNSCAN_RSS_FILE": "a.rss",
        "VULNSCAN_ATOM_FILE": "a.atom",
        "VULNSCAN_STATE_FILE": "s.json",
        "VULNSCAN_FEED_TITLE": "My feed",
        "VULNSCAN_FEED_LINK": "https://example.com/feeds/",
        "VULNSCAN_FEED_DESCRIPTION": "desc",
        "VULNSCAN_OSV_URL": "http://localhost:9000/",
        "VULNSCAN_TIMEOUT": "5",
        "VULNSCAN_INCLUDE_DEV": "false",
        "VULNSCAN_QUERY_UNKNOWN_VERSIONS": "yes",
    }
    settings = load_settings(env=env, dotenv_path=tmp_path / "missing.env")
    assert settings.project_path == (tmp_path / "proj").resolve()
    assert settings.feed_dir == (tmp_path / "out").resolve()
    assert settings.rss_filename == "a.rss"
    assert settings.atom_filename == "a.atom"
    assert settings.state_filename == "s.json"
    assert settings.feed_title == "My feed"
    assert settings.feed_link == "https://example.com/feeds/"
    assert settings.feed_description == "desc"
    assert settings.osv_base_url == "http://localhost:9000"
    assert settings.request_timeout == 5.0
    assert settings.include_dev is False
    assert settings.query_unknown_versions is True


def test_dotenv_file_is_read(tmp_path: Path):
    dotenv = tmp_path / ".env"
    dotenv.write_text("VULNSCAN_FEED_TITLE=From dotenv\nVULNSCAN_TIMEOUT=12\n")
    settings = load_settings(env={}, dotenv_path=dotenv)
    assert settings.feed_title == "From dotenv"
    assert settings.request_timeout == 12.0


def test_environment_wins_over_dotenv(tmp_path: Path):
    dotenv = tmp_path / ".env"
    dotenv.write_text("VULNSCAN_FEED_TITLE=From dotenv\n")
    settings = load_settings(env={"VULNSCAN_FEED_TITLE": "From env"}, dotenv_path=dotenv)
    assert settings.feed_title == "From env"


def test_overrides_win_over_everything(tmp_path: Path):
    dotenv = tmp_path / ".env"
    dotenv.write_text("VULNSCAN_PROJECT_PATH=/from/dotenv\n")
    settings = load_settings(
        env={"VULNSCAN_PROJECT_PATH": "/from/env"},
        dotenv_path=dotenv,
        overrides={"project_path": tmp_path / "cli"},
    )
    assert settings.project_path == (tmp_path / "cli").resolve()


def test_none_overrides_are_ignored(tmp_path: Path):
    settings = load_settings(
        env={"VULNSCAN_FEED_TITLE": "kept"},
        dotenv_path=tmp_path / "missing.env",
        overrides={"feed_title": None},
    )
    assert settings.feed_title == "kept"


@pytest.mark.parametrize(
    "raw,expected", [("1", True), ("TRUE", True), ("on", True), ("0", False), ("no", False)]
)
def test_boolean_parsing(tmp_path: Path, raw, expected):
    settings = load_settings(
        env={"VULNSCAN_INCLUDE_DEV": raw}, dotenv_path=tmp_path / "missing.env"
    )
    assert settings.include_dev is expected


def test_invalid_timeout_raises(tmp_path: Path):
    with pytest.raises(ValueError):
        load_settings(env={"VULNSCAN_TIMEOUT": "soon"}, dotenv_path=tmp_path / "missing.env")


def test_feed_paths_derive_from_feed_dir(tmp_path: Path):
    settings = Settings(
        project_path=tmp_path,
        feed_dir=tmp_path / "f",
        rss_filename="r.xml",
        atom_filename="a.xml",
        state_filename="s.json",
        feed_title="t",
        feed_link="",
        feed_description="d",
        osv_base_url="https://api.osv.dev",
        request_timeout=1.0,
        include_dev=True,
        query_unknown_versions=False,
    )
    assert settings.rss_path == tmp_path / "f" / "r.xml"
    assert settings.atom_path == tmp_path / "f" / "a.xml"
    assert settings.state_path == tmp_path / "f" / "s.json"


def test_new_settings_defaults(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    settings = load_settings(env={}, dotenv_path=tmp_path / "missing.env")
    assert settings.wordfence_api_key == ""
    assert settings.wordfence_url == "https://www.wordfence.com/api/intelligence/v3"
    assert settings.wordfence_ttl_hours == 24.0
    assert settings.cache_dir == (Path.home() / ".cache" / "vulnscan")
    assert settings.ignore_dirs == ()
    assert settings.markdown_filename == "vulns.md"
    assert settings.text_filename == "vulns.txt"


def test_new_settings_from_env(tmp_path: Path):
    env = {
        "VULNSCAN_WORDFENCE_API_KEY": "secret",
        "VULNSCAN_WORDFENCE_URL": "http://localhost:1/v3/",
        "VULNSCAN_WORDFENCE_TTL_HOURS": "6",
        "VULNSCAN_CACHE_DIR": str(tmp_path / "cache"),
        "VULNSCAN_IGNORE_DIRS": "legacy, old-site ,",
        "VULNSCAN_MARKDOWN_FILE": "report.md",
        "VULNSCAN_TEXT_FILE": "report.txt",
    }
    settings = load_settings(env=env, dotenv_path=tmp_path / "missing.env")
    assert settings.wordfence_api_key == "secret"
    assert settings.wordfence_url == "http://localhost:1/v3"
    assert settings.wordfence_ttl_hours == 6.0
    assert settings.cache_dir == (tmp_path / "cache").resolve()
    assert settings.ignore_dirs == ("legacy", "old-site")
    assert settings.markdown_filename == "report.md"
    assert settings.text_filename == "report.txt"


def test_cache_dir_honours_xdg(tmp_path: Path, monkeypatch):
    env = {"XDG_CACHE_HOME": str(tmp_path / "xdg")}
    settings = load_settings(env=env, dotenv_path=tmp_path / "missing.env")
    assert settings.cache_dir == (tmp_path / "xdg" / "vulnscan").resolve()


def test_report_paths_derive_from_feed_dir(tmp_path: Path):
    settings = load_settings(
        env={"VULNSCAN_FEED_DIR": str(tmp_path / "f")}, dotenv_path=tmp_path / "missing.env"
    )
    assert settings.markdown_path == (tmp_path / "f" / "vulns.md").resolve()
    assert settings.text_path == (tmp_path / "f" / "vulns.txt").resolve()
