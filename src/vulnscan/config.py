"""Settings loaded from environment variables and .env files."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, fields
from pathlib import Path
from typing import Any

from dotenv import dotenv_values

ENV_PREFIX = "VULNSCAN_"

# setting name -> (env var suffix, default)
_ENV_MAP: dict[str, tuple[str, Any]] = {
    "project_path": ("PROJECT_PATH", "."),
    "feed_dir": ("FEED_DIR", "feeds"),
    "rss_filename": ("RSS_FILE", "vulns.rss.xml"),
    "atom_filename": ("ATOM_FILE", "vulns.atom.xml"),
    "state_filename": ("STATE_FILE", "vulnscan-state.json"),
    "feed_title": ("FEED_TITLE", "Vulnerable dependencies"),
    "feed_link": ("FEED_LINK", ""),
    "feed_description": (
        "FEED_DESCRIPTION",
        "Direct dependencies with known security advisories",
    ),
    "osv_base_url": ("OSV_URL", "https://api.osv.dev"),
    "request_timeout": ("TIMEOUT", "30"),
    "include_dev": ("INCLUDE_DEV", "true"),
    "query_unknown_versions": ("QUERY_UNKNOWN_VERSIONS", "false"),
    "wordfence_api_key": ("WORDFENCE_API_KEY", ""),
    "wordfence_url": ("WORDFENCE_URL", "https://www.wordfence.com/api/intelligence/v3"),
    "wordfence_ttl_hours": ("WORDFENCE_TTL_HOURS", "24"),
    "wordfence_min_interval_minutes": ("WORDFENCE_MIN_INTERVAL_MINUTES", "30"),
    "cache_dir": ("CACHE_DIR", None),  # default depends on XDG_CACHE_HOME, see load_settings
    "ignore_dirs": ("IGNORE_DIRS", ""),
    "markdown_filename": ("MARKDOWN_FILE", "vulns.md"),
    "text_filename": ("TEXT_FILE", "vulns.txt"),
    "ntfy_server": ("NTFY_SERVER", "https://ntfy.sh"),
    "ntfy_topic": ("NTFY_TOPIC", ""),
    "ntfy_token": ("NTFY_TOKEN", ""),
    "ntfy_user": ("NTFY_USER", ""),
    "ntfy_password": ("NTFY_PASSWORD", ""),
    "ntfy_state_filename": ("NTFY_STATE_FILE", "ntfy-state.json"),
    "msteams_webhook_url": ("MSTEAMS_WEBHOOK_URL", ""),
    "msteams_state_filename": ("MSTEAMS_STATE_FILE", "msteams-state.json"),
    "interval_minutes": ("INTERVAL_MINUTES", "60"),
}

_TRUE = {"1", "true", "yes", "on", "y"}
_FALSE = {"0", "false", "no", "off", "n", ""}


def _to_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in _TRUE:
        return True
    if text in _FALSE:
        return False
    raise ValueError(f"Cannot interpret {value!r} as a boolean")


@dataclass(frozen=True)
class Settings:
    """Runtime configuration for one run of vulnscan.

    Built by :func:`load_settings` from ``VULNSCAN_*`` environment variables, a
    ``.env`` file and command line overrides. Paths are absolute; ``feed_dir`` is the
    base for every generated file.
    """

    project_path: Path
    feed_dir: Path
    rss_filename: str
    atom_filename: str
    state_filename: str
    feed_title: str
    feed_link: str
    feed_description: str
    osv_base_url: str
    request_timeout: float
    include_dev: bool
    query_unknown_versions: bool
    wordfence_api_key: str = ""
    wordfence_url: str = "https://www.wordfence.com/api/intelligence/v3"
    wordfence_ttl_hours: float = 24.0
    wordfence_min_interval_minutes: float = 30.0
    cache_dir: Path = Path.home() / ".cache" / "vulnscan"
    ignore_dirs: tuple[str, ...] = ()
    markdown_filename: str = "vulns.md"
    text_filename: str = "vulns.txt"
    ntfy_server: str = "https://ntfy.sh"
    ntfy_topic: str = ""
    ntfy_token: str = ""
    ntfy_user: str = ""
    ntfy_password: str = ""
    ntfy_state_filename: str = "ntfy-state.json"
    msteams_webhook_url: str = ""
    msteams_state_filename: str = "msteams-state.json"
    interval_minutes: float = 60.0

    @property
    def ntfy_state_path(self) -> Path:
        """Path of the file recording which ntfy notifications were already sent."""
        return self.feed_dir / self.ntfy_state_filename

    @property
    def msteams_state_path(self) -> Path:
        """Path of the file recording which Microsoft Teams notifications were already sent."""
        return self.feed_dir / self.msteams_state_filename

    @property
    def markdown_path(self) -> Path:
        """Default path of the Markdown report."""
        return self.feed_dir / self.markdown_filename

    @property
    def text_path(self) -> Path:
        """Default path of the plain-text report."""
        return self.feed_dir / self.text_filename

    @property
    def rss_path(self) -> Path:
        """Path of the RSS feed."""
        return self.feed_dir / self.rss_filename

    @property
    def atom_path(self) -> Path:
        """Path of the Atom feed."""
        return self.feed_dir / self.atom_filename

    @property
    def state_path(self) -> Path:
        """Path of the file recording when each feed entry was first seen."""
        return self.feed_dir / self.state_filename


def _to_tuple(value: Any) -> tuple[str, ...]:
    if isinstance(value, (tuple, list)):
        return tuple(str(v) for v in value)
    return tuple(part.strip() for part in str(value).split(",") if part.strip())


_COERCERS = {
    "project_path": lambda v: Path(v).expanduser().resolve(),
    "feed_dir": lambda v: Path(v).expanduser().resolve(),
    "osv_base_url": lambda v: str(v).rstrip("/"),
    "request_timeout": float,
    "include_dev": _to_bool,
    "query_unknown_versions": _to_bool,
    "wordfence_url": lambda v: str(v).rstrip("/"),
    "wordfence_ttl_hours": float,
    "wordfence_min_interval_minutes": float,
    "cache_dir": lambda v: Path(v).expanduser().absolute(),
    "ignore_dirs": _to_tuple,
    "ntfy_server": lambda v: str(v).rstrip("/"),
    "interval_minutes": float,
}


def _default_cache_dir(env: Mapping[str, str]) -> Path:
    xdg = env.get("XDG_CACHE_HOME")
    base = Path(xdg).expanduser() if xdg else Path.home() / ".cache"
    return base / "vulnscan"


def load_settings(
    env: Mapping[str, str] | None = None,
    dotenv_path: Path | None = None,
    overrides: Mapping[str, Any] | None = None,
) -> Settings:
    """Build Settings. Precedence: overrides > env > .env file > defaults."""
    if env is None:
        env = os.environ
    if dotenv_path is None:
        dotenv_path = Path.cwd() / ".env"
    file_values: dict[str, str | None] = {}
    if Path(dotenv_path).is_file():
        file_values = dotenv_values(dotenv_path)
    overrides = overrides or {}

    values: dict[str, Any] = {}
    for f in fields(Settings):
        suffix, default = _ENV_MAP[f.name]
        key = ENV_PREFIX + suffix
        raw: Any = default
        if f.name == "cache_dir":
            raw = _default_cache_dir(env)
        if file_values.get(key) is not None:
            raw = file_values[key]
        if env.get(key) is not None:
            raw = env[key]
        if overrides.get(f.name) is not None:
            raw = overrides[f.name]
        coerce = _COERCERS.get(f.name, str)
        values[f.name] = coerce(raw)
    return Settings(**values)
