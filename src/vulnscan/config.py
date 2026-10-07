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

    @property
    def rss_path(self) -> Path:
        return self.feed_dir / self.rss_filename

    @property
    def atom_path(self) -> Path:
        return self.feed_dir / self.atom_filename

    @property
    def state_path(self) -> Path:
        return self.feed_dir / self.state_filename


_COERCERS = {
    "project_path": lambda v: Path(v).expanduser().resolve(),
    "feed_dir": lambda v: Path(v).expanduser().resolve(),
    "osv_base_url": lambda v: str(v).rstrip("/"),
    "request_timeout": float,
    "include_dev": _to_bool,
    "query_unknown_versions": _to_bool,
}


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
        if file_values.get(key) is not None:
            raw = file_values[key]
        if env.get(key) is not None:
            raw = env[key]
        if overrides.get(f.name) is not None:
            raw = overrides[f.name]
        coerce = _COERCERS.get(f.name, str)
        values[f.name] = coerce(raw)
    return Settings(**values)
