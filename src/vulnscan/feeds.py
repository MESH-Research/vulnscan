"""RSS and Atom feed generation."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from vulnscan.config import Settings
from vulnscan.models import Dependency, ScanResult, Vulnerability


@dataclass
class FeedEntry:
    guid: str
    title: str
    link: str
    summary: str
    content_html: str
    published: datetime
    updated: datetime
    categories: list[str] = field(default_factory=list)


def entry_guid(project_name: str, dep: Dependency, vuln: Vulnerability) -> str:
    raise NotImplementedError


def load_state(path: Path) -> dict[str, str]:
    raise NotImplementedError


def save_state(path: Path, state: dict[str, str]) -> None:
    raise NotImplementedError


def build_entries(result: ScanResult, state: dict[str, str], now: datetime) -> list[FeedEntry]:
    raise NotImplementedError


def render_rss(entries: list[FeedEntry], settings: Settings, now: datetime) -> bytes:
    raise NotImplementedError


def render_atom(entries: list[FeedEntry], settings: Settings, now: datetime) -> bytes:
    raise NotImplementedError


def write_feeds(
    result: ScanResult, settings: Settings, now: datetime | None = None
) -> tuple[Path, Path]:
    raise NotImplementedError
