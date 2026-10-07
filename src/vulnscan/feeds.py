"""RSS 2.0 and Atom 1.0 feed generation."""

from __future__ import annotations

import json
import os
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.utils import format_datetime
from html import escape
from pathlib import Path
from urllib.parse import quote, urljoin

from vulnscan.config import Settings
from vulnscan.models import Dependency, ScanResult, Vulnerability, normalize_name
from vulnscan.wordfence import SOURCE as WORDFENCE_SOURCE
from vulnscan.wordfence import wordfence_attribution

ATOM_NS = "http://www.w3.org/2005/Atom"
GENERATOR = "vulnscan"


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
    """Stable identifier for one (project, dependency, advisory) triple."""
    name = normalize_name(dep.name, dep.ecosystem)
    return (
        f"urn:vulnscan:{quote(project_name, safe='')}:{dep.ecosystem.lower()}:"
        f"{quote(name, safe='')}:{quote(vuln.id, safe='')}"
    )


def load_state(path: Path) -> dict[str, str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {str(k): str(v) for k, v in data.items() if isinstance(v, str)}


def _write_atomic(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, path)


def save_state(path: Path, state: dict[str, str]) -> None:
    _write_atomic(path, json.dumps(state, indent=2, sort_keys=True).encode("utf-8"))


def _as_utc(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _entry_html(dep: Dependency, vuln: Vulnerability) -> str:
    rows = [
        ("Package", f"{dep.name} ({dep.ecosystem})"),
        ("Version", f"{dep.version or 'unknown'} (from {dep.version_source})"),
        ("Declared in", f"{dep.source_file} as {dep.constraint or 'any version'}"),
        ("Severity", vuln.severity + (f" ({vuln.cvss})" if vuln.cvss else "")),
        ("Fixed in", ", ".join(vuln.fixed_versions) or "no fix listed"),
        ("CVE", ", ".join(vuln.cve_ids) or "none assigned"),
        ("Aliases", ", ".join(vuln.aliases) or "none"),
    ]
    parts = ["<p><strong>" + escape(vuln.summary or vuln.id) + "</strong></p>", "<ul>"]
    parts += [f"<li><b>{escape(k)}:</b> {escape(v)}</li>" for k, v in rows]
    parts.append("</ul>")
    if vuln.details:
        parts.append("<pre>" + escape(vuln.details) + "</pre>")
    links = [vuln.url, *vuln.references]
    parts.append("<p>References:</p><ul>")
    parts += [f'<li><a href="{escape(u, quote=True)}">{escape(u)}</a></li>' for u in links]
    parts.append("</ul>")
    if vuln.source == WORDFENCE_SOURCE:
        parts.append("<p><small>" + escape(wordfence_attribution()) + "</small></p>")
    return "\n".join(parts)


def build_entries(result: ScanResult, state: dict[str, str], now: datetime) -> list[FeedEntry]:
    """Create one entry per (dependency, advisory). Records first-seen times in `state`."""
    project = result.project_path.name or "project"
    entries: list[FeedEntry] = []
    for finding in result.findings:
        dep = finding.dependency
        for vuln in finding.vulnerabilities:
            guid = entry_guid(project, dep, vuln)
            if guid not in state:
                state[guid] = now.isoformat()
            try:
                published = _as_utc(datetime.fromisoformat(state[guid]))
            except ValueError:
                published = now
                state[guid] = now.isoformat()
            version = dep.version or "unknown version"
            title = f"{dep.name} {version}: {vuln.id}"
            if vuln.summary:
                title += f" - {vuln.summary}"
            entries.append(
                FeedEntry(
                    guid=guid,
                    title=title,
                    link=vuln.url,
                    summary=vuln.summary or vuln.id,
                    content_html=_entry_html(dep, vuln),
                    published=published,
                    updated=_as_utc(vuln.modified) if vuln.modified else now,
                    categories=[vuln.severity, dep.ecosystem, dep.name],
                )
            )
    # Newest first; ties keep scan order (most severe dependency first).
    entries.sort(key=lambda e: e.published, reverse=True)
    return entries


def _channel_link(settings: Settings) -> str:
    return settings.feed_link or "https://osv.dev/"


def render_rss(entries: list[FeedEntry], settings: Settings, now: datetime) -> bytes:
    rss = ET.Element("rss", version="2.0", attrib={"xmlns:atom": ATOM_NS})
    channel = ET.SubElement(rss, "channel")
    ET.SubElement(channel, "title").text = settings.feed_title
    ET.SubElement(channel, "link").text = _channel_link(settings)
    ET.SubElement(channel, "description").text = settings.feed_description
    ET.SubElement(channel, "lastBuildDate").text = format_datetime(now)
    ET.SubElement(channel, "generator").text = GENERATOR
    if settings.feed_link:
        ET.SubElement(
            channel,
            "atom:link",
            href=urljoin(settings.feed_link, settings.rss_filename),
            rel="self",
            type="application/rss+xml",
        )
    for entry in entries:
        item = ET.SubElement(channel, "item")
        ET.SubElement(item, "title").text = entry.title
        ET.SubElement(item, "link").text = entry.link
        ET.SubElement(item, "guid", isPermaLink="false").text = entry.guid
        ET.SubElement(item, "pubDate").text = format_datetime(entry.published)
        ET.SubElement(item, "description").text = entry.content_html
        for category in entry.categories:
            ET.SubElement(item, "category").text = category
    return ET.tostring(rss, encoding="utf-8", xml_declaration=True)


def render_atom(entries: list[FeedEntry], settings: Settings, now: datetime) -> bytes:
    ET.register_namespace("", ATOM_NS)
    feed = ET.Element(f"{{{ATOM_NS}}}feed")

    def sub(parent: ET.Element, tag: str, text: str | None = None, **attrs: str) -> ET.Element:
        element = ET.SubElement(parent, f"{{{ATOM_NS}}}{tag}", attrs)
        if text is not None:
            element.text = text
        return element

    self_link = urljoin(settings.feed_link, settings.atom_filename) if settings.feed_link else ""
    project = quote(settings.project_path.name or "project", safe="")
    sub(feed, "title", settings.feed_title)
    sub(feed, "id", self_link or f"urn:vulnscan:{project}:feed")
    sub(feed, "updated", now.isoformat())
    sub(feed, "subtitle", settings.feed_description)
    sub(feed, "generator", GENERATOR)
    author = sub(feed, "author")
    sub(author, "name", GENERATOR)
    if settings.feed_link:
        sub(feed, "link", href=_channel_link(settings), rel="alternate")
        sub(feed, "link", href=self_link, rel="self", type="application/atom+xml")
    for entry in entries:
        node = sub(feed, "entry")
        sub(node, "id", entry.guid)
        sub(node, "title", entry.title)
        sub(node, "link", href=entry.link, rel="alternate")
        sub(node, "updated", entry.updated.isoformat())
        sub(node, "published", entry.published.isoformat())
        sub(node, "summary", entry.summary)
        sub(node, "content", entry.content_html, type="html")
        entry_author = sub(node, "author")
        sub(entry_author, "name", GENERATOR)
        for category in entry.categories:
            sub(node, "category", term=category)
    return ET.tostring(feed, encoding="utf-8", xml_declaration=True)


def write_feeds(
    result: ScanResult, settings: Settings, now: datetime | None = None
) -> tuple[Path, Path]:
    """Write RSS and Atom feeds plus the first-seen state file. Returns the feed paths."""
    now = now or datetime.now(UTC)
    state = load_state(settings.state_path)
    entries = build_entries(result, state, now)
    _write_atomic(settings.rss_path, render_rss(entries, settings, now))
    _write_atomic(settings.atom_path, render_atom(entries, settings, now))
    save_state(settings.state_path, state)
    return settings.rss_path, settings.atom_path
