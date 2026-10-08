import json
import xml.etree.ElementTree as ET
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from pathlib import Path

from vulnscan.config import Settings
from vulnscan.feeds import (
    FeedEntry,
    build_entries,
    entry_guid,
    load_state,
    render_atom,
    render_rss,
    save_state,
    write_feeds,
)
from vulnscan.models import PYPI, Declaration, Dependency, Finding, ScanResult, Vulnerability

NOW = datetime(2026, 10, 7, 12, 0, tzinfo=UTC)
ATOM_NS = "{http://www.w3.org/2005/Atom}"


def settings_for(tmp_path: Path, **kwargs) -> Settings:
    base = dict(
        project_path=tmp_path / "proj",
        feed_dir=tmp_path / "feeds",
        rss_filename="vulns.rss.xml",
        atom_filename="vulns.atom.xml",
        state_filename="state.json",
        feed_title="Demo feed",
        feed_link="https://example.com/feeds/",
        feed_description="Demo description",
        osv_base_url="https://osv.test",
        request_timeout=1.0,
        include_dev=True,
        query_unknown_versions=False,
    )
    base.update(kwargs)
    return Settings(**base)


def dep(name="requests", version="2.30.0"):
    return Dependency(name, PYPI, f"=={version}", version, "pinned", "requirements.txt")


def vuln(id_="GHSA-j8r2-6x86-q33q", **kwargs):
    base = dict(
        summary="Proxy-Authorization leak",
        details="Details <with> markup & stuff",
        aliases=["CVE-2023-32681"],
        severity="MEDIUM",
        published=datetime(2023, 5, 26, tzinfo=UTC),
        modified=datetime(2024, 2, 1, tzinfo=UTC),
        fixed_versions=["2.31.0"],
        references=["https://nvd.nist.gov/vuln/detail/CVE-2023-32681"],
    )
    base.update(kwargs)
    return Vulnerability(id_, **base)


def result_for(tmp_path: Path, findings=None) -> ScanResult:
    if findings is None:
        findings = [Finding(dep(), [vuln(), vuln("GHSA-other", aliases=[], fixed_versions=[])])]
    return ScanResult(tmp_path / "proj", [f.dependency for f in findings], findings, [], NOW)


def test_entry_guid_is_stable_and_distinct():
    a = entry_guid("proj", dep(), vuln())
    b = entry_guid("proj", dep(), vuln())
    c = entry_guid("proj", dep("flask"), vuln())
    d = entry_guid("proj", dep(), vuln("GHSA-other"))
    e = entry_guid("other", dep(), vuln())
    assert a == b
    assert len({a, c, d, e}) == 4
    assert "requests" in a and "GHSA-j8r2-6x86-q33q" in a


def test_entry_guid_ignores_version():
    assert entry_guid("p", dep(version="1.0"), vuln()) == entry_guid(
        "p", dep(version="2.0"), vuln()
    )


def test_load_state_missing_file(tmp_path: Path):
    assert load_state(tmp_path / "nope.json") == {}


def test_load_state_corrupt_file(tmp_path: Path):
    p = tmp_path / "s.json"
    p.write_text("{nope")
    assert load_state(p) == {}


def test_state_roundtrip(tmp_path: Path):
    p = tmp_path / "sub" / "s.json"
    save_state(p, {"g1": "2026-01-01T00:00:00+00:00"})
    assert load_state(p) == {"g1": "2026-01-01T00:00:00+00:00"}


def test_build_entries_one_per_dependency_vulnerability_pair(tmp_path: Path):
    entries = build_entries(result_for(tmp_path), {}, NOW)
    assert len(entries) == 2
    assert all(isinstance(e, FeedEntry) for e in entries)
    assert len({e.guid for e in entries}) == 2


def test_build_entries_content(tmp_path: Path):
    entry = build_entries(result_for(tmp_path), {}, NOW)[0]
    assert "requests" in entry.title
    assert "2.30.0" in entry.title
    assert "GHSA-j8r2-6x86-q33q" in entry.title
    assert entry.link == "https://osv.dev/vulnerability/GHSA-j8r2-6x86-q33q"
    assert "CVE-2023-32681" in entry.content_html
    assert "2.31.0" in entry.content_html
    assert "https://nvd.nist.gov/vuln/detail/CVE-2023-32681" in entry.content_html
    assert "requirements.txt" in entry.content_html
    assert "&lt;with&gt;" in entry.content_html
    assert "MEDIUM" in entry.categories
    assert PYPI in entry.categories
    assert entry.summary == "Proxy-Authorization leak"


def test_build_entries_published_is_first_seen_from_state(tmp_path: Path):
    first_seen = (NOW - timedelta(days=10)).isoformat()
    result = result_for(tmp_path)
    guid = entry_guid("proj", result.findings[0].dependency, result.findings[0].vulnerabilities[0])
    state = {guid: first_seen}
    entries = build_entries(result, state, NOW)
    by_guid = {e.guid: e for e in entries}
    assert by_guid[guid].published == NOW - timedelta(days=10)
    other = [e for e in entries if e.guid != guid][0]
    assert other.published == NOW


def test_build_entries_records_new_entries_in_state(tmp_path: Path):
    state: dict[str, str] = {}
    entries = build_entries(result_for(tmp_path), state, NOW)
    assert set(state) == {e.guid for e in entries}
    assert all(datetime.fromisoformat(v) == NOW for v in state.values())


def test_build_entries_updated_uses_vulnerability_modified(tmp_path: Path):
    entries = build_entries(result_for(tmp_path), {}, NOW)
    assert entries[0].updated == datetime(2024, 2, 1, tzinfo=UTC)
    entries2 = build_entries(result_for(tmp_path, [Finding(dep(), [vuln(modified=None)])]), {}, NOW)
    assert entries2[0].updated == NOW


def test_build_entries_newest_first(tmp_path: Path):
    result = result_for(tmp_path)
    guid_a = entry_guid(
        "proj", result.findings[0].dependency, result.findings[0].vulnerabilities[0]
    )
    state = {guid_a: (NOW - timedelta(days=3)).isoformat()}
    entries = build_entries(result, state, NOW)
    assert entries[0].guid != guid_a
    assert entries[1].guid == guid_a


def test_render_rss_structure(tmp_path: Path):
    settings = settings_for(tmp_path)
    entries = build_entries(result_for(tmp_path), {}, NOW)
    root = ET.fromstring(render_rss(entries, settings, NOW))
    assert root.tag == "rss" and root.get("version") == "2.0"
    channel = root.find("channel")
    assert channel.findtext("title") == "Demo feed"
    assert channel.findtext("description") == "Demo description"
    assert channel.findtext("link") == "https://example.com/feeds/"
    assert parsedate_to_datetime(channel.findtext("lastBuildDate")) == NOW
    items = channel.findall("item")
    assert len(items) == 2
    item = items[1]
    guid = item.find("guid")
    assert guid.text == entries[1].guid
    assert guid.get("isPermaLink") == "false"
    assert item.findtext("link") == entries[1].link
    assert "GHSA" in item.findtext("title")
    assert parsedate_to_datetime(item.findtext("pubDate")) == entries[1].published
    assert "CVE-2023-32681" in item.findtext("description")
    assert {c.text for c in item.findall("category")} >= {"MEDIUM", PYPI}


def test_render_rss_without_feed_link_still_valid(tmp_path: Path):
    settings = settings_for(tmp_path, feed_link="")
    root = ET.fromstring(render_rss([], settings, NOW))
    assert root.find("channel").findtext("title") == "Demo feed"
    assert root.find("channel").findall("item") == []


def test_render_atom_structure(tmp_path: Path):
    settings = settings_for(tmp_path)
    entries = build_entries(result_for(tmp_path), {}, NOW)
    root = ET.fromstring(render_atom(entries, settings, NOW))
    assert root.tag == f"{ATOM_NS}feed"
    assert root.findtext(f"{ATOM_NS}title") == "Demo feed"
    assert root.findtext(f"{ATOM_NS}id")
    assert datetime.fromisoformat(root.findtext(f"{ATOM_NS}updated")) == NOW
    links = {link.get("rel"): link.get("href") for link in root.findall(f"{ATOM_NS}link")}
    assert links["self"] == "https://example.com/feeds/vulns.atom.xml"
    atom_entries = root.findall(f"{ATOM_NS}entry")
    assert len(atom_entries) == 2
    first = atom_entries[0]
    assert first.findtext(f"{ATOM_NS}id") == entries[0].guid
    assert first.findtext(f"{ATOM_NS}title") == entries[0].title
    assert first.find(f"{ATOM_NS}link").get("href") == entries[0].link
    assert datetime.fromisoformat(first.findtext(f"{ATOM_NS}updated")) == entries[0].updated
    assert datetime.fromisoformat(first.findtext(f"{ATOM_NS}published")) == entries[0].published
    content = first.find(f"{ATOM_NS}content")
    assert content.get("type") == "html"
    assert "GHSA" in content.text
    assert {c.get("term") for c in first.findall(f"{ATOM_NS}category")} >= {"MEDIUM", PYPI}
    assert first.find(f"{ATOM_NS}author") is not None


def test_render_atom_ids_are_valid_iris(tmp_path: Path):
    entries = build_entries(result_for(tmp_path), {}, NOW)
    for e in entries:
        assert ":" in e.guid and " " not in e.guid


def test_write_feeds_creates_files_and_state(tmp_path: Path):
    settings = settings_for(tmp_path)
    rss, atom = write_feeds(result_for(tmp_path), settings, now=NOW)
    assert rss == settings.rss_path and atom == settings.atom_path
    assert rss.is_file() and atom.is_file()
    assert ET.parse(rss).getroot().tag == "rss"
    assert ET.parse(atom).getroot().tag == f"{ATOM_NS}feed"
    state = json.loads(settings.state_path.read_text())
    assert len(state) == 2


def test_write_feeds_preserves_first_seen_across_runs(tmp_path: Path):
    settings = settings_for(tmp_path)
    write_feeds(result_for(tmp_path), settings, now=NOW - timedelta(days=5))
    write_feeds(result_for(tmp_path), settings, now=NOW)
    root = ET.parse(settings.rss_path).getroot()
    dates = {
        parsedate_to_datetime(i.findtext("pubDate")) for i in root.find("channel").findall("item")
    }
    assert dates == {NOW - timedelta(days=5)}


def test_write_feeds_with_no_findings_writes_empty_feeds(tmp_path: Path):
    settings = settings_for(tmp_path)
    write_feeds(result_for(tmp_path, findings=[]), settings, now=NOW)
    assert ET.parse(settings.rss_path).getroot().find("channel").findall("item") == []


def test_wordfence_entries_carry_attribution(tmp_path: Path):
    from vulnscan.wordfence import WORDFENCE_COPYRIGHT, WORDFENCE_LICENSE_URL

    wf = vuln(
        "CVE-2023-1234",
        link="https://www.wordfence.com/threat-intel/vulnerabilities/id/abc",
        source="wordfence",
    )
    osv = vuln()
    entries = build_entries(result_for(tmp_path, [Finding(dep(), [wf, osv])]), {}, NOW)
    by_id = {e.link: e for e in entries}
    assert WORDFENCE_COPYRIGHT in by_id[wf.url].content_html
    assert WORDFENCE_LICENSE_URL in by_id[wf.url].content_html
    assert WORDFENCE_COPYRIGHT not in by_id[osv.url].content_html


def test_entry_content_lists_every_declaring_file(tmp_path: Path):
    d = Dependency(
        "authlib",
        PYPI,
        "==1.2.0",
        "1.2.0",
        "pinned",
        "requirements/base.txt",
        declarations=(
            Declaration("requirements/base.txt", "==1.2.0"),
            Declaration("requirements/production.txt", ">=1.2"),
        ),
    )
    result = ScanResult(tmp_path / "proj", [d], [Finding(d, [vuln()])], [], NOW)
    entries = build_entries(result, {}, NOW)
    assert "requirements/base.txt as ==1.2.0" in entries[0].content_html
    assert "requirements/production.txt as &gt;=1.2" in entries[0].content_html
