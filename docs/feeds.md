# Feeds and reports

## RSS and Atom

`--update-feeds` (or `f` in the TUI) writes an RSS 2.0 and an Atom 1.0 file
into the feed directory. Each entry is one (dependency, advisory) pair and
carries the package, version, every declaring file with its constraint,
severity and CVSS vector, fixed versions, CVE ids, aliases, the advisory
text and all reference links.

Entry ids are stable across runs (`urn:vulnscan:<project>:<ecosystem>:
<package>:<advisory>`), so feed readers notify you once per new advisory
rather than on every regeneration. A small state file
(`VULNSCAN_STATE_FILE`) records when each entry was first seen; that is the
entry's published date. The updated date is when the advisory source last
modified it. Entries carry the severity, ecosystem and package name as
categories, and the newest appear first.

Set `VULNSCAN_FEED_LINK` to the public base URL the files are served from
so the feeds contain correct self links, and `VULNSCAN_FEED_TITLE` /
`VULNSCAN_FEED_DESCRIPTION` to label them.

If the scan fails, the feeds are not rewritten: stale feeds are better than
empty ones that would make every vulnerability look resolved.

## Markdown and plain text

`--markdown` and `--text` (or `e` in the TUI) write reports with a summary
table (package, ecosystem, version, severity, advisories, fixed versions,
declaring files) followed by the full details of every advisory, the scan
warnings, and the Wordfence attribution when WordPress data was used. Pass
a filename, or `-` for stdout; with no argument they go to
`VULNSCAN_MARKDOWN_FILE` / `VULNSCAN_TEXT_FILE` in the feed directory.

## Preflight feeds and reports

`--preflight --update-feeds` writes a second pair of feeds,
`VULNSCAN_PREFLIGHT_RSS_FILE` and `VULNSCAN_PREFLIGHT_ATOM_FILE`
(`preflight.rss.xml` and `preflight.atom.xml`), with their own first-seen
state file (`VULNSCAN_PREFLIGHT_STATE_FILE`). Each entry is one (package,
risk) pair, or a bump-only entry for a package that would change version
without any risk; its categories are the risk kind (or `bump`), the ecosystem
and the package name. The feeds are not written when no manifest could be
resolved, for the same reason the advisory feeds survive a failed scan. They
carry the same `VULNSCAN_FEED_TITLE` and `VULNSCAN_FEED_DESCRIPTION` as the
advisory feeds.

`--preflight --text` and `--preflight --markdown` write
`VULNSCAN_PREFLIGHT_TEXT_FILE` and `VULNSCAN_PREFLIGHT_MARKDOWN_FILE`
(`preflight.txt`, `preflight.md`): the resolve outcome, the counts of bumps
and of each risk kind, one line per package of interest (`name (ecosystem,
process): current → would-be [risks]`), the ignored packages and the
warnings. `--preflight --json` writes `preflight.json`, the form meant for
CI; see [Preflight](usage.md#preflight-what-the-next-resolve-would-pull-in).

## Warnings

Every output lists the scan's warnings: no manifests found at all,
dependencies whose version could not be determined (and were therefore not
queried), packages installed from a custom source rather than Packagist or
wordpress.org, WordPress packages skipped for want of a Wordfence key, and
a stale Wordfence cache that could not be refreshed.
