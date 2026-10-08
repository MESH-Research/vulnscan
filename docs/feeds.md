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

## Warnings

Every output lists the scan's warnings: dependencies whose version could
not be determined (and were therefore not queried), packages installed from
a custom source rather than Packagist or wordpress.org, WordPress packages
skipped for want of a Wordfence key, and a stale Wordfence cache that could
not be refreshed.
