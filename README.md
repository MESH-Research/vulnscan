# vulnscan

Point it at a Python, PHP or WordPress project and it tells you which of your
direct dependencies have known security advisories, which versions fix them,
and publishes the result as RSS 2.0 and Atom 1.0 feeds plus Markdown and plain
text reports.

Advisory data comes from two sources:

- [OSV.dev](https://osv.dev) for PyPI and Packagist packages. It aggregates
  GitHub Security Advisories, PyPI advisories, CVEs and more. No key needed.
- [Wordfence Intelligence](https://www.wordfence.com/threat-intel/) for
  WordPress core, plugins and themes installed through Composer. This needs a
  free API key (see below).

Only direct dependencies declared in your manifests are evaluated. Lock files
are read solely to learn the exact installed version of those direct
dependencies; transitive dependencies are never scanned.

## Supported manifests

| Ecosystem | Manifests | Lock files used for versions |
|-----------|-----------|------------------------------|
| PHP | `composer.json` | `composer.lock` |
| WordPress | `composer.json` entries for `wp-plugin/*`, `wp-theme/*`, `wpackagist-plugin/*`, `wpackagist-theme/*`, `roots/wordpress`, `johnpbloch/wordpress`, and any package the lock file types as `wordpress-plugin`, `wordpress-muplugin`, `wordpress-theme` or `wordpress-core` | `composer.lock` |
| Python | `pyproject.toml` (PEP 621, PEP 735 dependency groups, Poetry), `requirements*.txt` (with `-r` includes), `Pipfile`, `setup.cfg` | `uv.lock`, `poetry.lock`, `Pipfile.lock` |

Manifests are discovered recursively, skipping `vendor/`, `node_modules/`,
virtualenvs, `wp-admin/`, `wp-includes/`, and whatever a `composer.json`
installs into (its `vendor-dir`, `extra.installer-paths` such as
`web/app/plugins/{$name}/`, and `extra.wordpress-install-dir`). That keeps the
`composer.json` files shipped inside installed plugins from being mistaken for
your own. Add more directory names to skip with `VULNSCAN_IGNORE_DIRS`.

Packages installed from a custom source (a VCS or `package` repository rather
than Packagist or wordpress.org) are still looked up by name or slug, but are
flagged in the warnings because no advisory database can be relied on to cover
them.

The version checked for each dependency is, in order of preference: the version
in an adjacent lock file, an exact pin in the manifest (`==1.2.3`, `1.2.3`), or
the lower bound of the constraint (`>=1.2`, `^1.2`, `~=1.2`). Dependencies with
no lower bound at all are listed as warnings and not queried unless
`VULNSCAN_QUERY_UNKNOWN_VERSIONS` is enabled.

## WordPress advisories: Wordfence API key

Wordfence publishes its vulnerability database under a free licence, but the
v3 API requires a key. Create a free account at wordfence.com, open
**Wordfence Intelligence** in the account dashboard, generate an API key under
**Integrations**, and set:

```
VULNSCAN_WORDFENCE_API_KEY=your-key
```

Without a key, WordPress packages are listed but not checked and a warning
says so. The feed is a single ~160 MB download covering every known WordPress
vulnerability, so vulnscan is careful never to overload the API:

- The feed is cached (slimmed to roughly half its size) under
  `~/.cache/vulnscan/` and reused for `VULNSCAN_WORDFENCE_TTL_HOURS`
  (default 24). Rescans in the TUI and repeated cron runs read the cache and
  make no requests at all while it is fresh.
- When the cache expires, the refresh is a conditional request carrying the
  cached `ETag` / `Last-Modified` when the server supplied them, so an
  unchanged feed can be answered with a `304` instead of a download.
- At most one request is made per `VULNSCAN_WORDFENCE_MIN_INTERVAL_MINUTES`
  (default 30), tracked in a marker file next to the cache. A failed download,
  a rejected key or a `429` is not retried before that interval passes.
- If a refresh fails, the stale cache is used and a warning is recorded. Only
  when there is no cache at all does a failure abort the scan.

The first scan therefore takes a minute or two; later scans are fast.

Records derived from Wordfence carry their copyright notice and licence in the
feeds, reports and TUI, as the licence requires.

## Install

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/).

```
uv sync
```

## Usage

Interactive TUI:

```
uv run vulnscan --path /path/to/project
```

| Key | Action |
|-----|--------|
| `↑` `↓` | Move between dependencies / advisories |
| `Tab` | Switch between the dependency and advisory tables |
| `o` | Open the selected advisory (osv.dev or wordfence.com) in your browser |
| `f` | Write the RSS and Atom feeds |
| `e` | Export Markdown and plain-text reports |
| `u` | Upgrade the selected dependency in its manifest (see below) |
| `r` | Rescan |
| `q` | Quit |

The left table lists vulnerable dependencies. The top-right table lists the
advisories for the selected dependency with their CVE ids. The bottom-right
pane shows the full disclosure: severity and CVSS vector, aliases, fixed
versions, the advisory text and all reference links.

Non-interactive mode, for cron:

```
uv run vulnscan --update-feeds --path /path/to/project --feed-dir /var/www/feeds
```

This scans, rewrites both feeds, prints a summary and exits 0. If an advisory
source cannot be reached it exits 1 and leaves the existing feeds untouched,
so a transient outage never makes vulnerabilities disappear from your reader.

Markdown and plain-text exports, alone or alongside the feeds:

```
uv run vulnscan --markdown --text --path /path/to/project      # <feed dir>/vulns.md and vulns.txt
uv run vulnscan --markdown report.md --path /path/to/project   # explicit file
uv run vulnscan --text - --path /path/to/project               # to stdout
uv run vulnscan --update-feeds --markdown --text               # feeds and both reports
```

## Remediation

Select a vulnerable dependency in the TUI and press `u`. vulnscan looks up the
versions published for it (PyPI, Packagist or wordpress.org) and offers two
choices:

- **Nearest safe version**: the smallest upgrade above the current version
  that is outside every known advisory's affected range. This keeps you as
  close as possible to what you have (for example `symfony/http-kernel` 5.4.0
  goes to 5.4.20, not 6.x).
- **Latest release**: the newest stable version. If even that is still
  affected by an open advisory, the option says so.

Choosing one rewrites the dependency's constraint in the manifest it came
from, touching nothing else in the file. The operator style is preserved:
`3.13.4` becomes `4.1.4`, `^12.2` becomes `^16.3`, `requests==2.30.0` becomes
`requests==2.32.4`, `Django>=4.2,<5` becomes `Django>=4.2.11,<5`. Supported
manifests: `composer.json`, `requirements*.txt`, `pyproject.toml` (PEP 621
strings and Poetry tables), `Pipfile` and `setup.cfg`. Constraints that track
a development branch (`dev-main`) are left for you to change by hand.

Lock files are not touched. The status bar tells you the command to run next,
such as `composer update wp-plugin/elementor --with-dependencies` or
`uv lock && uv sync`. Press `r` afterwards to rescan.

The same thing non-interactively:

```
uv run vulnscan --remediate wp-plugin/elementor --path /path/to/project
uv run vulnscan --remediate requests --strategy latest --path /path/to/project
```

`--strategy nearest` is the default. Pre-release and yanked versions are never
offered.

## Configuration

All settings are read from `VULNSCAN_*` environment variables, falling back to
a `.env` file in the current directory (or the file given with `--env-file`).
Command line flags override both. See [`.env.example`](.env.example) for every
option.

| Variable | Default | Purpose |
|----------|---------|---------|
| `VULNSCAN_PROJECT_PATH` | `.` | Project to scan |
| `VULNSCAN_FEED_DIR` | `./feeds` | Output directory |
| `VULNSCAN_RSS_FILE` / `VULNSCAN_ATOM_FILE` | `vulns.rss.xml` / `vulns.atom.xml` | Feed filenames |
| `VULNSCAN_STATE_FILE` | `vulnscan-state.json` | Records when each entry was first seen |
| `VULNSCAN_FEED_TITLE` / `VULNSCAN_FEED_DESCRIPTION` | generic text | Feed metadata |
| `VULNSCAN_FEED_LINK` | empty | Public base URL of the feeds, used for self links |
| `VULNSCAN_OSV_URL` | `https://api.osv.dev` | OSV API base URL |
| `VULNSCAN_TIMEOUT` | `30` | HTTP timeout in seconds |
| `VULNSCAN_INCLUDE_DEV` | `true` | Include dev / test / optional dependencies |
| `VULNSCAN_QUERY_UNKNOWN_VERSIONS` | `false` | Query packages whose version is unknown |
| `VULNSCAN_WORDFENCE_API_KEY` | empty | Wordfence Intelligence API key (needed for WordPress packages) |
| `VULNSCAN_WORDFENCE_URL` | `https://www.wordfence.com/api/intelligence/v3` | Wordfence API base URL |
| `VULNSCAN_WORDFENCE_TTL_HOURS` | `24` | How long the cached Wordfence feed stays fresh |
| `VULNSCAN_WORDFENCE_MIN_INTERVAL_MINUTES` | `30` | Minimum gap between requests to the Wordfence API |
| `VULNSCAN_CACHE_DIR` | `$XDG_CACHE_HOME/vulnscan` or `~/.cache/vulnscan` | Cache location |
| `VULNSCAN_IGNORE_DIRS` | empty | Extra directory names to skip, comma separated |
| `VULNSCAN_MARKDOWN_FILE` / `VULNSCAN_TEXT_FILE` | `vulns.md` / `vulns.txt` | Report filenames inside the feed directory |

## Feeds

Each feed entry is one (dependency, advisory) pair. Entry ids are stable across
runs, so feed readers only notify you once per new advisory. The published
date is the first time this project saw that advisory; the updated date is
when OSV last modified it. Entries carry the severity, ecosystem and package
name as categories.

## Development

```
uv run pytest
uv run ruff check . && uv run ruff format --check .
```

Tests use fake HTTP transports and never touch the network. See `docs/SPEC.md`
and `docs/PLAN.md` for the design.
