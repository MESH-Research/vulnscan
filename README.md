# vulnscan

Point it at a Python or PHP project and it tells you which of your direct
dependencies have known security advisories, which versions fix them, and
publishes the result as RSS 2.0 and Atom 1.0 feeds. Advisory data comes from
[OSV.dev](https://osv.dev), which aggregates GitHub Security Advisories, PyPI
advisories, CVEs and more. No API key is needed.

Only direct dependencies declared in your manifests are evaluated. Lock files
are read solely to learn the exact installed version of those direct
dependencies; transitive dependencies are never scanned.

## Supported manifests

| Ecosystem | Manifests | Lock files used for versions |
|-----------|-----------|------------------------------|
| PHP | `composer.json` | `composer.lock` |
| Python | `pyproject.toml` (PEP 621, PEP 735 dependency groups, Poetry), `requirements*.txt` (with `-r` includes), `Pipfile`, `setup.cfg` | `uv.lock`, `poetry.lock`, `Pipfile.lock` |

Manifests are discovered recursively, skipping `vendor/`, `node_modules/`,
virtualenvs and similar directories.

The version checked for each dependency is, in order of preference: the version
in an adjacent lock file, an exact pin in the manifest (`==1.2.3`, `1.2.3`), or
the lower bound of the constraint (`>=1.2`, `^1.2`, `~=1.2`). Dependencies with
no lower bound at all are listed as warnings and not queried unless
`VULNSCAN_QUERY_UNKNOWN_VERSIONS` is enabled.

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
| `o` | Open the selected advisory on osv.dev in your browser |
| `f` | Write the RSS and Atom feeds |
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

This scans, rewrites both feeds, prints a summary and exits 0. If OSV cannot
be reached it exits 1 and leaves the existing feeds untouched, so a transient
outage never makes vulnerabilities disappear from your reader.

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
