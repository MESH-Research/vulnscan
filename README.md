# vulnscan

Point vulnscan at a Python, PHP or WordPress project and it tells you which
of your direct dependencies have known security advisories, which versions
fix them, and every manifest in which each one is declared. It can rewrite
those manifests for you, publish the results as RSS and Atom feeds or as
Markdown and plain-text reports, and push a notification to your phone or a
Microsoft Teams channel the first time a new advisory appears.

- **Sources:** [OSV.dev](https://osv.dev) for PyPI and Packagist packages (no
  key needed) and [Wordfence Intelligence](https://www.wordfence.com/threat-intel/)
  for WordPress core, plugins and themes installed through Composer (free
  API key).
- **Manifests:** `composer.json`; `pyproject.toml` (PEP 621, PEP 735
  dependency groups, Poetry); `requirements*.txt` and `requirements/*.txt`
  with `-r` includes; `Pipfile`; `setup.cfg`. Installed versions come from
  `composer.lock`, `uv.lock`, `poetry.lock` and `Pipfile.lock`.
- **Interfaces:** an interactive terminal UI; non-interactive modes for
  cron; a continuous watch mode that notifies [ntfy](https://ntfy.sh) and/or
  Microsoft Teams.
- **Scope:** direct dependencies only. Lock files are read solely to learn
  the installed version of those direct dependencies; transitive
  dependencies are never scanned.

Full documentation, including an API reference, lives in [`docs/`](docs/)
and builds with MkDocs (`uv run mkdocs serve`).

## Quick start

Requires Python 3.12 or newer and [uv](https://docs.astral.sh/uv/).

```
git clone <repository url>
cd vulnscan
uv sync
uv run vulnscan --path /path/to/project
```

That opens the TUI. For WordPress projects, put a Wordfence Intelligence
API key in `.env` first (see [Wordfence API key](#wordfence-api-key)).

## Usage

### Interactive

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
| `u` | Upgrade the selected dependency in every manifest that declares it |
| `r` | Rescan |
| `q` | Quit |

The left table lists vulnerable dependencies: package, ecosystem, installed
version and where it was read from (`lock`, `pinned` or `constraint`), worst
severity, number of advisories, fixed versions, and a **File** column naming
every manifest that declares the package. The top-right table lists the
advisories for the selected dependency with their CVE ids. The bottom-right
pane shows the full disclosure: severity and CVSS vector, aliases, fixed
versions, each declaring file with its constraint, the advisory text and
all reference links.

### Feeds and reports (cron)

```
uv run vulnscan --update-feeds --path /path/to/project --feed-dir /var/www/feeds
uv run vulnscan --markdown --text --path /path/to/project      # <feed dir>/vulns.md and vulns.txt
uv run vulnscan --markdown report.md --path /path/to/project   # explicit file
uv run vulnscan --text - --path /path/to/project               # to stdout
```

`--update-feeds` rewrites both feeds, prints a summary and exits 0. If an
advisory source cannot be reached it exits 1 and leaves the existing feeds
untouched, so an outage never makes vulnerabilities disappear from your
reader. Feed entry ids are stable per (project, dependency, advisory), so
readers notify you once per new advisory; a small state file records when
each entry was first seen and uses that as its published date.

### Notifications: ntfy and Microsoft Teams

```
uv run vulnscan --ntfy --path /path/to/project              # push to an ntfy topic
uv run vulnscan --msteams --path /path/to/project           # post to a Teams channel
uv run vulnscan --ntfy --msteams --path /path/to/project    # both
```

Rescans every `VULNSCAN_INTERVAL_MINUTES` (default 60, or `--interval`)
and sends one notification per dependency with advisories that channel has
not received before for this project. The first run therefore pushes
everything currently found; afterwards only new advisories arrive. Each
channel keeps its own record, so adding Teams later gives it the full
backlog while ntfy stays quiet. Ids are recorded only after the service
accepts the message, so a failed push is retried next cycle. A failed scan
is logged and the loop carries on.

Every notification states the severity of the worst new advisory, the
installed version, the smallest published upgrade that clears every
advisory for the package (or that none exists yet), the latest release and
whether it is still affected, and the manifests that declare the package.
For each advisory it gives a link to the full record, the linked CVE id,
severity with CVSS vector, a summary and description, the lowest fixed
version above the installed one and whether that version is actually
available on PyPI, Packagist or wordpress.org. On Teams this is an Adaptive
Card with colour-coded severity and buttons that open the advisories; on
ntfy it is a plain-text message whose priority follows the severity.

- `kill -USR1 <pid>` re-sends every current finding immediately.
- `--resend` does the same at start-up.
- `--once` runs a single cycle and exits, for cron.
- `SIGINT` / `SIGTERM` stop cleanly.

Configure the destinations in `.env`:

```
VULNSCAN_INTERVAL_MINUTES=60
VULNSCAN_NTFY_SERVER=https://ntfy.sh
VULNSCAN_NTFY_TOPIC=mysite-vulns
VULNSCAN_NTFY_TOKEN=tk_xxxxxxxxxxxx        # or VULNSCAN_NTFY_USER / VULNSCAN_NTFY_PASSWORD
VULNSCAN_MSTEAMS_WEBHOOK_URL=https://<workflow webhook url>
```

The Teams URL comes from the **Workflows** app in the target channel: choose
the **Send webhook alerts to a channel** template (or any flow built on the
"When a Teams webhook request is received" trigger that posts the received
Adaptive Card) and copy its URL. See
[docs/notifications.md](docs/notifications.md).

### Upgrading a dependency

Press `u` in the TUI, or:

```
uv run vulnscan --remediate requests --path /path/to/project
uv run vulnscan --remediate wp-plugin/elementor --strategy latest --path /path/to/project
```

vulnscan looks up the versions published for the package and offers the
**nearest safe version** (the smallest upgrade above the installed one that
no advisory affects, so `symfony/http-kernel` 5.4.0 goes to 5.4.20, not
6.x) or the **latest release**, saying if even that is still affected.
Pre-release and yanked versions are never offered. The constraint is
rewritten in every manifest that declares the package, keeping the operator
style (`^12.2` becomes `^16.3`, `Django>=4.2,<5` becomes
`Django>=4.2.11,<5`) and touching nothing else in the file. All rewrites are
computed before any file is written. Lock files are not touched; the output
tells you which `composer update`, `uv lock`, `poetry lock`, `pipenv lock` or
`pip install -r` command to run next.

### Ignoring directories

Some directories should never be scanned, such as a quarantine of plugins
you have isolated and will never run. Put patterns in a `.vulnscanignore`
file in the project root:

```
# retired plugins, kept for reference only
web/app/plugins/graveyard
legacy
tools/scratch-*
```

A pattern without a slash matches a directory of that name anywhere; one
with a slash is relative to the project root; both take shell wildcards.
The same patterns can go in `VULNSCAN_IGNORE_DIRS` (comma separated) or
repeated `--ignore` flags. Version control metadata, virtualenvs,
`node_modules/`, `vendor/`, `build/`, `dist/`, dot-directories, WordPress
core and whatever a `composer.json` installs into are always skipped.

### A package declared in several files

The same package at the same installed version in several manifests (a
`requirements/base.txt` included by `requirements/production.txt`, plus a
`pyproject.toml`, say) is one dependency with several declarations. Every
output lists all of its files, and an upgrade edits each of them. Different
installed versions stay separate because they may have different
advisories.

## Configuration

All settings are read from `VULNSCAN_*` environment variables, falling back
to a `.env` file in the current directory (or the file given with
`--env-file`). Flags override both. [`.env.example`](.env.example) lists
every option with comments.

| Variable | Default | Purpose |
|----------|---------|---------|
| `VULNSCAN_PROJECT_PATH` | `.` | Project to scan (`--path`) |
| `VULNSCAN_INCLUDE_DEV` | `true` | Include dev / test / optional dependencies |
| `VULNSCAN_QUERY_UNKNOWN_VERSIONS` | `false` | Query packages whose version is unknown (noisy) |
| `VULNSCAN_IGNORE_DIRS` | empty | Directories to skip: names, relative paths or globs (`--ignore`) |
| `VULNSCAN_FEED_DIR` | `./feeds` | Output directory for feeds, reports and state files (`--feed-dir`) |
| `VULNSCAN_RSS_FILE` / `VULNSCAN_ATOM_FILE` | `vulns.rss.xml` / `vulns.atom.xml` | Feed filenames |
| `VULNSCAN_STATE_FILE` | `vulnscan-state.json` | When each feed entry was first seen |
| `VULNSCAN_MARKDOWN_FILE` / `VULNSCAN_TEXT_FILE` | `vulns.md` / `vulns.txt` | Report filenames |
| `VULNSCAN_FEED_TITLE` / `VULNSCAN_FEED_DESCRIPTION` | generic text | Feed metadata |
| `VULNSCAN_FEED_LINK` | empty | Public base URL of the feeds, for self links |
| `VULNSCAN_OSV_URL` | `https://api.osv.dev` | OSV API base URL |
| `VULNSCAN_TIMEOUT` | `30` | HTTP timeout in seconds, for every service |
| `VULNSCAN_WORDFENCE_API_KEY` | empty | Wordfence Intelligence API key (WordPress packages) |
| `VULNSCAN_WORDFENCE_URL` | `https://www.wordfence.com/api/intelligence/v3` | Wordfence API base URL |
| `VULNSCAN_WORDFENCE_TTL_HOURS` | `24` | How long the cached Wordfence feed stays fresh |
| `VULNSCAN_WORDFENCE_MIN_INTERVAL_MINUTES` | `30` | Minimum gap between Wordfence requests |
| `VULNSCAN_CACHE_DIR` | `$XDG_CACHE_HOME/vulnscan` or `~/.cache/vulnscan` | Cache location |
| `VULNSCAN_INTERVAL_MINUTES` | `60` | Minutes between scans in `--ntfy` / `--msteams` mode (`--interval`) |
| `VULNSCAN_NTFY_SERVER` | `https://ntfy.sh` | ntfy server |
| `VULNSCAN_NTFY_TOPIC` | empty | ntfy topic (required for `--ntfy`) |
| `VULNSCAN_NTFY_TOKEN` | empty | ntfy access token |
| `VULNSCAN_NTFY_USER` / `VULNSCAN_NTFY_PASSWORD` | empty | ntfy basic authentication, used when no token is set |
| `VULNSCAN_NTFY_STATE_FILE` | `ntfy-state.json` | Which advisories ntfy has received |
| `VULNSCAN_MSTEAMS_WEBHOOK_URL` | empty | Teams incoming webhook URL (required for `--msteams`) |
| `VULNSCAN_MSTEAMS_STATE_FILE` | `msteams-state.json` | Which advisories Teams has received |

### Wordfence API key

Wordfence publishes its vulnerability database under a free licence, but
the API requires a key. Create a free account at wordfence.com, open
**Wordfence Intelligence** in the dashboard, generate a key under
**Integrations**, and set `VULNSCAN_WORDFENCE_API_KEY`. Without a key,
WordPress packages are listed but not checked and a warning says so.

The feed is a single large download (over 100 MB) covering every known
WordPress vulnerability, so vulnscan caches it under `~/.cache/vulnscan/`
for `VULNSCAN_WORDFENCE_TTL_HOURS`, refreshes it with conditional requests
(`ETag` / `Last-Modified`), never contacts the API more than once per
`VULNSCAN_WORDFENCE_MIN_INTERVAL_MINUTES` even after a failure, and falls
back to the stale cache with a warning if a refresh fails. The first scan
takes a minute or two; later scans are fast. Records derived from Wordfence
carry their copyright notice and licence in the feeds, reports and TUI, as
the licence requires.

## How versions are determined

For each dependency, in order of preference: the version in an adjacent
lock file, an exact pin in the manifest (`==1.2.3`, `1.2.3`), or the lower
bound of the constraint (`>=1.2`, `^1.2`, `~=1.2`). Dependencies with no
lower bound at all are listed as warnings and not queried unless
`VULNSCAN_QUERY_UNKNOWN_VERSIONS` is enabled. Packages installed from a
custom source (a VCS or `package` repository rather than Packagist or
wordpress.org) are still looked up by name but flagged in the warnings,
because no advisory database can be relied on to cover them.

## Development

```
uv sync --all-groups
uv run pytest
uv run ruff check . && uv run ruff format --check .
uv run mkdocs serve        # documentation with API reference at http://127.0.0.1:8000
```

Tests use fake HTTP transports and never touch the network. See
[CONTRIBUTING.md](CONTRIBUTING.md) for the workflow and
[SECURITY.md](SECURITY.md) for reporting problems; `docs/` holds the
guides, the architecture notes and the design documents.

## Licence

[MIT](LICENSE).

## Acknowledgement

This application was developed with the assistance of large language models
(artificial intelligence tools) for drafting code, tests and documentation.
Bug reports and corrections are very welcome.
