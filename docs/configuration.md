# Configuration

Settings are read from `VULNSCAN_*` environment variables, falling back to
a `.env` file in the current directory (or the file given with
`--env-file`). Command line flags override both. Every value is optional;
copy `.env.example` from the repository
to `.env` and adjust.

## Scanning

| Variable | Default | Purpose |
|----------|---------|---------|
| `VULNSCAN_PROJECT_PATH` | `.` | Project to scan (`--path`) |
| `VULNSCAN_INCLUDE_DEV` | `true` | Include dev / test / optional dependencies |
| `VULNSCAN_QUERY_UNKNOWN_VERSIONS` | `false` | Query packages whose version cannot be determined. Reports every advisory ever published for them, so this is noisy |
| `VULNSCAN_IGNORE_DIRS` | empty | Directories to skip, comma separated: names, project-relative paths or globs (`--ignore`). See [Ignoring directories](ignoring.md) |
| `VULNSCAN_OSV_URL` | `https://api.osv.dev` | OSV API base URL |
| `VULNSCAN_TIMEOUT` | `30` | HTTP timeout in seconds, for every service |

## Output

| Variable | Default | Purpose |
|----------|---------|---------|
| `VULNSCAN_FEED_DIR` | `./feeds` | Where feeds, reports and state files are written (`--feed-dir`) |
| `VULNSCAN_RSS_FILE` / `VULNSCAN_ATOM_FILE` | `vulns.rss.xml` / `vulns.atom.xml` | Feed filenames |
| `VULNSCAN_STATE_FILE` | `vulnscan-state.json` | Records when each feed entry was first seen |
| `VULNSCAN_FEED_TITLE` / `VULNSCAN_FEED_DESCRIPTION` | generic text | Feed metadata |
| `VULNSCAN_FEED_LINK` | empty | Public base URL of the feeds, used for self links |
| `VULNSCAN_MARKDOWN_FILE` / `VULNSCAN_TEXT_FILE` | `vulns.md` / `vulns.txt` | Report filenames inside the feed directory |

## Wordfence

| Variable | Default | Purpose |
|----------|---------|---------|
| `VULNSCAN_WORDFENCE_API_KEY` | empty | Wordfence Intelligence API key, needed for WordPress packages |
| `VULNSCAN_WORDFENCE_URL` | `https://www.wordfence.com/api/intelligence/v3` | API base URL |
| `VULNSCAN_WORDFENCE_TTL_HOURS` | `24` | How long the cached feed stays fresh |
| `VULNSCAN_WORDFENCE_MIN_INTERVAL_MINUTES` | `30` | Minimum gap between requests to the API, even after failures |
| `VULNSCAN_CACHE_DIR` | `$XDG_CACHE_HOME/vulnscan` or `~/.cache/vulnscan` | Where the feed is cached |

The Wordfence feed is a single download of roughly 160 MB covering every
known WordPress vulnerability, so vulnscan is careful never to overload the
API:

- The feed is cached (slimmed to about half its size) and reused for the
  TTL. Rescans and repeated cron runs make no requests while it is fresh.
- When the cache expires, the refresh is a conditional request carrying the
  cached `ETag` / `Last-Modified`, so an unchanged feed is answered with a
  `304` instead of a download.
- At most one request is made per minimum interval, tracked in a marker file
  next to the cache. A failed download, a rejected key or a `429` is not
  retried before that interval passes.
- If a refresh fails, the stale cache is used and a warning is recorded.
  Only when there is no cache at all does a failure abort the scan.

The first scan therefore takes a minute or two; later scans are fast.
Records derived from Wordfence carry their copyright notice and licence in
the feeds, reports and TUI, as the licence requires.

## Notifications

| Variable | Default | Purpose |
|----------|---------|---------|
| `VULNSCAN_INTERVAL_MINUTES` | `60` | Minutes between scans in `--ntfy` / `--msteams` mode (`--interval`) |
| `VULNSCAN_NTFY_SERVER` | `https://ntfy.sh` | ntfy server base URL |
| `VULNSCAN_NTFY_TOPIC` | empty | Topic to publish to (required for `--ntfy`) |
| `VULNSCAN_NTFY_TOKEN` | empty | Access token (bearer authentication) |
| `VULNSCAN_NTFY_USER` / `VULNSCAN_NTFY_PASSWORD` | empty | Basic authentication, used when no token is set |
| `VULNSCAN_NTFY_STATE_FILE` | `ntfy-state.json` | Records which advisories ntfy has received, inside the feed directory |
| `VULNSCAN_MSTEAMS_WEBHOOK_URL` | empty | Microsoft Teams incoming webhook URL (required for `--msteams`) |
| `VULNSCAN_MSTEAMS_STATE_FILE` | `msteams-state.json` | Records which advisories Teams has received, inside the feed directory |

See [Notifications](notifications.md).

## Precedence

For every setting: command line flag, then environment variable, then the
`.env` file, then the default. The one exception is `.vulnscanignore`,
which is always read in addition to `VULNSCAN_IGNORE_DIRS` or `--ignore`.
