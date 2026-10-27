# Configuration

Settings are read from `VULNSCAN_*` environment variables, falling back to a
`.env` file in the current directory (or the file given with `--env-file`).
Command line flags override both. Every value is optional; copy `.env.example`
from the repository to `.env` and adjust.

## Scanning

| Variable                           | Default               | Purpose                                                                                                                                                             |
| ---------------------------------- | --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `VULNSCAN_PROJECT_PATH`            | `.`                   | Project to scan (`--path`)                                                                                                                                          |
| `VULNSCAN_INCLUDE_DEV`             | `true`                | Include dev / test / optional dependencies                                                                                                                          |
| `VULNSCAN_TRANSITIVE`              | `false`               | Also scan packages that lock files record but no manifest declares, marked as transitive with what requires them (`--transitive`)                                   |
| `VULNSCAN_QUERY_UNKNOWN_VERSIONS`  | `false`               | Query packages whose version cannot be determined. Reports every advisory ever published for them, so this is noisy                                                 |
| `VULNSCAN_IGNORE_DIRS`             | empty                 | Directories to skip, comma separated: names, project-relative paths or globs (`--ignore`). See [Ignoring directories](ignoring.md)                                  |
| `VULNSCAN_INVENIO_WEBPACK`         | `auto`                | Use Invenio `webpack.py` npm sources and remediation strategies: `auto`, `on`, or `off` (`--invenio-webpack`). See [Invenio / webpack.py](invenio.md)               |
| `VULNSCAN_INVENIO_WEBPACK_OVERLAY` | empty                 | Site overlay `webpack.py` file used as the root project requirements bundle (`--invenio-webpack-overlay`). When empty, the `site/*/webpack.py` theme bundle is used |
| `VULNSCAN_OSV_URL`                 | `https://api.osv.dev` | OSV API base URL                                                                                                                                                    |
| `VULNSCAN_TIMEOUT`                 | `30`                  | HTTP timeout in seconds, for every service (OSV, Wordfence, NVD, the package registries, ntfy, Teams)                                                               |

## Output

| Variable                                            | Default                            | Purpose                                                         |
| --------------------------------------------------- | ---------------------------------- | --------------------------------------------------------------- |
| `VULNSCAN_FEED_DIR`                                 | `./feeds`                          | Where feeds, reports and state files are written (`--feed-dir`) |
| `VULNSCAN_RSS_FILE` / `VULNSCAN_ATOM_FILE`          | `vulns.rss.xml` / `vulns.atom.xml` | Feed filenames                                                  |
| `VULNSCAN_STATE_FILE`                               | `vulnscan-state.json`              | Records when each feed entry was first seen                     |
| `VULNSCAN_FEED_TITLE` / `VULNSCAN_FEED_DESCRIPTION` | generic text                       | Feed metadata                                                   |
| `VULNSCAN_FEED_LINK`                                | empty                              | Public base URL of the feeds, used for self links               |
| `VULNSCAN_MARKDOWN_FILE` / `VULNSCAN_TEXT_FILE`     | `vulns.md` / `vulns.txt`           | Report filenames inside the feed directory                      |

## Wordfence

| Variable                                  | Default                                           | Purpose                                                       |
| ----------------------------------------- | ------------------------------------------------- | ------------------------------------------------------------- |
| `VULNSCAN_WORDFENCE_API_KEY`              | empty                                             | Wordfence Intelligence API key, needed for WordPress packages |
| `VULNSCAN_WORDFENCE_URL`                  | `https://www.wordfence.com/api/intelligence/v3`   | API base URL                                                  |
| `VULNSCAN_WORDFENCE_TTL_HOURS`            | `24`                                              | How long the cached feed stays fresh                          |
| `VULNSCAN_WORDFENCE_MIN_INTERVAL_MINUTES` | `30`                                              | Minimum gap between requests to the API, even after failures  |
| `VULNSCAN_CACHE_DIR`                      | `$XDG_CACHE_HOME/vulnscan` or `~/.cache/vulnscan` | Where the feed is cached                                      |

The Wordfence feed is a single large download (over 100 MB) covering every known
WordPress vulnerability, so vulnscan is careful never to overload the API:

- The feed is cached (with the per-record copyright boilerplate stripped and the
  notice kept once) and reused for the TTL. Rescans and repeated cron runs make
  no requests while it is fresh.
- When the cache expires, the refresh is a conditional request carrying the
  cached `ETag` / `Last-Modified`, so an unchanged feed is answered with a `304`
  instead of a download.
- At most one request is made per minimum interval, tracked in a marker file
  next to the cache. A failed download, a rejected key or a `429` is not retried
  before that interval passes.
- If a refresh fails, the stale cache is used and a warning is recorded. Only
  when there is no cache at all does a failure abort the scan.

The first scan therefore takes a minute or two; later scans are fast. Records
derived from Wordfence carry their copyright notice and licence in the feeds,
reports and TUI, as the licence requires.

## NVD (container images)

| Variable                   | Default                                            | Purpose                                                                        |
| -------------------------- | -------------------------------------------------- | ------------------------------------------------------------------------------ |
| `VULNSCAN_NVD_API_KEY`     | empty                                              | Optional API key; raises the limit from 5 to 50 requests per 30 seconds        |
| `VULNSCAN_NVD_URL`         | `https://services.nvd.nist.gov/rest/json/cves/2.0` | API base URL                                                                   |
| `VULNSCAN_NVD_TTL_HOURS`   | `24`                                               | How long a cached answer for one image version stays fresh                     |
| `VULNSCAN_IMAGE_PRODUCTS`  | empty                                              | Extra `image=vendor:product` mappings, comma separated (see below)             |

Container images found in Dockerfiles and Compose files are checked against the
NVD by CPE name: the image name is mapped to a `vendor:product` pair (`php` to
`php:php`, `traefik` to `traefik:traefik`, `nginx` to `f5:nginx`) and NVD is asked
which CVEs apply to the version in the tag. Each answer is cached under
`VULNSCAN_CACHE_DIR/nvd/` for the TTL, requests are spaced to stay inside the
public rate limit (6 seconds apart without a key, shared across threads), a
refused request waits out one 30-second window and is retried once, and a
failed refresh falls back to the stale cache with a warning. When nothing is
cached either, the image goes unchecked for that run and the scan carries on;
after the first such failure no further NVD requests are made in that run.
The failure is reported in the TUI status line and as a notification, as
`error:` lines on stderr, in an **Errors** section of the reports, and in the
debug log.

Images vulnscan does not know produce a warning naming the setting to use.
Give it the vendor and product exactly as they appear in NVD's CPE names, for
example:

```
VULNSCAN_IMAGE_PRODUCTS=myorg/app=myorg:app,ghcr.io/example/tool=example:tool
```

An entry for a built-in image overrides the built-in mapping.

## Forward check and preflight

| Variable                                                        | Default                                    | Purpose                                                                                                                                                                                  |
| --------------------------------------------------------------- | ------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `VULNSCAN_FRESH_HOURS`                                          | `24`                                       | A version published more recently than this is flagged as `fresh`, both when an upgrade is offered and in `--preflight`                                                                 |
| `VULNSCAN_STRICT_FRESH`                                         | `false`                                    | Make `--preflight` exit 2 when freshness is the only risk found (`--strict-fresh`)                                                                                                       |
| `VULNSCAN_PREFLIGHT_IGNORE`                                     | empty                                      | Packages excluded from preflight scoring, comma separated: `name` or `ecosystem:name`, wildcards allowed (`--preflight-ignore`). A `.vulnscan-preflight-ignore` file is always read too |
| `VULNSCAN_PREFLIGHT_RSS_FILE` / `VULNSCAN_PREFLIGHT_ATOM_FILE`  | `preflight.rss.xml` / `preflight.atom.xml` | Preflight feed filenames inside the feed directory                                                                                                                                       |
| `VULNSCAN_PREFLIGHT_STATE_FILE`                                 | `preflight-state.json`                     | Records when each preflight feed entry was first seen                                                                                                                                    |
| `VULNSCAN_PREFLIGHT_MARKDOWN_FILE` / `VULNSCAN_PREFLIGHT_TEXT_FILE` | `preflight.md` / `preflight.txt`       | Preflight report filenames inside the feed directory                                                                                                                                     |

The JSON report goes to `preflight.json` in the feed directory unless
`--json FILE` names another file. See [Preflight](usage.md#preflight-what-the-next-resolve-would-pull-in).

## Notifications

| Variable                                        | Default              | Purpose                                                                |
| ----------------------------------------------- | -------------------- | ---------------------------------------------------------------------- |
| `VULNSCAN_INTERVAL_MINUTES`                     | `60`                 | Minutes between scans in `--ntfy` / `--msteams` mode (`--interval`)    |
| `VULNSCAN_NTFY_SERVER`                          | `https://ntfy.sh`    | ntfy server base URL                                                   |
| `VULNSCAN_NTFY_TOPIC`                           | empty                | Topic to publish to (required for `--ntfy`)                            |
| `VULNSCAN_NTFY_TOKEN`                           | empty                | Access token (bearer authentication)                                   |
| `VULNSCAN_NTFY_USER` / `VULNSCAN_NTFY_PASSWORD` | empty                | Basic authentication, used when no token is set                        |
| `VULNSCAN_NTFY_STATE_FILE`                      | `ntfy-state.json`    | Records which advisories ntfy has received, inside the feed directory  |
| `VULNSCAN_MSTEAMS_WEBHOOK_URL`                  | empty                | Microsoft Teams incoming webhook URL (required for `--msteams`)        |
| `VULNSCAN_MSTEAMS_STATE_FILE`                   | `msteams-state.json` | Records which advisories Teams has received, inside the feed directory |

See [Notifications](notifications.md).

## Debugging

| Variable             | Default     | Purpose                                                                                                                                                  |
| -------------------- | ----------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `VULNSCAN_DEBUG`     | `0`         | Debug log verbosity: `0` off, `1` every HTTP request and response with a `curl` command that repeats it, `2` also control flow, `3` also library internals and tracebacks (`-d`, `-dd`, `-ddd`) |
| `VULNSCAN_DEBUG_LOG` | `debug.log` | Where the debug log is written, relative to the current directory (`--debug-log`). The file is appended to                                              |

Credentials are written to the log as `$VULNSCAN_*` variable references, never
as values. See [Diagnosing problems](usage.md#diagnosing-problems).

## Precedence

For every setting: command line flag, then environment variable, then the `.env`
file, then the default. The one exception is `.vulnscanignore`, which is always
read in addition to `VULNSCAN_IGNORE_DIRS` or `--ignore`.
