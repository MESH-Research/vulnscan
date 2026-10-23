# Usage

Every mode reads its settings from `VULNSCAN_*` environment variables or a
`.env` file, and flags override both. The examples below pass `--path`
explicitly; set `VULNSCAN_PROJECT_PATH` to avoid repeating it.

## Interactive TUI

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

The left table lists vulnerable dependencies: package, ecosystem, resolved
version and where that version came from (`lock`, `pinned` or `constraint`),
worst severity, number of advisories, fixed versions, and the **File**
column, which names every manifest declaring the package. The top-right
table lists the advisories for the selected dependency with their CVE ids.
The bottom-right pane shows the full disclosure: severity and CVSS vector,
aliases, fixed versions, each declaring file with the constraint written
there, the advisory text and all reference links.

## Outdated packages (any update, not only security)

```
uv run vulnscan --outdated --path /path/to/project
```

The same interface in **outdated mode**. The left table lists every direct
dependency with a newer stable release, whether or not an advisory affects
it: package, ecosystem, installed version and its source, the newest release
in the current series, the latest release, the number of known advisories
affecting the installed version (or `none`) and the declaring files. A banner
under the header and the window title state that these are routine updates,
not security advisories. The detail pane describes the available update; a
package that does have advisories still lists them in the top-right table.

`u` offers two choices, see [Upgrading dependencies](remediation.md#routine-updates):
the newest release in the current `major.minor` series (disabled when there
is none) and the latest release. `--outdated` is interactive only and is
rejected alongside any non-interactive flag.

## Feeds for a feed reader (cron)

```
uv run vulnscan --update-feeds --path /path/to/project --feed-dir /var/www/feeds
```

Scans, rewrites both feeds, prints a summary and exits 0. If an advisory
source cannot be reached it exits 1 and leaves the existing feeds untouched,
so a transient outage never makes vulnerabilities disappear from your
reader. See [Feeds and reports](feeds.md).

## Markdown and plain-text reports

```
uv run vulnscan --markdown --text --path /path/to/project      # <feed dir>/vulns.md and vulns.txt
uv run vulnscan --markdown report.md --path /path/to/project   # explicit file
uv run vulnscan --text - --path /path/to/project               # to stdout
uv run vulnscan --update-feeds --markdown --text               # feeds and both reports
```

## Upgrading a dependency from the command line

```
uv run vulnscan --remediate requests --path /path/to/project
uv run vulnscan --remediate wp-plugin/elementor --strategy latest --path /path/to/project
```

See [Upgrading dependencies](remediation.md). Every candidate version is
forward-checked before it is offered; see
[Forward check](remediation.md#forward-check).

## Continuous monitoring with notifications

```
uv run vulnscan --ntfy --path /path/to/project
uv run vulnscan --msteams --path /path/to/project
uv run vulnscan --ntfy --msteams --path /path/to/project
```

See [Notifications](notifications.md).

## Skipping directories

```
uv run vulnscan --ignore web/app/plugins/graveyard --ignore "*-old" --path /path/to/project
```

Or list patterns in a `.vulnscanignore` file in the project root. See
[Ignoring directories](ignoring.md).

## Supported manifests

| Ecosystem | Manifests | Lock files used for versions |
|-----------|-----------|------------------------------|
| Python (PyPI) | `pyproject.toml` (PEP 621, PEP 735 dependency groups, Poetry), `requirements*.txt` and `requirements/*.txt` with `-r` includes, `Pipfile`, `setup.cfg` | `uv.lock`, `poetry.lock`, `Pipfile.lock` |
| PHP (Packagist) | `composer.json` | `composer.lock` |
| WordPress | `composer.json` entries for `wp-plugin/*`, `wp-theme/*`, `wpackagist-plugin/*`, `wpackagist-theme/*`, `roots/wordpress`, `johnpbloch/wordpress`, and any package the lock file types as `wordpress-plugin`, `wordpress-muplugin`, `wordpress-theme` or `wordpress-core` | `composer.lock` |
| Node.js (npm) | `package.json` (`dependencies`, `optionalDependencies`, `devDependencies`; `npm:` aliases followed; git, path, tarball and workspace specs skipped; `peerDependencies` ignored) | `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock` (classic and Berry), `pnpm-lock.yaml` (root importer) |
| Container images (Docker) | `Dockerfile`, `Containerfile`, `Dockerfile.<x>`, `<x>.Dockerfile` (every `FROM`, with `ARG` defaults substituted; build-stage references and `scratch` skipped); `docker-compose*.yml`/`.yaml` and `compose*.yml`/`.yaml` (every service `image:`, with `${VAR:-default}` and a `.env` beside the file resolved); `.github/workflows/*.yml` (job `container:`, `services:` and `uses: docker://` steps; `${{ }}` expressions skipped); `.gitlab-ci.yml`, `*.gitlab-ci.yml` and `.gitlab/ci/*.yml` (top-level, `default:` and job `image:` and `services:`, with `$VAR` resolved from the file's `variables:`) | none: the version is the image tag |

Lock files resolve the versions of direct dependencies; for `yarn.lock`, a
package that appears at several versions is taken at the first one listed.
With `--transitive` the other packages they record are scanned too.

## Container images

A container image is a dependency like any other: `FROM php:8.2.19-fpm-bookworm`
is PHP 8.2.19 declared in `Dockerfile`, `image: traefik:v2.10` in a Compose
file is Traefik 2.10, and `container: php:8.2.19-cli` in a GitHub Actions job
or `image: php:8.2.19-cli` in `.gitlab-ci.yml` is the PHP your tests run on.
The same image at the same tag in several of these files is one finding that
lists every file. The tag supplies the version: a full `major.minor.patch`
counts as pinned, a shorter series such as `8.2` or `v2.10` as a floating
constraint whose lower bound is checked (so advisories against any `8.2.x` are
reported until you pin a patched tag), and a tag with no number (`latest`,
`bookworm-slim`) as unknown, with a warning asking you to pin one.

Advisories for images come from the [NVD](https://nvd.nist.gov). vulnscan maps
well-known images (`php`, `python`, `node`, `nginx`, `httpd`, `traefik`,
`caddy`, `postgres`, `mysql`, `mariadb`, `mongo`, `redis`, `rabbitmq`,
`elasticsearch`, `grafana/grafana`, `quay.io/keycloak/keycloak`,
`hashicorp/vault`, `wordpress`, `nextcloud`, `gitlab/gitlab-ce` and others) to
the CPE vendor and product NVD records CVEs against. An image outside that list
is reported once as a warning; add your own mapping with
`VULNSCAN_IMAGE_PRODUCTS=myorg/app=vendor:product`. Operating-system bases
(`debian`, `ubuntu`, `alpine`, `busybox` and the like) are listed but not
queried. Because NVD describes the software, not the image build, a CVE that
only applies on Windows or in a feature you do not use can still be reported;
read the advisory text before acting.

Pressing `u` on an image, or `--remediate php`, rewrites the tag wherever it is
declared (see [Upgrading dependencies](remediation.md#container-images)).

## Transitive dependencies

```
uv run vulnscan --transitive --path /path/to/project
uv run vulnscan --transitive --outdated --path /path/to/project
```

By default only packages declared in a manifest are scanned. `--transitive`
(or `VULNSCAN_TRANSITIVE=true`) adds every package recorded in a lock file
next to a manifest: `uv.lock`, `poetry.lock`, `Pipfile.lock`,
`composer.lock`, `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock` and
`pnpm-lock.yaml`. The TUI's **Via** column reads `lock (transitive)`, and
wherever a declaring file is listed the entry reads
`uv.lock (transitive; required by httpcore, httpx)`. Requirers come from
`uv.lock`, `poetry.lock`, `composer.lock` and `package-lock.json`; `Pipfile.lock`,
`yarn.lock` and `pnpm-lock.yaml` list the package without them. The project's
own package in `uv.lock` is never listed, and `composer.lock` types such as
`wordpress-plugin` are honoured, so a transitive WordPress plugin is checked
against Wordfence like a direct one. `VULNSCAN_INCLUDE_DEV=false` drops
packages the lock marks as development-only.

A transitive package has no manifest line to rewrite, so pressing `u` (after
a confirmation dialog) or running `--remediate` inserts a constraint into the
manifest next to the lock file instead; see
[Upgrading dependencies](remediation.md#transitive-dependencies).

## Preflight: what the next resolve would pull in

```
uv run vulnscan --preflight --path /path/to/project                    # interactive
uv run vulnscan --preflight --json - --path /path/to/project           # machine-readable, for CI
uv run vulnscan --preflight --text --update-feeds --strict-fresh --path /path/to/project
```

A scan reports on the versions you have. `--preflight` reports on the versions
you would get: for each manifest it copies the registry constraints into an
empty temporary project, runs a fresh resolve there without your lock files,
compares the would-be versions with the current tree and scores every package
that would change or that carries a risk. The project is never modified and no
lock file of yours is written.

| Manifest                                                                                              | Resolver                                                                                                              | Label             |
| ----------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ----------------- |
| `pyproject.toml` (PEP 621, PEP 735 groups, Poetry), `requirements*.txt`, `setup.cfg`, `Pipfile`       | `uv lock`                                                                                                             | `uv`              |
| `package.json`                                                                                        | `npm install --package-lock-only --ignore-scripts`, or `pnpm install --lockfile-only --ignore-scripts` when `packageManager` names pnpm | `npm`             |
| Invenio theme bundles (see [Invenio / webpack.py](invenio.md#preflight-preflight))                                        | one virtual assets `package.json`, resolved the same way                                                              | `invenio-assets`  |
| `composer.json`                                                                                       | `composer update --no-install --no-interaction --ignore-platform-reqs --no-scripts --no-plugins`                      | `composer`        |

The resolver must be installed (`uv`, `npm` or `pnpm`, `composer`). A manifest
whose resolve fails is reported as a warning with the tool's output, and when
none succeeds the run fails. Path, editable, git, URL and workspace
dependencies cannot be fetched from a registry: local path packages contribute
their own PyPI requirements, the rest are dropped with a warning.
`[build-system].requires`, uv constraint and override dependencies and
`[[tool.uv.index]]` entries are honoured. Container images and `webpack.py`
are skipped. Because the resolve is complete, the result covers the transitive
packages it would install, not only the direct ones.

Each would-be version is checked for four kinds of risk:

- **advisory**: an OSV advisory affects that exact version;
- **malware**: the advisory is a malicious-package report (OSV `MAL-` ids and
  records marked as such);
- **yanked**: the release has been withdrawn (PyPI yanked files, npm
  unpublished versions);
- **fresh**: it was published less than `VULNSCAN_FRESH_HOURS` ago (default
  24), the window in which a hijacked package does the most damage. PyPI,
  npm and Packagist give publish times; wordpress.org and container
  registries do not, so their versions are never fresh.

Alone, `--preflight` opens the TUI with a **Preflight** table: package,
ecosystem, build process, current version, would-be version, risks and
declaring file; `f` writes the preflight feeds and `r` resolves again. With
`--json`, `--text`, `--markdown` or `--update-feeds` it runs non-interactively
and writes `preflight.json`, `preflight.txt`, `preflight.md` or
`preflight.rss.xml` / `preflight.atom.xml` in the feed directory (`-` sends
JSON, text or Markdown to stdout). The JSON carries `schema_version`,
`resolve_ok`, a `summary` of counts, each package with its `current`,
`would_be`, `build_process` and `risks`, the `ignored` packages and the
`warnings`.

The exit code is 0 when nothing blocks, 1 when a package carries an advisory,
malware or yanked risk or no manifest could be resolved, and, with
`--strict-fresh` (or `VULNSCAN_STRICT_FRESH=true`), 2 when freshness is the
only problem. Exclude packages you accept with `--preflight-ignore NAME`
(repeatable or comma separated; a `pypi:`, `npm:`, `packagist:` or
`wordpress:` prefix and shell wildcards are allowed), with
`VULNSCAN_PREFLIGHT_IGNORE`, or with a `.vulnscan-preflight-ignore` file in the
project root, one pattern per line with `#` comments. Excluded packages are
still listed, under *ignored*, but never affect the exit code; a pattern that
matches nothing is a warning. `--preflight` cannot be combined with `--ntfy`,
`--msteams`, `--test` or `--remediate`.

## A package declared in several files

Projects often declare the same package more than once: a
`requirements/base.txt` included by `requirements/production.txt`, a
`pyproject.toml` alongside a `requirements.txt`, or a Poetry group that
repeats a main dependency. vulnscan treats each package *at the same resolved
version* as one dependency with several declarations. Every output lists all
of its files, and an upgrade rewrites the constraint in each of them. If the
files resolve to different versions (say `==1.2.0` in one and `==1.3.0` in
another) they stay separate, because they may have different advisories.

## Diagnosing problems

```
uv run vulnscan --update-feeds --path /path/to/project -d                        # writes ./debug.log
uv run vulnscan --update-feeds --path /path/to/project -dd --debug-log /tmp/vulnscan.log
```

When an advisory source answers with an error, or the result is not what you
expect, `-d` / `--debug` writes a diagnostic log through Python's standard
`logging` framework. Repeating the flag raises the verbosity; `VULNSCAN_DEBUG`
takes the same number.

| Flag   | `VULNSCAN_DEBUG` | What is recorded                                                                                                                                                                                                                                                                             |
| ------ | ---------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `-d`   | `1`              | Every outgoing HTTP request (method, URL, headers, body size) and its response (status, headers, body, elapsed time), each request followed by a `curl` command that repeats it exactly; plus every warning and error                                                                       |
| `-dd`  | `2`              | Also the control flow: which manifests were parsed, how many packages went to each source, cache and rate-limit decisions, registry lookups, upgrade plans, the resolver commands preflight runs and their exit codes, watch-mode cycles                                                    |
| `-ddd` | `3`              | Also `DEBUG` records from vulnscan and from every library it uses (httpx, httpcore, Textual), the stdout and stderr of preflight resolvers, and a full traceback for any uncaught exception                                                                                                   |

The log goes to `debug.log` in the current directory unless `--debug-log FILE`
or `VULNSCAN_DEBUG_LOG` says otherwise. It is appended to, and each run starts
with a banner naming the version, level, command line and Python version.
Response bodies longer than 16 KB are cut; request bodies never are, because
the `curl` command has to be complete. A request and its response share a
`#n` number so they can be matched when several run at once.

Credentials never reach the file. Wherever the Wordfence or NVD key, the ntfy
token or password, or the Teams webhook URL would appear, the log writes the
shell variable instead, for example
`-H "Authorization: Bearer $VULNSCAN_WORDFENCE_API_KEY"`, so a pasted command
works as soon as the variables are exported (`set -a; . ./.env; set +a` in
bash). The short-lived anonymous pull tokens that container registries issue
are the one credential written as is.

The records live in the `vulnscan.*` logger hierarchy, so a program that
imports vulnscan can configure `logging` itself instead of using the flag:
`vulnscan.http` carries the HTTP records at `DEBUG`, and the other modules log
their control flow at `INFO`.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | The scan failed (advisory source unreachable), the package to remediate was not found, or no suitable version exists; in `--preflight`, a package carries an advisory, malware or yanked risk, or no manifest could be resolved |
| 2 | Invalid configuration, such as `--ntfy` without a topic or `--msteams` without a webhook URL; in `--preflight --strict-fresh`, freshness is the only risk found |
