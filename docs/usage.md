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

See [Upgrading dependencies](remediation.md).

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

Lock files resolve the versions of direct dependencies; for `yarn.lock`, a
package that appears at several versions is taken at the first one listed.
With `--transitive` the other packages they record are scanned too.

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

## A package declared in several files

Projects often declare the same package more than once: a
`requirements/base.txt` included by `requirements/production.txt`, a
`pyproject.toml` alongside a `requirements.txt`, or a Poetry group that
repeats a main dependency. vulnscan treats each package *at the same resolved
version* as one dependency with several declarations. Every output lists all
of its files, and an upgrade rewrites the constraint in each of them. If the
files resolve to different versions (say `==1.2.0` in one and `==1.3.0` in
another) they stay separate, because they may have different advisories.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | The scan failed (advisory source unreachable), the package to remediate was not found, or no suitable version exists |
| 2 | Invalid configuration, such as `--ntfy` without a topic or `--msteams` without a webhook URL |
