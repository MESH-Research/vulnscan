# How it works

A scan is a straight pipeline. Each stage is a plain function or a small
client class with its I/O injected, which is what makes the test suite
fast and network-free.

```
discover manifests ──> parse ──> resolve versions ──> merge declarations
        │                                                    │
   .vulnscanignore,                              ┌───────────┴───────────┐
   VULNSCAN_IGNORE_DIRS,                         ▼                       ▼
   composer install paths                   OSV.dev (PyPI,       Wordfence (WordPress
                                            Packagist, npm)      core/plugins/themes)
                                                 │             NVD (container images)
                                                 └───────────┬───────────┘
                                                             ▼
                                                    Finding per dependency
                                                             │
                 ┌───────────────┬───────────────┬───────────┼───────────────┐
                 ▼               ▼               ▼           ▼               ▼
               TUI         RSS / Atom       Markdown /   ntfy / Teams    remediation
                                            plain text   notifications
```

## Discovery and parsing (`vulnscan.parsers`)

`discover_manifests` walks the project, pruning the built-in skip list,
dot-directories, anything a `composer.json` installs into, and the user's
ignore patterns. Each manifest goes to the parser registered for its name
in `parsers/__init__.py`; parsers return `Dependency` records with the
constraint as written and no version yet.

Dockerfiles, Compose files, GitHub Actions workflows and GitLab CI files are
parsed by `parsers/containers.py`: every `FROM`, service `image:`, job
`container:` and CI `services:` entry becomes a dependency in the `Docker`
ecosystem whose constraint is the tag and whose version is read from it,
with `ARG` defaults, `${VAR:-default}` interpolation, an adjacent `.env` and
GitLab `variables:` resolved. The YAML files are read by `parsers/yamlish.py`,
a small block-style reader whose string values remember their line, which is
what lets remediation rewrite exactly the lines that hold images. Discovery
enters `.github/workflows` and `.gitlab/ci` although other hidden directories
are skipped.

`resolve_dependency` then fills in the version from, in order of
preference, a lock file in the same directory (`composer.lock`,
`package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml`,
`uv.lock`, `poetry.lock`, `Pipfile.lock`), an exact pin in the manifest, or
the lower bound of the constraint. Constraint syntax is handled per
ecosystem: PEP 440 specifiers, Composer constraints and npm semver ranges.
`yarn.lock` and `pnpm-lock.yaml` are read with small line-based parsers
rather than a YAML library. A dependency with no determinable version is
reported as a warning and not queried unless
`VULNSCAN_QUERY_UNKNOWN_VERSIONS` is on.

## Declarations (`vulnscan.models`)

`merge_declarations` collapses the same package at the same resolved
version from several manifests into one `Dependency` whose `declarations`
tuple records each file and the constraint written there. `source_files`
and `declared_in_text` give the list and a human-readable form, and
`apply_remediation` iterates the same list when rewriting. The package is
treated as a dev dependency only if every declaration is.

## Advisory sources (`vulnscan.osv`, `vulnscan.wordfence`, `vulnscan.nvd`)

All three clients expose `find_vulnerabilities(deps, include_unknown_versions)`
and return `{Dependency: [Vulnerability, ...]}`. `OSVClient` uses the batch
query endpoint, follows pagination, and fetches each advisory's full record
for the details, severity and ranges. `WordfenceClient` downloads the
production feed once, slims it to the fields vulnscan needs, caches it on
disk, and answers lookups by slug and version range from the cache. Its
throttling rules are described under [Configuration](configuration.md#wordfence).
`NVDClient` maps an image name to a CPE `vendor:product` (built-in table plus
`VULNSCAN_IMAGE_PRODUCTS`), asks NVD for the CVEs matching that product at the
tag's version, turns each record's CPE match ranges into `VersionRange`s and
fixed versions, filters the answer again against those ranges, and caches it
per image version on disk.

`Vulnerability.affects(version, ecosystem)` evaluates the affected ranges
with ecosystem-aware version comparison (`vulnscan.versioncmp`), which is
what remediation planning uses to decide whether a candidate version is
safe.

## Forward-check and preflight

After advisories are collected, `scan` enriches each finding with a forward-checked
`upgrade_plan` (`vulnscan.risk` + `plan_remediation`). `--preflight` does **not** use
project lockfiles as resolve inputs. For each supported Python manifest
(`pyproject.toml`, requirements / `setup.cfg` / `Pipfile`) it builds a tiny temp
project and runs a fresh `uv lock`. Path/editable packages (uv sources and Poetry
path deps) are not resolved as themselves; their PyPI requirements are folded in
recursively from each package's `pyproject.toml` or `setup.cfg`, along with
`[build-system].requires` and `tool.uv` `constraint-dependencies` /
`override-dependencies` / `[[tool.uv.index]]`. For npm, a normal project
mock-locks each `package.json`; in **Invenio mode** it instead builds one
virtual assets `package.json` from the same webpack merge sources as
`invenio webpack create` (`build_virtual_assets_package_json`) and lockfile-only
resolves that, skipping on-disk `package.json` files. For PHP, each
`composer.json` is mock-locked with `composer update --no-install` (path/vcs
repos stripped). Each package is labeled with the build process that produced
it (`uv`, `npm`, `invenio-assets`, or `composer`) in the TUI/JSON. Would-be
versions are scored for bumps and risks against the project's current tree.

## Scanner (`vulnscan.scanner`)

`scan(settings)` is the orchestration: parse, drop dev dependencies if
configured, merge declarations, warn about custom sources, query each
source, and return a `ScanResult` with findings sorted by worst severity
then name. The OSV, Wordfence and NVD clients can be passed in, which is how
the tests inject fakes; the TUI instead injects a whole scan function.

## Outputs

- `vulnscan.feeds` renders RSS and Atom with `xml.etree` and keeps a
  first-seen state file so entry dates and ids are stable.
- `vulnscan.reports` renders Markdown and plain text.
- `vulnscan.notify` builds one `Notification` per dependency with unsent
  advisories, asking the registry (once per dependency) which fixed versions
  are actually published and which upgrade clears every advisory. Each
  channel is a `Target`: a client with a `send()` method plus its own
  sent-state file, so ntfy and Teams track independently. The watch loop in
  `run_watch` is driven by a `WatchControl` whose flags are set by signal
  handlers; tests drive it with a subclass instead of signals.
- `vulnscan.ntfy` renders a notification as text with an ntfy priority;
  `vulnscan.msteams` renders it as an Adaptive Card inside the Teams webhook
  message envelope, trimming details until it fits the 28 KB limit and
  pacing posts under the four-per-second throttle.
- `vulnscan.remediate` plans an upgrade from the registry's version list
  (`vulnscan.registry`) and rewrites constraints textually, preserving the
  operator style and everything else in the file.
- `vulnscan.tui` is the Textual application; `vulnscan.cli` chooses between
  it and the non-interactive modes.

## HTTP activity (`vulnscan.activity`)

`debuglog.Client.send` always streams the response and wraps its byte stream,
so it can publish an immutable `Transfer` snapshot to `vulnscan.activity` when
the request starts, when the headers arrive (status and `Content-Length`),
after every chunk and when the body is fully read or the transport fails.
Observers subscribe with a plain callable and are invoked on the thread doing
the request, so they only record. The TUI keeps the latest snapshot per
transfer under a lock and repaints its `#activity` panel from a timer, through
the pure `render_activity` function, dropping finished transfers after
`LINGER_SECONDS`. `describe` turns a URL into the label shown (`PyPI
requests`, `NVD php:php:8.2.19`).

## Debug logging (`vulnscan.debuglog`)

Every HTTP client is a `debuglog.Client`, a thin `httpx.Client` subclass whose
`send` records the request, the response (or the transport error) and a `curl`
command that replays the request, on the `vulnscan.http` logger at `DEBUG`.
The other modules log their control flow on `vulnscan.<module>` loggers at
`INFO` and finer detail at `DEBUG`. `debuglog.configure(level, path)` is the
only thing that attaches a handler: levels 1 and 2 put a file handler on the
`vulnscan` logger (at `WARNING` and `INFO` respectively, with `vulnscan.http`
forced to `DEBUG`); level 3 puts it on the root logger at `DEBUG` and installs
an `excepthook` so uncaught exceptions are written with their traceback. Secret
values from the settings are mapped to shell variable names and substituted
before anything is written. This is the one place with process-wide state,
mirroring the `logging` module it configures; `debuglog.reset()` undoes it.

## Design rules

- Type hints everywhere, dataclasses for data, no inheritance hierarchies
  for parsers: plain functions registered in a table.
- Functions take explicit inputs and return values; no module-level state.
- External I/O (HTTP, filesystem, signals, sleeping) is injected or
  isolated so tests can substitute fakes.
- Feeds are never written when a lookup failed; stale beats empty.

The original [specification](design/spec.md) and
[implementation plan](design/plan.md) are kept as design notes.
