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
                                            Packagist)           core/plugins/themes)
                                                 └───────────┬───────────┘
                                                             ▼
                                                    Finding per dependency
                                                             │
                 ┌───────────────┬───────────────┬───────────┼───────────────┐
                 ▼               ▼               ▼           ▼               ▼
               TUI         RSS / Atom       Markdown /    ntfy push      remediation
                                            plain text
```

## Discovery and parsing (`vulnscan.parsers`)

`discover_manifests` walks the project, pruning the built-in skip list,
dot-directories, anything a `composer.json` installs into, and the user's
ignore patterns. Each manifest goes to the parser registered for its name
in `parsers/__init__.py`; parsers return `Dependency` records with the
constraint as written and no version yet.

`resolve_dependency` then fills in the version from, in order of
preference, a lock file in the same directory (`composer.lock`, `uv.lock`,
`poetry.lock`, `Pipfile.lock`), an exact pin in the manifest, or the lower
bound of the constraint. A dependency with no determinable version is
reported as a warning and not queried unless
`VULNSCAN_QUERY_UNKNOWN_VERSIONS` is on.

## Declarations (`vulnscan.models`)

`merge_declarations` collapses the same package at the same resolved
version from several manifests into one `Dependency` whose `declarations`
tuple records each file and the constraint written there. `source_files`
and `declared_in_text` give the list and a human-readable form, and
`apply_remediation` iterates the same list when rewriting. The package is
treated as a dev dependency only if every declaration is.

## Advisory sources (`vulnscan.osv`, `vulnscan.wordfence`)

Both clients expose `find_vulnerabilities(deps, include_unknown_versions)`
and return `{Dependency: [Vulnerability, ...]}`. `OSVClient` uses the batch
query endpoint, follows pagination, and fetches each advisory's full record
for the details, severity and ranges. `WordfenceClient` downloads the
production feed once, slims it to the fields vulnscan needs, caches it on
disk, and answers lookups by slug and version range from the cache. Its
throttling rules are described under [Configuration](configuration.md#wordfence).

`Vulnerability.affects(version, ecosystem)` evaluates the affected ranges
with ecosystem-aware version comparison (`vulnscan.versioncmp`), which is
what remediation planning uses to decide whether a candidate version is
safe.

## Scanner (`vulnscan.scanner`)

`scan(settings)` is the orchestration: parse, drop dev dependencies if
configured, merge declarations, warn about custom sources, query each
source, and return a `ScanResult` with findings sorted by worst severity
then name. Clients can be passed in, which is how the tests and the TUI
inject fakes.

## Outputs

- `vulnscan.feeds` renders RSS and Atom with `xml.etree` and keeps a
  first-seen state file so entry dates and ids are stable.
- `vulnscan.reports` renders Markdown and plain text.
- `vulnscan.ntfy` builds one message per dependency with unsent advisories,
  publishes through ntfy's JSON API, and keeps its own sent-state file. The
  watch loop in `run_watch` is driven by a `WatchControl` whose flags are set
  by signal handlers; tests drive it with a subclass instead of signals.
- `vulnscan.remediate` plans an upgrade from the registry's version list
  (`vulnscan.registry`) and rewrites constraints textually, preserving the
  operator style and everything else in the file.
- `vulnscan.tui` is the Textual application; `vulnscan.cli` chooses between
  it and the non-interactive modes.

## Design rules

- Type hints everywhere, dataclasses for data, no inheritance hierarchies
  for parsers: plain functions registered in a table.
- Functions take explicit inputs and return values; no module-level state.
- External I/O (HTTP, filesystem, signals, sleeping) is injected or
  isolated so tests can substitute fakes.
- Feeds are never written when a lookup failed; stale beats empty.

The original [specification](design/spec.md) and
[implementation plan](design/plan.md) are kept as design notes.
