# Spec: vulnscan

## Objective

A terminal application that scans a Python or PHP project's dependency
manifests, looks up known security vulnerabilities for each *direct*
dependency, and publishes the results as RSS 2.0 and Atom 1.0 feeds.

Users:

- A developer who runs the TUI to browse vulnerable dependencies and read the
  CVE / advisory behind each one.
- A cron job that runs the non-interactive mode to refresh the feeds that a
  feed reader subscribes to.

Success looks like: pointing the tool at a project directory and, within a
few seconds, seeing which pinned/locked dependency versions have advisories,
which versions fix them, and having two feed files on disk that reflect the
same information.

## Tech Stack

- Python >= 3.12, packaged and run with `uv`
- `textual` for the TUI
- `httpx` for HTTP (OSV.dev API)
- `python-dotenv` for `.env` loading
- `packaging` for PEP 508 / PEP 440 parsing
- Standard library `tomllib`, `json`, `configparser`, `xml.etree` for
  parsing manifests and rendering feeds
- `pytest` + `pytest-asyncio` for tests, `ruff` for linting

## Commands

```
Install:  uv sync
Test:     uv run pytest
Lint:     uv run ruff check . && uv run ruff format --check .
TUI:      uv run vulnscan [--path DIR]
Feeds:    uv run vulnscan --update-feeds [--path DIR] [--feed-dir DIR]
```

## Project Structure

```
src/vulnscan/
  cli.py            argparse entry point; chooses TUI vs non-interactive
  config.py         Settings loaded from env vars / .env
  models.py         Dependency, Vulnerability, Finding, ScanResult
  parsers/
    __init__.py     manifest discovery and project parsing
    composer.py     composer.json
    python.py       pyproject.toml, requirements*.txt, Pipfile, setup.cfg
    lockfiles.py    composer.lock, uv.lock, poetry.lock, Pipfile.lock
    versions.py     constraint -> exact / minimum version resolution
  osv.py            OSV.dev client and response parsing
  wordfence.py      Wordfence Intelligence client (WordPress core/plugins/themes)
  registry.py       available-version lookup on PyPI, Packagist, wordpress.org
  remediate.py      choose and apply upgrades by rewriting manifest constraints
  scanner.py        orchestration: parse -> resolve -> query -> findings
  feeds.py          RSS / Atom rendering and first-seen state
  reports.py        Markdown and plain-text reports
  ntfy.py           push notifications to an ntfy topic and the watch loop
  tui.py            Textual application
tests/              pytest unit tests, one file per module
docs/               this spec and the plan
```

## Code Style

```python
@dataclass(frozen=True)
class Dependency:
    """A direct dependency declared in a manifest."""

    name: str
    ecosystem: str  # "PyPI" or "Packagist"
    constraint: str  # constraint as written, "" if none
    version: str | None  # resolved exact version, if known
    version_source: str  # "lock" | "pinned" | "constraint" | "unknown"
    source_file: str  # path relative to the project root
    dev: bool = False
```

- Type hints everywhere, dataclasses for data, no inheritance hierarchies
  for parsers (plain functions registered in a table).
- Functions take explicit inputs and return values; no module-level state.
- External I/O (HTTP, filesystem) is injected so tests can substitute fakes.

## Testing Strategy

- `pytest` unit tests under `tests/`, written before implementation against
  `NotImplementedError` stubs, verified red, then made green.
- HTTP is faked with `httpx.MockTransport`; no network access in tests.
- Filesystem fixtures use `tmp_path`.
- TUI is tested with Textual's `run_test()` pilot and an injected fake
  scanner.
- Tests assert on returned values and produced files, not on call counts.

## Boundaries

- Always: run `ruff` and `pytest` before committing; conventional commits.
- Ask first: adding runtime dependencies beyond those listed above.
- Never: commit `.env`; follow transitive dependencies; write feeds when
  the vulnerability lookup failed (stale feeds beat empty ones).

## Functional Requirements

1. Configuration from environment variables, with a `.env` file as a
   fallback. CLI flags override both. Keys are prefixed `VULNSCAN_`.
2. Manifests recognised: `composer.json`, `pyproject.toml`
   (PEP 621 `project.dependencies`, optional dependencies, PEP 735
   dependency groups, Poetry sections), `requirements*.txt` (with `-r`
   includes), `Pipfile`, `setup.cfg`.
3. Exact versions resolved, in priority order, from: a lock file in the same
   directory, an exact pin in the manifest, the lower bound of the
   constraint. Dependencies with no determinable version are reported as
   warnings and not queried (configurable).
4. Vulnerabilities fetched from OSV.dev by package, ecosystem and version.
   Each is presented with its OSV id, CVE aliases, severity, summary,
   details, fixed versions and reference URLs.
5. TUI lists vulnerable dependencies; selecting one lists its
   advisories; selecting an advisory shows the full disclosure. Keys to
   rescan, write feeds, open the advisory in a browser, quit.
6. `--update-feeds` scans and writes both feeds without any UI, exiting
   non-zero if the scan fails.
7. Feed entries have stable ids per (project, dependency, advisory) so
   readers do not re-notify on each regeneration. A small state file
   records when each entry was first seen, used as its published date.
8. Transitive dependencies are never evaluated.
9. A package declared in several manifests (for example
   `requirements/base.txt`, `requirements/production.txt` and
   `pyproject.toml`) at the same resolved version is one dependency with
   several *declarations*. Every output (TUI, reports, feeds, CLI summary)
   lists all of its files, and remediation rewrites the constraint in each
   of them. Different resolved versions remain separate dependencies.
10. Directories can be excluded from manifest discovery by name or by path
    relative to the project root, with shell wildcards, from three places:
    `VULNSCAN_IGNORE_DIRS`, repeatable `--ignore` flags, and a
    `.vulnscanignore` file in the project root (one pattern per line, `#`
    comments). A name pattern (no `/`) matches a directory anywhere in the
    tree; a path pattern matches the project-relative path.
11. ntfy mode (`--ntfy`): a non-interactive loop that rescans every
    `VULNSCAN_NTFY_INTERVAL_MINUTES` and pushes one notification per
    dependency whose (dependency, advisory) pairs have not been sent before
    for this project. The first run therefore sends everything. Sent ids are
    recorded in `VULNSCAN_NTFY_STATE_FILE` under the feed directory only after
    a successful publish, so a failed push is retried on the next cycle.
    `SIGUSR1` re-sends every current finding immediately; `--resend` does the
    same at start-up; `--once` runs a single cycle and exits (for cron);
    `SIGINT`/`SIGTERM` stop the loop. Scan or publish failures are logged and
    never stop the loop. Credentials: `VULNSCAN_NTFY_TOKEN` (bearer) or
    `VULNSCAN_NTFY_USER` / `VULNSCAN_NTFY_PASSWORD` (basic). Messages are
    published as JSON to `VULNSCAN_NTFY_SERVER` for topic `VULNSCAN_NTFY_TOPIC`
    with a priority derived from the worst severity and a click URL to the
    first advisory.
12. The repository is publishable as open source: MIT licence, README with
    an acknowledgement that LLM assistance was used, CONTRIBUTING and
    SECURITY documents, a CI workflow running ruff and pytest, and an MkDocs
    site (human guides plus an API reference generated from docstrings)
    buildable on Read the Docs.

## Success Criteria

- `uv run pytest` passes.
- Scanning a fixture project with a known-vulnerable pin produces a finding
  with the expected advisory id and fixed version (via faked OSV).
- Both feed files validate as well-formed XML with one entry per
  (dependency, advisory) pair.
- The TUI shows the findings table and the advisory detail for a selection.

## Assumptions

- ntfy notifications group by dependency: one message lists all of that
  dependency's newly seen advisories. Resolved advisories are not announced.
- Licence is MIT with the git author as copyright holder; change `LICENSE`
  and `pyproject.toml` if another licence is wanted.
- Documentation uses MkDocs with mkdocstrings so the API reference comes
  straight from docstrings; `.readthedocs.yaml` builds it.

## Open Questions

None blocking. Defaults chosen: feeds written to `./feeds/`, OSV base URL
`https://api.osv.dev`, dev dependencies included, ntfy server
`https://ntfy.sh`, ntfy interval 60 minutes.
