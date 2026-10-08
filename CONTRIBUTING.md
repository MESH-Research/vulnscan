# Contributing to vulnscan

Thank you for considering a contribution. Bug reports, parser fixes for
manifests we mis-read, and new advisory sources are all welcome.

## Getting set up

vulnscan uses [uv](https://docs.astral.sh/uv/) for everything.

```
git clone <repository url>
cd vulnscan
uv sync --all-groups
uv run pytest
uv run ruff check . && uv run ruff format --check .
uv run mkdocs build --strict
```

Tests never touch the network: HTTP clients are given `httpx.MockTransport`
fakes and manifests are written into pytest's `tmp_path`.

## How changes are made

1. Open an issue describing the bug or feature first unless it is trivial.
2. Branch from `main`: `feature/short-description-<issue>` or
   `bug/short-description-<issue>`.
3. Write a failing test, then the code that makes it pass. Tests assert on
   returned values and files written, not on how a function was implemented.
4. Run `uv run ruff check .`, `uv run ruff format .`, `uv run pytest` and, if
   you touched docstrings or `docs/`, `uv run mkdocs build --strict`.
5. Commit with a [Conventional Commits](https://www.conventionalcommits.org/)
   message, for example `fix(parsers): handle Pipfile tables without versions`,
   and reference the issue in the footer. Releases and the changelog are
   generated from these messages by commitizen, so the prefix matters:
   `feat:` bumps the minor version, `fix:` the patch version.
6. Open a pull request against `main`.

## Where things live

```
src/vulnscan/
  cli.py          argument parsing and the non-interactive modes
  config.py       Settings from VULNSCAN_* variables and .env
  models.py       Dependency, Declaration, Vulnerability, Finding, ScanResult
  parsers/        manifest discovery, manifest and lock-file parsers
  osv.py          OSV.dev client
  wordfence.py    Wordfence Intelligence client and cache
  registry.py     available versions from PyPI, Packagist, wordpress.org
  scanner.py      parse -> resolve -> query -> findings
  remediate.py    upgrade planning and manifest rewriting
  feeds.py        RSS and Atom
  reports.py      Markdown and plain text
  notify.py       notification building, sent state and the watch loop
  ntfy.py         ntfy channel
  msteams.py      Microsoft Teams channel (Adaptive Cards)
  tui.py          Textual interface
tests/            one test module per source module
docs/             MkDocs site (guides plus API reference from docstrings)
```

Adding a manifest format means a parser function in `parsers/` that returns
`Dependency` objects, an entry in the discovery table in
`parsers/__init__.py`, and (if upgrades should be supported) an editor in
`remediate.py`. Adding an advisory source means a client exposing
`find_vulnerabilities(deps, include_unknown_versions)` that returns
`{Dependency: [Vulnerability, ...]}`; see `osv.py` and `wordfence.py`.

## Documentation

Guides are Markdown under `docs/`; the API reference is generated from
docstrings. Preview with:

```
uv run mkdocs serve
```

Every public function, class and method needs a docstring because that is
what the reference is built from.

## Code of conduct

Participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md).
