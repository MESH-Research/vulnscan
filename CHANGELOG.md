## Unreleased

### Feat

- **parsers**: read (p)npm constraints from Invenio `webpack.py`
  (`WebpackThemeBundle`) in root project and submodules
- **remediate**: in Invenio apps, update npm dependencies in the site overlay
  `webpack.py` (insert or bump), declaring submodule `webpack.py` files, and
  companion `package.json`; block when pywebpack merge would fail due to
  same-major constraint or other upstream version pins
- **scanner**: after each Invenio scan, perform an in-memory pywebpack merge of
  entry-point webpack bundles; report conflicts with sources and clear
  nearest-safe when blocked
- **reports**: for Invenio projects, add per-finding **Upstream constraints**
  and **Upgrade limit** sections alongside **Declared in** (in details, TUI,
  feeds, ntfy and Teams); empty constraints say `no version constraint`
- **ui**: add activity spinners to the footer line during scans and the
  remediation overlay during upgrade operations (because Invenio ops can be
  slow)

## 1.5.0 (2026-10-11)

### Feat

- **deploy**: add a container health check driven by a run heartbeat

## 1.4.0 (2026-10-10)

### Feat

- **deploy**: add a container image, compose file and entrypoint loop
- **notify**: add --test to send one test message to ntfy and Teams

## 1.3.0 (2026-10-09)

### Feat

- **msteams**: redesign the Teams card as a short, consistent announcement

## 1.2.0 (2026-10-09)

### Feat

- **parsers**: scan npm dependencies from package.json

### Fix

- **remediate**: only rewrite dependencies inside dependency tables of
  pyproject.toml and Pipfile

## 1.1.0 (2026-10-08)

### Feat

- **notify**: post Adaptive Cards to a Microsoft Teams webhook with --msteams
- **ntfy**: push new findings to an ntfy topic and watch continuously
- **parsers**: ignore directories by relative path or glob, from .vulnscanignore
  or --ignore
- **remediate**: rewrite the constraint in every manifest that declares a
  dependency
- **models**: merge a dependency declared in several manifests into one with all
  its locations
- **tui**: mark remediated dependencies with a green tick
- remediate vulnerable dependencies by rewriting manifest constraints
- **wordfence**: throttle feed downloads and use conditional requests
- check WordPress plugins, themes and core via Wordfence Intelligence
- add OSV lookup, scanner, feed generation, CLI and TUI
- scaffold project with manifest parsers and version resolution

### Fix

- **osv**: ignore GIT ranges when collecting fixed versions
