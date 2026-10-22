## 1.9.0 (2026-10-22)

### Feat

- **parsers**: read container images from GitHub Actions and GitLab CI files
- **remediate**: upgrade container image tags in Dockerfiles and Compose files
- **nvd**: check container images against the NVD
- **parsers**: read container images from Dockerfiles and Compose files

## 1.8.0 (2026-10-21)

### Feat

- **remediate**: pin transitive dependencies by inserting a constraint
- **scan**: scan transitive dependencies from lock files

## 1.7.0 (2026-10-21)

### Feat

- **tui**: add --outdated mode listing packages with newer releases

## 1.6.0 (2026-10-21)

### Feat

- **invenio**: add InvenioRDM project scanning and remediation support

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
