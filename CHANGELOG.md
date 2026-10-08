## 1.1.0 (2026-10-08)

### Feat

- **notify**: post Adaptive Cards to a Microsoft Teams webhook with --msteams
- **ntfy**: push new findings to an ntfy topic and watch continuously
- **parsers**: ignore directories by relative path or glob, from .vulnscanignore or --ignore
- **remediate**: rewrite the constraint in every manifest that declares a dependency
- **models**: merge a dependency declared in several manifests into one with all its locations
- **tui**: mark remediated dependencies with a green tick
- remediate vulnerable dependencies by rewriting manifest constraints
- **wordfence**: throttle feed downloads and use conditional requests
- check WordPress plugins, themes and core via Wordfence Intelligence
- add OSV lookup, scanner, feed generation, CLI and TUI
- scaffold project with manifest parsers and version resolution

### Fix

- **osv**: ignore GIT ranges when collecting fixed versions
