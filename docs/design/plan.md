# Implementation Plan: vulnscan

## Overview

Build bottom-up from data models and parsers, through the OSV client and
scanner, to feeds, CLI and TUI. Each task starts with failing tests.

## Architecture Decisions

- OSV.dev as the advisory source for PyPI and Packagist: free, returns CVE
  aliases, fixed versions and references in one schema. Wordfence
  Intelligence added later for WordPress, as a locally cached feed because
  its API is a single bulk download with strict rate limits.
- Notifications share one builder (`notify.py`) and treat ntfy and Teams as
  interchangeable channels with separate sent-state, so more channels can
  be added without touching the loop.
- Lock files only resolve versions of direct dependencies; manifests define
  the dependency set. This satisfies "no transitive evaluation".
- Hand-rolled RSS/Atom via `xml.etree` to avoid an lxml dependency.
- `httpx.MockTransport` for HTTP fakes; no extra test dependencies.

## Task List

### Phase 1: Foundation
- [x] Task 1: Project scaffold (pyproject, uv, ruff, pytest, workflow)
- [x] Task 2: Models and config loading (`models.py`, `config.py`)
- [x] Task 3: Version resolution helpers (`parsers/versions.py`)

### Phase 2: Parsers
- [x] Task 4: Python manifests (`parsers/python.py`)
- [x] Task 5: Composer manifest (`parsers/composer.py`)
- [x] Task 6: Lock files (`parsers/lockfiles.py`)
- [x] Task 7: Discovery and project parsing (`parsers/__init__.py`)

### Checkpoint: parsers green

### Phase 3: Lookup and output
- [x] Task 8: OSV client and response parsing (`osv.py`)
- [x] Task 9: Scanner orchestration (`scanner.py`)
- [x] Task 10: Feeds and state (`feeds.py`)

### Phase 4: Interfaces
- [x] Task 11: CLI with non-interactive mode (`cli.py`)
- [x] Task 12: TUI (`tui.py`)
- [x] Task 13: README, .env.example

### Phase 5: Multiple declarations, ignores, ntfy, open source
- [x] Task 14: `Declaration` model, `merge_declarations`, scanner uses it (`models.py`, `scanner.py`)
- [x] Task 15: Remediation edits every declaring manifest (`remediate.py`, `cli.py`, `tui.py`)
- [x] Task 16: All outputs list every declaring file (`reports.py`, `feeds.py`, `tui.py`, `cli.py`)
- [x] Task 17: Ignore patterns by name/path/glob, `.vulnscanignore`, `--ignore` (`parsers/__init__.py`, `config.py`, `cli.py`)
- [x] Task 18: ntfy client, message building and sent-state (`ntfy.py`, `config.py`)
- [x] Task 19: Watch loop with signals and `--ntfy/--once/--resend/--interval` (`ntfy.py`, `cli.py`)
- [x] Task 20: Open-source packaging: LICENSE, CONTRIBUTING, SECURITY, CI, metadata, README
- [x] Task 21: MkDocs site with API reference, `.readthedocs.yaml`, docstrings

### Phase 6: Microsoft Teams
- [x] Task 22: Shared `notify.py` (notifications with registry-backed fix availability, per-channel state, watch loop); ntfy becomes a channel
- [x] Task 23: `msteams.py` Adaptive Card renderer and webhook client, `--msteams`, `VULNSCAN_INTERVAL_MINUTES` rename
- [x] Task 24: Docs for both channels

### Phase 7: Node.js
- [x] Task 25: `package.json` parser, npm semver resolution, npm comparison rules (`parsers/node.py`, `parsers/versions.py`, `versioncmp.py`)
- [x] Task 26: `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml` readers (`parsers/lockfiles.py`)
- [x] Task 27: npm registry versions and `package.json` rewriting (`registry.py`, `remediate.py`), docs

### Checkpoint: Phase 5
- [x] `uv run pytest` and `uv run ruff check .` clean, `mkdocs build --strict` clean

## Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| OSV batch pagination | Med | Follow `next_page_token` per query |
| Loose constraints give wrong version | Med | Prefer lock files; label version source in UI |
| OSV outage empties feeds | High | Fail without writing feeds |
| ntfy outage loses notifications | Med | Record ids as sent only after a 2xx; retry next cycle |
| Partial multi-file remediation | Med | Compute every rewrite before writing any file |
| Teams rejects messages over 28 KB or throttles bursts | Med | Trim details, then advisories, until the card fits; pace posts at under four per second |
