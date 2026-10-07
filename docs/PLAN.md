# Implementation Plan: vulnscan

## Overview

Build bottom-up from data models and parsers, through the OSV client and
scanner, to feeds, CLI and TUI. Each task starts with failing tests.

## Architecture Decisions

- OSV.dev as the single advisory source: free, covers PyPI and Packagist,
  returns CVE aliases, fixed versions and references in one schema.
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

## Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| OSV batch pagination | Med | Follow `next_page_token` per query |
| Loose constraints give wrong version | Med | Prefer lock files; label version source in UI |
| OSV outage empties feeds | High | Fail without writing feeds |
