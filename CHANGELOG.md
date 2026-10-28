## 1.12.1 (2026-10-28)

### Fix

- **nvd**: drop CVEs that name a container image only as a platform

## 1.12.0 (2026-10-27)

## 1.11.2 (2026-10-27)

### Feat

- **preflight**: TUI p/n mode switch, WEBPACKEXT pnpm, and merge-tree detail

### Fix

- **sources**: carry on when an advisory source fails and share the NVD rate limit
- **tui**: assert mode banner is hidden in normal mode, not absent

## 1.11.1 (2026-10-23)

### Fix

- **tui**: ignore the activity timer firing after the screen is torn down
- **preflight**: report a missing resolver binary instead of aborting the run

## 1.11.0 (2026-10-23)

### Feat

- **tui**: show every HTTP request with a progress bar in an activity panel
- **cli**: add --debug log with curl commands for every API request

### Fix

- **scanner**: keep container images out of OSV batches in the forward check

## 1.10.0 (2026-10-23)

### Feat

- forward-check upgrade plans and pin-float preflight

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

## 1.12.0 (2026-10-24)

### Feat

- **tui**: ``p`` runs preflight from normal/outdated mode; ``n`` restores the last
  scan or runs a fresh one (honouring ``--outdated``) when started in preflight;
  switching back to preflight reuses the cached report when settings and session
  remediations are unchanged (``r`` / ``p`` while already in preflight still refresh)
- **tui / preflight**: detail pane and JSON include ``resolve_from`` (mock-lock site) and,
  in Invenio mode, ``upstream_constraints`` (per-file merge-tree constraints, scan-parity)
- **preflight**: choose pnpm when ``invenio.cfg`` sets ``WEBPACKEXT_NPM_PKG_CLS`` to
  ``PNPMPackage`` (else ``packageManager: pnpm@…``, else npm); restore a missing root
  ``package.json`` ``packageManager`` field (and align ``engines``) when the cfg requires pnpm

## 1.11.2 (2026-10-27)

### Fix

- **sources**: carry on when an advisory source fails and share the NVD rate limit


## 1.11.1 (2026-10-23)

### Fix

- **tui**: ignore the activity timer firing after the screen is torn down
- **preflight**: report a missing resolver binary instead of aborting the run

## 1.11.0 (2026-10-23)

### Feat

- **tui**: show every HTTP request with a progress bar in an activity panel
- **cli**: add --debug log with curl commands for every API request

### Fix

- **scanner**: keep container images out of OSV batches in the forward check

## 1.10.0 (2026-10-23)

### Feat

- forward-check upgrade plans and pin-float preflight

## 1.9.0 (2026-10-22)

### Feat

- **parsers**: read container images from GitHub Actions and GitLab CI files
- **remediate**: upgrade container image tags in Dockerfiles and Compose files
- **nvd**: check container images against the NVD
- **parsers**: read container images from Dockerfiles and Compose files

## 1.8.0