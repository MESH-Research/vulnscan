## 1.12.0 (2026-10-24)

### Feat

- **tui**: ``p`` runs preflight from normal/outdated mode; ``n`` restores the last scan
- **tui / preflight**: detail pane and JSON include ``resolve_from`` (mock-lock site) and,
  in Invenio mode, ``upstream_constraints`` (per-file merge-tree constraints, scan-parity)
- **preflight**: choose pnpm when ``invenio.cfg`` sets ``WEBPACKEXT_NPM_PKG_CLS`` to
  ``PNPMPackage`` (else ``packageManager: pnpm@…``, else npm); restore a missing root
  ``package.json`` ``packageManager`` field (and align ``engines``) when the cfg requires pnpm

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