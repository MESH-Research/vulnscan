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