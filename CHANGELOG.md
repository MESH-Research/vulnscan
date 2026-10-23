## Unreleased

### Added
- Always-on **forward-check** for remediation candidates via OSV/Wordfence + registry metadata.
- **`--preflight`** per-manifest mock lock (no project lockfile inputs; path/editable
  sources dropped), TUI/JSON/feeds/excludes, CI exit codes. Invenio mode mock-locks a
  virtual assets `package.json` from the full webpack merge tree (not on-disk
  `package.json` files). Composer mock-lock via `composer update --no-install`.
  Packages carry a build-process label (`uv` / `npm` / `invenio-assets` / `composer`).
- `RegistryClient.release_info`; renamed `parsers.webpack` to `parsers.invenio_webpack`.

## 1.9.0 (2026-10-22)

### Feat

- **parsers**: read container images from GitHub Actions and GitLab CI files
- **remediate**: upgrade container image tags in Dockerfiles and Compose files
- **nvd**: check container images against the NVD
- **parsers**: read container images from Dockerfiles and Compose files

## 1.8.0