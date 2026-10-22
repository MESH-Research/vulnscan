# Upgrading dependencies

Select a vulnerable dependency in the TUI and press `u`, or run
`--remediate PACKAGE` from the command line. vulnscan looks up the versions
published for the package (PyPI, Packagist, npm or wordpress.org, or the tags
on a container image's registry) and offers two choices:

- **Nearest safe version**: the smallest upgrade above the current version
  that is outside every known advisory's affected range. This keeps you as
  close as possible to what you have: `symfony/http-kernel` 5.4.0 goes to
  5.4.20, not 6.x.
- **Latest release**: the newest stable version. If even that is still
  affected by an open advisory, the option says so.

Pre-release and yanked versions are never offered.

## Routine updates

`vulnscan --outdated` lists dependencies with newer releases regardless of
advisories. There `u` offers two different choices, and the dialog says that
the upgrade is not a security fix:

- **Newest release in the current series**: the newest version sharing the
  installed version's `major.minor`. On 2.6.1 with 2.6.2 and 2.7.2 published
  this is 2.6.2; it is disabled when the series has nothing newer.
- **Latest release**: the newest stable version.

If known advisories still affect the chosen version, the option says so.
What gets edited is the same as below.

## What gets edited

The constraint is rewritten in **every manifest that declares the package**
at that version, and nothing else in those files changes: ordering, comments
and indentation are preserved. The operator style is kept:

| Before | After |
|--------|------|
| `3.13.4` | `4.1.4` |
| `^12.2` | `^16.3` |
| `~4.18.2` (npm) | `~4.19.2` |
| `4.x` (npm) | `^4.19.2` |
| `requests==2.30.0` | `requests==2.32.4` |
| `Django>=4.2,<5` | `Django>=4.2.11,<5` |

Supported manifests: `composer.json`, `package.json`, `requirements*.txt`
and `requirements/*.txt`, `pyproject.toml` (PEP 621 strings, PEP 735 groups
and Poetry tables), `Pipfile` and `setup.cfg`. Composer constraints that
track a development branch (`dev-main`) are left for you to change by hand.
npm ranges that are not a single exact, `^`, `~`, `>=` or `=` version
(`x` ranges, `*`, hyphen ranges, `||` alternatives) become a caret range.

Every rewrite is computed before any file is written. If one of the
declaring files cannot be edited (it has changed since the scan, or its
format is unsupported) nothing is written and the error names the file.

## Container images

For an image the "constraint" is its tag, and the candidates are the tags on
its registry (Docker Hub, ghcr.io, quay.io or any registry speaking the
standard Docker Registry API) that carry the same variant suffix and are at
least as specific as the current tag. On `php:8.2.19-fpm-bookworm` the
candidates are the other `*-fpm-bookworm` tags, so the upgrade is
`php:8.2.20-fpm-bookworm` and never a `-cli` or `-alpine` image.

| Before | After |
|--------|------|
| `FROM php:8.2.19-fpm-bookworm` | `FROM php:8.2.20-fpm-bookworm` |
| `image: traefik:v2.10.7` | `image: traefik:v2.11.3` |
| `FROM php:8.2.19@sha256:…` | `FROM php:8.2.20` (the digest pinned the old content) |
| `ARG PHP_VERSION=8.2.19` + `FROM php:${PHP_VERSION}-fpm` | `ARG PHP_VERSION=8.2.20` |
| `image: traefik:${TRAEFIK_TAG:-v2.10.7}` | `image: traefik:${TRAEFIK_TAG:-v2.11.3}` |

Every `FROM`, service `image:`, GitHub Actions `container:`/`services:`/
`uses: docker://` and GitLab CI `image:`/`services:` entry naming that image at
that tag is rewritten, across all the files that declare it. In YAML files
only the lines the parser identified as images change, so a look-alike value
in an environment variable or a script line is left alone. A tag
that comes from a variable with no default in the file (`${TRAEFIK_TAG}` set
only in `.env` or the environment) is left alone and the error names the
variable, so you can change it where it is defined.

## After the edit

Lock files are not touched. The status bar (or the command line output)
tells you the command to run next for each manifest, such as
`composer update wp-plugin/elementor --with-dependencies`, `npm install`
(or `yarn install` / `pnpm install` when that tool's lock file is present),
`uv lock && uv sync`, `poetry lock && poetry install`, `pipenv lock &&
pipenv sync`, `pip install -e .` for a `setup.cfg`, or `pip install -r
base.txt` (with the directory to run it in when the manifest is not at the
project root). For a Dockerfile it asks you to rebuild the image; for a
Compose file, to run `docker compose pull && docker compose up -d`; for a CI
configuration, to commit and push.
Press `r` afterwards to rescan.

In the TUI the dependency's row and its advisories turn green with a ✔
"upgraded" marker so you can see what you have already dealt with. The
marker persists across rescans in the same session, since the dependency
keeps showing as vulnerable until the lock file is updated.

## Transitive dependencies

A package that only a lock file records (see `--transitive`) is not declared
anywhere, so there is no constraint to rewrite. Instead vulnscan **inserts**
one into the manifest next to that lock file. Pressing `u` first shows a
confirmation dialog naming the file, the section and the exact text that
will be added, with one option per candidate version (nearest safe and
latest, or newest-in-series and latest in outdated mode); Esc leaves the
file untouched. `--remediate` inserts the constraint straight away and prints
`Added certifi>=2026.10.19 to pyproject.toml`.

| Lock file | Manifest and section | Entry |
|-----------|---------------------|-------|
| `uv.lock`, `poetry.lock` | `pyproject.toml`: `[project] dependencies`, or the `[tool.poetry.dependencies]` table when there is no `[project]` table; `requirements.txt` when there is no `pyproject.toml` | `"certifi>=2026.10.19"` / `certifi = ">=2026.10.19"` / `certifi>=2026.10.19` |
| `Pipfile.lock` | `Pipfile`: `[packages]` | `certifi = ">=2026.10.19"` |
| `composer.lock` | `composer.json`: `require` | `"psr/log": "^3.0.1"` |
| `package-lock.json`, `npm-shrinkwrap.json` | `package.json`: `overrides` | `"cookie": "^0.6.0"` |
| `yarn.lock` | `package.json`: `resolutions` | `"cookie": "^0.6.0"` |
| `pnpm-lock.yaml` | `package.json`: `pnpm.overrides` | `"cookie": "^0.6.0"` |

The entry goes first in an existing array or object, a missing
`overrides`/`resolutions`/`pnpm` section is appended to `package.json`, and
a missing `dependencies` array is added under `[project]`. Formatting and
everything else in the file stay as they were. If the section already names
the package (an older override, say) its value is replaced. Then run the
lock tool the status line suggests, and rescan.

When no manifest can take the entry (no `pyproject.toml` or
`requirements.txt` next to `uv.lock`, or an Invenio project whose
`package.json` is generated) nothing is written. The status line, or the
error with exit code 1, then says what requires the package and which
constraint to add by hand.

## Command line

```
uv run vulnscan --remediate wp-plugin/elementor --path /path/to/project
uv run vulnscan --remediate requests --strategy latest --path /path/to/project
```

`PACKAGE` is a package name (`requests`, `wp-plugin/elementor`) or a
WordPress slug (`elementor`). `--strategy nearest` is the default. The exit
code is 1 if the package is not among the vulnerable dependencies or no
suitable version exists.
