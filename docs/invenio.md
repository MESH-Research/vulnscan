# InvenioRDM Projects

InvenioRDM generally treats python dependencies in a familiar way--declaring
them in the project `pyproject.toml` file and installing them via `uv` in the
local `.venv`. Keep in mind that dependencies and constraints may also be
declared in the `pyproject.toml` files of the extension submodules.

The situation is more idiosyncratic with JavaScript dependencies. Invenio apps
do not treat the generated root `package.json` as the durable source of (p)npm
constraints. Instead, individual python packages declare dependency bundles in
their `webpack.py` files via
`WebpackThemeBundle(..., themes={"semantic-ui": {"dependencies": {...}}})`.
pywebpack merges those maps (same major only) when you run
`invenio webpack create` during the Invenio assets build process. The resulting
`package.json` is not placed in the local project source but rather lives in the
dynamically generated assets folder (usually `/opt/invenio/var/instance/assets`
in application containers). The `package.json` files (and `node_modules`
folders) at the project source root is generally used to set up the testing
environment only and likely will _not_ match the dynamically generated instance
npm project.

When `VULNSCAN_INVENIO_WEBPACK` is `auto` (default), vulnscan detects that we
are in an InvenioRDM project by looking for this layout: at least one in-tree
`webpack.py` theme bundle **and** a clear Invenio signature in the project (a
`site/*/webpack.py` file, or `invenio-assets` / `invenio-app-rdm` dependencies
in project metadata). Force Invenio project mode with `on` / `off`, or
`--invenio-webpack`.

## Scanning

Python dependencies are discovered by scanning for `pyproject.toml` and
`uv.lock` files in the project and submodule roots.

For JavaScript, every non-ignored `webpack.py` that defines a theme bundle is
treated as an npm manifest. Constraints are read from
`themes["semantic-ui"]["dependencies"]`. "Installed versions" are still inferred
from `package.json` and npm/pnpm lock files as usual, with the caveat that these
may _not_ be the same as the versions installed dynamically in app containers.

## Preflight (`--preflight`)

In Invenio mode, npm preflight does **not** float each on-disk `package.json`
(those are typically the test-env tree). It builds one **virtual** assets
`package.json` from the same sources as `webpack create` / the scan merge index
(in-tree theme `webpack.py` files, `invenio_assets.webpack` entry points in the
project `.venv`, and the invenio-assets base templates), folds constraints with
pywebpack’s same-major `max_version` rule, then runs a lockfile-only npm/pnpm
resolve on that document. Major merge conflicts are omitted with warnings.
Python manifests are still mock-locked individually.

Exclude local forks of upstream modules you do not control using
`.vulnscanignore` (paths relative to the project root). Otherwise, dependencies
in any local submodules under, say, `site/kcworks/dependencies/` stay
discoverable.

## Remediating npm packages

When Invenio mode is active remediation of a python dependency will update the
`pyproject.toml` file where the dependency is declared. For an npm
vulnerability, vulnscan:

1. **Always** updates the site overlay `webpack.py` (default:
   `site/*/webpack.py`). It inserts the package (and new version constraint)
   there if it was previously only declared in a submodule or upstream package.
2. Updates every other in-tree (non-ignored) `webpack.py` that **already**
   declares the package. Does not insert the package into submodule files if it
   was absent.
3. Best-effort updates companion `package.json` files (root and submodule) that
   already list the package. This includes declarations discovered in the scan,
   plus each remediated submodule’s root `package.json`. Failures to find and
   updated a local `package.json` warn only; they do not undo `webpack.py`
   writes.

Success requires that steps 1 and 2 complete. Afterwards run
`invenio webpack clean create` in the running app context (then install/build as
usual).

## pywebpack major versions

`merge_deps` for Invenio projects refuses upgrades beyond the current major
version of a given npm package. After each scan, vulnscan runs an **in-memory
merge** of the same sources `webpack create` would use (no Flask app is spun up
here): in-tree `webpack.py` files, every `invenio_assets.webpack` entry point in
the project `.venv`, and the invenio-assets base `package.json`. Conflicts are
listed in the report with their sources. Affected findings show **Nearest safe**
as `none`, and `--remediate` / TUI nearest-safe is cleared for those packages. A
chosen upgrade that would still break the merge is **blocked** (no files
written).

Per-finding details (report, TUI, feeds, ntfy, Teams) show:

- **Declared in** — scanned manifests (empty constraint →
  `no version constraint`)
- **Upstream constraints** — the merge-tree sources above (`none` when absent)
- **Upgrade limit** — when pywebpack blocks a fix (including “major bump
  required”)
