# Upgrading dependencies

Select a vulnerable dependency in the TUI and press `u`, or run
`--remediate PACKAGE` from the command line. vulnscan looks up the versions
published for the package (PyPI, Packagist or wordpress.org) and offers two
choices:

- **Nearest safe version**: the smallest upgrade above the current version
  that is outside every known advisory's affected range. This keeps you as
  close as possible to what you have: `symfony/http-kernel` 5.4.0 goes to
  5.4.20, not 6.x.
- **Latest release**: the newest stable version. If even that is still
  affected by an open advisory, the option says so.

Pre-release and yanked versions are never offered.

## What gets edited

The constraint is rewritten in **every manifest that declares the package**
at that version, and nothing else in those files changes: ordering, comments
and indentation are preserved. The operator style is kept:

| Before | After (upgrade to 4.1.4 / 16.3 / 2.32.4 / 4.2.11) |
|--------|------|
| `3.13.4` | `4.1.4` |
| `^12.2` | `^16.3` |
| `requests==2.30.0` | `requests==2.32.4` |
| `Django>=4.2,<5` | `Django>=4.2.11,<5` |

Supported manifests: `composer.json`, `requirements*.txt` and
`requirements/*.txt`, `pyproject.toml` (PEP 621 strings, PEP 735 groups and
Poetry tables), `Pipfile` and `setup.cfg`. Constraints that track a
development branch (`dev-main`) are left for you to change by hand.

Every rewrite is computed before any file is written. If one of the
declaring files cannot be edited (it has changed since the scan, or its
format is unsupported) nothing is written and the error names the file.

## After the edit

Lock files are not touched. The status bar (or the command line output)
tells you the command to run next for each manifest, such as
`composer update wp-plugin/elementor --with-dependencies`, `uv lock && uv
sync`, `poetry lock && poetry install`, `pipenv lock && pipenv sync`,
`pip install -e .` for a `setup.cfg`, or `pip install -r base.txt` (with
the directory to run it in when the manifest is not at the project root).
Press `r` afterwards to rescan.

In the TUI the dependency's row and its advisories turn green with a ✔
"upgraded" marker so you can see what you have already dealt with. The
marker persists across rescans in the same session, since the dependency
keeps showing as vulnerable until the lock file is updated.

## Command line

```
uv run vulnscan --remediate wp-plugin/elementor --path /path/to/project
uv run vulnscan --remediate requests --strategy latest --path /path/to/project
```

`PACKAGE` is a package name (`requests`, `wp-plugin/elementor`) or a
WordPress slug (`elementor`). `--strategy nearest` is the default. The exit
code is 1 if the package is not among the vulnerable dependencies or no
suitable version exists.
