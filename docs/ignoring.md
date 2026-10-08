# Ignoring directories

Manifest discovery walks the whole project tree. Some directories are
always skipped:

- any directory whose name starts with a dot (`.git`, `.venv`, `.tox`,
  `.nox`, `.hg`, `.svn` and so on);
- `venv`, `env`, `site-packages`, `__pycache__`, `node_modules`, `vendor`,
  `build` and `dist`, wherever they appear;
- WordPress core: `wp-admin` and `wp-includes`;
- whatever a `composer.json` installs *into*: its `config.vendor-dir`,
  the prefixes of `extra.installer-paths` such as
  `web/app/plugins/{$name}/`, and `extra.wordpress-install-dir`. This keeps
  the `composer.json` files shipped inside installed plugins and themes
  from being mistaken for your own.

Beyond those, you can exclude anything else. A typical reason is a
quarantine directory: plugins you know are dangerous, have isolated, and
will never run again, but keep around for reference. There is no point
being told about them every scan.

## Three places to put patterns

All three are combined.

**`.vulnscanignore` in the project root** (recommended, because it lives
with the project):

```
# Plugins we have retired but keep for reference. Never scanned.
web/app/plugins/graveyard

# Any directory named "legacy", wherever it is
legacy

# Experiments
tools/scratch-*
```

Blank lines and lines starting with `#` are ignored.

**The `VULNSCAN_IGNORE_DIRS` setting**, comma separated, in `.env` or the
environment:

```
VULNSCAN_IGNORE_DIRS=legacy,web/app/plugins/graveyard
```

**The `--ignore` flag**, repeatable or comma separated. It overrides
`VULNSCAN_IGNORE_DIRS` (the `.vulnscanignore` file is still read):

```
uv run vulnscan --ignore legacy --ignore "web/app/plugins/graveyard,*-old"
```

## How patterns match

- A pattern **without a slash** matches a directory of that name anywhere in
  the tree: `graveyard` skips `web/app/plugins/graveyard` and
  `other/graveyard`.
- A pattern **with a slash** matches the path relative to the project root:
  `web/app/plugins/graveyard` skips that directory and nothing else.
- Both accept shell wildcards (`*`, `?`, `[...]`): `*-old`,
  `web/*/plugins/graveyard`.
- Leading `./` and trailing `/` are ignored, so `./legacy/` means `legacy`.
- Matching is case-sensitive.

A matched directory is pruned entirely, so nothing beneath it is visited.
