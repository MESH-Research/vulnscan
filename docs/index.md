# vulnscan

Point vulnscan at a Python, PHP, WordPress or Node.js project and it tells you which
of your **direct** dependencies have known security advisories, which
versions fix them, and where in your manifests each one is declared. It can
then rewrite those manifests for you, publish the results as RSS and Atom
feeds or Markdown and text reports, and push a notification to your phone
whenever something new turns up.

## What it does

- Reads `composer.json`, `package.json`, `pyproject.toml`,
  `requirements*.txt` (and `requirements/*.txt`), `Pipfile` and `setup.cfg`,
  and the lock files next to them, to learn exactly which version of each
  direct dependency you run; and reads the images in your Dockerfiles and
  Compose files, so the PHP, Traefik or Postgres you deploy counts too.
- Looks those versions up on [OSV.dev](https://osv.dev) (PyPI, Packagist,
  npm), [Wordfence Intelligence](https://www.wordfence.com/threat-intel/)
  (WordPress core, plugins and themes) and the [NVD](https://nvd.nist.gov)
  (container images).
- Shows the results in a terminal interface where every advisory can be read
  in full, or writes them out non-interactively for cron.
- Lists every manifest that declares a vulnerable package, and upgrades the
  constraint in all of them in one go, after checking that the version it
  offers is not itself vulnerable, malicious, yanked or only hours old.
- Resolves each manifest from scratch in a temporary directory on request
  (`--preflight`) and scores what the next update would pull in, with a JSON
  report and exit codes for CI.
- Keeps a watch on a project and pushes each advisory the first time it is
  seen to [ntfy](https://ntfy.sh) (your phone) and/or a Microsoft Teams
  channel, with the fix version, whether it is published, severity, CVE
  links and a summary.

## Where to start

- [Installation](installation.md)
- [Usage](usage.md) for the TUI and the command line modes, including
  [preflight](usage.md#preflight-what-the-next-resolve-would-pull-in) and
  [diagnosing problems](usage.md#diagnosing-problems)
- [Notifications](notifications.md) for continuous monitoring with ntfy or Teams
- [Configuration](configuration.md) for every setting
- [How it works](architecture.md) and the [API reference](api/index.md)
  if you want to extend it

## Scope

Direct dependencies are evaluated by default, which keeps the output focused
on things you can change in your own manifests. Pass `--transitive` (or set
`VULNSCAN_TRANSITIVE=true`) to scan every package a lock file records as well;
those are marked as transitive together with the packages that require them,
and upgrade advice tells you which constraint to add by hand. See
[Usage](usage.md#transitive-dependencies).
