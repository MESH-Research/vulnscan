# vulnscan

Point vulnscan at a Python, PHP or WordPress project and it tells you which
of your **direct** dependencies have known security advisories, which
versions fix them, and where in your manifests each one is declared. It can
then rewrite those manifests for you, publish the results as RSS and Atom
feeds or Markdown and text reports, and push a notification to your phone
whenever something new turns up.

## What it does

- Reads `composer.json`, `pyproject.toml`, `requirements*.txt` (and
  `requirements/*.txt`), `Pipfile` and `setup.cfg`, and the lock files next
  to them, to learn exactly which version of each direct dependency you run.
- Looks those versions up on [OSV.dev](https://osv.dev) (PyPI, Packagist)
  and [Wordfence Intelligence](https://www.wordfence.com/threat-intel/)
  (WordPress core, plugins and themes).
- Shows the results in a terminal interface where every advisory can be read
  in full, or writes them out non-interactively for cron.
- Lists every manifest that declares a vulnerable package, and upgrades the
  constraint in all of them in one go.
- Keeps a watch on a project and sends an [ntfy](https://ntfy.sh) push
  notification for each advisory the first time it is seen.

## Where to start

- [Installation](installation.md)
- [Usage](usage.md) for the TUI and the command line modes
- [Notifications with ntfy](notifications.md) for continuous monitoring
- [Configuration](configuration.md) for every setting
- [How it works](architecture.md) and the [API reference](api/index.md)
  if you want to extend it

## Scope

Only direct dependencies are evaluated. Lock files are read solely to learn
the installed version of those direct dependencies; transitive dependencies
are never scanned. That keeps the output focused on things you can actually
change in your own manifests.
