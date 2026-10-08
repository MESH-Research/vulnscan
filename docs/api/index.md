# API reference

vulnscan is primarily a command line tool, but every stage is importable.
The reference on the following pages is generated from the docstrings.

A minimal programmatic scan:

```python
from vulnscan.config import load_settings
from vulnscan.scanner import scan

settings = load_settings(overrides={"project_path": "/path/to/project"})
result = scan(settings)
for finding in result.findings:
    dep = finding.dependency
    print(dep.name, dep.version, dep.source_files, finding.worst_severity)
    for vuln in finding.vulnerabilities:
        print("  ", vuln.id, vuln.summary, vuln.fixed_versions)
```

Then, for example, `vulnscan.feeds.write_feeds(result, settings)`,
`vulnscan.reports.render_markdown(result)`,
`vulnscan.ntfy.notify(result, settings, client)` or
`vulnscan.remediate.apply_remediation(settings.project_path, dep, "1.3.1")`.

| Module | Role |
|--------|------|
| [`vulnscan.models`](models.md) | `Dependency`, `Declaration`, `Vulnerability`, `Finding`, `ScanResult` |
| [`vulnscan.config`](config.md) | `Settings` and `load_settings` |
| [`vulnscan.parsers`](parsers.md) | Manifest discovery, parsers, lock files, version resolution |
| [`vulnscan.scanner`](scanner.md) | `scan` orchestration |
| [`vulnscan.osv`](osv.md) | OSV.dev client |
| [`vulnscan.wordfence`](wordfence.md) | Wordfence Intelligence client and cache |
| [`vulnscan.registry`](registry.md) | Available versions from PyPI, Packagist and wordpress.org |
| [`vulnscan.remediate`](remediate.md) | Upgrade planning and manifest rewriting |
| [`vulnscan.feeds`](feeds.md) | RSS and Atom |
| [`vulnscan.reports`](reports.md) | Markdown and plain text |
| [`vulnscan.ntfy`](ntfy.md) | ntfy notifications and the watch loop |
| [`vulnscan.cli`](cli.md) | Command line entry point |
| [`vulnscan.tui`](tui.md) | Textual application |
| [`vulnscan.versioncmp`](versioncmp.md) | Ecosystem-aware version comparison |
