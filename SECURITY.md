# Security policy

## Reporting a vulnerability in vulnscan

If you find a security problem in vulnscan itself (for example a way to
make it rewrite files outside the project, leak an API key, or execute
content from a manifest), please do not open a public issue. Use GitHub's
private vulnerability reporting on this repository, or contact the
maintainer directly through the address in the repository profile. You can
expect an acknowledgement within a week.

## What vulnscan does with your data

- Package names and versions from your manifests are sent to OSV.dev
  (PyPI and Packagist packages) and, when upgrading, to PyPI, Packagist or
  wordpress.org to list available versions.
- WordPress packages are matched locally against a cached copy of the
  Wordfence Intelligence feed; only the download of that feed (with your API
  key) contacts Wordfence.
- In ntfy mode, advisory titles, package names, versions and the manifest
  paths that declare them are sent to the ntfy server you configure.

Nothing else leaves your machine. Keep `.env` out of version control: it
holds the Wordfence key and any ntfy credentials.

## Reporting a vulnerability in a package vulnscan found

vulnscan only reports what OSV.dev and Wordfence publish. Report problems
with an advisory's content to those projects, and report new vulnerabilities
to the package's maintainers.
