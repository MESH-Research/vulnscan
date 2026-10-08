# Contributing

The contributor guide lives in the repository as `CONTRIBUTING.md`; the
short version:

- `uv sync --all-groups`, then `uv run pytest` and `uv run ruff check .`.
- Branch from `main`, write a failing test first, keep commits to
  [Conventional Commits](https://www.conventionalcommits.org/) so releases
  and the changelog can be generated.
- Every public function, class and method needs a docstring, because the
  [API reference](api/index.md) is built from them. Preview the site with
  `uv run mkdocs serve`.
- Security problems in vulnscan itself go through private reporting, not a
  public issue; see `SECURITY.md`.

Participation is governed by the project's Code of Conduct.
