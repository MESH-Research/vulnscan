"""Command line entry point."""

from __future__ import annotations

import argparse
import logging
import sys
from collections.abc import Sequence
from pathlib import Path

from vulnscan import __version__
from vulnscan.config import Settings, load_settings
from vulnscan.feeds import write_feeds
from vulnscan.models import Finding, ScanResult, normalize_name
from vulnscan.ntfy import NtfyClient, WatchControl, install_signal_handlers, run_watch
from vulnscan.osv import OSVError
from vulnscan.registry import RegistryClient, RegistryError
from vulnscan.remediate import RemediationError, apply_remediation, plan_remediation
from vulnscan.reports import render_markdown, render_text
from vulnscan.scanner import scan
from vulnscan.wordfence import WordfenceError

SCAN_ERRORS = (OSVError, WordfenceError)


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser for the ``vulnscan`` command."""
    parser = argparse.ArgumentParser(
        prog="vulnscan",
        description=(
            "Scan a Python or PHP project's direct dependencies for known security "
            "advisories. Without flags, opens the interactive TUI."
        ),
        epilog=(
            "Settings come from VULNSCAN_* environment variables or a .env file. "
            "Flags override both."
        ),
    )
    parser.add_argument(
        "--update-feeds",
        action="store_true",
        help="non-interactive: scan and rewrite the RSS and Atom feeds, then exit",
    )
    parser.add_argument("--path", help="project directory to scan (VULNSCAN_PROJECT_PATH)")
    parser.add_argument("--feed-dir", help="directory to write feeds into (VULNSCAN_FEED_DIR)")
    parser.add_argument(
        "--markdown",
        nargs="?",
        const="",
        default=None,
        metavar="FILE",
        help="non-interactive: write a Markdown report to FILE ('-' for stdout; "
        "default: <feed dir>/vulns.md)",
    )
    parser.add_argument(
        "--text",
        nargs="?",
        const="",
        default=None,
        metavar="FILE",
        help="non-interactive: write a plain-text report to FILE ('-' for stdout; "
        "default: <feed dir>/vulns.txt)",
    )
    parser.add_argument(
        "--remediate",
        metavar="PACKAGE",
        help="non-interactive: scan, then rewrite PACKAGE's constraint in its manifest "
        "(name, e.g. requests or wp-plugin/elementor, or a WordPress slug)",
    )
    parser.add_argument(
        "--strategy",
        choices=("nearest", "latest"),
        default="nearest",
        help="with --remediate: 'nearest' = smallest upgrade clearing all advisories "
        "(default), 'latest' = newest release",
    )
    parser.add_argument(
        "--ntfy",
        action="store_true",
        help="non-interactive: rescan every VULNSCAN_NTFY_INTERVAL_MINUTES and push new "
        "findings to an ntfy topic; SIGUSR1 re-sends everything, SIGINT/SIGTERM stop",
    )
    parser.add_argument(
        "--once", action="store_true", help="with --ntfy: run a single cycle and exit"
    )
    parser.add_argument(
        "--resend",
        action="store_true",
        help="with --ntfy: push every current finding at start, not only unsent ones",
    )
    parser.add_argument(
        "--interval",
        type=float,
        metavar="MINUTES",
        help="with --ntfy: minutes between scans (VULNSCAN_NTFY_INTERVAL_MINUTES)",
    )
    parser.add_argument(
        "--ignore",
        action="append",
        metavar="PATTERN",
        help="directory to skip: a name (anywhere), a path relative to the project, or a "
        "glob; repeatable or comma separated; overrides VULNSCAN_IGNORE_DIRS. A "
        ".vulnscanignore file in the project root is always read as well",
    )
    parser.add_argument("--env-file", help="path to a .env file (default: ./.env)")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def fetch_versions(settings: Settings, dep) -> list[str]:
    """Look up the versions of ``dep`` on its registry, honouring the configured timeout."""
    return RegistryClient(timeout=settings.request_timeout).available_versions(dep)


def find_finding(result: ScanResult, wanted: str) -> Finding | None:
    """Return the finding whose dependency matches ``wanted``, or None.

    The match is case-insensitive against the declared name, the canonical name and,
    for WordPress packages, the wordpress.org slug.
    """
    needle = wanted.strip().lower()
    for finding in result.findings:
        dep = finding.dependency
        names = {dep.name.lower(), normalize_name(dep.name, dep.ecosystem), dep.slug.lower()}
        if needle in names:
            return finding
    return None


def run_remediate(settings: Settings, args: argparse.Namespace) -> int:
    """Scan, then rewrite the constraint of ``--remediate PACKAGE`` in every manifest.

    Returns:
        0 on success; 1 when the scan fails, the package is not among the vulnerable
        dependencies, no suitable version exists, or a manifest cannot be edited.
    """
    try:
        result = scan(settings)
    except SCAN_ERRORS as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finding = find_finding(result, args.remediate)
    if finding is None:
        print(
            f"error: {args.remediate} is not among the vulnerable direct dependencies "
            f"({len(result.findings)} found)",
            file=sys.stderr,
        )
        return 1
    dep = finding.dependency
    try:
        plan = plan_remediation(finding, fetch_versions(settings, dep))
    except RegistryError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    target = plan.nearest_safe if args.strategy == "nearest" else plan.latest
    if target is None:
        print(
            f"error: no {'safe' if args.strategy == 'nearest' else 'newer'} version of {dep.name} "
            f"is available above {dep.version or 'the current version'}",
            file=sys.stderr,
        )
        return 1
    if args.strategy == "latest" and not plan.latest_is_safe:
        print(f"warning: {target} still has known advisories", file=sys.stderr)
    try:
        outcome = apply_remediation(settings.project_path, dep, target)
    except RemediationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    for change in outcome.changes:
        print(
            f"Updated {change.source_file}: {change.old_constraint or '(any)'} -> "
            f"{change.new_constraint}"
        )
    print(outcome.hint)
    return 0


def build_ntfy_client(settings: Settings) -> NtfyClient:
    """Create an :class:`NtfyClient` from the ``ntfy_*`` settings."""
    return NtfyClient(
        server=settings.ntfy_server,
        topic=settings.ntfy_topic,
        token=settings.ntfy_token,
        user=settings.ntfy_user,
        password=settings.ntfy_password,
        timeout=settings.request_timeout,
    )


def run_ntfy(settings: Settings, args: argparse.Namespace) -> int:
    """Run ``--ntfy`` mode: scan and push new findings, once or on an interval.

    Signal handlers are installed only for the continuous loop. Returns 2 when no
    topic is configured, otherwise the exit code of :func:`vulnscan.ntfy.run_watch`.
    """
    if not settings.ntfy_topic:
        print("error: ntfy mode needs VULNSCAN_NTFY_TOPIC (and usually a token)", file=sys.stderr)
        return 2
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s", stream=sys.stderr
    )
    logging.getLogger("httpx").setLevel(logging.WARNING)
    control = WatchControl()
    if not args.once:
        install_signal_handlers(control)
    return run_watch(
        settings,
        control,
        build_ntfy_client(settings),
        scan_fn=scan,
        resend_first=args.resend,
        once=args.once,
    )


def run_tui(settings: Settings) -> None:
    """Start the interactive Textual interface (imported lazily to keep CLI start-up light)."""
    from vulnscan.tui import VulnScanApp

    VulnScanApp(settings).run()


def _print_summary(result: ScanResult, written: list[Path]) -> None:
    print(
        f"Scanned {len(result.dependencies)} direct dependencies in {result.project_path}: "
        f"{len(result.findings)} with known advisories."
    )
    for finding in result.findings:
        dep = finding.dependency
        ids = ", ".join(v.id for v in finding.vulnerabilities)
        fixed = ", ".join(finding.fixed_versions) or "no fix listed"
        files = ", ".join(dep.source_files)
        print(f"  [{finding.worst_severity}] {dep.name} {dep.version or '?'} ({files})")
        print(f"      advisories: {ids}")
        print(f"      fixed in: {fixed}")
    for warning in result.warnings:
        print(f"warning: {warning}", file=sys.stderr)
    for path in written:
        print(f"Wrote {path}")


def _export(content: str, target: str, default: Path) -> Path | None:
    if target == "-":
        sys.stdout.write(content)
        return None
    path = Path(target) if target else default
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def run_non_interactive(settings: Settings, args: argparse.Namespace) -> int:
    """Scan once, then write feeds and/or reports as the flags request.

    A ``-`` target sends a report to stdout and suppresses the printed summary.
    Returns 1 (writing nothing) when the scan fails, otherwise 0.
    """
    try:
        result = scan(settings)
    except SCAN_ERRORS as exc:
        print(f"error: {exc}", file=sys.stderr)
        print("Nothing was written.", file=sys.stderr)
        return 1
    to_stdout = "-" in (args.markdown, args.text)
    written: list[Path] = []
    if args.update_feeds:
        written.extend(write_feeds(result, settings))
    if args.markdown is not None:
        path = _export(render_markdown(result), args.markdown, settings.markdown_path)
        if path:
            written.append(path)
    if args.text is not None:
        path = _export(render_text(result), args.text, settings.text_path)
        if path:
            written.append(path)
    if not to_stdout:
        _print_summary(result, written)
    else:
        for warning in result.warnings:
            print(f"warning: {warning}", file=sys.stderr)
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point: parse ``argv``, load settings and dispatch to the requested mode.

    Returns:
        2 for invalid configuration, 1 for a missing project path, otherwise the
        exit code of the mode that ran (the TUI always yields 0).
    """
    args = build_parser().parse_args(argv)
    try:
        settings = load_settings(
            dotenv_path=Path(args.env_file) if args.env_file else None,
            overrides={
                "project_path": args.path,
                "feed_dir": args.feed_dir,
                "ignore_dirs": ",".join(args.ignore) if args.ignore else None,
                "ntfy_interval_minutes": args.interval,
            },
        )
    except ValueError as exc:
        print(f"error: invalid configuration: {exc}", file=sys.stderr)
        return 2
    if not settings.project_path.exists():
        print(f"error: project path does not exist: {settings.project_path}", file=sys.stderr)
        return 1
    if args.ntfy:
        return run_ntfy(settings, args)
    if args.remediate:
        return run_remediate(settings, args)
    if args.update_feeds or args.markdown is not None or args.text is not None:
        return run_non_interactive(settings, args)
    run_tui(settings)
    return 0
