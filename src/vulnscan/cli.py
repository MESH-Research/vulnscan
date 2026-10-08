"""Command line entry point."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from vulnscan import __version__
from vulnscan.config import Settings, load_settings
from vulnscan.feeds import write_feeds
from vulnscan.models import Finding, ScanResult, normalize_name
from vulnscan.osv import OSVError
from vulnscan.registry import RegistryClient, RegistryError
from vulnscan.remediate import RemediationError, apply_remediation, plan_remediation
from vulnscan.reports import render_markdown, render_text
from vulnscan.scanner import scan
from vulnscan.wordfence import WordfenceError

SCAN_ERRORS = (OSVError, WordfenceError)


def build_parser() -> argparse.ArgumentParser:
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
    parser.add_argument("--env-file", help="path to a .env file (default: ./.env)")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def fetch_versions(settings: Settings, dep) -> list[str]:
    return RegistryClient(timeout=settings.request_timeout).available_versions(dep)


def find_finding(result: ScanResult, wanted: str) -> Finding | None:
    needle = wanted.strip().lower()
    for finding in result.findings:
        dep = finding.dependency
        names = {dep.name.lower(), normalize_name(dep.name, dep.ecosystem), dep.slug.lower()}
        if needle in names:
            return finding
    return None


def run_remediate(settings: Settings, args: argparse.Namespace) -> int:
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


def run_tui(settings: Settings) -> None:
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
    args = build_parser().parse_args(argv)
    try:
        settings = load_settings(
            dotenv_path=Path(args.env_file) if args.env_file else None,
            overrides={"project_path": args.path, "feed_dir": args.feed_dir},
        )
    except ValueError as exc:
        print(f"error: invalid configuration: {exc}", file=sys.stderr)
        return 2
    if not settings.project_path.exists():
        print(f"error: project path does not exist: {settings.project_path}", file=sys.stderr)
        return 1
    if args.remediate:
        return run_remediate(settings, args)
    if args.update_feeds or args.markdown is not None or args.text is not None:
        return run_non_interactive(settings, args)
    run_tui(settings)
    return 0
