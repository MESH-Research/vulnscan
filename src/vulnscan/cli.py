"""Command line entry point."""

from __future__ import annotations

import argparse
import logging
import sys
from collections.abc import Sequence
from pathlib import Path

from vulnscan import __version__, debuglog
from vulnscan.config import Settings, load_settings
from vulnscan.feeds import write_feeds
from vulnscan.models import Finding, ScanResult, normalize_name
from vulnscan.msteams import TeamsClient
from vulnscan.notify import (
    NotificationError,
    Target,
    WatchControl,
    install_signal_handlers,
    run_watch,
)
from vulnscan.ntfy import NtfyClient
from vulnscan.nvd import NVDError
from vulnscan.osv import OSVError
from vulnscan.registry import RegistryClient, RegistryError
from vulnscan.remediate import (
    RemediationError,
    apply_remediation,
    format_latest_unsafe_note,
    plan_remediation,
)
from vulnscan.reports import render_markdown, render_text
from vulnscan.scanner import scan
from vulnscan.wordfence import WordfenceError

SCAN_ERRORS = (OSVError, WordfenceError, NVDError)

log = logging.getLogger("vulnscan.cli")


def _error(message: str, exc: BaseException | None = None) -> None:
    """Print ``error: message`` to stderr and record it in the debug log.

    The traceback is included only when the debug log is at its most verbose level.
    """
    print(f"error: {message}", file=sys.stderr)
    with_traceback = exc is not None and log.isEnabledFor(logging.DEBUG)
    log.error(message, exc_info=exc if with_traceback else None)


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser for the ``vulnscan`` command."""
    parser = argparse.ArgumentParser(
        prog="vulnscan",
        description=(
            "Scan a Python, PHP, WordPress or Node.js project's dependencies, and the "
            "container images its Dockerfiles and Compose files use, for known security "
            "advisories (direct ones by default, see --transitive). Without flags, opens "
            "the interactive TUI."
        ),
        epilog=(
            "Settings come from VULNSCAN_* environment variables or a .env file. "
            "Flags override both."
        ),
    )
    parser.add_argument(
        "--outdated",
        action="store_true",
        help="interactive: list dependencies with newer releases available (any update, "
        "not only security fixes); u offers the newest release in the current series and "
        "the latest release",
    )
    parser.add_argument(
        "--preflight",
        action="store_true",
        help="pin-float resolve in a temp tree and score would-be packages for advisories, "
        "malware, freshness and yank; alone opens the TUI, with --json/--text/--markdown/"
        "--update-feeds runs non-interactively for CI",
    )
    parser.add_argument(
        "--json",
        nargs="?",
        const="",
        default=None,
        metavar="FILE",
        help="with --preflight: write machine-readable JSON to FILE ('-' for stdout; "
        "default: <feed dir>/preflight.json)",
    )
    parser.add_argument(
        "--preflight-ignore",
        action="append",
        metavar="PKG",
        help="exclude package from preflight scoring only (name or ecosystem:name); "
        "repeatable; also VULNSCAN_PREFLIGHT_IGNORE and .vulnscan-preflight-ignore",
    )
    parser.add_argument(
        "--strict-fresh",
        action="store_true",
        help="with --preflight: freshness-only hits exit with code 2 (VULNSCAN_STRICT_FRESH)",
    )
    parser.add_argument(
        "--update-feeds",
        action="store_true",
        help="non-interactive: scan and rewrite the RSS and Atom feeds, then exit",
    )
    parser.add_argument(
        "--transitive",
        action="store_true",
        help="also scan packages that lock files record but no manifest declares, marked "
        "as transitive with what requires them (VULNSCAN_TRANSITIVE)",
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
        help="non-interactive: rescan every VULNSCAN_INTERVAL_MINUTES and push new findings "
        "to an ntfy topic; SIGUSR1 re-sends everything, SIGINT/SIGTERM stop. Combine with "
        "--msteams to notify both",
    )
    parser.add_argument(
        "--msteams",
        action="store_true",
        help="non-interactive: like --ntfy, but post an Adaptive Card to a Microsoft Teams "
        "incoming webhook (VULNSCAN_MSTEAMS_WEBHOOK_URL)",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="with --ntfy/--msteams: run a single cycle and exit",
    )
    parser.add_argument(
        "--resend",
        action="store_true",
        help="with --ntfy/--msteams: push every current finding at start, not only unsent ones",
    )
    parser.add_argument(
        "--test",
        action="store_true",
        help="with --ntfy/--msteams: send one test message to each selected channel and "
        "exit, without scanning or recording anything",
    )
    parser.add_argument(
        "--interval",
        type=float,
        metavar="MINUTES",
        help="with --ntfy/--msteams: minutes between scans (VULNSCAN_INTERVAL_MINUTES)",
    )
    parser.add_argument(
        "--ignore",
        action="append",
        metavar="PATTERN",
        help="directory to skip: a name (anywhere), a path relative to the project, or a "
        "glob; repeatable or comma separated; overrides VULNSCAN_IGNORE_DIRS. A "
        ".vulnscanignore file in the project root is always read as well",
    )
    parser.add_argument(
        "--invenio-webpack",
        choices=("auto", "on", "off"),
        help="treat Invenio webpack.py theme bundles as npm constraint sources and "
        "remediation targets (VULNSCAN_INVENIO_WEBPACK; default auto)",
    )
    parser.add_argument(
        "--invenio-webpack-overlay",
        metavar="PATH",
        help="site overlay webpack.py to always update on npm remediate "
        "(VULNSCAN_INVENIO_WEBPACK_OVERLAY)",
    )
    parser.add_argument("--env-file", help="path to a .env file (default: ./.env)")
    parser.add_argument(
        "-d",
        "--debug",
        action="count",
        default=0,
        help="write a diagnostic log (VULNSCAN_DEBUG): -d records every HTTP request and "
        "response with a curl command that repeats it; -dd adds control flow; -ddd adds "
        "library internals and tracebacks",
    )
    parser.add_argument(
        "--debug-log",
        metavar="FILE",
        help=f"where --debug writes (VULNSCAN_DEBUG_LOG; default: ./{debuglog.DEFAULT_LOG_FILE})",
    )
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
        _error(str(exc), exc)
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
    plan = getattr(finding, "upgrade_plan", None)
    if plan is None:
        try:
            plan = plan_remediation(
                finding, fetch_versions(settings, dep), webpack_merge=result.webpack_merge
            )
        except RegistryError as exc:
            _error(str(exc), exc)
            return 1
    for warning in getattr(plan, "warnings", ()):
        print(f"warning: {warning}", file=sys.stderr)
    target = plan.nearest_safe if args.strategy == "nearest" else plan.latest
    if target is None:
        extra = ""
        if finding.webpack_merge_block and args.strategy == "nearest":
            extra = f" ({finding.webpack_merge_block})"
        print(
            f"error: no {'safe' if args.strategy == 'nearest' else 'newer'} version of {dep.name} "
            f"is available above {dep.version or 'the current version'}{extra}",
            file=sys.stderr,
        )
        return 1
    if args.strategy == "latest" and not plan.latest_is_safe:
        print(f"warning: {target} {format_latest_unsafe_note(plan)}", file=sys.stderr)
    try:
        outcome = apply_remediation(
            settings.project_path,
            dep,
            target,
            settings=settings,
            webpack_merge=result.webpack_merge,
        )
    except RemediationError as exc:
        _error(str(exc), exc)
        return 1
    for change in outcome.authoritative_changes or outcome.changes:
        if change.added:
            print(f"Added {change.new_constraint} to {change.source_file}")
            continue
        print(
            f"Updated {change.source_file}: {change.old_constraint or '(any)'} -> "
            f"{change.new_constraint}"
        )
    companions = [c for c in outcome.changes if not c.authoritative]
    for change in companions:
        print(
            f"Also updated {change.source_file}: {change.old_constraint or '(any)'} -> "
            f"{change.new_constraint}"
        )
    for warning in outcome.warnings:
        print(f"warning: {warning}", file=sys.stderr)
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


def build_msteams_client(settings: Settings) -> TeamsClient:
    """Create a :class:`TeamsClient` from the ``msteams_*`` settings."""
    return TeamsClient(settings.msteams_webhook_url, timeout=settings.request_timeout)


def run_test_messages(settings: Settings, targets: Sequence[Target]) -> int:
    """Send one test message to every target channel, without scanning or saving state.

    Returns 0 when every channel accepted its message, otherwise 1.
    """
    project = settings.project_path.name or "project"
    failed = False
    for target in targets:
        channel = target.channel
        try:
            channel.send_test(project)
        except NotificationError as exc:
            print(f"{channel.name}: test message failed: {exc}", file=sys.stderr)
            failed = True
        else:
            print(f"{channel.name}: test message sent for {project}")
    return 1 if failed else 0


def run_notifications(settings: Settings, args: argparse.Namespace) -> int:
    """Run ``--ntfy`` and/or ``--msteams`` mode: scan and push new findings, once or forever.

    Each requested channel keeps its own sent-state file. Signal handlers are installed
    only for the continuous loop. With ``--test`` nothing is scanned: one test message
    goes to each channel instead. Returns 2 when a requested channel is not configured,
    otherwise the exit code of :func:`run_test_messages` or
    :func:`vulnscan.notify.run_watch`.
    """
    targets: list[Target] = []
    if args.ntfy:
        if not settings.ntfy_topic:
            print("error: --ntfy needs VULNSCAN_NTFY_TOPIC (and usually a token)", file=sys.stderr)
            return 2
        targets.append(Target(build_ntfy_client(settings), settings.ntfy_state_path))
    if args.msteams:
        if not settings.msteams_webhook_url:
            print("error: --msteams needs VULNSCAN_MSTEAMS_WEBHOOK_URL", file=sys.stderr)
            return 2
        targets.append(Target(build_msteams_client(settings), settings.msteams_state_path))
    if args.test:
        return run_test_messages(settings, targets)
    _configure_watch_logging()
    control = WatchControl()
    if not args.once:
        install_signal_handlers(control)
    return run_watch(
        settings,
        control,
        targets,
        scan_fn=scan,
        versions_fn=lambda dep: fetch_versions(settings, dep),
        resend_first=args.resend,
        once=args.once,
    )


class _StderrHandler(logging.StreamHandler):
    """A stream handler that always writes to the current ``sys.stderr``."""

    def __init__(self) -> None:
        super().__init__()

    @property
    def stream(self):  # type: ignore[override]
        return sys.stderr

    @stream.setter
    def stream(self, value) -> None:
        pass


def _configure_watch_logging() -> None:
    """Report watch-mode progress on stderr, without disturbing the debug log.

    The handler is attached to the ``vulnscan.notify`` logger only, so a debug log at
    any level still receives those records through propagation, and the control-flow
    and HTTP records of the other modules never reach the terminal.
    """
    notify_log = logging.getLogger("vulnscan.notify")
    if any(isinstance(h, _StderrHandler) for h in notify_log.handlers):
        return
    handler = _StderrHandler()
    handler.setLevel(logging.INFO)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    notify_log.addHandler(handler)
    if notify_log.getEffectiveLevel() > logging.INFO:
        notify_log.setLevel(logging.INFO)


def run_tui(settings: Settings, outdated: bool = False, preflight: bool = False) -> None:
    """Start the interactive Textual interface (imported lazily to keep CLI start-up light).

    With ``outdated`` the TUI lists dependencies with newer releases instead of
    vulnerable ones (also remembered when starting in ``preflight`` so ``n`` can
    return to outdated mode). With ``preflight`` it lists pin-float would-be risks.
    """
    from vulnscan.tui import VulnScanApp

    VulnScanApp(settings, outdated=outdated, preflight=preflight).run()


def _print_summary(result: ScanResult, written: list[Path]) -> None:
    transitive = sum(1 for d in result.dependencies if d.transitive)
    scope = "dependencies" if transitive else "direct dependencies"
    extra = f" ({transitive} transitive)" if transitive else ""
    print(
        f"Scanned {len(result.dependencies)} {scope}{extra} in {result.project_path}: "
        f"{len(result.findings)} with known advisories."
    )
    for finding in result.findings:
        dep = finding.dependency
        ids = ", ".join(v.id for v in finding.vulnerabilities)
        fixed = ", ".join(finding.fixed_versions) or "no fix listed"
        files = ", ".join(dep.source_files)
        print(f"  [{finding.worst_severity}] {dep.name} {dep.version or '?'} ({files})")
        if dep.transitive:
            via = f", required by {', '.join(dep.required_by)}" if dep.required_by else ""
            print(f"      transitive dependency{via}")
        print(f"      advisories: {ids}")
        print(f"      fixed in: {fixed}")
    _print_source_errors(result)
    for warning in result.warnings:
        print(f"warning: {warning}", file=sys.stderr)
    for path in written:
        print(f"Wrote {path}")


def _print_source_errors(result: ScanResult) -> None:
    """Advisory sources that failed this run, on stderr, ahead of the ordinary warnings."""
    for line in result.source_errors:
        print(f"error: {line}", file=sys.stderr)
    if result.source_errors:
        print(
            "error: the results above are incomplete; packages served by a failed source "
            "were not checked this run",
            file=sys.stderr,
        )


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
        _error(str(exc), exc)
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
        _print_source_errors(result)
        for warning in result.warnings:
            print(f"warning: {warning}", file=sys.stderr)
    return 0


def run_preflight_cli(settings: Settings, args: argparse.Namespace) -> int:
    """Run pin-float preflight; write JSON/text/markdown/feeds as requested."""
    from vulnscan.preflight import (
        render_preflight_text,
        run_preflight,
        write_json_report,
    )

    extra = []
    for raw in args.preflight_ignore or []:
        extra.extend(part.strip() for part in raw.split(",") if part.strip())
    strict = bool(args.strict_fresh or settings.strict_fresh)
    report = run_preflight(settings, extra_ignores=extra)
    written: list[Path] = []
    if args.json is not None:
        target = args.json or str(settings.feed_dir / "preflight.json")
        payload = write_json_report(
            report,
            None if target == "-" else Path(target),
            strict_fresh=strict,
        )
        if target == "-":
            print(payload, end="")
        else:
            written.append(Path(target))
            print(payload, end="") if False else None
    if args.text is not None:
        content = render_preflight_text(report)
        path = _export(content, args.text, settings.feed_dir / settings.preflight_text_filename)
        if path:
            written.append(path)
        elif args.text == "-":
            print(content, end="")
    if args.markdown is not None:
        # Markdown for preflight reuses the text form for v1.
        content = "# Preflight\n\n```\n" + render_preflight_text(report) + "```\n"
        path = _export(
            content, args.markdown, settings.feed_dir / settings.preflight_markdown_filename
        )
        if path:
            written.append(path)
        elif args.markdown == "-":
            print(content, end="")
    if args.update_feeds:
        from vulnscan.feeds import write_preflight_feeds

        written.extend(write_preflight_feeds(report, settings))
    if args.json is None and args.text is None and args.markdown is None and not args.update_feeds:
        print(render_preflight_text(report), end="")
    for path in written:
        print(f"Wrote {path}")
    for warning in report.warnings:
        print(f"warning: {warning}", file=sys.stderr)
    return report.exit_code(strict_fresh=strict)


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
                "interval_minutes": args.interval,
                "invenio_webpack": args.invenio_webpack,
                "invenio_webpack_overlay": args.invenio_webpack_overlay,
                "include_transitive": True if args.transitive else None,
                "strict_fresh": True if args.strict_fresh else None,
                "debug": min(args.debug, debuglog.MAX_LEVEL) if args.debug else None,
                "debug_log": args.debug_log,
            },
        )
    except ValueError as exc:
        print(f"error: invalid configuration: {exc}", file=sys.stderr)
        return 2
    if settings.debug:
        debuglog.configure(
            settings.debug,
            settings.debug_log,
            secrets=debuglog.secrets_from_settings(settings),
            argv=sys.argv if argv is None else ["vulnscan", *argv],
        )
        log.info(
            "settings: project %s, feed dir %s, cache %s, timeout %ss, transitive=%s, "
            "include_dev=%s, osv %s, wordfence key %s, nvd key %s",
            settings.project_path,
            settings.feed_dir,
            settings.cache_dir,
            settings.request_timeout,
            settings.include_transitive,
            settings.include_dev,
            settings.osv_base_url,
            "set" if settings.wordfence_api_key else "unset",
            "set" if settings.nvd_api_key else "unset",
        )
    if not settings.project_path.exists():
        _error(f"project path does not exist: {settings.project_path}")
        return 1
    non_interactive = (
        args.ntfy
        or args.msteams
        or args.test
        or args.remediate
        or args.update_feeds
        or args.markdown is not None
        or args.text is not None
        or args.json is not None
    )
    if args.outdated and non_interactive:
        print(
            "error: --outdated opens the TUI and cannot be combined with non-interactive flags",
            file=sys.stderr,
        )
        return 2
    if args.preflight and (args.ntfy or args.msteams or args.test or args.remediate):
        print(
            "error: --preflight cannot be combined with --ntfy/--msteams/--test/--remediate",
            file=sys.stderr,
        )
        return 2
    if args.ntfy or args.msteams:
        log.info(
            "mode: notifications (ntfy=%s, msteams=%s, once=%s)", args.ntfy, args.msteams, args.once
        )
        return run_notifications(settings, args)
    if args.test:
        print("error: --test needs --ntfy and/or --msteams", file=sys.stderr)
        return 2
    if args.remediate:
        log.info("mode: remediate %s (%s)", args.remediate, args.strategy)
        return run_remediate(settings, args)
    if args.preflight and non_interactive:
        log.info("mode: preflight, non-interactive")
        return run_preflight_cli(settings, args)
    if args.preflight:
        log.info("mode: preflight TUI (outdated=%s)", args.outdated)
        run_tui(settings, outdated=args.outdated, preflight=True)
        return 0
    if args.update_feeds or args.markdown is not None or args.text is not None:
        log.info(
            "mode: feeds/reports (feeds=%s, markdown=%r, text=%r)",
            args.update_feeds,
            args.markdown,
            args.text,
        )
        return run_non_interactive(settings, args)
    log.info("mode: TUI (outdated=%s)", args.outdated)
    run_tui(settings, outdated=args.outdated)
    return 0
