"""Textual user interface."""

from __future__ import annotations

import webbrowser
from collections.abc import Callable

from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.timer import Timer
from textual.widgets import DataTable, Footer, Header, Label, Markdown, OptionList, Static
from textual.widgets.option_list import Option

from vulnscan.config import Settings
from vulnscan.feeds import write_feeds
from vulnscan.models import Dependency, Finding, ScanResult, Vulnerability, format_declaration
from vulnscan.outdated import OutdatedPackage, UpgradeOptions, find_outdated
from vulnscan.registry import RegistryClient, RegistryError
from vulnscan.remediate import (
    RemediationError,
    RemediationPlan,
    RemediationResult,
    apply_remediation,
    plan_remediation,
    transitive_hint,
)
from vulnscan.reports import write_reports
from vulnscan.scanner import scan
from vulnscan.wordfence import SOURCE as WORDFENCE_SOURCE
from vulnscan.wordfence import wordfence_attribution

ScanFn = Callable[[Settings], ScanResult]
VersionsFn = Callable[[Dependency], list[str]]

# Braille spinner frames for the status bar while a worker is running.
_SPINNER_FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

DEP_COLUMNS = (
    " ",
    "Package",
    "Ecosystem",
    "Version",
    "Via",
    "Severity",
    "Advisories",
    "Fixed in",
    "File",
)
OUTDATED_COLUMNS = (
    " ",
    "Package",
    "Ecosystem",
    "Installed",
    "Via",
    "Series update",
    "Latest",
    "Advisories",
    "File",
)
VULN_COLUMNS = ("Advisory", "Severity", "CVE", "Summary", "Status")
REMEDIATED_STYLE = "bold green"
TICK = "✔"
OUTDATED_SUBTITLE = "OUTDATED PACKAGES: all updates, not security advisories"
OUTDATED_BANNER = (
    "Outdated mode: these packages have newer releases. These are routine updates, NOT "
    "security advisories; any known advisories are counted in the Advisories column. "
    "Press u for the newest release in the current series or the latest release."
)
NOT_SECURITY_NOTE = "Routine update: this is not a security advisory."


def _cells(values: list[str], remediated: bool) -> list[str | Text]:
    """Plain strings normally; green text once the dependency has been upgraded."""
    if not remediated:
        return list(values)
    return [Text(v, style=REMEDIATED_STYLE) for v in values]


def _plural(count: int, noun: str) -> str:
    return f"{count} {noun}" if count == 1 else f"{count} {noun}s"


def vulnerability_markdown(finding: Finding, vuln: Vulnerability) -> str:
    """Markdown shown in the detail pane for one advisory of a finding."""
    from vulnscan.reports import constraint_facts

    dep = finding.dependency
    lines = [f"# {vuln.id}", ""]
    if vuln.summary:
        lines += [f"**{vuln.summary}**", ""]
    declared = "; ".join(
        (
            format_declaration(d)
            if d.transitive
            else f"{d.source_file} as `{d.constraint}`"
            if d.constraint
            else f"{d.source_file}; no version constraint"
        )
        for d in dep.declared_in
    )
    constraint_lines = [
        f"- **Declared in:** {declared} (version from {dep.version_source})",
    ]
    for key, value in constraint_facts(finding):
        if key == "Declared in":
            continue
        constraint_lines.append(f"- **{key}:** {value}")
    lines += [
        f"- **Package:** {dep.name} {dep.version or '(unknown version)'} ({dep.ecosystem})",
        *constraint_lines,
        f"- **Severity:** {vuln.severity}" + (f" (`{vuln.cvss}`)" if vuln.cvss else ""),
        f"- **CVE:** {', '.join(vuln.cve_ids) or 'none assigned'}",
        f"- **Aliases:** {', '.join(vuln.aliases) or 'none'}",
        f"- **Fixed in:** {', '.join(vuln.fixed_versions) or 'no fix listed'}",
    ]
    if vuln.published:
        lines.append(f"- **Published:** {vuln.published:%Y-%m-%d}")
    if vuln.modified:
        lines.append(f"- **Modified:** {vuln.modified:%Y-%m-%d}")
    lines += [
        "",
        "## Details",
        "",
        vuln.details or "_No details provided._",
        "",
        "## References",
        "",
    ]
    lines += [f"- <{url}>" for url in [vuln.url, *vuln.references]]
    if vuln.source == WORDFENCE_SOURCE:
        lines += ["", "---", "", f"_{wordfence_attribution()}_"]
    return "\n".join(lines)


def _advisory_list(finding: Finding | None) -> str:
    if not finding or not finding.vulnerabilities:
        return "none"
    return ", ".join(f"{v.id} ({v.severity})" for v in finding.vulnerabilities)


def upgrade_markdown(dep: Dependency, options: UpgradeOptions, finding: Finding | None) -> str:
    """Markdown shown in the detail pane for an outdated (not necessarily vulnerable) package."""
    series = options.series or "?"
    if options.series_latest:
        series_line = f"newest {series}.x release is {options.series_latest}"
    else:
        series_line = f"no newer release in the {series} series"
    lines = [
        f"# {dep.name}",
        "",
        f"**{NOT_SECURITY_NOTE}** A newer release is available.",
        "",
        f"- **Package:** {dep.name} {options.current or '(unknown version)'} ({dep.ecosystem})",
        f"- **Declared in:** {dep.declared_in_text} (version from {dep.version_source})",
        f"- **Current series:** {series}; {series_line}",
        f"- **Latest release:** {options.latest or 'none newer'}",
        f"- **Known advisories affecting {options.current or 'this version'}:** "
        f"{_advisory_list(finding)}",
    ]
    if finding and finding.vulnerabilities:
        lines.append("")
        lines.append(
            "_Select an advisory in the table above for its details. "
            "Press o to open it in a browser._"
        )
    lines += ["", "Press u to upgrade this package in every manifest that declares it."]
    return "\n".join(lines)


class OptionDialog(ModalScreen[str | None]):
    """A modal with a summary, a list of options and a key hint; dismisses with an option id."""

    DEFAULT_CSS = """
    OptionDialog { align: center middle; }
    #remediate-box {
        width: 90; height: auto; max-height: 90%; padding: 1 2;
        border: thick $primary; background: $surface;
    }
    #remediate-summary { height: auto; margin-bottom: 1; }
    #remediate-options { height: auto; margin-top: 1; }
    #remediate-help { color: $text-muted; margin-top: 1; }
    """
    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    def summary_lines(self) -> list[str]:
        """Lines shown above the options."""
        raise NotImplementedError

    def options(self) -> list[Option]:
        """The selectable (or disabled) options."""
        raise NotImplementedError

    def compose(self) -> ComposeResult:
        """Build the dialog: a multi-line summary, the options and a key hint."""
        with Vertical(id="remediate-box"):
            yield Static("\n".join(self.summary_lines()), id="remediate-summary")
            yield OptionList(*self.options(), id="remediate-options")
            yield Label(
                "Enter to apply the highlighted option, Esc to cancel.", id="remediate-help"
            )

    def on_mount(self) -> None:
        """Focus the option list and highlight the first enabled option."""
        options = self.query_one("#remediate-options", OptionList)
        options.focus()
        for index in range(options.option_count):
            if not options.get_option_at_index(index).disabled:
                options.highlighted = index
                break

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        """Dismiss with the chosen option id."""
        self.dismiss(event.option.id)

    def action_cancel(self) -> None:
        """Dismiss with ``None`` (Esc)."""
        self.dismiss(None)


class RemediateScreen(OptionDialog):
    """Ask which security upgrade to apply. Dismisses with 'nearest', 'latest' or None."""

    def __init__(self, finding: Finding, plan: RemediationPlan) -> None:
        super().__init__()
        self.finding = finding
        self.plan = plan

    def summary_lines(self) -> list[str]:
        """Package, current version, constraint facts and a note when no safe version exists."""
        from vulnscan.reports import constraint_facts

        dep = self.finding.dependency
        summary = [
            f"Upgrade {dep.name} (currently {self.plan.current or 'unknown'})",
            *[f"{key}: {value}" for key, value in constraint_facts(self.finding)],
        ]
        if not self.plan.nearest_safe and not self.finding.upgrade_limit:
            summary.append("Nearest safe: none available")
        return summary

    def options(self) -> list[Option]:
        """Nearest safe version and latest release, disabled when unavailable."""
        if self.plan.nearest_safe:
            nearest = Option(
                f"Nearest safe version: {self.plan.nearest_safe}  "
                "(smallest upgrade that clears all known advisories)",
                id="nearest",
            )
        else:
            nearest = Option("Nearest safe version: none available", id="nearest", disabled=True)
        if self.plan.latest:
            note = "" if self.plan.latest_is_safe else "  (still has known advisories!)"
            latest = Option(f"Latest release: {self.plan.latest}{note}", id="latest")
        else:
            latest = Option("Latest release: none found", id="latest", disabled=True)
        return [nearest, latest]


class UpgradeScreen(OptionDialog):
    """Ask which routine upgrade to apply. Dismisses with 'series', 'latest' or None."""

    def __init__(self, dep: Dependency, options: UpgradeOptions, finding: Finding | None) -> None:
        super().__init__()
        self.dep = dep
        self.upgrade = options
        self.finding = finding

    def summary_lines(self) -> list[str]:
        """Package, current version, the not-a-security-fix note and where it is declared."""
        lines = [
            f"Upgrade {self.dep.name} (currently {self.upgrade.current or 'unknown'})",
            NOT_SECURITY_NOTE,
        ]
        if self.finding and self.finding.vulnerabilities:
            count = len(self.finding.vulnerabilities)
            noun = "known advisory affects" if count == 1 else "known advisories affect"
            lines.append(f"Note: {count} {noun} the current version.")
        lines.append(f"Declared in: {self.dep.declared_in_text}")
        return lines

    def _affected(self, version: str) -> bool:
        if not self.finding:
            return False
        return any(v.affects(version, self.dep.ecosystem) for v in self.finding.vulnerabilities)

    def options(self) -> list[Option]:
        """Newest release in the current series, then the latest release."""
        series = self.upgrade.series or "?"
        if self.upgrade.series_latest:
            note = (
                "  (still has known advisories!)"
                if self._affected(self.upgrade.series_latest)
                else ""
            )
            in_series = Option(
                f"Newest {series}.x release: {self.upgrade.series_latest}  "
                f"(smallest step, stays in the {series} series){note}",
                id="series",
            )
        else:
            in_series = Option(
                f"Newest {series}.x release: none newer than {self.upgrade.current}",
                id="series",
                disabled=True,
            )
        if self.upgrade.latest:
            note = "  (still has known advisories!)" if self._affected(self.upgrade.latest) else ""
            latest = Option(f"Latest release: {self.upgrade.latest}{note}", id="latest")
        else:
            latest = Option("Latest release: none newer", id="latest", disabled=True)
        return [in_series, latest]


class VulnScanApp(App[None]):
    """Interactive browser for scan results.

    Scans run in a worker thread so the interface stays responsive. Keys: ``r`` rescan,
    ``f`` write feeds, ``e`` export reports, ``u`` upgrade the selected dependency,
    ``o`` open the selected advisory in a browser, ``q`` quit. ``scan_fn`` and
    ``versions_fn`` replace the real scanner and registry lookups in tests.

    With ``outdated`` the dependency table lists every dependency that has a newer
    stable release, whether or not an advisory affects it, and ``u`` offers the newest
    release in the current series or the latest release. The interface says plainly
    that these are routine updates rather than security fixes.
    """

    TITLE = "vulnscan"
    CSS = """
    #deps { width: 3fr; height: 1fr; }
    #right { width: 2fr; height: 1fr; }
    #vulns { height: auto; max-height: 40%; min-height: 4; }
    #detail-scroll { height: 1fr; border-top: solid $primary; padding: 0 1; }
    #status { height: auto; padding: 0 1; background: $panel; }
    #mode-banner {
        height: auto; padding: 0 1; background: $warning 25%; text-style: bold;
    }
    """
    BINDINGS = [
        Binding("r", "rescan", "Rescan"),
        Binding("f", "write_feeds", "Write feeds"),
        Binding("e", "export_reports", "Export md/txt"),
        Binding("u", "remediate", "Upgrade dep"),
        Binding("o", "open_advisory", "Open advisory"),
        Binding("q", "quit", "Quit"),
    ]

    def __init__(
        self,
        settings: Settings,
        scan_fn: ScanFn | None = None,
        versions_fn: VersionsFn | None = None,
        outdated: bool = False,
    ) -> None:
        super().__init__()
        self.settings = settings
        self.outdated = outdated
        self._scan_fn: ScanFn = scan_fn or scan
        self._versions_fn: VersionsFn | None = versions_fn
        self.result: ScanResult | None = None
        self._remediated: dict[tuple[str, str], str] = {}
        self._rows: list[Finding] = []
        self._upgrades: dict[tuple[str, str], UpgradeOptions] = {}
        self._dep_row_keys: list = []
        self._dep_column_keys: list = []
        self._status = "Starting scan..."
        self._busy_message: str | None = None
        self._spinner_index = 0
        self._spinner_timer: Timer | None = None
        self._current_finding: Finding | None = None
        self._current_vuln: Vulnerability | None = None

    @property
    def status_text(self) -> str:
        """Base status text (without the busy spinner frame)."""
        return self._status

    @property
    def current_vulnerability(self) -> Vulnerability | None:
        """The advisory shown in the detail pane, if any."""
        return self._current_vuln

    @property
    def remediated(self) -> dict[tuple[str, str], str]:
        """Dependencies upgraded this session: dependency key -> new constraint."""
        return dict(self._remediated)

    def compose(self) -> ComposeResult:
        """Lay out the dependency table, advisory table, detail pane and status bar."""
        yield Header()
        if self.outdated:
            yield Static(OUTDATED_BANNER, id="mode-banner")
        with Horizontal():
            yield DataTable(id="deps", cursor_type="row", zebra_stripes=True)
            with Vertical(id="right"):
                yield DataTable(id="vulns", cursor_type="row", zebra_stripes=True)
                with VerticalScroll(id="detail-scroll"):
                    yield Markdown("_Select a dependency to see its advisories._", id="detail")
        yield Static(self._status, id="status")
        yield Footer()

    def on_mount(self) -> None:
        """Add the table columns and start the first scan."""
        self.sub_title = str(self.settings.project_path)
        columns = DEP_COLUMNS
        if self.outdated:
            self.sub_title += f"  |  {OUTDATED_SUBTITLE}"
            columns = OUTDATED_COLUMNS
        self._dep_column_keys = self.query_one("#deps", DataTable).add_columns(*columns)
        self.query_one("#vulns", DataTable).add_columns(*VULN_COLUMNS)
        self._start_scan()

    # -- status / busy spinner ----------------------------------------------------

    def _set_status(self, text: str) -> None:
        """Set a finished status line and stop any busy spinner."""
        self._stop_busy()
        self._status = text
        self.query_one("#status", Static).update(text)

    def _start_busy(self, message: str) -> None:
        """Show ``message`` with an animating spinner until the next ``_set_status``."""
        self._stop_busy()
        self._busy_message = message
        self._status = message
        self._spinner_index = 0
        self._paint_busy()
        self._spinner_timer = self.set_interval(0.1, self._tick_spinner)

    def _paint_busy(self) -> None:
        if self._busy_message is None:
            return
        frame = _SPINNER_FRAMES[self._spinner_index % len(_SPINNER_FRAMES)]
        self.query_one("#status", Static).update(f"{frame} {self._busy_message}")

    def _tick_spinner(self) -> None:
        if self._busy_message is None:
            return
        self._spinner_index += 1
        self._paint_busy()

    def _stop_busy(self) -> None:
        if self._spinner_timer is not None:
            self._spinner_timer.stop()
            self._spinner_timer = None
        self._busy_message = None

    def on_unmount(self) -> None:
        """Stop the busy timer if the app is torn down mid-scan."""
        self._stop_busy()

    # -- scanning -----------------------------------------------------------------

    def _start_scan(self) -> None:
        what = " and checking registries for newer releases" if self.outdated else ""
        self._start_busy(f"Scanning {self.settings.project_path}{what} ...")
        self.run_worker(self._scan_in_thread, thread=True, exclusive=True, exit_on_error=False)

    def _scan_in_thread(self) -> None:
        try:
            result = self._scan_fn(self.settings)
            outdated = None
            if self.outdated:
                outdated, warnings = find_outdated(result.dependencies, self._available_versions)
                # Lookup failures hide packages from the list, so they are shown first.
                result.warnings[:0] = warnings
        except Exception as exc:  # noqa: BLE001 - surfaced to the user in the status bar
            self.call_from_thread(self._apply_error, exc)
            return
        self.call_from_thread(self._apply_result, result, outdated)

    def _apply_error(self, exc: Exception) -> None:
        self.result = None
        self._rows = []
        self._upgrades = {}
        self._clear_tables()
        self._set_status(f"Scan failed: {exc}")

    def _clear_tables(self) -> None:
        self.query_one("#deps", DataTable).clear()
        self.query_one("#vulns", DataTable).clear()
        self.query_one("#detail", Markdown).update("_No advisory selected._")
        self._current_finding = None
        self._current_vuln = None

    def _outdated_rows(self, result: ScanResult, outdated: list[OutdatedPackage]) -> list[Finding]:
        """One row per outdated package, reusing the scan's finding when the package has one."""
        by_key = {f.dependency.key: f for f in result.findings}
        self._upgrades = {o.dependency.key: o.options for o in outdated}
        return [by_key.get(o.dependency.key) or Finding(o.dependency, []) for o in outdated]

    def _apply_result(
        self, result: ScanResult, outdated: list[OutdatedPackage] | None = None
    ) -> None:
        self.result = result
        self._clear_tables()
        if outdated is not None:
            self._rows = self._outdated_rows(result, outdated)
            subject = f"{_plural(len(self._rows), 'dependency')} with updates available"
            subject += " (any update, not only security fixes)"
        else:
            self._rows = list(result.findings)
            subject = _plural(len(self._rows), "vulnerable dependency")
        deps = self.query_one("#deps", DataTable)
        self._dep_row_keys = [deps.add_row(*self._dep_cells(finding)) for finding in self._rows]
        summary = (
            f"{_plural(len(result.dependencies), 'dependency')} scanned, "
            f"{subject}, "
            f"{_plural(len(result.warnings), 'warning')}."
        )
        if result.warnings:
            first = result.warnings[0]
            if len(first) > 120:
                first = first[:117] + "..."
            summary += f" First: {first}"
            if len(result.warnings) > 1:
                summary += f" (+{len(result.warnings) - 1} more in the exported report)"
        self._set_status(summary.replace("dependencys", "dependencies"))
        if self._rows:
            self._show_finding(0)

    # -- rows -----------------------------------------------------------------------

    def _is_remediated(self, finding: Finding) -> bool:
        return finding.dependency.key in self._remediated

    def _dep_cells(self, finding: Finding) -> list[str | Text]:
        dep = finding.dependency
        done = self._is_remediated(finding)
        via = dep.version_source + (" (transitive)" if dep.transitive else "")
        if self.outdated:
            options = self._upgrades.get(dep.key)
            values = [
                f"{TICK} upgraded" if done else "",
                dep.name,
                dep.ecosystem,
                dep.version or "?",
                via,
                (options.series_latest if options else None) or "-",
                (options.latest if options else None) or "-",
                str(len(finding.vulnerabilities)) if finding.vulnerabilities else "none",
                ", ".join(dep.source_files),
            ]
            return _cells(values, done)
        values = [
            f"{TICK} upgraded" if done else "",
            dep.name,
            dep.ecosystem,
            dep.version or "?",
            via,
            finding.worst_severity,
            str(len(finding.vulnerabilities)),
            ", ".join(finding.fixed_versions) or "-",
            ", ".join(dep.source_files),
        ]
        return _cells(values, done)

    def _vuln_cells(self, finding: Finding, vuln: Vulnerability) -> list[str | Text]:
        done = self._is_remediated(finding)
        status = f"{TICK} upgraded to {self._remediated[finding.dependency.key]}" if done else ""
        values = [
            vuln.id,
            vuln.severity,
            ", ".join(vuln.cve_ids) or "-",
            vuln.summary or "-",
            status,
        ]
        return _cells(values, done)

    def _refresh_dep_row(self, finding: Finding) -> None:
        if finding not in self._rows:
            return
        index = self._rows.index(finding)
        deps = self.query_one("#deps", DataTable)
        row_key = self._dep_row_keys[index]
        for column_key, value in zip(self._dep_column_keys, self._dep_cells(finding), strict=True):
            deps.update_cell(row_key, column_key, value, update_width=True)
        if self._current_finding is finding:
            self._show_finding(index)

    # -- selection ----------------------------------------------------------------

    def _show_finding(self, index: int) -> None:
        if index < 0 or index >= len(self._rows):
            return
        finding = self._rows[index]
        self._current_finding = finding
        vulns = self.query_one("#vulns", DataTable)
        vulns.clear()
        for vuln in finding.vulnerabilities:
            vulns.add_row(*self._vuln_cells(finding, vuln))
        if self.outdated:
            self._show_upgrade_detail(finding)
        elif finding.vulnerabilities:
            self._show_vulnerability(0)

    def _show_upgrade_detail(self, finding: Finding) -> None:
        dep = finding.dependency
        options = self._upgrades.get(dep.key) or UpgradeOptions(dep.version, None, None, None)
        self._current_vuln = finding.vulnerabilities[0] if finding.vulnerabilities else None
        self.query_one("#detail", Markdown).update(upgrade_markdown(dep, options, finding))

    def _show_vulnerability(self, index: int) -> None:
        finding = self._current_finding
        if not finding or index < 0 or index >= len(finding.vulnerabilities):
            return
        vuln = finding.vulnerabilities[index]
        self._current_vuln = vuln
        self.query_one("#detail", Markdown).update(vulnerability_markdown(finding, vuln))

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        """Show the highlighted dependency's advisories, or the highlighted advisory's details."""
        if event.data_table.id == "deps":
            self._show_finding(event.cursor_row)
        elif event.data_table.id == "vulns":
            # In outdated mode the pane describes the update until the user actually moves
            # into the advisory table; the automatic highlight after repopulating is ignored.
            if self.outdated and not event.data_table.has_focus:
                return
            self._show_vulnerability(event.cursor_row)

    # -- actions ------------------------------------------------------------------

    def action_rescan(self) -> None:
        """Scan the project again (``r``)."""
        self._start_scan()

    def action_write_feeds(self) -> None:
        """Write the RSS and Atom feeds for the last result (``f``); warns if no scan completed."""
        if self.result is None:
            self.notify("Nothing to write: no completed scan.", severity="warning")
            return
        try:
            rss, atom = write_feeds(self.result, self.settings)
        except OSError as exc:
            self._set_status(f"Could not write feeds: {exc}")
            return
        self._set_status(f"Wrote {rss} and {atom}")
        self.notify("Feeds written")

    def action_export_reports(self) -> None:
        """Write the Markdown and text reports for the last result (``e``)."""
        if self.result is None:
            self.notify("Nothing to export: no completed scan.", severity="warning")
            return
        try:
            markdown, text = write_reports(self.result, self.settings)
        except OSError as exc:
            self._set_status(f"Could not write reports: {exc}")
            return
        self._set_status(f"Wrote {markdown} and {text}")
        self.notify("Reports written")

    # -- remediation --------------------------------------------------------------

    def _available_versions(self, dep: Dependency) -> list[str]:
        if self._versions_fn is not None:
            return self._versions_fn(dep)
        return RegistryClient(timeout=self.settings.request_timeout).available_versions(dep)

    def action_remediate(self) -> None:
        """Look up versions for the selected dependency in a worker and offer an upgrade (``u``).

        In outdated mode the versions are already known, so the upgrade dialog opens at once.
        """
        finding = self._current_finding
        if finding is None:
            self.notify("Select a dependency first.", severity="warning")
            return
        if self.outdated:
            self._offer_upgrade(finding)
            return
        self._start_busy(f"Looking up available versions of {finding.dependency.name} ...")
        self.run_worker(
            lambda: self._lookup_versions(finding),
            thread=True,
            exclusive=False,
            exit_on_error=False,
        )

    def _lookup_versions(self, finding: Finding) -> None:
        try:
            plan = plan_remediation(
                finding,
                self._available_versions(finding.dependency),
                webpack_merge=self.result.webpack_merge if self.result else None,
            )
        except RegistryError as exc:
            self.call_from_thread(self._set_status, f"Could not look up versions: {exc}")
            return
        if finding.dependency.transitive:
            target = plan.nearest_safe or plan.latest or "a fixed version"
            self.call_from_thread(self._explain_transitive, finding, target)
            return
        self.call_from_thread(self._offer_remediation, finding, plan)

    def _explain_transitive(self, finding: Finding, target: str) -> None:
        """A transitive dependency has no manifest to edit: say what to add by hand instead."""
        self._set_status(transitive_hint(finding.dependency, target))
        self.notify(
            f"{finding.dependency.name} is transitive: see the status line.", severity="warning"
        )

    def _offer_remediation(self, finding: Finding, plan: RemediationPlan) -> None:
        self._set_status(
            f"{finding.dependency.name}: nearest safe {plan.nearest_safe or 'none'}, "
            f"latest {plan.latest or 'none'}"
        )

        def on_choice(choice: str | None) -> None:
            target = plan.nearest_safe if choice == "nearest" else plan.latest
            self._apply_choice(finding, choice, target)

        self.push_screen(RemediateScreen(finding, plan), on_choice)

    def _offer_upgrade(self, finding: Finding) -> None:
        """Outdated mode: offer the newest same-series release and the latest release."""
        dep = finding.dependency
        options = self._upgrades.get(dep.key)
        if options is None or not options.is_outdated:
            self.notify(f"{dep.name} has no newer release.", severity="warning")
            return
        if dep.transitive:
            self._explain_transitive(finding, options.series_latest or options.latest)
            return

        def on_choice(choice: str | None) -> None:
            target = options.series_latest if choice == "series" else options.latest
            self._apply_choice(finding, choice, target)

        self.push_screen(UpgradeScreen(dep, options, finding), on_choice)

    def _apply_choice(self, finding: Finding, choice: str | None, target: str | None) -> None:
        """Start the manifest rewrite for a dialog choice, or report why nothing happens."""
        if choice is None:
            self._set_status("Upgrade cancelled.")
            return
        if target is None:
            self._set_status("That option has no version to upgrade to.")
            return
        self._start_busy(f"Updating {finding.dependency.name} to {target} ...")
        self.run_worker(
            lambda: self._apply_remediation_in_thread(finding, target),
            thread=True,
            exclusive=False,
            exit_on_error=False,
        )

    def _apply_remediation_in_thread(self, finding: Finding, target: str) -> None:
        dep = finding.dependency
        try:
            outcome = apply_remediation(
                self.settings.project_path,
                dep,
                target,
                settings=self.settings,
                webpack_merge=self.result.webpack_merge if self.result else None,
            )
        except (RemediationError, OSError) as exc:
            self.call_from_thread(self._set_status, f"Could not update {dep.name}: {exc}")
            return
        self.call_from_thread(self._finish_remediation, finding, outcome)

    def _finish_remediation(self, finding: Finding, outcome: RemediationResult) -> None:
        dep = finding.dependency
        self._remediated[dep.key] = outcome.new_constraint
        self._refresh_dep_row(finding)
        authoritative = outcome.authoritative_changes or outcome.changes
        edits = "; ".join(
            f"{c.source_file}: {c.old_constraint or '(any)'} -> {c.new_constraint}"
            for c in authoritative
        )
        warn = f" ({'; '.join(outcome.warnings)})" if outcome.warnings else ""
        self._set_status(f"Updated {edits}. {outcome.hint}{warn} Press r to rescan afterwards.")
        self.notify(f"{dep.name} -> {outcome.new_constraint}")

    def action_open_advisory(self) -> None:
        """Open the selected advisory in the default web browser (``o``)."""
        if self._current_vuln is None:
            self.notify("No advisory selected.", severity="warning")
            return
        webbrowser.open(self._current_vuln.url)
