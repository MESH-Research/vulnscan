"""Textual user interface."""

from __future__ import annotations

import webbrowser
from collections.abc import Callable

from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import DataTable, Footer, Header, Label, Markdown, OptionList, Static
from textual.widgets.option_list import Option

from vulnscan.config import Settings
from vulnscan.feeds import write_feeds
from vulnscan.models import Dependency, Finding, ScanResult, Vulnerability
from vulnscan.registry import RegistryClient, RegistryError
from vulnscan.remediate import (
    RemediationError,
    RemediationPlan,
    apply_remediation,
    plan_remediation,
)
from vulnscan.reports import write_reports
from vulnscan.scanner import scan
from vulnscan.wordfence import SOURCE as WORDFENCE_SOURCE
from vulnscan.wordfence import wordfence_attribution

ScanFn = Callable[[Settings], ScanResult]
VersionsFn = Callable[[Dependency], list[str]]

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
VULN_COLUMNS = ("Advisory", "Severity", "CVE", "Summary", "Status")
REMEDIATED_STYLE = "bold green"
TICK = "✔"


def _cells(values: list[str], remediated: bool) -> list[str | Text]:
    """Plain strings normally; green text once the dependency has been upgraded."""
    if not remediated:
        return list(values)
    return [Text(v, style=REMEDIATED_STYLE) for v in values]


def _plural(count: int, noun: str) -> str:
    return f"{count} {noun}" if count == 1 else f"{count} {noun}s"


def vulnerability_markdown(finding: Finding, vuln: Vulnerability) -> str:
    """Markdown shown in the detail pane for one advisory of a finding."""
    dep = finding.dependency
    lines = [f"# {vuln.id}", ""]
    if vuln.summary:
        lines += [f"**{vuln.summary}**", ""]
    lines += [
        f"- **Package:** {dep.name} {dep.version or '(unknown version)'} ({dep.ecosystem})",
        "- **Declared in:** "
        + "; ".join(
            f"{d.source_file} as `{d.constraint or 'any version'}`" for d in dep.declared_in
        )
        + f" (version from {dep.version_source})",
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


class RemediateScreen(ModalScreen[str | None]):
    """Ask which upgrade to apply. Dismisses with 'nearest', 'latest' or None."""

    DEFAULT_CSS = """
    RemediateScreen { align: center middle; }
    #remediate-box {
        width: 90; height: auto; padding: 1 2; border: thick $primary; background: $surface;
    }
    #remediate-options { height: auto; margin-top: 1; }
    #remediate-help { color: $text-muted; margin-top: 1; }
    """
    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    def __init__(self, finding: Finding, plan: RemediationPlan) -> None:
        super().__init__()
        self.finding = finding
        self.plan = plan

    def compose(self) -> ComposeResult:
        """Build the dialog: a description, the two upgrade options and a key hint."""
        dep = self.finding.dependency
        with Vertical(id="remediate-box"):
            yield Label(
                f"Upgrade {dep.name} (currently {self.plan.current or 'unknown'}, "
                f"declared in {dep.declared_in_text})"
            )
            if self.plan.nearest_safe:
                nearest = Option(
                    f"Nearest safe version: {self.plan.nearest_safe}  "
                    "(smallest upgrade that clears all known advisories)",
                    id="nearest",
                )
            else:
                nearest = Option(
                    "Nearest safe version: none available", id="nearest", disabled=True
                )
            if self.plan.latest:
                note = "" if self.plan.latest_is_safe else "  (still has known advisories!)"
                latest = Option(f"Latest release: {self.plan.latest}{note}", id="latest")
            else:
                latest = Option("Latest release: none found", id="latest", disabled=True)
            yield OptionList(nearest, latest, id="remediate-options")
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
        """Dismiss with the chosen option id, ``'nearest'`` or ``'latest'``."""
        self.dismiss(event.option.id)

    def action_cancel(self) -> None:
        """Dismiss with ``None`` (Esc)."""
        self.dismiss(None)


class VulnScanApp(App[None]):
    """Interactive browser for scan results.

    Scans run in a worker thread so the interface stays responsive. Keys: ``r`` rescan,
    ``f`` write feeds, ``e`` export reports, ``u`` upgrade the selected dependency,
    ``o`` open the selected advisory in a browser, ``q`` quit. ``scan_fn`` and
    ``versions_fn`` replace the real scanner and registry lookups in tests.
    """

    TITLE = "vulnscan"
    CSS = """
    #deps { width: 3fr; height: 1fr; }
    #right { width: 2fr; height: 1fr; }
    #vulns { height: auto; max-height: 40%; min-height: 4; }
    #detail-scroll { height: 1fr; border-top: solid $primary; padding: 0 1; }
    #status { height: auto; padding: 0 1; background: $panel; }
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
    ) -> None:
        super().__init__()
        self.settings = settings
        self._scan_fn: ScanFn = scan_fn or scan
        self._versions_fn: VersionsFn | None = versions_fn
        self.result: ScanResult | None = None
        self._remediated: dict[tuple[str, str], str] = {}
        self._dep_row_keys: list = []
        self._dep_column_keys: list = []
        self._status = "Starting scan..."
        self._current_finding: Finding | None = None
        self._current_vuln: Vulnerability | None = None

    @property
    def status_text(self) -> str:
        """Text currently shown in the status bar."""
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
        self._dep_column_keys = self.query_one("#deps", DataTable).add_columns(*DEP_COLUMNS)
        self.query_one("#vulns", DataTable).add_columns(*VULN_COLUMNS)
        self._start_scan()

    # -- scanning -----------------------------------------------------------------

    def _set_status(self, text: str) -> None:
        self._status = text
        self.query_one("#status", Static).update(text)

    def _start_scan(self) -> None:
        self._set_status(f"Scanning {self.settings.project_path} ...")
        self.run_worker(self._scan_in_thread, thread=True, exclusive=True, exit_on_error=False)

    def _scan_in_thread(self) -> None:
        try:
            result = self._scan_fn(self.settings)
        except Exception as exc:  # noqa: BLE001 - surfaced to the user in the status bar
            self.call_from_thread(self._apply_error, exc)
            return
        self.call_from_thread(self._apply_result, result)

    def _apply_error(self, exc: Exception) -> None:
        self.result = None
        self._clear_tables()
        self._set_status(f"Scan failed: {exc}")

    def _clear_tables(self) -> None:
        self.query_one("#deps", DataTable).clear()
        self.query_one("#vulns", DataTable).clear()
        self.query_one("#detail", Markdown).update("_No advisory selected._")
        self._current_finding = None
        self._current_vuln = None

    def _apply_result(self, result: ScanResult) -> None:
        self.result = result
        self._clear_tables()
        deps = self.query_one("#deps", DataTable)
        self._dep_row_keys = [
            deps.add_row(*self._dep_cells(finding)) for finding in result.findings
        ]
        summary = (
            f"{_plural(len(result.dependencies), 'dependency')} scanned, "
            f"{_plural(len(result.findings), 'vulnerable dependency')}, "
            f"{_plural(len(result.warnings), 'warning')}."
        )
        if result.warnings:
            summary += f" First: {result.warnings[0]}"
            if len(result.warnings) > 1:
                summary += f" (+{len(result.warnings) - 1} more in the exported report)"
        self._set_status(summary.replace("dependencys", "dependencies"))
        if result.findings:
            self._show_finding(0)

    # -- rows -----------------------------------------------------------------------

    def _is_remediated(self, finding: Finding) -> bool:
        return finding.dependency.key in self._remediated

    def _dep_cells(self, finding: Finding) -> list[str | Text]:
        dep = finding.dependency
        done = self._is_remediated(finding)
        values = [
            f"{TICK} upgraded" if done else "",
            dep.name,
            dep.ecosystem,
            dep.version or "?",
            dep.version_source,
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
        if not self.result or finding not in self.result.findings:
            return
        index = self.result.findings.index(finding)
        deps = self.query_one("#deps", DataTable)
        row_key = self._dep_row_keys[index]
        for column_key, value in zip(self._dep_column_keys, self._dep_cells(finding), strict=True):
            deps.update_cell(row_key, column_key, value, update_width=True)
        if self._current_finding is finding:
            self._show_finding(index)

    # -- selection ----------------------------------------------------------------

    def _show_finding(self, index: int) -> None:
        if not self.result or index < 0 or index >= len(self.result.findings):
            return
        finding = self.result.findings[index]
        self._current_finding = finding
        vulns = self.query_one("#vulns", DataTable)
        vulns.clear()
        for vuln in finding.vulnerabilities:
            vulns.add_row(*self._vuln_cells(finding, vuln))
        if finding.vulnerabilities:
            self._show_vulnerability(0)

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
        """Look up versions for the selected dependency in a worker and offer an upgrade (``u``)."""
        finding = self._current_finding
        if finding is None:
            self.notify("Select a vulnerable dependency first.", severity="warning")
            return
        self._set_status(f"Looking up available versions of {finding.dependency.name} ...")
        self.run_worker(
            lambda: self._lookup_versions(finding),
            thread=True,
            exclusive=False,
            exit_on_error=False,
        )

    def _lookup_versions(self, finding: Finding) -> None:
        try:
            plan = plan_remediation(finding, self._available_versions(finding.dependency))
        except RegistryError as exc:
            self.call_from_thread(self._set_status, f"Could not look up versions: {exc}")
            return
        self.call_from_thread(self._offer_remediation, finding, plan)

    def _offer_remediation(self, finding: Finding, plan: RemediationPlan) -> None:
        self._set_status(
            f"{finding.dependency.name}: nearest safe {plan.nearest_safe or 'none'}, "
            f"latest {plan.latest or 'none'}"
        )

        def on_choice(choice: str | None) -> None:
            if choice is None:
                self._set_status("Upgrade cancelled.")
                return
            target = plan.nearest_safe if choice == "nearest" else plan.latest
            if target is None:
                self._set_status("That option has no version to upgrade to.")
                return
            self._apply_remediation(finding, target)

        self.push_screen(RemediateScreen(finding, plan), on_choice)

    def _apply_remediation(self, finding: Finding, target: str) -> None:
        dep = finding.dependency
        try:
            outcome = apply_remediation(self.settings.project_path, dep, target)
        except (RemediationError, OSError) as exc:
            self._set_status(f"Could not update {dep.name}: {exc}")
            return
        self._remediated[dep.key] = outcome.new_constraint
        self._refresh_dep_row(finding)
        edits = "; ".join(
            f"{c.source_file}: {c.old_constraint or '(any)'} -> {c.new_constraint}"
            for c in outcome.changes
        )
        self._set_status(f"Updated {edits}. {outcome.hint} Press r to rescan afterwards.")
        self.notify(f"{dep.name} -> {outcome.new_constraint}")

    def action_open_advisory(self) -> None:
        """Open the selected advisory in the default web browser (``o``)."""
        if self._current_vuln is None:
            self.notify("No advisory selected.", severity="warning")
            return
        webbrowser.open(self._current_vuln.url)
