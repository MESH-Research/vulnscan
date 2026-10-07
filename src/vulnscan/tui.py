"""Textual user interface."""

from __future__ import annotations

import webbrowser
from collections.abc import Callable

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import DataTable, Footer, Header, Markdown, Static

from vulnscan.config import Settings
from vulnscan.feeds import write_feeds
from vulnscan.models import Finding, ScanResult, Vulnerability
from vulnscan.reports import write_reports
from vulnscan.scanner import scan
from vulnscan.wordfence import SOURCE as WORDFENCE_SOURCE
from vulnscan.wordfence import wordfence_attribution

ScanFn = Callable[[Settings], ScanResult]

DEP_COLUMNS = (
    "Package",
    "Ecosystem",
    "Version",
    "Via",
    "Severity",
    "Advisories",
    "Fixed in",
    "File",
)
VULN_COLUMNS = ("Advisory", "Severity", "CVE", "Summary")


def _plural(count: int, noun: str) -> str:
    return f"{count} {noun}" if count == 1 else f"{count} {noun}s"


def vulnerability_markdown(finding: Finding, vuln: Vulnerability) -> str:
    dep = finding.dependency
    lines = [f"# {vuln.id}", ""]
    if vuln.summary:
        lines += [f"**{vuln.summary}**", ""]
    lines += [
        f"- **Package:** {dep.name} {dep.version or '(unknown version)'} ({dep.ecosystem})",
        f"- **Declared in:** {dep.source_file} as `{dep.constraint or 'any version'}`"
        f" (version from {dep.version_source})",
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


class VulnScanApp(App[None]):
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
        Binding("o", "open_advisory", "Open advisory"),
        Binding("q", "quit", "Quit"),
    ]

    def __init__(self, settings: Settings, scan_fn: ScanFn | None = None) -> None:
        super().__init__()
        self.settings = settings
        self._scan_fn: ScanFn = scan_fn or scan
        self.result: ScanResult | None = None
        self._status = "Starting scan..."
        self._current_finding: Finding | None = None
        self._current_vuln: Vulnerability | None = None

    @property
    def status_text(self) -> str:
        return self._status

    @property
    def current_vulnerability(self) -> Vulnerability | None:
        return self._current_vuln

    def compose(self) -> ComposeResult:
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
        self.sub_title = str(self.settings.project_path)
        self.query_one("#deps", DataTable).add_columns(*DEP_COLUMNS)
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
        for finding in result.findings:
            dep = finding.dependency
            deps.add_row(
                dep.name,
                dep.ecosystem,
                dep.version or "?",
                dep.version_source,
                finding.worst_severity,
                str(len(finding.vulnerabilities)),
                ", ".join(finding.fixed_versions) or "-",
                dep.source_file,
            )
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

    # -- selection ----------------------------------------------------------------

    def _show_finding(self, index: int) -> None:
        if not self.result or index < 0 or index >= len(self.result.findings):
            return
        finding = self.result.findings[index]
        self._current_finding = finding
        vulns = self.query_one("#vulns", DataTable)
        vulns.clear()
        for vuln in finding.vulnerabilities:
            vulns.add_row(
                vuln.id, vuln.severity, ", ".join(vuln.cve_ids) or "-", vuln.summary or "-"
            )
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
        if event.data_table.id == "deps":
            self._show_finding(event.cursor_row)
        elif event.data_table.id == "vulns":
            self._show_vulnerability(event.cursor_row)

    # -- actions ------------------------------------------------------------------

    def action_rescan(self) -> None:
        self._start_scan()

    def action_write_feeds(self) -> None:
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

    def action_open_advisory(self) -> None:
        if self._current_vuln is None:
            self.notify("No advisory selected.", severity="warning")
            return
        webbrowser.open(self._current_vuln.url)
