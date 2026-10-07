"""Textual user interface."""

from __future__ import annotations

from collections.abc import Callable

from textual.app import App

from vulnscan.config import Settings
from vulnscan.models import ScanResult

ScanFn = Callable[[Settings], ScanResult]


class VulnScanApp(App[None]):
    def __init__(self, settings: Settings, scan_fn: ScanFn | None = None) -> None:
        raise NotImplementedError
