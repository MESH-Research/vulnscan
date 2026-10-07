"""Scan orchestration."""

from __future__ import annotations

from vulnscan.config import Settings
from vulnscan.models import ScanResult
from vulnscan.osv import OSVClient


def scan(settings: Settings, client: OSVClient | None = None) -> ScanResult:
    raise NotImplementedError
