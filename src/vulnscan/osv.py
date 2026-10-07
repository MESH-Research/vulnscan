"""Client for the OSV.dev vulnerability API."""

from __future__ import annotations

from collections.abc import Iterable

import httpx

from vulnscan.models import Dependency, Vulnerability


class OSVError(Exception):
    """Raised when OSV cannot be queried."""


def parse_osv_vulnerability(data: dict, package_name: str, ecosystem: str) -> Vulnerability:
    raise NotImplementedError


class OSVClient:
    def __init__(
        self,
        base_url: str = "https://api.osv.dev",
        timeout: float = 30.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._transport = transport

    def query_batch(self, deps: list[Dependency]) -> list[list[str]]:
        raise NotImplementedError

    def get_vulnerability(self, vuln_id: str, package_name: str, ecosystem: str) -> Vulnerability:
        raise NotImplementedError

    def find_vulnerabilities(
        self, deps: Iterable[Dependency]
    ) -> dict[Dependency, list[Vulnerability]]:
        raise NotImplementedError
