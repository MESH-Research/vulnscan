"""Look up the versions available for a package on PyPI, Packagist, wordpress.org, npm
or a container registry.

Only stable, non-yanked releases are returned, sorted ascending.
"""

from __future__ import annotations

import re
from urllib.parse import quote

import httpx

from vulnscan import __version__
from vulnscan.models import CONTAINER, NPM, PACKAGIST, PYPI, WORDPRESS, Dependency, normalize_name
from vulnscan.parsers.containers import registry_and_repository, version_from_tag
from vulnscan.versioncmp import is_prerelease, normalize_version, sort_versions

PYPI_URL = "https://pypi.org/pypi/{name}/json"
PACKAGIST_URL = "https://repo.packagist.org/p2/{name}.json"
WP_PLUGIN_URL = "https://api.wordpress.org/plugins/info/1.2/"
WP_THEME_URL = "https://api.wordpress.org/themes/info/1.2/"
WP_CORE_URL = "https://api.wordpress.org/core/version-check/1.7/"
NPM_URL = "https://registry.npmjs.org/{name}"
TAGS_PAGE_SIZE = 1000

_CHALLENGE_FIELD = re.compile(r'(\w+)="([^"]*)"')
_NEXT_LINK = re.compile(r'<([^>]+)>\s*;\s*rel="?next"?')


def _component_count(version: str) -> int:
    return len(version.split("-", 1)[0].split("."))


class RegistryError(Exception):
    """Raised when available versions cannot be determined."""


class RegistryClient:
    """Query PyPI, Packagist, wordpress.org, npm or a container registry for the versions
    of a dependency.

    ``transport`` is for tests. Every failure surfaces as :class:`RegistryError`.
    """

    def __init__(self, timeout: float = 30.0, transport: httpx.BaseTransport | None = None) -> None:
        self.timeout = timeout
        self._transport = transport

    def _get_json(self, url: str, params: dict | None = None) -> dict:
        try:
            with httpx.Client(
                timeout=self.timeout,
                transport=self._transport,
                headers={"User-Agent": f"vulnscan/{__version__}", "Accept": "application/json"},
                follow_redirects=True,
            ) as http:
                response = http.get(url, params=params)
        except httpx.HTTPError as exc:
            raise RegistryError(f"Could not reach {url}: {exc}") from exc
        if response.status_code == 404:
            raise RegistryError(f"Package not found at {response.url}")
        if response.status_code >= 400:
            raise RegistryError(f"{response.url} returned HTTP {response.status_code}")
        try:
            data = response.json()
        except ValueError as exc:
            raise RegistryError(f"{response.url} returned invalid JSON") from exc
        if not isinstance(data, dict):
            raise RegistryError(f"{response.url} returned an unexpected response")
        return data

    def _pypi(self, dep: Dependency) -> list[str]:
        data = self._get_json(PYPI_URL.format(name=normalize_name(dep.name, PYPI)))
        versions = []
        for version, files in (data.get("releases") or {}).items():
            if not files or all(f.get("yanked") for f in files if isinstance(f, dict)):
                continue
            versions.append(str(version))
        return versions

    def _packagist(self, dep: Dependency) -> list[str]:
        name = normalize_name(dep.name, PACKAGIST)
        data = self._get_json(PACKAGIST_URL.format(name=name))
        entries = (data.get("packages") or {}).get(name)
        if not isinstance(entries, list):
            raise RegistryError(f"Packagist has no versions for {name}")
        return [
            normalize_version(str(e["version"]))
            for e in entries
            if isinstance(e, dict) and isinstance(e.get("version"), str)
        ]

    def _wordpress(self, dep: Dependency) -> list[str]:
        if dep.kind == "core":
            data = self._get_json(WP_CORE_URL)
            return list(
                {
                    str(o["version"])
                    for o in data.get("offers") or []
                    if isinstance(o, dict) and o.get("version")
                }
            )
        if dep.kind == "theme":
            url, action = WP_THEME_URL, "theme_information"
        else:
            url, action = WP_PLUGIN_URL, "plugin_information"
        params = {"action": action, "request[slug]": dep.slug, "request[fields][versions]": "1"}
        data = self._get_json(url, params)
        if data.get("error"):
            raise RegistryError(f"wordpress.org: {data['error']} ({dep.kind} {dep.slug})")
        versions = {str(v) for v in (data.get("versions") or {}) if str(v).lower() != "trunk"}
        if data.get("version"):
            versions.add(str(data["version"]))
        if not versions:
            raise RegistryError(f"wordpress.org lists no versions for {dep.kind} {dep.slug}")
        return list(versions)

    def _npm(self, dep: Dependency) -> list[str]:
        name = normalize_name(dep.name, NPM)
        data = self._get_json(NPM_URL.format(name=quote(name, safe="@")))
        versions = data.get("versions")
        if not isinstance(versions, dict) or not versions:
            raise RegistryError(f"npm lists no versions for {name}")
        return [str(v) for v in versions]

    def _registry_token(self, challenge: str) -> str | None:
        """Fetch an anonymous bearer token as a ``WWW-Authenticate: Bearer`` challenge asks."""
        fields = dict(_CHALLENGE_FIELD.findall(challenge))
        realm = fields.get("realm")
        if not realm:
            return None
        params = {k: v for k, v in fields.items() if k in ("service", "scope")}
        data = self._get_json(realm, params)
        token = data.get("token") or data.get("access_token")
        return str(token) if token else None

    def _docker_tags(self, registry: str, repository: str) -> list[str]:
        """Every tag of a repository, through the Docker Registry HTTP API v2."""
        url: str | None = f"https://{registry}/v2/{repository}/tags/list?n={TAGS_PAGE_SIZE}"
        headers = {"User-Agent": f"vulnscan/{__version__}", "Accept": "application/json"}
        tags: list[str] = []
        try:
            with httpx.Client(
                timeout=self.timeout, transport=self._transport, follow_redirects=True
            ) as http:
                while url:
                    response = http.get(url, headers=headers)
                    if response.status_code == 401 and "Authorization" not in headers:
                        token = self._registry_token(response.headers.get("WWW-Authenticate", ""))
                        if token:
                            headers["Authorization"] = f"Bearer {token}"
                            continue
                    if response.status_code == 404:
                        raise RegistryError(f"{registry} has no repository {repository}")
                    if response.status_code >= 400:
                        raise RegistryError(
                            f"{registry} returned HTTP {response.status_code} for {repository}"
                        )
                    try:
                        data = response.json()
                    except ValueError as exc:
                        raise RegistryError(f"{registry} returned invalid JSON") from exc
                    page = data.get("tags") if isinstance(data, dict) else None
                    tags.extend(str(t) for t in page or [])
                    url = None
                    link = _NEXT_LINK.search(response.headers.get("Link", ""))
                    if link:
                        url = str(httpx.URL(f"https://{registry}").join(link.group(1)))
        except httpx.HTTPError as exc:
            raise RegistryError(f"Could not reach {registry}: {exc}") from exc
        return tags

    def _docker(self, dep: Dependency) -> list[str]:
        """Versions of tags sharing the dependency's variant (``8.2.20`` for ``-fpm-bookworm``).

        Only tags at least as specific as the current one count: on ``8.2.19-fpm`` the
        floating ``8.3-fpm`` is not a candidate, but ``8.3.0-fpm`` is.
        """
        current, variant = version_from_tag(dep.constraint)
        if dep.version is None or current is None:
            raise RegistryError(
                f"{dep.name}: tag {dep.constraint or 'latest'!r} does not name a version, so "
                "there is no series of tags to choose an upgrade from"
            )
        registry, repository = registry_and_repository(dep.name)
        depth = _component_count(current)
        versions: list[str] = []
        for tag in self._docker_tags(registry, repository):
            version, tag_variant = version_from_tag(tag)
            if version and tag_variant == variant and _component_count(version) >= depth:
                versions.append(version)
        return versions

    def available_versions(self, dep: Dependency) -> list[str]:
        """Stable, installable versions of the package, oldest first."""
        if dep.ecosystem == PYPI:
            raw = self._pypi(dep)
        elif dep.ecosystem == PACKAGIST:
            raw = self._packagist(dep)
        elif dep.ecosystem == WORDPRESS:
            raw = self._wordpress(dep)
        elif dep.ecosystem == NPM:
            raw = self._npm(dep)
        elif dep.ecosystem == CONTAINER:
            raw = self._docker(dep)
        else:
            raise RegistryError(f"No registry known for ecosystem {dep.ecosystem!r}")
        stable = {v for v in raw if v and not is_prerelease(v, dep.ecosystem)}
        return sort_versions(list(stable), dep.ecosystem)
