"""Parsers for container build files: Dockerfiles and Docker Compose files.

Every image an application is built ``FROM`` or a Compose service runs as is a
dependency whose version is the image tag. A fully numeric tag such as ``8.2.19``
is treated as pinned; a shorter one such as ``8.2`` floats within its series and is
treated as a constraint whose lower bound is the series start.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from dotenv import dotenv_values

from vulnscan.models import CONTAINER, Dependency

DOCKER_HUB_REGISTRY = "registry-1.docker.io"

OS_IMAGES: frozenset[str] = frozenset(
    {
        "debian",
        "ubuntu",
        "alpine",
        "busybox",
        "fedora",
        "centos",
        "rockylinux",
        "almalinux",
        "amazonlinux",
        "oraclelinux",
        "archlinux",
        "opensuse/leap",
        "opensuse/tumbleweed",
        "redhat/ubi8",
        "redhat/ubi9",
        "registry.access.redhat.com/ubi8",
        "registry.access.redhat.com/ubi9",
        "gcr.io/distroless/base",
        "gcr.io/distroless/static",
        "gcr.io/distroless/cc",
        "gcr.io/distroless/python3",
        "gcr.io/distroless/java",
        "gcr.io/distroless/nodejs",
        "scratch",
    }
)
"""Operating-system base images: listed as dependencies but never queried for advisories.

Their tags name a distribution release, not a piece of software with its own CVE
history, so NVD cannot be asked about them in a meaningful way.
"""
_DOCKER_HUB_ALIASES = {
    "docker.io",
    "index.docker.io",
    "registry.hub.docker.com",
    "registry-1.docker.io",
}

_VERSION_TAG = re.compile(
    r"^v?(?P<numbers>\d+(?:\.\d+)*)"
    r"(?P<pre>[-_.]?(?:rc|alpha|beta|pre)\.?\d*)?"
    r"(?P<variant>$|[-_.].*)$",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class ImageReference:
    """A parsed image reference such as ``ghcr.io/astral-sh/uv:0.5.9@sha256:...``.

    ``name`` is the canonical image name (``php``, ``ghcr.io/astral-sh/uv``), ``tag``
    the tag as written (empty when absent), ``digest`` the ``sha256:...`` pin if any.
    """

    name: str
    tag: str = ""
    digest: str = ""


def _looks_like_registry(component: str) -> bool:
    return "." in component or ":" in component or component == "localhost"


def canonical_image_name(name: str) -> str:
    """Lower-case the name and drop Docker Hub's implicit ``docker.io/library/`` prefix."""
    text = name.strip().lower()
    parts = text.split("/")
    if len(parts) > 1 and parts[0] in _DOCKER_HUB_ALIASES:
        parts = parts[1:]
        if len(parts) == 2 and parts[0] == "library":
            parts = parts[1:]
    elif len(parts) == 2 and parts[0] == "library":
        parts = parts[1:]
    return "/".join(parts)


def parse_image_reference(text: str) -> ImageReference | None:
    """Split an image reference into its canonical name, tag and digest.

    ``None`` for empty text, ``scratch``, or anything still containing a ``$`` variable.
    """
    ref = text.strip()
    if not ref or "$" in ref or ref.lower() == "scratch":
        return None
    digest = ""
    if "@" in ref:
        ref, digest = ref.split("@", 1)
    tag = ""
    last_slash = ref.rfind("/")
    colon = ref.rfind(":")
    if colon > last_slash:
        ref, tag = ref[:colon], ref[colon + 1 :]
    if not ref:
        return None
    return ImageReference(canonical_image_name(ref), tag.strip(), digest.strip())


def registry_and_repository(name: str) -> tuple[str, str]:
    """The registry host and repository path used to query tags for an image name.

    Docker Hub names (``php``, ``grafana/grafana``) map to ``registry-1.docker.io`` with
    single-component names under ``library/``.
    """
    parts = canonical_image_name(name).split("/")
    if len(parts) > 1 and _looks_like_registry(parts[0]):
        return parts[0], "/".join(parts[1:])
    if len(parts) == 1:
        return DOCKER_HUB_REGISTRY, f"library/{parts[0]}"
    return DOCKER_HUB_REGISTRY, "/".join(parts)


def version_from_tag(tag: str) -> tuple[str | None, str]:
    """``(version, variant)`` for a tag: ``8.2.19-fpm`` gives ``("8.2.19", "-fpm")``.

    A leading ``v`` is dropped and a pre-release marker joined to the numbers with a
    hyphen (``8.2.8RC1`` reads as ``8.2.8-RC1``). Tags that do not start with a number
    (``latest``, ``bookworm-slim``) have no version and are returned whole as the variant.
    """
    match = _VERSION_TAG.match(tag.strip())
    if not match:
        return None, tag.strip()
    version = match.group("numbers")
    pre = match.group("pre")
    if pre:
        version += "-" + pre.lstrip("-_.")
    return version, match.group("variant")


def tag_for_version(version: str, variant: str) -> str:
    """The tag naming ``version`` with the same variant suffix."""
    return f"{version}{variant}"


def _dependency(ref: ImageReference, source_file: str) -> Dependency:
    version, _variant = version_from_tag(ref.tag)
    if version is None:
        source = "unknown"
    elif len(version.split("-", 1)[0].split(".")) >= 3:
        source = "pinned"
    else:
        source = "constraint"
    return Dependency(
        name=ref.name,
        ecosystem=CONTAINER,
        constraint=ref.tag,
        version=version,
        version_source=source,
        source_file=source_file,
        kind="image",
    )


def _relative(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


# --- Dockerfile ---------------------------------------------------------------------------------

_DOCKERFILE_NAMES = {"dockerfile", "containerfile"}
_VARIABLE = re.compile(r"\$(?:\{(?P<braced>[^}]*)\}|(?P<bare>[A-Za-z_][A-Za-z0-9_]*))")


def is_dockerfile(path: Path) -> bool:
    """``Dockerfile``, ``Containerfile``, ``Dockerfile.<x>`` or ``<x>.Dockerfile`` (any case)."""
    lowered = path.name.lower()
    if lowered in _DOCKERFILE_NAMES:
        return True
    stem, dot, suffix = lowered.partition(".")
    if dot and stem in _DOCKERFILE_NAMES and suffix and suffix != "md":
        return True
    return lowered.rsplit(".", 1)[-1] in _DOCKERFILE_NAMES and "." in lowered


def substitute_variables(text: str, values: Mapping[str, str]) -> str:
    """Expand ``$VAR``, ``${VAR}``, ``${VAR:-default}`` and ``${VAR-default}``.

    ``$$`` is a literal dollar sign. Variables with neither a value nor a default stay
    as written, so callers can detect them.
    """

    def expand(match: re.Match) -> str:
        if match.group("bare") is not None:
            name = match.group("bare")
            return values[name] if values.get(name) else match.group(0)
        inner = match.group("braced")
        name, default = inner, None
        for sep in (":-", "-"):
            if sep in inner:
                name, default = inner.split(sep, 1)
                break
        value = values.get(name)
        if value:
            return value
        if default is not None:
            return default
        return match.group(0)

    parts = text.split("$$")
    return "$".join(_VARIABLE.sub(expand, part) for part in parts)


def dockerfile_instructions(text: str) -> list[tuple[str, str]]:
    """``(INSTRUCTION, arguments)`` pairs with comments dropped and continuations joined."""
    instructions: list[tuple[str, str]] = []
    buffer = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not buffer and (not line or line.startswith("#")):
            continue
        if buffer and line.startswith("#"):
            continue
        if line.endswith("\\"):
            buffer += line[:-1] + " "
            continue
        buffer += line
        head, _, rest = buffer.strip().partition(" ")
        instructions.append((head.upper(), rest.strip()))
        buffer = ""
    if buffer.strip():
        head, _, rest = buffer.strip().partition(" ")
        instructions.append((head.upper(), rest.strip()))
    return instructions


def _from_image(arguments: str) -> tuple[str, str | None]:
    """The image reference and the stage name (``AS name``) from ``FROM`` arguments."""
    tokens = [t for t in arguments.split() if not t.startswith("--")]
    if not tokens:
        return "", None
    stage = None
    if len(tokens) >= 3 and tokens[1].lower() == "as":
        stage = tokens[2]
    return tokens[0], stage


def dockerfile_images(text: str) -> list[tuple[str, str]]:
    """``(raw reference, expanded reference)`` for every ``FROM`` that names an image.

    ``ARG`` defaults declared before a ``FROM`` are substituted; references to earlier
    stages and ``scratch`` are skipped.
    """
    args: dict[str, str] = {}
    stages: set[str] = set()
    images: list[tuple[str, str]] = []
    for instruction, arguments in dockerfile_instructions(text):
        if instruction == "ARG":
            name, eq, value = arguments.partition("=")
            if eq:
                args[name.strip()] = value.strip().strip("\"'")
            continue
        if instruction != "FROM":
            continue
        raw, stage = _from_image(arguments)
        if stage:
            stages.add(stage.lower())
        if not raw or raw.lower() in stages:
            continue
        images.append((raw, substitute_variables(raw, args)))
    return images


def parse_dockerfile(path: Path, root: Path) -> list[Dependency]:
    """One dependency per image a Dockerfile builds ``FROM``.

    Returns ``[]`` when the file is missing or unreadable.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []
    source_file = _relative(path, root)
    deps: list[Dependency] = []
    for _raw, expanded in dockerfile_images(text):
        ref = parse_image_reference(expanded)
        if ref is not None:
            deps.append(_dependency(ref, source_file))
    return deps


# --- Compose -----------------------------------------------------------------------------------

_COMPOSE_NAMES = re.compile(r"^(docker-compose|compose)(\.[^.]+)*\.ya?ml$", re.IGNORECASE)
_COMPOSE_IMAGE = re.compile(r"^(\s*)image\s*:\s*(.*)$")


def is_compose_file(path: Path) -> bool:
    """``docker-compose*.yml``/``.yaml`` or ``compose*.yml``/``.yaml``."""
    return bool(_COMPOSE_NAMES.match(path.name))


def _strip_yaml_scalar(value: str) -> str:
    text = value.strip()
    if text[:1] in ("'", '"') and text.count(text[0]) >= 2:
        return text[1 : text.index(text[0], 1)]
    return text.split(" #", 1)[0].strip() if " #" in text else text


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" \t"))


def compose_images(text: str) -> list[str]:
    """The ``image:`` value of every service, as written, in file order.

    Only keys directly under a service are read, so an ``image`` key nested in a
    service's ``environment`` block is ignored. The file is scanned by indentation
    rather than parsed as YAML.
    """
    images: list[str] = []
    in_services = False
    service_indent: int | None = None
    child_indent: int | None = None
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = _indent(raw)
        if indent == 0:
            in_services = bool(re.match(r"^services\s*:\s*$", stripped))
            service_indent = child_indent = None
            continue
        if not in_services:
            continue
        if service_indent is None or indent <= service_indent:
            service_indent, child_indent = indent, None
            continue
        if child_indent is None:
            child_indent = indent
        if indent != child_indent:
            continue
        match = _COMPOSE_IMAGE.match(raw)
        if match:
            value = _strip_yaml_scalar(match.group(2))
            if value:
                images.append(value)
    return images


def _compose_environment(path: Path) -> dict[str, str]:
    env_file = path.parent / ".env"
    if not env_file.is_file():
        return {}
    try:
        return {k: v for k, v in dotenv_values(env_file).items() if v is not None}
    except (OSError, UnicodeDecodeError):
        return {}


def parse_compose_file(path: Path, root: Path) -> list[Dependency]:
    """One dependency per ``image:`` a Compose file's services run.

    ``${VAR}`` interpolation uses defaults written in the file and a ``.env`` next to it.
    Services that only ``build`` are skipped, as are images still containing unresolved
    variables. Returns ``[]`` when the file is missing or unreadable.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []
    values = _compose_environment(path)
    source_file = _relative(path, root)
    deps: list[Dependency] = []
    for raw in compose_images(text):
        ref = parse_image_reference(substitute_variables(raw, values))
        if ref is not None:
            deps.append(_dependency(ref, source_file))
    return deps
