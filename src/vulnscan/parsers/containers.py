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
from vulnscan.parsers.yamlish import load_yamlish

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


def is_compose_file(path: Path) -> bool:
    """``docker-compose*.yml``/``.yaml`` or ``compose*.yml``/``.yaml``."""
    return bool(_COMPOSE_NAMES.match(path.name))


def _image_value(spec: object, key: str = "image") -> str | None:
    """A written image reference from a scalar or a mapping holding it under ``key``."""
    if isinstance(spec, str):
        return spec or None
    if isinstance(spec, dict) and isinstance(spec.get(key), str):
        return spec[key] or None
    return None


def compose_images(text: str) -> list[str]:
    """The ``image:`` value of every service, as written, in file order.

    Only the ``image`` key directly under a service is read, so an ``image`` key nested
    in a service's ``environment`` block is ignored.
    """
    data = load_yamlish(text)
    services = data.get("services") if isinstance(data, dict) else None
    if not isinstance(services, dict):
        return []
    images: list[str] = []
    for service in services.values():
        if isinstance(service, dict):
            image = _image_value(service.get("image"))
            if image:
                images.append(image)
    return images


def _compose_environment(path: Path) -> dict[str, str]:
    env_file = path.parent / ".env"
    if not env_file.is_file():
        return {}
    try:
        return {k: v for k, v in dotenv_values(env_file).items() if v is not None}
    except (OSError, UnicodeDecodeError):
        return {}


def _parse_written_images(
    path: Path, root: Path, images: list[str], values: Mapping[str, str]
) -> list[Dependency]:
    deps: list[Dependency] = []
    source_file = _relative(path, root)
    for raw in images:
        ref = parse_image_reference(substitute_variables(raw, values))
        if ref is not None:
            deps.append(_dependency(ref, source_file))
    return deps


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
    return _parse_written_images(path, root, compose_images(text), _compose_environment(path))


# --- CI configuration ----------------------------------------------------------------------

GITHUB_WORKFLOWS_DIR = ".github/workflows"
GITLAB_CI_DIR = ".gitlab/ci"
CI_DIRECTORIES = (GITHUB_WORKFLOWS_DIR, GITLAB_CI_DIR)
"""Dot-directories that discovery enters, although hidden directories are otherwise skipped."""

DOCKER_URI_PREFIX = "docker://"
_GITLAB_RESERVED = {
    "default",
    "include",
    "stages",
    "variables",
    "workflow",
    "cache",
    "before_script",
    "after_script",
    "image",
    "services",
    "pages",
    "spec",
}


def _is_yaml(path: Path) -> bool:
    return path.name.lower().endswith((".yml", ".yaml"))


def is_github_workflow(path: Path) -> bool:
    """A ``.yml``/``.yaml`` file inside a ``.github/workflows`` directory."""
    parts = path.parts
    return (
        _is_yaml(path)
        and len(parts) >= 3
        and parts[-3].lower() == ".github"
        and parts[-2].lower() == "workflows"
    )


def is_gitlab_ci_file(path: Path) -> bool:
    """``.gitlab-ci.yml``, ``<x>.gitlab-ci.yml`` or a ``.yml`` inside ``.gitlab/ci``."""
    lowered = path.name.lower()
    if lowered == ".gitlab-ci.yml" or lowered.endswith((".gitlab-ci.yml", ".gitlab-ci.yaml")):
        return True
    parts = path.parts
    return (
        _is_yaml(path)
        and len(parts) >= 3
        and parts[-3].lower() == ".gitlab"
        and parts[-2].lower() == "ci"
    )


def github_workflow_images(text: str) -> list[str]:
    """Job ``container`` and ``services`` images and ``uses: docker://`` steps, as written."""
    data = load_yamlish(text)
    jobs = data.get("jobs") if isinstance(data, dict) else None
    if not isinstance(jobs, dict):
        return []
    images: list[str] = []
    for job in jobs.values():
        if not isinstance(job, dict):
            continue
        container = _image_value(job.get("container"))
        if container:
            images.append(container)
        services = job.get("services")
        if isinstance(services, dict):
            for service in services.values():
                image = _image_value(service)
                if image:
                    images.append(image)
        steps = job.get("steps")
        for step in steps if isinstance(steps, list) else []:
            uses = step.get("uses") if isinstance(step, dict) else None
            if isinstance(uses, str) and uses.startswith(DOCKER_URI_PREFIX):
                images.append(uses)
    return images


def _gitlab_section_images(section: dict) -> list[str]:
    images: list[str] = []
    image = _image_value(section.get("image"), key="name")
    if image:
        images.append(image)
    services = section.get("services")
    for service in services if isinstance(services, list) else []:
        entry = _image_value(service, key="name")
        if entry:
            images.append(entry)
    return images


def gitlab_ci_images(text: str) -> list[str]:
    """Top-level, ``default`` and per-job ``image`` and ``services`` entries, as written."""
    data = load_yamlish(text)
    if not isinstance(data, dict):
        return []
    images = _gitlab_section_images(data)
    default = data.get("default")
    if isinstance(default, dict):
        images.extend(_gitlab_section_images(default))
    for key, job in data.items():
        if key in _GITLAB_RESERVED or not isinstance(job, dict):
            continue
        images.extend(_gitlab_section_images(job))
    return images


def _gitlab_variables(text: str) -> dict[str, str]:
    data = load_yamlish(text)
    variables = data.get("variables") if isinstance(data, dict) else None
    if not isinstance(variables, dict):
        return {}
    values: dict[str, str] = {}
    for name, value in variables.items():
        if isinstance(value, str):
            values[name] = value
        elif isinstance(value, dict) and isinstance(value.get("value"), str):
            values[name] = value["value"]
    return values


def parse_github_workflow(path: Path, root: Path) -> list[Dependency]:
    """One dependency per container image a GitHub Actions workflow runs jobs or services in.

    ``${{ }}`` expressions cannot be resolved, so images given that way are skipped.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []
    images = [i.removeprefix(DOCKER_URI_PREFIX) for i in github_workflow_images(text)]
    return _parse_written_images(path, root, images, {})


def parse_gitlab_ci(path: Path, root: Path) -> list[Dependency]:
    """One dependency per image a GitLab CI configuration runs jobs or services in.

    ``$VAR`` references are resolved from the file's own ``variables:`` block; anything
    else (predefined ``$CI_*`` variables, project settings) stays unresolved and is skipped.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []
    return _parse_written_images(path, root, gitlab_ci_images(text), _gitlab_variables(text))
