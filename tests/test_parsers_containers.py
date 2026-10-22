from pathlib import Path

import pytest

from vulnscan.models import CONTAINER, Declaration, Dependency
from vulnscan.parsers import discover_manifests, is_manifest, parse_manifest, parse_project
from vulnscan.parsers.containers import (
    ImageReference,
    is_compose_file,
    is_dockerfile,
    parse_compose_file,
    parse_dockerfile,
    parse_image_reference,
    registry_and_repository,
    tag_for_version,
    version_from_tag,
)
from vulnscan.parsers.versions import resolve_dependency

# --- image references ------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("php", ImageReference("php", "", "")),
        ("php:8.2-fpm", ImageReference("php", "8.2-fpm", "")),
        ("library/php:8.2", ImageReference("php", "8.2", "")),
        ("docker.io/library/php:8.2", ImageReference("php", "8.2", "")),
        ("docker.io/traefik:v2.10", ImageReference("traefik", "v2.10", "")),
        ("index.docker.io/library/nginx:1.25", ImageReference("nginx", "1.25", "")),
        ("grafana/grafana:10.4.1", ImageReference("grafana/grafana", "10.4.1", "")),
        (
            "ghcr.io/astral-sh/uv:python3.12-bookworm-slim",
            ImageReference("ghcr.io/astral-sh/uv", "python3.12-bookworm-slim", ""),
        ),
        (
            "localhost:5000/team/app:1.0.0",
            ImageReference("localhost:5000/team/app", "1.0.0", ""),
        ),
        (
            "php:8.2.19@sha256:0123456789abcdef",
            ImageReference("php", "8.2.19", "sha256:0123456789abcdef"),
        ),
        ("php@sha256:abc", ImageReference("php", "", "sha256:abc")),
        ("PHP:8.2", ImageReference("php", "8.2", "")),
    ],
)
def test_parse_image_reference(text, expected):
    assert parse_image_reference(text) == expected


@pytest.mark.parametrize("text", ["", "   ", "scratch", "${UNRESOLVED}", "php:${TAG}", ":8.2"])
def test_parse_image_reference_rejects_unusable_text(text):
    assert parse_image_reference(text) is None


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("php", ("registry-1.docker.io", "library/php")),
        ("grafana/grafana", ("registry-1.docker.io", "grafana/grafana")),
        ("ghcr.io/astral-sh/uv", ("ghcr.io", "astral-sh/uv")),
        ("quay.io/prometheus/node-exporter", ("quay.io", "prometheus/node-exporter")),
        ("localhost:5000/team/app", ("localhost:5000", "team/app")),
    ],
)
def test_registry_and_repository(name, expected):
    assert registry_and_repository(name) == expected


# --- tags --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("tag", "expected"),
    [
        ("8.2.19-fpm-bookworm", ("8.2.19", "-fpm-bookworm")),
        ("8.2-fpm", ("8.2", "-fpm")),
        ("8", ("8", "")),
        ("v2.10", ("2.10", "")),
        ("v3.1.0", ("3.1.0", "")),
        ("16-alpine3.19", ("16", "-alpine3.19")),
        ("1.25.3-alpine-slim", ("1.25.3", "-alpine-slim")),
        ("2024.1", ("2024.1", "")),
        ("3.0.0-rc1", ("3.0.0-rc1", "")),
        ("8.2.8RC1-fpm", ("8.2.8-RC1", "-fpm")),
        ("1.2.3_beta2-alpine", ("1.2.3-beta2", "-alpine")),
        ("latest", (None, "latest")),
        ("stable", (None, "stable")),
        ("python3.12-bookworm-slim", (None, "python3.12-bookworm-slim")),
        ("bookworm-slim", (None, "bookworm-slim")),
        ("", (None, "")),
    ],
)
def test_version_from_tag(tag, expected):
    assert version_from_tag(tag) == expected


@pytest.mark.parametrize(
    ("version", "variant", "expected"),
    [
        ("8.2.20", "-fpm-bookworm", "8.2.20-fpm-bookworm"),
        ("3.1.0", "", "3.1.0"),
        ("16", "-alpine3.19", "16-alpine3.19"),
    ],
)
def test_tag_for_version(version, variant, expected):
    assert tag_for_version(version, variant) == expected


# --- file names --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "Dockerfile",
        "dockerfile",
        "Containerfile",
        "Dockerfile.prod",
        "Dockerfile.dev",
        "app.Dockerfile",
        "app.dockerfile",
        "Containerfile.ci",
    ],
)
def test_is_dockerfile_accepts(name, tmp_path: Path):
    assert is_dockerfile(tmp_path / name)
    assert is_manifest(tmp_path / name)


@pytest.mark.parametrize("name", ["Dockerfile.md", "README.md", ".dockerignore", "docker.txt"])
def test_is_dockerfile_rejects(name, tmp_path: Path):
    assert not is_dockerfile(tmp_path / name)


@pytest.mark.parametrize(
    "name",
    [
        "docker-compose.yml",
        "docker-compose.yaml",
        "docker-compose.override.yml",
        "docker-compose.prod.yaml",
        "compose.yml",
        "compose.yaml",
        "compose.override.yaml",
    ],
)
def test_is_compose_file_accepts(name, tmp_path: Path):
    assert is_compose_file(tmp_path / name)
    assert is_manifest(tmp_path / name)


@pytest.mark.parametrize("name", ["config.yml", "docker-compose.md", "composer.json", "ci.yaml"])
def test_is_compose_file_rejects(name, tmp_path: Path):
    assert not is_compose_file(tmp_path / name)
    assert not is_manifest(tmp_path / name) or name == "composer.json"


def test_discover_manifests_finds_container_files(tmp_path: Path):
    (tmp_path / "Dockerfile").write_text("FROM php:8.2\n")
    (tmp_path / "deploy").mkdir()
    (tmp_path / "deploy" / "docker-compose.yml").write_text("services: {}\n")
    (tmp_path / "deploy" / "worker.Dockerfile").write_text("FROM python:3.12\n")
    (tmp_path / "node_modules" / "x").mkdir(parents=True)
    (tmp_path / "node_modules" / "x" / "Dockerfile").write_text("FROM node:20\n")
    found = sorted(p.relative_to(tmp_path).as_posix() for p in discover_manifests(tmp_path))
    assert found == ["Dockerfile", "deploy/docker-compose.yml", "deploy/worker.Dockerfile"]


# --- Dockerfile ---------------------------------------------------------------------------------


def dep_tuples(deps: list[Dependency]) -> list[tuple]:
    return [(d.name, d.constraint, d.version, d.version_source) for d in deps]


def test_parse_dockerfile_reads_from_lines(tmp_path: Path):
    (tmp_path / "Dockerfile").write_text(
        "# syntax=docker/dockerfile:1\n"
        "FROM php:8.2.19-fpm-bookworm\n"
        "RUN apt-get update\n"
        "COPY . /app\n"
    )
    deps = parse_dockerfile(tmp_path / "Dockerfile", tmp_path)
    assert dep_tuples(deps) == [("php", "8.2.19-fpm-bookworm", "8.2.19", "pinned")]
    dep = deps[0]
    assert dep.ecosystem == CONTAINER
    assert dep.source_file == "Dockerfile"
    assert dep.kind == "image"
    assert dep.dev is False


def test_parse_dockerfile_floating_tag_is_a_constraint(tmp_path: Path):
    (tmp_path / "Dockerfile").write_text("FROM php:8.2-fpm\n")
    deps = parse_dockerfile(tmp_path / "Dockerfile", tmp_path)
    assert dep_tuples(deps) == [("php", "8.2-fpm", "8.2", "constraint")]


def test_parse_dockerfile_tagless_and_latest_have_no_version(tmp_path: Path):
    (tmp_path / "Dockerfile").write_text("FROM nginx\nFROM redis:latest\n")
    deps = parse_dockerfile(tmp_path / "Dockerfile", tmp_path)
    assert dep_tuples(deps) == [
        ("nginx", "", None, "unknown"),
        ("redis", "latest", None, "unknown"),
    ]


def test_parse_dockerfile_multi_stage_skips_stage_references_and_scratch(tmp_path: Path):
    (tmp_path / "Dockerfile").write_text(
        "FROM golang:1.22 AS builder\n"
        "RUN go build\n"
        "FROM builder as tester\n"
        "FROM scratch\n"
        "COPY --from=builder /app /app\n"
        "FROM --platform=$BUILDPLATFORM node:20-alpine AS web\n"
        "from BUILDER\n"
    )
    deps = parse_dockerfile(tmp_path / "Dockerfile", tmp_path)
    assert dep_tuples(deps) == [
        ("golang", "1.22", "1.22", "constraint"),
        ("node", "20-alpine", "20", "constraint"),
    ]


def test_parse_dockerfile_substitutes_arg_defaults(tmp_path: Path):
    (tmp_path / "Dockerfile").write_text(
        "ARG PHP_VERSION=8.2.19\n"
        "ARG VARIANT=fpm\n"
        "ARG REGISTRY\n"
        "FROM php:${PHP_VERSION}-$VARIANT\n"
        "FROM ${REGISTRY:-ghcr.io}/astral-sh/uv:${UV_VERSION:-0.5.9}\n"
        "FROM ${UNKNOWN}/app:1.0\n"
        "FROM traefik:${TRAEFIK_TAG}\n"
    )
    deps = parse_dockerfile(tmp_path / "Dockerfile", tmp_path)
    assert dep_tuples(deps) == [
        ("php", "8.2.19-fpm", "8.2.19", "pinned"),
        ("ghcr.io/astral-sh/uv", "0.5.9", "0.5.9", "pinned"),
    ]


def test_parse_dockerfile_handles_continuations_digests_and_comments(tmp_path: Path):
    (tmp_path / "Dockerfile").write_text(
        "FROM \\\n"
        "    php:8.3.8-cli@sha256:deadbeef \\\n"
        "    AS base\n"
        "# FROM commented:1.0\n"
        "   # indented comment\n"
        "FROM   mysql:8.0.36   \n"
    )
    deps = parse_dockerfile(tmp_path / "Dockerfile", tmp_path)
    assert dep_tuples(deps) == [
        ("php", "8.3.8-cli", "8.3.8", "pinned"),
        ("mysql", "8.0.36", "8.0.36", "pinned"),
    ]


def test_parse_dockerfile_same_image_twice_yields_two_declarations(tmp_path: Path):
    (tmp_path / "Dockerfile").write_text("FROM node:20 AS a\nFROM node:20 AS b\n")
    deps = parse_dockerfile(tmp_path / "Dockerfile", tmp_path)
    assert [d.name for d in deps] == ["node", "node"]


def test_parse_dockerfile_unreadable_gives_empty(tmp_path: Path):
    assert parse_dockerfile(tmp_path / "Dockerfile", tmp_path) == []
    (tmp_path / "Dockerfile").write_bytes(b"\xff\xfe FROM php:8\n")
    assert parse_dockerfile(tmp_path / "Dockerfile", tmp_path) == []


def test_parse_dockerfile_source_file_is_project_relative(tmp_path: Path):
    (tmp_path / "deploy").mkdir()
    path = tmp_path / "deploy" / "Dockerfile.worker"
    path.write_text("FROM python:3.12-slim\n")
    deps = parse_dockerfile(path, tmp_path)
    assert deps[0].source_file == "deploy/Dockerfile.worker"


# --- Compose -----------------------------------------------------------------------------------


def test_parse_compose_reads_service_images(tmp_path: Path):
    (tmp_path / "docker-compose.yml").write_text(
        "version: '3.8'\n"
        "services:\n"
        "  proxy:\n"
        "    image: traefik:v2.10\n"
        "    ports:\n"
        "      - '80:80'\n"
        "  app:\n"
        "    build: .\n"
        "    image: 'myorg/app:1.4.2'\n"
        "  db:\n"
        '    image: "postgres:16.2-alpine"\n'
        "    environment:\n"
        "      image: not-a-service-image\n"
        "volumes:\n"
        "  data: {}\n"
    )
    deps = parse_compose_file(tmp_path / "docker-compose.yml", tmp_path)
    assert dep_tuples(deps) == [
        ("traefik", "v2.10", "2.10", "constraint"),
        ("myorg/app", "1.4.2", "1.4.2", "pinned"),
        ("postgres", "16.2-alpine", "16.2", "constraint"),
    ]
    assert all(d.ecosystem == CONTAINER and d.kind == "image" for d in deps)
    assert deps[0].source_file == "docker-compose.yml"


def test_parse_compose_build_only_services_are_skipped(tmp_path: Path):
    (tmp_path / "compose.yaml").write_text(
        "services:\n  app:\n    build:\n      context: .\n  cache:\n    image: redis:7.2.4\n"
    )
    deps = parse_compose_file(tmp_path / "compose.yaml", tmp_path)
    assert dep_tuples(deps) == [("redis", "7.2.4", "7.2.4", "pinned")]


def test_parse_compose_interpolates_defaults_and_dotenv(tmp_path: Path):
    (tmp_path / ".env").write_text("TRAEFIK_TAG=v3.0.1\nREGISTRY=ghcr.io\n")
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n"
        "  proxy:\n"
        "    image: traefik:${TRAEFIK_TAG}\n"
        "  app:\n"
        "    image: ${REGISTRY}/org/app:${APP_TAG:-2.0.0}\n"
        "  other:\n"
        "    image: ${REGISTRY:-docker.io}/org/other:${OTHER_TAG-1.0.0}\n"
        "  unknown:\n"
        "    image: thing:${MISSING}\n"
        "  escaped:\n"
        "    image: literal:$$NOT_A_VAR\n"
    )
    deps = parse_compose_file(tmp_path / "docker-compose.yml", tmp_path)
    assert dep_tuples(deps) == [
        ("traefik", "v3.0.1", "3.0.1", "pinned"),
        ("ghcr.io/org/app", "2.0.0", "2.0.0", "pinned"),
        ("ghcr.io/org/other", "1.0.0", "1.0.0", "pinned"),
    ]


def test_parse_compose_tolerates_comments_and_tabs(tmp_path: Path):
    (tmp_path / "docker-compose.yml").write_text(
        "# top comment\n"
        "services:\n"
        "  # a commented service\n"
        "  web:\n"
        "    image: nginx:1.25.4 # inline comment\n"
        "\n"
        "  worker:\n"
        "    image:   php:8.3-cli\n"
        "x-common:\n"
        "  image: ignored:1.0\n"
    )
    deps = parse_compose_file(tmp_path / "docker-compose.yml", tmp_path)
    assert dep_tuples(deps) == [
        ("nginx", "1.25.4", "1.25.4", "pinned"),
        ("php", "8.3-cli", "8.3", "constraint"),
    ]


def test_parse_compose_without_services_or_unreadable_gives_empty(tmp_path: Path):
    (tmp_path / "docker-compose.yml").write_text("volumes:\n  data: {}\n")
    assert parse_compose_file(tmp_path / "docker-compose.yml", tmp_path) == []
    assert parse_compose_file(tmp_path / "missing.yml", tmp_path) == []


# --- integration with discovery and resolution ------------------------------------------------


def test_parse_manifest_dispatches_container_files(tmp_path: Path):
    (tmp_path / "Dockerfile").write_text("FROM php:8.2.19\n")
    (tmp_path / "compose.yml").write_text("services:\n  p:\n    image: traefik:v2.10.7\n")
    assert [d.name for d in parse_manifest(tmp_path / "Dockerfile", tmp_path)] == ["php"]
    assert [d.name for d in parse_manifest(tmp_path / "compose.yml", tmp_path)] == ["traefik"]


def test_resolve_dependency_leaves_container_images_alone():
    dep = Dependency("php", CONTAINER, "8.2-fpm", "8.2", "constraint", "Dockerfile", kind="image")
    assert resolve_dependency(dep, {}) == dep
    assert resolve_dependency(dep, {("Docker", "php"): "9.9.9"}) == dep


def test_parse_project_keeps_image_versions_and_warns_on_floating_latest(tmp_path: Path):
    (tmp_path / "Dockerfile").write_text(
        "FROM php:8.2.19-fpm\nFROM nginx:latest\nFROM debian:bookworm-slim\n"
    )
    deps, warnings = parse_project(tmp_path)
    assert dep_tuples(deps) == [
        ("php", "8.2.19-fpm", "8.2.19", "pinned"),
        ("nginx", "latest", None, "unknown"),
        ("debian", "bookworm-slim", None, "unknown"),
    ]
    nginx = [w for w in warnings if "nginx" in w]
    assert len(nginx) == 1
    assert "Dockerfile" in nginx[0] and "latest" in nginx[0] and "pin" in nginx[0].lower()
    assert not any("debian" in w for w in warnings)


def test_image_declarations_format_like_other_manifests():
    dep = Dependency(
        "php",
        CONTAINER,
        "8.2-fpm",
        "8.2",
        "constraint",
        "Dockerfile",
        kind="image",
        declarations=(
            Declaration("Dockerfile", "8.2-fpm"),
            Declaration("deploy/docker-compose.yml", "8.2-fpm"),
        ),
    )
    assert dep.declared_in_text == "Dockerfile as 8.2-fpm; deploy/docker-compose.yml as 8.2-fpm"
    assert dep.key == ("Docker", "php")
