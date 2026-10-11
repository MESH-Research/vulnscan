"""Behaviour of the container scripts in deploy/: the health check and the run loop."""

import os
import subprocess
import time
from pathlib import Path

import pytest

DEPLOY = Path(__file__).resolve().parent.parent / "deploy"
HEALTHCHECK = DEPLOY / "healthcheck.sh"
ENTRYPOINT = DEPLOY / "docker-entrypoint.sh"


def run_healthcheck(state: Path, every: int = 60) -> subprocess.CompletedProcess:
    env = {
        **os.environ,
        "VULNSCAN_STATE_DIR": str(state),
        "VULNSCAN_RUN_EVERY_MINUTES": str(every),
    }
    return subprocess.run(["bash", str(HEALTHCHECK)], env=env, capture_output=True, text=True)


def heartbeat(state: Path, content: str, age_seconds: int = 0) -> Path:
    path = state / ".heartbeat"
    path.write_text(content + "\n")
    stamp = time.time() - age_seconds
    os.utime(path, (stamp, stamp))
    return path


def test_unhealthy_before_any_run(tmp_path: Path):
    assert run_healthcheck(tmp_path).returncode != 0


@pytest.mark.parametrize("content", ["ok", "running"])
def test_healthy_when_the_heartbeat_is_fresh(tmp_path: Path, content: str):
    heartbeat(tmp_path, content, age_seconds=30)
    assert run_healthcheck(tmp_path).returncode == 0


def test_unhealthy_when_the_last_run_failed(tmp_path: Path):
    heartbeat(tmp_path, "failed 1", age_seconds=30)
    result = run_healthcheck(tmp_path)
    assert result.returncode != 0
    assert "failed" in result.stdout + result.stderr


def test_unhealthy_when_the_heartbeat_is_stale(tmp_path: Path):
    # Two intervals plus a grace period have passed without a run completing.
    heartbeat(tmp_path, "ok", age_seconds=5 * 60 * 2 + 15 * 60)
    assert run_healthcheck(tmp_path, every=5).returncode != 0


def test_staleness_scales_with_the_run_interval(tmp_path: Path):
    heartbeat(tmp_path, "ok", age_seconds=25 * 60)
    assert run_healthcheck(tmp_path, every=5).returncode != 0
    assert run_healthcheck(tmp_path, every=60).returncode == 0


def test_a_long_running_first_scan_is_not_stale(tmp_path: Path):
    heartbeat(tmp_path, "running", age_seconds=8 * 60)
    assert run_healthcheck(tmp_path, every=60).returncode == 0


# --- entrypoint: records a heartbeat around every run ----------------------------------------


def run_entrypoint(tmp_path: Path, exit_code: int) -> subprocess.CompletedProcess:
    fake = tmp_path / "fake-run"
    fake.write_text(f"#!/bin/sh\nexit {exit_code}\n")
    fake.chmod(0o755)
    state = tmp_path / "state"
    state.mkdir()
    env = {
        **os.environ,
        "VULNSCAN_STATE_DIR": str(state),
        "VULNSCAN_RUN_EVERY_MINUTES": "0",
        "VULNSCAN_RUN_COMMAND": str(fake),
    }
    result = subprocess.run(
        ["bash", str(ENTRYPOINT)], env=env, capture_output=True, text=True, timeout=20
    )
    result.heartbeat = (state / ".heartbeat").read_text().strip()  # type: ignore[attr-defined]
    return result


def test_entrypoint_records_a_successful_run(tmp_path: Path):
    result = run_entrypoint(tmp_path, 0)
    assert result.returncode == 0
    assert result.heartbeat.split()[0] == "ok"


def test_entrypoint_records_a_failed_run_and_its_code(tmp_path: Path):
    result = run_entrypoint(tmp_path, 3)
    assert result.returncode == 3
    assert result.heartbeat.split() == ["failed", "3"]


def test_entrypoint_heartbeat_passes_the_healthcheck_after_success(tmp_path: Path):
    run_entrypoint(tmp_path, 0)
    assert run_healthcheck(tmp_path / "state").returncode == 0
