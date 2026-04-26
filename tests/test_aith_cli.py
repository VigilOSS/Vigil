"""Root-level smoke tests for `aith` runtime helpers.

These tests exercise the `aith runtime resources` helper against a stub Docker
runner and skip cleanly when the host has no docker CLI on PATH. The deeper
CLI test surface lives in `orchestrator/backend/tests/test_aith_cli.py`; this
file is a contract guard so the runtime helper stays callable from the
installable package surface even without backend test infrastructure.
"""
from __future__ import annotations

import shutil
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))


def test_aith_runtime_resources_helper_renders_against_stub_container(monkeypatch, capsys):
    from ai_threat_hunting_cli.docker import DockerResult
    from ai_threat_hunting_cli.runtime import aith_runtime_resources

    monkeypatch.setenv("AITH_RUNTIME_MEMORY_GB", "8")
    monkeypatch.setenv("AITH_RUNTIME_CPUS", "4")

    def runner(argv, **_):
        if argv[:3] == ["docker", "ps", "--format"]:
            return DockerResult(0, "security-research\n", "")
        if argv[:3] == ["docker", "exec", "security-research"]:
            return DockerResult(
                0,
                "/sys/fs/cgroup/memory.max=max\n"
                "/sys/fs/cgroup/cpu.max=max\n"
                "/sys/fs/cgroup/pids.max=max\n",
                "",
            )
        return DockerResult(0, "", "")

    aith_runtime_resources(runner=runner)
    output = capsys.readouterr().out
    assert "configured\tmemory=8g" in output
    assert "memory.max=max" in output


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker CLI not installed on host")
def test_aith_runtime_resources_helper_handles_real_docker_cli_gracefully(capsys):
    """When docker is on PATH but no `security-research` container is running, the helper
    reports `running=False` and prints `live\tcontainer not running` rather than crashing."""
    from ai_threat_hunting_cli.runtime import aith_runtime_resources

    aith_runtime_resources(container_name="security-research-stub-nonexistent")
    output = capsys.readouterr().out
    assert "running=False" in output
    assert "container not running" in output
