"""Root-level smoke tests for `vigil` runtime helpers.

These tests exercise the `vigil runtime resources` helper against a stub Docker
runner and skip cleanly when the host has no docker CLI on PATH. The deeper
CLI test surface lives in `orchestrator/backend/tests/test_aith_cli.py`; this
file is a contract guard so the runtime helper stays callable from the
installable package surface even without backend test infrastructure.
"""
from __future__ import annotations

import io
import shutil
import sys
import urllib.error
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))


def test_vigil_runtime_resources_helper_renders_against_stub_container(monkeypatch, capsys):
    from vigil_cli.docker import DockerResult
    from vigil_cli.runtime import vigil_runtime_resources

    monkeypatch.setenv("VIGIL_RUNTIME_MEMORY_GB", "8")
    monkeypatch.setenv("VIGIL_RUNTIME_CPUS", "4")

    def runner(argv, **_):
        if argv[:3] == ["docker", "ps", "--format"]:
            return DockerResult(0, "vigil\n", "")
        if argv[:3] == ["docker", "exec", "vigil"]:
            return DockerResult(
                0,
                "/sys/fs/cgroup/memory.max=max\n"
                "/sys/fs/cgroup/cpu.max=max\n"
                "/sys/fs/cgroup/pids.max=max\n",
                "",
            )
        return DockerResult(0, "", "")

    vigil_runtime_resources(runner=runner)
    output = capsys.readouterr().out
    assert "configured\tmemory=8g" in output
    assert "memory.max=max" in output


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker CLI not installed on host")
def test_vigil_runtime_resources_helper_handles_real_docker_cli_gracefully(capsys):
    """When docker is on PATH but no `vigil` container is running, the helper
    reports `running=False` and prints `live\tcontainer not running` rather than crashing."""
    from vigil_cli.runtime import vigil_runtime_resources

    vigil_runtime_resources(container_name="vigil-stub-nonexistent")
    output = capsys.readouterr().out
    assert "running=False" in output
    assert "container not running" in output


def _seed_engagement(eng_dir: Path) -> None:
    """Create a minimal engagement skeleton — scope.json is the discovery marker."""
    eng_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / "scope.json").write_text("{}", encoding="utf-8")


def test_doctor_failed_audit(tmp_path, monkeypatch):
    """`vigil doctor` must surface orphaned `<run_uuid>.failed-audit` markers.

    Without this signal, a long engagement can accumulate dozens of markers
    silently — each one is an `vigil assess kali` invocation whose audit row
    never reached the orchestrator backend, so coverage drifts behind the
    runtime evidence.
    """
    from vigil_cli.status import (
        _failed_audit_marker_check,
        list_failed_audit_markers,
    )

    install_root = tmp_path
    eng_root = install_root / "agent" / "engagements"
    eng_dir = eng_root / "2026-04-28-000000-target"
    _seed_engagement(eng_dir)

    # Quiet env so unrelated checks (frp token) don't leak state into the test.
    monkeypatch.delenv("VIGIL_FRP_TOKEN", raising=False)

    # Empty case: no scans/kali dir → check returns OK with quiet message.
    assert list_failed_audit_markers(eng_dir) == []
    quiet = _failed_audit_marker_check(install_root)
    assert quiet.name == "failed-audit-markers"
    assert quiet.status == "OK"

    # Populated case: write a marker and assert WARN with engagement key + count.
    kali_dir = eng_dir / "scans" / "kali"
    kali_dir.mkdir(parents=True)
    marker_path = kali_dir / "abc.failed-audit"
    marker_path.write_text("2026-04-28T00:00:00Z audit POST failed: connection refused\n", encoding="utf-8")

    markers = list_failed_audit_markers(eng_dir)
    assert markers == [marker_path]

    warn = _failed_audit_marker_check(install_root)
    assert warn.name == "failed-audit-markers"
    assert warn.status == "WARN"
    assert "1 orphaned marker(s) across 1 engagement(s)" in warn.detail
    assert eng_dir.name in warn.detail
    assert str(marker_path) in warn.detail


def test_doctor_failed_audit_no_engagements_dir(tmp_path):
    """When the install root has no engagements directory yet, the check returns OK."""
    from vigil_cli.status import _failed_audit_marker_check

    result = _failed_audit_marker_check(tmp_path)
    assert result.name == "failed-audit-markers"
    assert result.status == "OK"


def test_readyz_http_error_preserves_readiness_payload(tmp_path, monkeypatch):
    """HTTP 503 from /readyz is a reachable not-ready state, not a transport failure."""
    from vigil_cli import status as status_module

    body = (
        b'{"status":"not_ready","database_connected":true,'
        b'"assessment_schema_ready":false,"code_analysis_schema_ready":true}'
    )

    def fail_readyz(url, *, timeout):
        assert url.endswith("/readyz")
        assert timeout == 1
        raise urllib.error.HTTPError(
            url,
            503,
            "Service Unavailable",
            hdrs=None,
            fp=io.BytesIO(body),
        )

    monkeypatch.setattr(status_module.urllib.request, "urlopen", fail_readyz)

    healthy, readiness = status_module._orchestrator_readyz_snapshot(tmp_path)

    assert healthy is False
    assert readiness["reachable"] is True
    assert readiness["http_status"] == 503
    assert readiness["status"] == "not_ready"
    assert readiness["database_connected"] is True
    assert readiness["assessment_schema_ready"] is False
    assert readiness["code_analysis_schema_ready"] is True
