"""Doctor health gates and optional host-tool setup."""
from __future__ import annotations

import importlib.metadata
import json
import subprocess
from pathlib import Path

import pytest

from vigil_cli.host_tools import setup_host_tools


def test_host_tool_plan_matches_platform_and_presence():
    def missing(_):
        return None
    plan = {
        step["tool"]: step["command"]
        for step in setup_host_tools(which=missing, system=lambda: "Darwin")["install_plan"]
    }
    assert plan["subfinder"] == "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.17.0"
    assert plan["massdns"] == "brew install massdns"
    assert "massdns" not in {
        step["tool"]
        for step in setup_host_tools(which=missing, system=lambda: "Linux")["install_plan"]
    }
    assert setup_host_tools(which=lambda _: "/usr/bin/acme")["install_plan"] == []


def test_binary_check_uses_go_version_command(monkeypatch):
    from vigil_cli import status

    calls = []
    monkeypatch.setattr(status.shutil, "which", lambda _: "/usr/bin/go")

    def run(argv, **_kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, "go version go1.26.1 darwin/arm64", "")

    monkeypatch.setattr(status.subprocess, "run", run)
    assert status._binary_check("go").status == "OK"
    assert calls == [["go", "version"]]


@pytest.mark.parametrize(("install", "dry_run", "executes"), [(False, False, False), (True, True, False), (True, False, True)])
def test_host_installation_requires_explicit_request_and_honors_dry_run(install, dry_run, executes):
    installed = set()
    calls = []
    def runner(argv):
        calls.append(list(argv))
        for binary in ("subfinder", "dnsx", "httpx", "puredns", "massdns", "shuffledns", "alterx"):
            if binary in argv[-1]:
                installed.add(binary)
        return subprocess.CompletedProcess(argv, 0, "", "")
    report = setup_host_tools(
        install=install,
        dry_run=dry_run,
        which=lambda binary: f"/usr/local/bin/{binary}" if binary in installed else None,
        system=lambda: "Darwin",
        runner=runner,
    )
    assert bool(calls) == executes
    assert bool(report["executed"]) == executes
    assert report["ok"] is True
    if executes:
        assert len(calls) == len(report["install_plan"])
        assert ["brew", "install", "massdns"] in calls
    assert {row["binary"] for row in report["tools"]} >= {"subfinder", "massdns"}


def test_host_installation_does_not_claim_success_when_binary_is_still_missing():
    def runner(argv):
        return subprocess.CompletedProcess(argv, 0, "installed", "")

    report = setup_host_tools(
        install=True,
        which=lambda _: None,
        system=lambda: "Darwin",
        runner=runner,
    )

    assert report["ok"] is False
    assert report["executed"]
    assert all(row["ok"] is False for row in report["executed"])
    assert all("not found on PATH" in row["detail"] for row in report["executed"])


@pytest.mark.parametrize("failure", ["exit", "missing-installer"])
def test_host_installation_reports_failed_commands(failure):
    def runner(argv):
        if failure == "missing-installer":
            raise FileNotFoundError("go not found")
        return subprocess.CompletedProcess(argv, 1, "", "Acme installation failed")
    report = setup_host_tools(install=True, which=lambda _: None, system=lambda: "Linux", runner=runner)
    assert report["ok"] is False
    assert all(not row["ok"] and row["detail"] for row in report["executed"])
    assert any(row["binary"] == "massdns" for row in report["manual"])


def test_doctor_exits_non_zero_when_a_check_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    """A readiness command that reports FAIL and exits 0 cannot gate anything.

    README points at `vigil doctor` to confirm a running install is healthy, so
    a script or CI job has no way to act on a FAIL row today.
    """
    from vigil_cli import main as main_module
    from vigil_cli.status import Check

    monkeypatch.setattr(
        main_module,
        "collect_doctor_checks",
        lambda *_a, **_k: [Check("ok-row", "OK"), Check("docker-daemon", "FAIL")],
    )

    with pytest.raises(SystemExit) as excinfo:
        main_module.main(["doctor"])

    assert excinfo.value.code != 0


def test_doctor_names_failed_host_tool_install_in_final_summary(monkeypatch, capsys):
    from vigil_cli import main as main_module
    from vigil_cli.status import Check

    monkeypatch.setattr(
        main_module,
        "setup_host_tools",
        lambda **_kwargs: {
            "dry_run": False,
            "tools": [],
            "install_plan": [{"tool": "subfinder", "command": "go install example.com/subfinder"}],
            "manual": [],
            "executed": [
                {
                    "tool": "subfinder",
                    "ok": False,
                    "detail": "installer succeeded but binary is not found on PATH",
                }
            ],
            "ok": False,
        },
    )
    monkeypatch.setattr(
        main_module,
        "collect_doctor_checks",
        lambda *_args, **_kwargs: [Check("workspace", "OK")],
    )

    with pytest.raises(SystemExit):
        main_module.main(["doctor", "--install-host-tools"])

    assert "not ready: subfinder (install failed)" in capsys.readouterr().err


def test_doctor_exits_zero_for_warn_and_optional_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An advisory MISSING does not gate — OOB is legitimately unset."""
    from vigil_cli import main as main_module
    from vigil_cli.status import Check

    monkeypatch.setattr(
        main_module,
        "collect_doctor_checks",
        lambda *_a, **_k: [
            Check("ok-row", "OK"),
            Check("oob.frp_token", "MISSING"),
            Check("oob.relay-route", "WARN"),
        ],
    )

    main_module.main(["doctor"])  # must not raise


def test_doctor_exits_non_zero_when_a_required_prerequisite_is_missing(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A host with no Docker cannot run Vigil, and MISSING is how that reads.

    `MISSING` carries both "not configured, and that is fine" and "this host
    cannot run Vigil", so a filter that treats the status alone as advisory
    reported `ok` on a host with no Docker CLI at all — the daemon probe is
    skipped in that branch, so no FAIL row is ever produced to catch it.
    """
    from vigil_cli import main as main_module
    from vigil_cli.status import Check

    monkeypatch.setattr(
        main_module,
        "collect_doctor_checks",
        lambda *_a, **_k: [
            Check("docker", "MISSING", "not found", required=True),
            Check("docker-daemon", "SKIPPED", "docker CLI not found"),
            Check("oob.frp_token", "MISSING"),
        ],
    )

    with pytest.raises(SystemExit) as excinfo:
        main_module.main(["doctor"])

    assert excinfo.value.code != 0
    # The gating row is named, so an operator is not left comparing two MISSING
    # rows to work out which one ended the command.
    err = capsys.readouterr().err
    assert "docker (MISSING)" in err
    assert "oob.frp_token" not in err


def test_doctor_allows_source_only_install_without_docker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The required flag is set by the collector, not hard-coded by the caller."""
    from vigil_cli import status as status_module

    monkeypatch.setattr(
        status_module,
        "_binary_check",
        lambda command: status_module.Check(command, "MISSING", "not found"),
    )

    checks = {
        check.name: check
        for check in status_module.collect_doctor_checks(tmp_path / "absent")
    }

    assert checks["docker"].required is False
    assert checks["install-root"].required is True
    # Imported release assets are available even before workspace initialization.
    assert checks["agent-dir"].status == "OK"
    assert checks["agent-dir"].required is False
    # A client binary is not a prerequisite: Vigil supports five and needs one.
    assert checks["claude"].required is False
    assert checks["codex"].required is False


def test_doctor_json_is_machine_readable(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """`vigil status` has --json; doctor is the readiness command and had none."""
    from vigil_cli import main as main_module
    from vigil_cli.status import Check

    monkeypatch.setattr(
        main_module,
        "collect_doctor_checks",
        lambda *_a, **_k: [Check("docker-daemon", "FAIL", "no daemon")],
    )

    with pytest.raises(SystemExit):
        main_module.main(["doctor", "--json"])

    payload = json.loads(capsys.readouterr().out)
    assert payload["checks"] == [
        {
            "name": "docker-daemon",
            "status": "FAIL",
            "detail": "no daemon",
            "required": False,
        }
    ]
    assert payload["ok"] is False


def test_version_flag_reports_the_installed_cli_version(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The two-layer model makes the CLI's own version the first thing to check.

    A newer CLI against a stale working root leaves features silently inert, so
    reconciling the two layers starts with knowing which CLI is installed.
    """
    from vigil_cli import main as main_module

    monkeypatch.setattr(main_module.importlib.metadata, "version", lambda name: "9.8.7")

    with pytest.raises(SystemExit) as excinfo:
        main_module.main(["--version"])

    assert excinfo.value.code == 0
    assert capsys.readouterr().out == "vigil 9.8.7\n"


def test_version_resolution_survives_a_missing_distribution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No package metadata must not break the whole CLI.

    The bench participant bundle runs `vigil` from a copied source tree with no
    installed distribution. The version string is built while the parser is
    constructed, so raising here would fail every invocation, not just
    `--version`.
    """
    from vigil_cli import main as main_module

    def no_metadata(_name: str) -> str:
        raise importlib.metadata.PackageNotFoundError("vigil")

    monkeypatch.setattr(main_module.importlib.metadata, "version", no_metadata)

    assert "unknown" in main_module._cli_version()


def test_broken_docker_is_advisory_for_source_investigation(tmp_path, monkeypatch):
    from vigil_cli import status

    monkeypatch.setattr(status, '_binary_check', lambda name: status.Check(name, 'FAIL' if name == 'docker' else 'MISSING'))
    rows = {row.name: row for row in status.collect_doctor_checks(tmp_path)}
    assert rows['docker'].status == 'WARN'
    assert rows['docker'].required is False
    assert 'source investigation' in rows['docker'].detail


def test_doctor_treats_docker_assets_as_unknown_when_daemon_is_unavailable(tmp_path, monkeypatch):
    from vigil_cli import status
    from vigil_cli.docker import DockerResult

    monkeypatch.setattr(status, "_binary_check", lambda name: status.Check(name, "OK"))
    calls = []

    def runner(argv, **_kwargs):
        calls.append(list(argv))
        assert argv == ["docker", "info"]
        return DockerResult(1, "", "Cannot connect to the Docker daemon")

    rows = {row.name: row for row in status.collect_doctor_checks(tmp_path, runner=runner)}

    assert calls == [["docker", "info"]]
    assert rows["docker-daemon"].status == "WARN"
    assert rows["runtime-image"].status == "SKIPPED"
    assert rows["mitmproxy-image"].status == "SKIPPED"
    assert rows["mitmproxy-container-drift"].status == "SKIPPED"
    assert not any(row.name.startswith("runtime-tool:") for row in rows.values())


def test_doctor_explains_optional_go_requirement_for_host_tool_installation(tmp_path, monkeypatch):
    from vigil_cli import status

    monkeypatch.setattr(status, '_binary_check', lambda name: status.Check(name, 'MISSING'))
    rows = {row.name: row for row in status.collect_doctor_checks(tmp_path)}
    assert 'go' in rows
    assert rows['go'].required is False
    assert 'host recon tool installation' in rows['go'].detail
