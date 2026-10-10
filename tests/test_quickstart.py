"""Tests for the `vigil quickstart` onboarding wizard.

Focus: the host-tool install plan is computed purely (no PATH mutation, nothing
executed), missing tools render their exact install commands, and NO install
command runs unless `--install-host-tools` is passed (and never under --dry-run).
"""
from __future__ import annotations

import importlib.metadata
import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from vigil_cli.quickstart import (  # noqa: E402
    HOST_RECON_TOOLS,
    QuickstartOptions,
    host_tool_plan,
    prerequisite_status,
    run_quickstart,
)


class RecordingRunner:
    """Stub runner that records every argv it is asked to execute."""

    def __init__(self, returncode: int = 0, stderr: str = "") -> None:
        self.calls: list[list[str]] = []
        self.returncode = returncode
        self.stderr = stderr

    def __call__(self, argv):
        self.calls.append(list(argv))
        import subprocess

        return subprocess.CompletedProcess(list(argv), self.returncode, "", self.stderr)


def _which_missing(_binary):
    return None


def _which_present(_binary):
    return "/usr/bin/stub"


def _darwin():
    return "Darwin"


def _opts(**kw):
    base = dict(
        install_root=Path("/home/op/vigil"),
        non_interactive=True,
    )
    base.update(kw)
    return QuickstartOptions(**base)


def test_plan_renders_go_install_and_brew_commands_when_missing():
    plan = host_tool_plan(which=_which_missing, system=_darwin)
    by_tool = {step.tool: step.command for step in plan}
    # Every declared recon tool with an auto command is planned when absent.
    assert by_tool["subfinder"] == (
        "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.17.0"
    )
    assert by_tool["httpx"] == "go install github.com/projectdiscovery/httpx/cmd/httpx@v1.9.0"
    # massdns is not go-installable; on macOS it gets a brew command.
    assert by_tool["massdns"] == "brew install massdns"


def test_massdns_manual_off_macos():
    plan = host_tool_plan(which=_which_missing, system=lambda: "Linux")
    tools = {step.tool for step in plan}
    # go-installable tools still planned cross-platform...
    assert "subfinder" in tools
    # ...but massdns has no auto command off macOS, so it is not in the plan.
    assert "massdns" not in tools


def test_plan_empty_when_all_present():
    assert host_tool_plan(which=_which_present, system=_darwin) == []


def test_no_install_without_flag():
    runner = RecordingRunner()
    rc = run_quickstart(
        _opts(),
        which=_which_missing,
        system=_darwin,
        runner=runner,
        stdin_isatty=lambda: False,
    )
    assert rc == 0
    # Default (no --install-host-tools): nothing is executed.
    assert runner.calls == []


def test_dry_run_never_installs_even_with_flag():
    runner = RecordingRunner()
    rc = run_quickstart(
        _opts(install_host_tools=True, dry_run=True),
        which=_which_missing,
        system=_darwin,
        runner=runner,
        stdin_isatty=lambda: False,
    )
    assert rc == 0
    assert runner.calls == []


def test_install_runs_commands_only_with_flag():
    runner = RecordingRunner()
    rc = run_quickstart(
        _opts(install_host_tools=True),
        which=_which_missing,
        system=_darwin,
        runner=runner,
        stdin_isatty=lambda: False,
    )
    assert rc == 0
    ran = {tuple(call) for call in runner.calls}
    assert ("go", "install", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.17.0") in ran
    assert ("brew", "install", "massdns") in ran
    # One call per planned tool, nothing more.
    assert len(runner.calls) == len(host_tool_plan(which=_which_missing, system=_darwin))


def test_failed_install_returns_nonzero():
    runner = RecordingRunner(returncode=1, stderr="boom")
    rc = run_quickstart(
        _opts(install_host_tools=True),
        which=_which_missing,
        system=_darwin,
        runner=runner,
        stdin_isatty=lambda: False,
    )
    assert rc == 1


def test_text_output_renders_plan_and_next_steps(capsys):
    rc = run_quickstart(
        _opts(target="https://app.example.com", hosts="app.example.com"),
        which=_which_missing,
        system=_darwin,
        runner=RecordingRunner(),
        stdin_isatty=lambda: False,
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "vigil quickstart" in out
    assert "install root: /home/op/vigil" in out
    # Plan is printed but flagged as not executed.
    assert "go install github.com/projectdiscovery/dnsx/cmd/dnsx@v1.2.3" in out
    assert "--install-host-tools" in out
    # Next-step checklist keys to the resolved install root + supplied target.
    assert "vigil install /home/op/vigil" in out
    assert "vigil engagement create https://app.example.com --hosts app.example.com" in out


def test_json_output_shape(capsys):
    rc = run_quickstart(
        _opts(json_output=True),
        which=_which_missing,
        system=_darwin,
        runner=RecordingRunner(),
        stdin_isatty=lambda: False,
    )
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["install_root"] == "/home/op/vigil"
    assert payload["installs_executed"] is False
    assert {row["binary"] for row in payload["host_tools"]} == {t.binary for t in HOST_RECON_TOOLS}
    assert any(step["tool"] == "subfinder" for step in payload["install_plan"])
    binaries = {p["binary"] for p in payload["prerequisites"]}
    assert {"uv", "docker", "go"} == binaries


def test_prerequisite_status_reports_presence():
    # Inject the daemon probe too: docker's row is binary AND daemon, so a test
    # that injects only `which` would consult the real host and fail wherever no
    # daemon is running.
    rows = prerequisite_status(which=_which_present, daemon_available=lambda: True)
    assert all(row.present for row in rows)
    rows = prerequisite_status(which=_which_missing, daemon_available=lambda: False)
    assert all(not row.present for row in rows)
    assert [row.binary for row in rows] == ["uv", "docker", "go"]


def test_quickstart_docker_row_reflects_the_daemon_not_just_the_binary() -> None:
    """A `which` hit is not readiness — the next command runs `docker build`.

    README frames `vigil quickstart` as the host check to run first, and its
    checklist sends the operator straight to `vigil install`, which builds the
    runtime image. Reporting `[ok] docker` for a host with the client binary and
    no reachable daemon greens a host that cannot complete the very next step.
    `vigil doctor` already probes the daemon; quickstart must use the same probe.
    """
    from vigil_cli.quickstart import prerequisite_status

    rows = prerequisite_status(
        which=lambda binary: f"/usr/bin/{binary}",
        daemon_available=lambda: False,
    )
    docker_row = next(row for row in rows if row.binary == "docker")

    assert docker_row.present is False, "binary present but daemon down is not ready"
    assert "daemon" in docker_row.detail.lower()


def test_quickstart_docker_row_is_ok_when_the_daemon_answers() -> None:
    from vigil_cli.quickstart import prerequisite_status

    rows = prerequisite_status(
        which=lambda binary: f"/usr/bin/{binary}",
        daemon_available=lambda: True,
    )
    docker_row = next(row for row in rows if row.binary == "docker")

    assert docker_row.present is True
    assert docker_row.detail == ""


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


def test_doctor_marks_docker_and_install_root_required_when_absent(
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

    assert checks["docker"].required is True
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
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The two-layer model makes the CLI's own version the first thing to check.

    A newer CLI against a stale working root leaves features silently inert, so
    reconciling the two layers starts with knowing which CLI is installed.
    """
    from vigil_cli import main as main_module

    with pytest.raises(SystemExit) as excinfo:
        main_module.main(["--version"])

    assert excinfo.value.code == 0
    assert importlib.metadata.version("vigil") in capsys.readouterr().out


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
