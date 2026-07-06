"""Tests for the `vigil quickstart` onboarding wizard.

Focus: the host-tool install plan is computed purely (no PATH mutation, nothing
executed), missing tools render their exact install commands, and NO install
command runs unless `--install-host-tools` is passed (and never under --dry-run).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

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
        "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    )
    assert by_tool["httpx"] == "go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
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
    assert ("go", "install", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest") in ran
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
    assert "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest" in out
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
    assert {"uv", "git", "docker", "go", "npm"} <= binaries


def test_prerequisite_status_reports_presence():
    rows = prerequisite_status(which=_which_present)
    assert all(row.present for row in rows)
    rows = prerequisite_status(which=_which_missing)
    assert all(not row.present for row in rows)
    assert [row.binary for row in rows] == ["uv", "git", "docker", "go", "npm"]
