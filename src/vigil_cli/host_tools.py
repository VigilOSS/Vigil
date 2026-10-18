"""Optional host recon tool planning and installation for ``vigil doctor``.

Readiness checks live in status.py; this module only prepares and executes the
explicitly requested host-tool installation, never engagement or service setup.
"""
from __future__ import annotations

import platform
import shlex
import shutil
import subprocess
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any

from .runtime import HOST_RECON_TOOLS, HostTool

WhichFn = Callable[[str], str | None]
SystemFn = Callable[[], str]
Runner = Callable[[Sequence[str]], "subprocess.CompletedProcess[str]"]


@dataclass(frozen=True, slots=True)
class InstallStep:
    tool: str
    command: str


def _default_runner(argv: Sequence[str]) -> "subprocess.CompletedProcess[str]":
    return subprocess.run(list(argv), text=True, capture_output=True, check=False)


def _host_tool_command(tool: HostTool, system_name: str) -> str | None:
    """Auto-runnable install command for a host recon tool, or None (manual).

    go-installable tools are cross-platform; `massdns` is not go-installable, so
    it only gets an auto command on macOS (`brew`). Elsewhere it stays manual and
    its `note` carries the build pointer.
    """
    if tool.go_install:
        return f"go install {tool.go_install}"
    if tool.binary == "massdns" and system_name == "Darwin":
        return "brew install massdns"
    return None


def host_tool_statuses(
    *, which: WhichFn = shutil.which, system: SystemFn = platform.system
) -> list[tuple[HostTool, bool, str | None]]:
    """(tool, present, auto_command_or_None) for every host recon tool."""
    system_name = system()
    return [
        (tool, which(tool.binary) is not None, _host_tool_command(tool, system_name))
        for tool in HOST_RECON_TOOLS
    ]


def setup_host_tools(
    *,
    install: bool = False,
    dry_run: bool = False,
    which: WhichFn = shutil.which,
    system: SystemFn = platform.system,
    runner: Runner = _default_runner,
) -> dict[str, Any]:
    """Report every checked binary and optionally install missing host tools.

    Passing ``install=True`` is the explicit request; there is no additional
    prompt, and a dry run never invokes the runner. Linux tools are optional
    but still checked when the operator requests this report.
    """
    rows = host_tool_statuses(which=which, system=system)
    plan = [InstallStep(tool.binary, command) for tool, present, command in rows
            if not present and command is not None]
    executed = []
    if install and not dry_run:
        for step in plan:
            print(f"[vigil] $ {step.command}", file=sys.stderr)
            try:
                result = runner(shlex.split(step.command))
                if result.returncode != 0:
                    ok = False
                    detail = (result.stderr or result.stdout or "").strip()
                elif which(step.tool) is None:
                    ok = False
                    detail = (
                        "installer exited successfully, but the binary is still not found on PATH; "
                        "open a new shell or add the install directory to PATH, then rerun `vigil doctor`"
                    )
                else:
                    ok, detail = True, ""
            except OSError as exc:
                ok, detail = False, str(exc)
            executed.append({"tool": step.tool, "ok": ok, "detail": detail})
            if not ok:
                print(f"[vigil] {step.tool}: {detail or 'installation failed'}", file=sys.stderr)
    return {
        "dry_run": dry_run,
        "tools": [{"binary": tool.binary, "present": present, "install_command": command}
                  for tool, present, command in rows],
        "install_plan": [{"tool": step.tool, "command": step.command} for step in plan],
        "manual": [{"binary": tool.binary, "note": tool.note}
                   for tool, present, command in rows if not present and command is None],
        "executed": executed,
        "ok": all(row["ok"] for row in executed),
    }


def print_host_tool_setup(report: dict[str, Any]) -> None:
    """Print the explicit plan without turning uninspected tools into success."""
    print("Host recon tool installation:")
    for row in report["install_plan"]:
        print(f"  {row['tool']}: {row['command']}")
    for row in report["manual"]:
        print(f"  {row['binary']}: install manually — {row['note']}")
    if report["dry_run"]:
        print("  Dry run: no installers executed.")
    for row in report["executed"]:
        print(f"  {row['tool']}: {'installed' if row['ok'] else 'failed'}")
    if not report["install_plan"] and not report["manual"]:
        print("  All checked host recon tools are present.")
