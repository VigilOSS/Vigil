"""`vigil quickstart` — a macOS-first onboarding wizard.

Gets a new operator from a bare checkout to a running engagement: it probes the
host prerequisites (uv/docker/go), reports which host-side recon tools
are missing, and either PLANS or (behind an explicit flag) RUNS their install
commands. It never touches the working root, backend, or Docker on its own — the
only side effect it can take is running the host-tool install commands, and only
when `--install-host-tools` is passed. Everything else is printed as an ordered
next-command checklist keyed to the resolved install root (`~/vigil`).

The install/plan logic is factored into pure functions (`prerequisite_status`,
`host_tool_plan`) so it can be asserted on without side effects.
"""
from __future__ import annotations

import json
import platform
import shlex
import shutil
import subprocess
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from . import docker
from .runtime import HOST_RECON_TOOLS, HostTool

WhichFn = Callable[[str], str | None]
SystemFn = Callable[[], str]
Runner = Callable[[Sequence[str]], "subprocess.CompletedProcess[str]"]


@dataclass(frozen=True, slots=True)
class Prerequisite:
    """A bootstrap CLI tool the wizard reports on but never auto-installs.

    These are foundational (docker Desktop, the uv that ships the CLI itself);
    auto-running their installers from a wizard is the wrong call, so we only
    surface the macOS `brew` hint and let the operator install deliberately.
    """

    binary: str
    macos_hint: str
    note: str


PREREQUISITES: tuple[Prerequisite, ...] = (
    Prerequisite("uv", "brew install uv", "Python runner behind the CLI and the assess scripts"),
    Prerequisite(
        "docker",
        "brew install --cask docker",
        "Kali runtime + mitmproxy containers (the orchestrator runs on the host)",
    ),
    Prerequisite("go", "brew install go", "builds the go-installable host recon tools"),
)


@dataclass(frozen=True, slots=True)
class ToolStatus:
    binary: str
    present: bool
    macos_hint: str
    note: str
    detail: str = ""


@dataclass(frozen=True, slots=True)
class InstallStep:
    """One host tool to install and the exact command that would install it."""

    tool: str
    command: str


@dataclass(frozen=True, slots=True)
class QuickstartOptions:
    install_root: Path
    non_interactive: bool = False
    assume_yes: bool = False
    install_host_tools: bool = False
    dry_run: bool = False
    json_output: bool = False
    target: str | None = None
    hosts: str | None = None


def _default_runner(argv: Sequence[str]) -> "subprocess.CompletedProcess[str]":
    return subprocess.run(list(argv), text=True, capture_output=True, check=False)


def prerequisite_status(
    *,
    which: WhichFn = shutil.which,
    daemon_available: Callable[[], bool] | None = None,
) -> list[ToolStatus]:
    """Readiness of each bootstrap prerequisite, in declaration order.

    Docker is the one prerequisite where the binary is not the capability: the
    checklist this wizard prints leads straight to an image build, so a client
    binary with no reachable daemon is not ready. Same probe `vigil doctor`
    uses, so the two commands cannot disagree about the same host.
    """
    probe = daemon_available if daemon_available is not None else docker.daemon_available
    rows: list[ToolStatus] = []
    for prerequisite in PREREQUISITES:
        present = which(prerequisite.binary) is not None
        detail = ""
        if present and prerequisite.binary == "docker" and not probe():
            present = False
            detail = "binary found but the Docker daemon is not reachable — start Docker"
        rows.append(
            ToolStatus(
                prerequisite.binary, present, prerequisite.macos_hint, prerequisite.note, detail
            )
        )
    return rows


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


def host_tool_plan(
    *, which: WhichFn = shutil.which, system: SystemFn = platform.system
) -> list[InstallStep]:
    """Ordered install steps for the MISSING host tools that have an auto command.

    Pure: no PATH is mutated and nothing is executed. A missing tool without an
    auto-runnable command (e.g. `massdns` off macOS) is omitted here and surfaced
    as a manual note by the renderer instead.
    """
    return [
        InstallStep(tool.binary, command)
        for tool, present, command in host_tool_statuses(which=which, system=system)
        if not present and command is not None
    ]


def run_quickstart(
    options: QuickstartOptions,
    *,
    which: WhichFn = shutil.which,
    system: SystemFn = platform.system,
    runner: Runner = _default_runner,
    stdin_isatty: Callable[[], bool] = sys.stdin.isatty,
) -> int:
    """Drive the wizard. Returns a process exit code (0 = ok).

    The ONLY action that mutates the host is running host-tool install commands,
    gated behind `options.install_host_tools` and never taken under `--dry-run`.
    """
    interactive = not options.non_interactive and stdin_isatty()
    prereqs = prerequisite_status(which=which)
    tool_rows = host_tool_statuses(which=which, system=system)
    plan = [
        InstallStep(tool.binary, command)
        for tool, present, command in tool_rows
        if not present and command is not None
    ]
    manual = [tool for tool, present, command in tool_rows if not present and command is None]

    # `--target`/`--hosts` (if supplied) only template the copy-paste next-step
    # checklist. quickstart probes host readiness and mutates nothing engagement-
    # related, so it never prompts for an engagement target of its own.
    target, hosts = options.target, options.hosts

    executed: list[tuple[InstallStep, bool]] = []
    ran_installs = False
    if plan and options.install_host_tools and not options.dry_run:
        if not interactive or options.assume_yes or _confirm(
            f"Install {len(plan)} missing host tool(s) now?"
        ):
            ran_installs = True
            executed = _execute_plan(plan, runner)

    next_commands = _next_commands(options.install_root, target, hosts)

    if options.json_output:
        _emit_json(options, prereqs, tool_rows, plan, manual, executed, ran_installs, next_commands)
    else:
        _emit_text(
            options, prereqs, tool_rows, plan, manual, executed, ran_installs, next_commands
        )

    failed = [step for step, ok in executed if not ok]
    if failed:
        return 1
    # Missing bootstrap prerequisites are a soft warning, not a hard failure —
    # the wizard's job is to surface them, not to block on a still-installing
    # Docker Desktop. Exit non-zero only when an install command we RAN failed.
    return 0


def _execute_plan(plan: list[InstallStep], runner: Runner) -> list[tuple[InstallStep, bool]]:
    results: list[tuple[InstallStep, bool]] = []
    for step in plan:
        print(f"[quickstart] $ {step.command}", file=sys.stderr)
        proc = runner(shlex.split(step.command))
        ok = proc.returncode == 0
        if not ok:
            err = (getattr(proc, "stderr", "") or "").strip().splitlines()
            tail = err[-1] if err else f"exit {proc.returncode}"
            print(f"[quickstart]   FAILED: {step.tool}: {tail}", file=sys.stderr)
        results.append((step, ok))
    return results


def _next_commands(install_root: Path, target: str | None, hosts: str | None) -> list[str]:
    # Shell-quote every interpolated value so the printed command is safe to
    # copy-paste: a target with `&` in its query string, or whitespace in the
    # host list / install path, would otherwise split or background the command
    # and `vigil engagement create` would receive a truncated argument.
    if target:
        create = f"vigil engagement create {shlex.quote(target)}"
        if hosts:
            create += f" --hosts {shlex.quote(hosts)}"
    else:
        create = "vigil engagement create https://target.example --hosts target.example"
    return [
        f"vigil install {shlex.quote(str(install_root))}",
        "vigil up",
        create,
        "vigil engagement start <key> --client claude",
    ]


def _emit_text(
    options: QuickstartOptions,
    prereqs: list[ToolStatus],
    tool_rows: list[tuple[HostTool, bool, str | None]],
    plan: list[InstallStep],
    manual: list[HostTool],
    executed: list[tuple[InstallStep, bool]],
    ran_installs: bool,
    next_commands: list[str],
) -> None:
    print("vigil quickstart — host readiness + setup checklist")
    print(f"install root: {options.install_root}")
    print()
    print("prerequisites (install these yourself if MISSING):")
    for p in prereqs:
        state = "ok " if p.present else "MISS"
        suffix = "" if p.present else f"  {p.detail or p.macos_hint}"
        print(f"  [{state}] {p.binary:<8} {p.note}{suffix}")
    print()
    print("host recon tools:")
    for tool, present, command in tool_rows:
        state = "ok " if present else "MISS"
        detail = "" if present else f"  {command or tool.note}"
        print(f"  [{state}] {tool.binary}{detail}")
    print()
    if not plan and not manual:
        print("all host recon tools present.")
    else:
        if plan:
            verb = "installed" if ran_installs else "would install"
            print(f"host-tool plan ({verb}):")
            for step in plan:
                if ran_installs:
                    ok = next((o for s, o in executed if s is step), None)
                    mark = "ok" if ok else ("FAILED" if ok is False else "skipped")
                    print(f"  [{mark}] {step.tool}: {step.command}")
                else:
                    print(f"  {step.tool}: {step.command}")
            if not ran_installs:
                if options.dry_run:
                    print("  (dry-run: nothing executed)")
                elif not options.install_host_tools:
                    print("  re-run with --install-host-tools to execute these commands.")
        if manual:
            print("manual (no auto-install on this platform):")
            for tool in manual:
                print(f"  {tool.binary}: {tool.note}")
    print()
    print("next steps:")
    for command in next_commands:
        print(f"  {command}")


def _emit_json(
    options: QuickstartOptions,
    prereqs: list[ToolStatus],
    tool_rows: list[tuple[HostTool, bool, str | None]],
    plan: list[InstallStep],
    manual: list[HostTool],
    executed: list[tuple[InstallStep, bool]],
    ran_installs: bool,
    next_commands: list[str],
) -> None:
    payload = {
        "install_root": str(options.install_root),
        "install_host_tools": options.install_host_tools,
        "dry_run": options.dry_run,
        "installs_executed": ran_installs,
        "prerequisites": [
            {
                "binary": p.binary,
                "present": p.present,
                "macos_hint": p.macos_hint,
                "note": p.note,
                "detail": p.detail,
            }
            for p in prereqs
        ],
        "host_tools": [
            {"binary": tool.binary, "present": present, "install_command": command}
            for tool, present, command in tool_rows
        ],
        "install_plan": [{"tool": step.tool, "command": step.command} for step in plan],
        "manual": [{"binary": tool.binary, "note": tool.note} for tool in manual],
        "executed": [{"tool": step.tool, "ok": ok} for step, ok in executed],
        "next_commands": next_commands,
    }
    print(json.dumps(payload, indent=2))


def _read_line() -> str:
    try:
        return input()
    except EOFError:
        return ""


def _confirm(prompt: str) -> bool:
    print(f"{prompt} [y/N] ", end="", file=sys.stderr, flush=True)
    return _read_line().strip().lower() in {"y", "yes"}
