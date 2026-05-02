"""Host-side `aith assess kali` orchestration.

Owns ``kali_exec`` — the high-level loop that ties the docker-exec
subprocess, the audit pipeline (pre-exec POST + finalize PATCH), output
spilling under ``${ENGAGEMENT_DIR}/scans/kali/<run-id>.{out,err}``, the
two-namespace process-group cleanup on timeout, scope/auth context
capture, and dedup warnings together. Typed kali_* commands and the raw
``kali exec`` fallback all delegate here.

Implementation responsibilities are split across sibling modules so the
blast radius of future changes stays scoped:

- ``kali_tool_naming``  — tool-name derivation + shell-pipeline parsing
- ``kali_runtime_exec`` — docker-exec wrapping + two-namespace kill cascade
- ``kali_audit``        — pre-exec POST, finalize PATCH, failed-audit marker,
                          input validation, agent-name + engagement-dir resolution
- ``kali_output``       — head+tail preview, RSS rollup, scope/auth context,
                          ``KaliResult`` dataclass
- ``kali_cli``          — argparse scaffolding (flags, kwargs builder,
                          ``emit_result``) used by every ``kali_<verb>`` file

This module re-exports the public surface (``kali_exec``, ``KaliResult``,
``ALLOWED_PHASES``, ``add_required_kali_flags``, etc.) plus the private
helpers that ``orchestrator/backend/tests/test_kali_cli.py`` patches via
``monkeypatch.setattr(kali, "<name>", ...)`` so test mocks keep resolving
without touching the rest of the suite.
"""
from __future__ import annotations

import os
import resource
import signal
import subprocess
import sys
import time
import uuid
from pathlib import Path

from .client import AssessError, AssessmentClient
from .config import Config, load_config

# Re-exports — keep this block ordered by source module so the public surface
# is grep-friendly. Tests patch a number of these via the legacy
# ``kali.<name>`` attribute path; the orchestrator below also calls them via
# bare name lookup, which resolves to these globals (so patches take effect).
from .audit_enums import PROBE_KIND_ENUM, TECHNIQUE_ENUM
from .kali_audit import (
    ALLOWED_PHASES,
    _INTENT_MAX_LEN,
    _patch_finalize,
    _post_pre_exec_row,
    _resolve_agent_name,
    _resolve_engagement_dir,
    _validate_inputs,
    _write_failed_audit_marker,
)
from .kali_cli import (
    add_passthrough_args_flag,
    add_required_kali_flags,
    emit_result,
    extend_cmd_with_extra_args,
    kali_args_to_kwargs,
)
from .kali_output import (
    KaliResult,
    _auth_context,
    _peak_rss_kilobytes_to_bytes,
    _read_proc_peak_rss,
    _read_safely,
    _scope_version,
    _utcnow_iso,
)
from .kali_runtime_exec import (
    _DEFAULT_CONTAINER_NAME,
    _build_docker_exec,
    _check_container_running,
    _cleanup_container_pid_file,
    _container_pid_file,
    _kill_in_container,
    _read_container_pid,
)
from .kali_tool_naming import (
    _SHELL_BINARIES,
    _SHELL_KEYWORDS,
    _analyze_tool_name,
    _derive_tool_name,
    _is_plausible_executable,
    _scan_inner_for_first_exec,
    _split_inner_pipeline_stages,
)


# Test-mode override: when set, skips both audit POST and `docker exec` so
# argparse round-trip tests don't require a live backend or container. The
# `run` callable on every kali_* command should still be reachable for `--help`
# without going through the helper.
_KALI_NOOP_ENV = "AITH_KALI_NOOP"


def kali_exec(
    cmd: list[str],
    *,
    technique: str,
    intent: str,
    probe_kind: str,
    phase: str,
    destructive: bool = False,
    timeout: int,
    agent_name: str | None = None,
    engagement_dir: Path | None = None,
    engagement_key: str | None = None,
    force: bool = False,
    container_name: str = _DEFAULT_CONTAINER_NAME,
    config: Config | None = None,
    tool_name: str | None = None,
) -> KaliResult:
    """Run `cmd` inside the runtime container with full audit recording.

    The pre-exec audit row is written before docker-exec starts so a crash
    leaves a `running` row that can be reaped by orphan-sweep tooling.
    Stdout/stderr stream to disk from line 1 — never buffered in memory.
    """
    # When the caller passes engagement_dir explicitly (typically via
    # --engagement-dir hoisted by assess.cli), forward it to load_config so
    # config resolution doesn't fall back to env/cwd and erroneously
    # SystemExit with "Cannot resolve engagement directory."
    cfg = config or load_config(str(engagement_dir) if engagement_dir else None)
    eng_dir = _resolve_engagement_dir(engagement_dir, cfg)
    eng_key = engagement_key or eng_dir.name or cfg.engagement_key
    resolved_agent = _resolve_agent_name(agent_name)
    _validate_inputs(
        technique=technique,
        intent=intent,
        probe_kind=probe_kind,
        phase=phase,
        timeout=timeout,
        agent_name=resolved_agent,
    )

    run_uuid = uuid.uuid4().hex
    out_dir = eng_dir / "scans" / "kali"
    out_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = out_dir / f"{run_uuid}.out"
    stderr_path = out_dir / f"{run_uuid}.err"

    started_at_iso = _utcnow_iso()
    started_monotonic = time.monotonic()
    scope_version = _scope_version(eng_dir)
    auth_context = _auth_context(eng_dir)

    if os.environ.get(_KALI_NOOP_ENV):
        # Test-only short-circuit. Returns a synthetic result so argparse
        # smoke tests work without a real container or backend.
        return KaliResult(
            run_id=None,
            status="completed",
            return_code=0,
            stdout_path=str(stdout_path),
            stderr_path=str(stderr_path),
            duration_ms=0,
            peak_rss_bytes=None,
            stdout_preview="",
            stderr_preview="",
            timed_out=False,
            partial_results=False,
        )

    _check_container_running(container_name)

    derived_tool_name = tool_name or _derive_tool_name(cmd)
    docker_argv = _build_docker_exec(
        cmd,
        container_name=container_name,
        run_uuid=run_uuid,
        working_dir=f"/engagements/{eng_key}",
    )

    client = AssessmentClient(cfg.base_url, eng_key)
    run_id: int | None = None
    superseded_by_id: int | None = None
    audit_failed = False
    try:
        try:
            row = _post_pre_exec_row(
                client,
                cmd=cmd,
                technique=technique,
                intent=intent,
                probe_kind=probe_kind,
                phase=phase,
                destructive=destructive,
                agent_name=resolved_agent,
                engagement_dir=eng_dir,
                container_name=container_name,
                timeout=timeout,
                force=force,
                started_at_iso=started_at_iso,
                stdout_path=str(stdout_path),
                stderr_path=str(stderr_path),
                working_dir=os.getcwd(),
                scope_version=scope_version,
                auth_context=auth_context,
                tool_name=derived_tool_name,
                run_uuid=run_uuid,
            )
            run_id = int(row.get("id")) if row.get("id") is not None else None
            superseded_by_id = row.get("superseded_by_id")
            if superseded_by_id and not force:
                # Warn-and-continue: parallel specialists racing on the same
                # wildcard list inside the dedup window should not be hard-
                # blocked. The backend has already inserted a fresh row and
                # linked it to the predecessor via ``superseded_by_id``; the
                # finalize PATCH below targets that NEW row's id.
                # ``--force`` suppresses the warning entirely (and also tells
                # the backend to skip the supersede link).
                print(
                    f"warning: dedup hit — equivalent command-run id={superseded_by_id} "
                    f"is still in flight.",
                    file=sys.stderr,
                )
        except AssessError as exc:
            print(
                f"warning: pre-exec audit POST failed: {exc}; continuing without audit row.",
                file=sys.stderr,
            )
            _write_failed_audit_marker(eng_dir, run_uuid=run_uuid, error=str(exc))
            audit_failed = True

        # Open output files BEFORE Popen so streaming starts at line 1.
        with stdout_path.open("wb") as out_fh, stderr_path.open("wb") as err_fh:
            try:
                process = subprocess.Popen(  # noqa: S603 — controlled argv
                    docker_argv,
                    shell=False,
                    stdin=subprocess.DEVNULL,
                    stdout=out_fh,
                    stderr=err_fh,
                    start_new_session=True,
                )
            except FileNotFoundError as exc:
                raise AssessError(f"docker not found: {exc}") from exc
            timed_out = False
            partial_results = False
            return_code: int | None = None
            try:
                return_code = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                # Two-namespace kill cascade. ``os.killpg`` only signals the
                # host-side ``docker exec`` client and any siblings in our
                # process group — it cannot reach the user command running
                # inside the container's PID namespace under ``dockerd+tini``,
                # and dockerd's signal forwarding is best-effort. SIGTERM-
                # trapping tools (sqlmap, nuclei) survive that path. The
                # wrapper shell records the in-container PID to a pid file so
                # we can also send ``docker exec kill`` directly at the user
                # command across the namespace boundary.
                container_pid = _read_container_pid(container_name, run_uuid)
                if container_pid is not None:
                    _kill_in_container(container_name, container_pid, "TERM")
                else:
                    # If the exact PID is unavailable, avoid argv-pattern
                    # cleanup. `pkill -f` can match sibling agent runs inside
                    # the shared runtime container; host-side kill plus
                    # sweep-orphans is safer than a broad in-container signal.
                    print(
                        f"warning: in-container pid file missing for run {run_uuid}; "
                        "using host process-group cleanup only.",
                        file=sys.stderr,
                    )
                try:
                    pgid = os.getpgid(process.pid)
                    os.killpg(pgid, signal.SIGTERM)
                except (ProcessLookupError, PermissionError):
                    pass
                try:
                    return_code = process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    if container_pid is not None:
                        _kill_in_container(container_name, container_pid, "KILL")
                    try:
                        pgid = os.getpgid(process.pid)
                        os.killpg(pgid, signal.SIGKILL)
                    except (ProcessLookupError, PermissionError):
                        pass
                    try:
                        return_code = process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        return_code = None
                _cleanup_container_pid_file(container_name, run_uuid)

        # Clean up the pid file on the happy path too so /tmp doesn't grow
        # unboundedly. The wrapper writes the file then ``exec``s the user
        # command, so by the time we get here the user command has exited
        # but the file remains.
        if not timed_out:
            _cleanup_container_pid_file(container_name, run_uuid)

        ended_at_iso = _utcnow_iso()
        duration_ms = int((time.monotonic() - started_monotonic) * 1000)

        # Resource snapshot. getrusage(RUSAGE_CHILDREN) is rolled-up across all
        # waited-for children of the calling process; for a single-shot CLI
        # call the caller is the lone child so the values are accurate.
        try:
            usage = resource.getrusage(resource.RUSAGE_CHILDREN)
            cpu_user_seconds = float(usage.ru_utime)
            cpu_system_seconds = float(usage.ru_stime)
            peak_rss_bytes: int | None = _peak_rss_kilobytes_to_bytes(int(usage.ru_maxrss))
        except OSError:
            cpu_user_seconds = None
            cpu_system_seconds = None
            peak_rss_bytes = None

        proc_peak = _read_proc_peak_rss(process.pid)
        if proc_peak is not None:
            peak_rss_bytes = proc_peak

        stdout_preview = _read_safely(stdout_path)
        stderr_preview = _read_safely(stderr_path)

        if timed_out and (stdout_preview or stderr_preview):
            partial_results = True

        if return_code is None:
            terminal_status = "killed"
        elif timed_out:
            terminal_status = "timed_out"
        elif return_code != 0:
            terminal_status = "failed"
        else:
            terminal_status = "completed"

        if run_id is not None and not audit_failed:
            try:
                _patch_finalize(
                    client,
                    run_id=run_id,
                    status=terminal_status,
                    return_code=return_code,
                    ended_at_iso=ended_at_iso,
                    duration_ms=duration_ms,
                    stdout_preview=stdout_preview,
                    stderr_preview=stderr_preview,
                    timed_out=timed_out,
                    partial_results=partial_results,
                    peak_rss_bytes=peak_rss_bytes,
                    cpu_user_seconds=cpu_user_seconds,
                    cpu_system_seconds=cpu_system_seconds,
                )
            except AssessError as exc:
                # 409 races are now handled inside _patch_finalize; reaching
                # this branch means a real failure (network, 4xx other than
                # 409, 5xx exhaustion) and the row may genuinely need sweep.
                print(
                    f"warning: finalize PATCH failed: {exc}; row stays running and may need orphan sweep.",
                    file=sys.stderr,
                )

        return KaliResult(
            run_id=run_id,
            status=terminal_status,
            return_code=return_code,
            stdout_path=str(stdout_path),
            stderr_path=str(stderr_path),
            duration_ms=duration_ms,
            peak_rss_bytes=peak_rss_bytes,
            stdout_preview=stdout_preview,
            stderr_preview=stderr_preview,
            timed_out=timed_out,
            partial_results=partial_results,
        )
    finally:
        client.close()


# Backward-compat re-exports for callers and test mocks. These names live in
# this module's globals so:
#   1. ``from assess.lib.kali import _resolve_agent_name`` keeps resolving for
#      ``kali_job.py`` and friends.
#   2. ``monkeypatch.setattr(kali, "_check_container_running", stub)`` replaces
#      the name the orchestrator code calls, since orchestrator code looks up
#      these helpers via the module globals (the names imported above).
__all__ = [
    # Audit + validation (from kali_audit)
    "ALLOWED_PHASES",
    "_INTENT_MAX_LEN",
    "_post_pre_exec_row",
    "_patch_finalize",
    "_resolve_agent_name",
    "_resolve_engagement_dir",
    "_validate_inputs",
    "_write_failed_audit_marker",
    # CLI scaffolding (from kali_cli)
    "add_required_kali_flags",
    "add_passthrough_args_flag",
    "extend_cmd_with_extra_args",
    "kali_args_to_kwargs",
    "emit_result",
    # Output + RSS (from kali_output)
    "KaliResult",
    "_auth_context",
    "_peak_rss_kilobytes_to_bytes",
    "_read_proc_peak_rss",
    "_read_safely",
    "_scope_version",
    "_utcnow_iso",
    # Runtime exec + kill cascade (from kali_runtime_exec)
    "_DEFAULT_CONTAINER_NAME",
    "_build_docker_exec",
    "_check_container_running",
    "_cleanup_container_pid_file",
    "_container_pid_file",
    "_kill_in_container",
    "_read_container_pid",
    # Tool-name derivation (from kali_tool_naming)
    "_SHELL_BINARIES",
    "_SHELL_KEYWORDS",
    "_analyze_tool_name",
    "_derive_tool_name",
    "_is_plausible_executable",
    "_scan_inner_for_first_exec",
    "_split_inner_pipeline_stages",
    # Re-export AssessmentClient + audit enums for tests that patch them
    "AssessmentClient",
    "PROBE_KIND_ENUM",
    "TECHNIQUE_ENUM",
    # Public surface
    "kali_exec",
]
