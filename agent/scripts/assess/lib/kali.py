"""Host-side `vigil assess kali` orchestration.

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

from . import vuln_taxonomy
from .client import AssessError, AssessmentClient, default_runtime_container
from .config import Config, load_config
from .identity import identity_names, resolve_identity

# Re-exports — keep this block ordered by source module so the public surface
# is grep-friendly. Tests patch a number of these via the legacy
# ``kali.<name>`` attribute path; the orchestrator below also calls them via
# bare name lookup, which resolves to these globals (so patches take effect).
from .audit_enums import (
    PROBE_KIND_ENUM,
    TECHNIQUE_ENUM,
    normalize_probe_kind,
    normalize_technique,
)
from .kali_audit import (
    ALLOWED_PHASES,
    _INTENT_MAX_LEN,
    _extract_target_anchor,
    _extract_target_host,
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
    _engagement_type,
    _peak_rss_kilobytes_to_bytes,
    _read_proc_peak_rss,
    _read_safely,
    _scope_version,
    _utcnow_iso,
)
from .kali_runtime_exec import (
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
_KALI_NOOP_ENV = "VIGIL_KALI_NOOP"


_PROBE_EMITTING_KINDS = frozenset({"payload", "exploit", "baseline", "replay"})

_NON_WEB_ENGAGEMENT_TYPES = frozenset({"code", "blue"})


def _emit_probe_run(
    client: AssessmentClient,
    *,
    engagement_type: str,
    technique: str,
    probe_kind: str,
    auth_context: str,
    tool_name: str,
    agent_name: str,
    return_code: int | None,
    timed_out: bool,
    cmd: list[str],
    evidence_ref: str,
) -> None:
    """Best-effort auto-emit one probe_run from a finished kali run (Wave 5 / 2a).

    This is the linchpin that makes depth observable: every typed kali call
    already carries a vuln-class ``--technique`` and a ``--probe-kind``, so a
    completed real-attack probe honestly records "this vuln class was tested
    against this host" WITHOUT any new specialist behavior.

    Emission rules (each derived from durable run state, never a blind default):
      * WEB-ONLY GUARD: skip unless engagement_type ∈ {web, both} — no
        cross-track bleed onto code/blue (R-H2 doctrine).
      * Only for a REAL test (probe_kind ∈ payload/exploit/baseline/replay);
        fingerprint/cleanup never emit.
      * attack_family = TECHNIQUE_TO_CLASS[technique]; if None (operational
        technique like RECON/FUZZ/HEALTH) there is no vuln class to attribute,
        so SKIP — never invent a class.
      * result_status: timed_out OR return_code not in (0, None) → "error"
        (which is NOT in PROBE_RESULT_STATUSES_COVERING, so a failed probe never
        counts as covered, S4); otherwise "tested". Operational/fingerprint
        probes are already excluded, so a completed real-attack probe = the
        class was honestly tested.

    BEST-EFFORT: any failure warns to stderr and returns; it must NEVER block or
    fail the tool run, and must not raise.
    """
    try:
        if str(engagement_type or "").lower() in _NON_WEB_ENGAGEMENT_TYPES:
            return
        if probe_kind not in _PROBE_EMITTING_KINDS:
            return
        attack_family = vuln_taxonomy.TECHNIQUE_TO_CLASS.get(technique)
        if attack_family is None:
            return
        if timed_out or (return_code not in (0, None)):
            result_status = "error"
        else:
            result_status = "tested"
        target_host, target_path, target_port = _extract_target_anchor(tool_name, cmd)
        if not target_host:
            target_host = _extract_target_host(tool_name, cmd)
        payload = {
            "target_host": target_host,
            "target_path": target_path,
            "target_port": target_port,
            "auth_context": auth_context,
            "input_slot": "unknown",
            "attack_family": attack_family,
            "payload_family": "",
            "payload_value": "",
            "tool_name": tool_name,
            "agent_name": agent_name,
            "result_status": result_status,
            "observed_http_status": None,
            "evidence_ref": evidence_ref,
        }
        client.post("probe-runs", payload)
    except Exception as exc:  # noqa: BLE001 — best-effort, must never break a run
        print(
            f"warning: probe-run auto-emit failed: {exc}; depth harness skipped this run.",
            file=sys.stderr,
        )


_IDENTITY_INJECTABLE_TOOLS = frozenset({"curl", "httpx", "nuclei", "ffuf", "sqlmap", "katana"})


def _identity_header_pairs(material: dict) -> list[tuple[str, str]]:
    """Flatten an identity's auth material into ``(header, value)`` pairs.

    Supports a ``headers`` map, a ``cookies`` map (joined into one ``Cookie``
    header), and an optional bearer ``token``. Order is deterministic.
    """
    pairs: list[tuple[str, str]] = []
    headers = material.get("headers")
    if isinstance(headers, dict):
        for key, value in headers.items():
            if str(key).strip():
                pairs.append((str(key), str(value)))
    cookies = material.get("cookies")
    if isinstance(cookies, dict) and cookies:
        cookie = "; ".join(f"{k}={v}" for k, v in cookies.items())
        pairs.append(("Cookie", cookie))
    token = material.get("token") or material.get("bearer")
    if token and not any(name.lower() == "authorization" for name, _ in pairs):
        pairs.append(("Authorization", f"Bearer {token}"))
    return pairs


def _apply_identity_material(cmd: list[str], tool_name: str, material: dict) -> bool:
    """Inject a named identity's auth headers/cookies into an HTTP command argv so
    the request actually runs AS that identity.

    Returns True when the credentials were applied (the caller may then relabel
    auth_context to the identity); False when there is nothing to apply or the
    tool can't take injected headers. A False return MUST prevent relabeling, so
    a run that did not actually carry the identity's credentials is never counted
    as a distinct identity by the depth ledger's cross-identity rule.
    """
    if not isinstance(material, dict):
        return False
    pairs = _identity_header_pairs(material)
    if not pairs:
        return False
    exe = os.path.basename(str(cmd[0])).lower() if cmd else ""
    if exe not in _IDENTITY_INJECTABLE_TOOLS:
        return False
    for name, value in pairs:
        cmd.extend(["-H", f"{name}: {value}"])
    return True


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
    container_name: str | None = None,
    config: Config | None = None,
    tool_name: str | None = None,
    identity: str | None = None,
) -> KaliResult:
    """Run `cmd` inside the runtime container with full audit recording.

    The pre-exec audit row is written before docker-exec starts so a crash
    leaves a `running` row that can be reaped by orphan-sweep tooling.
    Stdout/stderr stream to disk from line 1 — never buffered in memory.
    """
    # Resolve the container name at call time (not import time) so a
    # VIGIL_RUNTIME_CONTAINER set after this module was imported — or by a test
    # via monkeypatch.setenv — is honoured. Default stays "vigil" when unset.
    container_name = container_name or default_runtime_container()
    # When the caller passes engagement_dir explicitly (typically via
    # --engagement-dir hoisted by assess.cli), forward it to load_config so
    # config resolution doesn't fall back to env/cwd and erroneously
    # SystemExit with "Cannot resolve engagement directory."
    cfg = config or load_config(str(engagement_dir) if engagement_dir else None)
    eng_dir = _resolve_engagement_dir(engagement_dir, cfg)
    eng_key = engagement_key or eng_dir.name or cfg.engagement_key
    resolved_agent = _resolve_agent_name(agent_name)
    technique = normalize_technique(technique)
    probe_kind = normalize_probe_kind(probe_kind)
    if phase:
        phase = phase.strip().lower()
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
    _identity_name: str | None = None
    _identity_material: dict = {}
    if identity is not None:
        _identity_name, _identity_material = resolve_identity(eng_dir, identity)
        if not _identity_material:
            print(
                f"warning: --identity '{identity}' not found in auth.json "
                f"(known: {', '.join(identity_names(eng_dir)) or 'none'}); "
                "no auth material to apply.",
                file=sys.stderr,
            )

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
    if identity is not None:
        if _apply_identity_material(cmd, derived_tool_name, _identity_material):
            auth_context = _identity_name or auth_context
        else:
            print(
                f"warning: --identity '{identity}': auth material was NOT applied "
                f"(tool '{derived_tool_name}' takes no injectable -H header, or no "
                "material). Leaving auth_context derived so this run is NOT counted "
                "as a cross-identity probe — inject the identity's auth into the "
                "command manually if this tool needs it.",
                file=sys.stderr,
            )
    container_working_dir = f"/engagements/{eng_key}"
    docker_argv = _build_docker_exec(
        cmd,
        container_name=container_name,
        run_uuid=run_uuid,
        working_dir=container_working_dir,
        engagement_key=eng_key,
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
                working_dir=container_working_dir,
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
                # ``docker`` binary missing on PATH. The pre-exec POST at
                # line 186 already wrote a status=running audit row; without
                # this finalize the row stays "running" forever and confuses
                # sweep-orphans + operator audit. PATCH it to failed before
                # raising so the row reflects what actually happened.
                if run_id is not None and not audit_failed:
                    try:
                        _patch_finalize(
                            client,
                            run_id=run_id,
                            status="failed",
                            return_code=None,
                            ended_at_iso=_utcnow_iso(),
                            duration_ms=0,
                            stdout_preview="",
                            stderr_preview=f"docker not found: {exc}",
                            timed_out=False,
                            partial_results=False,
                            peak_rss_bytes=None,
                            cpu_user_seconds=None,
                            cpu_system_seconds=None,
                        )
                    except AssessError as patch_exc:
                        # Belt-and-braces: if the PATCH also fails, drop a
                        # failed-audit marker so sweep-orphans can pick it up.
                        _write_failed_audit_marker(
                            eng_dir,
                            run_uuid=run_uuid,
                            error=(
                                f"docker not found AND finalize PATCH failed: "
                                f"{patch_exc}"
                            ),
                        )
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
                finalize_ok = True
            except AssessError as exc:
                # 409 races are now handled inside _patch_finalize; reaching
                # this branch means a real failure (network, 4xx other than
                # 409, 5xx exhaustion) and the row may genuinely need sweep.
                finalize_ok = False
                print(
                    f"warning: finalize PATCH failed: {exc}; row stays running and may need orphan sweep.",
                    file=sys.stderr,
                )

            if finalize_ok:
                evidence_ref = f"{container_working_dir}/scans/kali/{run_uuid}.out"
                _emit_probe_run(
                    client,
                    engagement_type=_engagement_type(eng_dir),
                    technique=technique,
                    probe_kind=probe_kind,
                    auth_context=auth_context,
                    tool_name=derived_tool_name,
                    agent_name=resolved_agent,
                    return_code=return_code,
                    timed_out=timed_out,
                    cmd=cmd,
                    evidence_ref=evidence_ref,
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
    "_extract_target_host",
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
    "_engagement_type",
    "_peak_rss_kilobytes_to_bytes",
    "_read_proc_peak_rss",
    "_read_safely",
    "_scope_version",
    "_utcnow_iso",
    # Runtime exec + kill cascade (from kali_runtime_exec)
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
    "default_runtime_container",
    "PROBE_KIND_ENUM",
    "TECHNIQUE_ENUM",
    "_emit_probe_run",
    # Public surface
    "kali_exec",
]
