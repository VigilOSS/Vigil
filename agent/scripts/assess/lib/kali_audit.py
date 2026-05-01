"""Audit POST/PATCH plumbing and input validation for kali runs.

Owns the orchestrator-backend interactions tied to the audit pipeline:
the pre-exec ``command-runs`` POST that registers a ``running`` row before
docker-exec starts, the finalize PATCH that writes the terminal status,
and the ``failed-audit`` marker file written when the POST itself fails.
Also hosts the input-validation helpers (``--phase`` enum, agent-name
resolution, engagement-dir resolution) because they gate whether a row
makes it onto the wire at all.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from .audit_enums import PROBE_KIND_ENUM, TECHNIQUE_ENUM
from .client import AssessError, AssessmentClient
from .config import Config
from .kali_output import _utcnow_iso


# Allowed phase enum mirrors orchestrator/backend/app/api/assessment.py
# `_ALLOWED_PHASES`. Fail closed if the agent passes anything else so the
# operator gets a clear error before the backend rejects with 422.
ALLOWED_PHASES: tuple[str, ...] = (
    "recon",
    "collect",
    "consume-test",
    "verify",
    "exploit",
    "report",
    "code-ingest",
    "code-classify",
    "code-hunt",
    "code-verify",
    "recon-pivot",
    "exploit-recon",
)


_INTENT_MAX_LEN = 200


def _validate_inputs(
    *,
    technique: str,
    intent: str,
    probe_kind: str,
    phase: str,
    timeout: int,
    agent_name: str,
) -> None:
    if not technique:
        raise AssessError("--technique is required")
    if TECHNIQUE_ENUM and technique not in TECHNIQUE_ENUM:
        raise AssessError(
            f"--technique '{technique}' is not in TECHNIQUE_ENUM. "
            f"Allowed values: {', '.join(TECHNIQUE_ENUM)}"
        )
    if not intent:
        raise AssessError("--intent is required")
    if len(intent) > _INTENT_MAX_LEN:
        raise AssessError(f"--intent exceeds {_INTENT_MAX_LEN} characters")
    if not probe_kind:
        raise AssessError("--probe-kind is required")
    if PROBE_KIND_ENUM and probe_kind not in PROBE_KIND_ENUM:
        raise AssessError(
            f"--probe-kind '{probe_kind}' is not in PROBE_KIND_ENUM. "
            f"Allowed values: {', '.join(PROBE_KIND_ENUM)}"
        )
    if not phase:
        raise AssessError("--phase is required (no env-var fallback)")
    if phase not in ALLOWED_PHASES:
        raise AssessError(
            f"--phase '{phase}' is not allowed. Allowed values: {', '.join(ALLOWED_PHASES)}"
        )
    if timeout is None or timeout <= 0:
        raise AssessError("--timeout (seconds) is required and must be > 0")
    if not agent_name:
        # `_resolve_agent_name` always returns a non-empty string thanks to the
        # default-to-"operator" fallback, so reaching this branch means an
        # internal regression (e.g. someone bypassed the resolver). Defense in
        # depth — keep the guard with a different message so the failure mode
        # is clear if it ever fires.
        raise AssessError("internal error: agent_name unexpectedly empty")


def _resolve_agent_name(explicit: str | None) -> str:
    """Resolve --agent-name with env-var fallback and an "operator" default.

    Precedence: explicit flag > $AGENT_NAME > $AITH_AGENT_NAME > "operator".
    The default lets the operator run mechanical pipeline checks (tier-pick
    smoke, runtime health, credential validation) without remembering to set
    --agent-name. Specialist dispatch wrappers are responsible for exporting
    AGENT_NAME=<role>; if that wrapper context is absent, the caller should
    pass --agent-name explicitly to avoid operator misattribution.
    """
    if explicit:
        return explicit
    env_value = os.environ.get("AGENT_NAME") or os.environ.get("AITH_AGENT_NAME") or ""
    if env_value:
        return env_value
    return "operator"


def _resolve_engagement_dir(explicit: Path | None, cfg: Config) -> Path:
    if explicit is not None:
        return Path(explicit).resolve()
    return Path(cfg.engagement_dir).resolve()


def _post_pre_exec_row(
    client: AssessmentClient,
    *,
    cmd: list[str],
    technique: str,
    intent: str,
    probe_kind: str,
    phase: str,
    destructive: bool,
    agent_name: str,
    engagement_dir: Path,
    container_name: str,
    timeout: int,
    force: bool,
    started_at_iso: str,
    stdout_path: str,
    stderr_path: str,
    working_dir: str,
    scope_version: str,
    auth_context: str,
    tool_name: str,
    run_uuid: str,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "command": " ".join(cmd),
        "argv": list(cmd),
        "tool_name": tool_name,
        "route": f"aith assess kali/{tool_name}",
        "agent_name": agent_name,
        "phase": phase,
        "started_at": started_at_iso,
        "completed_at": started_at_iso,
        "duration_ms": 0,
        "stdout": "",
        "stderr": "",
        "audit_source": "header",
        "technique": technique,
        "intent": intent[:_INTENT_MAX_LEN],
        "probe_kind": probe_kind,
        "destructive": destructive,
        "status": "running",
        "stdout_path": stdout_path,
        "stderr_path": stderr_path,
        "working_dir": working_dir,
        "scope_version": scope_version,
        "auth_context": auth_context,
        "timeout_seconds_requested": int(timeout),
        "force": bool(force),
        # Pin the backend's `run_uuid` column to the engagement-wide id the
        # CLI generated for the wrapper pid file and stdout path. Without
        # this, the backend would generate its OWN uuid and the column would
        # not match the pid file key — orphan-sweep would have no DB-side way
        # to recover the in-container PID and would fall back to regex-parsing
        # stdout_path, which breaks the moment the artifact dir is reconfigured.
        "run_uuid": run_uuid,
    }
    return client.post("command-runs", payload)


def _patch_finalize(
    client: AssessmentClient,
    *,
    run_id: int,
    status: str,
    return_code: int | None,
    ended_at_iso: str,
    duration_ms: int,
    stdout_preview: str,
    stderr_preview: str,
    timed_out: bool,
    partial_results: bool,
    peak_rss_bytes: int | None,
    cpu_user_seconds: float | None,
    cpu_system_seconds: float | None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "status": status,
        "return_code": return_code,
        "ended_at": ended_at_iso,
        "duration_ms": int(duration_ms),
        "stdout_preview": stdout_preview,
        "stderr_preview": stderr_preview,
        "timed_out": bool(timed_out),
        "partial_results": bool(partial_results),
    }
    if peak_rss_bytes is not None:
        payload["peak_rss_bytes"] = int(peak_rss_bytes)
    if cpu_user_seconds is not None:
        payload["cpu_user_seconds"] = float(cpu_user_seconds)
    if cpu_system_seconds is not None:
        payload["cpu_system_seconds"] = float(cpu_system_seconds)
    # 409 from the finalize endpoint means a concurrent finalize already
    # wrote the canonical row — accept it and return that row, do not raise.
    return client.patch(f"command-runs/{int(run_id)}", payload, accept_409=True)


def _write_failed_audit_marker(engagement_dir: Path, *, run_uuid: str, error: str) -> None:
    marker_dir = engagement_dir / "scans" / "kali"
    marker_dir.mkdir(parents=True, exist_ok=True)
    marker = marker_dir / f"{run_uuid}.failed-audit"
    try:
        marker.write_text(f"{_utcnow_iso()} {error}\n", encoding="utf-8")
    except OSError:
        pass
