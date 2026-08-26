"""vigil assess kali sweep-orphans — reconcile incomplete command-run state.

When a `kali_exec` finalize PATCH fails (network blip, backend restart, host
crash mid-run), the pre-exec audit row stays at ``status=running`` forever.
This command sweeps rows older than ``--max-age-seconds`` and either leaves
them alone (the in-container PID is still alive), finalizes them to
``status=lost`` (the PID is gone or the wrapper pid file is missing), or skips
them when Docker probing itself fails and liveness is unknown.

The same sweep is the durable owner for a rarer crash window: a host-exec
terminal row whose transaction committed with output cleanup or integrity
still ``pending`` before the request worker died.  Replaying the terminal
PATCH asks the backend to adopt and verify that pending work idempotently.

The wrapper shell in ``kali.py:_build_docker_exec`` writes the in-container
PID to ``/tmp/vigil-pid-<run_uuid>.pid``. The canonical source of ``run_uuid``
is the DB column on ``assessment_command_runs`` (CLI-generated, written into
the row via the pre-exec POST). The legacy regex parse against ``stdout_path``
(``scans/kali/<run_uuid>.out``) is kept as a fallback for rows written before
the CLI propagated ``run_uuid`` into the POST payload — see
``_resolve_run_uuid``.
"""
from __future__ import annotations

import datetime as _dt
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote, urlencode

from assess.lib.client import AssessError, AssessmentClient, default_runtime_container
from assess.lib.config import load_config
from assess.lib.kali_jobs import _job_pid_file as _job_pid_file_in_container
from assess.lib.kali_jobs import _read_exit_marker as _read_job_exit_marker
from assess.lib.kali_jobs import finalize_parent_command_run
from assess.lib.kali_runtime_exec import _cat_container_pid_file, _container_pid_file
from assess.lib.host_processes import reap_registered_processes
from assess.lib.rate_leases import release_target_rate_lease

_DEFAULT_MAX_AGE_SECONDS = 3600
_ATTENTION_ID_LIMIT = 20
_OUTPUT_ATTENTION_ACTION = (
    "vigil assess command-run list --output-attention --json --limit 1000"
)

# What `run()` reconciles. ``command-runs`` (default) preserves the original
# behavior byte-for-byte; ``jobs`` reconciles stuck assessment_jobs rows (the
# dtach-supervised async-job lifecycle); ``host-processes`` reaps precisely
# registered host children; ``all`` reconciles all three resource classes.
_VALID_SCOPES = ("command-runs", "jobs", "host-processes", "all")

# Statuses that are still in-flight (worth probing for liveness). Anything else
# is terminal and the row should be skipped silently — its outcome is already
# recorded, so finalizing it again would be a no-op at best and a destructive
# overwrite at worst (e.g., flipping a recorded ``completed`` to ``lost``).
_RUNNING_STATUSES = frozenset({"running", "queued"})
_TERMINAL_COMMAND_STATUSES = frozenset(
    {"completed", "failed", "timed_out", "killed", "lost"}
)
_RECOVERED_CLEANUP_STATUSES = frozenset({"not_required", "deferred", "warning"})
_RECOVERED_INTEGRITY_STATUSES = frozenset(
    {"not_applicable", "verified", "warning"}
)
_DEGRADED_RETENTION_STATUSES = frozenset(
    {"integrity_failure", "suppression_deferred", "untrusted"}
)
_RECOVERED_RETENTION_STATUSES = frozenset(
    {
        "artifact",
        "retained",
        "empty",
        "suppressed",
        *_DEGRADED_RETENTION_STATUSES,
    }
)
_JOB_RECONCILABLE_STATUSES = frozenset({"running", "queued", "stop_failed"})

# stdout_path is recorded as ``<engagement-dir>/scans/kali/<run_uuid>.out``.
# We accept any prefix so tests and engagements with custom mount points still
# match — only the trailing ``scans/kali/<run_uuid>.out`` segment is load-
# bearing for run_uuid extraction.
_RUN_UUID_PATTERN = re.compile(r"scans/kali/(?P<run_uuid>[A-Za-z0-9_-]+)\.out$")


@dataclass(frozen=True)
class _PidReadResult:
    pid: int | None
    reason: str


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "sweep-orphans",
        help=(
            "Reconcile rows stuck in status=running/queued past a threshold age "
            "by probing the in-container PID. Default scope is command-runs; "
            "--scope jobs|host-processes|all also reconciles async jobs and "
            "precisely registered host processes."
        ),
    )
    p.add_argument(
        "--max-age-seconds",
        dest="max_age_seconds",
        type=int,
        default=_DEFAULT_MAX_AGE_SECONDS,
        help=(
            "Rows whose started_at is older than (now - max_age_seconds) are "
            f"candidates. Default: {_DEFAULT_MAX_AGE_SECONDS} (1 hour)."
        ),
    )
    # Resolve at parse time (not bound to a frozen module constant) so
    # VIGIL_RUNTIME_CONTAINER is read when the parser is built.
    default_container = default_runtime_container()
    p.add_argument(
        "--container-name",
        dest="container_name",
        default=default_container,
        help=(
            f"Docker container to probe for liveness via `docker exec ... kill -0` "
            f"(default: {default_container})."
        ),
    )
    p.add_argument(
        "--dry-run",
        dest="dry_run",
        action="store_true",
        help="List candidates and the planned action without writing.",
    )
    p.add_argument(
        "--scope",
        dest="scope",
        choices=list(_VALID_SCOPES),
        default="command-runs",
        help=(
            "What to reconcile: command-runs (default), jobs (async dtach rows), "
            "host-processes (owned host PIDs), or all."
        ),
    )
    p.set_defaults(func=run)


def _utcnow_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_started_at(value: str | None) -> _dt.datetime | None:
    if not value:
        return None
    raw = str(value).strip()
    if not raw:
        return None
    # Backend serializes timestamps as either ``YYYY-MM-DDTHH:MM:SSZ`` (the
    # CLI-side `_utcnow_iso` shape) or with a ``+00:00`` offset. Normalize both
    # so ``fromisoformat`` accepts the value across Python 3.11+.
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        parsed = _dt.datetime.fromisoformat(raw)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=_dt.timezone.utc)
    return parsed


def _row_age_seconds(row: dict, now: _dt.datetime) -> float | None:
    """Compute ``now - started_at`` in seconds; return None if started_at is
    missing or unparseable so the caller can skip without raising."""
    started_at = _parse_started_at(row.get("started_at"))
    if started_at is None:
        return None
    return (now - started_at).total_seconds()


def _pending_output_age_seconds(row: dict, now: _dt.datetime) -> float | None:
    """Age pending work only from the backend-owned recovery observation clock."""
    terminal_at = _parse_started_at(row.get("output_recovery_observed_at"))
    return None if terminal_at is None else (now - terminal_at).total_seconds()


def _pending_recovery_proof(
    recovered: object,
    *,
    row_id: int,
    terminal_status: str,
) -> tuple[bool, bool, str]:
    """Validate the backend's exact adoption proof for pending output work."""
    if not isinstance(recovered, dict):
        return False, False, "response was not an object"
    recovered_id = recovered.get("id")
    if type(recovered_id) is not int or recovered_id != row_id:
        return False, False, "response did not identify the same numeric row"
    recovered_status = str(recovered.get("status") or "").strip().lower()
    if (
        terminal_status not in _TERMINAL_COMMAND_STATUSES
        or recovered_status != terminal_status
    ):
        return False, False, "response did not preserve the terminal status"
    if recovered.get("recovered_pending_output") is not True:
        return False, False, "response did not prove pending-output adoption"
    cleanup_status = str(
        recovered.get("output_cleanup_status") or ""
    ).strip().lower()
    integrity_status = str(
        recovered.get("output_integrity_status") or ""
    ).strip().lower()
    if cleanup_status not in _RECOVERED_CLEANUP_STATUSES:
        return False, False, "response carried an invalid cleanup outcome"
    if integrity_status not in _RECOVERED_INTEGRITY_STATUSES:
        return False, False, "response carried an invalid integrity outcome"
    retention_status = str(
        recovered.get("output_retention_status") or ""
    ).strip().lower()
    if retention_status not in _RECOVERED_RETENTION_STATUSES:
        return False, False, "response carried an invalid or pending retention outcome"
    degraded = (
        cleanup_status in {"deferred", "warning"}
        or integrity_status == "warning"
        or retention_status in _DEGRADED_RETENTION_STATUSES
    )
    return True, degraded, ""


def _remember_attention_id(summary: dict, field: str, row_id: int) -> None:
    ids = summary[field]
    if len(ids) < _ATTENTION_ID_LIMIT:
        ids.append(int(row_id))
    else:
        summary[f"{field}_omitted"] += 1


def _job_age_seconds(row: dict, now: _dt.datetime) -> float | None:
    """Age queued jobs from creation; running jobs from their actual start."""
    timestamp = row.get("started_at") or row.get("created_at")
    parsed = _parse_started_at(timestamp)
    return None if parsed is None else (now - parsed).total_seconds()


def _run_uuid_from_stdout_path(stdout_path: str | None) -> str | None:
    """Legacy fallback: parse ``run_uuid`` out of ``stdout_path``.

    The wrapper in ``kali.py:_build_docker_exec`` writes the in-container PID
    to ``/tmp/vigil-pid-<run_uuid>.pid`` and ``stdout_path`` is recorded as
    ``<eng-dir>/scans/kali/<run_uuid>.out``. ``run_uuid`` is now the canonical
    DB column (``assessment_command_runs.run_uuid``), but rows written before
    that plumbing existed only carry it implicitly via ``stdout_path``. This
    helper is kept as a fallback for those legacy rows.

    Returns None when the path is missing, empty, or does not match the
    expected layout (legacy rows, custom paths). Callers treat None as "pid
    file unknown" — equivalent to a missing pid file (the row is finalized
    as lost rather than left running).
    """
    if not stdout_path:
        return None
    match = _RUN_UUID_PATTERN.search(str(stdout_path))
    if not match:
        return None
    return match.group("run_uuid")


def _resolve_run_uuid(row: dict) -> str | None:
    """Pick ``run_uuid`` from the DB column when present, else fall back to
    parsing ``stdout_path``. The DB column is the primary source because it
    is independent of the artifact-dir layout — the regex returns None for
    any row whose stdout_path was reconfigured to a non-default location.

    The fallback exists for rows written before the CLI propagated
    ``run_uuid`` into the POST payload; once those rows finalize naturally
    or are reaped here, the fallback becomes dead code."""
    direct = row.get("run_uuid")
    if isinstance(direct, str) and direct.strip():
        return direct.strip()
    return _run_uuid_from_stdout_path(row.get("stdout_path"))


def _read_container_pid_result(container_name: str, run_uuid: str) -> _PidReadResult:
    """Read the wrapper-recorded PID, preserving the rich diagnostic ``reason``
    the dry-run output keys on. Delegates to the shared
    ``kali_runtime_exec._cat_container_pid_file`` core (which emits the same
    reason tags) and re-wraps its ``(pid, reason)`` tuple into the local
    ``_PidReadResult`` — no behavioural change, just no duplicated
    cat/parse/path logic."""
    pid, reason = _cat_container_pid_file(container_name, _container_pid_file(run_uuid))
    return _PidReadResult(pid, reason)


def _read_container_pid(container_name: str, run_uuid: str) -> int | None:
    return _read_container_pid_result(container_name, run_uuid).pid


def _pid_alive_in_container(container_name: str, pid: int) -> bool | None:
    """Probe the in-container PID with ``kill -0``. Returns True only when the
    docker exec call succeeded with rc=0, False when the in-container kill
    reports the PID is gone, and None when Docker probing itself failed."""
    try:
        result = subprocess.run(
            ["docker", "exec", container_name, "kill", "-0", str(pid)],
            check=False,
            capture_output=True,
            timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    if result.returncode == 0:
        return True
    if result.returncode == 1:
        return False
    return None


def _list_command_run_rows(client: AssessmentClient) -> list[dict]:
    """Page every row needed for running-orphan and pending-terminal recovery."""
    rows: list[dict] = []
    limit = 1000
    offset = 0
    while True:
        params = [("limit", str(limit)), ("offset", str(offset))]
        endpoint = "command-runs?" + urlencode(params, quote_via=quote)
        page = client.get(endpoint)
        if not isinstance(page, list):
            break
        rows.extend(page)
        if len(page) < limit:
            break
        offset += limit
    return rows


def _finalize_lost(client: AssessmentClient, *, run_id: int, now_iso: str) -> dict:
    payload = {
        "status": "lost",
        "ended_at": now_iso,
        "return_code": None,
        "timed_out": False,
        "partial_results": False,
    }
    return client.patch(f"command-runs/{int(run_id)}", payload, accept_409=True)


def _sweep_command_runs(
    client: AssessmentClient,
    args,
    now: _dt.datetime,
    now_iso: str,
    max_age: int,
) -> dict:
    """Reconcile stale in-flight rows and committed terminal pending output."""
    # ``skipped`` is a conflated union — split into two sub-counters so the
    # resume-brief WARN (resume_brief._orphan_attention) fires ONLY on the
    # genuinely-bad bucket. This sweep intentionally pages all historical rows:
    # terminal host rows can carry crash-recoverable pending output work. Benign
    # terminal rows can reach the thousands and must not drown the actionable
    # signal. ``skipped`` remains the grand total for compatibility.
    #   * skipped_already_terminal — BENIGN: the row's outcome is already
    #     recorded, so re-finalizing would be a no-op (or a destructive
    #     overwrite). Not worth surfacing.
    #   * skipped_unverifiable — genuinely stuck: liveness/pid probe failed, or
    #     the finalize PATCH failed. These are the rows an operator must chase.
    summary = {
        "checked": 0,
        "still_running": 0,
        "finalized": 0,
        "skipped": 0,
        "skipped_already_terminal": 0,
        "skipped_unverifiable": 0,
        "recovered_pending": 0,
        "recovered_degraded": 0,
        "recovered_degraded_ids": [],
        "recovered_degraded_ids_omitted": 0,
        "pending_recovery_failed": 0,
        "pending_recovery_failed_ids": [],
        "pending_recovery_failed_ids_omitted": 0,
        "output_attention_action": "",
    }
    rows = _list_command_run_rows(client)

    for row in rows:
        row_id = row.get("id")
        if row_id is None:
            continue
        existing_status = str(row.get("status") or "").strip().lower()
        pending_output = existing_status not in _RUNNING_STATUSES and any(
            str(row.get(field) or "").strip().lower() == "pending"
            for field in ("output_cleanup_status", "output_integrity_status")
        )
        age_seconds = (
            _pending_output_age_seconds(row, now)
            if pending_output
            else _row_age_seconds(row, now)
        )
        if pending_output and age_seconds is None:
            summary["checked"] += 1
            summary["skipped"] += 1
            summary["skipped_unverifiable"] += 1
            summary["pending_recovery_failed"] += 1
            _remember_attention_id(
                summary, "pending_recovery_failed_ids", int(row_id)
            )
            summary["output_attention_action"] = _OUTPUT_ATTENTION_ACTION
            print(
                "warning: pending-output recovery baseline is missing or "
                f"unparseable for id={row_id}; refusing client-time fallback",
                file=sys.stderr,
            )
            continue
        if age_seconds is None or age_seconds < max_age:
            continue
        summary["checked"] += 1

        # Terminal rows are immutable except for backend-owned adoption of a
        # committed pending cleanup/integrity operation. All other terminal
        # rows remain benign skips.
        if existing_status not in _RUNNING_STATUSES:
            if pending_output:
                if args.dry_run:
                    summary["recovered_pending"] += 1
                    print(
                        f"would-recover id={row_id} status={existing_status} "
                        "reason=terminal-output-pending"
                    )
                    continue
                try:
                    recovered = client.patch(
                        f"command-runs/{int(row_id)}",
                        {
                            "status": existing_status,
                            "ended_at": row.get("completed_at") or now_iso,
                        },
                        accept_409=True,
                    )
                except (AssessError, json.JSONDecodeError) as exc:
                    summary["skipped"] += 1
                    summary["skipped_unverifiable"] += 1
                    summary["pending_recovery_failed"] += 1
                    _remember_attention_id(
                        summary, "pending_recovery_failed_ids", int(row_id)
                    )
                    summary["output_attention_action"] = _OUTPUT_ATTENTION_ACTION
                    print(
                        f"warning: pending-output recovery PATCH failed for "
                        f"id={row_id}: {exc}",
                        file=sys.stderr,
                    )
                    continue
                proved, degraded, proof_error = _pending_recovery_proof(
                    recovered,
                    row_id=int(row_id),
                    terminal_status=existing_status,
                )
                if not proved:
                    summary["skipped"] += 1
                    summary["skipped_unverifiable"] += 1
                    summary["pending_recovery_failed"] += 1
                    _remember_attention_id(
                        summary, "pending_recovery_failed_ids", int(row_id)
                    )
                    summary["output_attention_action"] = _OUTPUT_ATTENTION_ACTION
                    print(
                        f"warning: pending-output recovery was not proven for "
                        f"id={row_id}: {proof_error}",
                        file=sys.stderr,
                    )
                    continue
                summary["recovered_pending"] += 1
                if degraded:
                    summary["recovered_degraded"] += 1
                    _remember_attention_id(
                        summary, "recovered_degraded_ids", int(row_id)
                    )
                    summary["output_attention_action"] = _OUTPUT_ATTENTION_ACTION
                print(
                    f"recovered-pending id={row_id} status={existing_status} "
                    f"degraded={'true' if degraded else 'false'}"
                )
                continue
            summary["skipped"] += 1
            summary["skipped_already_terminal"] += 1
            if args.dry_run:
                print(
                    f"would-skip id={row_id} reason=already-terminal "
                    f"status={existing_status or 'unknown'}"
                )
            continue

        run_uuid = _resolve_run_uuid(row)
        pid_read = _PidReadResult(None, "pid-file-unknown")
        if run_uuid:
            pid_read = _read_container_pid_result(args.container_name, run_uuid)
        container_pid = pid_read.pid

        alive: bool | None = False
        if container_pid is not None:
            alive = _pid_alive_in_container(args.container_name, container_pid)

        if alive:
            summary["still_running"] += 1
            print(
                f"still-running id={row_id} age={int(age_seconds)} "
                f"pid={container_pid} run_uuid={run_uuid}"
            )
            continue
        if alive is None or pid_read.reason.startswith("pid-probe-failed"):
            summary["skipped"] += 1
            summary["skipped_unverifiable"] += 1
            print(
                f"skipped id={row_id} age={int(age_seconds)} "
                f"reason={pid_read.reason if container_pid is None else 'liveness-probe-failed'} "
                f"run_uuid={run_uuid or 'unknown'}"
            )
            continue

        # PID file missing OR pid is gone — treat the row as lost.
        if args.dry_run:
            summary["finalized"] += 1
            reason = pid_read.reason if container_pid is None else "pid-dead"
            print(
                f"would-finalize id={row_id} age={int(age_seconds)} "
                f"reason={reason} new_status=lost"
            )
            continue

        try:
            _finalize_lost(client, run_id=int(row_id), now_iso=now_iso)
        except AssessError as exc:
            summary["skipped"] += 1
            summary["skipped_unverifiable"] += 1
            print(
                f"warning: finalize PATCH failed for id={row_id}: {exc}",
                file=sys.stderr,
            )
            continue
        summary["finalized"] += 1
        print(
            f"finalized id={row_id} previous_status=running new_status=lost "
            f"age={int(age_seconds)}"
        )
    return summary


def _list_running_jobs(client: AssessmentClient) -> list[dict]:
    """Fetch in-flight ``assessment_jobs`` rows.

    Unlike command-runs, the backend filters jobs server-side
    (``list_jobs`` honours ``?status=``), so we ask per pre-terminal status.
    Fetch every page so a long-lived engagement cannot hide stale rows beyond
    the backend's 1000-row request cap.
    """
    rows: list[dict] = []
    for state in sorted(_JOB_RECONCILABLE_STATUSES):
        offset = 0
        while True:
            page = client.get(
                f"jobs?status={state}&limit=1000&offset={offset}"
            )
            if not isinstance(page, list):
                break
            rows.extend(page)
            if len(page) < 1000:
                break
            offset += len(page)
    return rows


def _finalize_job(
    client: AssessmentClient,
    *,
    job_id: int,
    status_value: str,
    now_iso: str,
    exit_code: int | None = None,
) -> dict:
    payload: dict = {"status": status_value, "ended_at": now_iso}
    if exit_code is not None:
        payload["exit_code"] = int(exit_code)
    return client.patch(f"jobs/{int(job_id)}", payload, accept_409=True)


def _release_swept_job_rate_lease(client: AssessmentClient, row: dict) -> None:
    metadata = row.get("audit_metadata")
    if not isinstance(metadata, dict):
        return
    token = str(metadata.get("rate_lease_token") or "")
    if not token:
        return
    try:
        release_target_rate_lease(token, client=client)
    except AssessError:
        return


def _sweep_jobs(
    client: AssessmentClient,
    args,
    now: _dt.datetime,
    now_iso: str,
    max_age: int,
) -> dict:
    """Reconcile stuck ``assessment_jobs`` rows.

    The dtach worker is detached (``dtach -n``) and publishes its real exit code
    to a host-readable marker on completion. This sweep converges any row the
    in-band ``job_status``/``job_stop`` finalizers missed (agent killed before
    polling): marker present -> completed/failed; PID gone with no marker ->
    lost; PID alive -> left running; docker unreachable -> skipped.
    """
    # Same benign-vs-genuine split as _sweep_command_runs so resume-brief warns
    # only on the unverifiable bucket (I-05). The jobs backend DOES honour
    # ?status= (_list_running_jobs), so already-terminal rows are rare here —
    # but the split keeps the two sweeps' summary shape and semantics identical.
    summary = {
        "checked": 0,
        "still_running": 0,
        "finalized": 0,
        "skipped": 0,
        "skipped_already_terminal": 0,
        "skipped_unverifiable": 0,
    }
    rows = _list_running_jobs(client)

    for row in rows:
        row_id = row.get("id")
        if row_id is None:
            continue
        age_seconds = _job_age_seconds(row, now)
        if age_seconds is None or age_seconds < max_age:
            continue
        summary["checked"] += 1

        existing_status = str(row.get("status") or "").strip().lower()
        if existing_status not in _JOB_RECONCILABLE_STATUSES:
            summary["skipped"] += 1
            summary["skipped_already_terminal"] += 1
            if args.dry_run:
                print(
                    f"would-skip job id={row_id} reason=already-terminal "
                    f"status={existing_status or 'unknown'}"
                )
            continue

        # Marker first: read the host-side exit marker with a plain filesystem
        # read (it lives on the /engagements bind mount) — never a docker-exec
        # poll loop (I-012). A present marker is authoritative over PID probing.
        rc = _read_job_exit_marker(row)
        if rc is not None:
            final_status = "completed" if rc == 0 else "failed"
            if args.dry_run:
                summary["finalized"] += 1
                print(
                    f"would-finalize job id={row_id} age={int(age_seconds)} "
                    f"reason=exit-marker exit_code={rc} new_status={final_status}"
                )
                continue
            try:
                _finalize_job(
                    client,
                    job_id=int(row_id),
                    status_value=final_status,
                    now_iso=now_iso,
                    exit_code=rc,
                )
                finalize_parent_command_run(
                    client,
                    row,
                    status_value=final_status,
                    return_code=rc,
                    ended_at_iso=now_iso,
                )
                _release_swept_job_rate_lease(client, row)
            except AssessError as exc:
                summary["skipped"] += 1
                summary["skipped_unverifiable"] += 1
                print(
                    f"warning: finalize PATCH failed for job id={row_id}: {exc}",
                    file=sys.stderr,
                )
                continue
            summary["finalized"] += 1
            print(
                f"finalized job id={row_id} previous_status={existing_status} "
                f"new_status={final_status} exit_code={rc} age={int(age_seconds)}"
            )
            continue

        # No marker -> probe the in-container PID. The job pid file lives at
        # /tmp/vigil-jobs/<uuid>.pid; the uuid is the dtach socket stem.
        socket_path = row.get("dtach_socket_path") or ""
        container_pid: int | None = None
        if socket_path:
            uuid_stem = Path(socket_path).stem
            container_pid = _cat_container_pid_file(
                args.container_name, _job_pid_file_in_container(uuid_stem)
            )[0]

        alive: bool | None = False
        if container_pid is not None:
            alive = _pid_alive_in_container(args.container_name, container_pid)

        if alive:
            summary["still_running"] += 1
            print(
                f"still-running job id={row_id} age={int(age_seconds)} "
                f"pid={container_pid}"
            )
            continue
        if alive is None:
            summary["skipped"] += 1
            summary["skipped_unverifiable"] += 1
            print(
                f"skipped job id={row_id} age={int(age_seconds)} "
                f"reason=liveness-probe-failed"
            )
            continue

        # PID gone (or pid file unknown) AND no marker -> the worker died
        # without publishing an exit code. Reconcile to lost (unrecoverable).
        reason = "pid-dead" if container_pid is not None else "pid-file-unknown"
        if args.dry_run:
            summary["finalized"] += 1
            print(
                f"would-finalize job id={row_id} age={int(age_seconds)} "
                f"reason={reason} new_status=lost"
            )
            continue
        try:
            _finalize_job(client, job_id=int(row_id), status_value="lost", now_iso=now_iso)
            finalize_parent_command_run(
                client,
                row,
                status_value="lost",
                return_code=None,
                ended_at_iso=now_iso,
            )
            _release_swept_job_rate_lease(client, row)
        except AssessError as exc:
            summary["skipped"] += 1
            summary["skipped_unverifiable"] += 1
            print(
                f"warning: finalize PATCH failed for job id={row_id}: {exc}",
                file=sys.stderr,
            )
            continue
        summary["finalized"] += 1
        print(
            f"finalized job id={row_id} previous_status={existing_status} "
            f"new_status=lost reason={reason} age={int(age_seconds)}"
        )
    return summary


def run(args) -> None:
    # getattr keeps pre-scope callers (and existing tests that build args
    # without a scope attr) on the default command-runs path.
    scope = getattr(args, "scope", "command-runs")
    if scope not in _VALID_SCOPES:
        raise AssessError(f"--scope must be one of {', '.join(_VALID_SCOPES)}")
    cfg = load_config(args.engagement_dir)
    max_age = int(args.max_age_seconds)
    if max_age < 0:
        raise AssessError("--max-age-seconds must be >= 0")

    cr_summary: dict | None = None
    job_summary: dict | None = None
    host_summary: dict | None = None
    if scope in ("command-runs", "jobs", "all"):
        with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
            now = _dt.datetime.now(_dt.timezone.utc)
            now_iso = _utcnow_iso()
            if scope in ("command-runs", "all"):
                cr_summary = _sweep_command_runs(client, args, now, now_iso, max_age)
            if scope in ("jobs", "all"):
                job_summary = _sweep_jobs(client, args, now, now_iso, max_age)
    if scope in ("host-processes", "all"):
        host_summary = reap_registered_processes(
            cfg.engagement_dir,
            max_age_seconds=max_age,
            dry_run=bool(args.dry_run),
        )

    dry = bool(args.dry_run)
    if scope == "command-runs":
        # Unchanged output shape for the default path.
        print(json.dumps({"summary": cr_summary, "dry_run": dry}, ensure_ascii=False))
    elif scope == "jobs":
        print(json.dumps({"summary": job_summary, "dry_run": dry, "scope": "jobs"}, ensure_ascii=False))
    elif scope == "host-processes":
        print(
            json.dumps(
                {"summary": host_summary, "dry_run": dry, "scope": "host-processes"},
                ensure_ascii=False,
            )
        )
    else:
        print(
            json.dumps(
                {
                    "summary": cr_summary,
                    "jobs_summary": job_summary,
                    "host_processes_summary": host_summary,
                    "dry_run": dry,
                    "scope": "all",
                },
                ensure_ascii=False,
            )
        )
