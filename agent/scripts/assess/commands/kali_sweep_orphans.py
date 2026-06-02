"""vigil assess kali sweep-orphans — reconcile stuck `running` command-run rows.

When a `kali_exec` finalize PATCH fails (network blip, backend restart, host
crash mid-run), the pre-exec audit row stays at ``status=running`` forever.
This command sweeps rows older than ``--max-age-seconds`` and either leaves
them alone (the in-container PID is still alive), finalizes them to
``status=lost`` (the PID is gone or the wrapper pid file is missing), or skips
them when Docker probing itself fails and liveness is unknown.

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
from urllib.parse import quote, urlencode

from assess.lib.client import AssessError, AssessmentClient, default_runtime_container
from assess.lib.config import load_config


_DEFAULT_CONTAINER_NAME = default_runtime_container()
_DEFAULT_MAX_AGE_SECONDS = 3600

# Statuses that are still in-flight (worth probing for liveness). Anything else
# is terminal and the row should be skipped silently — its outcome is already
# recorded, so finalizing it again would be a no-op at best and a destructive
# overwrite at worst (e.g., flipping a recorded ``completed`` to ``lost``).
_RUNNING_STATUSES = frozenset({"running", "queued"})

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
            "Find assessment_command_runs rows stuck in status=running past a "
            "threshold age and reconcile them by probing the in-container PID."
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
    p.add_argument(
        "--container-name",
        dest="container_name",
        default=_DEFAULT_CONTAINER_NAME,
        help=(
            f"Docker container to probe for liveness via `docker exec ... kill -0` "
            f"(default: {_DEFAULT_CONTAINER_NAME})."
        ),
    )
    p.add_argument(
        "--dry-run",
        dest="dry_run",
        action="store_true",
        help="List candidates and the planned action without writing.",
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


def _container_pid_file(run_uuid: str) -> str:
    """Mirror of ``kali.py:_container_pid_file`` — the wrapper writes the
    in-container PID here."""
    return f"/tmp/vigil-pid-{run_uuid}.pid"


def _read_container_pid_result(container_name: str, run_uuid: str) -> _PidReadResult:
    pid_file = _container_pid_file(run_uuid)
    try:
        result = subprocess.run(
            ["docker", "exec", container_name, "cat", pid_file],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return _PidReadResult(None, f"pid-probe-failed:{exc.__class__.__name__}")
    if result.returncode != 0:
        stderr = (result.stderr or "").lower()
        if "no such file" in stderr or "cannot open" in stderr:
            return _PidReadResult(None, "pid-file-missing")
        return _PidReadResult(None, "pid-probe-failed")
    raw = (result.stdout or "").strip().splitlines()
    if not raw:
        return _PidReadResult(None, "pid-file-empty")
    try:
        return _PidReadResult(int(raw[0]), "pid-read")
    except ValueError:
        return _PidReadResult(None, "pid-file-invalid")


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


def _list_running_rows(client: AssessmentClient) -> list[dict]:
    """Page through ``GET command-runs?status=running`` and return every row.

    The CLI sends ``status=running`` server-side as a forward-compatible hint —
    the backend currently ignores it (``list_command_runs`` does not yet filter
    on status), so we apply the same filter client-side as a fallback. Without
    the client-side filter every terminal row is returned and the per-row
    decision logic prints misleading ``would-finalize`` lines for rows it will
    actually skip.
    """
    rows: list[dict] = []
    limit = 1000
    offset = 0
    while True:
        params = [("status", "running"), ("limit", str(limit)), ("offset", str(offset))]
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


def run(args) -> None:
    cfg = load_config(args.engagement_dir)
    max_age = int(args.max_age_seconds)
    if max_age < 0:
        raise AssessError("--max-age-seconds must be >= 0")

    summary = {"checked": 0, "still_running": 0, "finalized": 0, "skipped": 0}
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        rows = _list_running_rows(client)
        now = _dt.datetime.now(_dt.timezone.utc)
        now_iso = _utcnow_iso()

        for row in rows:
            row_id = row.get("id")
            if row_id is None:
                continue
            age_seconds = _row_age_seconds(row, now)
            if age_seconds is None or age_seconds < max_age:
                continue
            summary["checked"] += 1

            # Client-side status filter as a fallback for the unfiltered GET
            # response (see ``_list_running_rows``). Rows already in a terminal
            # state are not candidates for finalize; print a ``would-skip``
            # line so the dry-run output never claims it would finalize a row
            # whose outcome is already recorded.
            existing_status = str(row.get("status") or "").strip().lower()
            if existing_status not in _RUNNING_STATUSES:
                summary["skipped"] += 1
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

    print(json.dumps({"summary": summary, "dry_run": bool(args.dry_run)}, ensure_ascii=False))
