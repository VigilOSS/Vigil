"""aith assess kali sweep-orphans — reconcile stuck `running` command-run rows.

When a `kali_exec` finalize PATCH fails (network blip, backend restart, host
crash mid-run), the pre-exec audit row stays at ``status=running`` forever.
This command sweeps rows older than ``--max-age-seconds`` and either leaves
them alone (the in-container PID is still alive) or finalizes them to
``status=lost`` (the PID is gone or the wrapper pid file is missing).

The wrapper shell in ``kali.py:_build_docker_exec`` writes the in-container
PID to ``/tmp/aith-pid-<run_uuid>.pid``. The ``run_uuid`` is not stored as a
column on the row, so we parse it out of ``stdout_path`` (which is shaped
``scans/kali/<run_uuid>.out``). See ``_run_uuid_from_stdout_path``.
"""
from __future__ import annotations

import datetime as _dt
import json
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import quote, urlencode

from assess.lib.client import AssessError, AssessmentClient
from assess.lib.config import load_config


_DEFAULT_CONTAINER_NAME = "security-research"
_DEFAULT_MAX_AGE_SECONDS = 3600

# stdout_path is recorded as ``<engagement-dir>/scans/kali/<run_uuid>.out``.
# We accept any prefix so tests and engagements with custom mount points still
# match — only the trailing ``scans/kali/<run_uuid>.out`` segment is load-
# bearing for run_uuid extraction.
_RUN_UUID_PATTERN = re.compile(r"scans/kali/(?P<run_uuid>[A-Za-z0-9_-]+)\.out$")


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
    """Extract the engagement-wide ``run_uuid`` from the recorded stdout path.

    The wrapper in ``kali.py:_build_docker_exec`` writes the in-container PID
    to ``/tmp/aith-pid-<run_uuid>.pid`` and ``stdout_path`` is recorded as
    ``<eng-dir>/scans/kali/<run_uuid>.out``. We do not store ``run_uuid`` as
    a column on the row, so this regex parse against the path is the only way
    to recover the identifier the pid file was keyed under.

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


def _container_pid_file(run_uuid: str) -> str:
    """Mirror of ``kali.py:_container_pid_file`` — the wrapper writes the
    in-container PID here."""
    return f"/tmp/aith-pid-{run_uuid}.pid"


def _read_container_pid(container_name: str, run_uuid: str) -> int | None:
    pid_file = _container_pid_file(run_uuid)
    try:
        result = subprocess.run(
            ["docker", "exec", container_name, "cat", pid_file],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    raw = (result.stdout or "").strip().splitlines()
    if not raw:
        return None
    try:
        return int(raw[0])
    except ValueError:
        return None


def _pid_alive_in_container(container_name: str, pid: int) -> bool:
    """Probe the in-container PID with ``kill -0``. Returns True only when the
    docker exec call succeeded with rc=0 — any failure mode (container gone,
    docker not reachable, PID gone) is treated as "not alive" so a flaky probe
    cannot keep an orphan row pinned at ``running`` forever."""
    try:
        result = subprocess.run(
            ["docker", "exec", container_name, "kill", "-0", str(pid)],
            check=False,
            capture_output=True,
            timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def _list_running_rows(client: AssessmentClient) -> list[dict]:
    """Page through ``GET command-runs?status=running`` and return every row."""
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

    client = AssessmentClient(cfg.base_url, cfg.engagement_key)
    summary = {"checked": 0, "still_running": 0, "finalized": 0, "skipped": 0}
    try:
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

            run_uuid = _run_uuid_from_stdout_path(row.get("stdout_path"))
            container_pid: int | None = None
            if run_uuid:
                container_pid = _read_container_pid(args.container_name, run_uuid)

            alive = False
            if container_pid is not None:
                alive = _pid_alive_in_container(args.container_name, container_pid)

            if alive:
                summary["still_running"] += 1
                print(
                    f"still-running id={row_id} age={int(age_seconds)} "
                    f"pid={container_pid} run_uuid={run_uuid}"
                )
                continue

            # PID file missing OR pid is gone — treat the row as lost.
            if args.dry_run:
                summary["skipped"] += 1
                reason = "pid-file-missing" if run_uuid is None or container_pid is None else "pid-dead"
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
    finally:
        client.close()

    print(json.dumps({"summary": summary, "dry_run": bool(args.dry_run)}, ensure_ascii=False))
