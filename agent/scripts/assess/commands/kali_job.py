"""vigil assess kali job — async-job lifecycle commands.

Subcommands:
- start  — write `assessment_jobs` queued row, spawn dtach session, mark running.
- status — fetch a job row by id.
- tail   — tail the spilled stdout file.
- stop   — terminate the recorded PID and PATCH killed/stop_failed/lost.
- list   — list jobs, optionally filtered by status / parent_command_run_id.
"""
from __future__ import annotations

import json
import sys

from pathlib import Path

from assess.lib.client import AssessError, default_runtime_container
from assess.lib.config import load_config
from assess.lib.audit_enums import normalize_technique
from assess.lib.kali import (
    ALLOWED_PHASES,
    PROBE_KIND_ENUM,
    TECHNIQUE_ENUM,
    ScopedErrorParser,
    _INTENT_MAX_LEN,
    _resolve_agent_name,
)
from assess.lib.kali_audit import _enum_reject_message
from assess.lib.kali_jobs import job_list, job_status, job_stop, job_tail, start_job


_DEFAULT_JOB_TIMEOUT_SECONDS = 24 * 60 * 60  # 24h hard cap parity with `kali exec` budgets


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "job",
        help="Async-job lifecycle (start | status | tail | stop | list).",
    )
    # parser_class routes a parse-time --probe-kind/--phase enum miss through the
    # same scoped did-you-mean formatter the typed kali verbs use, instead of the
    # stock top-level usage dump.
    job_sub = p.add_subparsers(dest="job_action", parser_class=ScopedErrorParser)
    job_sub.required = False

    start = job_sub.add_parser("start", help="Spawn a dtach-supervised job.")
    # --technique carries NO argparse choices= so it defers to the same
    # technique enum validation the typed verbs run (see _run_start), giving an
    # identical scoped did-you-mean error everywhere. (probe-kind/phase keep
    # choices, now re-rendered by ScopedErrorParser.)
    start.add_argument(
        "--technique",
        required=True,
        help=(
            "Vulnerability-class technique tag (e.g. RECON, SSRF, SQLI). "
            f"Allowed: {', '.join(TECHNIQUE_ENUM) if TECHNIQUE_ENUM else 'see audit_enums.py'}"
        ),
    )
    start.add_argument("--intent", required=True)
    start.add_argument(
        "--probe-kind",
        dest="probe_kind",
        required=True,
        choices=list(PROBE_KIND_ENUM) if PROBE_KIND_ENUM else None,
    )
    start.add_argument("--phase", required=True, choices=list(ALLOWED_PHASES))
    start.add_argument(
        "--target-host",
        dest="target_host",
        default=None,
        help="Primary target host the job is acting against (audit metadata).",
    )
    start.add_argument(
        "--timeout",
        dest="timeout",
        type=int,
        default=None,
        help=(
            "Wall-clock budget hint in seconds (audit metadata). "
            f"Defaults to {_DEFAULT_JOB_TIMEOUT_SECONDS}s with a stderr warn when omitted."
        ),
    )
    start.add_argument("--destructive", action="store_true")
    start.add_argument("--agent-name", dest="agent_name", required=False, default=None)
    start.add_argument("--container-name", dest="container_name", default=default_runtime_container())
    start.add_argument(
        "--parent-command-run-id",
        dest="parent_command_run_id",
        type=int,
        default=None,
    )
    start.add_argument(
        "command",
        nargs="+",
        help="Command and arguments. Use `--` to separate.",
    )
    start.set_defaults(func=_run_start)

    status_p = job_sub.add_parser("status", help="Fetch a job row.")
    status_p.add_argument("job_id", type=int)
    status_p.set_defaults(func=_run_status)

    tail_p = job_sub.add_parser("tail", help="Tail the job stdout file.")
    tail_p.add_argument("job_id", type=int)
    tail_p.add_argument("--follow", action="store_true")
    tail_p.set_defaults(func=_run_tail)

    stop_p = job_sub.add_parser(
        "stop",
        help="Terminate the recorded PID and PATCH killed/stop_failed/lost.",
    )
    stop_p.add_argument("job_id", type=int)
    stop_p.add_argument("--container-name", dest="container_name", default=default_runtime_container())
    stop_p.set_defaults(func=_run_stop)

    list_p = job_sub.add_parser("list", help="List jobs.")
    list_p.add_argument("--status", default=None)
    list_p.add_argument(
        "--parent-run-id",
        dest="parent_run_id",
        type=int,
        default=None,
    )
    list_p.set_defaults(func=_run_list)

    p.set_defaults(func=_print_help_when_missing)


def _print_help_when_missing(args) -> None:
    print("usage: vigil assess kali job {start|status|tail|stop|list} ...", file=sys.stderr)
    raise AssessError("missing kali job action")


def _run_start(args) -> None:
    # --technique has no argparse choices= (CLI-1 reconciliation), so validate it
    # here through the exact same enum check + scoped formatter the typed verbs'
    # _validate_inputs uses, so `kali job start --technique FINGERPRINT` errors
    # identically to `kali exec --technique FINGERPRINT`.
    technique = args.technique or ""
    if not technique:
        raise AssessError("--technique is required")
    if TECHNIQUE_ENUM and normalize_technique(technique) not in TECHNIQUE_ENUM:
        raise AssessError(_enum_reject_message(
            "--technique", technique, TECHNIQUE_ENUM,
            hint="--technique is the vuln-class tag for the AUDIT row, not the probe step; "
                 "the per-step kind is --probe-kind. For initial mapping use RECON.",
        ))
    intent = args.intent or ""
    if len(intent) > _INTENT_MAX_LEN:
        raise AssessError(f"--intent exceeds {_INTENT_MAX_LEN} characters")
    timeout_value = args.timeout
    if timeout_value is None:
        print(
            "warning: --timeout not provided to `kali job start`; defaulting to "
            f"{_DEFAULT_JOB_TIMEOUT_SECONDS}s (24h). Pass --timeout SECONDS for a tighter budget.",
            file=sys.stderr,
        )
        timeout_value = _DEFAULT_JOB_TIMEOUT_SECONDS
    elif timeout_value <= 0:
        raise AssessError("--timeout must be > 0")
    resolved_agent = _resolve_agent_name(args.agent_name)
    audit_meta = {
        "technique": args.technique,
        "intent": intent,
        "probe_kind": args.probe_kind,
        "phase": args.phase,
        "destructive": bool(args.destructive),
        "agent_name": resolved_agent or None,
        "target_host": args.target_host,
        "timeout_seconds_requested": int(timeout_value),
    }
    cfg = _load_job_config(args)
    explicit_dir = getattr(args, "engagement_dir", None)
    engagement_dir = Path(explicit_dir).expanduser().resolve() if explicit_dir else None
    record = start_job(
        list(args.command),
        audit_meta=audit_meta,
        container_name=args.container_name,
        parent_command_run_id=args.parent_command_run_id,
        engagement_dir=engagement_dir,
        config=cfg,
    )
    print(json.dumps(record, indent=2, ensure_ascii=False))


def _load_job_config(args):
    explicit_dir = getattr(args, "engagement_dir", None)
    return load_config(str(explicit_dir) if explicit_dir else None)


def _run_status(args) -> None:
    cfg = _load_job_config(args)
    print(json.dumps(job_status(args.job_id, config=cfg), indent=2, ensure_ascii=False))


def _run_tail(args) -> None:
    cfg = _load_job_config(args)
    job_tail(args.job_id, follow=bool(args.follow), config=cfg)


def _run_stop(args) -> None:
    cfg = _load_job_config(args)
    print(json.dumps(job_stop(args.job_id, container_name=args.container_name, config=cfg), indent=2, ensure_ascii=False))


def _run_list(args) -> None:
    cfg = _load_job_config(args)
    rows = job_list(status_value=args.status, parent_run_id=args.parent_run_id, config=cfg)
    print(json.dumps(rows, indent=2, ensure_ascii=False))
