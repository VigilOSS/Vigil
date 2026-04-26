"""aith assess kali job — async-job lifecycle commands.

Subcommands:
- start  — write `assessment_jobs` queued row, spawn dtach session, mark running.
- status — fetch a job row by id.
- tail   — tail the spilled stdout file.
- stop   — send Ctrl-C through dtach and PATCH status=killed.
- list   — list jobs, optionally filtered by status / parent_command_run_id.
"""
from __future__ import annotations

import json
import sys

from assess.lib.client import AssessError
from assess.lib.kali import (
    ALLOWED_PHASES,
    PROBE_KIND_ENUM,
    TECHNIQUE_ENUM,
)
from assess.lib.kali_jobs import job_list, job_status, job_stop, job_tail, start_job


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "job",
        help="Async-job lifecycle (start | status | tail | stop | list).",
    )
    job_sub = p.add_subparsers(dest="job_action")
    job_sub.required = False

    start = job_sub.add_parser("start", help="Spawn a dtach-supervised job.")
    start.add_argument("--technique", required=True, help=", ".join(TECHNIQUE_ENUM) if TECHNIQUE_ENUM else "")
    start.add_argument("--intent", required=True)
    start.add_argument(
        "--probe-kind",
        dest="probe_kind",
        required=True,
        choices=list(PROBE_KIND_ENUM) if PROBE_KIND_ENUM else None,
    )
    start.add_argument("--phase", required=True, choices=list(ALLOWED_PHASES))
    start.add_argument("--destructive", action="store_true")
    start.add_argument("--agent-name", dest="agent_name", required=False, default=None)
    start.add_argument("--container-name", dest="container_name", default="security-research")
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

    stop_p = job_sub.add_parser("stop", help="Send Ctrl-C and PATCH status=killed.")
    stop_p.add_argument("job_id", type=int)
    stop_p.add_argument("--container-name", dest="container_name", default="security-research")
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
    print("usage: aith assess kali job {start|status|tail|stop|list} ...", file=sys.stderr)
    raise AssessError("missing kali job action")


def _run_start(args) -> None:
    audit_meta = {
        "technique": args.technique,
        "intent": args.intent,
        "probe_kind": args.probe_kind,
        "phase": args.phase,
        "destructive": bool(args.destructive),
        "agent_name": args.agent_name,
    }
    record = start_job(
        list(args.command),
        audit_meta=audit_meta,
        container_name=args.container_name,
        parent_command_run_id=args.parent_command_run_id,
    )
    print(json.dumps(record, indent=2, ensure_ascii=False))


def _run_status(args) -> None:
    print(json.dumps(job_status(args.job_id), indent=2, ensure_ascii=False))


def _run_tail(args) -> None:
    job_tail(args.job_id, follow=bool(args.follow))


def _run_stop(args) -> None:
    print(json.dumps(job_stop(args.job_id, container_name=args.container_name), indent=2, ensure_ascii=False))


def _run_list(args) -> None:
    rows = job_list(status_value=args.status, parent_run_id=args.parent_run_id)
    print(json.dumps(rows, indent=2, ensure_ascii=False))
