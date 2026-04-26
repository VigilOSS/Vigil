"""aith assess kali nuclei — typed wrapper around nuclei inside the runtime."""
from __future__ import annotations

import sys

from assess.lib.client import AssessError
from assess.lib.kali import (
    add_passthrough_args_flag,
    add_required_kali_flags,
    emit_result,
    extend_cmd_with_extra_args,
    kali_args_to_kwargs,
    kali_exec,
)


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "nuclei",
        help="Run nuclei inside the runtime container with audit recording.",
    )
    add_required_kali_flags(p)
    add_passthrough_args_flag(p)
    p.add_argument("-u", dest="target_url", default="", help="Single target URL.")
    p.add_argument("-l", dest="target_list", default="", help="File of newline-separated targets.")
    p.add_argument("-t", dest="templates", default="", help="Comma-separated template list.")
    p.add_argument("-tags", dest="tags", default="", help="Filter by tag list (comma-separated).")
    p.add_argument("-as", dest="automatic_scan", action="store_true", help="-as automatic scan.")
    p.add_argument("-severity", dest="severity", default="", help="Comma-separated severity list.")
    p.add_argument("-rate-limit", dest="rate_limit", default="", help="Requests per second.")
    p.add_argument("-c", dest="concurrency", default="", help="Worker concurrency.")
    p.add_argument("-bs", dest="bulk_size", default="", help="Bulk batch size.")
    p.add_argument("-stream", dest="stream", action="store_true", help="-stream output mode.")
    p.add_argument("-jsonl", dest="jsonl", action="store_true", help="-jsonl output.")
    p.add_argument("-o", dest="output", default="", help="-o output file (engagement-relative).")
    p.set_defaults(func=run)


def run(args) -> None:
    if not args.target_url and not args.target_list:
        print("nuclei: pass -u <url> or -l <list>", file=sys.stderr)
        raise AssessError("missing -u or -l")
    cmd: list[str] = ["nuclei"]
    if args.target_url:
        cmd.extend(["-u", args.target_url])
    if args.target_list:
        cmd.extend(["-l", args.target_list])
    if args.templates:
        cmd.extend(["-t", args.templates])
    if args.tags:
        cmd.extend(["-tags", args.tags])
    if args.automatic_scan:
        cmd.append("-as")
    if args.severity:
        cmd.extend(["-severity", args.severity])
    if args.rate_limit:
        cmd.extend(["-rate-limit", str(args.rate_limit)])
    if args.concurrency:
        cmd.extend(["-c", str(args.concurrency)])
    if args.bulk_size:
        cmd.extend(["-bs", str(args.bulk_size)])
    if args.stream:
        cmd.append("-stream")
    if args.jsonl:
        cmd.append("-jsonl")
    if args.output:
        cmd.extend(["-o", args.output])
    extend_cmd_with_extra_args(cmd, args)

    result = kali_exec(cmd, tool_name="nuclei", **kali_args_to_kwargs(args))
    emit_result(result)
