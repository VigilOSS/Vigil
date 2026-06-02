"""vigil assess kali httpx — typed wrapper around httpx inside the runtime."""
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
        "httpx",
        help="Run httpx inside the runtime container with audit recording.",
    )
    add_required_kali_flags(p)
    add_passthrough_args_flag(p)
    p.add_argument("-u", dest="target_url", default="", help="Single target URL.")
    p.add_argument("-l", dest="target_list", default="", help="File of newline-separated targets.")
    p.add_argument("-status-code", dest="status_code", action="store_true", help="-status-code probe.")
    p.add_argument("-title", dest="title", action="store_true", help="-title extraction.")
    p.add_argument("-tech-detect", dest="tech_detect", action="store_true", help="-tech-detect via wappalyzer.")
    p.add_argument("-tls-grab", dest="tls_grab", action="store_true", help="-tls-grab certificate metadata.")
    p.add_argument("-json", dest="output_json", action="store_true", help="-json output.")
    p.add_argument("-o", dest="output", default="", help="-o output file (engagement-relative).")
    p.set_defaults(func=run)


def run(args) -> None:
    if not args.target_url and not args.target_list:
        print("httpx: pass -u <url> or -l <list>", file=sys.stderr)
        raise AssessError("missing -u or -l")
    cmd: list[str] = ["httpx"]
    if args.target_url:
        cmd.extend(["-u", args.target_url])
    if args.target_list:
        cmd.extend(["-l", args.target_list])
    if args.status_code:
        cmd.append("-status-code")
    if args.title:
        cmd.append("-title")
    if args.tech_detect:
        cmd.append("-tech-detect")
    if args.tls_grab:
        cmd.append("-tls-grab")
    if args.output_json:
        cmd.append("-json")
    if args.output:
        cmd.extend(["-o", args.output])
    extend_cmd_with_extra_args(cmd, args)

    result = kali_exec(cmd, tool_name="httpx", **kali_args_to_kwargs(args))
    emit_result(result)
