"""vigil assess kali subfinder — typed wrapper around subfinder inside the runtime."""
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
        "subfinder",
        help="Run subfinder inside the runtime container with audit recording.",
    )
    add_required_kali_flags(p)
    add_passthrough_args_flag(p)
    p.add_argument("-d", dest="domain", default="", help="Single domain.")
    p.add_argument("-dL", dest="domain_list", default="", help="File of newline-separated domains.")
    p.add_argument("-all", dest="all_sources", action="store_true", help="-all sources (slow but exhaustive).")
    p.add_argument("-recursive", dest="recursive", action="store_true", help="-recursive resolution.")
    p.add_argument("-t", dest="threads", default="", help="Worker threads.")
    p.add_argument("-o", dest="output", default="", help="-o output file.")
    p.add_argument("-silent", dest="silent", action="store_true", help="-silent (suppress info).")
    p.set_defaults(func=run)


def run(args) -> None:
    if not args.domain and not args.domain_list:
        print("subfinder: pass -d <domain> or -dL <list>", file=sys.stderr)
        raise AssessError("missing -d or -dL")
    cmd: list[str] = ["subfinder"]
    if args.domain:
        cmd.extend(["-d", args.domain])
    if args.domain_list:
        cmd.extend(["-dL", args.domain_list])
    if args.all_sources:
        cmd.append("-all")
    if args.recursive:
        cmd.append("-recursive")
    if args.threads:
        cmd.extend(["-t", str(args.threads)])
    if args.output:
        cmd.extend(["-o", args.output])
    if args.silent:
        cmd.append("-silent")
    extend_cmd_with_extra_args(cmd, args)

    result = kali_exec(cmd, tool_name="subfinder", **kali_args_to_kwargs(args))
    emit_result(result)
