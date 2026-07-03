"""vigil assess kali wafw00f — typed wrapper around wafw00f inside the runtime."""
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
        "wafw00f",
        help="Run wafw00f inside the runtime container with audit recording.",
    )
    add_required_kali_flags(p)
    add_passthrough_args_flag(p)
    p.add_argument("target", nargs="?", default="", help="Target URL (positional). Mutually exclusive with -i.")
    p.add_argument("-i", dest="input_file", default="", help="File of newline-separated URLs.")
    p.add_argument("-a", dest="test_all", action="store_true", help="-a test against every WAF signature.")
    p.add_argument("-p", "--proxy", dest="proxy", default="", help="Proxy <host:port> to route the probe through.")
    p.add_argument("-r", "--noredirect", dest="noredirect", action="store_true",
                   help="Do not follow redirects (test the edge response directly).")
    p.add_argument("-o", dest="output_csv", default="", help="-o CSV output file (engagement-relative).")
    p.set_defaults(func=run)


def run(args) -> None:
    if not args.target and not args.input_file:
        print("wafw00f: pass <target> or -i <list>", file=sys.stderr)
        raise AssessError("missing <target> or -i")
    cmd: list[str] = ["wafw00f"]
    if args.test_all:
        cmd.append("-a")
    if args.proxy:
        cmd.extend(["-p", args.proxy])
    if args.noredirect:
        cmd.append("-r")
    if args.input_file:
        cmd.extend(["-i", args.input_file])
    if args.output_csv:
        cmd.extend(["-o", args.output_csv])
    extend_cmd_with_extra_args(cmd, args)
    if args.target:
        cmd.append(args.target)

    result = kali_exec(cmd, tool_name="wafw00f", **kali_args_to_kwargs(args))
    emit_result(result)
