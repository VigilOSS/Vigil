"""vigil assess kali whatweb — typed wrapper around whatweb inside the runtime."""
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
        "whatweb",
        help="Run whatweb inside the runtime container with audit recording.",
    )
    add_required_kali_flags(p)
    add_passthrough_args_flag(p)
    p.add_argument("target", nargs="?", default="", help="Target URL or hostname (positional).")
    p.add_argument("-i", dest="input_file", default="", help="-i input file of targets.")
    p.add_argument("-a", dest="aggression", default="", help="-a aggression (1=stealth, 4=heavy).")
    p.add_argument("--user-agent", "-U", dest="user_agent", default="",
                   help="Custom User-Agent (browser-like UA helps past scanner-UA edge blocks).")
    p.add_argument("--header", "-H", dest="headers", action="append", default=None,
                   help="Custom request header (repeatable), e.g. --header 'Cookie: s=...'.")
    p.add_argument("--proxy", dest="proxy", default="", help="Proxy <host:port> to route requests through.")
    p.add_argument("--log-json", dest="log_json", default="", help="--log-json output file.")
    p.set_defaults(func=run)


def run(args) -> None:
    if not args.target and not args.input_file:
        print("whatweb: pass <target> or -i <file>", file=sys.stderr)
        raise AssessError("missing <target> or -i")
    cmd: list[str] = ["whatweb"]
    if args.aggression:
        cmd.extend(["-a", str(args.aggression)])
    if args.user_agent:
        cmd.extend(["--user-agent", args.user_agent])
    for header in args.headers or []:
        cmd.extend(["--header", header])
    if args.proxy:
        cmd.extend(["--proxy", args.proxy])
    if args.log_json:
        cmd.extend(["--log-json", args.log_json])
    if args.input_file:
        cmd.extend(["-i", args.input_file])
    extend_cmd_with_extra_args(cmd, args)
    if args.target:
        cmd.append(args.target)

    result = kali_exec(cmd, tool_name="whatweb", **kali_args_to_kwargs(args))
    emit_result(result)
