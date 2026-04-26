"""aith assess kali dnsx — typed wrapper around dnsx inside the runtime."""
from __future__ import annotations

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
        "dnsx",
        help="Run dnsx inside the runtime container with audit recording.",
    )
    add_required_kali_flags(p)
    add_passthrough_args_flag(p)
    p.add_argument("-d", dest="domain", default="", help="Single domain.")
    p.add_argument("-l", dest="target_list", default="", help="File of subdomains.")
    p.add_argument("-w", dest="wordlist", default="", help="Wordlist for active enumeration.")
    p.add_argument("-r", dest="resolvers", default="", help="Resolvers file.")
    p.add_argument("-rl", dest="rate_limit", default="", help="Rate limit per second.")
    p.add_argument("-t", dest="threads", default="", help="Worker threads.")
    p.add_argument("-retry", dest="retry", default="", help="Retry count.")
    p.add_argument("-a", dest="a_records", action="store_true", help="-a A record probe.")
    p.add_argument("-cname", dest="cname", action="store_true", help="-cname records.")
    p.add_argument("-resp", dest="resp", action="store_true", help="-resp full response.")
    p.add_argument("-resp-only", dest="resp_only", action="store_true", help="-resp-only.")
    p.add_argument("-json", dest="output_json", action="store_true", help="-json output.")
    p.add_argument("-silent", dest="silent", action="store_true", help="-silent.")
    p.add_argument("-o", dest="output", default="", help="-o output file.")
    p.set_defaults(func=run)


def run(args) -> None:
    cmd: list[str] = ["dnsx"]
    if args.domain:
        cmd.extend(["-d", args.domain])
    if args.target_list:
        cmd.extend(["-l", args.target_list])
    if args.wordlist:
        cmd.extend(["-w", args.wordlist])
    if args.resolvers:
        cmd.extend(["-r", args.resolvers])
    if args.rate_limit:
        cmd.extend(["-rl", str(args.rate_limit)])
    if args.threads:
        cmd.extend(["-t", str(args.threads)])
    if args.retry:
        cmd.extend(["-retry", str(args.retry)])
    if args.a_records:
        cmd.append("-a")
    if args.cname:
        cmd.append("-cname")
    if args.resp:
        cmd.append("-resp")
    if args.resp_only:
        cmd.append("-resp-only")
    if args.output_json:
        cmd.append("-json")
    if args.silent:
        cmd.append("-silent")
    if args.output:
        cmd.extend(["-o", args.output])
    extend_cmd_with_extra_args(cmd, args)

    result = kali_exec(cmd, tool_name="dnsx", **kali_args_to_kwargs(args))
    emit_result(result)
