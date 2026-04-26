"""aith assess kali ffuf — typed wrapper around ffuf inside the runtime."""
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
        "ffuf",
        help="Run ffuf inside the runtime container with audit recording.",
    )
    add_required_kali_flags(p)
    add_passthrough_args_flag(p)
    p.add_argument("-u", dest="target_url", required=True, help="Target URL with FUZZ keyword.")
    p.add_argument("-w", dest="wordlist", required=True, help="Wordlist path.")
    p.add_argument("-rate", dest="rate", default="", help="Requests per second.")
    p.add_argument("-mc", dest="match_codes", default="", help="Match HTTP codes (e.g. 200,301).")
    p.add_argument("-fc", dest="filter_codes", default="", help="Filter HTTP codes (drop matches).")
    p.add_argument("-fs", dest="filter_size", default="", help="Filter response size.")
    p.add_argument("-o", dest="output", default="", help="Output file.")
    p.add_argument("-of", dest="output_format", default="", help="Output format (json|csv|html|md).")
    p.set_defaults(func=run)


def run(args) -> None:
    cmd: list[str] = ["ffuf", "-u", args.target_url, "-w", args.wordlist]
    if args.rate:
        cmd.extend(["-rate", str(args.rate)])
    if args.match_codes:
        cmd.extend(["-mc", args.match_codes])
    if args.filter_codes:
        cmd.extend(["-fc", args.filter_codes])
    if args.filter_size:
        cmd.extend(["-fs", str(args.filter_size)])
    if args.output:
        cmd.extend(["-o", args.output])
    if args.output_format:
        cmd.extend(["-of", args.output_format])
    extend_cmd_with_extra_args(cmd, args)

    result = kali_exec(cmd, tool_name="ffuf", **kali_args_to_kwargs(args))
    emit_result(result)
