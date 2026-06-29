"""vigil assess kali ffuf — typed wrapper around ffuf inside the runtime."""
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
    p.add_argument("-t", dest="threads", default="", help="Concurrent threads.")
    p.add_argument("-timeout", dest="timeout_http", default="", help="Per-request timeout (seconds).")
    p.add_argument("-H", dest="headers", action="append", default=None,
                   help="Extra request header (repeatable). Program attribution headers are "
                        "injected automatically on top of these.")
    p.add_argument("-mc", dest="match_codes", default="", help="Match HTTP codes (e.g. 200,301).")
    p.add_argument("-fc", dest="filter_codes", default="", help="Filter HTTP codes (drop matches).")
    p.add_argument("-fs", dest="filter_size", default="", help="Filter response size.")
    p.add_argument("-fw", dest="filter_words", default="", help="Filter by word count.")
    p.add_argument("-fl", dest="filter_lines", default="", help="Filter by line count.")
    p.add_argument("-fr", dest="filter_regex", default="", help="Filter by regex on the response.")
    p.add_argument("-ic", dest="ignore_comments", action="store_true", help="Ignore wordlist comment lines.")
    p.add_argument("-ac", dest="auto_calibrate", action="store_true",
                   help="Auto-calibrate filters (recommended to suppress soft-404 noise).")
    p.add_argument("-recursion", dest="recursion", action="store_true", help="Recurse into discovered dirs.")
    p.add_argument("-recursion-depth", dest="recursion_depth", default="", help="Max recursion depth.")
    p.add_argument("-o", dest="output", default="", help="Output file.")
    p.add_argument("-of", dest="output_format", default="", help="Output format (json|csv|html|md).")
    p.set_defaults(func=run)


def run(args) -> None:
    cmd: list[str] = ["ffuf", "-u", args.target_url, "-w", args.wordlist]
    if args.rate:
        cmd.extend(["-rate", str(args.rate)])
    if args.threads:
        cmd.extend(["-t", str(args.threads)])
    if args.timeout_http:
        cmd.extend(["-timeout", str(args.timeout_http)])
    for header in args.headers or []:
        cmd.extend(["-H", header])
    if args.match_codes:
        cmd.extend(["-mc", args.match_codes])
    if args.filter_codes:
        cmd.extend(["-fc", args.filter_codes])
    if args.filter_size:
        cmd.extend(["-fs", str(args.filter_size)])
    if args.filter_words:
        cmd.extend(["-fw", str(args.filter_words)])
    if args.filter_lines:
        cmd.extend(["-fl", str(args.filter_lines)])
    if args.filter_regex:
        cmd.extend(["-fr", args.filter_regex])
    if args.ignore_comments:
        cmd.append("-ic")
    if args.auto_calibrate:
        cmd.append("-ac")
    if args.recursion:
        cmd.append("-recursion")
    if args.recursion_depth:
        cmd.extend(["-recursion-depth", str(args.recursion_depth)])
    if args.output:
        cmd.extend(["-o", args.output])
    if args.output_format:
        cmd.extend(["-of", args.output_format])
    extend_cmd_with_extra_args(cmd, args)

    result = kali_exec(cmd, tool_name="ffuf", **kali_args_to_kwargs(args))
    emit_result(result)
