"""vigil assess kali gau — typed wrapper around gau inside the runtime."""
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
        "gau",
        help="Run gau inside the runtime container with audit recording.",
    )
    add_required_kali_flags(p)
    add_passthrough_args_flag(p)
    p.add_argument("target", nargs="?", default="", help="Target domain (positional).")
    p.add_argument("--list", dest="target_list", default="", help="File of newline-separated domains.")
    p.add_argument("--subs", dest="subs", action="store_true", help="Include subdomains.")
    p.add_argument("--threads", dest="threads", default="", help="Worker threads.")
    # gau's `--timeout` collides with the audit scaffolding's own `--timeout`.
    # Expose `--gau-timeout` and translate it in run() (mirrors sqlmap's
    # `--sql-technique` -> `--technique` rename).
    p.add_argument("--gau-timeout", dest="timeout_http", default="", help="gau per-request timeout (seconds).")
    p.add_argument("--retries", dest="retries", default="", help="Retries per request.")
    p.add_argument("--blacklist", dest="blacklist", default="", help="Comma-separated extension blacklist.")
    p.add_argument("--providers", dest="providers", default="", help="Comma-separated providers (wayback,otx,...).")
    p.add_argument("--fc", dest="filter_codes", default="", help="Filter (drop) these response codes.")
    p.add_argument("--mc", dest="match_codes", default="", help="Match only these response codes.")
    p.add_argument("--from", dest="date_from", default="", help="Fetch URLs from this date (YYYYMM).")
    p.add_argument("--to", dest="date_to", default="", help="Fetch URLs up to this date (YYYYMM).")
    p.add_argument("-o", dest="output", default="", help="Output file.")
    p.set_defaults(func=run)


def run(args) -> None:
    if not args.target and not args.target_list:
        print("gau: pass <target> or --list <file>", file=sys.stderr)
        raise AssessError("missing <target> or --list")
    cmd: list[str] = ["gau"]
    if args.subs:
        cmd.append("--subs")
    if args.threads:
        cmd.extend(["--threads", str(args.threads)])
    if args.timeout_http:
        cmd.extend(["--timeout", str(args.timeout_http)])
    if args.retries:
        cmd.extend(["--retries", str(args.retries)])
    if args.blacklist:
        cmd.extend(["--blacklist", args.blacklist])
    if args.providers:
        cmd.extend(["--providers", args.providers])
    if args.filter_codes:
        cmd.extend(["--fc", args.filter_codes])
    if args.match_codes:
        cmd.extend(["--mc", args.match_codes])
    if args.date_from:
        cmd.extend(["--from", str(args.date_from)])
    if args.date_to:
        cmd.extend(["--to", str(args.date_to)])
    if args.output:
        # gau's CLI uses `--o` (double-dash), not the conventional `-o` short
        # flag; pass the long form or gau won't parse the value.
        cmd.extend(["--o", args.output])
    if args.target_list:
        cmd.extend(["--list", args.target_list])
    extend_cmd_with_extra_args(cmd, args)
    if args.target:
        cmd.append(args.target)

    result = kali_exec(cmd, tool_name="gau", **kali_args_to_kwargs(args))
    emit_result(result)
