"""aith assess kali asnmap — typed wrapper around asnmap (ASN → CIDR mapper)."""
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
        "asnmap",
        help="Run asnmap inside the runtime container with audit recording (ASN → CIDR mapper).",
    )
    add_required_kali_flags(p)
    p.add_argument("-d", "--domain", dest="domain", default="", help="Single domain to resolve to ASN.")
    p.add_argument(
        "-l",
        "--input-list",
        dest="input_list",
        default="",
        help="File of domains/IPs (one per line).",
    )
    p.add_argument(
        "-asn",
        dest="asn",
        default="",
        help="ASN identifier passthrough (e.g. AS13335).",
    )
    p.add_argument(
        "-org",
        dest="org",
        default="",
        help="Organization name to resolve when apex ASN lookup fails.",
    )
    p.add_argument("-silent", dest="silent", action="store_true", help="-silent (suppress info).")
    p.add_argument("-json", dest="output_json", action="store_true", help="-json output.")
    p.add_argument("-o", "--output", dest="output", default="", help="-o output file.")
    add_passthrough_args_flag(p)
    p.set_defaults(func=run)


def run(args) -> None:
    if not args.domain and not args.input_list and not args.asn and not args.org:
        print("asnmap: pass -d <domain>, -l <list>, -asn <ASN>, or -org <name>", file=sys.stderr)
        raise AssessError("missing -d/--domain, -l/--input-list, -asn, or -org")
    cmd: list[str] = ["asnmap"]
    if args.domain:
        cmd.extend(["-d", args.domain])
    if args.input_list:
        cmd.extend(["-l", args.input_list])
    if args.asn:
        cmd.extend(["-asn", args.asn])
    if args.org:
        cmd.extend(["-org", args.org])
    if args.silent:
        cmd.append("-silent")
    if args.output_json:
        cmd.append("-json")
    if args.output:
        cmd.extend(["-o", args.output])
    extend_cmd_with_extra_args(cmd, args)

    result = kali_exec(cmd, tool_name="asnmap", **kali_args_to_kwargs(args))
    emit_result(result)
