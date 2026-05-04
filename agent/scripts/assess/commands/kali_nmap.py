"""aith assess kali nmap-scan — typed wrapper around nmap inside the runtime."""
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
        "nmap-scan",
        help="Run nmap inside the runtime container with audit recording.",
    )
    add_required_kali_flags(p)
    add_passthrough_args_flag(p)
    p.add_argument("--target", default="", help="Target host or CIDR. Optional when -iL is supplied.")
    p.add_argument("--ports", default="top-1000", help="Port spec: top-100 | top-1000 | -p- full | explicit list (e.g. 22,80,443).")
    p.add_argument("--scripts", default="", help="Comma-separated NSE scripts (e.g. default,vuln).")
    p.add_argument(
        "--scan-type",
        dest="scan_type",
        choices=["sS", "sT", "sU", "sV", "sn"],
        default="",
        help="nmap scan type flag (passed as -<scan-type>).",
    )
    p.add_argument("--service-detection", dest="service_detection", action="store_true", help="Enable -sV.")
    p.add_argument("--os-detection", dest="os_detection", action="store_true", help="Enable -O.")
    p.add_argument("--max-rate", dest="max_rate", default="", help="--max-rate <pps>.")
    p.add_argument("--max-retries", dest="max_retries", default="", help="--max-retries N.")
    p.add_argument("--host-timeout", dest="host_timeout", default="", help="--host-timeout <duration>.")
    p.add_argument("-iL", dest="input_list", default="", help="-iL input list path (engagement-relative).")
    p.add_argument("-oA", dest="output_prefix", default="", help="-oA output prefix.")
    p.set_defaults(func=run)


def run(args) -> None:
    if not args.target and not args.input_list:
        print("nmap-scan: pass --target <host-or-cidr> or -iL <file>", file=sys.stderr)
        raise AssessError("missing --target or -iL")

    cmd: list[str] = ["nmap"]
    if args.scan_type:
        cmd.append(f"-{args.scan_type}")
    if args.service_detection:
        cmd.append("-sV")
    if args.os_detection:
        cmd.append("-O")
    if args.scripts:
        cmd.append(f"--script={args.scripts}")
    if args.max_rate:
        cmd.extend(["--max-rate", str(args.max_rate)])
    if args.max_retries:
        cmd.extend(["--max-retries", str(args.max_retries)])
    if args.host_timeout:
        cmd.extend(["--host-timeout", str(args.host_timeout)])
    if args.input_list:
        cmd.extend(["-iL", args.input_list])
    if args.output_prefix:
        cmd.extend(["-oA", args.output_prefix])

    if args.ports == "full":
        cmd.append("-p-")
    elif args.ports == "top-100":
        cmd.extend(["--top-ports", "100"])
    elif args.ports == "top-1000":
        cmd.extend(["--top-ports", "1000"])
    elif args.ports:
        cmd.extend(["-p", args.ports])

    extend_cmd_with_extra_args(cmd, args)
    if args.target:
        cmd.append(args.target)

    result = kali_exec(cmd, tool_name="nmap", **kali_args_to_kwargs(args))
    emit_result(result)
