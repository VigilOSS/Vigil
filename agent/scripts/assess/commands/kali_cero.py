"""aith assess kali cero — typed wrapper around cero (TLS-handshake SAN scraper)."""
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
        "cero",
        help="Run cero inside the runtime container with audit recording (TLS SAN scraper).",
    )
    add_required_kali_flags(p)
    p.add_argument("-d", "--domain", dest="domain", default="", help="Domain or CIDR target.")
    p.add_argument(
        "-p",
        "--ports",
        dest="ports",
        default="",
        help="Comma-separated ports to probe (default: 443,8443 — cero default).",
    )
    p.add_argument(
        "-c",
        "--concurrency",
        dest="concurrency",
        default="",
        help="Number of concurrent workers (cero default: 100).",
    )
    p.add_argument(
        "-t",
        "--timeout-seconds",
        dest="timeout_seconds",
        default="",
        help="Per-host TCP/TLS timeout in seconds (cero default: 4).",
    )
    p.add_argument(
        "--only-domains",
        dest="only_domains",
        action="store_true",
        help="cero -d: filter results to valid domain names only (strip IPs / wildcards / gibberish).",
    )
    p.add_argument(
        "-v",
        "--verbose",
        dest="verbose",
        action="store_true",
        help="cero -v: print 'addr -- [results]' lines and stderr errors.",
    )
    add_passthrough_args_flag(p)
    p.set_defaults(func=run)


def run(args) -> None:
    if not args.domain:
        print("cero: pass -d <domain-or-cidr>", file=sys.stderr)
        raise AssessError("missing -d/--domain")
    cmd: list[str] = ["cero"]
    if args.ports:
        cmd.extend(["-p", args.ports])
    if args.concurrency:
        cmd.extend(["-c", str(args.concurrency)])
    if args.timeout_seconds:
        cmd.extend(["-t", str(args.timeout_seconds)])
    if args.only_domains:
        cmd.append("-d")
    if args.verbose:
        cmd.append("-v")
    cmd.append(args.domain)
    extend_cmd_with_extra_args(cmd, args)

    result = kali_exec(cmd, tool_name="cero", **kali_args_to_kwargs(args))
    emit_result(result)
