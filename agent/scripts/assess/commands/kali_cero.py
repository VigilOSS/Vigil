"""aith assess kali cero — typed wrapper around cero (TLS-handshake SAN scraper)."""
from __future__ import annotations

import shlex
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
    # NOTE: argparse short flag `-d` is intentionally NOT bound here. cero's
    # native `-d` flag is a toggle (filter results to valid domain names only),
    # not a target argument. The wrapper exposes the target via `--target` /
    # `--domain` (single host or CIDR) and `-l` / `--input-list` (file of
    # targets), and surfaces cero's `-d` toggle as `--only-domains`.
    p.add_argument("--target", "--domain", dest="domain", default="", help="Single domain or CIDR target.")
    p.add_argument(
        "-l",
        "--input-list",
        dest="input_list",
        default="",
        help="File of newline-separated domains/CIDRs (piped to cero on stdin).",
    )
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
        help="cero -d toggle: filter results to valid domain names only (strip IPs / wildcards / gibberish).",
    )
    p.add_argument(
        "-v",
        "--verbose",
        dest="verbose",
        action="store_true",
        help="cero -v: print 'addr -- [results]' lines and stderr errors.",
    )
    p.add_argument("-o", "--output", dest="output", default="", help="-o output file.")
    add_passthrough_args_flag(p)
    p.set_defaults(func=run)


def _build_cero_argv(args) -> list[str]:
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
    if args.output:
        cmd.extend(["-o", args.output])
    if args.domain:
        cmd.append(args.domain)
    return cmd


def run(args) -> None:
    if not args.domain and not args.input_list:
        print("cero: pass --target/--domain <host-or-cidr> or -l <file>", file=sys.stderr)
        raise AssessError("missing --target/--domain or -l/--input-list")

    cero_argv = _build_cero_argv(args)
    extend_cmd_with_extra_args(cero_argv, args)

    if args.input_list:
        # cero reads targets from stdin when no positional args are provided.
        # Pipe the file via a sh -c wrapper so the audit row records the
        # canonical invocation (`cat <file> | cero ...`).
        inner = "cat {input} | {cero}".format(
            input=shlex.quote(args.input_list),
            cero=" ".join(shlex.quote(tok) for tok in cero_argv),
        )
        cmd = ["sh", "-c", inner]
    else:
        cmd = cero_argv

    result = kali_exec(cmd, tool_name="cero", **kali_args_to_kwargs(args))
    emit_result(result)
