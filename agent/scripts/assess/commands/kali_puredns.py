"""aith assess kali puredns — typed wrapper around puredns inside the runtime."""
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
        "puredns",
        help="Run puredns inside the runtime container with audit recording.",
    )
    add_required_kali_flags(p)
    add_passthrough_args_flag(p)
    p.add_argument(
        "subcommand",
        choices=["bruteforce", "resolve"],
        help="puredns subcommand.",
    )
    p.add_argument("wordlist_or_input", help="Wordlist (bruteforce) or input file (resolve).")
    p.add_argument("domain", nargs="?", default="", help="Target domain (bruteforce only).")
    p.add_argument("-r", dest="resolvers", default="", help="-r resolvers file.")
    p.add_argument("--resolvers-trusted", dest="resolvers_trusted", default="", help="--resolvers-trusted file.")
    p.add_argument("--rate-limit", dest="rate_limit", default="", help="--rate-limit (per resolver).")
    p.add_argument(
        "--rate-limit-trusted",
        dest="rate_limit_trusted",
        default="",
        help="--rate-limit-trusted.",
    )
    p.add_argument("--wildcard-batch", dest="wildcard_batch", default="", help="--wildcard-batch size.")
    p.add_argument("--wildcard-tests", dest="wildcard_tests", default="", help="--wildcard-tests count.")
    p.add_argument("-w", dest="write_path", default="", help="-w output file path.")
    p.set_defaults(func=run)


def run(args) -> None:
    cmd: list[str] = ["puredns", args.subcommand, args.wordlist_or_input]
    if args.subcommand == "bruteforce" and args.domain:
        cmd.append(args.domain)
    if args.resolvers:
        cmd.extend(["-r", args.resolvers])
    if args.resolvers_trusted:
        cmd.extend(["--resolvers-trusted", args.resolvers_trusted])
    if args.rate_limit:
        cmd.extend(["--rate-limit", str(args.rate_limit)])
    if args.rate_limit_trusted:
        cmd.extend(["--rate-limit-trusted", str(args.rate_limit_trusted)])
    if args.wildcard_batch:
        cmd.extend(["--wildcard-batch", str(args.wildcard_batch)])
    if args.wildcard_tests:
        cmd.extend(["--wildcard-tests", str(args.wildcard_tests)])
    if args.write_path:
        cmd.extend(["-w", args.write_path])
    extend_cmd_with_extra_args(cmd, args)

    result = kali_exec(cmd, tool_name="puredns", **kali_args_to_kwargs(args))
    emit_result(result)
