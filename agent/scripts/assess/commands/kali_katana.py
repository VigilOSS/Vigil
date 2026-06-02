"""vigil assess kali katana — typed wrapper around katana inside the runtime."""
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
        "katana",
        help="Run katana inside the runtime container with audit recording.",
    )
    add_required_kali_flags(p)
    add_passthrough_args_flag(p)
    p.add_argument("-u", dest="target_url", default="", help="Target URL.")
    p.add_argument("-list", dest="target_list", default="", help="File of newline-separated URLs.")
    p.add_argument("-jc", dest="js_crawl", action="store_true", help="-jc JavaScript crawl.")
    p.add_argument("-jsl", dest="jsluice", action="store_true", help="-jsl jsluice mode.")
    p.add_argument("-d", dest="depth", default="", help="-d max depth.")
    p.add_argument("-c", dest="concurrency", default="", help="-c concurrency.")
    p.add_argument("-rl", dest="rate_limit", default="", help="-rl rate limit.")
    p.add_argument("-headless", dest="headless", action="store_true", help="-headless mode.")
    p.add_argument("-o", dest="output", default="", help="-o output file.")
    p.add_argument("-jsonl", dest="jsonl", action="store_true", help="-jsonl output.")
    p.set_defaults(func=run)


def run(args) -> None:
    if not args.target_url and not args.target_list:
        print("katana: pass -u <url> or -list <file>", file=sys.stderr)
        raise AssessError("missing -u or -list")
    cmd: list[str] = ["katana"]
    if args.target_url:
        cmd.extend(["-u", args.target_url])
    if args.target_list:
        cmd.extend(["-list", args.target_list])
    if args.js_crawl:
        cmd.append("-jc")
    if args.jsluice:
        cmd.append("-jsl")
    if args.depth:
        cmd.extend(["-d", str(args.depth)])
    if args.concurrency:
        cmd.extend(["-c", str(args.concurrency)])
    if args.rate_limit:
        cmd.extend(["-rl", str(args.rate_limit)])
    if args.headless:
        cmd.append("-headless")
    if args.output:
        cmd.extend(["-o", args.output])
    if args.jsonl:
        cmd.append("-jsonl")
    extend_cmd_with_extra_args(cmd, args)

    result = kali_exec(cmd, tool_name="katana", **kali_args_to_kwargs(args))
    emit_result(result)
