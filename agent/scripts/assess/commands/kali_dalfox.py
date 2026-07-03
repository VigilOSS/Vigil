"""vigil assess kali dalfox — typed wrapper around dalfox inside the runtime.

Parameter→XSS confirmation. dalfox fires reflection-aware XSS payloads at a
parameterized URL (or a list of them), verifies whether the reflection actually
executes (DOM/HTML/attribute context), and is WAF-aware. The intended chain is
AFTER `arjun` surfaces hidden params: arjun isolates the injectable parameter,
dalfox confirms whether it is XSS-exploitable.

Reflective by DEFAULT — no blind/OOB payloads fire unless the operator opts in
with `--blind <callback>` (which sends payloads to an out-of-band collector and
can store a persisted payload, so pair it with `--destructive`). dalfox is in the
required-header INJECTABLE set (curl-style ``-H``), so a required-headers program
marker rides every probe automatically.
"""
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
        "dalfox",
        help="Run dalfox inside the runtime container with audit recording (param→XSS confirmation).",
    )
    add_required_kali_flags(p)
    add_passthrough_args_flag(p)
    p.add_argument("-u", "--url", dest="target", default="",
                   help="Single target URL (dalfox `url` mode). Point it at the arjun-surfaced parameter.")
    p.add_argument("-i", "--input", dest="input_file", default="",
                   help="File of newline-separated URLs (dalfox `file` mode).")
    p.add_argument("-p", "--param", dest="param", default="",
                   help="Test ONLY this parameter (focus dalfox on the arjun-isolated param).")
    p.add_argument("--header", "-H", dest="headers", action="append", default=None,
                   help="Custom request header (repeatable), e.g. -H 'Authorization: Bearer ...'.")
    p.add_argument("--cookie", dest="cookie", default="", help="Cookie string to send with each request.")
    p.add_argument("--blind", dest="blind", default="",
                   help="Blind-XSS callback URL (OPT-IN). Sends OOB payloads that may persist — pair with --destructive.")
    p.add_argument("--custom-payload", dest="custom_payload", default="", help="File of custom XSS payloads.")
    p.add_argument("-w", "--worker", dest="worker", default="", help="Concurrent workers (dalfox -w).")
    p.add_argument("--delay", dest="delay", default="", help="Delay in milliseconds between requests (politeness).")
    p.add_argument("--dalfox-timeout", dest="dalfox_timeout", default="",
                   help="dalfox per-request timeout in seconds (emitted as dalfox's --timeout; renamed to avoid the audit --timeout collision).")
    p.add_argument("--waf-evasion", dest="waf_evasion", action="store_true", help="Enable dalfox WAF-evasion mode.")
    p.add_argument("--skip-bav", dest="skip_bav", action="store_true",
                   help="Skip the basic-another-vuln scan so the run stays focused on XSS.")
    p.add_argument("--follow-redirects", dest="follow_redirects", action="store_true", help="Follow HTTP redirects.")
    p.add_argument("--format", dest="output_format", default="", help="Output format (e.g. json, plain).")
    p.add_argument("-o", "--output", dest="output", default="", help="-o output file (engagement-relative).")
    p.add_argument("--silence", dest="silence", action="store_true", help="Reduce dalfox console noise.")
    p.set_defaults(func=run)


def run(args) -> None:
    target = (args.target or "").strip()
    if not target and not args.input_file:
        print("dalfox: pass -u <url> or -i <list>", file=sys.stderr)
        raise AssessError("missing -u or -i")

    cmd: list[str] = ["dalfox"]
    # dalfox requires a MODE subcommand first: `url <u>` for one target, `file
    # <f>` for a list. `-u` wins when both are given.
    if target:
        cmd.extend(["url", target])
    else:
        cmd.extend(["file", args.input_file])

    if args.param:
        cmd.extend(["-p", args.param])
    for header in args.headers or []:
        cmd.extend(["-H", header])
    if args.cookie:
        cmd.extend(["--cookie", args.cookie])
    if args.blind:
        cmd.extend(["-b", args.blind])
    if args.custom_payload:
        cmd.extend(["--custom-payload", args.custom_payload])
    if args.worker:
        cmd.extend(["-w", str(args.worker)])
    if args.delay:
        cmd.extend(["--delay", str(args.delay)])
    if args.dalfox_timeout:
        cmd.extend(["--timeout", str(args.dalfox_timeout)])
    if args.waf_evasion:
        cmd.append("--waf-evasion")
    if args.skip_bav:
        cmd.append("--skip-bav")
    if args.follow_redirects:
        cmd.append("--follow-redirects")
    if args.output_format:
        cmd.extend(["--format", args.output_format])
    if args.output:
        cmd.extend(["-o", args.output])
    if args.silence:
        cmd.append("--silence")
    extend_cmd_with_extra_args(cmd, args)

    result = kali_exec(cmd, tool_name="dalfox", **kali_args_to_kwargs(args))
    emit_result(result)
