"""vigil assess kali alterx — typed wrapper around alterx (subdomain permutation generator)."""
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

_DISABLE_UPDATE_CHECK_FLAG = "-disable-update-check"


def _operator_passed_disable_update_check(args) -> bool:
    """True when the operator already supplied -disable-update-check via --extra-args.

    The typed verb has no dedicated flag for it, so the only way an operator can
    pass it explicitly is through the raw passthrough. Honor that so the default
    injection stays idempotent and never double-adds the flag.
    """
    extra = getattr(args, "extra_args", "") or ""
    if not extra:
        return False
    try:
        tokens = shlex.split(extra)
    except ValueError:
        # Malformed quoting is reported later by extend_cmd_with_extra_args;
        # treat as "not present" here so we don't suppress the safe default.
        return False
    return _DISABLE_UPDATE_CHECK_FLAG in tokens


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "alterx",
        help="Run alterx inside the runtime container with audit recording (subdomain permutation generator).",
    )
    add_required_kali_flags(p)
    p.add_argument(
        "-l",
        "--list",
        dest="input_list",
        default="",
        help="Input file of known subdomains (one per line).",
    )
    p.add_argument(
        "-d",
        "--domain",
        dest="domain",
        default="",
        help="Single domain to permute (alternative to -l).",
    )
    p.add_argument(
        "-p",
        "--pattern",
        dest="patterns",
        action="append",
        default=[],
        help="Pattern string to apply (repeatable). Omit to use alterx built-in patterns.",
    )
    p.add_argument(
        "-pf",
        "--pattern-file",
        dest="pattern_file",
        default="",
        help="Pattern file path.",
    )
    p.add_argument(
        "-pp",
        "--payload",
        dest="payloads",
        action="append",
        default=[],
        help="Payload key=value (repeatable).",
    )
    p.add_argument(
        "-en",
        "-enrich",
        "--enrich",
        dest="enrich",
        action="store_true",
        help="-enrich (-en) enrich permutations from input.",
    )
    p.add_argument(
        "-estimate",
        dest="estimate",
        action="store_true",
        help="-estimate print candidate count without generating output (always run before -limit).",
    )
    p.add_argument(
        "-limit",
        dest="limit",
        default="",
        help="-limit N output cap.",
    )
    p.add_argument("-o", "--output", dest="output", default="", help="-o output file.")
    add_passthrough_args_flag(p)
    p.set_defaults(func=run)


def run(args) -> None:
    if not args.input_list and not args.domain:
        print("alterx: pass -l <list> or -d <domain>", file=sys.stderr)
        raise AssessError("missing -l/--list or -d/--domain")
    cmd: list[str] = ["alterx"]
    # Inject -disable-update-check by default: alterx v0.1.0's startup update
    # check is pure noise/latency in an egress-restricted container. Idempotent —
    # skip if the operator already passed it via --extra-args.
    if not _operator_passed_disable_update_check(args):
        cmd.append(_DISABLE_UPDATE_CHECK_FLAG)
    if args.input_list:
        cmd.extend(["-l", args.input_list])
    elif args.domain:
        cmd.extend(["-d", args.domain])
    for pattern in args.patterns or []:
        cmd.extend(["-p", pattern])
    if args.pattern_file:
        cmd.extend(["-pf", args.pattern_file])
    for payload in args.payloads or []:
        cmd.extend(["-pp", payload])
    if args.enrich:
        cmd.append("-en")
    if args.estimate:
        cmd.append("-estimate")
    if args.limit:
        cmd.extend(["-limit", str(args.limit)])
    if args.output:
        cmd.extend(["-o", args.output])
    extend_cmd_with_extra_args(cmd, args)

    result = kali_exec(cmd, tool_name="alterx", **kali_args_to_kwargs(args))
    emit_result(result)
