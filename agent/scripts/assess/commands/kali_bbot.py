"""vigil assess kali bbot — typed wrapper around bbot (multi-module recon scanner)."""
from __future__ import annotations

import shlex
import sys
import time

from assess.lib.client import AssessError
from assess.lib.kali import (
    add_passthrough_args_flag,
    add_required_kali_flags,
    emit_result,
    extend_cmd_with_extra_args,
    kali_args_to_kwargs,
    kali_exec,
)


def _operator_passed_output_module(args) -> bool:
    """True when the operator already supplied an output module via --extra-args.

    The typed verb has no -om flag, so passthrough is the only way to override
    the default JSON output module. Honor that so the injection stays idempotent.
    """
    extra = getattr(args, "extra_args", "") or ""
    if not extra:
        return False
    try:
        tokens = shlex.split(extra)
    except ValueError:
        return False
    return "-om" in tokens or "--output-modules" in tokens


def _default_output_dir() -> str:
    """Container path for the bbot output dir when the operator did not set one.

    bbot's final txt output is crash-truncated (I-011: v2.6.0 dnsresolve
    crash-loop), so a JSON output module + a deterministic output dir is the
    default. Keep this relative because ``kali_exec`` always runs with
    ``cwd=/engagements/<resolved-key>``; deriving an absolute path separately
    could disagree with an explicit ``--engagement-dir`` selector.
    """
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    return f"scans/bbot_{stamp}"


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "bbot",
        help="Run bbot inside the runtime container with audit recording (multi-module recon scanner).",
    )
    add_required_kali_flags(p)
    p.add_argument(
        "-t",
        "--target",
        dest="targets",
        action="append",
        default=[],
        help="Target (repeatable). Required if -tL is not passed.",
    )
    p.add_argument(
        "-tL",
        "--target-list",
        dest="target_list",
        default="",
        help="File of newline-separated targets.",
    )
    p.add_argument(
        "-p",
        "--preset",
        dest="presets",
        action="append",
        default=[],
        help="bbot preset (repeatable). Recommend 'subdomain-enum' for sub work.",
    )
    p.add_argument(
        "-rf",
        "--required-flags",
        dest="required_flags",
        action="append",
        default=[],
        help="Required-flag filter (repeatable). Use 'passive' for passive-only sub work.",
    )
    p.add_argument(
        "-ef",
        "--excluded-flags",
        dest="excluded_flags",
        action="append",
        default=[],
        help="Excluded-flag filter (repeatable).",
    )
    p.add_argument(
        "-m",
        "--modules",
        dest="modules",
        action="append",
        default=[],
        help="Explicit module to enable (repeatable).",
    )
    p.add_argument(
        "-em",
        "--excluded-modules",
        dest="excluded_modules",
        action="append",
        default=[],
        help="Module to disable (repeatable).",
    )
    p.add_argument(
        "-o",
        "--output-dir",
        dest="output_dir",
        default="",
        help=(
            "bbot output directory. When unset, defaults to "
            "scans/bbot_<ts> under the resolved engagement. The wrapper always emits JSON "
            "(-om json) into this dir — harvest DNS_NAME events from output.json, "
            "not the crash-truncated final txt (CR-24)."
        ),
    )
    p.add_argument(
        "--allow-deadly",
        dest="allow_deadly",
        action="store_true",
        help=(
            "Allow active/deadly modules. REQUIRES --destructive — bbot's deadly modules "
            "perform real attacks (e.g. fuzzing, brute-force, exploit), so the audit row "
            "must reflect destructive intent."
        ),
    )
    add_passthrough_args_flag(p)
    p.set_defaults(func=run)


def run(args) -> None:
    if not args.targets and not args.target_list:
        print("bbot: pass -t <target> (repeatable) or -tL <list>", file=sys.stderr)
        raise AssessError("missing -t/--target or -tL/--target-list")
    if args.allow_deadly and not getattr(args, "destructive", False):
        print(
            "bbot: --allow-deadly requires --destructive. Deadly bbot modules perform "
            "real attacks (active fuzzing, brute-force, exploit attempts) — the audit "
            "row must reflect destructive intent. Re-run with --destructive.",
            file=sys.stderr,
        )
        raise AssessError("--allow-deadly without --destructive")

    # Default to machine-parseable JSON output: the v2.6.0 dnsresolve crash-loop
    # (I-011 / CR-24, see _default_output_dir) truncates the final txt to ~250 B,
    # so DNS_NAME events are harvested from output.json. Both injections are
    # idempotent:
    # skip -om if the operator supplied their own output module via --extra-args,
    # and never override an explicit -o.
    output_dir = args.output_dir or _default_output_dir()
    inject_json_module = not _operator_passed_output_module(args)

    cmd: list[str] = ["bbot"]
    for target in args.targets or []:
        cmd.extend(["-t", target])
    if args.target_list:
        cmd.extend(["-tL", args.target_list])
    for preset in args.presets or []:
        cmd.extend(["-p", preset])
    for flag in args.required_flags or []:
        cmd.extend(["-rf", flag])
    for flag in args.excluded_flags or []:
        cmd.extend(["-ef", flag])
    for module in args.modules or []:
        cmd.extend(["-m", module])
    for module in args.excluded_modules or []:
        cmd.extend(["-em", module])
    cmd.extend(["-o", output_dir])
    if inject_json_module:
        cmd.extend(["-om", "json"])
    if args.allow_deadly:
        cmd.append("--allow-deadly")
    extend_cmd_with_extra_args(cmd, args)

    result = kali_exec(cmd, tool_name="bbot", **kali_args_to_kwargs(args))
    emit_result(result)
