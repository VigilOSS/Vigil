"""vigil assess kali bbot — typed wrapper around bbot (multi-module recon scanner)."""
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
        help="bbot output directory.",
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
    if args.output_dir:
        cmd.extend(["-o", args.output_dir])
    if args.allow_deadly:
        cmd.append("--allow-deadly")
    extend_cmd_with_extra_args(cmd, args)

    result = kali_exec(cmd, tool_name="bbot", **kali_args_to_kwargs(args))
    emit_result(result)
