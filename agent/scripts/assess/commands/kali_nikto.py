"""aith assess kali nikto — typed wrapper around nikto inside the runtime."""
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
        "nikto",
        help="Run nikto inside the runtime container with audit recording.",
    )
    add_required_kali_flags(p)
    add_passthrough_args_flag(p)
    # Note: nikto's native flag is `-h <host>`, but `-h` collides with argparse's
    # built-in --help. Expose --host as the canonical flag and translate to `-h`
    # at runtime so the underlying tool sees its expected arg.
    p.add_argument("--host", dest="host", required=True, help="Target host (URL or hostname).")
    p.add_argument("-ssl", dest="ssl", action="store_true", help="Force SSL.")
    p.add_argument("-Tuning", dest="tuning", default="", help="Tuning string (e.g. x60).")
    p.add_argument("-Pause", dest="pause", default="", help="Pause between requests (seconds).")
    p.add_argument("-maxtime", dest="maxtime", default="", help="Wall-clock budget for nikto.")
    p.add_argument("-Format", dest="format", default="", help="Output format (csv|htm|json|txt|xml).")
    p.add_argument("-output", dest="output", default="", help="Output file.")
    p.add_argument("-evasion", dest="evasion", default="", help="Evasion techniques.")
    p.set_defaults(func=run)


def run(args) -> None:
    cmd: list[str] = ["nikto", "-h", args.host]
    if args.ssl:
        cmd.append("-ssl")
    if args.tuning:
        cmd.extend(["-Tuning", args.tuning])
    if args.pause:
        cmd.extend(["-Pause", str(args.pause)])
    if args.maxtime:
        cmd.extend(["-maxtime", str(args.maxtime)])
    if args.format:
        cmd.extend(["-Format", args.format])
    if args.output:
        cmd.extend(["-output", args.output])
    if args.evasion:
        cmd.extend(["-evasion", args.evasion])
    extend_cmd_with_extra_args(cmd, args)

    result = kali_exec(cmd, tool_name="nikto", **kali_args_to_kwargs(args))
    emit_result(result)
