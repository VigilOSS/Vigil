"""vigil assess kali exec — raw passthrough fallback for tools that aren't yet typed."""
from __future__ import annotations

from assess.lib.kali import add_required_kali_flags, emit_result, kali_args_to_kwargs, kali_exec


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "exec",
        help="Run an arbitrary command inside the runtime container with audit recording.",
    )
    add_required_kali_flags(p)
    p.add_argument(
        "command",
        nargs="+",
        help="Command and arguments. Use `--` to separate from kali flags if any look like options.",
    )
    p.set_defaults(func=run)


def run(args) -> None:
    cmd: list[str] = list(args.command)
    tool_name = cmd[0] if cmd else "command"
    result = kali_exec(cmd, tool_name=tool_name, **kali_args_to_kwargs(args))
    emit_result(result)
