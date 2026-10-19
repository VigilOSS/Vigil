"""Shared terminal questions; presentation stays off machine-readable stdout."""
from __future__ import annotations

import sys
from contextlib import redirect_stdout
from typing import Any

from . import term


def read_line() -> str:
    try:
        return input()
    except (EOFError, KeyboardInterrupt) as exc:
        raise SystemExit("interactive prompt cancelled or stdin closed; pass the missing flags explicitly") from exc


def uses_prompt_ui() -> bool:
    return term.is_terminal(sys.stdin) and term.is_terminal(sys.stderr)


def terminal_question(kind: str, label: str, **kwargs: Any) -> Any:
    import questionary

    if not term.supports_style(sys.stderr):
        kwargs["color_depth"] = "DEPTH_1_BIT"
    try:
        with redirect_stdout(sys.stderr):
            answer = getattr(questionary, kind)(label, **kwargs).unsafe_ask()
    except (KeyboardInterrupt, EOFError) as exc:
        raise SystemExit("interactive prompt cancelled") from exc
    if answer is None:
        raise SystemExit("interactive prompt cancelled")
    return answer


def prompt_choice(label: str, default: str, choices: list[str], *, attempts: int = 3) -> str:
    if uses_prompt_ui():
        return str(terminal_question("select", label, choices=choices, default=default))
    for _ in range(attempts):
        print(label, file=sys.stderr)
        for idx, choice in enumerate(choices, start=1):
            suffix = " [default]" if choice == default else ""
            print(f"  {idx}. {choice}{suffix}", file=sys.stderr)
        print("> ", end="", file=sys.stderr, flush=True)
        raw = read_line().strip()
        if not raw:
            return default
        if raw.isdigit() and 1 <= int(raw) <= len(choices):
            return choices[int(raw) - 1]
        if raw in choices:
            return raw
        print(f"Invalid {label.lower()}: {raw}", file=sys.stderr)
    raise SystemExit(f"Invalid {label.lower()}: no valid selection after {attempts} attempts")
