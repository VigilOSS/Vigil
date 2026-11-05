"""Small shared primitives for structural index extractors."""
from __future__ import annotations

import re
from functools import lru_cache
from re import _constants as _sre_constants  # type: ignore[attr-defined]
from re import _parser as _sre_parser  # type: ignore[attr-defined]
from typing import Any

_ZERO_WIDTH = (_sre_constants.AT, _sre_constants.ASSERT, _sre_constants.ASSERT_NOT)
_REPEATS = (
    _sre_constants.MAX_REPEAT,
    _sre_constants.MIN_REPEAT,
    _sre_constants.POSSESSIVE_REPEAT,
)


# The most spellings one literal requirement may carry, so the gate stays a
# short alternation.
_LITERAL_SPELLINGS_LIMIT = 64


def _exact_spellings(items: Any, *, case_blind: bool) -> frozenset[tuple[int, ...]] | None:
    """Every text a parsed sequence can match, when it is a finite literal set.

    A sequence of literal characters, zero-width assertions and alternations
    of such sequences matches only its spellings; anything else is None.
    """
    spellings: set[tuple[int, ...]] = {()}
    for op, argument in items:
        if op is _sre_constants.LITERAL:
            spellings = {spelling + (argument,) for spelling in spellings}
            continue
        if op in _ZERO_WIDTH:
            continue
        if op is _sre_constants.BRANCH:
            choices: set[tuple[int, ...]] = set()
            for branch in argument[1]:
                branch_spellings = _exact_spellings(branch, case_blind=case_blind)
                if branch_spellings is None:
                    return None
                choices |= branch_spellings
        elif op is _sre_constants.SUBPATTERN:
            _group, add_flags, _del_flags, body = argument
            if add_flags & _sre_constants.SRE_FLAG_IGNORECASE and not case_blind:
                return None
            body_spellings = _exact_spellings(body, case_blind=case_blind)
            if body_spellings is None:
                return None
            choices = set(body_spellings)
        else:
            return None
        if len(spellings) * len(choices) > _LITERAL_SPELLINGS_LIMIT:
            return None
        spellings = {spelling + choice for spelling in spellings for choice in choices}
    return frozenset(spellings)


def _literal_need(items: Any, *, case_blind: bool) -> frozenset[Any] | None:
    """Literals one of which every match of a parsed sequence contains.

    A run of literal characters, extended through any alternation of literal
    spellings it meets (`\\$_(?:GET|POST)` needs `$_GET` or `$_POST`), is
    matched verbatim. A group, an alternation all of whose branches need a
    literal, and a repeat that must match at least once pass their own
    requirement up. Anything else ends the run. The longest-shortest
    candidate wins, so the literal is as selective as the sequence allows.
    """
    best: frozenset[Any] | None = None
    run: set[tuple[int, ...]] = {()}

    def offer(candidate: frozenset[Any] | None) -> None:
        nonlocal best
        if candidate and (best is None or min(map(len, candidate)) > min(map(len, best))):
            best = candidate

    def flush() -> None:
        nonlocal run
        if all(run):
            offer(frozenset(run))
        run = {()}

    for op, argument in items:
        if op is _sre_constants.LITERAL:
            run = {spelling + (argument,) for spelling in run}
            continue
        if op in _ZERO_WIDTH:
            # An anchor or a lookaround consumes nothing, so its neighbours
            # are adjacent in the matched text.
            continue
        spellings = (
            _exact_spellings([(op, argument)], case_blind=case_blind)
            if op in (_sre_constants.BRANCH, _sre_constants.SUBPATTERN)
            else None
        )
        if spellings is not None and len(run) * len(spellings) <= _LITERAL_SPELLINGS_LIMIT:
            run = {spelling + choice for spelling in run for choice in spellings}
            continue
        flush()
        if op is _sre_constants.SUBPATTERN:
            _group, add_flags, _del_flags, body = argument
            if add_flags & _sre_constants.SRE_FLAG_IGNORECASE and not case_blind:
                continue
            offer(_literal_need(body, case_blind=case_blind))
        elif op is _sre_constants.ATOMIC_GROUP:
            offer(_literal_need(argument, case_blind=case_blind))
        elif op is _sre_constants.BRANCH:
            branches = [_literal_need(branch, case_blind=case_blind) for branch in argument[1]]
            if all(branches):
                offer(frozenset().union(*branches))  # type: ignore[arg-type]
        elif op in _REPEATS and argument[0] >= 1:
            offer(_literal_need(argument[2], case_blind=case_blind))
    flush()
    return best


@lru_cache(maxsize=None)
def _required_literals(pattern: re.Pattern[Any]) -> frozenset[Any] | None:
    """Substrings one of which every match of *pattern* contains, or None.

    They let a line reader skip text no match could occur in, without
    running the pattern. A bytes pattern yields lowercase literals for text
    lowered the same ASCII-only way its case-blind matching works. A str
    pattern yields exact literals, and none when it is case-blind: Unicode
    case folding (`ſ` matches `s`) is not `str.lower`. None means the
    pattern needs no literal and must always run.
    """
    is_bytes = isinstance(pattern.pattern, bytes)
    flags = pattern.flags
    if is_bytes and flags & re.LOCALE:
        return None
    if not is_bytes and flags & re.IGNORECASE:
        return None
    try:
        parsed = _sre_parser.parse(pattern.pattern, flags)
    except Exception:  # noqa: BLE001 - an unreadable pattern just runs ungated
        return None
    need = _literal_need(parsed, case_blind=is_bytes)
    if need is None:
        return None
    if is_bytes:
        return frozenset(bytes(codes).lower() for codes in need)
    return frozenset("".join(map(chr, codes)) for codes in need)


# A literal shorter than this (`e`, `$`, a backtick) is in nearly every line,
# so a pattern requiring one is left ungated rather than defeating the gate.
_GATE_LITERAL_MIN_LENGTH = 3


def _gate_literals(pattern: re.Pattern[Any]) -> frozenset[Any] | None:
    """The literals a gate admits *pattern* by, or None to always run it."""
    literals = _required_literals(pattern)
    if literals is None or min(map(len, literals)) < _GATE_LITERAL_MIN_LENGTH:
        return None
    return literals


@lru_cache(maxsize=256)
def _literal_gate(patterns: tuple[re.Pattern[Any], ...]) -> re.Pattern[Any] | None:
    """One search that finds any literal some gated pattern requires.

    Text it does not match cannot match any pattern `_gate_literals` gates;
    bytes text must be lowered first. None when no pattern is gated.
    """
    literals = {
        literal
        for pattern in patterns
        for literal in (_gate_literals(pattern) or ())
    }
    if not literals:
        return None
    ordered = sorted(literals, key=lambda literal: (-len(literal), literal))
    if isinstance(ordered[0], bytes):
        return re.compile(b"|".join(re.escape(literal) for literal in ordered))
    return re.compile("|".join(re.escape(literal) for literal in ordered))


def _snippet(line: str, limit: int = 120) -> str:
    s = line.strip()
    if len(s) > limit:
        s = s[: limit - 3] + "..."
    return s

def _empty_func(name: str, line_start: int, line_end: int) -> dict[str, Any]:
    return {
        "name": name,
        "qualified_name": name,
        "line_start": line_start,
        "line_end": line_end,
        "params": [],
        "modifiers": [],
        "annotations": [],
        "is_entry_point": False,
    }

def _php_import_record(kind: str, name: str, alias: str, line: int) -> dict[str, Any]:
    """One name a PHP `use` declaration imports, as every PHP reader publishes it.

    `raw` is the fully qualified name, so `imports` and `import_targets` stay one
    entry per imported name. Only a class import names something a file can
    declare; a function or a constant resolves to no file.
    """
    qualified_name = "".join(name.split()).lstrip("\\")
    return {
        "raw": qualified_name,
        "resolved": qualified_name.replace("\\", "/") if kind == "class" else "",
        "kind": kind,
        "qualified_name": qualified_name,
        "alias": alias,
        "line": line,
    }
