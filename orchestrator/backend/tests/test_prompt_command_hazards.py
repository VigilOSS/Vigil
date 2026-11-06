"""Structural guards against hazardous command forms in emitted prompt blocks.

Prompts are maintained prose, so this test asserts nothing about what any prompt
SAYS. It scans only fenced command blocks -- the copy-and-run surface an agent
executes verbatim -- for three forms that fail silently, producing a plausible
empty or zero-exit result instead of an error:

1. ``rg`` with a short-flag cluster containing ``r``. In ripgrep ``-r`` is
   ``--replace``, so ``rg -rn 'pat'`` rewrites every match to ``n`` and exits 0,
   and ``rg -r foo src`` searches for ``src``. ripgrep already recurses.
2. An unquoted ``rg``/``grep`` argument containing ``|`` or ``(``. The shell
   consumes those before the search tool sees them, so the tool searches for a
   truncated pattern while the rest becomes a pipeline or a subshell.
3. ``for x in $VAR`` in a block that does not run under ``bash -c``. zsh (the
   maintainer and operator default shell) does not field-split an unquoted
   parameter expansion, so the loop runs exactly once with the whole list as the
   value. Target-facing work goes through ``vigil assess kali exec ... -- bash -c``
   anyway, which both fixes the split and records the audit row; a host-side list
   is written literally instead.

Scope is the prompt sources plus the rendered wrapper trees, because the wrappers
are what an installed client actually reads. Inline code spans are out of scope:
the canonical ripgrep warning necessarily names the hazardous form inline, and a
guard that cannot tell a warning from an instruction is a wording test.

The detector itself is pinned by ``test_detectors_classify_known_hazards`` so a
parsing regression cannot turn the three scans vacuously green.
"""

from __future__ import annotations

import re
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[3]
_PROMPT_ROOT = _REPO_ROOT / "agent"
# Engagement directories hold operator runtime data, not prompts, and are ignored by git.
_EXCLUDED_DIRS = ("engagements",)

_FENCE = re.compile(r"^\s{0,3}(`{3,}|~{3,})\s*([^\s`~]*)")
_SHELL_WRAPPER = re.compile(r"\b(?:ba|z)?sh\s+-c\b")
_FOR_PARAMETER_LOOP = re.compile(
    r"\bfor\s+[A-Za-z_][A-Za-z0-9_]*\s+in\s+\$\{?[A-Za-z_]"
)
_SHORT_FLAG_WITH_R = re.compile(r"^-[A-Za-z]*r[A-Za-z]*$")
_SEARCH_COMMANDS = frozenset({"rg", "ripgrep", "grep", "egrep", "fgrep"})
_COMMAND_BREAKS = frozenset({"|", "||", "&&", ";", "&", "|&", "(", ")", ">", ">>", "<", "2>"})


def _prompt_files() -> list[Path]:
    return sorted(
        path
        for path in _PROMPT_ROOT.glob("**/*.md")
        if not any(part in _EXCLUDED_DIRS for part in path.relative_to(_PROMPT_ROOT).parts)
    )


def _fenced_blocks(text: str) -> list[list[tuple[int, str]]]:
    """Return each fenced block as a list of ``(line number, line)`` pairs."""

    blocks: list[list[tuple[int, str]]] = []
    current: list[tuple[int, str]] | None = None
    closer = ""
    for number, line in enumerate(text.splitlines(), start=1):
        match = _FENCE.match(line)
        if current is None:
            if match:
                current = []
                closer = match.group(1)[0] * 3
            continue
        if match and line.strip().startswith(closer):
            blocks.append(current)
            current = None
            continue
        current.append((number, line))
    if current is not None:
        blocks.append(current)
    return blocks


def _tokenize(line: str) -> list[tuple[str, str]]:
    """Split one command line into ``(token, unquoted portion)`` pairs.

    The unquoted portion is what the shell still interprets, so quoted text and
    intentional substitutions (``$(...)``, ``${...}``, backticks) contribute
    nothing to it and never split a token.
    """

    tokens: list[tuple[str, str]] = []
    token = ""
    bare = ""
    quote: str | None = None
    substitution = 0
    index = 0
    while index < len(line):
        char = line[index]
        index += 1
        if quote is not None:
            token += char
            if char == quote:
                quote = None
            continue
        if char == "`":
            token += char
            substitution = 0 if substitution else 1
            continue
        if char in "'\"":
            quote = char
            token += char
            continue
        if char == "$" and index < len(line) and line[index] in "({":
            token += char + line[index]
            index += 1
            substitution += 1
            continue
        if substitution:
            token += char
            if char in ")}":
                substitution -= 1
            continue
        if char.isspace():
            if token:
                tokens.append((token, bare))
            token, bare = "", ""
            continue
        token += char
        bare += char
    if token:
        tokens.append((token, bare))
    return tokens


def _search_invocations(line: str) -> list[tuple[str, list[tuple[str, str]]]]:
    """Return ``(command, arguments)`` for every search-tool call on one line."""

    tokens = _tokenize(line)
    invocations: list[tuple[str, list[tuple[str, str]]]] = []
    for index, (_, bare) in enumerate(tokens):
        if bare not in _SEARCH_COMMANDS:
            continue
        arguments: list[tuple[str, str]] = []
        for token, argument_bare in tokens[index + 1 :]:
            if argument_bare in _COMMAND_BREAKS:
                break
            arguments.append((token, argument_bare))
        invocations.append((bare, arguments))
    return invocations


def _replace_flag_hazards(line: str) -> list[str]:
    """Return the ``rg`` short-flag clusters on this line that mean ``--replace``."""

    hazards: list[str] = []
    for command, arguments in _search_invocations(line):
        if command not in {"rg", "ripgrep"}:
            continue
        hazards.extend(
            bare for _, bare in arguments if _SHORT_FLAG_WITH_R.match(bare)
        )
    return hazards


def _unquoted_metacharacter_hazards(line: str) -> list[str]:
    """Return search arguments whose unquoted text the shell would consume."""

    hazards: list[str] = []
    for _, arguments in _search_invocations(line):
        for token, bare in arguments:
            if bare.startswith("-"):
                continue
            if "|" in bare or "(" in bare:
                hazards.append(token)
    return hazards


def _unsplit_parameter_loops(block: list[tuple[int, str]]) -> list[tuple[int, str]]:
    """Return ``for x in $VAR`` lines in this block that run outside ``bash -c``."""

    wrapper_line: int | None = None
    hazards: list[tuple[int, str]] = []
    for number, line in block:
        if wrapper_line is None and _SHELL_WRAPPER.search(line):
            wrapper_line = number
        if not _FOR_PARAMETER_LOOP.search(line):
            continue
        if wrapper_line is None or number < wrapper_line:
            hazards.append((number, line.strip()))
    return hazards


def _format(findings: list[tuple[Path, int, str]]) -> str:
    return "\n".join(
        f"  {path.relative_to(_REPO_ROOT)}:{number}: {detail}"
        for path, number, detail in findings
    )


def test_prompt_tree_is_scannable() -> None:
    files = _prompt_files()
    assert len(files) > 200, f"only {len(files)} prompt files found under {_PROMPT_ROOT}"
    assert any(part.startswith(".") for path in files for part in path.parts), (
        "rendered client wrapper trees (agent/.claude, agent/.codex, ...) were not scanned"
    )


def test_detectors_classify_known_hazards() -> None:
    assert _replace_flag_hazards("rg -rn 'needle' src") == ["-rn"]
    assert _replace_flag_hazards("rg -r needle src") == ["-r"]
    assert _replace_flag_hazards("rg -n 'needle' src") == []
    # grep's own -r means recursion, so it is not the same hazard.
    assert _replace_flag_hazards("grep -rn needle src") == []

    assert _unquoted_metacharacter_hazards("rg -n a-b|c-d file") == ["a-b|c-d"]
    assert _unquoted_metacharacter_hazards("grep -n foo( file") == ["foo("]
    assert _unquoted_metacharacter_hazards("rg -n 'a-b|c-d' file") == []
    assert _unquoted_metacharacter_hazards("rg -n 'needle' src | head -5") == []
    assert _unquoted_metacharacter_hazards('rg -n "$pattern" "$snapshot_path"') == []
    assert _unquoted_metacharacter_hazards("grep -n needle $(cat list.txt)") == []

    bare_loop = [(1, "HOSTS='a b c'"), (2, "for h in $HOSTS; do"), (3, "done")]
    assert _unsplit_parameter_loops(bare_loop) == [(2, "for h in $HOSTS; do")]

    wrapped_loop = [
        (1, "vigil assess kali exec --technique RECON -- bash -c '"),
        (2, "for h in $HOSTS; do"),
        (3, "done'"),
    ]
    assert _unsplit_parameter_loops(wrapped_loop) == []

    literal_loop = [(1, "for h in a.example b.example; do"), (2, "done")]
    assert _unsplit_parameter_loops(literal_loop) == []

    substitution_loop = [(1, "for i in $(seq 1 20); do"), (2, "done")]
    assert _unsplit_parameter_loops(substitution_loop) == []


def test_command_blocks_do_not_use_ripgrep_replace_as_recursion() -> None:
    findings: list[tuple[Path, int, str]] = []
    for path in _prompt_files():
        for block in _fenced_blocks(path.read_text(encoding="utf-8")):
            for number, line in block:
                for flag in _replace_flag_hazards(line):
                    findings.append((path, number, f"rg {flag} rewrites matches: {line.strip()}"))

    assert not findings, (
        "ripgrep's -r is --replace, so these commands rewrite every match and exit 0. "
        "Use -n/-l/-C<n>; ripgrep already recurses.\n" + _format(findings)
    )


def test_command_block_search_patterns_are_quoted() -> None:
    findings: list[tuple[Path, int, str]] = []
    for path in _prompt_files():
        for block in _fenced_blocks(path.read_text(encoding="utf-8")):
            for number, line in block:
                for argument in _unquoted_metacharacter_hazards(line):
                    findings.append(
                        (path, number, f"unquoted {argument!r} in: {line.strip()}")
                    )

    assert not findings, (
        "the shell consumes an unquoted | or ( before the search tool sees it, so the "
        "search runs on a truncated pattern. Quote the pattern.\n" + _format(findings)
    )


def test_command_block_loops_split_their_lists() -> None:
    findings: list[tuple[Path, int, str]] = []
    for path in _prompt_files():
        for block in _fenced_blocks(path.read_text(encoding="utf-8")):
            for number, line in _unsplit_parameter_loops(block):
                findings.append((path, number, line))

    assert not findings, (
        "zsh does not field-split an unquoted parameter expansion, so each of these loops "
        "runs once with the whole list as the value and its empty result reads as a clean "
        "probe. Run the block through `vigil assess kali exec ... -- bash -c` or write the "
        "list literally.\n" + _format(findings)
    )
