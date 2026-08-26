"""vigil assess list-mindsets — compact index of the Dispatch-Mindset lens library.

`agent/rules/mindsets/` holds the analytic lenses the operator injects into a
dispatch (`mindset lens: agent/rules/mindsets/idor-bac.md — <why it fits the
observed signal>`). Until this command existed it was the ONE discovery axis
still enumerated by hand: the packet menu was copy-pasted into ~16 sites across
the operator cores, the phase files, and the role prompts, so adding a packet
meant editing every menu — and forgetting one (or all of them) left the packet
unreachable. `list-skills` / `list-references` / `list-commands` all
self-register; this is the mindsets analogue, so the library is discovered, not
enumerated.

Adding a packet is self-registering: drop a `.md` into `agent/rules/mindsets/`
and it appears on the next run. Nothing to add to a menu.

Description derivation (why there is no frontmatter here). Unlike skills and
references, mindset packets carry NO YAML frontmatter — they are prose the
specialist reads top-to-bottom, and a metadata block at the top would be the
first thing in that specialist's context window. So the row's `title` is the H1
and its `description` is derived from the file's own preamble: the prose between
the H1 and the first `##` section, trimmed to its leading sentence(s). Every
packet already opens with a "what this lens is for" paragraph, so the derivation
is faithful to what a maintainer wrote rather than a second, drift-prone copy of
it. `--sections` surfaces each packet's `##` headings, which is what an operator
actually needs to choose a lens without opening the file.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from assess.lib import frontmatter


# Mindsets directory is resolved relative to this file's location:
# agent/scripts/assess/commands/list_mindsets.py -> agent/rules/mindsets/
_MINDSETS_DIR = Path(__file__).resolve().parents[3] / "rules" / "mindsets"

# Printed above the table so the operator knows what to DO with a row. The
# dispatch contract is "exactly ONE lens per dispatch" — a menu handed to the
# specialist is the failure mode this library exists to avoid.
_INTRO = (
    "Dispatch-Mindset lens library. Name exactly ONE packet per dispatch — "
    "`mindset lens: <path> — <one line: why this lens fits the observed "
    "signal>`; never hand a specialist a menu to choose from."
)

# Sentence boundary: a terminator immediately followed by whitespace. The
# lookbehind is deliberately narrow so `agent/rules/hunting.md` (period followed
# by a letter) and `...payload*.` (terminator is the final char) both behave.
_SENTENCE_SPLIT = re.compile(r"(?<=[.!?])\s+")

# Chunks ending in one of these are an abbreviation, not a sentence end.
_ABBREVIATIONS = ("e.g.", "i.e.", "etc.", "vs.", "cf.", "approx.", "resp.")

# Grow the derived description until it clears this many characters (or the
# preamble runs out). One packet opens with a deliberately terse thesis
# ("A stance, not a mechanic.") that is true but useless as an index entry.
_MIN_DESCRIPTION = 80

# Hard stop so a packet whose preamble is one long paragraph does not produce a
# multi-hundred-character JSON `description`.
_MAX_SENTENCES = 3


def register(subparsers: argparse._SubParsersAction) -> None:
    p = subparsers.add_parser(
        "list-mindsets",
        help="List the Dispatch-Mindset lens packets with compact descriptions",
        description=(
            "Walk agent/rules/mindsets/*.md and emit a compact index of the "
            "analytic lenses a dispatch can inject. Use this in place of a "
            "hard-coded packet menu to pick the ONE lens that matches the "
            "observed signal. Mirrors list-skills / list-references / "
            "list-commands."
        ),
    )
    p.add_argument(
        "--json",
        dest="as_json",
        action="store_true",
        help="Emit JSON instead of the default human-readable table",
    )
    p.add_argument(
        "--grep",
        dest="grep",
        default=None,
        help=(
            "Show only packets whose name, title, description, or section "
            "headings contain this substring (case-insensitive)"
        ),
    )
    p.add_argument(
        "--sections",
        dest="sections",
        action="store_true",
        help=(
            "Expand each packet into its `##` section headings (the detail an "
            "operator needs to choose a lens without opening the file)"
        ),
    )
    p.add_argument(
        "--mindsets-dir",
        dest="mindsets_dir",
        default=None,
        help=(
            "Override the mindsets directory (default: agent/rules/mindsets "
            "relative to this script)"
        ),
    )
    p.set_defaults(func=run)


def run(args: argparse.Namespace) -> None:
    mindsets_dir = Path(args.mindsets_dir) if args.mindsets_dir else _MINDSETS_DIR
    if not mindsets_dir.is_dir():
        print(f"mindsets directory not found: {mindsets_dir}", file=sys.stderr)
        sys.exit(2)

    rows = _collect_mindsets(mindsets_dir)

    if args.grep:
        term = args.grep.lower()
        rows = [r for r in rows if term in _haystack(r)]

    if args.as_json:
        print(json.dumps(rows, ensure_ascii=False, indent=2))
        return

    if not rows:
        print("(no mindset packets found)")
        return

    print(_INTRO)
    print()
    if args.sections:
        _print_expanded(rows)
    else:
        _print_table(rows)


def _haystack(row: dict) -> str:
    return " ".join(
        [row["name"], row["title"], row["description"], *row["sections"]]
    ).lower()


def _collect_mindsets(mindsets_dir: Path) -> list[dict]:
    rows: list[dict] = []
    for md in sorted(mindsets_dir.glob("*.md")):
        lines = _read_lines(md)
        rows.append(
            {
                "name": md.stem,
                # `frontmatter.parse` already falls back to the first H1 when a
                # file has no frontmatter, which is exactly the mindset case —
                # reuse it rather than re-implementing heading extraction.
                "title": frontmatter.parse(md).get("description") or md.stem,
                "description": _derive_description(lines) or "(no preamble)",
                "sections": _section_headings(lines),
                "path": _display_path(md, mindsets_dir),
            }
        )
    return rows


def _read_lines(md: Path) -> list[str]:
    try:
        return md.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []


def _display_path(md: Path, mindsets_dir: Path) -> str:
    """Repo-relative path when the library sits in its normal place, else the
    path as given (so `--mindsets-dir /tmp/x` still prints something usable)."""
    resolved_dir = mindsets_dir.resolve()
    # agent/rules/mindsets -> parents[2] is the repo root.
    if len(resolved_dir.parents) >= 3:
        try:
            return md.resolve().relative_to(resolved_dir.parents[2]).as_posix()
        except ValueError:
            pass
    return md.as_posix()


def _preamble(lines: list[str]) -> str:
    """The prose between the H1 and the first `##` section, as one line.

    Packets are hard-wrapped, so the paragraph is rejoined with single spaces.
    Blank lines end the paragraph: only the FIRST preamble paragraph is used —
    later ones elaborate rather than define.
    """
    collected: list[str] = []
    seen_h1 = False
    for raw in lines:
        line = raw.strip()
        if not seen_h1:
            if line.startswith("# "):
                seen_h1 = True
            continue
        if line.startswith("## "):
            break
        if not line:
            if collected:
                break
            continue
        collected.append(line)
    return " ".join(collected)


def _split_sentences(text: str) -> list[str]:
    """Split on terminator+whitespace, re-joining chunks that ended on a known
    abbreviation (`etc.`, `e.g.`) rather than a real sentence end."""
    parts = _SENTENCE_SPLIT.split(text)
    sentences: list[str] = []
    for part in parts:
        if sentences and sentences[-1].lower().endswith(_ABBREVIATIONS):
            sentences[-1] = f"{sentences[-1]} {part}"
        else:
            sentences.append(part)
    return [s for s in sentences if s]


def _derive_description(lines: list[str]) -> str:
    preamble = _preamble(lines)
    if not preamble:
        return ""
    sentences = _split_sentences(preamble)
    if not sentences:
        return ""
    taken: list[str] = []
    for sentence in sentences[:_MAX_SENTENCES]:
        taken.append(sentence)
        if len(" ".join(taken)) >= _MIN_DESCRIPTION:
            break
    return " ".join(taken)


def _section_headings(lines: list[str]) -> list[str]:
    return [line.strip()[3:].strip() for line in lines if line.strip().startswith("## ")]


def _print_table(rows: list[dict]) -> None:
    name_w = max(len("MINDSET"), max(len(r["name"]) for r in rows))
    desc_w = min(70, max(len("DESCRIPTION"), max(len(r["description"]) for r in rows)))
    header = f"{'MINDSET':<{name_w}}  {'DESCRIPTION':<{desc_w}}  PATH"
    print(header)
    print("-" * len(header))
    for row in rows:
        desc = row["description"]
        if len(desc) > desc_w:
            desc = desc[: desc_w - 1] + "…"
        print(f"{row['name']:<{name_w}}  {desc:<{desc_w}}  {row['path']}")


def _print_expanded(rows: list[dict]) -> None:
    for idx, row in enumerate(rows):
        if idx:
            print()
        print(f"## {row['name']} — {row['title']}")
        print(f"{row['path']}")
        print(row["description"])
        for heading in row["sections"]:
            print(f"  - {heading}")
