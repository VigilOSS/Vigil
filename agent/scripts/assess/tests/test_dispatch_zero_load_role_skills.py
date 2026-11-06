"""A role that loads nothing is never dispatched with a skill to read.

`agent start` renders one mandatory-read order per name in `--skills`:
`_dispatch_skill_lines` turns each name into `agent/skills/<name>/SKILL.md` and
hands the specialist that repository path, asserting the skill outranks the
packet for procedural steps. That is correct for every investigative role, whose
`Load First` already names repository files it must open.

It is the whole failure mode for a role that opens nothing. The blind-triage
Pass-2 reviewer (`agent/agents/general.md`) exists so that a Medium-or-above
submission is judged by an agent that cannot look up how the submission was
produced; its entire admissible input is the packet the operator exports. A
`--skills` name on that dispatch does not add context the packet lacks, it adds
a filesystem foothold, and it points that foothold at the operator's half of the
gate — the Pass-1 QA pass, the verdict mapping, and the recording commands the
blind pass exists to withhold.

The invariant is structural over two executable facts: which roster roles declare
no standing load, and which `--role` / `--skills` pairs the installed prompt
sources actually tell an operator to run. Neither side is a wording assertion —
a role is "zero-load" because its `Load First` section names no repository path,
and the harm is measured by calling the dispatcher's own renderer.
"""
from __future__ import annotations

import re
from pathlib import Path

from assess.commands.agent import _dispatch_skill_lines

REPO_ROOT = Path(__file__).resolve().parents[4]
AGENT_ROOT = REPO_ROOT / "agent"
ROSTER_DIR = AGENT_ROOT / "agents"

# `--role <name>` / `--skills <name>[,<name>]` as literal invocations, in either
# the space or the `=` spelling argparse accepts. A placeholder (`--role <role>`,
# `--skills <skills>`, `--skills $S`) is prose about the flag, not a dispatch
# claim, so it is deliberately unmatched. Blocks are backtick-normalized before
# matching (see `_paragraphs`), so inline-code spans do not hide a flag.
_ROLE_FLAG_RE = re.compile(r"--role[=\s]+([A-Za-z][A-Za-z0-9_-]*)")
_SKILLS_FLAG_RE = re.compile(r"--skills[=\s]+([A-Za-z][A-Za-z0-9_,-]*)")

# A repository path a `Load First` bullet tells the role to open. Any role whose
# MANDATORY/lazy load list names one is an investigative role for this
# invariant's purposes; a role that names none loads nothing.
_REPO_PATH_RE = re.compile(r"agent/[A-Za-z0-9_./*-]+")


def _prompt_sources() -> list[Path]:
    """The canonical prompt sources an operator or specialist reads.

    Generated client wrappers are excluded: they are copies of these files, so a
    drifted invocation in one of them is render drift, which render-check owns.
    """
    files: list[Path] = []
    files += sorted(AGENT_ROOT.glob("operator-core*.md"))
    files += sorted(AGENT_ROOT.glob("shared-constraints*.md"))
    files += sorted(ROSTER_DIR.glob("*.md"))
    files += sorted((AGENT_ROOT / "phases").glob("*.md"))
    files += sorted((AGENT_ROOT / "skills").glob("*/SKILL.md"))
    files += sorted((AGENT_ROOT / "rules").rglob("*.md"))
    files += sorted((AGENT_ROOT / "references").rglob("*.md"))
    files += sorted((AGENT_ROOT / "commands").glob("*.md"))
    specialist_core = AGENT_ROOT / "shared-specialist-core.md"
    if specialist_core.is_file():
        files.append(specialist_core)
    return files


def _load_first_section(text: str) -> str:
    """The role file's `## Load First` section, up to the next `## ` heading."""
    lines = text.splitlines()
    collected: list[str] = []
    inside = False
    for line in lines:
        if line.startswith("## "):
            if inside:
                break
            inside = line.strip().lower() == "## load first"
            continue
        if inside:
            collected.append(line)
    return "\n".join(collected)


def _zero_load_roles() -> set[str]:
    """Roster roles whose `Load First` section names no repository file."""
    zero_load: set[str] = set()
    for role_file in sorted(ROSTER_DIR.glob("*.md")):
        section = _load_first_section(role_file.read_text(encoding="utf-8"))
        if not section.strip():
            continue
        if not _REPO_PATH_RE.search(section):
            zero_load.add(role_file.stem)
    return zero_load


def _paragraphs(text: str) -> list[str]:
    """Blank-line-separated blocks — the window one invocation is written in.

    An `agent start` recipe is written either as one fenced command or as one
    prose paragraph naming the flags in sequence, so a blank-line block is the
    unit that holds a single invocation's flags together. Backticks become
    spaces so a flag written as an inline-code span reads the same as a flag
    written bare, without joining two adjacent tokens.
    """
    normalized = text.replace("`", " ")
    return [block for block in re.split(r"\n[ \t]*\n", normalized) if block.strip()]


def test_the_dispatcher_turns_a_named_skill_into_a_repository_path() -> None:
    """The harm this invariant guards is live in the renderer, not hypothetical.

    If `_dispatch_skill_lines` ever stops handing the specialist a repository
    path for a named skill, the invariant below is no longer load-bearing and
    should be re-derived rather than left passing vacuously.
    """
    rendered = "\n".join(_dispatch_skill_lines("blind-triage"))
    assert "agent/skills/blind-triage/SKILL.md" in rendered, rendered


def test_zero_load_roles_are_discoverable_and_not_the_whole_roster() -> None:
    roster = {path.stem for path in ROSTER_DIR.glob("*.md")}
    assert len(roster) > 10, f"roster discovery collapsed to {sorted(roster)}"
    zero_load = _zero_load_roles()
    assert zero_load, (
        "no roster role parsed as zero-load; the Load First parse drifted and "
        "the invariant below would pass vacuously"
    )
    assert zero_load < roster, (
        "every role parsed as zero-load, so the Load First parse is finding no "
        f"repository paths at all: {sorted(zero_load)}"
    )


def test_no_zero_load_role_is_dispatched_with_a_skill_to_read() -> None:
    zero_load = _zero_load_roles()
    assert zero_load

    sources = _prompt_sources()
    assert len(sources) > 50, (
        f"prompt-source discovery collapsed to {len(sources)} files; the "
        "invariant would pass vacuously"
    )

    offenders: list[str] = []
    for source in sources:
        relative = source.relative_to(REPO_ROOT)
        for block in _paragraphs(source.read_text(encoding="utf-8")):
            roles = {role for role in _ROLE_FLAG_RE.findall(block) if role in zero_load}
            if not roles:
                continue
            named_skills = [
                name
                for group in _SKILLS_FLAG_RE.findall(block)
                for name in group.split(",")
                if name
            ]
            for role in sorted(roles):
                for skill in named_skills:
                    rendered = "\n".join(_dispatch_skill_lines(skill))
                    offenders.append(
                        f"{relative}: --role {role} is dispatched with --skills "
                        f"{skill}, so the packet orders it to open "
                        f"agent/skills/{skill}/SKILL.md. Rendered by "
                        f"`agent start` as:\n    "
                        + "\n    ".join(rendered.splitlines())
                    )
    assert not offenders, (
        "A role whose `Load First` names no repository file is dispatched with "
        "a skill. `agent start` renders a mandatory-read order for every named "
        "skill and tells the agent the skill outranks the packet, so this "
        "dispatch instructs a zero-load role to read the repository. Drop "
        "`--skills` from the invocation, or give the role a standing load that "
        "makes the read admissible:\n  " + "\n  ".join(offenders)
    )
