"""Every role a prompt tells the operator to dispatch resolves in the roster.

`agent start` refuses a role that has no `agent/agents/<role>.md`, because the
packet renders "read agent/agents/<role>.md and its mandatory references before
work" into the launch envelope and a missing file means the dispatch runs with no
role prompt at all. The refusal is only as good as the agreement between that
roster and the prompts that name roles: `agent/skills/blind-triage/SKILL.md`
prescribes `--role general` for the Pass-2 reviewer that gates
`transition-phase report` / `complete` for every Medium-or-above finding, so a
role named there but absent from the roster makes the documented route to
satisfying that gate exit 1.

This is a structural invariant over two executable facts — the `--role <name>`
tokens the installed prompts emit, and the predicate `agent start` applies to
them — not an assertion about any file's wording.
"""
from __future__ import annotations

import re
from pathlib import Path
from types import SimpleNamespace

import pytest

from assess.commands.agent import (
    _require_registered_role,
    _role_roster_dir,
    _warn_undeclared_dispatch_mode,
)
from assess.lib import contracts
from assess.lib.contract_registry import DISPATCH_MODES_BY_ROLE, SPECIALIST_DISPATCH_MODES

REPO_ROOT = Path(__file__).resolve().parents[4]
AGENT_ROOT = REPO_ROOT / "agent"

# `--role <name>` as a literal invocation. A placeholder (`--role <role>`,
# `--role $ROLE`, `--role L1|L2`) is prose about the flag, not a role claim.
_ROLE_FLAG_RE = re.compile(r"--role\s+([A-Za-z][A-Za-z0-9_-]*)")


def _cfg() -> SimpleNamespace:
    return SimpleNamespace(
        agent_root=str(AGENT_ROOT),
        engagement_dir=str(AGENT_ROOT / "engagements" / "unused"),
    )


def _prompt_sources() -> list[Path]:
    """The canonical prompt sources an operator or specialist reads.

    Generated client wrappers are deliberately excluded: they are copies of
    these files, so a drifted role name in one of them is render drift, which
    render-check already owns.
    """
    files: list[Path] = []
    files += sorted(AGENT_ROOT.glob("operator-core*.md"))
    files += sorted(AGENT_ROOT.glob("shared-constraints*.md"))
    files += sorted((AGENT_ROOT / "agents").glob("*.md"))
    files += sorted((AGENT_ROOT / "phases").glob("*.md"))
    files += sorted((AGENT_ROOT / "skills").glob("*/SKILL.md"))
    files += sorted((AGENT_ROOT / "rules").rglob("*.md"))
    files += sorted((AGENT_ROOT / "references").rglob("*.md"))
    files += sorted((AGENT_ROOT / "commands").glob("*.md"))
    specialist_core = AGENT_ROOT / "shared-specialist-core.md"
    if specialist_core.is_file():
        files.append(specialist_core)
    return files


def test_role_roster_resolves_from_the_installed_agent_root() -> None:
    roster = _role_roster_dir(_cfg())
    assert roster is not None, (
        "the roster directory must resolve from agent_root, or the refusal "
        "degrades to a warning and nothing is checked"
    )
    assert sorted(path.stem for path in roster.glob("*.md")), roster


def test_every_role_named_in_a_prompt_source_is_dispatchable() -> None:
    sources = _prompt_sources()
    assert len(sources) > 50, (
        f"prompt-source discovery collapsed to {len(sources)} files; the "
        "invariant would pass vacuously"
    )

    roster = _role_roster_dir(_cfg())
    assert roster is not None
    registered = {path.stem for path in roster.glob("*.md")}

    named: dict[str, list[str]] = {}
    for source in sources:
        text = source.read_text(encoding="utf-8")
        for role in _ROLE_FLAG_RE.findall(text):
            named.setdefault(role, []).append(
                str(source.relative_to(REPO_ROOT))
            )
    assert named, "no --role invocation found in any prompt source"

    unregistered = {
        role: sorted(set(paths))
        for role, paths in sorted(named.items())
        if role not in registered
    }
    assert not unregistered, (
        "These roles are named in a `--role` invocation an operator is told to "
        "run, but `agent start` refuses them because they have no prompt under "
        "agent/agents/. Add the role prompt or correct the invocation:\n  "
        + "\n  ".join(
            f"{role}: named in {', '.join(paths)}"
            for role, paths in unregistered.items()
        )
    )


@pytest.mark.parametrize(
    "skill_relative, role",
    [("agent/skills/blind-triage/SKILL.md", "general")],
)
def test_the_gating_skill_reviewer_role_passes_the_start_predicate(
    skill_relative: str, role: str
) -> None:
    """The blind-triage reviewer role clears the exact `agent start` gate.

    `transition-phase report` and `complete` hard-block every Medium-or-above
    finding on a recorded blind-triage Accept, so this role is on the only
    documented path to a published report. The predicate — not a grep of the
    roster — is what the operator actually hits.
    """
    skill = REPO_ROOT / skill_relative
    assert skill.is_file(), skill_relative
    assert f"--role {role}" in skill.read_text(encoding="utf-8"), (
        f"{skill_relative} no longer prescribes --role {role}; this case must "
        "track the role the skill actually names"
    )
    _require_registered_role({"agent_role": role}, _cfg())


# The iteration modes a role prompt describes: the backticked modes between its
# "**Iteration mode:**" label and "**Default when omitted:**".
_ITERATION_MODES_RE = re.compile(r"\*\*Iteration mode:\*\*(?P<modes>.*?)\*\*Default when omitted", re.S)
_DEFAULT_MODE_RE = re.compile(r"Default when omitted:\*\*\s*`([a-z-]+)`")


def test_every_role_prompt_declares_the_modes_the_registry_names() -> None:
    """`agent start` warns from DISPATCH_MODES_BY_ROLE; each role prompt must
    describe exactly those modes, defaulting to the first, so the warning and
    the guidance the specialist reads agree."""
    roster = _role_roster_dir(_cfg())
    assert roster is not None
    roles = {path.stem for path in roster.glob("*.md")}
    assert set(DISPATCH_MODES_BY_ROLE) == roles
    for role_file in sorted(roster.glob("*.md")):
        text = role_file.read_text(encoding="utf-8")
        declared = _ITERATION_MODES_RE.search(text)
        assert declared, f"{role_file.name} has no Iteration mode declaration"
        modes = tuple(re.findall(r"`([a-z-]+)`", declared.group("modes")))
        registered = DISPATCH_MODES_BY_ROLE[role_file.stem]
        assert modes == registered, role_file.name
        assert set(registered) <= set(SPECIALIST_DISPATCH_MODES), role_file.name
        default = _DEFAULT_MODE_RE.search(text)
        assert default and default.group(1) == registered[0], role_file.name


def test_an_omitted_dispatch_mode_resolves_to_the_role_declared_default() -> None:
    """`agent start` without --dispatch-mode records the first mode the role
    declares, which the role prompt's "Default when omitted" line names (pinned
    above), so a role added to the registry never falls through to the generic
    fallback."""
    for role, modes in DISPATCH_MODES_BY_ROLE.items():
        assert contracts.default_dispatch_mode_for_role(role) == modes[0], role
        assert contracts.default_dispatch_mode_for_role(role.title()) == modes[0], role


@pytest.mark.parametrize(("mode", "warned"), [("item-iterating", True),
                                              ("deep-manual", False), ("swarm", False)])
def test_an_undeclared_dispatch_mode_is_named_with_the_role_declaration(
    capsys, mode: str, warned: bool
) -> None:
    _warn_undeclared_dispatch_mode(
        {"agent_role": "code-architect", "dispatch_mode": mode}, _cfg()
    )
    err = capsys.readouterr().err
    if not warned:
        assert err == ""
        return
    assert "dispatch_mode 'item-iterating'" in err
    assert "hypothesis-driven, deep-manual" in err
    assert "code-architect.md" in err


def test_the_undeclared_mode_warning_reads_the_registry_not_the_prompt(
    capsys, tmp_path: Path
) -> None:
    """A roster whose prompt carries no parseable declaration still warns."""
    roster = tmp_path / "agent" / "agents"
    roster.mkdir(parents=True)
    (roster / "code-architect.md").write_text("# Acme role prompt\n", encoding="utf-8")
    cfg = SimpleNamespace(
        agent_root=str(tmp_path / "agent"),
        engagement_dir=str(tmp_path / "agent" / "engagements" / "unused"),
    )

    _warn_undeclared_dispatch_mode(
        {"agent_role": "code-architect", "dispatch_mode": "item-iterating"}, cfg
    )

    assert "hypothesis-driven, deep-manual" in capsys.readouterr().err
