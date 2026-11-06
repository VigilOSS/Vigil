"""The packet does not tell a no-skills role to pick skills and write a handoff.

`agent start` renders a skills block into every dispatch packet. With skills
named it emits a "you MUST read and follow <path>" line per skill; with none it
falls back to telling the specialist to self-select and to record the loaded
names in its handoff.

That fallback is wrong for the two roles the skills requirement exempts, and for
`general` it is wrong in the way that matters: the blind packet reviewer loads
nothing by design, makes no tool calls, and does not write the handoff -- the
operator does. A packet that tells it to self-select skills and record them
contradicts its own role prompt, which is the same defect as the one that made
`agent/skills/blind-triage/SKILL.md` name a skill the reviewer must not read.

These drive the real renderer, so the packet text stays in step with the exempt
set rather than being asserted twice.
"""
from __future__ import annotations

from assess.commands.agent import _dispatch_skill_lines


def test_the_blind_reviewer_is_not_told_to_self_select_or_record_skills() -> None:
    rendered = "\n".join(_dispatch_skill_lines(None, role="general"))

    assert "self-selected" not in rendered, rendered
    assert "record the loaded skill names" not in rendered, rendered
    # It still says something about skills, rather than leaving a silent gap
    # where every other role has a block.
    assert "skills:" in rendered, rendered


def test_a_specialist_that_omitted_skills_is_still_told_to_record_them() -> None:
    # The fallback is load-bearing for every role that does load context: the
    # dispatch row is the only audit of which skill a specialist actually used.
    rendered = "\n".join(_dispatch_skill_lines(None, role="code-vuln-hunter"))

    assert "self-selected" in rendered
    assert "record the loaded skill names" in rendered


def test_a_named_skill_still_renders_its_mandatory_read() -> None:
    rendered = "\n".join(
        _dispatch_skill_lines("okta-investigation", role="investigator")
    )

    assert "You MUST read and follow agent/skills/okta-investigation/SKILL.md" in rendered
