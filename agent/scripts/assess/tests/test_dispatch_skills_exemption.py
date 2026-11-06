"""A role that is told to name no skills is not warned for naming none.

The `skills` warning exists so a dispatch row is a truthful audit of the
specialist context a role loaded. Two roles have nothing to audit, for opposite
reasons: `operator` coordinates phases rather than executing a skill, and
`general` is the blind packet reviewer whose whole premise is that it loads
nothing -- `agent/skills/blind-triage/SKILL.md` instructs the operator to name
no `--skills` on that dispatch, precisely because `agent start` renders a
"you MUST read and follow <skill>" line for every skill named, and this role's
defining rule is that it reads no repository file.

So for `general` the warning advises the one thing the gating skill forbids.
These drive the real predicate rather than asserting the exempt set, so the
roles stay in step with what the CLI actually does.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from assess.lib.contracts import validate_specialist_dispatch_contract


def _skill_warnings(role: str) -> list[str]:
    errors, warnings = validate_specialist_dispatch_contract(
        {
            "agent_role": role,
            "role": role,
            "task": "review the supplied packet and return a verdict",
            "dispatch_mode": "deep-manual",
        }
    )
    assert errors == [], errors
    return [w for w in warnings if "skills not set" in w]


def test_the_blind_reviewer_is_not_told_to_name_a_skill_it_must_not_read() -> None:
    assert _skill_warnings("general") == []


def test_the_operator_keeps_its_own_exemption() -> None:
    assert _skill_warnings("operator") == []


def test_an_investigative_specialist_is_still_warned() -> None:
    # The warning is load-bearing for every role that does load context: a
    # blanket exemption would retire the skill audit rather than scope it.
    assert len(_skill_warnings("code-vuln-hunter")) == 1
