"""Structural invariant: proof-bearing roles carry the proof/receipt lifecycle.

The proof and scan run lifecycle (proof-assignment authority, terminal-verdict
receipts, run sealing and resumption) lives in one reference module. A claimed
proof dispatch renders only the role's MANDATORY loads
(``proof_work._mandatory_load_lines``), so every role the backend admits for
proof work must list that module as MANDATORY or a claimed proof lane starts
without the rules that keep one receipt bound to one verification event.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from assess.commands.proof_work import _mandatory_load_lines
from assess.lib.prompt_census import census_role

AGENT_ROOT = Path(__file__).resolve().parents[3]
LIFECYCLE = "agent/references/specialist-proof-and-scan-lifecycle.md"


def test_the_lifecycle_module_is_a_regular_file():
    assert (AGENT_ROOT / LIFECYCLE.removeprefix("agent/")).is_file()


# The roles and routes `state_manager.proof_work` admits for claimed proof work.
@pytest.mark.parametrize(("role", "route"), [
    ("exploit-developer", "web"),
    ("exploit-developer", "code"),
    ("vulnerability-analyst", "web"),
    ("code-vuln-verifier", "code"),
])
def test_claimed_proof_work_renders_the_lifecycle_as_a_mandatory_load(role, route):
    rendered = _mandatory_load_lines(AGENT_ROOT, role, route)
    assert f"- {LIFECYCLE}" in rendered.splitlines()


def test_blue_verifier_loads_the_lifecycle_before_citing_receipts():
    # incident-verifier cites proof receipts on every terminal disposition.
    census = census_role(AGENT_ROOT, AGENT_ROOT / "agents" / "incident-verifier.md", None)
    paths = [ref["path"] for ref in census["mandatory_references"]]
    assert LIFECYCLE in paths
