"""Layer 3 — dispatch/handoff contract fidelity.

Grades agent-produced specialist dispatch payloads against the project's
``validate_specialist_dispatch_contract`` function from
``assess.lib.contracts``.

Valid contracts must produce zero errors.
Invalid contracts must surface the specific expected error(s).

The conftest in this directory inserts ``agent/scripts`` onto sys.path so
``assess.*`` is importable without extra dependencies.

Fixtures are embedded inline rather than in JSON files because the
``SpecialistDispatchContract`` dataclass fields and validation logic are
tightly coupled to documented error strings — keeping them in one file
makes the intent clear and diff noise low.
"""
from __future__ import annotations

import pytest

from assess.lib.contracts import (
    SPECIALIST_DISPATCH_MODES,
    validate_specialist_dispatch_contract,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _dispatch(payload: dict) -> tuple[list[str], list[str]]:
    """Convenience wrapper — returns (errors, warnings)."""
    return validate_specialist_dispatch_contract(payload)


# ---------------------------------------------------------------------------
# Valid: operator dispatch (no skills required; operator is exempt)
# ---------------------------------------------------------------------------


def test_valid_operator_dispatch_no_errors():
    """Operator role is exempt from skills; minimal dispatch must pass."""
    payload = {
        "role": "operator",
        "dispatch_mode": "hypothesis-driven",
    }
    errors, warnings = _dispatch(payload)
    assert errors == [], f"Unexpected errors: {errors}"


# ---------------------------------------------------------------------------
# Valid: vulnerability-analyst dispatch with skills
# ---------------------------------------------------------------------------


def test_valid_vuln_analyst_dispatch_no_errors():
    """vulnerability-analyst with a valid skill list and dispatch_mode passes."""
    payload = {
        "role": "vulnerability-analyst",
        "dispatch_mode": "item-iterating",
        "skills": ["sqli-testing", "xss-testing"],
    }
    errors, warnings = _dispatch(payload)
    assert errors == [], f"Unexpected errors: {errors}"


# ---------------------------------------------------------------------------
# Valid: exploit-developer dispatch (deep-manual mode)
# ---------------------------------------------------------------------------


def test_valid_exploit_developer_dispatch_no_errors():
    """exploit-developer with skills and deep-manual mode passes."""
    payload = {
        "role": "exploit-developer",
        "dispatch_mode": "deep-manual",
        "skills": ["exploit-playbook-authoring"],
        "requested_model": "claude-opus-4-5",
    }
    errors, warnings = _dispatch(payload)
    assert errors == [], f"Unexpected errors: {errors}"


# ---------------------------------------------------------------------------
# Valid: agent_role alias accepted
# ---------------------------------------------------------------------------


def test_valid_agent_role_alias_accepted():
    """Using ``agent_role`` instead of ``role`` is a valid alias."""
    payload = {
        "agent_role": "osint-analyst",
        "dispatch_mode": "hypothesis-driven",
        "skills": ["osint-recon"],
    }
    errors, warnings = _dispatch(payload)
    assert errors == [], f"Unexpected errors: {errors}"


# ---------------------------------------------------------------------------
# Valid: all dispatch_modes are accepted
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("mode", SPECIALIST_DISPATCH_MODES)
def test_all_dispatch_modes_accepted(mode: str):
    """Every documented dispatch_mode must be accepted."""
    payload = {
        "role": "vulnerability-analyst",
        "dispatch_mode": mode,
        "skills": ["sqli-testing"],
    }
    errors, warnings = _dispatch(payload)
    assert errors == [], f"dispatch_mode={mode!r} produced unexpected errors: {errors}"


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------


def test_missing_dispatch_mode_warns_and_defaults():
    """A missing dispatch_mode is no longer rejected (L2-1): it defaults from
    the role table and surfaces an advisory WARNING, never a hard error."""
    payload = {
        "role": "vulnerability-analyst",
        "skills": ["sqli-testing"],
    }
    errors, warnings = _dispatch(payload)
    assert not any("dispatch_mode" in e for e in errors), (
        f"missing dispatch_mode must not be a hard error, got: {errors}"
    )
    assert any("dispatch_mode" in w and "default" in w.lower() for w in warnings), (
        f"Expected a dispatch_mode defaulting warning, got: {warnings}"
    )


# ---------------------------------------------------------------------------
# Invalid: missing role (and no agent_role alias)
# ---------------------------------------------------------------------------


def test_missing_role_is_rejected():
    """A dispatch payload without role or agent_role must surface an error."""
    payload = {
        "dispatch_mode": "hypothesis-driven",
        "skills": ["sqli-testing"],
    }
    errors, warnings = _dispatch(payload)
    assert any("role" in e for e in errors), (
        f"Expected a role-missing error, got: {errors}"
    )


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------


def test_invalid_dispatch_mode_value_warns_not_rejected():
    """An unknown dispatch_mode is advisory (L2-4): it WARNS (listing the known
    modes) and proceeds, rather than hard-rejecting a possibly newly-coined
    mode."""
    payload = {
        "role": "vulnerability-analyst",
        "dispatch_mode": "fire-and-forget",
        "skills": ["sqli-testing"],
    }
    errors, warnings = _dispatch(payload)
    assert not any("fire-and-forget" in e for e in errors), (
        f"unknown dispatch_mode must not be a hard error, got: {errors}"
    )
    assert any("dispatch_mode" in w and "fire-and-forget" in w for w in warnings), (
        f"Expected a dispatch_mode advisory warning, got: {warnings}"
    )
    assert any("hypothesis-driven" in w for w in warnings), (
        f"Expected known modes listed in warning, got: {warnings}"
    )


# ---------------------------------------------------------------------------
# Invalid: specialist role without skills
# ---------------------------------------------------------------------------


def test_specialist_role_without_skills_warns_but_is_not_rejected():
    """Missing skills WARNs and proceeds; it never blocks a dispatch.

    A specialist picks its skills from what it observes on the surface, so the
    honest list is only known once the dispatch has run — requiring it up front
    forced the operator to guess a vulnerability class before the hunt.
    """
    payload = {
        "role": "vulnerability-analyst",
        "dispatch_mode": "hypothesis-driven",
    }
    errors, warnings = _dispatch(payload)
    assert not any("skills" in e.lower() for e in errors), (
        f"Missing skills must not error, got: {errors}"
    )
    assert any("skills" in w.lower() for w in warnings), (
        f"Expected a skills warning, got: {warnings}"
    )


# ---------------------------------------------------------------------------
# Invalid: role and agent_role mismatch
# ---------------------------------------------------------------------------


def test_role_and_agent_role_mismatch_is_rejected():
    """When both role and agent_role are present and differ, an error must fire."""
    payload = {
        "role": "vulnerability-analyst",
        "agent_role": "osint-analyst",
        "dispatch_mode": "hypothesis-driven",
        "skills": ["sqli-testing"],
    }
    errors, warnings = _dispatch(payload)
    assert any("role" in e and "agent_role" in e and "match" in e for e in errors), (
        f"Expected a role/agent_role mismatch error, got: {errors}"
    )


# ---------------------------------------------------------------------------
# Valid: application-unit attribution is optional dispatch metadata
# ---------------------------------------------------------------------------


def test_application_unit_identity_is_valid_dispatch_metadata():
    """Concrete unit attribution is metadata, never dispatch authorization."""
    payload = {
        "role": "vulnerability-analyst",
        "dispatch_mode": "item-iterating",
        "skills": ["sqli-testing"],
        "application_unit_id": 17,
    }
    errors, warnings = _dispatch(payload)
    assert errors == []
    assert not any("scope" in warning.lower() for warning in warnings)


def test_dispatch_contract_does_not_require_target_scope():
    """Dispatch admission is about the agent contract, not target authorization."""
    payload = {
        "role": "vulnerability-analyst",
        "dispatch_mode": "item-iterating",
        "skills": ["sqli-testing"],
    }
    errors, warnings = _dispatch(payload)
    assert errors == []
    assert not any("scope" in warning.lower() for warning in warnings)


# ---------------------------------------------------------------------------
# Valid: active specialist roles need no scope field
# ---------------------------------------------------------------------------


def test_vulnerability_analyst_dispatch_needs_no_scope_field():
    """A specialist dispatch carries an objective, not a scope declaration."""
    payload = {
        "role": "vulnerability-analyst",
        "dispatch_mode": "item-iterating",
        "skills": ["sqli-testing"],
    }
    errors, warnings = _dispatch(payload)
    assert errors == [], f"Unexpected errors: {errors}"


def test_exploit_developer_dispatch_needs_no_scope_field():
    """Exploit dispatch validation is independent of scope-shaping settings."""
    payload = {
        "role": "exploit-developer",
        "dispatch_mode": "deep-manual",
        "skills": ["sqli-testing"],
    }
    errors, _warnings = _dispatch(payload)
    assert errors == []


# ---------------------------------------------------------------------------
# Invalid: non-string role
# ---------------------------------------------------------------------------


def test_non_string_role_is_rejected():
    """role must be a string; an integer must surface a type error."""
    payload = {
        "role": 42,
        "dispatch_mode": "hypothesis-driven",
        "skills": ["sqli-testing"],
    }
    errors, warnings = _dispatch(payload)
    assert any("role" in e and "string" in e for e in errors), (
        f"Expected a role type error, got: {errors}"
    )


# ---------------------------------------------------------------------------
# Invalid: payload is not a dict (not a JSON object)
# ---------------------------------------------------------------------------


def test_non_dict_payload_is_rejected():
    """A non-dict payload must surface an immediate contract error."""
    errors, warnings = validate_specialist_dispatch_contract("not a dict")
    assert errors, "Expected errors for non-dict payload"
    assert any("object" in e.lower() for e in errors), (
        f"Expected 'must be a JSON object' error, got: {errors}"
    )
