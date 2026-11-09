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
# Valid: one row per documented dispatch shape, each must pass unchanged
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "payload",
    [
        # Operator role is exempt from skills; minimal dispatch must pass.
        pytest.param(
            {"role": "operator", "dispatch_mode": "hypothesis-driven"},
            id="operator_dispatch",
        ),
        # vulnerability-analyst with a valid skill list and dispatch_mode passes.
        pytest.param(
            {
                "role": "vulnerability-analyst",
                "dispatch_mode": "item-iterating",
                "skills": ["sqli-testing", "xss-testing"],
            },
            id="vuln_analyst_dispatch",
        ),
        # exploit-developer with skills and deep-manual mode passes.
        pytest.param(
            {
                "role": "exploit-developer",
                "dispatch_mode": "deep-manual",
                "skills": ["exploit-playbook-authoring"],
                "requested_model": "claude-opus-4-5",
            },
            id="exploit_developer_dispatch",
        ),
        # Using ``agent_role`` instead of ``role`` is a valid alias.
        pytest.param(
            {
                "agent_role": "osint-analyst",
                "dispatch_mode": "hypothesis-driven",
                "skills": ["osint-recon"],
            },
            id="agent_role_alias",
        ),
    ],
)
def test_valid_dispatch_no_errors(payload: dict):
    """Every documented valid dispatch shape must produce zero errors."""
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
# Valid: dispatch admission never depends on a scope declaration
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "payload",
    [
        # Concrete unit attribution is metadata, never dispatch authorization.
        pytest.param(
            {
                "role": "vulnerability-analyst",
                "dispatch_mode": "item-iterating",
                "skills": ["sqli-testing"],
                "application_unit_id": 17,
            },
            id="application_unit_identity_is_dispatch_metadata",
        ),
        # Dispatch admission is about the agent contract, not target authorization.
        # A specialist dispatch carries an objective, not a scope declaration.
        pytest.param(
            {
                "role": "vulnerability-analyst",
                "dispatch_mode": "item-iterating",
                "skills": ["sqli-testing"],
            },
            id="vulnerability_analyst_needs_no_scope_field",
        ),
        # Exploit dispatch validation is independent of scope-shaping settings.
        pytest.param(
            {
                "role": "exploit-developer",
                "dispatch_mode": "deep-manual",
                "skills": ["sqli-testing"],
            },
            id="exploit_developer_needs_no_scope_field",
        ),
    ],
)
def test_dispatch_contract_does_not_require_target_scope(payload: dict):
    """Dispatch admission is about the agent contract, not target authorization."""
    errors, warnings = _dispatch(payload)
    assert errors == [], f"Unexpected errors: {errors}"
    assert not any("scope" in warning.lower() for warning in warnings)


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
