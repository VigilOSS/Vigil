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

import json
import tempfile
from pathlib import Path

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


def _dispatch_with_engagement(payload: dict, scope_hosts: list[str]) -> tuple[list[str], list[str]]:
    """Run the validator with a synthetic engagement dir + scope.json.

    Creates a temp directory with a minimal scope.json so the scope-gate
    logic fires. Cleaned up automatically after the call.

    Note: scope_entries() in scope.py only processes string items from the
    ``hosts`` list (dicts are silently skipped), so hosts must be plain strings.
    """
    scope_json = {
        "name": "eval-test-scope",
        "description": "Eval harness synthetic scope",
        "hosts": scope_hosts,
    }
    with tempfile.TemporaryDirectory() as tmpdir:
        scope_path = Path(tmpdir) / "scope.json"
        scope_path.write_text(json.dumps(scope_json), encoding="utf-8")
        return validate_specialist_dispatch_contract(payload, engagement_dir=tmpdir)


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
        "scope_host": "target.example",
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
        "scope_host": "target.example",
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
# Invalid: missing dispatch_mode
# ---------------------------------------------------------------------------


def test_missing_dispatch_mode_is_rejected():
    """A dispatch payload without dispatch_mode must surface the missing-field error."""
    payload = {
        "role": "vulnerability-analyst",
        "skills": ["sqli-testing"],
    }
    errors, warnings = _dispatch(payload)
    assert any("dispatch_mode" in e for e in errors), (
        f"Expected a dispatch_mode error, got: {errors}"
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
# Invalid: bad dispatch_mode value
# ---------------------------------------------------------------------------


def test_invalid_dispatch_mode_value_is_rejected():
    """An unknown dispatch_mode value must surface an error listing valid modes."""
    payload = {
        "role": "vulnerability-analyst",
        "dispatch_mode": "fire-and-forget",
        "skills": ["sqli-testing"],
    }
    errors, warnings = _dispatch(payload)
    assert any("dispatch_mode" in e and "fire-and-forget" in e for e in errors), (
        f"Expected a dispatch_mode enum error, got: {errors}"
    )
    # Error must mention the valid modes
    assert any("hypothesis-driven" in e for e in errors), (
        f"Expected valid modes listed in error, got: {errors}"
    )


# ---------------------------------------------------------------------------
# Invalid: specialist role without skills
# ---------------------------------------------------------------------------


def test_specialist_role_without_skills_is_rejected():
    """A non-operator specialist role with no skills must surface a skills error."""
    payload = {
        "role": "vulnerability-analyst",
        "dispatch_mode": "hypothesis-driven",
    }
    errors, warnings = _dispatch(payload)
    assert any("skills" in e and "required" in e.lower() for e in errors), (
        f"Expected a skills-required error, got: {errors}"
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
# Invalid: scope-gated role (vulnerability-analyst) with out-of-scope host
# ---------------------------------------------------------------------------


def test_scope_gated_role_out_of_scope_host_is_rejected():
    """vulnerability-analyst dispatched against a host not in scope.json must fail.

    This is the key regression guard: the scope-gate must catch active-probing
    dispatches targeting hosts that were found during recon but are not in scope.
    """
    payload = {
        "role": "vulnerability-analyst",
        "dispatch_mode": "item-iterating",
        "skills": ["sqli-testing"],
        "scope_host": "adjacent-domain-not-in-scope.example",
    }
    in_scope_hosts = ["target.example", "api.target.example"]
    errors, warnings = _dispatch_with_engagement(payload, in_scope_hosts)
    assert any("not in scope" in e or "scope_host" in e for e in errors), (
        f"Expected a scope_host error, got errors={errors}, warnings={warnings}"
    )


# ---------------------------------------------------------------------------
# Valid: scope-gated role with in-scope host passes
# ---------------------------------------------------------------------------


def test_scope_gated_role_in_scope_host_passes():
    """vulnerability-analyst dispatched against a host in scope.json must pass."""
    payload = {
        "role": "vulnerability-analyst",
        "dispatch_mode": "item-iterating",
        "skills": ["sqli-testing"],
        "scope_host": "target.example",
    }
    in_scope_hosts = ["target.example", "api.target.example"]
    errors, warnings = _dispatch_with_engagement(payload, in_scope_hosts)
    assert errors == [], f"Unexpected errors for in-scope host: {errors}"


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
