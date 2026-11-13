"""The CLI's decision-file rosters mirror the backend verification models.

Agent code cannot import the backend package, so `finding verify` pre-checks
each structured decision document against a hand-written mirror. A field that
drifts from the model either hides it from every agent reading the error or
teaches a document the API refuses with a bare 422.
"""
from __future__ import annotations

import re
from typing import get_args

import pytest
from annotated_types import MaxLen

from app.api.assessment import (
    FindingConfirmCheckRequest,
    FindingCounterCheckRequest,
    FindingSeverityVarianceRequest,
)
from app.services.state_manager.findings import _DERIVED_VARIANCE_FIELDS
from app.services.state_manager.proofs import TERMINAL_VERIFICATION_STATUSES
from assess.lib import contracts
from assess.lib.contract_registry import DECISION_CHECK_FIELDS
from assess.commands.verify_finding import (
    _DECISION_FIELDS,
    _SEVERITY_BANDS,
    _TERMINAL_STATUSES,
    decision_problems,
)

_MODELS = {
    "counter_check": FindingCounterCheckRequest,
    "confirm_check": FindingConfirmCheckRequest,
    "severity_variance": FindingSeverityVarianceRequest,
}


def test_each_decision_roster_mirrors_its_backend_model() -> None:
    for field_name, model in _MODELS.items():
        assert [name for name, _kind, _bound in _DECISION_FIELDS[field_name]] == list(
            model.model_fields
        ), field_name


def test_both_sides_require_the_same_decision_fields() -> None:
    """The pre-check reports exactly the fields the backend model requires.

    A severity variance requires only its reason; the backend derives the rest
    from the verification (ADR 0046).
    """
    for field_name, model in _MODELS.items():
        required = [name for name, field in model.model_fields.items() if field.is_required()]
        assert decision_problems(field_name, {}) == [
            f"{field_name}.{name} is required" for name in required
        ], field_name


def test_every_optional_variance_field_is_one_the_backend_derives() -> None:
    """A field the author may omit must be one the verification fills in;
    an optional field nothing derives would be stored empty and unattributed."""
    optional = {
        name
        for name, field in FindingSeverityVarianceRequest.model_fields.items()
        if not field.is_required()
    }
    assert optional == {"normal_band", "chosen_severity", "actor", "proof_receipt_id"}
    assert optional == set(_DERIVED_VARIANCE_FIELDS)


def test_text_length_bounds_mirror_the_backend_models() -> None:
    for field_name, model in _MODELS.items():
        declared = {
            name: bound
            for name, _kind, bound in _DECISION_FIELDS[field_name]
            if bound is not None
        }
        actual = {
            name: item.max_length
            for name, field in model.model_fields.items()
            for item in field.metadata
            if isinstance(item, MaxLen)
        }
        assert declared == actual, field_name


def test_the_severity_band_vocabulary_mirrors_the_variance_model() -> None:
    annotation = FindingSeverityVarianceRequest.model_fields["normal_band"].annotation
    (bands,) = [arg for arg in get_args(annotation) if arg is not type(None)]
    assert _SEVERITY_BANDS == get_args(bands)


def test_the_cli_terminal_statuses_mirror_the_backend_gate() -> None:
    assert _TERMINAL_STATUSES == TERMINAL_VERIFICATION_STATUSES


def test_the_precheck_accepts_exactly_what_each_model_accepts() -> None:
    documents = {
        "counter_check": {
            "method": "Trace the guarded source path",
            "expected_result": "attacker input reaches the sink",
            "observed_result": "every path is rejected before the sink",
            "falsified_claim": "attacker input reaches the sink",
            "completed": True,
            "proof_receipt_ids": [17],
        },
        "confirm_check": {
            "method": "Replay the claim against the expected guard",
            "attempted_falsification": "Check whether the guard defeats the claim",
            "expected_result": "The guard prevents the claimed outcome",
            "observed_result": "The claimed outcome still occurs",
            "completed": True,
            "proof_receipt_ids": [17],
        },
        "severity_variance": {
            "normal_band": "medium",
            "chosen_severity": "high",
            "actor": "code-vuln-verifier",
            "reason": "The exposed records trigger a contractual incident.",
            "proof_receipt_id": 17,
        },
    }
    for field_name, document in documents.items():
        assert decision_problems(field_name, document) == [], field_name
        _MODELS[field_name].model_validate(document)


@pytest.mark.parametrize("field_name", ["counter_check", "confirm_check"])
def test_the_contract_names_every_check_field_and_whether_it_is_required(field_name) -> None:
    """`contract finding verify --field <check>` is where a verifier learns the
    check's shape before writing it, so it lists every field the model takes
    and marks each one the model requires."""
    model = _MODELS[field_name]
    assert [name for name, _domain, _meaning in DECISION_CHECK_FIELDS[field_name]] == (
        list(model.model_fields)
    )
    text = contracts.render_field_sections("finding verify", [field_name])
    for name, field in model.model_fields.items():
        match = re.search(rf"\b{name} \(([^)]*)\)", text)
        assert match, (field_name, name, text)
        assert ("required" in match.group(1)) == field.is_required(), (name, match.group(1))
