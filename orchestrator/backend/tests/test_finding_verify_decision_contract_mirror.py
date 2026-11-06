"""The CLI's decision-file rosters mirror the backend verification models.

Agent code cannot import the backend package, so `finding verify` pre-checks
each structured decision document against a hand-written mirror. A field that
drifts from the model either hides it from every agent reading the error or
teaches a document the API refuses with a bare 422.
"""
from __future__ import annotations

from typing import get_args

from annotated_types import MaxLen

from app.api.assessment import (
    FindingConfirmCheckRequest,
    FindingCounterCheckRequest,
    FindingSeverityVarianceRequest,
)
from app.services.state_manager.proofs import TERMINAL_VERIFICATION_STATUSES
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


def test_every_decision_field_is_required_by_both_sides() -> None:
    """The pre-check reports a missing field, so neither side may default one."""
    for field_name, model in _MODELS.items():
        assert not [
            name for name, field in model.model_fields.items() if not field.is_required()
        ], field_name
        assert decision_problems(field_name, {}) == [
            f"{field_name}.{name} is required"
            for name, _kind, _bound in _DECISION_FIELDS[field_name]
        ]


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
    assert _SEVERITY_BANDS == get_args(annotation)


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
