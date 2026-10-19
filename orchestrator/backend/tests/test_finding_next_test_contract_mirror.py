"""The CLI's runtime proof plan roster mirrors ``FindingNextTestRequest``.

Agent code cannot import the backend package, so `finding verify --next-test-file`
pre-checks the plan against a hand-written mirror. A field or route hint that
drifts from the model either hides a field from every agent reading the
contract or teaches a plan the API refuses with a 422.
"""
from __future__ import annotations

from typing import get_args

from annotated_types import MaxLen

from app.api.assessment import FindingNextTestRequest
from app.services.state_manager import finding_next_tests
from assess.lib import contracts
from assess.lib.next_test import (
    NEXT_TEST_TEXT_MAX_LENGTH,
    OPTIONAL_NEXT_TEST_FIELDS,
    next_test_problems,
)


def test_documented_plan_fields_mirror_the_backend_model():
    assert [name for name, _, _ in contracts.NEXT_TEST_FIELDS] == list(
        FindingNextTestRequest.model_fields
    )


def test_route_hints_mirror_the_backend_literal():
    annotation = FindingNextTestRequest.model_fields["route_hint"].annotation
    assert contracts.NEXT_TEST_ROUTE_HINTS == get_args(annotation)


def test_the_cli_precheck_accepts_exactly_what_the_model_accepts():
    plan = {"hypothesis": "h", "confirm_if": "c", "falsify_if": "f", "route_hint": "unknown"}
    assert next_test_problems(plan) == []
    FindingNextTestRequest.model_validate(plan)


def test_the_storage_roster_mirrors_the_backend_model():
    assert finding_next_tests.NEXT_TEST_FIELDS == tuple(FindingNextTestRequest.model_fields)


def test_the_cli_precheck_mirrors_the_models_optional_fields_and_length_bound():
    fields = FindingNextTestRequest.model_fields
    assert OPTIONAL_NEXT_TEST_FIELDS == {
        name for name, field in fields.items() if not field.is_required()
    }
    text_bounds = {
        name: [item.max_length for item in field.metadata if isinstance(item, MaxLen)]
        for name, field in fields.items()
        if field.annotation is str
    }
    assert text_bounds == {
        name: [NEXT_TEST_TEXT_MAX_LENGTH]
        for name, field in fields.items()
        if field.annotation is str
    }
    assert set(text_bounds) == set(fields) - {"route_hint"}
