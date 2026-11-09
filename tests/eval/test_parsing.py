"""Layer 1 — schema/parsing fidelity.

Grades agent-produced payloads against the project's bundled JSON schemas
using only the existing ``assess.lib.schema_validation`` module
(``load_schema`` + ``collect_validation_errors``).

Positive fixtures must produce ZERO errors.
Negative fixtures must surface the EXPECTED validation error(s).

The conftest in this directory inserts ``agent/scripts`` onto sys.path so
``assess.*`` is importable without any extra dependencies.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from assess.lib.schema_validation import collect_validation_errors, load_schema

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


def _load(filename: str) -> dict:
    return json.loads((_FIXTURES_DIR / filename).read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Positive: one row per schema family, every fixture must validate cleanly
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("schema_name", "fixture"),
    [
        # finding-record: schema example 1 (SQLi).
        pytest.param("finding-record.schema.json", "finding_sqli.json", id="schema_example_sqli"),
        # finding-record: schema example 2 (heap BOF) patched to supply required fields.
        pytest.param("finding-record.schema.json", "finding_bof.json", id="schema_example_bof"),
        # finding-record: stored XSS finding fixture.
        pytest.param("finding-record.schema.json", "finding_xss.json", id="finding_xss"),
        # probe-run: minimal valid payload.
        pytest.param("probe-run.schema.json", "probe_run_valid.json", id="probe_run"),
        # intel-cve: minimal valid payload.
        pytest.param("intel-cve.schema.json", "intel_cve_valid.json", id="intel_cve"),
        # attack-chain: minimal valid payload.
        pytest.param("attack-chain.schema.json", "attack_chain_valid.json", id="attack_chain"),
    ],
)
def test_positive_fixture_validates(schema_name: str, fixture: str):
    """A positive fixture must validate against its schema with zero errors."""
    schema = load_schema(schema_name)
    payload = _load(fixture)
    errors = collect_validation_errors(payload, schema)
    assert errors == [], f"Unexpected errors: {errors}"


def test_finding_record_file_location_requires_snapshot_binding():
    schema = load_schema("finding-record.schema.json")
    payload = _load("finding_bof.json")
    payload["provenance"].pop("code_snapshot", None)

    errors = collect_validation_errors(payload, schema)

    assert any("provenance.code_snapshot is required" in error for error in errors)


def test_finding_record_file_location_rejects_null_snapshot_binding():
    schema = load_schema("finding-record.schema.json")
    payload = _load("finding_bof.json")
    payload["provenance"]["code_snapshot"] = None

    errors = collect_validation_errors(payload, schema)

    assert any("provenance.code_snapshot must be an object" in error for error in errors)


def test_finding_record_whitespace_prefixed_file_location_requires_snapshot_binding():
    schema = load_schema("finding-record.schema.json")
    payload = _load("finding_bof.json")
    payload["canonical_location"] = "  file:src/parser.c:41"
    payload["provenance"].pop("code_snapshot", None)

    errors = collect_validation_errors(payload, schema)

    assert any("provenance.code_snapshot is required" in error for error in errors)


def test_finding_record_snapshot_digest_must_be_lowercase_sha256():
    schema = load_schema("finding-record.schema.json")
    payload = _load("finding_bof.json")
    payload["provenance"]["code_snapshot"]["source_manifest_digest"] = "A" * 64

    errors = collect_validation_errors(payload, schema)

    assert any("source_manifest_digest" in error and "pattern" in error for error in errors)


# ---------------------------------------------------------------------------
# Negative: a required-or-enum violation must name the offending field
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("fixture", "expected_substrings"),
    [
        # Missing required top-level field: expect a 'title is required' error.
        pytest.param(
            "neg_finding_missing_title.json",
            ("title", "required"),
            id="finding_record_missing_title",
        ),
        # Bad enum value (severity="urgent" — not a real severity).
        pytest.param(
            "neg_finding_bad_severity.json",
            ("severity", "must be one of"),
            id="finding_record_bad_severity_enum",
        ),
        # Missing nested required field: expect a 'details.evidence is required' error.
        pytest.param(
            "neg_finding_missing_details_evidence.json",
            ("evidence", "required"),
            id="finding_record_missing_details_evidence",
        ),
    ],
)
def test_negative_fixture_is_rejected(fixture: str, expected_substrings: tuple[str, ...]):
    """A negative fixture must surface one error carrying every expected substring."""
    schema = load_schema("finding-record.schema.json")
    payload = _load(fixture)
    errors = collect_validation_errors(payload, schema)
    assert any(all(part in e for part in expected_substrings) for e in errors), (
        f"Expected an error containing {expected_substrings}, got: {errors}"
    )


# ---------------------------------------------------------------------------
# Negative: wrong type (severity is integer instead of string)
# ---------------------------------------------------------------------------


def test_finding_record_wrong_type_severity_is_rejected():
    """severity=9 (integer) must surface a type error."""
    schema = load_schema("finding-record.schema.json")
    payload = _load("neg_finding_wrong_type.json")
    errors = collect_validation_errors(payload, schema)
    assert any("severity" in e and ("string" in e or "one of" in e) for e in errors), (
        f"Expected a severity type error, got: {errors}"
    )


# ---------------------------------------------------------------------------
# Negative: unknown field that should trigger "did you mean" hint
# ---------------------------------------------------------------------------


def test_finding_record_unknown_field_did_you_mean():
    """'evidnce' (typo for 'evidence') in details triggers a did-you-mean hint."""
    schema = load_schema("finding-record.schema.json")
    payload = _load("neg_finding_unknown_field.json")
    errors = collect_validation_errors(payload, schema)
    # Must flag the unknown field
    unknown_errors = [e for e in errors if "evidnce" in e and "not allowed" in e]
    assert unknown_errors, f"Expected 'not allowed' error for 'evidnce', got: {errors}"
    # Must include a did-you-mean hint
    assert any("Did you mean" in e for e in unknown_errors), (
        f"Expected 'Did you mean' hint in error, got: {unknown_errors}"
    )
