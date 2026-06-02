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


from assess.lib.schema_validation import collect_validation_errors, load_schema

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


def _load(filename: str) -> dict:
    return json.loads((_FIXTURES_DIR / filename).read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Positive: finding-record (schema examples — extracted verbatim)
# ---------------------------------------------------------------------------


def test_finding_record_schema_example_sqli_validates():
    """Schema example 1 (SQLi) must validate with zero errors."""
    schema = load_schema("finding-record.schema.json")
    payload = _load("finding_sqli.json")
    errors = collect_validation_errors(payload, schema)
    assert errors == [], f"Unexpected errors: {errors}"


def test_finding_record_schema_example_bof_validates():
    """Schema example 2 (heap BOF) patched to supply required fields validates."""
    schema = load_schema("finding-record.schema.json")
    payload = _load("finding_bof.json")
    errors = collect_validation_errors(payload, schema)
    assert errors == [], f"Unexpected errors: {errors}"


def test_finding_record_xss_validates():
    """Stored XSS finding fixture validates."""
    schema = load_schema("finding-record.schema.json")
    payload = _load("finding_xss.json")
    errors = collect_validation_errors(payload, schema)
    assert errors == [], f"Unexpected errors: {errors}"


# ---------------------------------------------------------------------------
# Positive: probe-run
# ---------------------------------------------------------------------------


def test_probe_run_validates():
    """Minimal valid probe-run payload validates with zero errors."""
    schema = load_schema("probe-run.schema.json")
    payload = _load("probe_run_valid.json")
    errors = collect_validation_errors(payload, schema)
    assert errors == [], f"Unexpected errors: {errors}"


# ---------------------------------------------------------------------------
# Positive: intel-cve
# ---------------------------------------------------------------------------


def test_intel_cve_validates():
    """Minimal valid intel-cve payload validates with zero errors."""
    schema = load_schema("intel-cve.schema.json")
    payload = _load("intel_cve_valid.json")
    errors = collect_validation_errors(payload, schema)
    assert errors == [], f"Unexpected errors: {errors}"


# ---------------------------------------------------------------------------
# Positive: attack-chain
# ---------------------------------------------------------------------------


def test_attack_chain_validates():
    """Minimal valid attack-chain payload validates with zero errors."""
    schema = load_schema("attack-chain.schema.json")
    payload = _load("attack_chain_valid.json")
    errors = collect_validation_errors(payload, schema)
    assert errors == [], f"Unexpected errors: {errors}"


# ---------------------------------------------------------------------------
# Negative: missing required top-level field (title)
# ---------------------------------------------------------------------------


def test_finding_record_missing_title_is_rejected():
    """A finding payload with no ``title`` must surface a required-field error."""
    schema = load_schema("finding-record.schema.json")
    payload = _load("neg_finding_missing_title.json")
    errors = collect_validation_errors(payload, schema)
    assert any("title" in e and "required" in e for e in errors), (
        f"Expected a 'title is required' error, got: {errors}"
    )


# ---------------------------------------------------------------------------
# Negative: bad enum value (severity="urgent" — not a real severity)
# ---------------------------------------------------------------------------


def test_finding_record_bad_severity_enum_is_rejected():
    """severity='urgent' must surface an enum validation error."""
    schema = load_schema("finding-record.schema.json")
    payload = _load("neg_finding_bad_severity.json")
    errors = collect_validation_errors(payload, schema)
    assert any("severity" in e and "must be one of" in e for e in errors), (
        f"Expected a severity enum error, got: {errors}"
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


# ---------------------------------------------------------------------------
# Negative: missing nested required field (details.evidence)
# ---------------------------------------------------------------------------


def test_finding_record_missing_details_evidence_is_rejected():
    """A finding payload missing ``details.evidence`` must surface a required error."""
    schema = load_schema("finding-record.schema.json")
    payload = _load("neg_finding_missing_details_evidence.json")
    errors = collect_validation_errors(payload, schema)
    assert any("evidence" in e and "required" in e for e in errors), (
        f"Expected 'details.evidence is required' error, got: {errors}"
    )
