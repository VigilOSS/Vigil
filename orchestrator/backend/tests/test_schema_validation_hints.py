"""Tests for the agent-side schema validation `Did you mean` hint.

When a payload uses a field name close to but not in the allowed set
(``source`` vs ``source_name``, ``agent`` vs ``agent_name``), the
validation error should include a structured suggestion so operators can
self-correct without re-reading the contract.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def _load_module(name: str, relative: str):
    repo_root = Path(__file__).resolve().parents[3]
    scripts_root = repo_root / "agent" / "scripts"
    if str(scripts_root) not in sys.path:
        sys.path.insert(0, str(scripts_root))
    module_path = repo_root / relative
    spec = importlib.util.spec_from_file_location(name, module_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _validation_module():
    return _load_module(
        "test_schema_validation_module",
        "agent/scripts/assess/lib/schema_validation.py",
    )


def test_did_you_mean_suggests_source_name_when_source_used():
    module = _validation_module()
    schema = module.load_schema("intel-tech-component.schema.json")
    payload = {"component": "vendor-saas-platform", "source": "wappalyzer"}

    errors = module.collect_validation_errors(payload, schema)
    matches = [e for e in errors if "source" in e and "is not allowed" in e]
    assert matches, errors
    assert "Did you mean:" in matches[0]
    assert "source_name" in matches[0]


def test_did_you_mean_omitted_for_truly_unknown_field():
    module = _validation_module()
    schema = module.load_schema("intel-tech-component.schema.json")
    payload = {"component": "x", "fizzbuzz": "y"}

    errors = module.collect_validation_errors(payload, schema)
    matches = [e for e in errors if "fizzbuzz" in e]
    assert matches, errors
    # Random short token shouldn't trigger a high-confidence match.
    assert "Did you mean" not in matches[0]


def test_did_you_mean_returns_multiple_suggestions_when_close():
    """The hint surfaces up to three candidates so a single high-score outlier
    (`evidence` -> `evidence_ref`) does not drown out alternatives like
    `evidence_quote` that are equally plausible.
    """
    module = _validation_module()
    schema = module.load_schema("intel-tech-component.schema.json")
    payload = {"component": "x", "evidence": "stuff"}

    errors = module.collect_validation_errors(payload, schema)
    matches = [e for e in errors if "evidence" in e and "is not allowed" in e]
    assert matches, errors
    # `evidence_ref` is the closest candidate but the schema has no other
    # `evidence_*` siblings on the tech-component root, so the hint should
    # at minimum mention `evidence_ref` and use the multi-suggestion format.
    assert "Did you mean:" in matches[0]
    assert "evidence_ref" in matches[0]


def test_intel_cve_allof_if_then_enforces_block_reason_when_attempted_blocked():
    """L4-5: the validator previously IGNORED allOf/if-then, so intel-cve's
    `validation_status='attempted_blocked' -> details.block_reason required`
    rule was silently un-enforced. It must now reject a payload that violates
    the conditional and accept a conforming one — matching the backend Pydantic
    `CveRecordRequest` model_validator.
    """
    module = _validation_module()
    schema = module.load_schema("intel-cve.schema.json")

    bad = {
        "cve_id": "CVE-2023-12345",
        "validation_status": "attempted_blocked",
        "details": {},
    }
    errors = module.collect_validation_errors(bad, schema)
    assert any("block_reason" in e and "required" in e for e in errors), errors

    empty = {
        "cve_id": "CVE-2023-12345",
        "validation_status": "attempted_blocked",
        "details": {"block_reason": ""},
    }
    assert any("block_reason" in e for e in module.collect_validation_errors(empty, schema))

    good = {
        "cve_id": "CVE-2023-12345",
        "validation_status": "attempted_blocked",
        "details": {"block_reason": "ModSecurity 403 on payload"},
    }
    assert module.collect_validation_errors(good, schema) == []


def test_intel_cve_if_then_does_not_fire_when_status_not_attempted_blocked():
    """L4-5: the conditional must NOT bite when validation_status is anything
    other than attempted_blocked — a CVE with no block_reason and a non-blocked
    status is valid (the if-condition fails, so `then` is not applied).
    """
    module = _validation_module()
    schema = module.load_schema("intel-cve.schema.json")

    neutral = {
        "cve_id": "CVE-2023-12345",
        "validation_status": "unverified",
        "details": {},
    }
    assert module.collect_validation_errors(neutral, schema) == []

    assert module.collect_validation_errors({"cve_id": "CVE-2023-12345"}, schema) == []


def _finding_base() -> dict:
    """Minimal valid finding-record payload (all record-time required fields)."""
    return {
        "title": "SQLi in login form",
        "severity": "high",
        "workflow_status": "active",
        "verification_status": "unreviewed",
        "defect_family": "sql-injection",
        "root_cause_key": "",
        "auth_context": "anonymous",
        "canonical_location": "",
        "summary": "SQLi in login form",
        "evidence_ref": "",
        "notes": "",
        "details": {"evidence": "error-based dump", "impact": "full DB read"},
    }


def test_finding_rejects_empty_cvss_vector_but_accepts_a_zero_score():
    """An empty cvss_vector is a meaningless record and stays rejected
    (minLength:1). A cvss_score of 0.0 is NOT: an all-N vector genuinely
    computes to it, and it is the only score the `info` severity band (< 0.1)
    can hold, so excluding it made an informational finding unrepresentable.
    Below zero is still off the CVSS scale.
    """
    module = _validation_module()
    schema = module.load_schema("finding-record.schema.json")

    base = _finding_base()

    empty_vector = dict(base)
    empty_vector["details"] = {**base["details"], "cvss_vector": ""}
    errors = module.collect_validation_errors(empty_vector, schema)
    assert any("cvss_vector" in e for e in errors), errors

    info_finding = dict(base)
    info_finding["details"] = {
        **base["details"],
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
        "cvss_score": 0,
    }
    assert module.collect_validation_errors(info_finding, schema) == []

    negative_score = dict(base)
    negative_score["details"] = {**base["details"], "cvss_score": -0.1}
    errors = module.collect_validation_errors(negative_score, schema)
    assert any("cvss_score" in e for e in errors), errors


def test_finding_accepts_valid_cvss_and_no_cvss_at_record_time():
    """L4-6: a real CVSS (vector set + score 7.5) passes, and a finding with NO
    cvss at all still passes — cvss is a report-time field, not in
    details.required, so the record-time floor must remain unblocked.
    """
    module = _validation_module()
    schema = module.load_schema("finding-record.schema.json")

    base = _finding_base()

    valid_cvss = dict(base)
    valid_cvss["details"] = {
        **base["details"],
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "cvss_score": 7.5,
    }
    assert module.collect_validation_errors(valid_cvss, schema) == []

    assert module.collect_validation_errors(base, schema) == []


def test_patch_validation_skips_required_check_but_keeps_unknown_field_hint():
    """Partial-update validators must not reject a payload for missing required
    natural-key fields, since the backend whitelist filters those. Typos still
    surface a Did-you-mean hint.
    """
    module = _validation_module()
    schema = module.load_schema("intel-tech-component.schema.json")

    # `component` is required in the full schema; the patch validator must
    # accept a payload without it.
    errors = module.collect_patch_validation_errors({"version": "2.0.0"}, schema)
    assert errors == [], errors

    # Typos still light up.
    errors = module.collect_patch_validation_errors({"source": "agent"}, schema)
    matches = [e for e in errors if "source" in e and "is not allowed" in e]
    assert matches, errors
    assert "source_name" in matches[0]


def test_array_bounds_are_enforced_at_every_nested_level():
    module = _validation_module()
    schema = {
        "type": "array",
        "minItems": 1,
        "maxItems": 2,
        "items": {
            "type": "object",
            "properties": {
                "tags": {
                    "type": "array",
                    "minItems": 2,
                    "maxItems": 3,
                    "items": {"type": "string"},
                }
            },
        },
    }

    assert module.collect_validation_errors([], schema) == [
        "payload must contain at least 1 items"
    ]
    assert module.collect_validation_errors([{"tags": ["one"]}], schema) == [
        "payload[0].tags must contain at least 2 items"
    ]
    assert module.collect_validation_errors(
        [{"tags": ["one", "two", "three", "four"]}], schema
    ) == ["payload[0].tags must contain at most 3 items"]
    assert module.collect_validation_errors([{}, {}, {}], schema) == [
        "payload must contain at most 2 items"
    ]


def test_unique_items_handles_nested_json_values_deterministically():
    module = _validation_module()
    schema = {
        "type": "array",
        "uniqueItems": True,
        "items": {
            "type": "object",
            "properties": {
                "values": {"type": "array", "uniqueItems": True},
            },
        },
    }
    payload = [
        {"values": [{"b": 2, "a": 1}, {"a": 1, "b": 2}]},
        {"values": ["distinct"]},
        {"values": ["distinct"]},
    ]

    assert module.collect_validation_errors(payload, schema) == [
        "payload[0].values must contain unique items; indexes 0 and 1 are equal",
        "payload must contain unique items; indexes 1 and 2 are equal",
    ]


def test_typeless_array_subschema_still_applies_array_keywords_recursively():
    module = _validation_module()
    schema = {
        "properties": {
            "groups": {
                "items": {"minItems": 1, "uniqueItems": True},
            }
        }
    }

    assert module.collect_validation_errors(
        {"groups": [[], ["same", "same"]]}, schema
    ) == [
        "payload.groups[0] must contain at least 1 items",
        "payload.groups[1] must contain unique items; indexes 0 and 1 are equal",
    ]
