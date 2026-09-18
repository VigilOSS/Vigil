"""`finding record` holds its payload to the contract the backend enforces.

Two record-time axes the CLI did not own:

1. ``verification_status``. ``finding-record.schema.json`` lists all seven
   values because it also validates STORED and captured records, but the create
   request model pins ``Literal["unreviewed"]`` — so a payload that opened at
   ``confirmed`` cleared client validation and came back a 422 with no pointer
   at ``finding verify``, which is the verb that owns every other transition
   (and its evidence gates).
2. ``evidence_type``. ``finding update`` has had ``--evidence-type`` since the
   column landed; ``finding record`` had no flag at all, so the label could only
   be set by hand-editing the JSON payload.

Plus the client half of the ``chain_required`` -> ``chain_rationale`` pair gate:
the schema now carries the same if/then the backend enforces, so the refusal
lands before the POST.
"""
from __future__ import annotations

import argparse

import pytest

from assess.commands import record_finding
from assess.lib.schema_validation import collect_validation_errors


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    record_finding.register(parser.add_subparsers(dest="command"))
    return parser


def _normalize(payload: dict, **kwargs):
    return record_finding._normalize_payload(
        payload, agent_name="hunter-a", candidate_slug="VA-001", **kwargs
    )


@pytest.mark.parametrize(
    "status",
    ["confirmed", "downgraded", "disputed", "pending_runtime_proof", "blocked", "false_positive"],
)
def test_record_refuses_a_verification_status_the_backend_would_reject(status, capsys) -> None:
    with pytest.raises(SystemExit) as exit_info:
        _normalize({"title": "Missing authorization", "verification_status": status})

    assert exit_info.value.code == 1
    err = capsys.readouterr().err
    assert status in err
    assert "finding verify" in err


def test_record_still_accepts_an_explicit_unreviewed() -> None:
    payload = _normalize({"title": "Missing authorization", "verification_status": "unreviewed"})

    assert payload["verification_status"] == "unreviewed"


def test_record_accepts_an_evidence_type_flag() -> None:
    args = _parser().parse_args(
        ["record", "vulnerability-analyst", "f.json", "--evidence-type", "theoretical"]
    )

    assert args.evidence_type == "theoretical"


def test_the_evidence_type_flag_lands_on_the_payload() -> None:
    payload = _normalize({"title": "Blind SQLi"}, evidence_type="theoretical")

    assert payload["evidence_type"] == "theoretical"


def test_evidence_type_stays_absent_when_nobody_labels_it() -> None:
    payload = _normalize({"title": "Blind SQLi"})

    assert "evidence_type" not in payload


def test_a_flag_that_contradicts_the_payload_is_refused(capsys) -> None:
    with pytest.raises(SystemExit) as exit_info:
        _normalize(
            {"title": "Blind SQLi", "evidence_type": "code-inferred"},
            evidence_type="theoretical",
        )

    assert exit_info.value.code == 1
    err = capsys.readouterr().err
    assert "code-inferred" in err and "theoretical" in err


def test_a_flag_that_restates_the_payload_is_accepted() -> None:
    payload = _normalize(
        {"title": "Blind SQLi", "evidence_type": "theoretical"}, evidence_type="theoretical"
    )

    assert payload["evidence_type"] == "theoretical"


def test_the_schema_holds_chain_required_to_its_rationale() -> None:
    """The client mirror of ``_validate_chain_rationale_pair`` (backend)."""
    payload = {
        "title": "Internal host reachable from the URL parser",
        "severity": "medium",
        "workflow_status": "active",
        "verification_status": "unreviewed",
        "defect_family": "ssrf",
        "root_cause_key": "",
        "auth_context": "anonymous",
        "canonical_location": "https://app.example/fetch",
        "summary": "Summary",
        "evidence_ref": "",
        "notes": "",
        "details": {"evidence": "proof", "impact": "impact", "chain_required": True},
    }

    errors = collect_validation_errors(payload, record_finding._FINDING_SCHEMA)
    assert any("chain_rationale" in error for error in errors), errors

    payload["details"]["chain_rationale"] = "Reaches the metadata service once VA-002 lands."
    assert collect_validation_errors(payload, record_finding._FINDING_SCHEMA) == []

    # An explicit "this stands alone" is not dragged in with the flag's presence.
    payload["details"] = {"evidence": "proof", "impact": "impact", "chain_required": False}
    assert collect_validation_errors(payload, record_finding._FINDING_SCHEMA) == []
