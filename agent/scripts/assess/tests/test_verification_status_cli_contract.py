from __future__ import annotations

import argparse

import pytest

from assess.commands import list_findings, record_finding, verify_finding


def _parser(register) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    register(parser.add_subparsers(dest="command"))
    return parser


def test_finding_record_defaults_only_the_one_axis_status() -> None:
    payload = record_finding._normalize_payload(
        {"title": "Missing authorization"},
        agent_name="hunter-a",
        candidate_slug="VA-001",
    )

    assert payload["verification_status"] == "unreviewed"
    assert "verification_state" not in payload
    assert "verification_disposition" not in payload


def test_finding_list_exposes_only_verification_status_filter() -> None:
    parser = _parser(list_findings.register)

    args = parser.parse_args(["list", "--verification-status", "confirmed"])
    assert args.verification_status == "confirmed"

    with pytest.raises(SystemExit) as state_exit:
        parser.parse_args(["list", "--verification-state", "verified"])
    assert state_exit.value.code == 2

    with pytest.raises(SystemExit) as disposition_exit:
        parser.parse_args(["list", "--verification-disposition", "confirmed"])
    assert disposition_exit.value.code == 2


def test_finding_verify_exposes_status_without_disposition_alias() -> None:
    parser = _parser(verify_finding.register)

    args = parser.parse_args(
        ["verify", "VA-001", "--status", "confirmed", "--reason", "reproduced"]
    )
    assert args.verification_status == "confirmed"

    with pytest.raises(SystemExit) as legacy_exit:
        parser.parse_args(
            [
                "verify",
                "VA-001",
                "--disposition",
                "confirmed",
                "--reason",
                "reproduced",
            ]
        )
    assert legacy_exit.value.code == 2


def test_finding_verify_exposes_structured_decision_evidence_without_prose_kill_aliases() -> None:
    parser = _parser(verify_finding.register)

    args = parser.parse_args(
        [
            "verify",
            "VA-001",
            "--status",
            "confirmed",
            "--reason",
            "independent proof",
            "--proof-receipt-id",
            "17",
            "--proof-receipt-id",
            "18",
        ]
    )
    assert args.proof_receipt_ids == [17, 18]

    with pytest.raises(SystemExit) as legacy_exit:
        parser.parse_args(
            [
                "verify",
                "VA-001",
                "--status",
                "false_positive",
                "--reason",
                "not reproduced",
                "--kill-reason",
                "prose-only claim",
            ]
        )
    assert legacy_exit.value.code == 2
