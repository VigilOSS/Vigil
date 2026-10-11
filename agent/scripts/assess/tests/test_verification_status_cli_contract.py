from __future__ import annotations

import argparse

from assess.commands import list_findings, record_finding, verify_finding


def _parser(register) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    register(parser.add_subparsers(dest="command"))
    return parser


def test_finding_record_defaults_verification_status_to_unreviewed() -> None:
    payload = record_finding._normalize_payload(
        {"title": "Missing authorization"},
        agent_name="hunter-a",
        candidate_slug="VA-001",
    )

    assert payload["verification_status"] == "unreviewed"


def test_finding_list_exposes_verification_status_filter() -> None:
    parser = _parser(list_findings.register)

    args = parser.parse_args(["list", "--verification-status", "confirmed"])
    assert args.verification_status == "confirmed"


def test_finding_verify_exposes_status() -> None:
    parser = _parser(verify_finding.register)

    args = parser.parse_args(
        ["verify", "VA-001", "--status", "confirmed", "--reason", "reproduced"]
    )
    assert args.verification_status == "confirmed"


def test_finding_verify_exposes_structured_decision_evidence() -> None:
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
