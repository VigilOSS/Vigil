"""Status and label words fold case and separator at the CLI door too.

The backend folds `Blocked`, `pending-runtime-proof` and `in_progress` to the one
canonical word each names (`folded_vocabulary`); a CLI that refused them first
made the contract's folding note false for anyone typing the command. Every
folded flag and payload word lands as the canonical spelling, and a word
outside the vocabulary is still refused.
"""
from __future__ import annotations

import argparse

import pytest

from assess.commands import agent, record_finding, update_finding, verify_finding


def _parser(register) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    register(parser.add_subparsers())
    return parser


@pytest.mark.parametrize(
    ("argv", "dest", "expected"),
    [
        (["agent", "done", "AG-1", "--status", "Completed"], "dispatch_status", "completed"),
        (["agent", "done", "AG-1", "--status", "ABORTED"], "dispatch_status", "aborted"),
        (["agent", "list", "--status", "in_progress"], "dispatch_status", "in-progress"),
        (["agent", "close", "AG-1", "--status", "Failed", "--reason", "x"], "close_status", "failed"),
    ],
)
def test_agent_status_words_fold(argv, dest, expected) -> None:
    assert getattr(_parser(agent.register).parse_args(argv), dest) == expected


def test_an_agent_status_outside_the_vocabulary_is_refused() -> None:
    with pytest.raises(SystemExit):
        _parser(agent.register).parse_args(["agent", "done", "AG-1", "--status", "done"])


_RECORD_PREFIX = ("record", "hunter-a", "finding.json")
_UPDATE_PREFIX = ("update", "VA-001")


def test_evidence_type_folds_on_record_and_update_flags_and_payload() -> None:
    record_args = _parser(record_finding.register).parse_args(
        [*_RECORD_PREFIX, "--evidence-type", "Network_Confirmed"]
    )
    assert record_args.evidence_type == "network-confirmed"
    update_args = _parser(update_finding.register).parse_args(
        [*_UPDATE_PREFIX, "--evidence-type", "code inferred"]
    )
    assert update_args.evidence_type == "code-inferred"
    payload = record_finding._normalize_payload(
        {"title": "Acme IDOR", "evidence_type": "Code_Inferred", "verification_status": "Unreviewed"},
        agent_name="hunter-a", candidate_slug="VA-001",
    )
    assert payload["evidence_type"] == "code-inferred"
    assert payload["verification_status"] == "unreviewed"


def test_a_verify_payload_status_folds_before_it_is_read() -> None:
    assert verify_finding.fold_payload_status(
        {"verification_status": "Pending-Runtime-Proof"}
    ) == {"verification_status": "pending_runtime_proof"}
