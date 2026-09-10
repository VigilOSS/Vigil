"""The verification contract is one explicit seven-value status axis."""
from __future__ import annotations

from app.services.state_manager import _common


def test_verification_status_vocabulary_is_complete_and_unranked() -> None:
    assert {status.value for status in _common.VERIFICATION_STATUSES} == {
        "unreviewed",
        "confirmed",
        "downgraded",
        "pending_runtime_proof",
        "blocked",
        "false_positive",
        "disputed",
    }
    assert not hasattr(_common, "VERIFICATION_DISPOSITION_RANK")
