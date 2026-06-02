"""Unit tests for the verification-disposition coalesce rank mechanism.

These exercise ``_coalesce_verification_disposition`` directly (no DB) to lock
in the rank ordering that makes ``pending_runtime_proof`` sticky against a bare
``none`` while still yielding to a stronger ``downgraded``/``confirmed`` and to
``false_positive`` (handled by explicit early-returns, not rank).
"""
from __future__ import annotations

from app.services.state_manager import _common, findings


def test_disposition_rank_orders_pending_between_none_and_downgraded():
    rank = _common.VERIFICATION_DISPOSITION_RANK
    assert rank[_common.VerificationDisposition.NONE] < rank[_common.VerificationDisposition.PENDING_RUNTIME_PROOF]
    assert rank[_common.VerificationDisposition.PENDING_RUNTIME_PROOF] < rank[_common.VerificationDisposition.DOWNGRADED]
    assert rank[_common.VerificationDisposition.DOWNGRADED] < rank[_common.VerificationDisposition.CONFIRMED]


def test_pending_runtime_proof_is_sticky_against_none():
    # Existing pending, incoming bare none must NOT clobber it (0 >= 1 is False).
    assert findings._coalesce_verification_disposition("pending_runtime_proof", "none") == "pending_runtime_proof"


def test_pending_runtime_proof_overwrites_none():
    assert findings._coalesce_verification_disposition("none", "pending_runtime_proof") == "pending_runtime_proof"


def test_pending_runtime_proof_yields_to_confirmed():
    assert findings._coalesce_verification_disposition("pending_runtime_proof", "confirmed") == "confirmed"


def test_pending_runtime_proof_yields_to_downgraded():
    assert findings._coalesce_verification_disposition("pending_runtime_proof", "downgraded") == "downgraded"


def test_confirmed_does_not_regress_to_pending_runtime_proof():
    # A weaker incoming pending must not overwrite an existing confirmed.
    assert findings._coalesce_verification_disposition("confirmed", "pending_runtime_proof") == "confirmed"


def test_pending_runtime_proof_yields_to_false_positive():
    # false_positive wins via explicit early-return regardless of rank.
    assert findings._coalesce_verification_disposition("pending_runtime_proof", "false_positive") == "false_positive"


def test_false_positive_is_sticky_over_incoming_pending_runtime_proof():
    assert findings._coalesce_verification_disposition("false_positive", "pending_runtime_proof") == "false_positive"


def test_explicit_override_forces_pending_runtime_proof():
    # An explicit verifier override may set pending even over a higher rank.
    assert (
        findings._coalesce_verification_disposition("confirmed", "pending_runtime_proof", explicit_override=True)
        == "pending_runtime_proof"
    )
