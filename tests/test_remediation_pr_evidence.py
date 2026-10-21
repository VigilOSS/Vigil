from __future__ import annotations

import pytest

from vigil_cli import remediation


def publication_case():
    def record(identifier, observed, *, kind="api-test", revision="current", outcome="passed", method="pytest"):
        return {"id": identifier, "kind": kind, "method": method, "environment": "local",
                "revision": revision, "outcome": outcome, "observed": observed, "proved": "Account controls"}
    return {
        "approvals": [{"evidence_cutoff_id": 6}], "worktree_revision": "current",
        "verification_plan": "Verify account ownership and legitimate access",
        "verification_requirements": {"requirements": [
            {"kind": "api-test", "methods": ["pytest"]},
            {"kind": "red-test", "methods": ["pytest"], "outcome": "failed_as_expected"},
        ]},
        "evidence": [
            record(1, "Old implementation permits cross-account writes", revision="old"),
            record(2, "Current attempt failed", outcome="failed"),
            record(3, "Wrong method passed", method="unselected"),
            record(4, "Artifact no longer matches its recorded bytes"),
            record(5, "Current implementation denies cross-account writes"),
            record(6, "Named regression failed with the fix restored", kind="red-test", outcome="failed_as_expected"),
            record(7, "Post-approval verification passed"),
        ],
        "verification_matches": [
            {"requirement_index": 0, "evidence_ids": [5, 7], "missing": None},
            {"requirement_index": 1, "evidence_ids": [6], "missing": None},
        ],
        "release_plan": {"production_canary_decision": "not_required", "production_canary_rationale": "Local account controls",
                         "safe_procedure": "", "monitoring": "Watch authorization failures"},
    }


def verification_lines(case):
    body = remediation._pr_body(case, {}, "A record was selected without account ownership",
                                "Require account ownership before returning the record")
    return body.splitlines()


def test_pr_summary_uses_backend_matches_within_the_approval_cutoff():
    lines = verification_lines(publication_case())
    assert [line for line in lines if line.startswith("- ")] == [
        "- pytest [environment: local] (passed): Current implementation denies cross-account writes",
        "- pytest [environment: local] (failed as expected): Named regression failed with the fix restored",
    ]


def test_pr_summary_keeps_valid_tree_carried_verification():
    case = publication_case()
    case["evidence"][4]["revision"] = "original-revision"
    case["evidence_carries"] = [{"evidence_id": 5, "from_revision": "original-revision", "to_revision": "current", "tree_id": "same-tree"}]
    assert [line for line in verification_lines(case) if line.startswith("- ")] == [
        "- pytest [environment: local] (passed): Current implementation denies cross-account writes",
        "- pytest [environment: local] (failed as expected): Named regression failed with the fix restored",
    ]


@pytest.mark.parametrize("matches", [None, [], [{"requirement_index": 0, "evidence_ids": [7], "missing": None}]])
def test_pr_content_requires_approved_matches_for_every_requirement(matches):
    case = publication_case()
    case["verification_matches"] = matches
    with pytest.raises(SystemExit, match="verification.*match|reviewed.*evidence"):
        remediation._required_reviewed_evidence_lines(case)
