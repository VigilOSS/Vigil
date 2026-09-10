"""The blocked-for-provisioning reason marker shared by list-findings and
resume-brief.

A finding blocked-for-provisioning (verification_status='blocked') is held
OUT of the report and renders as a bare active/blocked line, so neither compact
renderer used to say WHY it stalled — the operator had to open the finding to
read details.block_reason. `finding_render.blocked_reason_summary` computes a
one-line ``BLOCKED: <reason>`` marker from EITHER read shape:

  * list-findings' serialized record, with a parsed ``details`` object;
  * resume-brief's bounded projection, where ``block_reason`` is a flattened
    top-level field.

The marker is gated strictly on ``verification_status == 'blocked'`` — a
block_reason may sit on a non-blocked finding (a pending hold), and labelling
that BLOCKED would be wrong. These pin the marker semantics and that
`list_findings._finding_row` appends it. The compact projection intentionally
omits richer prerequisite metadata, which remains available on finding detail.
"""
from __future__ import annotations

from assess.commands import list_findings
from assess.lib.finding_render import blocked_reason_summary


def test_marker_from_parsed_details():
    # list-findings shape: full public API record.
    finding = {
        "verification_status": "blocked",
        "details": {"block_reason": "no test account provisioned"},
    }
    assert blocked_reason_summary(finding) == "BLOCKED: no test account provisioned"


def test_marker_from_flattened_projection_fields():
    # resume-brief shape: flattened top-level fields, no nested details.
    finding = {
        "verification_status": "blocked",
        "block_reason": "missing credential",
    }
    assert blocked_reason_summary(finding) == "BLOCKED: missing credential"


def test_marker_empty_for_non_blocked_findings():
    assert blocked_reason_summary({"verification_status": "confirmed"}) == ""
    assert blocked_reason_summary({"verification_status": "unreviewed", "details": {}}) == ""
    assert blocked_reason_summary({}) == ""


def test_marker_gated_strictly_on_blocked_status():
    # A block_reason on a NON-blocked finding (e.g. a pending_runtime_proof hold)
    # must NOT render as BLOCKED — the disposition, not the field's presence, is
    # the gate. Mirrors real data (pending/unreviewed findings carrying a
    # block_reason).
    pending = {"verification_status": "pending_runtime_proof", "block_reason": "held pending sandbox"}
    assert blocked_reason_summary(pending) == ""
    unreviewed = {"verification_status": "unreviewed", "block_reason": "line unavailable"}
    assert blocked_reason_summary(unreviewed) == ""


def test_marker_blocked_without_reason_shows_bare_label():
    # Defensive: status=blocked with no reason present still flags BLOCKED
    # (the backend invariant guarantees a reason, but the renderer must not crash
    # or drop the signal if one is ever absent).
    assert blocked_reason_summary({"verification_status": "blocked"}) == "BLOCKED"


def test_list_findings_row_appends_blocked_cell():
    item = {
        "slug": "VA-047", "severity": "high", "workflow_status": "active",
        "verification_status": "blocked",
        "root_cause_role": "", "title": "IDOR on /orders",
        "details": {
            "block_reason": "Needs finance-admin account and this WONT be given",
        },
    }
    row = list_findings._finding_row(item)
    # The six existing columns are preserved, with the reason appended as a cell.
    assert row.startswith("VA-047 | high | active | blocked |  | IDOR on /orders")
    assert row.endswith("| BLOCKED: Needs finance-admin account and this WONT be given")


def test_list_findings_row_unchanged_for_normal_finding():
    item = {
        "slug": "VA-001", "severity": "low", "workflow_status": "active",
        "verification_status": "confirmed",
        "root_cause_role": "", "title": "XSS", "details": {},
    }
    row = list_findings._finding_row(item)
    assert "BLOCKED" not in row
    # Six columns → five separators; no trailing blocked cell.
    assert row.count(" | ") == 5
