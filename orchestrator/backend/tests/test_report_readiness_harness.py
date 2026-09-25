"""Harness-doctrine tests for report-readiness advisory behavior.

These exercise the harness pivot recorded in ``docs/adr/0001``:
administrative-hygiene checks at the report
boundary are softened from HARD blockers to ADVISORIES (``ready`` does not flip
to False on them alone). A web finding parked in ``draft`` remains visible as
an advisory; file/code drafts hard-block in the code-workflow regressions. A
genuine quality blocker (unverified high finding) MUST still block, proving we
did not over-soften.

Covered:
  - L1-1: an unlinked markdown note → advisory, ``ready`` stays True.
  - L1-8: a stale ready handoff on an in-progress dispatch → advisory, not blocking.
  - S21 : a web URL draft → ``draft_finding_needs_disposition`` advisory listing
          its slug; it remains visible without changing the established web gate.
  - over-soften guard: an unverified high finding STILL hard-blocks.
"""
from __future__ import annotations

import json
from pathlib import Path

from app import db as db_module
from tests.proof_fixtures import completed_confirm_check, post_artifact_backed_source_observation


ENGAGEMENT_KEY = "2026-05-20-090000-harness"
BASE = f"/engagements/{ENGAGEMENT_KEY}/assessment"


def _ensure_dispatch(client, agent_id: str, role: str) -> None:
    existing = client.get(f"{BASE}/dispatches/{agent_id}")
    if existing.status_code == 200:
        return
    assert existing.status_code == 404, existing.text
    dispatch = client.post(
        f"{BASE}/dispatches",
        json={"agent_id": agent_id, "agent_role": role, "task": role},
    )
    assert dispatch.status_code == 201, dispatch.text


def _write_engagement(engagements_dir: Path) -> Path:
    eng = engagements_dir / ENGAGEMENT_KEY
    (eng / "sessions").mkdir(parents=True, exist_ok=True)
    (eng / "engagement.json").write_text(
        json.dumps(
            {
                "key": ENGAGEMENT_KEY,
                "target": "https://example.com",
                "hostname": "example.com",
                "created_at": "2026-05-20T09:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    (eng / "scope.json").write_text(
        json.dumps(
            {
                "hostname": "example.com",
                "hosts": ["example.com"],
                "status": "in_progress",
                "current_phase": "consume-test",
            }
        ),
        encoding="utf-8",
    )
    return eng


def _reportable_finding(
    client,
    eng: Path,
    slug: str = "HR-001",
    *,
    normal_severity_band: str | None = None,
    **overrides,
) -> None:
    """Seed a fully-reportable finding (verified/confirmed, evidence linked)."""
    (eng / "notes").mkdir(parents=True, exist_ok=True)
    (eng / "notes" / f"{slug}-note.md").write_text(f"{slug} evidence", encoding="utf-8")
    verification_status = overrides.pop("verification_status", "confirmed")
    payload = {
        "slug": slug,
        "title": "Reportable finding",
        "severity": "high",
        "workflow_status": "active",
        "verification_status": "unreviewed",
        "canonical_location": f"https://example.com/{slug}",
        "summary": "A fully reportable finding.",
        "evidence_ref": f"notes/{slug}-note.md",
        "source_name": "vulnerability-analyst",
        "provenance": {"agent_id": "HUNT-1"},
        "details": {
            "cvss_score": 8.1,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
            "steps_to_reproduce": ["step one", "step two"],
            "remediation": "Fix it",
            "impact": "High impact",
            "evidence": "Captured request in linked artifact",
        },
    }
    payload.update(overrides)
    _ensure_dispatch(client, "HUNT-1", "vulnerability-analyst")
    response = client.post(f"{BASE}/findings", json=payload)
    assert response.status_code == 201, response.text
    if verification_status == "unreviewed":
        return

    _ensure_dispatch(client, "VERIFY-1", "code-vuln-verifier")
    run = client.post(
        f"{BASE}/assessment-runs",
        json={
            "run_uuid": f"report-readiness-{slug}",
            "run_kind": "code",
            "producer_dispatch_agent_id": "VERIFY-1",
        },
    )
    assert run.status_code == 201, run.text
    linked = client.post(
        f"{BASE}/findings/{slug}/links",
        json={
            "link_kind": "proof_run", "target_kind": "assessment_run",
            "target_id": run.json()["id"],
        },
    )
    assert linked.status_code == 200, linked.text
    receipt = post_artifact_backed_source_observation(
        client,
        f"{BASE}/proof-receipts",
        json={
            "run_id": run.json()["id"],
            "evidence_kind": "source_observation",
            "expected_result": "the reported claim survives an independent check",
            "observed_result": "the independent check reproduced the reported claim",
        },
    )
    assert receipt.status_code == 201, receipt.text
    completed = client.patch(
        f"{BASE}/assessment-runs/{run.json()['id']}",
        json={"status": "completed"},
    )
    assert completed.status_code == 200, completed.text
    verify_payload = {
        "verification_status": verification_status,
        "reason_text": "independently verified for report readiness",
        "proof_receipt_ids": [receipt.json()["id"]],
        "confirm_check": completed_confirm_check(receipt.json()["id"]),
    }
    if normal_severity_band is not None:
        verify_payload["severity_variance"] = {
            "normal_band": normal_severity_band,
            "chosen_severity": payload["severity"],
            "actor": "VERIFY-1",
            "reason": "Reviewed business impact warrants the chosen severity band.",
            "proof_receipt_id": receipt.json()["id"],
        }
    verify = client.post(f"{BASE}/findings/{slug}/verify", json=verify_payload)
    assert verify.status_code == 200, verify.text


def _readiness(client) -> dict:
    response = client.get(f"{BASE}/report-readiness")
    assert response.status_code == 200, response.text
    return response.json()


def test_return_shape_backward_compatible(client, isolate_settings) -> None:
    eng = _write_engagement(isolate_settings["engagements_dir"])
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200
    _reportable_finding(client, eng)

    body = _readiness(client)
    assert set(["ready", "blocker_count", "blockers", "coverage"]).issubset(body.keys())
    assert isinstance(body["advisories"], list)
    assert body["advisory_count"] == len(body["advisories"])
    assert body["ready"] is True, body


def test_l1_1_unlinked_markdown_note_is_advisory_not_blocking(client, isolate_settings) -> None:
    eng = _write_engagement(isolate_settings["engagements_dir"])
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200
    _reportable_finding(client, eng)

    (eng / "notes" / "loose.md").write_text("durable, not linked anywhere", encoding="utf-8")
    register = client.post(f"{BASE}/artifacts", json={"path": "notes/loose.md", "kind": "note"})
    assert register.status_code == 201, register.text

    body = _readiness(client)
    assert not any(b["kind"] == "unlinked_markdown_note" for b in body["blockers"]), body
    advisory = next(
        a for a in body["advisories"]
        if a["kind"] == "unlinked_markdown_note" and a["path"] == "notes/loose.md"
    )
    assert "mark-scratch" in advisory["detail"]
    assert body["ready"] is True, body


def test_l1_8_stale_ready_handoff_is_advisory_not_blocking(client, isolate_settings) -> None:
    eng = _write_engagement(isolate_settings["engagements_dir"])
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200
    _reportable_finding(client, eng)

    dispatch = client.post(
        f"{BASE}/dispatches",
        json={
            "agent_id": "HF-009",
            "agent_role": "vulnerability-analyst",
            "task": "stale handoff test",
            "skills": "auth-bypass",
        },
    )
    assert dispatch.status_code == 201, dispatch.text
    handoff = client.post(
        f"{BASE}/dispatch-handoffs",
        json={
            "agent_id": "HF-009",
            "agent_role": "vulnerability-analyst",
            "phase": "consume-test",
            "summary": "Ready for promotion but dispatch left in-progress.",
            "handoff_status": "ready",
        },
    )
    assert handoff.status_code == 201, handoff.text

    body = _readiness(client)
    assert not any(b["kind"] == "stale_dispatch_ready_handoff" for b in body["blockers"]), body
    advisory = next(
        a for a in body["advisories"]
        if a["kind"] == "stale_dispatch_ready_handoff" and a["agent_id"] == "HF-009"
    )
    assert "reconcile-stale" in advisory["detail"]
    assert body["ready"] is True, body


def test_s21_web_draft_finding_is_advisory_with_slug(client, isolate_settings) -> None:
    eng = _write_engagement(isolate_settings["engagements_dir"])
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200
    _reportable_finding(client, eng, slug="HR-002", workflow_status="draft")

    body = _readiness(client)
    advisory = next(
        row for row in body["advisories"]
        if row["kind"] == "draft_finding_needs_disposition" and row["slug"] == "HR-002"
    )
    assert "finding update HR-002 --status active" in advisory["detail"]
    assert "finding verify HR-002 --status false_positive" in advisory["detail"]
    assert "--counter-check-file" in advisory["detail"]
    assert "--proof-receipt-id" in advisory["detail"]
    assert not any(
        row["kind"] == "draft_finding_needs_disposition" and row["slug"] == "HR-002"
        for row in body["blockers"]
    )
    assert body["ready"] is True, body


def test_over_soften_guard_unverified_high_finding_still_blocks(client, isolate_settings) -> None:
    eng = _write_engagement(isolate_settings["engagements_dir"])
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200
    _reportable_finding(
        client,
        eng,
        slug="HR-003",
        verification_status="unreviewed",
    )

    body = _readiness(client)
    assert body["ready"] is False, body
    assert any(
        b["kind"] == "finding_verification_status" and b["slug"] == "HR-003"
        for b in body["blockers"]
    ), body


def test_legacy_severity_rationale_does_not_fabricate_variance_approval(
    client, isolate_settings
) -> None:
    eng = _write_engagement(isolate_settings["engagements_dir"])
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200
    _reportable_finding(
        client,
        eng,
        slug="HR-004",
        verification_status="unreviewed",
        details={
            "cvss_score": 5.3,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "severity_band_rationale": "legacy prose is history, not approval",
            "steps_to_reproduce": ["step one", "step two"],
            "remediation": "Fix it",
            "impact": "High contractual impact",
            "evidence": "Captured request in linked artifact",
        },
    )
    # Model an already-confirmed legacy row: the current write path correctly
    # rejects this transition without a structured severity-variance event.
    with db_module.get_connection() as connection:
        connection.execute(
            "UPDATE assessment_findings SET verification_status = 'confirmed' "
            "WHERE slug = ?",
            ("HR-004",),
        )

    body = _readiness(client)

    blocker = next(
        row for row in body["blockers"]
        if row["kind"] == "severity_cvss_mismatch" and row["slug"] == "HR-004"
    )
    assert "--severity-variance-file" in blocker["detail"]
    assert not any(
        row["kind"] == "severity_cvss_band_divergence" and row["slug"] == "HR-004"
        for row in body["advisories"]
    )


def test_attributed_severity_variance_allows_report_readiness(
    client, isolate_settings
) -> None:
    eng = _write_engagement(isolate_settings["engagements_dir"])
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200
    _reportable_finding(
        client,
        eng,
        slug="HR-005",
        normal_severity_band="medium",
        details={
            "cvss_score": 5.3,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "severity_band_rationale": "legacy prose remains descriptive only",
            "steps_to_reproduce": ["step one", "step two"],
            "remediation": "Fix it",
            "impact": "High contractual impact",
            "evidence": "Captured request in linked artifact",
        },
    )

    body = _readiness(client)

    assert not any(
        row["kind"] == "severity_cvss_mismatch" and row["slug"] == "HR-005"
        for row in body["blockers"]
    )
    advisory = next(
        row for row in body["advisories"]
        if row["kind"] == "severity_cvss_band_divergence" and row["slug"] == "HR-005"
    )
    assert "structured variance" in advisory["detail"]


def test_same_status_reverification_repairs_legacy_severity_variance(
    client, isolate_settings
) -> None:
    eng = _write_engagement(isolate_settings["engagements_dir"])
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200
    _reportable_finding(
        client,
        eng,
        slug="HR-006",
        verification_status="unreviewed",
        details={
            "cvss_score": 5.3,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "steps_to_reproduce": ["step one", "step two"],
            "remediation": "Fix it",
            "impact": "High contractual impact",
            "evidence": "Captured request in linked artifact",
        },
    )
    with db_module.get_connection() as connection:
        connection.execute(
            "UPDATE assessment_findings SET verification_status = 'confirmed' "
            "WHERE slug = ?",
            ("HR-006",),
        )
    assert any(
        row["kind"] == "severity_cvss_mismatch"
        for row in _readiness(client)["blockers"]
    )

    _ensure_dispatch(client, "HUNT-1", "vulnerability-analyst")
    _ensure_dispatch(client, "VERIFY-1", "code-vuln-verifier")
    run = client.post(
        f"{BASE}/assessment-runs",
        json={
            "run_uuid": "report-readiness-HR-006-repair",
            "run_kind": "code",
            "producer_dispatch_agent_id": "VERIFY-1",
        },
    )
    assert run.status_code == 201, run.text
    linked = client.post(
        f"{BASE}/findings/HR-006/links",
        json={
            "link_kind": "proof_run", "target_kind": "assessment_run",
            "target_id": run.json()["id"],
        },
    )
    assert linked.status_code == 200, linked.text
    receipt = post_artifact_backed_source_observation(
        client,
        f"{BASE}/proof-receipts",
        json={
            "run_id": run.json()["id"],
            "evidence_kind": "source_observation",
            "expected_result": "medium is the normal CVSS band",
            "observed_result": "contractual impact justifies high severity",
        },
    )
    assert receipt.status_code == 201, receipt.text
    completed = client.patch(
        f"{BASE}/assessment-runs/{run.json()['id']}",
        json={"status": "completed"},
    )
    assert completed.status_code == 200, completed.text
    verified = client.post(
        f"{BASE}/findings/HR-006/verify",
        json={
            "verification_status": "confirmed",
            "reason_text": "fresh independent review confirms the legacy finding",
            "proof_receipt_ids": [receipt.json()["id"]],
            "confirm_check": completed_confirm_check(receipt.json()["id"]),
            "severity_variance": {
                "normal_band": "medium",
                "chosen_severity": "high",
                "actor": "VERIFY-1",
                "reason": "Contractual exposure justifies the chosen band.",
                "proof_receipt_id": receipt.json()["id"],
            },
        },
    )
    assert verified.status_code == 200, verified.text

    body = _readiness(client)
    assert not any(
        row["kind"] == "severity_cvss_mismatch" and row["slug"] == "HR-006"
        for row in body["blockers"]
    )
    assert any(
        row["kind"] == "severity_cvss_band_divergence"
        and row["slug"] == "HR-006"
        for row in body["advisories"]
    )


def test_chain_non_step_links_do_not_block_readiness(client, isolate_settings) -> None:
    """I-14a: evidence/access/credential chain links (relation != 'step') are
    legitimate supporting context, not path steps, so they must NOT be flagged
    as unlinked finding-steps. Only genuine 'step' links must resolve to a
    reportable finding slug.

    Regression: the chain-link readiness query had no relation filter and
    flagged every non-finding link as ``chain_step_not_finding_linked``.
    """
    eng = _write_engagement(isolate_settings["engagements_dir"])
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200
    _reportable_finding(client, eng, slug="HR-010")

    chain = client.post(
        f"{BASE}/attack-chains",
        json={
            "chain_key": "chain-mixed-links",
            "title": "Mixed-relation chain",
            "severity": "high",
            "links": [
                {"relation": "step", "entity_kind": "finding", "entity_ref": "HR-010"},
                {"relation": "evidence", "entity_kind": "evidence", "entity_ref": "notes/evidence.md"},
                {"relation": "access", "entity_kind": "access", "entity_ref": "admin-shell"},
                {"relation": "credential", "entity_kind": "credential", "entity_ref": "db-root"},
            ],
        },
    )
    assert chain.status_code == 201, chain.text

    blockers = _readiness(client)["blockers"]
    not_finding = [b for b in blockers if b.get("kind") == "chain_step_not_finding_linked"]
    assert not_finding == [], not_finding
    # The lone step points at a reportable finding, so no missing-step blocker either.
    missing_step = [b for b in blockers if b.get("kind") == "chain_step_missing_finding"]
    assert missing_step == [], missing_step


def test_chain_non_finding_step_still_blocks_readiness(client, isolate_settings) -> None:
    """Over-scope guard for I-14a: a genuine 'step' link whose entity is not a
    finding MUST still block. The fix narrows the rule to steps, it does not
    disable it."""
    eng = _write_engagement(isolate_settings["engagements_dir"])
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200
    _reportable_finding(client, eng, slug="HR-011")

    chain = client.post(
        f"{BASE}/attack-chains",
        json={
            "chain_key": "chain-bad-step",
            "title": "Chain with a non-finding step",
            "severity": "high",
            "links": [
                {"relation": "step", "entity_kind": "finding", "entity_ref": "HR-011"},
                {"relation": "step", "entity_kind": "credential", "entity_ref": "db-root"},
            ],
        },
    )
    assert chain.status_code == 201, chain.text

    blockers = _readiness(client)["blockers"]
    not_finding = [b for b in blockers if b.get("kind") == "chain_step_not_finding_linked"]
    assert len(not_finding) == 1, not_finding
    assert not_finding[0]["chain_key"] == "chain-bad-step"
    assert "credential" in not_finding[0]["detail"]
