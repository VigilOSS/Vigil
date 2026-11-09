"""A root-cause link made with no stated effect groups without costing a verdict.

``root_cause_effect`` is the claim a root-cause link makes about what fixing the
root buys for the sibling. ``eliminates_attack_path`` says the sibling survives
the root fix as a standalone remediation item and keeps its verdict;
``eliminates_finding`` claims the root fix retires the sibling, which is a claim
change, so the finding change policy raises an independent claim review on every
confirmed or downgraded sibling and report readiness blocks on
``finding_claim_review_pending``.

The operator prompts and ``docs/engagements.md`` promise that a pure grouping
pass "costs nothing and never disturbs a verdict". That promise holds only if
the WIRE default agrees with it: a UI link, a raw ``vigil assess post`` and any
other non-CLI client send no ``root_cause_effect`` at all, so the request model
and the service read decide what they meant. These tests pin the wire default
and pin the CLI's ``--effect`` default to the same backend value, because a
default duplicated across the request model, the service read and the CLI is
exactly how the two sides drifted apart.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from app.api.assessment import RootCauseLinkRequest
from app.services.state_manager import links
from app.services.state_manager.links import DEFAULT_ROOT_CAUSE_EFFECT
from assess.commands import link_finding
from tests.proof_fixtures import (
    completed_confirm_check,
    post_artifact_backed_source_observation,
)

ENGAGEMENT_KEY = "2026-05-05-171900-rc-effect"
BASE = f"/engagements/{ENGAGEMENT_KEY}/assessment"
AUTHOR_AGENT_ID = "RC-EFFECT-FIXTURE-AUTHOR"


def _write_engagement(engagements_dir: Path) -> None:
    engagement_dir = engagements_dir / ENGAGEMENT_KEY
    (engagement_dir / "sessions").mkdir(parents=True, exist_ok=True)
    (engagement_dir / "scope.json").write_text(
        json.dumps(
            {"engagement_name": "Root Cause Effect Test", "targets": ["https://app.example"]}
        ),
        encoding="utf-8",
    )
    (engagement_dir / "findings.md").write_text("# Findings\n", encoding="utf-8")


def _seed(client, isolate_settings) -> None:
    _write_engagement(isolate_settings["engagements_dir"])
    response = client.get(f"/engagements/{ENGAGEMENT_KEY}")
    assert response.status_code == 200, response.text
    dispatch = client.post(
        f"{BASE}/dispatches",
        json={
            "agent_id": AUTHOR_AGENT_ID,
            "agent_role": "vulnerability-analyst",
            "task": "Record root-cause effect fixture findings",
        },
    )
    assert dispatch.status_code == 201, dispatch.text


def _finding(slug: str, title: str, *, root_key: str) -> dict:
    return {
        "slug": slug,
        "title": title,
        "severity": "high",
        "workflow_status": "exploited",
        "verification_status": "unreviewed",
        "defect_family": "auth-bypass",
        "root_cause_key": root_key,
        "canonical_location": f"https://app.example/{slug.lower()}",
        "summary": title,
        "evidence_ref": "findings.md",
        "source_name": "test",
        "provenance": {"agent_id": AUTHOR_AGENT_ID},
        "details": {
            "cvss_score": 8.1,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
            "steps_to_reproduce": ["Replay the recorded request."],
            "remediation": "Enforce authorization in the shared guard.",
            "impact": "Attackers can reach protected functionality.",
            "evidence": "Verified with a replayable request.",
        },
    }


def _create(client, payload: dict) -> None:
    slug = str(payload["slug"])
    author_id = f"AUTHOR-{slug}"
    dispatch = client.post(
        f"{BASE}/dispatches",
        json={
            "agent_id": author_id,
            "agent_role": "vulnerability-analyst",
            "task": f"Record {slug}",
        },
    )
    assert dispatch.status_code == 201, dispatch.text
    response = client.post(
        f"{BASE}/findings",
        json={**payload, "provenance": {"agent_id": author_id}},
    )
    assert response.status_code in {200, 201}, response.text


def _confirm(client, slug: str) -> int:
    agent_id = f"VERIFY-{slug}"
    dispatch = client.post(
        f"{BASE}/dispatches",
        json={
            "agent_id": agent_id,
            "agent_role": "rc-effect-fixture-verifier",
            "task": f"Independently verify {slug}",
        },
    )
    assert dispatch.status_code == 201, dispatch.text
    run = client.post(
        f"{BASE}/assessment-runs",
        json={
            "run_uuid": f"rc-effect-fixture-{slug}",
            "run_kind": "shared",
            "producer_dispatch_agent_id": agent_id,
        },
    )
    assert run.status_code == 201, run.text
    linked = client.post(
        f"{BASE}/findings/{slug}/links",
        json={
            "link_kind": "proof_run",
            "target_kind": "assessment_run",
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
            "expected_result": "the finding survives independent root-cause review",
            "observed_result": "the independent review reproduced the finding",
        },
    )
    assert receipt.status_code == 201, receipt.text
    completed = client.patch(
        f"{BASE}/assessment-runs/{run.json()['id']}",
        json={"status": "completed"},
    )
    assert completed.status_code == 200, completed.text
    verified = client.post(
        f"{BASE}/findings/{slug}/verify",
        json={
            "verification_status": "confirmed",
            "reason_text": "independent root-cause effect fixture proof",
            "proof_receipt_ids": [receipt.json()["id"]],
            "confirm_check": completed_confirm_check(receipt.json()["id"]),
        },
    )
    assert verified.status_code == 200, verified.text
    return int(receipt.json()["id"])


def _cli_effect_default() -> str:
    """The ``--effect`` default argparse actually registered on `finding link`."""
    parser = argparse.ArgumentParser()
    link_finding.register(parser.add_subparsers())
    return str(parser.parse_args(["link", "RC-902", "--root-cause", "RC-901"]).root_cause_effect)


def test_wire_root_cause_link_without_an_effect_groups_and_keeps_the_verdict(
    client, isolate_settings
):
    """A body with no ``root_cause_effect`` is a grouping pass, not a claim."""
    _seed(client, isolate_settings)
    _create(client, _finding("RC-901", "Shared auth guard bypass", root_key="guard-a"))
    _create(client, _finding("RC-902", "Admin export reachable through bypass", root_key="guard-b"))
    _confirm(client, "RC-902")

    linked = client.put(
        f"{BASE}/findings/RC-902/root-cause",
        json={
            "root_cause_slug": "RC-901",
            "note": "Both reach the same missing authorization guard.",
        },
    )

    assert linked.status_code == 200, linked.text
    body = linked.json()
    assert body["root_cause_effect"] == "eliminates_attack_path"
    assert body["verification_effect"] == "keep"
    assert body["verification_invalidated"] is False

    finding = client.get(f"{BASE}/findings/RC-902")
    assert finding.status_code == 200, finding.text
    assert finding.json()["verification_status"] == "confirmed"
    assert finding.json()["verification_audit"]["claim_review_pending"] is False

    transitions = client.get(f"{BASE}/findings/RC-902/transitions")
    assert transitions.status_code == 200, transitions.text
    assert transitions.json()[0]["action"] == "relationship_recorded"

    group = client.get(f"{BASE}/finding-groups/RC-901")
    assert group.status_code == 200, group.text
    siblings = group.json()["siblings"]
    assert [sibling["slug"] for sibling in siblings] == ["RC-902"]
    assert siblings[0]["root_cause_effect"] == "eliminates_attack_path"
    assert group.json()["residual_path_count"] == 1

    readiness = client.get(f"{BASE}/report-readiness")
    assert readiness.status_code == 200, readiness.text
    assert [
        blocker
        for blocker in readiness.json()["blockers"]
        if blocker["kind"] == "finding_claim_review_pending"
    ] == []


def test_a_link_row_recording_no_effect_reads_as_the_backend_default():
    """The stored-row read resolves a missing effect to the same one owner."""
    metadata = links._root_cause_link_metadata(
        {"id": 1, "target_ref": "RC-901", "notes": "", "provenance_json": "{}"}
    )
    assert metadata["root_cause_effect"] == DEFAULT_ROOT_CAUSE_EFFECT


def test_cli_effect_default_mirrors_the_backend_default():
    """The CLI flag and the wire request model resolve to one backend owner.

    Agent code cannot import the backend package, so ``--effect``'s default is a
    hand-written mirror of the backend's, and a hand-written mirror is the shape
    that rots. This is the guard that stops the two sides drifting again.
    """
    assert RootCauseLinkRequest.model_fields["root_cause_effect"].default == (
        DEFAULT_ROOT_CAUSE_EFFECT
    )
    assert _cli_effect_default() == DEFAULT_ROOT_CAUSE_EFFECT
