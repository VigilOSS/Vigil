"""`details.chain_required` cannot be claimed without `details.chain_rationale`.

``chain_rationale``'s schema description has said "Required when chain_required
is true" since the pair landed, but nothing held the two together: the string
was documentation, not a constraint. A finding could park itself as
chain-dependent — which is what keeps it out of the report and what an
exploit-developer pass is supposed to pick up — while saying nothing about which
chain step it enables, and the omission surfaced only at report time as a
finding nobody could act on.

The gate is shaped like ``_validate_cvss_pair``: it fires only when a write
AUTHORS one of the two keys and judges the EFFECTIVE merged pair, so supplying
just ``chain_required`` against a stored rationale passes and a pre-existing row
never traps the patch that repairs it.
"""
from __future__ import annotations

import json

import pytest

from app import db as db_module

ENGAGEMENT_KEY = "2026-09-17-090000-chain-rationale"
BASE = f"/engagements/{ENGAGEMENT_KEY}/assessment"


def _seed(client, isolate_settings) -> None:
    engagement_dir = isolate_settings["engagements_dir"] / ENGAGEMENT_KEY
    (engagement_dir / "sessions").mkdir(parents=True, exist_ok=True)
    (engagement_dir / "scope.json").write_text(
        json.dumps({"engagement_name": "Chain rationale", "targets": ["https://app.example"]}),
        encoding="utf-8",
    )
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200
    author = client.post(
        f"{BASE}/dispatches",
        json={
            "agent_id": "CHAIN-AUTHOR",
            "agent_role": "vulnerability-analyst",
            "task": "Record chain-dependent fixture findings.",
        },
    )
    assert author.status_code == 201, author.text


def _record(client, slug: str, **detail_overrides):
    details = {"evidence": "proof", "impact": "impact"}
    details.update(detail_overrides)
    return client.post(
        f"{BASE}/findings",
        json={
            "slug": slug,
            "title": f"Finding {slug}",
            "severity": "medium",
            "workflow_status": "active",
            "verification_status": "unreviewed",
            "defect_family": "ssrf",
            "canonical_location": f"https://app.example/{slug.lower()}",
            "summary": "Summary",
            "evidence_ref": "findings.md",
            "source_name": "test",
            "provenance": {"agent_id": "CHAIN-AUTHOR"},
            "details": details,
        },
    )


def test_record_rejects_chain_required_without_a_rationale(client, isolate_settings):
    _seed(client, isolate_settings)

    response = _record(client, "VA-001", chain_required=True)

    assert response.status_code == 400, response.text
    detail = response.json()["detail"]
    assert "chain_rationale" in detail
    assert "chain_required" in detail


def test_record_accepts_the_pair_together(client, isolate_settings):
    _seed(client, isolate_settings)

    response = _record(
        client,
        "VA-002",
        chain_required=True,
        chain_rationale="Only exploitable once VA-001 supplies the internal host.",
    )

    assert response.status_code == 201, response.text


@pytest.mark.parametrize("flag", [False, None])
def test_a_chain_required_that_is_not_true_needs_no_rationale(client, isolate_settings, flag):
    _seed(client, isolate_settings)

    response = _record(client, f"VA-00{3 if flag is False else 4}", chain_required=flag)

    assert response.status_code == 201, response.text


def test_a_patch_scores_chain_required_against_the_stored_rationale(client, isolate_settings):
    _seed(client, isolate_settings)
    assert _record(
        client,
        "VA-005",
        chain_rationale="Needs the VA-001 oracle to supply victim userIds.",
    ).status_code == 201

    response = client.patch(
        f"{BASE}/findings/VA-005",
        json={"details": {"chain_required": True}, "reason_text": "park it"},
    )

    assert response.status_code == 200, response.text


def test_a_patch_that_erases_the_rationale_under_a_live_flag_is_rejected(
    client, isolate_settings
):
    _seed(client, isolate_settings)
    assert _record(
        client,
        "VA-006",
        chain_required=True,
        chain_rationale="Needs the VA-001 oracle to supply victim userIds.",
    ).status_code == 201

    row_version = client.get(f"{BASE}/findings/VA-006").json()["row_version"]
    response = client.patch(
        f"{BASE}/findings/VA-006",
        json={
            "details": {"evidence": "proof", "impact": "impact", "chain_required": True},
            "details_mode": "replace",
            "expected_row_version": row_version,
            "reason_text": "scrub",
        },
    )

    assert response.status_code == 400, response.text
    assert "chain_rationale" in response.json()["detail"]


def test_an_unrelated_patch_never_trips_on_a_legacy_row(client, isolate_settings):
    """A row that predates the gate stays editable — the pair is judged only
    when the write authors one of the two keys."""
    _seed(client, isolate_settings)
    assert _record(client, "VA-007").status_code == 201
    # Force the legacy shape in past the gate, the way a pre-gate row exists.
    with db_module.get_connection() as connection:
        connection.execute(
            "UPDATE assessment_findings SET details_json = ? WHERE slug = ?",
            (json.dumps({"evidence": "proof", "impact": "impact", "chain_required": True}), "VA-007"),
        )
        connection.commit()

    response = client.patch(
        f"{BASE}/findings/VA-007",
        json={"details": {"impact": "a sharper impact statement"}, "reason_text": "edit"},
    )

    assert response.status_code == 200, response.text
