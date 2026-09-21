"""Compact finding-history index with lossless point reads."""

from __future__ import annotations

import json

from app import db as db_module


ENGAGEMENT_KEY = "2026-09-21-finding-history"
BASE = f"/engagements/{ENGAGEMENT_KEY}/assessment"


def _seed_history(client, isolate_settings) -> tuple[int, str]:
    engagement_dir = isolate_settings["engagements_dir"] / ENGAGEMENT_KEY
    (engagement_dir / "sessions").mkdir(parents=True)
    (engagement_dir / "scope.json").write_text(
        json.dumps(
            {
                "engagement_name": "Finding history API",
                "targets": ["https://app.example"],
            }
        ),
        encoding="utf-8",
    )
    (engagement_dir / "findings.md").write_text("# Findings\n", encoding="utf-8")
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200

    author = client.post(
        f"{BASE}/dispatches",
        json={
            "agent_id": "HISTORY-AUTHOR",
            "agent_role": "vulnerability-analyst",
            "task": "Record the history projection fixture.",
        },
    )
    assert author.status_code == 201, author.text
    created = client.post(
        f"{BASE}/findings",
        json={
            "slug": "VA-001",
            "title": "History projection fixture",
            "severity": "high",
            "workflow_status": "active",
            "verification_status": "unreviewed",
            "canonical_location": "https://app.example/admin",
            "summary": "The fixture retains a large transition body.",
            "evidence_ref": "findings.md",
            "source_name": "vulnerability-analyst",
            "provenance": {"agent_id": "HISTORY-AUTHOR"},
        },
    )
    assert created.status_code == 201, created.text
    transition_id = int(created.json()["transition"]["id"])

    reason_text = " ".join(f"word-{index}" for index in range(1, 106))
    with db_module.get_connection() as connection:
        connection.execute(
            """
            UPDATE assessment_finding_transitions
            SET reason_text = ?, details_before_json = ?, details_after_json = ?,
                notes_before_json = ?, notes_after_json = ?, metadata_json = ?
            WHERE id = ?
            """,
            (
                reason_text,
                json.dumps({"evidence": "before" * 20_000}),
                json.dumps({"evidence": "after" * 20_000}),
                "before" * 20_000,
                "after" * 20_000,
                json.dumps({"source": "fixture"}),
                transition_id,
            ),
        )
    return transition_id, reason_text


def test_transition_summary_projection_is_bounded_and_points_to_lossless_detail(
    client, isolate_settings
):
    transition_id, reason_text = _seed_history(client, isolate_settings)

    response = client.get(
        f"{BASE}/findings/VA-001/transitions",
        params={"projection": "summary"},
    )

    assert response.status_code == 200, response.text
    [summary] = response.json()
    assert summary["id"] == transition_id
    assert summary["reason_preview"] == " ".join(reason_text.split()[:100])
    assert summary["reason_word_count"] == 105
    assert summary["reason_truncated"] is True
    assert summary["has_snapshot"] is True
    assert {
        "details_before_json",
        "details_after_json",
        "notes_before_json",
        "notes_after_json",
        "reason_text",
        "metadata_json",
        "verification_audit",
    }.isdisjoint(summary)

    detail = client.get(
        f"{BASE}/findings/VA-001/transitions/{transition_id}"
    )
    assert detail.status_code == 200, detail.text
    assert detail.json()["reason_text"] == reason_text
    assert json.loads(detail.json()["details_after_json"])["evidence"].startswith(
        "after"
    )
    assert detail.json()["verification_audit"]["truncated"] is False


def test_transition_point_read_is_scoped_to_its_finding(client, isolate_settings):
    transition_id, _ = _seed_history(client, isolate_settings)

    wrong_finding = client.get(
        f"{BASE}/findings/VA-999/transitions/{transition_id}"
    )
    missing_transition = client.get(
        f"{BASE}/findings/VA-001/transitions/{transition_id + 10_000}"
    )

    assert wrong_finding.status_code == 404
    assert missing_transition.status_code == 404


def test_transition_list_defaults_to_full_rows_for_the_cli_contract(
    client, isolate_settings
):
    _, reason_text = _seed_history(client, isolate_settings)

    response = client.get(f"{BASE}/findings/VA-001/transitions")

    assert response.status_code == 200, response.text
    [transition] = response.json()
    assert transition["reason_text"] == reason_text
    assert "details_after_json" in transition
    assert "verification_audit" in transition
