from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from app import db as db_module


ENGAGEMENT_KEY = "2026-07-20-120000-merge-integrity"
ASSESSMENT_BASE = f"/engagements/{ENGAGEMENT_KEY}/assessment"


def _write_engagement(engagements_dir: Path, key: str = ENGAGEMENT_KEY) -> None:
    engagement_dir = engagements_dir / key
    (engagement_dir / "sessions").mkdir(parents=True)
    (engagement_dir / "engagement.json").write_text(
        json.dumps(
            {
                "key": key,
                "target": "https://merge.example",
                "hostname": "merge.example",
                "created_at": "2026-07-20T12:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    (engagement_dir / "scope.json").write_text(
        json.dumps(
            {
                "hostname": "merge.example",
                "scope_hosts": ["merge.example"],
                "scope": ["merge.example"],
                "out_of_scope": [],
                "status": "in_progress",
                "current_phase": "report",
            }
        ),
        encoding="utf-8",
    )
    (engagement_dir / "sessions" / "index.json").write_text("[]", encoding="utf-8")


def _seed_engagement(client, isolate_settings, key: str = ENGAGEMENT_KEY) -> None:
    _write_engagement(isolate_settings["engagements_dir"], key)
    response = client.get("/engagements")
    assert response.status_code == 200, response.text


def _create_finding(client, slug: str, *, key: str = ENGAGEMENT_KEY) -> dict:
    response = client.post(
        f"/engagements/{key}/assessment/findings",
        json={
            "slug": slug,
            "title": f"Finding {slug}",
            "severity": "low",
            "workflow_status": "active",
            "verification_state": "verified",
            "verification_disposition": "confirmed",
            "defect_family": "merge-integrity",
            "auth_context": "anonymous",
            "canonical_location": f"https://merge.example/{slug.lower()}",
            "summary": f"Summary for {slug}",
            "evidence_ref": f"evidence/{slug.lower()}.json",
            "source_name": "test-agent",
            "details": {"evidence": "proof", "impact": "impact"},
            "provenance": {"agent_name": "test-agent"},
            "links": [],
        },
    )
    assert response.status_code == 201, response.text
    return response.json()["finding"]


def _merge(client, source_slug: str, target_slug: str):
    return client.post(
        f"{ASSESSMENT_BASE}/findings/merge",
        json={
            "source_slug": source_slug,
            "target_slug": target_slug,
            "reason": "same root cause",
            "source_name": "operator",
        },
    )


@pytest.mark.parametrize(
    ("case", "expected_detail"),
    [
        ("merged_source", "source finding MI-001 is already merged"),
        ("merged_target", "target finding MI-001 is already merged"),
        ("source_pointer", "source finding MI-001 has a merge target"),
        ("target_pointer", "target finding MI-002 has a merge target"),
        ("source_has_children", "would create a merge chain"),
    ],
)
def test_merge_rejects_nonflat_or_corrupt_graph_shapes(
    client,
    isolate_settings,
    case: str,
    expected_detail: str,
) -> None:
    _seed_engagement(client, isolate_settings)
    for slug in ("MI-001", "MI-002", "MI-003"):
        _create_finding(client, slug)

    if case in {"merged_source", "merged_target", "source_has_children"}:
        first_merge = _merge(client, "MI-001", "MI-002")
        assert first_merge.status_code == 200, first_merge.text

    if case == "merged_source":
        response = _merge(client, "MI-001", "MI-003")
    elif case == "merged_target":
        response = _merge(client, "MI-003", "MI-001")
    elif case == "source_has_children":
        response = _merge(client, "MI-002", "MI-003")
    else:
        with db_module.get_connection() as connection:
            rows = {
                str(row["slug"]): int(row["id"])
                for row in connection.execute(
                    "SELECT id, slug FROM assessment_findings WHERE slug IN ('MI-001', 'MI-002')"
                )
            }
            corrupt_slug = "MI-001" if case == "source_pointer" else "MI-002"
            pointer_slug = "MI-002" if case == "source_pointer" else "MI-001"
            connection.execute(
                "UPDATE assessment_findings SET merged_into_finding_id = ? WHERE id = ?",
                (rows[pointer_slug], rows[corrupt_slug]),
            )
        response = _merge(client, "MI-001", "MI-002")

    assert response.status_code == 400, response.text
    assert expected_detail in response.json()["detail"]


def test_merge_rejects_target_from_another_engagement(client, isolate_settings) -> None:
    other_key = "2026-07-20-120500-other-engagement"
    _seed_engagement(client, isolate_settings)
    _write_engagement(isolate_settings["engagements_dir"], other_key)
    assert client.get("/engagements").status_code == 200
    _create_finding(client, "MI-010")
    _create_finding(client, "MI-011", key=other_key)

    response = _merge(client, "MI-010", "MI-011")

    assert response.status_code == 404, response.text
    assert "MI-011" in response.json()["detail"]


def test_startup_leaves_legacy_merge_chain_untouched_and_readiness_blocks(
    client,
    isolate_settings,
) -> None:
    _seed_engagement(client, isolate_settings)
    for slug in ("MI-101", "MI-102", "MI-103"):
        _create_finding(client, slug)

    assert _merge(client, "MI-101", "MI-102").status_code == 200

    with db_module.get_connection() as connection:
        rows = {
            str(row["slug"]): dict(row)
            for row in connection.execute("SELECT * FROM assessment_findings")
        }
        connection.execute(
            """
            UPDATE assessment_findings
            SET status = 'merged', merged_into_finding_id = ?, row_version = row_version + 1
            WHERE id = ?
            """,
            (rows["MI-103"]["id"], rows["MI-102"]["id"]),
        )

    db_module.init_db()

    with db_module.get_connection() as connection:
        after = {
            str(row["slug"]): dict(row)
            for row in connection.execute("SELECT * FROM assessment_findings")
        }
    assert after["MI-101"]["merged_into_finding_id"] == after["MI-102"]["id"]
    assert after["MI-101"]["row_version"] == rows["MI-101"]["row_version"]

    response = client.get(f"{ASSESSMENT_BASE}/report-readiness")
    assert response.status_code == 200, response.text
    merge_blockers = {
        str(item.get("slug")): str(item.get("detail"))
        for item in response.json()["blockers"]
        if item.get("kind") == "finding_merge_integrity"
    }
    assert "depth" in merge_blockers["MI-101"]
    assert "MI-102" in merge_blockers["MI-101"]
    assert "MI-103" in merge_blockers["MI-101"]


def test_report_readiness_names_every_merge_graph_corruption(client, isolate_settings) -> None:
    other_key = "2026-07-20-122000-readiness-other"
    _seed_engagement(client, isolate_settings)
    _write_engagement(isolate_settings["engagements_dir"], other_key)
    assert client.get("/engagements").status_code == 200
    slugs = (
        "MI-201",
        "MI-202",
        "MI-203",
        "MI-204",
        "MI-205",
        "MI-206",
        "MI-207",
        "MI-208",
        "MI-209",
        "MI-210",
        "MI-211",
    )
    for slug in slugs:
        _create_finding(client, slug)
    _create_finding(client, "MI-299", key=other_key)

    with db_module.get_connection() as connection:
        rows = {
            str(row["slug"]): dict(row)
            for row in connection.execute("SELECT * FROM assessment_findings")
        }
        connection.execute(
            "UPDATE assessment_findings SET status = 'merged', merged_into_finding_id = NULL WHERE id = ?",
            (rows["MI-201"]["id"],),
        )
        connection.execute(
            "UPDATE assessment_findings SET status = 'merged', merged_into_finding_id = ? WHERE id = ?",
            (rows["MI-299"]["id"], rows["MI-203"]["id"]),
        )
        connection.execute(
            "UPDATE assessment_findings SET status = 'merged', merged_into_finding_id = id WHERE id = ?",
            (rows["MI-204"]["id"],),
        )
        connection.execute(
            "UPDATE assessment_findings SET status = 'merged', merged_into_finding_id = ? WHERE id = ?",
            (rows["MI-206"]["id"], rows["MI-205"]["id"]),
        )
        connection.execute(
            "UPDATE assessment_findings SET status = 'merged', merged_into_finding_id = ? WHERE id = ?",
            (rows["MI-207"]["id"], rows["MI-206"]["id"]),
        )
        connection.execute(
            "UPDATE assessment_findings SET status = 'merged', merged_into_finding_id = ? WHERE id = ?",
            (rows["MI-209"]["id"], rows["MI-208"]["id"]),
        )
        connection.execute(
            "UPDATE assessment_findings SET status = 'merged', merged_into_finding_id = ? WHERE id = ?",
            (rows["MI-208"]["id"], rows["MI-209"]["id"]),
        )
        connection.execute(
            "UPDATE assessment_findings SET merged_into_finding_id = ? WHERE id = ?",
            (rows["MI-207"]["id"], rows["MI-210"]["id"]),
        )
    db_module.close_thread_connection()
    with sqlite3.connect(str(db_module.database_path())) as raw_connection:
        raw_connection.execute("PRAGMA foreign_keys = OFF")
        raw_connection.execute(
            "UPDATE assessment_findings SET status = 'merged', merged_into_finding_id = 999999999 WHERE id = ?",
            (rows["MI-202"]["id"],),
        )
        raw_connection.execute(
            "UPDATE assessment_findings SET status = 'merged', merged_into_finding_id = 'invalid' WHERE id = ?",
            (rows["MI-211"]["id"],),
        )

    response = client.get(f"{ASSESSMENT_BASE}/report-readiness")

    assert response.status_code == 200, response.text
    blockers = [
        blocker
        for blocker in response.json()["blockers"]
        if blocker["kind"] == "finding_merge_integrity"
    ]
    by_slug = {str(blocker["slug"]): str(blocker["detail"]) for blocker in blockers}
    expected_corrupt_slugs = set(slugs) - {"MI-206", "MI-207"}
    assert expected_corrupt_slugs <= set(by_slug)
    assert "no merge target" in by_slug["MI-201"]
    assert "does not exist" in by_slug["MI-202"]
    assert "another engagement" in by_slug["MI-203"]
    assert "MI-299" not in by_slug["MI-203"]
    assert "itself" in by_slug["MI-204"]
    assert "depth" in by_slug["MI-205"]
    assert "MI-206" in by_slug["MI-205"]
    assert "MI-207" in by_slug["MI-205"]
    assert "cycle" in by_slug["MI-208"]
    assert "cycle" in by_slug["MI-209"]
    assert "non-merged" in by_slug["MI-210"]
    assert "valid finding id" in by_slug["MI-211"]


def test_fractional_merge_pointers_are_never_coerced_to_finding_ids(
    client,
    isolate_settings,
) -> None:
    _seed_engagement(client, isolate_settings)
    for slug in ("MI-301", "MI-302", "MI-303"):
        _create_finding(client, slug)

    with db_module.get_connection() as connection:
        rows = {
            str(row["slug"]): dict(row)
            for row in connection.execute(
                "SELECT * FROM assessment_findings WHERE slug IN ('MI-301', 'MI-302', 'MI-303')"
            )
        }
    db_module.close_thread_connection()
    with sqlite3.connect(str(db_module.database_path())) as raw_connection:
        raw_connection.execute("PRAGMA foreign_keys = OFF")
        # MI-301 is a chain whose intermediate target has a corrupt fractional
        # pointer; MI-303 carries the same corrupt shape directly.
        raw_connection.execute(
            "UPDATE assessment_findings SET status = 'merged', merged_into_finding_id = ? WHERE id = ?",
            (rows["MI-302"]["id"], rows["MI-301"]["id"]),
        )
        raw_connection.execute(
            "UPDATE assessment_findings SET status = 'merged', merged_into_finding_id = 1.5 WHERE id = ?",
            (rows["MI-302"]["id"],),
        )
        raw_connection.execute(
            "UPDATE assessment_findings SET status = 'merged', merged_into_finding_id = 1.5 WHERE id = ?",
            (rows["MI-303"]["id"],),
        )

    db_module.init_db()

    with db_module.get_connection() as connection:
        after = {
            str(row["slug"]): dict(row)
            for row in connection.execute(
                "SELECT * FROM assessment_findings WHERE slug IN ('MI-301', 'MI-302', 'MI-303')"
            )
        }
    assert after["MI-301"]["merged_into_finding_id"] == rows["MI-302"]["id"]
    assert after["MI-302"]["merged_into_finding_id"] == 1.5
    assert after["MI-303"]["merged_into_finding_id"] == 1.5

    response = client.get(f"{ASSESSMENT_BASE}/report-readiness")
    assert response.status_code == 200, response.text
    merge_blockers = {
        str(item.get("slug")): str(item.get("detail"))
        for item in response.json()["blockers"]
        if item.get("kind") == "finding_merge_integrity"
    }
    assert "valid finding id" in merge_blockers["MI-301"]
    assert "valid finding id" in merge_blockers["MI-302"]
    assert "valid finding id" in merge_blockers["MI-303"]
