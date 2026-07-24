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


_HIGH_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
_MEDIUM_VECTOR = "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N"


def _create_cvss_finding(
    client,
    slug: str,
    *,
    severity: str,
    cvss_score: float,
    cvss_vector: str,
    impact: str,
    workflow_status: str = "active",
    verification_state: str = "verified",
    verification_disposition: str = "confirmed",
    key: str = ENGAGEMENT_KEY,
) -> dict:
    """Create a finding carrying flat CVSS/impact details_json keys."""
    response = client.post(
        f"/engagements/{key}/assessment/findings",
        json={
            "slug": slug,
            "title": f"Finding {slug}",
            "severity": severity,
            "workflow_status": workflow_status,
            "verification_state": verification_state,
            "verification_disposition": verification_disposition,
            "defect_family": "merge-integrity",
            "auth_context": "anonymous",
            "canonical_location": f"https://merge.example/{slug.lower()}",
            "summary": f"Summary for {slug}",
            "evidence_ref": f"evidence/{slug.lower()}.json",
            "source_name": "test-agent",
            "details": {
                "cvss_score": cvss_score,
                "cvss_vector": cvss_vector,
                "impact": impact,
                "evidence": "proof",
            },
            "provenance": {"agent_name": "test-agent"},
            "links": [],
        },
    )
    assert response.status_code == 201, response.text
    return response.json()["finding"]


def test_merge_medium_into_high_preserves_canonical_cvss_and_impact(client, isolate_settings) -> None:
    """I-13: merging a weaker (Medium) duplicate into the High canonical keeps
    the canonical's severity AND its CVSS/impact.

    Regression: ``details_json`` previously let the SOURCE win every non-empty
    key, so the canonical's cvss_score/cvss_vector/impact were overwritten with
    the Medium values while severity stayed High — tripping the severity↔CVSS
    readiness gate.
    """
    _seed_engagement(client, isolate_settings)
    _create_cvss_finding(
        client, "MI-401",
        severity="high", cvss_score=8.1, cvss_vector=_HIGH_VECTOR, impact="Full account takeover",
    )
    _create_cvss_finding(
        client, "MI-402",
        severity="medium", cvss_score=5.3, cvss_vector=_MEDIUM_VECTOR, impact="Limited disclosure",
    )

    response = _merge(client, "MI-402", "MI-401")
    assert response.status_code == 200, response.text

    target = response.json()["target"]
    assert target["severity"] == "high"
    details = json.loads(target["details_json"])
    assert details["cvss_score"] == 8.1
    assert details["cvss_vector"] == _HIGH_VECTOR
    assert details["impact"] == "Full account takeover"

    # The severity↔CVSS gate must not trip on the merged canonical.
    readiness = client.get(f"{ASSESSMENT_BASE}/report-readiness")
    assert readiness.status_code == 200, readiness.text
    mismatches = [
        blocker
        for blocker in readiness.json()["blockers"]
        if blocker.get("kind") == "severity_cvss_mismatch" and blocker.get("slug") == "MI-401"
    ]
    assert mismatches == [], mismatches


def test_merge_high_source_into_medium_target_lets_stronger_source_cvss_win(
    client, isolate_settings
) -> None:
    """A stronger source may raise CVSS, but cannot overwrite canonical prose."""
    _seed_engagement(client, isolate_settings)
    _create_cvss_finding(
        client, "MI-403",
        severity="medium", cvss_score=5.3, cvss_vector=_MEDIUM_VECTOR, impact="Limited disclosure",
    )
    _create_cvss_finding(
        client, "MI-404",
        severity="high", cvss_score=8.1, cvss_vector=_HIGH_VECTOR, impact="Full account takeover",
    )

    response = _merge(client, "MI-404", "MI-403")
    assert response.status_code == 200, response.text

    target = response.json()["target"]
    assert target["severity"] == "high"
    details = json.loads(target["details_json"])
    assert details["cvss_score"] == 8.1
    assert details["cvss_vector"] == _HIGH_VECTOR
    assert details["impact"] == "Limited disclosure"


def test_merge_source_only_fills_missing_narrative_keys(
    client, isolate_settings
) -> None:
    _seed_engagement(client, isolate_settings)
    target = _create_cvss_finding(
        client,
        "MI-407",
        severity="medium",
        cvss_score=5.3,
        cvss_vector=_MEDIUM_VECTOR,
        impact="Canonical impact.",
    )
    source = _create_cvss_finding(
        client,
        "MI-408",
        severity="medium",
        cvss_score=5.3,
        cvss_vector=_MEDIUM_VECTOR,
        impact="Duplicate impact.",
    )
    # Give both rows colliding narrative fields, with one source-only field.
    for slug, chain, followup, extra in (
        ("MI-407", "Canonical chain.", "Canonical follow-up.", {}),
        (
            "MI-408",
            "Duplicate chain.",
            "Merge into canonical.",
            {"source_only_evidence": "preserve this additional fact"},
        ),
    ):
        response = client.patch(
            f"{ASSESSMENT_BASE}/findings/{slug}",
            json={
                "details": {
                    "chain_rationale": chain,
                    "required_followup": followup,
                    **extra,
                }
            },
        )
        assert response.status_code == 200, response.text

    merged = _merge(client, source["slug"], target["slug"])
    assert merged.status_code == 200, merged.text
    details = json.loads(merged.json()["target"]["details_json"])
    assert details["chain_rationale"] == "Canonical chain."
    assert details["required_followup"] == "Canonical follow-up."
    assert details["source_only_evidence"] == "preserve this additional fact"


def test_merge_retires_source_links_instead_of_deleting_evidence(
    client, isolate_settings
) -> None:
    _seed_engagement(client, isolate_settings)
    _create_finding(client, "MI-501")
    _create_finding(client, "MI-502")
    created_link = client.post(
        f"{ASSESSMENT_BASE}/findings/MI-501/links",
        json={
            "link_kind": "related",
            "target_kind": "chain",
            "target_id": 77,
            "notes": "Source relationship evidence.",
        },
    )
    assert created_link.status_code == 200, created_link.text
    source_link_id = created_link.json()["id"]

    merged = _merge(client, "MI-501", "MI-502")

    assert merged.status_code == 200, merged.text
    links = client.get(f"{ASSESSMENT_BASE}/finding-links").json()
    original = next(row for row in links if row["id"] == source_link_id)
    assert original["finding_slug"] == "MI-501"
    assert original["notes"] == "Source relationship evidence."
    assert original["retired_at"]
    copied = [
        row
        for row in links
        if row["finding_slug"] == "MI-502"
        and row["target_kind"] == "chain"
        and row["target_id"] == 77
    ]
    assert len(copied) == 1
    assert copied[0]["retired_at"] is None


def test_merge_progressed_low_severity_source_keeps_canonical_high_cvss(
    client, isolate_settings
) -> None:
    """Reverse edge (QC MINOR-2): details/summary precedence keys off confidence
    (``source_stronger``), but CVSS must key off SEVERITY. A more-progressed
    (verified/confirmed) but LOWER-severity source merged into a fresher,
    HIGHER-severity target must NOT drag the canonical's CVSS down to the
    source's band — which would leave severity=high with a medium cvss_score and
    trip the severity↔CVSS readiness gate."""
    _seed_engagement(client, isolate_settings)
    # Target: fresh/unreviewed but HIGH.
    _create_cvss_finding(
        client, "MI-405",
        severity="high", cvss_score=8.1, cvss_vector=_HIGH_VECTOR, impact="Full account takeover",
        workflow_status="active", verification_state="unreviewed", verification_disposition="none",
    )
    # Source: more-progressed (verified/confirmed) but only MEDIUM -> source_stronger by confidence,
    # even though its severity is lower.
    _create_cvss_finding(
        client, "MI-406",
        severity="medium", cvss_score=5.3, cvss_vector=_MEDIUM_VECTOR, impact="Limited disclosure",
        workflow_status="active", verification_state="verified", verification_disposition="confirmed",
    )

    response = _merge(client, "MI-406", "MI-405")
    assert response.status_code == 200, response.text

    target = response.json()["target"]
    assert target["severity"] == "high"
    details = json.loads(target["details_json"])
    # CVSS follows the severity winner (target/high), NOT the confidence winner (source/medium).
    assert details["cvss_score"] == 8.1
    assert details["cvss_vector"] == _HIGH_VECTOR

    readiness = client.get(f"{ASSESSMENT_BASE}/report-readiness")
    assert readiness.status_code == 200, readiness.text
    mismatches = [
        blocker
        for blocker in readiness.json()["blockers"]
        if blocker.get("kind") == "severity_cvss_mismatch" and blocker.get("slug") == "MI-405"
    ]
    assert mismatches == [], mismatches


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
