from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from app import db as db_module
from tests.proof_fixtures import completed_confirm_check, post_artifact_backed_source_observation


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
    dispatch = client.post(
        f"/engagements/{key}/assessment/dispatches",
        json={
            "agent_id": "test-agent",
            "agent_role": "finding-author",
            "task": "Author merge-integrity fixtures.",
        },
    )
    assert dispatch.status_code == 201, dispatch.text


def _create_finding(client, slug: str, *, key: str = ENGAGEMENT_KEY) -> dict:
    dispatch_path = f"/engagements/{key}/assessment/dispatches/test-agent"
    existing_dispatch = client.get(dispatch_path)
    if existing_dispatch.status_code == 404:
        dispatch = client.post(
            f"/engagements/{key}/assessment/dispatches",
            json={
                "agent_id": "test-agent",
                "agent_role": "finding-author",
                "task": "Author merge-integrity fixtures.",
            },
        )
        assert dispatch.status_code == 201, dispatch.text
    else:
        assert existing_dispatch.status_code == 200, existing_dispatch.text
    response = client.post(
        f"/engagements/{key}/assessment/findings",
        json={
            "slug": slug,
            "title": f"Finding {slug}",
            "severity": "low",
            "workflow_status": "active",
            "verification_status": "unreviewed",
            "defect_family": "merge-integrity",
            "auth_context": "anonymous",
            "canonical_location": f"https://merge.example/{slug.lower()}",
            "summary": f"Summary for {slug}",
            "evidence_ref": f"evidence/{slug.lower()}.json",
            "source_name": "test-agent",
            "details": {"evidence": "proof", "impact": "impact"},
            "provenance": {"agent_name": "test-agent", "agent_id": "test-agent"},
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


def _confirm_finding(client, slug: str) -> dict:
    verifier_id = f"merge-verifier-{slug.lower()}"
    dispatch = client.post(
        f"{ASSESSMENT_BASE}/dispatches",
        json={
            "agent_id": verifier_id,
            "agent_role": "merge-verifier",
            "task": f"Independently verify {slug}.",
        },
    )
    assert dispatch.status_code == 201, dispatch.text
    run = client.post(
        f"{ASSESSMENT_BASE}/assessment-runs",
        json={
            "run_uuid": f"merge-proof-{slug.lower()}",
            "run_kind": "shared",
            "producer_dispatch_agent_id": verifier_id,
        },
    )
    assert run.status_code == 201, run.text
    linked = client.post(
        f"{ASSESSMENT_BASE}/findings/{slug}/links",
        json={
            "link_kind": "proof_run", "target_kind": "assessment_run",
            "target_id": run.json()["id"],
        },
    )
    assert linked.status_code == 200, linked.text
    receipt = post_artifact_backed_source_observation(
        client,
        f"{ASSESSMENT_BASE}/proof-receipts",
        json={
            "run_id": run.json()["id"],
            "evidence_kind": "source_observation",
            "expected_result": "The reported behavior follows from the recorded evidence.",
            "observed_result": "Independent review confirmed the reported behavior.",
        },
    )
    assert receipt.status_code == 201, receipt.text
    completed = client.patch(
        f"{ASSESSMENT_BASE}/assessment-runs/{run.json()['id']}",
        json={"status": "completed"},
    )
    assert completed.status_code == 200, completed.text
    verified = client.post(
        f"{ASSESSMENT_BASE}/findings/{slug}/verify",
        json={
            "verification_status": "confirmed",
            "reason_text": "Independent review confirmed the finding.",
            "source_name": "merge-verifier",
            "proof_receipt_ids": [receipt.json()["id"]],
            "confirm_check": completed_confirm_check(receipt.json()["id"]),
        },
    )
    assert verified.status_code == 200, verified.text
    return verified.json()["finding"]


# Both vectors compute EXACTLY the score they are paired with below — the
# write-time cvss_score<->cvss_vector check rejects a fixture that does not.
_HIGH_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"  # 8.1
_MEDIUM_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"  # 5.3


def _create_cvss_finding(
    client,
    slug: str,
    *,
    severity: str,
    cvss_score: float,
    cvss_vector: str,
    impact: str,
    workflow_status: str = "active",
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
            "verification_status": "unreviewed",
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
            "provenance": {"agent_name": "test-agent", "agent_id": "test-agent"},
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
    details = target["details"]
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
    details = target["details"]
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
        ("MI-407", "Canonical chain.", ["Canonical follow-up."], {}),
        (
            "MI-408",
            "Duplicate chain.",
            ["Merge into canonical."],
            {"attempts_summary": "preserve this additional fact"},
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
    details = merged.json()["target"]["details"]
    assert details["chain_rationale"] == "Canonical chain."
    assert details["required_followup"] == ["Canonical follow-up."]
    assert details["attempts_summary"] == "preserve this additional fact"


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
        workflow_status="active",
    )
    # Source: more-progressed (verified/confirmed) but only MEDIUM -> source_stronger by confidence,
    # even though its severity is lower.
    _create_cvss_finding(
        client, "MI-406",
        severity="medium", cvss_score=5.3, cvss_vector=_MEDIUM_VECTOR, impact="Limited disclosure",
        workflow_status="active",
    )
    _confirm_finding(client, "MI-406")

    response = _merge(client, "MI-406", "MI-405")
    assert response.status_code == 200, response.text

    target = response.json()["target"]
    assert target["severity"] == "high"
    details = target["details"]
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


# --------------------------------------------------------------------------- #
# CVSS is a pair: merge must never assemble one out of two findings
# --------------------------------------------------------------------------- #


def _create_finding_with_details(client, slug: str, *, severity: str, details: dict) -> dict:
    response = client.post(
        f"{ASSESSMENT_BASE}/findings",
        json={
            "slug": slug,
            "title": f"Finding {slug}",
            "severity": severity,
            "workflow_status": "active",
            "verification_status": "unreviewed",
            "defect_family": "merge-integrity",
            "auth_context": "anonymous",
            "canonical_location": f"https://merge.example/{slug.lower()}",
            "summary": f"Summary for {slug}",
            "evidence_ref": f"evidence/{slug.lower()}.json",
            "source_name": "test-agent",
            "details": details,
            "provenance": {"agent_name": "test-agent", "agent_id": "test-agent"},
            "links": [],
        },
    )
    assert response.status_code == 201, response.text
    return response.json()["finding"]


def test_merge_never_completes_a_half_cvss_pair_from_the_losing_side(
    client, isolate_settings
):
    """Filling only the half the winner lacks manufactures a score its own
    vector never produced — a mismatch NEITHER input finding had."""
    _seed_engagement(client, isolate_settings)
    _create_finding_with_details(
        client,
        "CV-901",
        severity="high",
        details={"cvss_vector": _HIGH_VECTOR, "impact": "Full account takeover"},
    )
    _create_finding_with_details(
        client,
        "CV-902",
        severity="medium",
        details={"cvss_score": 5.3, "cvss_vector": _MEDIUM_VECTOR, "impact": "Limited"},
    )

    response = _merge(client, "CV-902", "CV-901")
    assert response.status_code == 200, response.text

    details = client.get(f"{ASSESSMENT_BASE}/findings/CV-901").json()["details"]
    assert details["cvss_vector"] == _HIGH_VECTOR
    # The severity winner declared no score, so it inherits none — the loser's
    # 5.3 belongs to the loser's vector, not to this one.
    assert "cvss_score" not in details


@pytest.mark.parametrize(
    ("planted", "expected_blocker", "expected_in_warning"),
    [
        ({"cvss_score": 4.4}, "cvss_vector_score_mismatch", "4.4"),
        ({"cvss_vector": "CVSS:3.1/AV:N"}, "cvss_vector_invalid", "CVSS:3.1/AV:N"),
    ],
    ids=["score_mismatch", "unparseable_vector"],
)
def test_merge_completes_over_a_legacy_cvss_defect_and_reports_it(
    client, isolate_settings, planted, expected_blocker, expected_in_warning
):
    """Consolidating duplicates must never be refused over data the caller did
    not author.

    The atomic pair-move above means a contradictory merged pair always arrived
    whole on ONE input — merge cannot manufacture one. Blocking would strand a
    correct consolidation mid-engagement and leave two duplicates in the report,
    so the merge completes, the response says what is wrong, and report-readiness
    still refuses to ship the finding. The defect is planted directly in the row
    because the write path rejects authoring one.
    """
    _seed_engagement(client, isolate_settings)
    _create_finding_with_details(
        client,
        "CV-903",
        severity="high",
        details={"cvss_score": 8.1, "cvss_vector": _HIGH_VECTOR, "impact": "Takeover"},
    )
    _create_finding_with_details(
        client,
        "CV-904",
        severity="medium",
        details={"cvss_score": 5.3, "cvss_vector": _MEDIUM_VECTOR, "impact": "Limited"},
    )
    with db_module.get_connection() as connection:
        stored = json.loads(
            connection.execute(
                "SELECT details_json FROM assessment_findings WHERE slug = ?",
                ("CV-903",),
            ).fetchone()[0]
        )
        stored.update(planted)
        connection.execute(
            "UPDATE assessment_findings SET details_json = ? WHERE slug = ?",
            (json.dumps(stored), "CV-903"),
        )

    response = _merge(client, "CV-904", "CV-903")

    assert response.status_code == 200, response.text
    body = response.json()
    # The consolidation actually happened — the duplicate is gone from the report.
    assert body["source"]["workflow_status"] == "merged"
    assert body["target"]["slug"] == "CV-903"
    # ... and the contradiction is stated, with the verb that repairs it.
    assert len(body["warnings"]) == 1, body["warnings"]
    warning = body["warnings"][0]
    assert expected_in_warning in warning
    assert "vigil assess finding update CV-903" in warning

    # Merge correctly invalidates prior verification because it materially
    # changes the target. Reconstruct the reportable legacy state through the
    # real proof-backed verification path, then restore the historical defect
    # that no public write contract permits.
    repaired = {
        **stored,
        "cvss_score": 8.1,
        "cvss_vector": _HIGH_VECTOR,
    }
    with db_module.get_connection() as connection:
        connection.execute(
            "UPDATE assessment_findings SET details_json = ? WHERE slug = ?",
            (json.dumps(repaired), "CV-903"),
        )
    _confirm_finding(client, "CV-903")
    with db_module.get_connection() as connection:
        connection.execute(
            "UPDATE assessment_findings SET details_json = ? WHERE slug = ?",
            (json.dumps(stored), "CV-903"),
        )

    # The backstop that actually keeps it out of a submission is still armed.
    blockers = client.get(f"{ASSESSMENT_BASE}/report-readiness").json()["blockers"]
    assert [
        blocker
        for blocker in blockers
        if blocker.get("slug") == "CV-903" and blocker["kind"] == expected_blocker
    ], blockers


def test_a_clean_merge_reports_no_warnings(client, isolate_settings):
    """The ``warnings`` key is unconditional so a caller can read it blind."""
    _seed_engagement(client, isolate_settings)
    _create_finding_with_details(
        client,
        "CV-905",
        severity="high",
        details={"cvss_score": 8.1, "cvss_vector": _HIGH_VECTOR, "impact": "Takeover"},
    )
    _create_finding_with_details(
        client,
        "CV-906",
        severity="medium",
        details={"cvss_score": 5.3, "cvss_vector": _MEDIUM_VECTOR, "impact": "Limited"},
    )

    response = _merge(client, "CV-906", "CV-905")

    assert response.status_code == 200, response.text
    assert response.json()["warnings"] == []
