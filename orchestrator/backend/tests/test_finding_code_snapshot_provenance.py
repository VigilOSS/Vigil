from __future__ import annotations

import json
from pathlib import Path

import pytest
from app import db as db_module
from app.api.assessment import (
    FindingPatchRequest,
    FindingRecordRequest,
    FindingVerifyRequest,
)
from app.services.state_manager import findings as findings_service
from fastapi import HTTPException
from pydantic import ValidationError

_CODE_SNAPSHOT = {
    "repo_id": 7,
    "repo_generation": 3,
    "source_manifest_digest": "7f" * 32,
}

_ENGAGEMENT_KEY = "2026-08-04-finding-provenance"


def _write_code_engagement(engagements_dir: Path) -> None:
    engagement_dir = engagements_dir / _ENGAGEMENT_KEY
    (engagement_dir / "sessions").mkdir(parents=True)
    (engagement_dir / "engagement.json").write_text(
        json.dumps(
            {
                "key": _ENGAGEMENT_KEY,
                "target": "https://example.com",
                "created_at": "2026-08-04T12:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    (engagement_dir / "scope.json").write_text(
        json.dumps(
            {
                "hostname": "example.com",
                "engagement_type": "code",
                "status": "in_progress",
                "current_phase": "code-verify",
            }
        ),
        encoding="utf-8",
    )
    (engagement_dir / "sessions" / "index.json").write_text("[]", encoding="utf-8")
    (engagement_dir / "log.md").write_text("# Engagement Log\n", encoding="utf-8")
    (engagement_dir / "findings.md").write_text("# Findings\n", encoding="utf-8")


def _seed_repo(client, isolate_settings, *, quality: str = "verified") -> dict[str, object]:
    _write_code_engagement(isolate_settings["engagements_dir"])
    assert client.get("/engagements").status_code == 200
    with db_module.get_connection() as connection:
        engagement_id = int(
            connection.execute(
                "SELECT id FROM engagements WHERE key = ?", (_ENGAGEMENT_KEY,)
            ).fetchone()["id"]
        )
        cursor = connection.execute(
            """
            INSERT INTO code_repos (
                engagement_id, repo_key, name, repo_path, active_generation,
                source_manifest_digest, source_snapshot_quality
            ) VALUES (?, 'bound-repo', 'Bound repo', '/tmp/bound-repo', 3, ?, ?)
            """,
            (engagement_id, _CODE_SNAPSHOT["source_manifest_digest"], quality),
        )
    return {
        "repo_id": int(cursor.lastrowid),
        "repo_generation": 3,
        "source_manifest_digest": _CODE_SNAPSHOT["source_manifest_digest"],
    }


def _finding_payload(
    slug: str,
    binding: dict[str, object] | None,
    *,
    location: str = "file:src/parser.c:41",
    severity: str = "info",
) -> dict[str, object]:
    provenance: dict[str, object] = {"agent_name": "code-vuln-hunter"}
    if binding is not None:
        provenance["code_snapshot"] = binding
    return {
        "slug": slug,
        "title": f"Unchecked parser length {slug}",
        "severity": severity,
        "workflow_status": "active",
        "verification_state": "verified",
        "verification_disposition": "confirmed",
        "defect_family": "buffer-overflow",
        "canonical_location": location,
        "summary": "An attacker-controlled length reaches a fixed-size copy.",
        "source_name": "code-vuln-hunter",
        "details": {
            "evidence": "The copy length is attacker controlled.",
            "impact": "Memory corruption",
            "cvss_score": 8.1,
            "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "steps_to_reproduce": ["Reach parse_packet with an oversized length."],
            "remediation": "Reject lengths larger than the destination buffer.",
        },
        "provenance": provenance,
        "evidence_type": "code-inferred",
    }


def _record(client, payload: dict[str, object]):
    return client.post(
        f"/engagements/{_ENGAGEMENT_KEY}/assessment/findings", json=payload
    )


def _advance_repo(binding: dict[str, object]) -> dict[str, object]:
    current = {
        **binding,
        "repo_generation": int(binding["repo_generation"]) + 1,
        "source_manifest_digest": "8e" * 32,
    }
    with db_module.get_connection() as connection:
        connection.execute(
            """
            UPDATE code_repos
            SET active_generation = ?, source_manifest_digest = ?
            WHERE id = ?
            """,
            (
                current["repo_generation"],
                current["source_manifest_digest"],
                current["repo_id"],
            ),
        )
    return current


def test_finding_requests_normalize_canonical_location_boundaries() -> None:
    record = FindingRecordRequest(
        **_finding_payload(
            "VA-NORMALIZED",
            _CODE_SNAPSHOT,
            location="  file:src/parser.c:41  ",
        )
    )
    patch = FindingPatchRequest(canonical_location="  file:src/parser.c:42  ")

    assert record.canonical_location == "file:src/parser.c:41"
    assert patch.canonical_location == "file:src/parser.c:42"


def _record_payload() -> dict[str, object]:
    return {
        "title": "Unchecked parser length",
        "canonical_location": "file:src/parser.c:41",
        "provenance": {"agent_name": "code-vuln-hunter", "code_snapshot": _CODE_SNAPSHOT},
    }


def test_finding_record_requires_complete_code_snapshot_shape() -> None:
    payload = _record_payload()
    payload["provenance"] = {
        "code_snapshot": {"repo_id": 7, "repo_generation": 3}
    }

    with pytest.raises(ValidationError, match="source_manifest_digest"):
        FindingRecordRequest.model_validate(payload)


def test_finding_verify_requires_complete_code_snapshot_shape() -> None:
    with pytest.raises(ValidationError, match="source_manifest_digest"):
        FindingVerifyRequest.model_validate(
            {
                "disposition": "confirmed",
                "reason_text": "Reviewed the complete dataflow.",
                "provenance": {
                    "code_snapshot": {"repo_id": 7, "repo_generation": 3}
                },
            }
        )


@pytest.mark.parametrize(
    "digest",
    [
        "a" * 63,
        "a" * 65,
        "A" * 64,
        "g" * 64,
        f"{'a' * 63} ",
    ],
)
def test_code_snapshot_digest_requires_exact_lowercase_sha256_in_api(digest) -> None:
    payload = _record_payload()
    payload["provenance"] = {
        "code_snapshot": {
            **_CODE_SNAPSHOT,
            "source_manifest_digest": digest,
        }
    }

    with pytest.raises(ValidationError, match="source_manifest_digest"):
        FindingRecordRequest.model_validate(payload)


@pytest.mark.parametrize("digest", ["A" * 64, "g" * 64, "a" * 63, f"{'a' * 63} "])
def test_code_snapshot_digest_requires_exact_lowercase_sha256_in_service(digest) -> None:
    with pytest.raises(HTTPException) as exc_info:
        findings_service._code_snapshot_binding(
            {
                "code_snapshot": {
                    **_CODE_SNAPSHOT,
                    "source_manifest_digest": digest,
                }
            },
            strict=True,
        )

    assert exc_info.value.status_code == 400
    assert "lowercase SHA-256" in str(exc_info.value.detail)


def test_generic_finding_patch_rejects_reserved_code_snapshot_binding() -> None:
    with pytest.raises(ValidationError, match="code_snapshot"):
        FindingPatchRequest.model_validate(
            {"provenance": {"reviewed_by": "operator", "code_snapshot": _CODE_SNAPSHOT}}
        )


def test_non_reserved_patch_provenance_remains_compatible() -> None:
    request = FindingPatchRequest.model_validate(
        {"provenance": {"reviewed_by": "operator"}}
    )

    assert request.provenance == {"reviewed_by": "operator"}


def test_non_file_finding_remains_compatible_without_code_snapshot(
    client, isolate_settings
) -> None:
    _seed_repo(client, isolate_settings)
    response = _record(
        client,
        _finding_payload(
            "VA-001", None, location="https://example.com/api/orders/7"
        ),
    )

    assert response.status_code == 201, response.text


@pytest.mark.parametrize(
    ("binding_mutation", "expected_detail"),
    [
        (lambda binding: {**binding, "repo_generation": 2}, "generation"),
        (
            lambda binding: {**binding, "source_manifest_digest": "00" * 32},
            "digest",
        ),
    ],
)
def test_file_finding_record_rejects_stale_snapshot_binding(
    client, isolate_settings, binding_mutation, expected_detail
) -> None:
    binding = _seed_repo(client, isolate_settings)
    response = _record(
        client, _finding_payload("VA-002", binding_mutation(binding))
    )

    assert response.status_code == 409, response.text
    assert expected_detail in response.json()["detail"].lower()


def test_file_finding_record_rejects_unverified_repo_snapshot(
    client, isolate_settings
) -> None:
    binding = _seed_repo(client, isolate_settings, quality="legacy-unverified")
    response = _record(client, _finding_payload("VA-003", binding))

    assert response.status_code == 409, response.text
    assert "verified" in response.json()["detail"].lower()


def test_file_finding_record_accepts_current_verified_snapshot(
    client, isolate_settings
) -> None:
    binding = _seed_repo(client, isolate_settings)
    response = _record(client, _finding_payload("VA-004", binding))

    assert response.status_code == 201, response.text
    stored = json.loads(response.json()["finding"]["provenance_json"])
    assert stored["code_snapshot"] == binding


def test_verify_is_the_only_path_that_can_rebind_a_stale_file_finding(
    client, isolate_settings
) -> None:
    stale_binding = _seed_repo(client, isolate_settings)
    created = _record(client, _finding_payload("VA-005", stale_binding))
    assert created.status_code == 201, created.text
    current_binding = _advance_repo(stale_binding)

    listed = client.get(
        f"/engagements/{_ENGAGEMENT_KEY}/assessment/findings"
    ).json()
    assert json.loads(listed[0]["provenance_json"])["code_snapshot"] == stale_binding
    assert listed[0]["code_snapshot_status"] == "stale"

    fetched = client.get(
        f"/engagements/{_ENGAGEMENT_KEY}/assessment/findings/VA-005"
    )
    assert fetched.status_code == 200, fetched.text
    assert fetched.json()["code_snapshot_status"] == "stale"

    patch = client.patch(
        f"/engagements/{_ENGAGEMENT_KEY}/assessment/findings/VA-005",
        json={"provenance": {"code_snapshot": current_binding}},
    )
    assert patch.status_code == 422

    verify_without_binding = client.post(
        f"/engagements/{_ENGAGEMENT_KEY}/assessment/findings/VA-005/verify",
        json={
            "disposition": "confirmed",
            "reason_text": "Re-reviewed the current dataflow.",
        },
    )
    assert verify_without_binding.status_code == 400

    verified = client.post(
        f"/engagements/{_ENGAGEMENT_KEY}/assessment/findings/VA-005/verify",
        json={
            "disposition": "confirmed",
            "reason_text": "Re-reviewed the current dataflow.",
            "source_name": "code-vuln-verifier",
            "provenance": {"code_snapshot": current_binding},
        },
    )
    assert verified.status_code == 200, verified.text
    rebound = json.loads(verified.json()["finding"]["provenance_json"])
    assert rebound["code_snapshot"] == current_binding

    relisted = client.get(
        f"/engagements/{_ENGAGEMENT_KEY}/assessment/findings"
    ).json()
    assert relisted[0]["code_snapshot_status"] == "current"


def test_finding_reads_distinguish_unbound_legacy_and_non_file_records(
    client, isolate_settings
) -> None:
    binding = _seed_repo(client, isolate_settings)
    assert _record(
        client,
        _finding_payload(
            "VA-016", binding, location="https://example.com/api/orders/16"
        ),
    ).status_code == 201
    assert _record(
        client,
        _finding_payload(
            "VA-017", None, location="https://example.com/legacy/17"
        ),
    ).status_code == 201
    with db_module.get_connection() as connection:
        connection.execute(
            """
            UPDATE assessment_findings
            SET canonical_location = 'file:src/legacy.c:17', provenance_json = '{}'
            WHERE engagement_id = (SELECT id FROM engagements WHERE key = ?)
              AND slug = 'VA-017'
            """,
            (_ENGAGEMENT_KEY,),
        )

    rows = {
        row["slug"]: row
        for row in client.get(
            f"/engagements/{_ENGAGEMENT_KEY}/assessment/findings"
        ).json()
    }

    assert rows["VA-016"]["code_snapshot_status"] == "current"
    assert rows["VA-017"]["code_snapshot_status"] == "unbound"


@pytest.mark.parametrize(
    "replacement",
    ["https://example.com/api/parser", "FILE:src/parser.c:42"],
)
def test_generic_patch_cannot_remove_file_finding_snapshot_gating(
    client, isolate_settings, replacement
) -> None:
    binding = _seed_repo(client, isolate_settings)
    assert _record(client, _finding_payload("VA-019", binding)).status_code == 201
    _advance_repo(binding)

    patched = client.patch(
        f"/engagements/{_ENGAGEMENT_KEY}/assessment/findings/VA-019",
        json={"canonical_location": replacement},
    )
    assert patched.status_code == 400, patched.text
    assert "category" in patched.json()["detail"].lower()

    fetched = client.get(
        f"/engagements/{_ENGAGEMENT_KEY}/assessment/findings/VA-019"
    )
    assert fetched.status_code == 200, fetched.text
    assert fetched.json()["canonical_location"] == "file:src/parser.c:41"
    assert fetched.json()["code_snapshot_status"] == "stale"
    readiness = client.get(
        f"/engagements/{_ENGAGEMENT_KEY}/assessment/report-readiness"
    ).json()
    assert any(
        blocker.get("kind") == "finding_code_snapshot"
        and blocker.get("slug") == "VA-019"
        for blocker in readiness["blockers"]
    )


def test_generic_patch_cannot_turn_non_file_finding_into_file_finding(
    client, isolate_settings
) -> None:
    _seed_repo(client, isolate_settings)
    assert _record(
        client,
        _finding_payload(
            "VA-020", None, location="https://example.com/api/parser"
        ),
    ).status_code == 201

    patched = client.patch(
        f"/engagements/{_ENGAGEMENT_KEY}/assessment/findings/VA-020",
        json={"canonical_location": "file:src/parser.c:42"},
    )
    assert patched.status_code == 400, patched.text
    assert "category" in patched.json()["detail"].lower()


def test_generic_patch_preserves_same_category_location_corrections(
    client, isolate_settings
) -> None:
    binding = _seed_repo(client, isolate_settings)
    assert _record(client, _finding_payload("VA-021", binding)).status_code == 201
    assert _record(
        client,
        _finding_payload(
            "VA-022", None, location="https://example.com/api/parser"
        ),
    ).status_code == 201

    file_patch = client.patch(
        f"/engagements/{_ENGAGEMENT_KEY}/assessment/findings/VA-021",
        json={"canonical_location": "file:src/parser.c:42"},
    )
    assert file_patch.status_code == 200, file_patch.text
    assert file_patch.json()["finding"]["canonical_location"] == "file:src/parser.c:42"
    assert json.loads(file_patch.json()["finding"]["provenance_json"])[
        "code_snapshot"
    ] == binding

    web_patch = client.patch(
        f"/engagements/{_ENGAGEMENT_KEY}/assessment/findings/VA-022",
        json={"canonical_location": "https://example.com/api/parser/2"},
    )
    assert web_patch.status_code == 200, web_patch.text
    assert (
        web_patch.json()["finding"]["canonical_location"]
        == "https://example.com/api/parser/2"
    )


def test_same_slug_rerecord_cannot_remove_legacy_file_snapshot_gating(
    client, isolate_settings
) -> None:
    _seed_repo(client, isolate_settings)
    original = _finding_payload(
        "VA-025", None, location="https://example.com/legacy/parser"
    )
    assert _record(client, original).status_code == 201
    with db_module.get_connection() as connection:
        connection.execute(
            """
            UPDATE assessment_findings
            SET canonical_location = 'file:src/legacy.c:25', provenance_json = '{}'
            WHERE engagement_id = (SELECT id FROM engagements WHERE key = ?)
              AND slug = 'VA-025'
            """,
            (_ENGAGEMENT_KEY,),
        )

    replay = _finding_payload(
        "VA-025", None, location="https://example.com/api/parser/25"
    )
    rerecorded = _record(client, replay)
    assert rerecorded.status_code == 409, rerecorded.text
    assert "category" in rerecorded.json()["detail"].lower()

    fetched = client.get(
        f"/engagements/{_ENGAGEMENT_KEY}/assessment/findings/VA-025"
    )
    assert fetched.status_code == 200, fetched.text
    assert fetched.json()["canonical_location"] == "file:src/legacy.c:25"
    assert fetched.json()["code_snapshot_status"] == "unbound"
    readiness = client.get(
        f"/engagements/{_ENGAGEMENT_KEY}/assessment/report-readiness"
    ).json()
    assert any(
        blocker.get("kind") == "finding_code_snapshot"
        and blocker.get("slug") == "VA-025"
        for blocker in readiness["blockers"]
    )


def test_merge_rejects_findings_from_different_code_snapshots(
    client, isolate_settings
) -> None:
    first_binding = _seed_repo(client, isolate_settings)
    assert _record(
        client,
        _finding_payload("VA-006", first_binding, location="file:src/parser.c:41"),
    ).status_code == 201
    second_binding = _advance_repo(first_binding)
    assert _record(
        client,
        _finding_payload("VA-007", second_binding, location="file:src/parser.c:58"),
    ).status_code == 201

    merged = client.post(
        f"/engagements/{_ENGAGEMENT_KEY}/assessment/findings/merge",
        json={
            "source_slug": "VA-006",
            "target_slug": "VA-007",
            "reason": "Same parser family.",
        },
    )

    assert merged.status_code == 409, merged.text
    assert "code snapshot" in merged.json()["detail"].lower()


@pytest.mark.parametrize("bound_is_source", [True, False])
def test_merge_rejects_bound_and_unbound_file_findings(
    client, isolate_settings, bound_is_source
) -> None:
    binding = _seed_repo(client, isolate_settings)
    bound_slug = "VA-010"
    unbound_slug = "VA-011"
    assert _record(
        client,
        _finding_payload(bound_slug, binding, location="file:src/bound.c:10"),
    ).status_code == 201
    assert _record(
        client,
        _finding_payload(unbound_slug, None, location="https://example.com/legacy"),
    ).status_code == 201
    with db_module.get_connection() as connection:
        connection.execute(
            """
            UPDATE assessment_findings
            SET canonical_location = 'file:src/legacy.c:11', provenance_json = '{}'
            WHERE engagement_id = (SELECT id FROM engagements WHERE key = ?)
              AND slug = ?
            """,
            (_ENGAGEMENT_KEY, unbound_slug),
        )
    source_slug, target_slug = (
        (bound_slug, unbound_slug)
        if bound_is_source
        else (unbound_slug, bound_slug)
    )

    merged = client.post(
        f"/engagements/{_ENGAGEMENT_KEY}/assessment/findings/merge",
        json={
            "source_slug": source_slug,
            "target_slug": target_slug,
            "reason": "Legacy duplicate of a snapshot-bound finding.",
        },
    )

    assert merged.status_code == 409, merged.text
    assert "code snapshot" in merged.json()["detail"].lower()


def test_merge_allows_two_unbound_legacy_file_findings(client, isolate_settings) -> None:
    _seed_repo(client, isolate_settings)
    for slug in ("VA-012", "VA-013"):
        assert _record(
            client,
            _finding_payload(slug, None, location=f"https://example.com/{slug}"),
        ).status_code == 201
    with db_module.get_connection() as connection:
        connection.execute(
            """
            UPDATE assessment_findings
            SET canonical_location = 'file:src/legacy.c:12', provenance_json = '{}'
            WHERE engagement_id = (SELECT id FROM engagements WHERE key = ?)
              AND slug IN ('VA-012', 'VA-013')
            """,
            (_ENGAGEMENT_KEY,),
        )

    merged = client.post(
        f"/engagements/{_ENGAGEMENT_KEY}/assessment/findings/merge",
        json={
            "source_slug": "VA-012",
            "target_slug": "VA-013",
            "reason": "Two legacy duplicates without snapshot identity.",
        },
    )

    assert merged.status_code == 200, merged.text


def test_merge_rejects_bound_and_unbound_non_file_findings(client, isolate_settings) -> None:
    binding = _seed_repo(client, isolate_settings)
    assert _record(
        client,
        _finding_payload("VA-014", binding, location="https://example.com/api/orders/14"),
    ).status_code == 201
    assert _record(
        client,
        _finding_payload("VA-015", None, location="https://example.com/api/orders/15"),
    ).status_code == 201

    merged = client.post(
        f"/engagements/{_ENGAGEMENT_KEY}/assessment/findings/merge",
        json={
            "source_slug": "VA-014",
            "target_slug": "VA-015",
            "reason": "Equivalent web finding from a mixed producer fleet.",
        },
    )

    assert merged.status_code == 409, merged.text
    assert "code snapshot" in merged.json()["detail"].lower()


def test_merge_rejects_file_and_non_file_findings_with_the_same_binding(
    client, isolate_settings
) -> None:
    binding = _seed_repo(client, isolate_settings)
    assert _record(
        client,
        _finding_payload("VA-023", binding, location="file:src/parser.c:23"),
    ).status_code == 201
    assert _record(
        client,
        _finding_payload(
            "VA-024", binding, location="https://example.com/api/parser/24"
        ),
    ).status_code == 201

    merged = client.post(
        f"/engagements/{_ENGAGEMENT_KEY}/assessment/findings/merge",
        json={
            "source_slug": "VA-023",
            "target_slug": "VA-024",
            "reason": "Cross-category duplicate.",
        },
    )

    assert merged.status_code == 409, merged.text
    assert "category" in merged.json()["detail"].lower()


def test_report_readiness_blocks_active_stale_and_unbound_file_findings_at_any_severity(
    client, isolate_settings
) -> None:
    stale_binding = _seed_repo(client, isolate_settings)
    assert _record(
        client, _finding_payload("VA-008", stale_binding, severity="info")
    ).status_code == 201
    _advance_repo(stale_binding)

    legacy = _record(
        client,
        _finding_payload(
            "VA-009", None, location="https://example.com/legacy", severity="low"
        ),
    )
    assert legacy.status_code == 201, legacy.text
    with db_module.get_connection() as connection:
        connection.execute(
            """
            UPDATE assessment_findings
            SET canonical_location = '	file:src/legacy.c:9', provenance_json = '{}'
            WHERE engagement_id = (SELECT id FROM engagements WHERE key = ?)
              AND slug = 'VA-009'
            """,
            (_ENGAGEMENT_KEY,),
        )

    response = client.get(
        f"/engagements/{_ENGAGEMENT_KEY}/assessment/report-readiness"
    )
    assert response.status_code == 200, response.text
    snapshot_blockers = {
        blocker["slug"]: blocker["snapshot_status"]
        for blocker in response.json()["blockers"]
        if blocker["kind"] == "finding_code_snapshot"
    }
    assert snapshot_blockers == {"VA-008": "stale", "VA-009": "unbound"}


@pytest.mark.parametrize(
    "workflow_status",
    ["blocked", "exploited", "contained", "eradicated", "recovered", "reported"],
)
@pytest.mark.parametrize("snapshot_status", ["stale", "unbound"])
def test_report_readiness_blocks_invalid_file_snapshot_in_every_reportable_status(
    client, isolate_settings, workflow_status, snapshot_status
) -> None:
    binding = _seed_repo(client, isolate_settings)
    payload = _finding_payload("VA-018", binding)
    payload["workflow_status"] = workflow_status
    assert _record(client, payload).status_code == 201
    if snapshot_status == "stale":
        _advance_repo(binding)
    else:
        with db_module.get_connection() as connection:
            connection.execute(
                """
                UPDATE assessment_findings
                SET provenance_json = '{}'
                WHERE engagement_id = (
                    SELECT id FROM engagements WHERE key = ?
                ) AND slug = 'VA-018'
                """,
                (_ENGAGEMENT_KEY,),
            )

    response = client.get(
        f"/engagements/{_ENGAGEMENT_KEY}/assessment/report-readiness"
    )
    assert response.status_code == 200, response.text
    snapshot_blockers = [
        blocker
        for blocker in response.json()["blockers"]
        if blocker["kind"] == "finding_code_snapshot"
    ]
    assert [blocker["slug"] for blocker in snapshot_blockers] == ["VA-018"]
    assert snapshot_blockers[0]["snapshot_status"] == snapshot_status

    final = client.get(
        f"/engagements/{_ENGAGEMENT_KEY}/assessment/report-findings?mode=final"
    )
    assert final.status_code == 409
