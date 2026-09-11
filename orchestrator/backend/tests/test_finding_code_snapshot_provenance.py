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
from tests.proof_fixtures import post_artifact_backed_source_observation

_CODE_SNAPSHOT = {
    "repo_id": 7,
    "repo_generation": 3,
    "source_manifest_digest": "7f" * 32,
}

_ENGAGEMENT_KEY = "2026-08-04-finding-provenance"
_DEFAULT_AUTHOR_AGENT_ID = "snapshot-fixture-author"


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
    _dispatch(client, _DEFAULT_AUTHOR_AGENT_ID)
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
    author_agent_id: str | None = _DEFAULT_AUTHOR_AGENT_ID,
) -> dict[str, object]:
    provenance: dict[str, object] = {"agent_name": "code-vuln-hunter"}
    if author_agent_id is not None:
        provenance["agent_id"] = author_agent_id
    if binding is not None:
        provenance["code_snapshot"] = binding
    return {
        "slug": slug,
        "title": f"Unchecked parser length {slug}",
        "severity": severity,
        "workflow_status": "active",
        "verification_status": "unreviewed",
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
                "verification_status": "confirmed",
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
    stored = response.json()["finding"]["provenance"]
    assert stored["code_snapshot"] == binding


def test_verify_is_the_only_path_that_can_rebind_a_stale_file_finding(
    client, isolate_settings
) -> None:
    stale_binding = _seed_repo(client, isolate_settings)
    _dispatch(client, "hunter-005")
    created = _record(
        client,
        _finding_payload("VA-005", stale_binding, author_agent_id="hunter-005"),
    )
    assert created.status_code == 201, created.text
    current_binding = _advance_repo(stale_binding)

    listed = client.get(
        f"/engagements/{_ENGAGEMENT_KEY}/assessment/findings"
    ).json()
    assert listed[0]["provenance"]["code_snapshot"] == stale_binding
    assert listed[0]["code_snapshot_status"] == "stale"

    fetched = client.get(
        f"/engagements/{_ENGAGEMENT_KEY}/assessment/findings/VA-005"
    )
    assert fetched.status_code == 200, fetched.text
    assert fetched.json()["code_snapshot_status"] == "stale"

    _dispatch(client, "cvv-005", role="code-vuln-verifier")
    proof_receipt_id = _verification_receipt(client, "cvv-005", "VA-005")

    patch = client.patch(
        f"/engagements/{_ENGAGEMENT_KEY}/assessment/findings/VA-005",
        json={"provenance": {"code_snapshot": current_binding}},
    )
    assert patch.status_code == 422

    verify_without_binding = client.post(
        f"/engagements/{_ENGAGEMENT_KEY}/assessment/findings/VA-005/verify",
        json={
            "verification_status": "confirmed",
            "reason_text": "Re-reviewed the current dataflow.",
            "proof_receipt_ids": [proof_receipt_id],
            "severity_variance": _info_severity_variance(proof_receipt_id),
        },
    )
    assert verify_without_binding.status_code == 400

    verified = client.post(
        f"/engagements/{_ENGAGEMENT_KEY}/assessment/findings/VA-005/verify",
        json={
            "verification_status": "confirmed",
            "reason_text": "Re-reviewed the current dataflow.",
            "source_name": "code-vuln-verifier",
            "provenance": {"code_snapshot": current_binding},
            "proof_receipt_ids": [proof_receipt_id],
            "severity_variance": _info_severity_variance(proof_receipt_id),
        },
    )
    assert verified.status_code == 200, verified.text
    rebound = verified.json()["finding"]["provenance"]
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
    # The derived status is only self-explaining beside the PARSED binding that
    # produced it. While provenance was an opaque string with no parsed twin,
    # two findings differing solely in provenance.code_snapshot read identically
    # in every default response, and the status looked like a mystery.
    assert rows["VA-016"]["provenance"]["code_snapshot"] == binding
    assert "code_snapshot" not in rows["VA-017"]["provenance"]


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
    assert file_patch.json()["finding"]["provenance"][
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
    assert rerecorded.status_code == 400, rerecorded.text
    assert "bind-author" in rerecorded.json()["detail"].lower()

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


@pytest.mark.parametrize("live_has_binding", [False, True])
def test_merge_cross_track_keeps_structured_source_location_and_both_evidence_refs(
    client, isolate_settings, live_has_binding
) -> None:
    binding = _seed_repo(client, isolate_settings)
    source_payload = _finding_payload(
        "VA-023", binding, location="file:src/parser.c:23"
    )
    source_payload["evidence_ref"] = "evidence/static-parser.json"
    assert _record(client, source_payload).status_code == 201
    live_payload = _finding_payload(
        "VA-024",
        binding if live_has_binding else None,
        location="https://example.com/api/parser/24",
    )
    live_payload["evidence_ref"] = "evidence/live-parser.json"
    assert _record(client, live_payload).status_code == 201

    merged = client.post(
        f"/engagements/{_ENGAGEMENT_KEY}/assessment/findings/merge",
        json={
            "source_slug": "VA-023",
            "target_slug": "VA-024",
            "reason": "Cross-category duplicate.",
        },
    )

    assert merged.status_code == 200, merged.text
    target = merged.json()["target"]
    assert target["canonical_location"] == "file:src/parser.c:23"
    assert target["provenance"]["code_snapshot"] == binding
    assert target["code_snapshot_status"] == "current"
    with db_module.get_connection() as connection:
        evidence_refs = {
            str(row["target_ref"])
            for row in connection.execute(
                """
                SELECT target_ref
                FROM assessment_finding_links
                WHERE engagement_id = (SELECT id FROM engagements WHERE key = ?)
                  AND finding_id = (SELECT id FROM assessment_findings WHERE slug = 'VA-024')
                  AND link_kind = 'evidence'
                  AND retired_at IS NULL
                """,
                (_ENGAGEMENT_KEY,),
            ).fetchall()
        }
    assert evidence_refs == {
        "evidence/static-parser.json",
        "evidence/live-parser.json",
    }


def test_cross_track_merge_preserves_confirmed_target_when_evidence_is_only_additive(
    client, isolate_settings
) -> None:
    binding = _seed_repo(client, isolate_settings)
    _dispatch(client, "merge-target-author")
    target_payload = _finding_payload(
        "VA-060",
        binding,
        location="file:src/parser.c:60",
        severity="high",
        author_agent_id="merge-target-author",
    )
    target_payload["evidence_ref"] = "evidence/static-confirmed.json"
    assert _record(client, target_payload).status_code == 201
    _dispatch(client, "merge-target-verifier", role="code-vuln-verifier")
    proof_receipt_id = _verification_receipt(
        client, "merge-target-verifier", "VA-060"
    )
    confirmed = _verify(
        client,
        "VA-060",
        {
            "verification_status": "confirmed",
            "reason_text": "Independent review confirmed the source defect.",
            "source_name": "code-vuln-verifier",
            "provenance": {"code_snapshot": binding},
            "proof_receipt_ids": [proof_receipt_id],
        },
    )
    assert confirmed.status_code == 200, confirmed.text

    _dispatch(client, "merge-live-author")
    live_payload = _finding_payload(
        "VA-061",
        None,
        location="https://example.com/api/parser/60",
        severity="high",
        author_agent_id="merge-live-author",
    )
    live_payload["evidence_ref"] = "evidence/live-confirmation.json"
    recorded_live = _record(client, live_payload)
    assert recorded_live.status_code == 201, recorded_live.text
    merged = client.post(
        f"/engagements/{_ENGAGEMENT_KEY}/assessment/findings/merge",
        json={
            "source_slug": "VA-061",
            "target_slug": "VA-060",
            "reason": "Live confirmation independently proves the same source defect.",
        },
    )

    assert merged.status_code == 200, merged.text
    target = merged.json()["target"]
    assert target["verification_status"] == "confirmed"
    assert target["canonical_location"] == "file:src/parser.c:60"
    with db_module.get_connection() as connection:
        receipt_links = connection.execute(
            """
            SELECT proof_receipt_id
            FROM assessment_finding_proof_receipts
            WHERE finding_id = (
                SELECT id FROM assessment_findings WHERE slug = 'VA-060'
            ) AND relation = 'verification'
            """
        ).fetchall()
        evidence_refs = {
            str(row["target_ref"])
            for row in connection.execute(
                """
                SELECT target_ref
                FROM assessment_finding_links
                WHERE finding_id = (
                    SELECT id FROM assessment_findings WHERE slug = 'VA-060'
                ) AND link_kind = 'evidence' AND retired_at IS NULL
                """
            ).fetchall()
        }
    assert [int(row["proof_receipt_id"]) for row in receipt_links] == [proof_receipt_id]
    assert evidence_refs == {
        "evidence/static-confirmed.json",
        "evidence/live-confirmation.json",
    }


def test_cross_track_merge_preserves_confirmation_when_source_adds_material_detail(
    client, isolate_settings
) -> None:
    binding = _seed_repo(client, isolate_settings)
    _dispatch(client, "merge-material-target-author")
    target_payload = _finding_payload(
        "VA-064",
        binding,
        location="file:src/parser.c:64",
        severity="high",
        author_agent_id="merge-material-target-author",
    )
    target_payload["evidence_ref"] = "evidence/static-material.json"
    assert "cwe_id" not in target_payload["details"]
    assert _record(client, target_payload).status_code == 201
    _dispatch(
        client, "merge-material-target-verifier", role="code-vuln-verifier"
    )
    proof_receipt_id = _verification_receipt(
        client, "merge-material-target-verifier", "VA-064"
    )
    confirmed = _verify(
        client,
        "VA-064",
        {
            "verification_status": "confirmed",
            "reason_text": "Independent review confirmed the source defect.",
            "source_name": "code-vuln-verifier",
            "provenance": {"code_snapshot": binding},
            "proof_receipt_ids": [proof_receipt_id],
        },
    )
    assert confirmed.status_code == 200, confirmed.text

    _dispatch(client, "merge-material-live-author")
    live_payload = _finding_payload(
        "VA-065",
        None,
        location="https://example.com/api/parser/64",
        severity="high",
        author_agent_id="merge-material-live-author",
    )
    live_payload["evidence_ref"] = "evidence/live-material.json"
    live_payload["details"]["cwe_id"] = "CWE-120"
    recorded_live = _record(client, live_payload)
    assert recorded_live.status_code == 201, recorded_live.text
    merged = client.post(
        f"/engagements/{_ENGAGEMENT_KEY}/assessment/findings/merge",
        json={
            "source_slug": "VA-065",
            "target_slug": "VA-064",
            "reason": "Runtime proof adds evidence without replacing reviewed facts.",
        },
    )

    assert merged.status_code == 200, merged.text
    target = merged.json()["target"]
    assert target["verification_status"] == "confirmed"
    assert target["details"]["cwe_id"] == "CWE-120"
    with db_module.get_connection() as connection:
        receipt_links = connection.execute(
            """
            SELECT proof_receipt_id
            FROM assessment_finding_proof_receipts
            WHERE finding_id = (
                SELECT id FROM assessment_findings WHERE slug = 'VA-064'
            ) AND relation = 'verification'
            """
        ).fetchall()
        evidence_refs = {
            str(row["target_ref"])
            for row in connection.execute(
                """
                SELECT target_ref
                FROM assessment_finding_links
                WHERE finding_id = (
                    SELECT id FROM assessment_findings WHERE slug = 'VA-064'
                ) AND link_kind = 'evidence' AND retired_at IS NULL
                """
            ).fetchall()
        }
    assert [int(row["proof_receipt_id"]) for row in receipt_links] == [proof_receipt_id]
    assert evidence_refs == {
        "evidence/static-material.json",
        "evidence/live-material.json",
    }


def test_cross_track_merge_invalidates_confirmation_when_claim_dependencies_are_replaced(
    client, isolate_settings
) -> None:
    binding = _seed_repo(client, isolate_settings)
    _dispatch(client, "merge-destructive-author")
    target_payload = _finding_payload(
        "VA-062",
        binding,
        location="file:src/parser.c:62",
        severity="high",
        author_agent_id="merge-destructive-author",
    )
    target_payload["summary"] = "The source parser has a confirmed bounded-copy defect."
    target_payload["evidence_ref"] = "evidence/original-proof.json"
    assert _record(client, target_payload).status_code == 201
    _dispatch(client, "merge-destructive-verifier", role="code-vuln-verifier")
    proof_receipt_id = _verification_receipt(
        client, "merge-destructive-verifier", "VA-062"
    )
    confirmed = _verify(
        client,
        "VA-062",
        {
            "verification_status": "confirmed",
            "reason_text": "Independent review confirmed the original claim.",
            "source_name": "code-vuln-verifier",
            "provenance": {"code_snapshot": binding},
            "proof_receipt_ids": [proof_receipt_id],
        },
    )
    assert confirmed.status_code == 200, confirmed.text

    _dispatch(client, "merge-replacement-author")
    replacement = _finding_payload(
        "VA-063",
        None,
        location="https://example.com/api/parser/62",
        severity="critical",
        author_agent_id="merge-replacement-author",
    )
    replacement["workflow_status"] = "exploited"
    replacement["summary"] = "A different stronger runtime claim replaces the reviewed summary."
    replacement["evidence_ref"] = "evidence/replacement-proof.json"
    replacement["details"]["cvss_score"] = 9.8
    replacement["details"]["cvss_vector"] = (
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    )
    recorded_replacement = _record(client, replacement)
    assert recorded_replacement.status_code == 201, recorded_replacement.text
    merged = client.post(
        f"/engagements/{_ENGAGEMENT_KEY}/assessment/findings/merge",
        json={
            "source_slug": "VA-063",
            "target_slug": "VA-062",
            "reason": "Runtime evidence materially replaced the reviewed claim.",
        },
    )

    assert merged.status_code == 200, merged.text
    assert merged.json()["target"]["verification_status"] == "unreviewed"
    transitions = client.get(
        f"/engagements/{_ENGAGEMENT_KEY}/assessment/findings/VA-062/transitions"
    ).json()
    assert transitions[0]["action"] == "verification_invalidated"
    assert transitions[0]["reason_code"] == "merge_replaced_verification_dependency"
    metadata = json.loads(transitions[0]["metadata_json"])
    assert metadata["verification_invalidated"] is True
    assert set(metadata["replaced_dependencies"]) >= {
        "severity",
        "workflow_status",
        "summary",
        "evidence_ref",
        "details",
    }


def test_merge_cross_track_rejects_bare_file_prefix_without_source_identity(
    client, isolate_settings
) -> None:
    _seed_repo(client, isolate_settings)
    assert _record(
        client,
        _finding_payload("VA-026", None, location="https://example.com/legacy"),
    ).status_code == 201
    with db_module.get_connection() as connection:
        connection.execute(
            """
            UPDATE assessment_findings
            SET canonical_location = 'file:src/legacy.c:26', provenance_json = '{}'
            WHERE engagement_id = (SELECT id FROM engagements WHERE key = ?)
              AND slug = 'VA-026'
            """,
            (_ENGAGEMENT_KEY,),
        )
    assert _record(
        client,
        _finding_payload(
            "VA-027", None, location="https://example.com/api/parser/27"
        ),
    ).status_code == 201

    merged = client.post(
        f"/engagements/{_ENGAGEMENT_KEY}/assessment/findings/merge",
        json={
            "source_slug": "VA-026",
            "target_slug": "VA-027",
            "reason": "A bare file prefix is not source identity.",
        },
    )

    assert merged.status_code == 409, merged.text
    assert "structured code snapshot" in merged.json()["detail"].lower()


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


def _verify(client, slug: str, payload: dict[str, object]):
    return client.post(
        f"/engagements/{_ENGAGEMENT_KEY}/assessment/findings/{slug}/verify",
        json=payload,
    )


def _verification_receipt(client, verifier_id: str, slug: str) -> int:
    run = client.post(
        f"/engagements/{_ENGAGEMENT_KEY}/assessment/assessment-runs",
        json={
            "run_uuid": f"snapshot-proof-{slug.lower()}",
            "run_kind": "code",
            "producer_dispatch_agent_id": verifier_id,
        },
    )
    assert run.status_code == 201, run.text
    receipt = post_artifact_backed_source_observation(
        client,
        f"/engagements/{_ENGAGEMENT_KEY}/assessment/proof-receipts",
        json={
            "run_id": run.json()["id"],
            "evidence_kind": "source_observation",
            "expected_result": "The recorded source path does not establish the defect.",
            "observed_result": "Independent review confirmed the recorded source path.",
        },
    )
    assert receipt.status_code == 201, receipt.text
    completed = client.patch(
        f"/engagements/{_ENGAGEMENT_KEY}/assessment/assessment-runs/{run.json()['id']}",
        json={"status": "completed"},
    )
    assert completed.status_code == 200, completed.text
    return int(receipt.json()["id"])


def _info_severity_variance(proof_receipt_id: int) -> dict[str, object]:
    return {
        "normal_band": "high",
        "chosen_severity": "info",
        "actor": "code-vuln-verifier",
        "reason": "This fixture isolates snapshot provenance at informational severity.",
        "proof_receipt_id": proof_receipt_id,
    }


def test_verify_reports_the_snapshot_transition_on_its_own_response(
    client, isolate_settings
) -> None:
    """The one verb whose purpose is to MOVE the binding used to be in the set of
    projections that never reported it."""
    binding = _seed_repo(client, isolate_settings)
    _dispatch(client, "hunter-035")
    assert _record(
        client,
        _finding_payload(
            "VA-035",
            binding,
            location="file:src/parser.c:35",
            author_agent_id="hunter-035",
        ),
    ).status_code == 201
    current = _advance_repo(binding)
    _dispatch(client, "cvv-035", role="code-vuln-verifier")
    proof_receipt_id = _verification_receipt(client, "cvv-035", "VA-035")

    rebound = _verify(
        client,
        "VA-035",
        {
            "verification_status": "confirmed",
            "reason_text": "Re-read the current source; the defect stands.",
            "source_name": "code-vuln-verifier",
            "provenance": {"code_snapshot": current},
            "proof_receipt_ids": [proof_receipt_id],
            "severity_variance": _info_severity_variance(proof_receipt_id),
        },
    )

    assert rebound.status_code == 200, rebound.text
    finding = rebound.json()["finding"]
    assert finding["code_snapshot_status_before"] == "stale"
    assert finding["code_snapshot_status"] == "current"
    transitions = client.get(
        f"/engagements/{_ENGAGEMENT_KEY}/assessment/findings/VA-035/transitions"
    ).json()
    metadata = json.loads(transitions[0]["metadata_json"])
    assert metadata["code_snapshot_status_before"] == "stale"
    assert metadata["code_snapshot_status_after"] == "current"


# ──────────────────────────────────────────────────────────────────────────
# Audited relocation across the file/non-file boundary
# ──────────────────────────────────────────────────────────────────────────


def test_relocation_crosses_the_category_boundary_and_records_both_locations(
    client, isolate_settings
) -> None:
    binding = _seed_repo(client, isolate_settings)
    assert _record(
        client, _finding_payload("VA-040", binding, location="file:src/parser.c:40")
    ).status_code == 201
    row_version = client.get(
        f"/engagements/{_ENGAGEMENT_KEY}/assessment/findings/VA-040"
    ).json()["row_version"]

    moved = client.put(
        f"/engagements/{_ENGAGEMENT_KEY}/assessment/findings/VA-040/canonical-location",
        json={
            "canonical_location": "https://example.com/api/parse",
            "reason_text": "Runtime proof relocated the defect to the edge service.",
            "source_name": "exploit-specialist",
            "expected_row_version": row_version,
        },
    )

    assert moved.status_code == 200, moved.text
    finding = moved.json()["finding"]
    assert finding["canonical_location"] == "https://example.com/api/parse"
    # The binding is RESERVED, not deleted: it records which bytes were reviewed.
    assert "code_snapshot" not in finding["provenance"]
    assert finding["provenance"]["superseded_code_snapshot"]["code_snapshot"] == binding
    transitions = client.get(
        f"/engagements/{_ENGAGEMENT_KEY}/assessment/findings/VA-040/transitions"
    ).json()
    assert transitions[0]["action"] == "location_relocated"
    assert transitions[0]["from_canonical_location"] == "file:src/parser.c:40"
    assert transitions[0]["to_canonical_location"] == "https://example.com/api/parse"


@pytest.mark.parametrize(
    "reviewed_status",
    [
        "confirmed",
        "downgraded",
        "false_positive",
        "disputed",
        "pending_runtime_proof",
        "blocked",
    ],
)
def test_relocation_invalidates_a_reviewed_verification(
    client, isolate_settings, reviewed_status
) -> None:
    binding = _seed_repo(client, isolate_settings)
    assert _record(
        client,
        _finding_payload(
            "VA-045",
            binding,
            location="file:src/parser.c:45",
        ),
    ).status_code == 201
    with db_module.get_connection() as connection:
        connection.execute(
            """
            UPDATE assessment_findings
            SET verification_status = ?, row_version = row_version + 1
            WHERE engagement_id = (
                SELECT id FROM engagements WHERE key = ?
            ) AND slug = 'VA-045'
            """,
            (reviewed_status, _ENGAGEMENT_KEY),
        )
    terminal = client.get(
        f"/engagements/{_ENGAGEMENT_KEY}/assessment/findings/VA-045"
    )
    assert terminal.status_code == 200, terminal.text
    assert terminal.json()["verification_status"] == reviewed_status

    moved = client.put(
        f"/engagements/{_ENGAGEMENT_KEY}/assessment/findings/VA-045/canonical-location",
        json={
            "canonical_location": "https://example.com/api/parse",
            "reason_text": "Runtime proof relocated the defect to the edge service.",
            "source_name": "exploit-specialist",
            "expected_row_version": terminal.json()["row_version"],
        },
    )

    assert moved.status_code == 200, moved.text
    assert moved.json()["finding"]["verification_status"] == "unreviewed"
    transitions = client.get(
        f"/engagements/{_ENGAGEMENT_KEY}/assessment/findings/VA-045/transitions"
    ).json()
    assert transitions[0]["action"] == "location_relocated"
    assert transitions[0]["from_verification_status"] == reviewed_status
    assert transitions[0]["to_verification_status"] == "unreviewed"
    metadata = json.loads(transitions[0]["metadata_json"])
    assert metadata["material_change"] is True
    assert metadata["verification_invalidated"] is True


def test_relocation_into_file_still_requires_a_current_binding(
    client, isolate_settings
) -> None:
    """The dedicated route must not become a back door around the snapshot gate."""
    _seed_repo(client, isolate_settings)
    assert _record(
        client, _finding_payload("VA-041", None, location="https://example.com/api/x")
    ).status_code == 201
    row_version = client.get(
        f"/engagements/{_ENGAGEMENT_KEY}/assessment/findings/VA-041"
    ).json()["row_version"]

    refused = client.put(
        f"/engagements/{_ENGAGEMENT_KEY}/assessment/findings/VA-041/canonical-location",
        json={
            "canonical_location": "file:src/parser.c:41",
            "reason_text": "Source review located the defect.",
            "source_name": "code-vuln-verifier",
            "expected_row_version": row_version,
        },
    )

    assert refused.status_code == 400, refused.text
    assert "code_snapshot" in refused.json()["detail"]


def _ingest_file(repo_id: int, file_path: str) -> None:
    """Seed one row of the backend's file inventory for this repo."""
    with db_module.get_connection() as connection:
        engagement_id = int(
            connection.execute(
                "SELECT id FROM engagements WHERE key = ?", (_ENGAGEMENT_KEY,)
            ).fetchone()["id"]
        )
        connection.execute(
            """
            INSERT INTO code_files (engagement_id, repo_id, file_path, language)
            VALUES (?, ?, ?, 'ruby')
            """,
            (engagement_id, repo_id, file_path),
        )


def test_the_origin_path_form_and_the_repo_relative_form_collide(
    client, isolate_settings
) -> None:
    """The two forms describe one line of one file, and used to collide in
    nothing — not the dedup tuple, not the title tier, not the killed-remint
    guard. The stripped prefix is a contiguous SUFFIX of the real repo root, so
    it removes the origin root the author echoed rather than an arbitrary
    leading directory."""
    binding = _seed_repo(client, isolate_settings)
    with db_module.get_connection() as connection:
        connection.execute(
            "UPDATE code_repos SET source_origin_path = ? WHERE id = ?",
            ("/work/engagements/e1/source/acme-firstparty-0731", binding["repo_id"]),
        )

    first = _record(
        client,
        _finding_payload(
            "VA-042", binding, location="file:source/acme-firstparty-0731/pkg/x.rb:12"
        ),
    )

    assert first.status_code == 201, first.text
    finding = first.json()["finding"]
    assert finding["canonical_location"] == "file:pkg/x.rb:12"
    # The audit trail keeps what the author actually wrote.
    assert (
        finding["provenance"]["original_canonical_location"]
        == "file:source/acme-firstparty-0731/pkg/x.rb:12"
    )

    # The two forms now resolve to ONE finding rather than two.
    again = _record(
        client, _finding_payload("VA-042", binding, location="file:pkg/x.rb:12")
    )
    assert again.status_code in (200, 201), again.text
    listing = client.get(f"/engagements/{_ENGAGEMENT_KEY}/assessment/findings").json()
    assert [row["slug"] for row in listing].count("VA-042") == 1


def test_a_bare_repo_directory_name_is_stripped_only_when_the_inventory_agrees(
    client, isolate_settings
) -> None:
    """A one-segment candidate is the repo's own directory name, which is exactly
    the case a heuristic gets wrong: a repository whose directory is called
    ``src`` would otherwise eat the ``src/`` of every correctly-authored path."""
    binding = _seed_repo(client, isolate_settings)
    _ingest_file(int(binding["repo_id"]), "pkg/x.rb")

    corroborated = _record(
        client, _finding_payload("VA-043", binding, location="file:bound-repo/pkg/x.rb:12")
    )
    assert corroborated.status_code == 201, corroborated.text
    assert corroborated.json()["finding"]["canonical_location"] == "file:pkg/x.rb:12"


def test_a_correctly_authored_path_is_never_eaten_by_a_repo_named_after_it(
    client, isolate_settings
) -> None:
    binding = _seed_repo(client, isolate_settings)
    with db_module.get_connection() as connection:
        connection.execute(
            "UPDATE code_repos SET repo_path = ?, source_origin_path = ? WHERE id = ?",
            ("/work/src", "/work/src", binding["repo_id"]),
        )
    _ingest_file(int(binding["repo_id"]), "src/parser.c")

    recorded = _record(
        client, _finding_payload("VA-044", binding, location="file:src/parser.c:41")
    )

    assert recorded.status_code == 201, recorded.text
    assert recorded.json()["finding"]["canonical_location"] == "file:src/parser.c:41"
    assert (
        "original_canonical_location"
        not in recorded.json()["finding"]["provenance"]
    )


# ──────────────────────────────────────────────────────────────────────────
# Provenance attestation: the gate proves the snapshot is CURRENT, never that
# THIS verifier read THESE bytes for THIS finding
# ──────────────────────────────────────────────────────────────────────────


def _dispatch(client, agent_id: str, role: str = "code-vuln-hunter") -> None:
    created = client.post(
        f"/engagements/{_ENGAGEMENT_KEY}/assessment/dispatches",
        json={
            "agent_id": agent_id,
            "agent_role": role,
            "task": "Review the parser for unbounded copies.",
            "status": "in-progress",
            "skills": "code-review",
        },
    )
    assert created.status_code in (200, 201), created.text


def _attestation(client, slug: str) -> dict | None:
    provenance = client.get(
        f"/engagements/{_ENGAGEMENT_KEY}/assessment/findings/{slug}"
    ).json()["provenance"]
    return provenance.get("code_snapshot_attestation")


def _attestation_status(client, slug: str) -> str:
    return client.get(
        f"/engagements/{_ENGAGEMENT_KEY}/assessment/findings/{slug}"
    ).json()["code_snapshot_attestation_status"]


def test_a_genuine_binding_round_trips_with_its_recording_identity(
    client, isolate_settings
) -> None:
    binding = _seed_repo(client, isolate_settings)
    _dispatch(client, "cvh-001")
    payload = _finding_payload("VA-050", binding, location="file:src/parser.c:50")
    payload["provenance"] = {**payload["provenance"], "agent_id": "cvh-001"}

    created = _record(client, payload)

    assert created.status_code == 201, created.text
    # The binding itself is untouched — the attestation is a SIBLING, so exact
    # comparisons against a declared binding keep working.
    assert created.json()["finding"]["provenance"]["code_snapshot"] == binding
    stamped = _attestation(client, "VA-050")
    assert stamped["finding_slug"] == "VA-050"
    assert stamped["write_mode"] == "record"
    assert stamped["agent_id"] == "cvh-001"
    assert isinstance(stamped["dispatch_id"], int)
    assert "copied_from_finding_slug" not in stamped
    assert _attestation_status(client, "VA-050") == "attested"


def test_a_binding_copied_verbatim_from_another_finding_is_distinguishable(
    client, isolate_settings
) -> None:
    """Copying another finding's provenance is the reported workaround. It carries
    the attestation along with the binding it was meant to justify, so the copy
    names the finding it came from instead of looking identical to a real one."""
    binding = _seed_repo(client, isolate_settings)
    _dispatch(client, "cvh-002")
    genuine = _finding_payload("VA-051", binding, location="file:src/parser.c:51")
    genuine["provenance"] = {**genuine["provenance"], "agent_id": "cvh-002"}
    assert _record(client, genuine).status_code == 201
    stolen = client.get(
        f"/engagements/{_ENGAGEMENT_KEY}/assessment/findings/VA-051"
    ).json()["provenance"]

    laundered = _finding_payload("VA-052", None, location="file:src/other.c:52")
    laundered["provenance"] = {
        "agent_id": _DEFAULT_AUTHOR_AGENT_ID,
        "agent_name": "code-vuln-hunter",
        "code_snapshot": stolen["code_snapshot"],
        "code_snapshot_attestation": stolen["code_snapshot_attestation"],
    }
    created = _record(client, laundered)

    # The gate still ACCEPTS it — this change is additive and does not alter the
    # gate's verdict. What changes is that the copy is now visible.
    assert created.status_code == 201, created.text
    stamped = _attestation(client, "VA-052")
    assert stamped["finding_slug"] == "VA-052"
    assert stamped["copied_from_finding_slug"] == "VA-051"
    assert _attestation_status(client, "VA-052") == "copied"
    assert _attestation_status(client, "VA-051") == "attested"


def test_a_binding_asserted_by_an_unknown_dispatch_is_rejected_at_creation(
    client, isolate_settings
) -> None:
    """A claimed author with no dispatch can no longer create a finding."""
    binding = _seed_repo(client, isolate_settings)
    payload = _finding_payload("VA-053", binding, location="file:src/parser.c:53")
    payload["provenance"] = {**payload["provenance"], "agent_id": "never-dispatched"}

    refused = _record(client, payload)

    assert refused.status_code == 400, refused.text
    assert "does not resolve to a dispatch" in refused.json()["detail"]
    assert client.get(
        f"/engagements/{_ENGAGEMENT_KEY}/assessment/findings/VA-053"
    ).status_code == 404


def test_an_unattested_reportable_finding_is_an_advisory_never_a_blocker(
    client, isolate_settings
) -> None:
    binding = _seed_repo(client, isolate_settings)
    payload = _finding_payload(
        "VA-054", binding, location="file:src/parser.c:54", severity="high"
    )
    assert _record(client, payload).status_code == 201
    with db_module.get_connection() as connection:
        connection.execute(
            """
            UPDATE assessment_findings
            SET provenance_json = ?
            WHERE engagement_id = (SELECT id FROM engagements WHERE key = ?)
              AND slug = 'VA-054'
            """,
            (
                json.dumps(
                    {
                        "agent_id": _DEFAULT_AUTHOR_AGENT_ID,
                        "agent_name": "code-vuln-hunter",
                        "code_snapshot": binding,
                        "code_snapshot_attestation": {
                            "finding_slug": "VA-054",
                            "write_mode": "record",
                            "agent_id": "never-dispatched",
                            "dispatch_id": None,
                            "command_run_id": None,
                        },
                    }
                ),
                _ENGAGEMENT_KEY,
            ),
        )

    readiness = client.get(
        f"/engagements/{_ENGAGEMENT_KEY}/assessment/report-readiness"
    ).json()

    assert any(
        item.get("kind") == "finding_code_snapshot_unattested"
        and item.get("slug") == "VA-054"
        for item in readiness["advisories"]
    )
    assert not any(
        item.get("kind") == "finding_code_snapshot_unattested"
        for item in readiness["blockers"]
    )


def test_a_legacy_row_with_no_attestation_stays_readable_and_writable(
    client, isolate_settings
) -> None:
    """Rows written before the attestation existed carry no stamp. That is legacy,
    NOT a violation: they must keep reading and keep accepting writes."""
    binding = _seed_repo(client, isolate_settings)
    assert _record(
        client, _finding_payload("VA-055", binding, location="file:src/parser.c:55")
    ).status_code == 201
    with db_module.get_connection() as connection:
        connection.execute(
            """
            UPDATE assessment_findings
            SET provenance_json = ?
            WHERE engagement_id = (SELECT id FROM engagements WHERE key = ?)
              AND slug = 'VA-055'
            """,
            (json.dumps({"agent_name": "legacy", "code_snapshot": binding}), _ENGAGEMENT_KEY),
        )

    fetched = client.get(f"/engagements/{_ENGAGEMENT_KEY}/assessment/findings/VA-055")
    assert fetched.status_code == 200, fetched.text
    assert fetched.json()["code_snapshot_attestation_status"] == "legacy"
    assert fetched.json()["code_snapshot_status"] == "current"

    patched = client.patch(
        f"/engagements/{_ENGAGEMENT_KEY}/assessment/findings/VA-055",
        json={"summary": "Still maintainable."},
    )
    assert patched.status_code == 200, patched.text
    # A patch that never asserted a binding leaves the legacy row exactly as found.
    assert _attestation_status(client, "VA-055") == "legacy"
    # And it is not surfaced as unattested — legacy is not a violation.
    readiness = client.get(
        f"/engagements/{_ENGAGEMENT_KEY}/assessment/report-readiness"
    ).json()
    assert not any(
        item.get("slug") == "VA-055"
        and item.get("kind") == "finding_code_snapshot_unattested"
        for item in readiness["advisories"]
    )


def test_a_verify_rebind_re_attests_under_the_verifying_agent(
    client, isolate_settings
) -> None:
    binding = _seed_repo(client, isolate_settings)
    _dispatch(client, "cvh-003")
    payload = _finding_payload("VA-056", binding, location="file:src/parser.c:56")
    payload["provenance"] = {**payload["provenance"], "agent_id": "cvh-003"}
    assert _record(client, payload).status_code == 201
    current = _advance_repo(binding)
    _dispatch(client, "cvv-001", role="code-vuln-verifier")
    _dispatch(client, "cvv-proof-001", role="code-vuln-verifier")
    proof_receipt_id = _verification_receipt(client, "cvv-proof-001", "VA-056")

    rebound = _verify(
        client,
        "VA-056",
        {
            "verification_status": "confirmed",
            "reason_text": "Re-read the current source; the defect stands.",
            "source_name": "code-vuln-verifier",
            "provenance": {"code_snapshot": current, "agent_id": "cvv-001"},
            "proof_receipt_ids": [proof_receipt_id],
            "severity_variance": _info_severity_variance(proof_receipt_id),
        },
    )

    assert rebound.status_code == 200, rebound.text
    stamped = _attestation(client, "VA-056")
    assert stamped["write_mode"] == "verify"
    assert stamped["agent_id"] == "cvv-001"
    assert stamped["recorded_by"] == "code-vuln-verifier"
    assert _attestation_status(client, "VA-056") == "attested"
