"""The finding wire shape: ``details`` / ``provenance`` parsed, no string twin.

The finding read projection was ``dict(sqlite3.Row)``, so the DB's storage
encoding leaked straight into the wire contract: every finding-bearing response
carried ``details_json`` / ``provenance_json`` as opaque STRINGS with no parsed
sibling, while the intel projection beside it decoded properly. Two findings that
differed only in ``provenance.code_snapshot`` were indistinguishable in every
default read, and every consumer carried its own defensive re-parse.

This module pins the shape across every finding-bearing response so the
divergence cannot come back one endpoint at a time.
"""
from __future__ import annotations

import json
from pathlib import Path

from app import db as db_module

ENGAGEMENT_KEY = "2026-08-20-finding-shape"
AUTHOR_AGENT_ID = "FINDING-SHAPE-AUTHOR"


def _base() -> str:
    return f"/engagements/{ENGAGEMENT_KEY}/assessment"


def _seed(client, isolate_settings) -> None:
    engagement_dir: Path = isolate_settings["engagements_dir"] / ENGAGEMENT_KEY
    (engagement_dir / "sessions").mkdir(parents=True, exist_ok=True)
    (engagement_dir / "scope.json").write_text(
        json.dumps({"engagement_name": "Shape", "targets": ["https://app.example"]}),
        encoding="utf-8",
    )
    (engagement_dir / "findings.md").write_text("# Findings\n", encoding="utf-8")
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200
    dispatch = client.post(
        f"{_base()}/dispatches",
        json={
            "agent_id": AUTHOR_AGENT_ID,
            "agent_role": "vulnerability-analyst",
            "task": "Record finding-shape fixture rows",
        },
    )
    assert dispatch.status_code == 201, dispatch.text


def _payload(slug: str, **over) -> dict:
    payload = {
        "slug": slug,
        "title": f"IDOR in /api/users/{{id}} allows anon read of any user PII ({slug})",
        "severity": "medium",
        "workflow_status": "active",
        "verification_status": "unreviewed",
        "defect_family": "access-control",
        "root_cause_key": f"missing-object-authz-{slug}",
        "canonical_location": f"https://app.example/api/users/{slug}",
        "summary": "IDOR",
        "evidence_ref": "findings.md",
        "source_name": "vulnerability-analyst",
        "details": {
            "evidence": "Replayable request.",
            "impact": "PII disclosure.",
            "cvss_score": 5.3,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "steps_to_reproduce": ["GET /api/users/2 as an anonymous caller."],
            "remediation": "Enforce object-level authorization.",
        },
        "provenance": {
            "agent_id": AUTHOR_AGENT_ID,
            "agent_name": "vulnerability-analyst",
        },
    }
    payload.update(over)
    return payload


def _assert_parsed(record: dict, where: str) -> None:
    assert isinstance(record.get("details"), dict), f"{where}: details must be an object"
    assert isinstance(record.get("provenance"), dict), f"{where}: provenance must be an object"
    # POP, not duplicate: emitting both would leave readers guessing which one is
    # authoritative and would double every payload.
    assert "details_json" not in record, f"{where}: details_json string twin leaked"
    assert "provenance_json" not in record, f"{where}: provenance_json string twin leaked"


def test_every_finding_bearing_response_returns_parsed_details_and_provenance(
    client, isolate_settings
) -> None:
    _seed(client, isolate_settings)

    created = client.post(f"{_base()}/findings", json=_payload("VA-001"))
    assert created.status_code == 201, created.text
    _assert_parsed(created.json()["finding"], "POST /findings")
    assert created.json()["finding"]["details"]["cvss_score"] == 5.3

    assert client.post(f"{_base()}/findings", json=_payload("VA-002")).status_code == 201

    listing = client.get(f"{_base()}/findings")
    assert listing.status_code == 200, listing.text
    for row in listing.json():
        _assert_parsed(row, "GET /findings")

    detail = client.get(f"{_base()}/findings/VA-001")
    _assert_parsed(detail.json(), "GET /findings/{slug}")

    patched = client.patch(f"{_base()}/findings/VA-001", json={"summary": "Refined."})
    assert patched.status_code == 200, patched.text
    _assert_parsed(patched.json()["finding"], "PATCH /findings/{slug}")

    verified = client.post(
        f"{_base()}/findings/VA-001/verify",
        json={
            "verification_status": "pending_runtime_proof",
            "reason_text": "Reproduced against the live service.",
            "source_name": "vulnerability-analyst",
        },
    )
    assert verified.status_code == 200, verified.text
    _assert_parsed(verified.json()["finding"], "POST /findings/{slug}/verify")

    root_cause = client.put(
        f"{_base()}/findings/VA-002/root-cause",
        json={"root_cause_slug": "VA-001", "note": "Same missing check."},
    )
    assert root_cause.status_code == 200, root_cause.text

    groups = client.get(f"{_base()}/finding-groups")
    assert groups.status_code == 200, groups.text
    for group in groups.json():
        _assert_parsed(group["root"], "GET /finding-groups root")
        for member in group.get("members", []):
            _assert_parsed(member, "GET /finding-groups member")

    one_group = client.get(f"{_base()}/finding-groups/VA-001")
    assert one_group.status_code == 200, one_group.text

    candidates = client.get(f"{_base()}/exploit-candidates")
    assert candidates.status_code == 200, candidates.text
    for row in candidates.json():
        _assert_parsed(row, "GET /exploit-candidates")

    report = client.get(f"{_base()}/report-findings")
    assert report.status_code == 200, report.text
    report_body = report.json()
    for group in report_body["groups"]:
        _assert_parsed(group["root"], "GET /report-findings root")
        for member in group.get("members", []):
            _assert_parsed(member, "GET /report-findings member")

    # The report-export payload is assembled from the same projection
    # (``list_report_finding_groups``); assert the shape at the service seam
    # since the HTTP route renders HTML.
    from app.services import state_manager

    with_engagement = client.get(f"/engagements/{ENGAGEMENT_KEY}").json()
    exported = state_manager.list_report_finding_groups(int(with_engagement["id"]))
    for group in exported["groups"]:
        _assert_parsed(group["root"], "report-export projection")

    summary = client.get(f"{_base()}/summary")
    assert summary.status_code == 200, summary.text
    for row in summary.json().get("top_findings", []):
        _assert_parsed(row, "GET /summary top_findings")

    cleared = client.delete(f"{_base()}/findings/VA-002/root-cause")
    assert cleared.status_code == 200, cleared.text

    merged = client.post(
        f"{_base()}/findings/merge",
        json={
            "source_slug": "VA-002",
            "target_slug": "VA-001",
            "reason": "Same defect on the same endpoint.",
        },
    )
    assert merged.status_code == 200, merged.text
    _assert_parsed(merged.json()["source"], "POST /findings/merge source")
    _assert_parsed(merged.json()["target"], "POST /findings/merge target")


def test_a_malformed_details_column_reads_as_an_empty_object_not_a_crash(
    client, isolate_settings
) -> None:
    """The read path must never crash on invalid stored data — validation belongs
    on the write paths."""
    from app import db as db_module

    _seed(client, isolate_settings)
    assert client.post(f"{_base()}/findings", json=_payload("VA-003")).status_code == 201
    with db_module.get_connection() as connection:
        connection.execute(
            "UPDATE assessment_findings SET details_json = 'not json' WHERE slug = ?",
            ("VA-003",),
        )

    detail = client.get(f"{_base()}/findings/VA-003")

    assert detail.status_code == 200, detail.text
    assert detail.json()["details"] == {}


def test_the_write_envelope_carries_the_snapshot_standing_and_duplicate_advisories(
    client, isolate_settings
) -> None:
    _seed(client, isolate_settings)
    created = client.post(f"{_base()}/findings", json=_payload("VA-004"))

    assert created.status_code == 201, created.text
    body = created.json()
    assert body["finding"]["code_snapshot_status"] == "not_applicable"
    # Always present so a caller can read it unconditionally.
    assert body["duplicate_advisories"] == []


def test_a_record_that_collides_with_a_filed_sibling_is_warned_not_refused(
    client, isolate_settings
) -> None:
    """``root_cause_key`` is author-invented free text with no collision surface,
    so a rediscovery of an already-submitted defect landed silently beside it."""
    _seed(client, isolate_settings)
    assert client.post(f"{_base()}/findings", json=_payload("VA-005")).status_code == 201
    assert (
        client.patch(
            f"{_base()}/findings/VA-005",
            json={"submission_status": "submitted", "submission_ref": "BC-77"},
        ).status_code
        == 200
    )

    twin = client.post(
        f"{_base()}/findings",
        json=_payload("VA-006", root_cause_key="missing-object-authz-VA-005"),
    )

    assert twin.status_code == 201, twin.text
    advisories = twin.json()["duplicate_advisories"]
    assert [item["slug"] for item in advisories] == ["VA-005"]
    assert advisories[0]["submission_status"] == "submitted"
    assert advisories[0]["submission_ref"] == "BC-77"
    assert "root_cause_key" in advisories[0]["matched_on"]


def test_duplicate_advisory_requires_matching_defect_family_and_auth_context(
    client, isolate_settings
) -> None:
    _seed(client, isolate_settings)
    assert client.post(f"{_base()}/findings", json=_payload("VA-007")).status_code == 201
    submitted = client.patch(
        f"{_base()}/findings/VA-007",
        json={"submission_status": "submitted", "submission_ref": "BC-78"},
    )
    assert submitted.status_code == 200, submitted.text

    unrelated = client.post(
        f"{_base()}/findings",
        json=_payload(
            "VA-008", defect_family="server-side-request-forgery",
            auth_context="administrator",
            root_cause_key="separate-egress-control",
            canonical_location="https://app.example/api/users/VA-007",
        ),
    )

    assert unrelated.status_code == 201, unrelated.text
    assert unrelated.json()["duplicate_advisories"] == []


def test_duplicate_advisory_finds_older_exact_location_after_many_submissions(
    client, isolate_settings
) -> None:
    _seed(client, isolate_settings)
    original = client.post(f"{_base()}/findings", json=_payload("VA-009"))
    assert original.status_code == 201, original.text
    assert client.patch(
        f"{_base()}/findings/VA-009",
        json={"submission_status": "submitted", "submission_ref": "BC-79"},
    ).status_code == 200
    with db_module.get_connection() as connection:
        engagement_id = connection.execute(
            "SELECT id FROM engagements WHERE key = ?", (ENGAGEMENT_KEY,)
        ).fetchone()["id"]
        connection.executemany(
            """
            INSERT INTO assessment_findings (
                engagement_id, slug, title, severity, status, verification_status,
                defect_family, root_cause_key, auth_context, canonical_location,
                submission_status, submission_ref
            ) VALUES (?, ?, ?, 'medium', 'active', 'unreviewed',
                      'access-control', ?, '', ?, 'submitted', ?)
            """,
            (
                (engagement_id, f"OLD-{index}", f"Unrelated {index}",
                 f"other-{index}", f"https://app.example/unrelated/{index}",
                 f"BC-{index}")
                for index in range(501)
            ),
        )

    twin = client.post(
        f"{_base()}/findings",
        json=_payload(
            "VA-010", root_cause_key="new-key",
            canonical_location="https://app.example/api/users/VA-009",
        ),
    )

    assert twin.status_code == 201, twin.text
    assert [item["slug"] for item in twin.json()["duplicate_advisories"]] == ["VA-009"]
