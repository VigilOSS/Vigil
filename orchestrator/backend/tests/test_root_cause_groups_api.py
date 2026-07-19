import json
from pathlib import Path


ENGAGEMENT_KEY = "2026-05-05-170700-root-cause"


def _write_engagement(engagements_dir: Path) -> None:
    engagement_dir = engagements_dir / ENGAGEMENT_KEY
    (engagement_dir / "sessions").mkdir(parents=True, exist_ok=True)
    (engagement_dir / "scope.json").write_text(
        json.dumps({"engagement_name": "Root Cause Test", "targets": ["https://app.example"]}),
        encoding="utf-8",
    )
    (engagement_dir / "findings.md").write_text("# Findings\n", encoding="utf-8")


def _seed(client, isolate_settings) -> None:
    _write_engagement(isolate_settings["engagements_dir"])
    response = client.get(f"/engagements/{ENGAGEMENT_KEY}")
    assert response.status_code == 200, response.text


def _finding(slug: str, title: str, *, root_key: str, severity: str = "high") -> dict:
    cvss_score = 5.4 if severity == "medium" else 8.1
    cvss_vector = (
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N"
        if severity == "medium"
        else "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
    )
    return {
        "slug": slug,
        "title": title,
        "severity": severity,
        "workflow_status": "exploited",
        "verification_state": "verified",
        "verification_disposition": "confirmed",
        "defect_family": "auth-bypass",
        "root_cause_key": root_key,
        "canonical_location": f"https://app.example/{slug.lower()}",
        "summary": title,
        "evidence_ref": "findings.md",
        "source_name": "test",
        "details": {
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector,
            "steps_to_reproduce": ["Replay the recorded request."],
            "remediation": "Enforce authorization in the shared guard.",
            "impact": "Attackers can reach protected functionality.",
            "evidence": "Verified with a replayable request.",
        },
    }


def test_root_cause_link_groups_findings_and_clears_duplicate_blocker(client, isolate_settings):
    _seed(client, isolate_settings)
    for payload in (
        _finding("RC-001", "Shared auth guard bypass", root_key="shared-auth-guard"),
        _finding("RC-002", "Admin export reachable through bypass", root_key="shared-auth-guard"),
        _finding("RC-003", "XXE reachable after takeover", root_key="shared-auth-guard", severity="medium"),
    ):
        response = client.post(f"/engagements/{ENGAGEMENT_KEY}/assessment/findings", json=payload)
        assert response.status_code in {200, 201}, response.text

    before = client.get(f"/engagements/{ENGAGEMENT_KEY}/assessment/report-readiness").json()
    assert any(blocker["kind"] == "duplicate_root_cause" for blocker in before["blockers"])

    link_response = client.put(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/findings/RC-002/root-cause",
        json={
            "root_cause_slug": "RC-001",
            "sibling_order": 2,
            "root_cause_effect": "eliminates_finding",
            "note": "Auth fix removes this path.",
        },
    )
    assert link_response.status_code == 200, link_response.text
    residual_response = client.put(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/findings/RC-003/root-cause",
        json={
            "root_cause_slug": "RC-001",
            "sibling_order": 1,
            "root_cause_effect": "eliminates_attack_path",
            "note": "ATO path is removed, but XXE remains independently reachable.",
        },
    )
    assert residual_response.status_code == 200, residual_response.text

    group = client.get(f"/engagements/{ENGAGEMENT_KEY}/assessment/finding-groups/RC-001").json()
    assert group["root"]["slug"] == "RC-001"
    assert [sibling["slug"] for sibling in group["siblings"]] == ["RC-003", "RC-002"]
    assert group["residual_path_count"] == 1

    readiness = client.get(f"/engagements/{ENGAGEMENT_KEY}/assessment/report-readiness").json()
    assert not any(blocker["kind"] == "duplicate_root_cause" for blocker in readiness["blockers"])

    report_groups = client.get(f"/engagements/{ENGAGEMENT_KEY}/assessment/report-findings?mode=final")
    assert report_groups.status_code == 200, report_groups.text
    body = report_groups.json()
    assert body["group_count"] == 1
    assert body["groups"][0]["root"]["slug"] == "RC-001"


def test_root_cause_link_rejects_nested_groups_and_merge_of_group_root(client, isolate_settings):
    _seed(client, isolate_settings)
    for payload in (
        _finding("RC-010", "Primary guard bypass", root_key="guard-a"),
        _finding("RC-011", "Sibling guard outcome", root_key="guard-a"),
        _finding("RC-012", "Another root", root_key="guard-b"),
    ):
        response = client.post(f"/engagements/{ENGAGEMENT_KEY}/assessment/findings", json=payload)
        assert response.status_code in {200, 201}, response.text

    response = client.put(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/findings/RC-011/root-cause",
        json={"root_cause_slug": "RC-010"},
    )
    assert response.status_code == 200, response.text

    nested = client.put(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/findings/RC-012/root-cause",
        json={"root_cause_slug": "RC-011"},
    )
    assert nested.status_code == 400, nested.text

    parent_as_sibling = client.put(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/findings/RC-010/root-cause",
        json={"root_cause_slug": "RC-012"},
    )
    assert parent_as_sibling.status_code == 400, parent_as_sibling.text

    merge = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/findings/merge",
        json={"source_slug": "RC-010", "target_slug": "RC-012", "reason": "duplicate"},
    )
    assert merge.status_code == 400, merge.text

    clear = client.delete(f"/engagements/{ENGAGEMENT_KEY}/assessment/findings/RC-011/root-cause")
    assert clear.status_code == 200, clear.text
    assert clear.json()["cleared"] == 1


def test_record_finding_rejects_embedded_root_cause_link(client, isolate_settings):
    _seed(client, isolate_settings)
    response = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/findings",
        json={
            **_finding("RC-020", "Embedded root-cause link attempt", root_key="guard-c"),
            "links": [
                {
                    "link_kind": "root_cause",
                    "target_kind": "finding",
                    "target_ref": "RC-019",
                }
            ],
        },
    )
    assert response.status_code == 422, response.text
    assert "root_cause links must be created with `finding link`" in response.text


# ---------------------------------------------------------------------------
# C44 — evidence_type field on findings (nullable, no backfill)
# ---------------------------------------------------------------------------


def _finding_field(response_json: dict, field: str):
    """Extract `field` from a record-finding / update-finding response. The
    POST response shape is {'finding': {...}, 'transition': {...}, 'links': [...]}.
    """
    finding = response_json.get("finding") or response_json
    return finding.get(field) if isinstance(finding, dict) else None


def test_finding_evidence_type_round_trips_when_set(client, isolate_settings):
    """C44: new findings carry the evidence_type tag and the column round-trips
    through list/get serializers. Existing rows that predate this column stay
    NULL — verified separately by absence of backfill (the column ALTER has
    no UPDATE clause)."""
    _seed(client, isolate_settings)
    payload = _finding("EV-001", "Captured request demonstrates IDOR", root_key="ev-1")
    payload["evidence_type"] = "network-confirmed"
    response = client.post(f"/engagements/{ENGAGEMENT_KEY}/assessment/findings", json=payload)
    assert response.status_code in {200, 201}, response.text
    assert _finding_field(response.json(), "evidence_type") == "network-confirmed"

    # Round-trip via list-findings
    listed = client.get(f"/engagements/{ENGAGEMENT_KEY}/assessment/findings")
    assert listed.status_code == 200
    rows = listed.json()
    by_slug = {r["slug"]: r for r in rows}
    assert by_slug["EV-001"]["evidence_type"] == "network-confirmed"


def test_finding_evidence_type_nullable_when_omitted(client, isolate_settings):
    """C44: omitting evidence_type stores NULL — confirmed by serializer
    returning None for the field."""
    _seed(client, isolate_settings)
    payload = _finding("EV-002", "Pre-migration finding", root_key="ev-2")
    response = client.post(f"/engagements/{ENGAGEMENT_KEY}/assessment/findings", json=payload)
    assert response.status_code in {200, 201}, response.text
    assert _finding_field(response.json(), "evidence_type") is None


def test_finding_evidence_type_rejects_invalid_value(client, isolate_settings):
    """C44: the four-value enum is enforced at the API layer; bogus values 422."""
    _seed(client, isolate_settings)
    payload = _finding("EV-003", "Rejected evidence type", root_key="ev-3")
    payload["evidence_type"] = "speculation"  # not in the enum
    response = client.post(f"/engagements/{ENGAGEMENT_KEY}/assessment/findings", json=payload)
    assert response.status_code == 422, response.text


def test_finding_evidence_type_patch_via_update(client, isolate_settings):
    """C44: operators can label legacy NULL findings via update-finding."""
    _seed(client, isolate_settings)
    payload = _finding("EV-004", "Initially unclassified finding", root_key="ev-4")
    response = client.post(f"/engagements/{ENGAGEMENT_KEY}/assessment/findings", json=payload)
    assert response.status_code in {200, 201}, response.text
    assert _finding_field(response.json(), "evidence_type") is None

    patched = client.patch(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/findings/EV-004",
        json={
            "evidence_type": "code-inferred",
            "reason_code": "retroactive-classification",
            "reason_text": "labeled during pre-report audit per C44",
        },
    )
    assert patched.status_code == 200, patched.text
    assert _finding_field(patched.json(), "evidence_type") == "code-inferred"


def test_report_findings_draft_mode_excludes_draft_workflow_status(client, isolate_settings):
    """report_readiness draft projection must drop ``workflow_status == "draft"``
    findings: report_readiness() never gates draft (it is not a reportable
    status) and ``final`` mode already excludes it, so it must not leak into the
    draft projection either."""
    _seed(client, isolate_settings)

    active_payload = _finding("RP-001", "Reportable active finding", root_key="rp-active")
    draft_payload = _finding("RP-002", "Still-draft finding", root_key="rp-draft")
    draft_payload["workflow_status"] = "draft"

    for payload in (active_payload, draft_payload):
        response = client.post(
            f"/engagements/{ENGAGEMENT_KEY}/assessment/findings", json=payload
        )
        assert response.status_code in {200, 201}, response.text

    draft_report = client.get(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/report-findings?mode=draft"
    )
    assert draft_report.status_code == 200, draft_report.text
    body = draft_report.json()

    # Both findings are ungrouped, so they would land in ``standalone``; the
    # draft-status one must have been filtered out entirely.
    standalone_slugs = {record.get("slug") for record in body["standalone"]}
    assert "RP-001" in standalone_slugs
    assert "RP-002" not in standalone_slugs
    assert body["finding_count"] == 1
