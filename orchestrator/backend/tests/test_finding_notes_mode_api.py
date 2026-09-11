"""PATCH /findings/{slug} notes_mode: append (default) vs replace.

Regression for the append-only `notes` column that made stale/contradicted
internal text impossible to scrub via the CLI (`update-finding`).
"""
import json

import pytest
from fastapi import HTTPException

from app import db as db_module
from app.services import state_manager

ENGAGEMENT_KEY = "2026-05-29-120000-notes-mode"
AUTHOR_AGENT_ID = "NOTES-MODE-FIXTURE-AUTHOR"


def _seed(client, isolate_settings) -> None:
    engagement_dir = isolate_settings["engagements_dir"] / ENGAGEMENT_KEY
    (engagement_dir / "sessions").mkdir(parents=True, exist_ok=True)
    (engagement_dir / "scope.json").write_text(
        json.dumps({"engagement_name": "Notes Mode Test", "targets": ["https://app.example"]}),
        encoding="utf-8",
    )
    (engagement_dir / "findings.md").write_text("# Findings\n", encoding="utf-8")
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200
    dispatch = client.post(
        f"{_base()}/dispatches",
        json={
            "agent_id": AUTHOR_AGENT_ID,
            "agent_role": "vulnerability-analyst",
            "task": "Record notes-mode fixture findings",
        },
    )
    assert dispatch.status_code == 201, dispatch.text


def _finding_payload() -> dict:
    return {
        "slug": "VA-001",
        "title": "IDOR in /api/users/{id} allows anon read of any user PII",
        "severity": "high",
        "workflow_status": "exploited",
        "verification_status": "unreviewed",
        "defect_family": "access-control",
        "root_cause_key": "missing-object-authz",
        "canonical_location": "https://app.example/api/users",
        "summary": "IDOR",
        "evidence_ref": "findings.md",
        "source_name": "test",
        "provenance": {"agent_id": AUTHOR_AGENT_ID},
        "notes": "PROVEN by run 13691",
        "details": {
            "cvss_score": 7.5,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "steps_to_reproduce": ["Replay the recorded request."],
            "remediation": "Enforce object-level authorization.",
            "impact": "Anonymous attackers read any user's PII.",
            "evidence": "Replayable request.",
        },
    }


def _base(key=ENGAGEMENT_KEY):
    return f"/engagements/{key}/assessment"


def test_patch_notes_appends_by_default(client, isolate_settings):
    _seed(client, isolate_settings)
    assert client.post(f"{_base()}/findings", json=_finding_payload()).status_code in (200, 201)

    resp = client.patch(f"{_base()}/findings/VA-001", json={"notes": "verify phase disproved run 13691"})
    assert resp.status_code == 200, resp.text
    notes = resp.json()["finding"]["notes"]
    # Default keeps the original line AND the new line (append/checkpoint behavior).
    assert "PROVEN by run 13691" in notes
    assert "verify phase disproved run 13691" in notes


def test_patch_notes_append_records_full_before_and_after(
    client, isolate_settings
):
    _seed(client, isolate_settings)
    created = client.post(f"{_base()}/findings", json=_finding_payload())
    assert created.status_code in (200, 201), created.text

    appended = client.patch(
        f"{_base()}/findings/VA-001",
        json={"notes": "verify phase disproved run 13691"},
    )
    assert appended.status_code == 200, appended.text

    transitions = client.get(f"{_base()}/findings/VA-001/transitions").json()
    latest = transitions[0]
    assert latest["notes_before_json"] == "PROVEN by run 13691"
    assert latest["notes_after_json"] == appended.json()["finding"]["notes"]
    assert latest["notes_history_status"] == "recorded"


def test_patch_notes_replace_overwrites(client, isolate_settings):
    _seed(client, isolate_settings)
    assert client.post(f"{_base()}/findings", json=_finding_payload()).status_code in (200, 201)

    resp = client.patch(
        f"{_base()}/findings/VA-001",
        json={
            "notes": "Disproven; see VA-001 verify handoff.",
            "notes_mode": "replace",
            "expected_row_version": 1,
        },
    )
    assert resp.status_code == 200, resp.text
    notes = resp.json()["finding"]["notes"]
    # The stale line is gone — only the replacement remains.
    assert "PROVEN by run 13691" not in notes
    assert notes.strip() == "Disproven; see VA-001 verify handoff."
    latest = client.get(f"{_base()}/findings/VA-001/transitions").json()[0]
    assert latest["notes_before_json"] == "PROVEN by run 13691"
    assert latest["notes_after_json"] == notes
    assert latest["notes_history_status"] == "recorded"


@pytest.mark.parametrize(
    "payload",
    [
        {"notes": "replacement", "notes_mode": "replace"},
        {"details": {}, "details_mode": "replace"},
    ],
    ids=["notes", "details"],
)
def test_patch_replace_requires_caller_cas_at_api_boundary(
    client, isolate_settings, payload
):
    _seed(client, isolate_settings)
    created = client.post(f"{_base()}/findings", json=_finding_payload())
    assert created.status_code in (200, 201), created.text

    resp = client.patch(f"{_base()}/findings/VA-001", json=payload)

    assert resp.status_code == 422, resp.text
    assert "expected_row_version" in resp.text
    unchanged = client.get(f"{_base()}/findings/VA-001")
    assert unchanged.status_code == 200
    assert unchanged.json()["row_version"] == 1
    assert unchanged.json()["notes"] == "PROVEN by run 13691"


@pytest.mark.parametrize(
    "patch_kwargs",
    [
        {"notes": "replacement", "notes_mode": "replace"},
        {"details": {}, "details_mode": "replace"},
    ],
    ids=["notes", "details"],
)
def test_patch_service_rejects_replace_without_caller_cas(
    client, isolate_settings, patch_kwargs
):
    _seed(client, isolate_settings)
    created = client.post(f"{_base()}/findings", json=_finding_payload())
    assert created.status_code in (200, 201), created.text
    with db_module.get_connection() as connection:
        engagement_id = int(
            connection.execute(
                "SELECT id FROM engagements WHERE key = ?", (ENGAGEMENT_KEY,)
            ).fetchone()["id"]
        )

    with pytest.raises(HTTPException) as exc_info:
        state_manager.patch_finding(
            engagement_id,
            slug="VA-001",
            **patch_kwargs,
        )

    assert exc_info.value.status_code == 400
    assert "expected_row_version" in str(exc_info.value.detail)


def test_patch_notes_replace_requires_notes(client, isolate_settings):
    _seed(client, isolate_settings)
    assert client.post(f"{_base()}/findings", json=_finding_payload()).status_code in (200, 201)

    resp = client.patch(
        f"{_base()}/findings/VA-001",
        json={"notes_mode": "replace"},
    )
    assert resp.status_code == 422

    detail = client.get(f"{_base()}/findings/VA-001")
    assert detail.status_code == 200
    assert detail.json()["notes"] == "PROVEN by run 13691"


def test_patch_notes_mode_rejects_unknown_value(client, isolate_settings):
    _seed(client, isolate_settings)
    assert client.post(f"{_base()}/findings", json=_finding_payload()).status_code in (200, 201)
    resp = client.patch(
        f"{_base()}/findings/VA-001",
        json={"notes": "x", "notes_mode": "prepend"},
    )
    assert resp.status_code == 422  # Literal["append","replace"] rejects others


@pytest.mark.parametrize(
    "payload",
    [
        {"expected_row_version": 1},
        {
            "expected_row_version": 1,
            "notes_mode": "append",
            "details_mode": "merge",
        },
    ],
)
def test_patch_rejects_only_concurrency_and_mode_controls(
    client, isolate_settings, payload
):
    _seed(client, isolate_settings)
    created = client.post(f"{_base()}/findings", json=_finding_payload())
    assert created.status_code in (200, 201), created.text

    resp = client.patch(f"{_base()}/findings/VA-001", json=payload)

    assert resp.status_code == 422, resp.text
    assert "do not update a finding" in resp.text
    unchanged = client.get(f"{_base()}/findings/VA-001")
    assert unchanged.status_code == 200
    assert unchanged.json()["row_version"] == 1


@pytest.mark.parametrize(
    "payload",
    [
        {
            "reason_code": "checkpoint",
            "reason_text": "No finding field changed.",
            "artifact_ref": "evidence/no-op.txt",
            "expected_row_version": 1,
        },
        {
            "summary": None,
            "notes": None,
            "details": None,
            "provenance": None,
            "expected_row_version": 1,
        },
        {
            "defect_family": "",
            "root_cause_key": "",
            "canonical_location": "",
            "summary": "",
            "evidence_ref": "",
            "notes": "",
            "notes_mode": "append",
            "source_name": "",
            "details": {},
            "details_mode": "merge",
            "provenance": {},
            "expected_row_version": 1,
        },
    ],
)
def test_patch_rejects_transition_metadata_and_empty_merge_noops(
    client, isolate_settings, payload
):
    _seed(client, isolate_settings)
    created = client.post(f"{_base()}/findings", json=_finding_payload())
    assert created.status_code in (200, 201), created.text

    resp = client.patch(f"{_base()}/findings/VA-001", json=payload)

    assert resp.status_code == 422, resp.text
    unchanged = client.get(f"{_base()}/findings/VA-001")
    assert unchanged.status_code == 200
    assert unchanged.json()["row_version"] == 1


def test_patch_allows_empty_notes_replacement_with_cas(client, isolate_settings):
    _seed(client, isolate_settings)
    created = client.post(f"{_base()}/findings", json=_finding_payload())
    assert created.status_code in (200, 201), created.text

    resp = client.patch(
        f"{_base()}/findings/VA-001",
        json={"notes": "", "notes_mode": "replace", "expected_row_version": 1},
    )

    assert resp.status_code == 200, resp.text
    finding = resp.json()["finding"]
    assert finding["notes"] == ""
    assert finding["row_version"] == 2


def test_patch_allows_empty_details_replacement_with_cas(client, isolate_settings):
    _seed(client, isolate_settings)
    created = client.post(f"{_base()}/findings", json=_finding_payload())
    assert created.status_code in (200, 201), created.text

    resp = client.patch(
        f"{_base()}/findings/VA-001",
        json={"details": {}, "details_mode": "replace", "expected_row_version": 1},
    )

    assert resp.status_code == 200, resp.text
    finding = resp.json()["finding"]
    assert finding["details"] == {}
    assert finding["row_version"] == 2


# ──────────────────────────────────────────────────────────────────────────
# The cap is enforced where the field GROWS (and there is an exit for the rows
# that already grew past it)
# ──────────────────────────────────────────────────────────────────────────


def _row_version(client, slug: str = "VA-001") -> int:
    return client.get(f"{_base()}/findings/{slug}").json()["row_version"]


def _stored_notes(slug: str = "VA-001") -> str:
    with db_module.get_connection() as connection:
        row = connection.execute(
            "SELECT notes FROM assessment_findings WHERE slug = ?", (slug,)
        ).fetchone()
    return str(row["notes"])


def _grow_notes_past_the_cap(client, isolate_settings) -> None:
    _seed(client, isolate_settings)
    assert client.post(f"{_base()}/findings", json=_finding_payload()).status_code in (200, 201)
    with db_module.get_connection() as connection:
        connection.execute(
            "UPDATE assessment_findings SET notes = ? WHERE slug = ?",
            ("x" * (state_manager.FINDING_NOTES_MAX_LENGTH + 4005), "VA-001"),
        )


def test_an_append_that_would_cross_the_cap_is_refused_loudly(client, isolate_settings):
    """The cap used to be asserted on the DELTA while the accumulator was
    unbounded, so every append fit and only the repair write 422'd."""
    _grow_notes_past_the_cap(client, isolate_settings)

    refused = client.patch(
        f"{_base()}/findings/VA-001", json={"notes": "one more checkpoint"}
    )

    assert refused.status_code == 400, refused.text
    detail = refused.json()["detail"]
    assert "past the" in detail and "--notes-replace" in detail


def test_a_row_already_over_the_cap_can_be_rewritten_whole(client, isolate_settings):
    """The replace ceiling is deliberately higher than the append cap: the repair
    write is the one that has to carry the whole over-cap field."""
    _grow_notes_past_the_cap(client, isolate_settings)

    replaced = client.patch(
        f"{_base()}/findings/VA-001",
        json={
            "notes": "y" * (state_manager.FINDING_NOTES_MAX_LENGTH + 1),
            "notes_mode": "replace",
            "expected_row_version": _row_version(client),
        },
    )

    assert replaced.status_code == 200, replaced.text
    assert len(_stored_notes()) == state_manager.FINDING_NOTES_MAX_LENGTH + 1


def test_rotate_banks_the_prior_notes_on_the_transition_ledger(client, isolate_settings):
    """Rotation is the exit that SHRINKS the column without discarding anything:
    the prior text lands on the ledger row this write emits, so the pointer left
    behind is a real address."""
    _grow_notes_past_the_cap(client, isolate_settings)
    original = _stored_notes()

    rotated = client.patch(
        f"{_base()}/findings/VA-001",
        json={
            "notes": "Rotated; see the ledger for the accumulated checkpoints.",
            "notes_mode": "rotate",
            "expected_row_version": _row_version(client),
        },
    )

    assert rotated.status_code == 200, rotated.text
    now = _stored_notes()
    assert len(now) < state_manager.FINDING_NOTES_MAX_LENGTH
    assert "notes rotated" in now and "finding history VA-001" in now

    transitions = client.get(f"{_base()}/findings/VA-001/transitions").json()
    banked = transitions[0]["notes_before_json"]
    assert banked == original
    # And an append works again afterwards.
    assert (
        client.patch(f"{_base()}/findings/VA-001", json={"notes": "next checkpoint"}).status_code
        == 200
    )


def test_rotate_preserves_an_oversized_prior_note_without_truncation(
    client, isolate_settings
):
    _seed(client, isolate_settings)
    created = client.post(f"{_base()}/findings", json=_finding_payload())
    assert created.status_code in (200, 201), created.text
    original = "large-note:" + ("x" * 70_000) + ":tail"
    with db_module.get_connection() as connection:
        connection.execute(
            "UPDATE assessment_findings SET notes = ? WHERE slug = ?",
            (original, "VA-001"),
        )

    rotated = client.patch(
        f"{_base()}/findings/VA-001",
        json={
            "notes": "Rotated after the field exceeded its append bound.",
            "notes_mode": "rotate",
            "expected_row_version": _row_version(client),
        },
    )
    assert rotated.status_code == 200, rotated.text

    transitions = client.get(f"{_base()}/findings/VA-001/transitions").json()
    assert transitions[0]["notes_before_json"] == original
    assert transitions[0]["notes_after_json"] == rotated.json()["finding"]["notes"]


def test_merge_records_full_note_history_for_source_and_target(
    client, isolate_settings
):
    _seed(client, isolate_settings)
    source_payload = {
        **_finding_payload(),
        "slug": "VA-002",
        "title": "Duplicate source finding",
        "root_cause_key": "duplicate-source",
        "canonical_location": "https://app.example/api/users/source",
        "notes": "Source-specific note.",
    }
    target_payload = {
        **_finding_payload(),
        "slug": "VA-003",
        "title": "Canonical target finding",
        "root_cause_key": "canonical-target",
        "canonical_location": "https://app.example/api/users/target",
        "notes": "Target-specific note.",
    }
    source = client.post(f"{_base()}/findings", json=source_payload)
    target = client.post(f"{_base()}/findings", json=target_payload)
    assert source.status_code in (200, 201), source.text
    assert target.status_code in (200, 201), target.text

    merged = client.post(
        f"{_base()}/findings/merge",
        json={
            "source_slug": "VA-002",
            "target_slug": "VA-003",
            "reason": "Same root cause after review.",
            "source_name": "operator",
            "expected_source_row_version": source.json()["finding"]["row_version"],
            "expected_target_row_version": target.json()["finding"]["row_version"],
        },
    )
    assert merged.status_code == 200, merged.text

    source_history = client.get(f"{_base()}/findings/VA-002/transitions").json()[0]
    target_history = client.get(f"{_base()}/findings/VA-003/transitions").json()[0]
    assert source_history["notes_before_json"] == source_payload["notes"]
    assert source_history["notes_after_json"] == merged.json()["source"]["notes"]
    assert target_history["notes_before_json"] == target_payload["notes"]
    assert target_history["notes_after_json"] == merged.json()["target"]["notes"]


def test_transition_projection_marks_unrecoverable_legacy_note_history(
    client, isolate_settings
):
    _seed(client, isolate_settings)
    created = client.post(f"{_base()}/findings", json=_finding_payload())
    assert created.status_code in (200, 201), created.text
    with db_module.get_connection() as connection:
        finding = connection.execute(
            "SELECT id, engagement_id FROM assessment_findings WHERE slug = ?",
            ("VA-001",),
        ).fetchone()
        connection.execute(
            """
            INSERT INTO assessment_finding_transitions (
                engagement_id, finding_id, actor, action,
                to_workflow_status, to_verification_status, to_severity,
                metadata_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                int(finding["engagement_id"]),
                int(finding["id"]),
                "legacy-writer",
                "operator_override",
                "exploited",
                "confirmed",
                "high",
                "{}",
            ),
        )

    transitions = client.get(f"{_base()}/findings/VA-001/transitions").json()
    assert transitions[0]["notes_history_status"] == "historical_gap"


def test_an_oversized_row_is_surfaced_as_a_readiness_advisory(client, isolate_settings):
    """Make the condition visible BEFORE it blocks a write."""
    _grow_notes_past_the_cap(client, isolate_settings)

    readiness = client.get(f"{_base()}/report-readiness").json()

    assert any(
        item["kind"] == "finding_notes_over_cap" and item["slug"] == "VA-001"
        for item in readiness["advisories"]
    )


def test_a_details_clobber_is_recoverable_from_the_transition_ledger(
    client, isolate_settings
):
    """"Merge" means dict.update(): a repeated top-level key's value is wholly
    replaced, and the prior value used to exist nowhere — a pure details patch
    wrote no transition row at all."""
    _seed(client, isolate_settings)
    assert client.post(f"{_base()}/findings", json=_finding_payload()).status_code in (200, 201)

    clobbered = client.patch(
        f"{_base()}/findings/VA-001",
        json={"details": {"impact": "Rewritten, losing the original wording."}},
    )
    assert clobbered.status_code == 200, clobbered.text

    transitions = client.get(f"{_base()}/findings/VA-001/transitions").json()
    latest = transitions[0]
    assert latest["action"] == "details_patched"
    before = json.loads(latest["details_before_json"])
    assert before["impact"] == "Anonymous attackers read any user's PII."
    after = json.loads(latest["details_after_json"])
    assert after["impact"] == "Rewritten, losing the original wording."


def test_finding_transition_history_applies_limit_and_offset(client, isolate_settings):
    _seed(client, isolate_settings)
    created = client.post(f"{_base()}/findings", json=_finding_payload())
    assert created.status_code in (200, 201), created.text
    for impact in ("First correction.", "Second correction."):
        patched = client.patch(
            f"{_base()}/findings/VA-001",
            json={"details": {"impact": impact}},
        )
        assert patched.status_code == 200, patched.text

    complete = client.get(f"{_base()}/findings/VA-001/transitions").json()
    page = client.get(
        f"{_base()}/findings/VA-001/transitions",
        params={"limit": 1, "offset": 1},
    )

    assert page.status_code == 200, page.text
    assert page.json() == [complete[1]]


def test_details_append_concatenates_lists_and_deep_merges_objects(
    client, isolate_settings
):
    """``merge`` unions at the TOP LEVEL and REPLACES a repeated key's whole
    value. ``append`` is the non-destructive sibling for the keys that accrete."""
    _seed(client, isolate_settings)
    assert client.post(f"{_base()}/findings", json=_finding_payload()).status_code in (200, 201)
    assert (
        client.patch(
            f"{_base()}/findings/VA-001",
            json={
                "details": {
                    "required_followup": ["Confirm the reachable caller."],
                    "poc_request": {"method": "GET", "url": "/api/users/2"},
                }
            },
        ).status_code
        == 200
    )

    appended = client.patch(
        f"{_base()}/findings/VA-001",
        json={
            "details": {
                "required_followup": ["Replay as a second tenant."],
                "poc_request": {"headers": {"Cookie": "session=..."}},
            },
            "details_mode": "append",
        },
    )

    assert appended.status_code == 200, appended.text
    details = client.get(f"{_base()}/findings/VA-001").json()["details"]
    assert details["required_followup"] == [
        "Confirm the reachable caller.",
        "Replay as a second tenant.",
    ]
    assert details["poc_request"] == {
        "method": "GET",
        "url": "/api/users/2",
        "headers": {"Cookie": "session=..."},
    }


def test_details_append_refuses_a_scalar_rather_than_guessing(client, isolate_settings):
    """Silently concatenating strings is how you get a new instance of this bug,
    and there is no defensible guess between extend and overwrite for a number."""
    _seed(client, isolate_settings)
    assert client.post(f"{_base()}/findings", json=_finding_payload()).status_code in (200, 201)

    refused = client.patch(
        f"{_base()}/findings/VA-001",
        json={"details": {"impact": " — and cross-tenant."}, "details_mode": "append"},
    )

    assert refused.status_code == 400, refused.text
    detail = refused.json()["detail"]
    assert "details.impact already holds a str" in detail
    assert "append cannot extend" in detail
