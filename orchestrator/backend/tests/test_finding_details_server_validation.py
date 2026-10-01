"""The ``details`` allow-list is a SERVER invariant, not a per-verb CLI lint.

It used to be enforced in the CLI only, and only on two of the three write verbs:
``finding verify`` ran no validation at all, so a key it happily created was then
refused by ``finding update``. Evidence was *creatable but not maintainable*, and
the same hole let an out-of-range ``kill_check`` onto records that the update path
would not touch afterwards.

Enforcement is scoped to what a write AUTHORS (mirroring the CVSS-pair check), and
permissive for keys already stored, so closing the door cannot strand what came
through it.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi import HTTPException

from app import db as db_module
from app.services.state_manager.finding_details import validate_finding_details
from tests.proof_fixtures import post_artifact_backed_source_observation

ENGAGEMENT_KEY = "2026-08-22-details-schema"


def _base() -> str:
    return f"/engagements/{ENGAGEMENT_KEY}/assessment"


def _capture_sent_reply(seeded, reply: dict) -> dict:
    draft = {**reply, "sent_status": "draft", "sent_at": None}
    stored = seeded.patch(
        f"{_base()}/findings/VA-001", json={"details": {"replies": [draft]}}
    )
    assert stored.status_code == 200, stored.text
    sent = seeded.post(
        f"{_base()}/submissions/VA-001/replies/1/send",
        json={
            "expected_row_version": stored.json()["finding"]["row_version"],
            "actor": "report-writer",
            "reason": "Sent after operator review.",
        },
    )
    assert sent.status_code == 201, sent.text
    return sent.json()["finding"]


@pytest.fixture
def seeded(client, isolate_settings):
    engagement_dir: Path = isolate_settings["engagements_dir"] / ENGAGEMENT_KEY
    (engagement_dir / "sessions").mkdir(parents=True, exist_ok=True)
    (engagement_dir / "scope.json").write_text(
        json.dumps({"engagement_name": "Details", "targets": ["https://app.example"]}),
        encoding="utf-8",
    )
    (engagement_dir / "findings.md").write_text("# Findings\n", encoding="utf-8")
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200
    for agent_id, role in (
        ("HUNT-1", "vulnerability-analyst"),
        ("VERIFY-1", "code-vuln-verifier"),
    ):
        response = client.post(
            f"{_base()}/dispatches",
            json={"agent_id": agent_id, "agent_role": role, "task": role},
        )
        assert response.status_code == 201, response.text
    assert client.post(f"{_base()}/findings", json=_payload()).status_code == 201
    return client


def _payload(slug: str = "VA-001", **over) -> dict:
    payload = {
        "slug": slug,
        "title": "IDOR in /api/users/{id} allows anon read of any user PII",
        "severity": "medium",
        "workflow_status": "active",
        "defect_family": "access-control",
        "root_cause_key": "missing-object-authz",
        "canonical_location": "https://app.example/api/users",
        "summary": "IDOR",
        "evidence_ref": "findings.md",
        "source_name": "vulnerability-analyst",
        "details": {"evidence": "Replayable request.", "impact": "PII disclosure."},
        "provenance": {"agent_id": "HUNT-1", "agent_name": "vulnerability-analyst"},
    }
    payload.update(over)
    return payload


def test_authored_repro_runs_must_resolve_to_this_engagement_command_runs(seeded) -> None:
    missing = seeded.patch(
        f"{_base()}/findings/VA-001",
        json={"details": {"repro_runs": [999999]}},
    )
    assert missing.status_code == 400, missing.text
    assert "repro_runs" in missing.json()["detail"]

    command = seeded.post(
        f"{_base()}/command-runs",
        json={
            "run_uuid": "repro-ran-001", "command": "curl https://app.example/api/users/2",
            "tool_name": "curl", "agent_name": "HUNT-1", "phase": "verify",
            "status": "completed", "return_code": 0,
            "started_at": "2026-09-25T12:00:00Z",
            "completed_at": "2026-09-25T12:00:01Z", "stdout": "user 2",
        },
    )
    assert command.status_code == 201, command.text
    accepted = seeded.patch(
        f"{_base()}/findings/VA-001",
        json={"details": {"repro_runs": [command.json()["id"]]}},
    )
    assert accepted.status_code == 200, accepted.text


def test_reproduction_decision_matches_numeric_string_repro_run_ids(seeded) -> None:
    reviewer = seeded.post(
        f"{_base()}/dispatches",
        json={
            "agent_id": "COLD-REVIEW", "agent_role": "vulnerability-analyst",
            "task": "Cold reproduction of the finding",
        },
    )
    assert reviewer.status_code == 201, reviewer.text
    command = seeded.post(
        f"{_base()}/command-runs",
        json={
            "run_uuid": "cold-repro-001", "command": "curl https://app.example/api/users/2",
            "tool_name": "curl", "agent_name": "COLD-REVIEW", "phase": "report",
            "status": "completed", "return_code": 0,
            "started_at": "2026-09-25T12:00:00Z",
            "completed_at": "2026-09-25T12:00:01Z", "stdout": "user 2",
        },
    )
    assert command.status_code == 201, command.text
    run_id = command.json()["id"]
    updated = seeded.patch(
        f"{_base()}/findings/VA-001",
        json={"details": {"repro_runs": [str(run_id)]}},
    )
    assert updated.status_code == 200, updated.text

    decision = seeded.post(
        f"{_base()}/dispatch-decisions",
        json={"kind": "repro_rehearsal", "payload": {
            "finding_slug": "VA-001", "verdict": "followed", "proof_mode": "live",
            "verifier_dispatch_agent_id": "COLD-REVIEW", "runs_checked": [run_id],
            "observed_outcome": "The second user's record was returned.",
        }},
    )

    assert decision.status_code == 201, decision.text


@pytest.mark.parametrize(
    "key",
    [
        "honest_bounds",
        "intent_basis_caveat",
        "scope_metric_note",
        "self_obtainability_verdict",
        "mechanism_verdict",
        "severity_band_rationale",
        "correction_history",
        "withdrawal_reason",
    ],
)
def test_the_adjudication_vocabulary_is_writable(seeded, key) -> None:
    """These are the keys a later lane must be able to CORRECT; refusing them at
    the maintenance door while the create door accepted them is what stranded
    them in the first place."""
    response = seeded.patch(
        f"{_base()}/findings/VA-001", json={"details": {key: "adjudicated"}}
    )

    assert response.status_code == 200, response.text
    assert seeded.get(f"{_base()}/findings/VA-001").json()["details"][key] == "adjudicated"


@pytest.mark.parametrize("route", ["record", "patch", "verify"])
def test_an_unknown_details_key_is_refused_on_every_write_path(seeded, route) -> None:
    if route == "record":
        response = seeded.post(
            f"{_base()}/findings",
            json=_payload(
                "VA-002",
                root_cause_key="a-distinct-root-cause",
                canonical_location="https://app.example/api/orders",
                details={"evidence": "e", "impact": "i", "bogus": 1},
            ),
        )
    elif route == "patch":
        response = seeded.patch(
            f"{_base()}/findings/VA-001", json={"details": {"bogus": 1}}
        )
    else:
        response = seeded.post(
            f"{_base()}/findings/VA-001/verify",
            json={
                "verification_status": "confirmed",
                "reason_text": "Reproduced.",
                "details": {"bogus": 1},
            },
        )

    assert response.status_code == 400, response.text
    assert "details.bogus is not an allowed finding detail key" in response.json()["detail"]


def test_a_key_already_stored_on_the_record_can_always_be_rewritten(seeded) -> None:
    """Once a key is in the data, refusing to let anyone correct it strands it
    forever. Matching is EXACT key equality, never a prefix or fuzzy match."""
    with db_module.get_connection() as connection:
        connection.execute(
            "UPDATE assessment_findings SET details_json = ? WHERE slug = ?",
            (json.dumps({"evidence": "e", "impact": "i", "legacy_lane_key": "old"}), "VA-001"),
        )

    repaired = seeded.patch(
        f"{_base()}/findings/VA-001", json={"details": {"legacy_lane_key": "corrected"}}
    )
    assert repaired.status_code == 200, repaired.text
    assert (
        seeded.get(f"{_base()}/findings/VA-001").json()["details"]["legacy_lane_key"]
        == "corrected"
    )
    # A genuinely new unknown key is still refused on the same record.
    assert (
        seeded.patch(
            f"{_base()}/findings/VA-001", json={"details": {"legacy_lane_ke": "typo"}}
        ).status_code
        == 400
    )


def test_backend_preserves_sent_reply_bytes_and_accepts_linked_correction(seeded) -> None:
    sent = {
        "seq": 1,
        "platform": "hackerone",
        "in_response_to": "question",
        "reply_to_seq": None,
        "body": "bytes actually sent",
        "new_evidence": "",
        "new_evidence_ref": "",
        "sent_status": "sent",
        "created_at": "2026-09-11T00:00:00Z",
        "sent_at": "2026-09-11T00:01:00Z",
        "author": "report-writer",
    }
    stored = _capture_sent_reply(seeded, sent)
    sent = stored["details"]["replies"][0]

    rewritten = seeded.patch(
        f"{_base()}/findings/VA-001",
        json={"details": {"replies": [{**sent, "body": "rewritten"}]}},
    )
    assert rewritten.status_code == 409, rewritten.text
    assert "immutable" in rewritten.json()["detail"]

    correction = {
        **sent,
        "seq": 2,
        "body": "corrected bytes",
        "sent_status": "draft",
        "sent_at": None,
        "corrects_seq": 1,
        "event_type": "correction",
    }
    appended = seeded.patch(
        f"{_base()}/findings/VA-001",
        json={"details": {"replies": [sent, correction]}},
    )
    assert appended.status_code == 200, appended.text


def test_backend_refuses_details_replace_that_drops_a_sent_reply(seeded) -> None:
    sent = {
        "seq": 1,
        "platform": "hackerone",
        "in_response_to": "question",
        "reply_to_seq": None,
        "body": "immutable reply bytes",
        "new_evidence": "",
        "new_evidence_ref": "",
        "sent_status": "sent",
        "created_at": "2026-09-11T00:00:00Z",
        "sent_at": "2026-09-11T00:01:00Z",
        "author": "report-writer",
    }
    recorded_finding = _capture_sent_reply(seeded, sent)
    sent = recorded_finding["details"]["replies"][0]

    refused = seeded.patch(
        f"{_base()}/findings/VA-001",
        json={
            "details": {"impact": "replacement details"},
            "details_mode": "replace",
            "expected_row_version": recorded_finding["row_version"],
        },
    )

    assert refused.status_code == 409, refused.text
    assert "sent reply seq 1 is immutable" in refused.json()["detail"]
    fetched = seeded.get(f"{_base()}/findings/VA-001")
    assert fetched.status_code == 200, fetched.text
    assert fetched.json()["details"]["replies"] == [sent]


def test_backend_rejects_duplicate_reply_sequence_before_persistence(seeded) -> None:
    first = {
        "seq": 1,
        "platform": "hackerone",
        "in_response_to": "question",
        "reply_to_seq": None,
        "body": "authentic reply bytes",
        "new_evidence": "",
        "new_evidence_ref": "",
        "sent_status": "draft",
        "created_at": "2026-09-11T00:00:00Z",
        "sent_at": None,
        "author": "report-writer",
    }
    forged = {**first, "body": "forged competing bytes"}

    refused = seeded.patch(
        f"{_base()}/findings/VA-001",
        json={"details": {"replies": [first, forged]}},
    )

    assert refused.status_code == 400, refused.text
    assert "duplicate reply seq 1" in refused.json()["detail"]
    assert "replies" not in seeded.get(f"{_base()}/findings/VA-001").json()["details"]


def test_finding_get_and_list_refuse_legacy_duplicate_reply_sequences(seeded) -> None:
    first = {
        "seq": 1,
        "platform": "hackerone",
        "in_response_to": "question",
        "reply_to_seq": None,
        "body": "authentic reply bytes",
        "new_evidence": "",
        "new_evidence_ref": "",
        "sent_status": "sent",
        "created_at": "2026-09-11T00:00:00Z",
        "sent_at": "2026-09-11T00:01:00Z",
        "author": "report-writer",
    }
    with db_module.get_connection() as connection:
        connection.execute(
            "UPDATE assessment_findings SET details_json = ? WHERE slug = ?",
            (
                json.dumps({"replies": [first, {**first, "body": "ambiguous bytes"}]}),
                "VA-001",
            ),
        )

    fetched = seeded.get(f"{_base()}/findings/VA-001")
    listed = seeded.get(f"{_base()}/findings")

    assert fetched.status_code == 409, fetched.text
    assert "duplicate reply seq 1" in fetched.json()["detail"]
    assert listed.status_code == 409, listed.text
    assert "duplicate reply seq 1" in listed.json()["detail"]


@pytest.mark.parametrize(
    ("mutation", "expected_detail"),
    [
        (lambda row: {key: value for key, value in row.items() if key != "seq"}, "seq is required"),
        (
            lambda row: {
                key: value for key, value in row.items() if key != "author"
            },
            "author is required",
        ),
        (
            lambda row: {**row, "sent_status": "sent", "sent_at": None},
            "sent replies require a nonempty sent_at",
        ),
        (
            lambda row: {
                **row,
                "sent_status": "draft",
                "sent_at": "2026-09-11T00:01:00Z",
            },
            "draft replies require sent_at=null",
        ),
        (
            lambda row: {**row, "corrects_seq": 1},
            "correction replies require event_type='correction' and corrects_seq",
        ),
        (
            lambda row: {**row, "event_type": "correction"},
            "correction replies require event_type='correction' and corrects_seq",
        ),
    ],
    ids=[
        "missing-seq",
        "missing-author",
        "sent-without-timestamp",
        "draft-with-timestamp",
        "correction-without-event",
        "correction-without-pointer",
    ],
)
def test_backend_requires_complete_reply_version_rows(
    seeded, mutation, expected_detail
) -> None:
    row = {
        "seq": 1,
        "platform": "hackerone",
        "in_response_to": "question",
        "reply_to_seq": None,
        "body": "reply bytes",
        "new_evidence": "",
        "new_evidence_ref": "",
        "sent_status": "draft",
        "created_at": "2026-09-11T00:00:00Z",
        "sent_at": None,
        "author": "report-writer",
    }

    refused = seeded.patch(
        f"{_base()}/findings/VA-001",
        json={"details": {"replies": [mutation(row)]}},
    )

    assert refused.status_code == 400, refused.text
    assert expected_detail in refused.json()["detail"]


@pytest.mark.parametrize(
    ("reference_fields", "expected_detail"),
    [
        (
            {"corrects_seq": 999, "event_type": "correction"},
            "correction must reference an existing sent reply",
        ),
        (
            {"reply_to_seq": 999},
            "reply_to_seq must reference a prior reply",
        ),
    ],
    ids=["dangling-correction", "dangling-thread-pointer"],
)
def test_backend_rejects_dangling_reply_references_on_create(
    seeded, reference_fields, expected_detail
) -> None:
    row = {
        "seq": 1,
        "platform": "hackerone",
        "in_response_to": "question",
        "reply_to_seq": None,
        "body": "reply bytes",
        "new_evidence": "",
        "new_evidence_ref": "",
        "sent_status": "draft",
        "created_at": "2026-09-11T00:00:00Z",
        "sent_at": None,
        "author": "report-writer",
        **reference_fields,
    }

    refused = seeded.post(
        f"{_base()}/findings",
        json=_payload(
            "VA-002",
            root_cause_key="distinct-reply-thread",
            canonical_location="https://app.example/api/replies",
            details={"replies": [row]},
        ),
    )

    assert refused.status_code == 400, refused.text
    assert expected_detail in refused.json()["detail"]


def test_backend_allows_unchanged_incomplete_legacy_reply_when_appending(seeded) -> None:
    legacy_sent = {
        "seq": 1,
        "platform": "hackerone",
        "in_response_to": "question",
        "reply_to_seq": None,
        "body": "legacy sent bytes",
        "new_evidence": "",
        "new_evidence_ref": "",
        "sent_status": "sent",
        "created_at": "2026-09-11T00:00:00Z",
        "sent_at": "2026-09-11T00:01:00Z",
    }
    with db_module.get_connection() as connection:
        connection.execute(
            "UPDATE assessment_findings SET details_json = ? WHERE slug = ?",
            (json.dumps({"replies": [legacy_sent]}), "VA-001"),
        )
    appended = {
        **legacy_sent,
        "seq": 2,
        "body": "new draft bytes",
        "sent_status": "draft",
        "sent_at": None,
        "author": "report-writer",
    }

    response = seeded.patch(
        f"{_base()}/findings/VA-001",
        json={"details": {"replies": [legacy_sent, appended]}},
    )

    assert response.status_code == 200, response.text
    assert response.json()["finding"]["details"]["replies"] == [
        legacy_sent,
        appended,
    ]


def test_kill_check_is_bounded_at_the_verify_door(seeded) -> None:
    """The five-check protocol has five checks; a 6 is an authoring error, and
    verify was the door it walked through."""
    refused = seeded.post(
        f"{_base()}/findings/VA-001/verify",
        json={
            "verification_status": "false_positive",
            "reason_text": "Guard present.",
            "details": {"kill_reason": "Upstream guard bounds the length.", "kill_check": 6},
        },
    )

    assert refused.status_code == 400, refused.text
    assert "details.kill_check must be <= 5" in refused.json()["detail"]


def test_a_row_already_storing_an_out_of_range_kill_check_stays_repairable(
    seeded,
) -> None:
    """A naive bound check on the update path would freeze exactly the rows the
    bound exists to fix."""
    with db_module.get_connection() as connection:
        connection.execute(
            "UPDATE assessment_findings SET details_json = ? WHERE slug = ?",
            (
                json.dumps({"evidence": "e", "impact": "i", "kill_check": 6}),
                "VA-001",
            ),
        )

    lowered = seeded.patch(
        f"{_base()}/findings/VA-001", json={"details": {"kill_check": 3}}
    )

    assert lowered.status_code == 200, lowered.text
    assert seeded.get(f"{_base()}/findings/VA-001").json()["details"]["kill_check"] == 3
    # An unrelated patch on the un-repaired row is never judged for it either.
    with db_module.get_connection() as connection:
        connection.execute(
            "UPDATE assessment_findings SET details_json = ? WHERE slug = ?",
            (json.dumps({"evidence": "e", "impact": "i", "kill_check": 6}), "VA-001"),
        )
    assert (
        seeded.patch(f"{_base()}/findings/VA-001", json={"summary": "unrelated"}).status_code
        == 200
    )


def test_a_declared_enum_and_type_are_enforced(seeded) -> None:
    bad_enum = seeded.patch(
        f"{_base()}/findings/VA-001", json={"details": {"confidence": "certain"}}
    )
    assert bad_enum.status_code == 400, bad_enum.text
    assert "must be one of" in bad_enum.json()["detail"]

    bad_type = seeded.patch(
        f"{_base()}/findings/VA-001", json={"details": {"required_followup": "a string"}}
    )
    assert bad_type.status_code == 400, bad_type.text
    assert "must be of type array" in bad_type.json()["detail"]


@pytest.mark.parametrize(
    "details",
    [
        {
            "function": "read_export",
            "discovery_stage": "hunt",
            "source_anchor": "return candidate.read_bytes()",
            "entry_point": "read_export(filename)",
            "sink": "Path.read_bytes",
            "taint_path": ["filename", "candidate", "Path.read_bytes"],
            "proof_complete": True,
        },
        {
            "discovered_credential": {
                "credential_key": "leaked-session-cookie",
                "credential_id": 42,
                "principal": "victim@target.example",
                "kind": "session_cookie",
                "minted_identity": "disc-sessionid-deadbeef",
                "session_minted": True,
            }
        },
        {
            "poc_request": {
                "method": "POST",
                "url": "https://app.example/api/users",
                "headers": {"Content-Type": "application/json"},
                "body": '{"id": 7}',
            }
        },
        {
            "timeline": [
                {
                    "timestamp": "2026-08-22T12:34:56Z",
                    "event": "Suspicious OAuth grant created.",
                    "source_file": "ir/reports/oauth-grants.json",
                    "command_run_id": 73,
                }
            ],
            "iocs": ["203.0.113.9", {"type": "domain", "value": "evil.example"}],
        },
    ],
    ids=["code-v1", "credential-v1", "web-v1", "blue-v1"],
)
def test_valid_workflow_extension_shapes_are_accepted(details) -> None:
    validate_finding_details(details)


@pytest.mark.parametrize(
    ("details", "expected_path"),
    [
        (
            {
                "discovered_credential": {
                    "credential_key": "leaked-password",
                    "credential_id": 42,
                    "principal": "admin@target.example",
                    "kind": "password",
                    "minted_identity": None,
                    "session_minted": "no",
                }
            },
            "details.discovered_credential.session_minted",
        ),
        (
            {
                "discovered_credential": {
                    "credential_key": "leaked-password",
                    "credential_id": 42,
                    "principal": "admin@target.example",
                    "kind": "password",
                    "minted_identity": None,
                    "session_minted": False,
                    "session_mintd": False,
                }
            },
            "details.discovered_credential.session_mintd",
        ),
        (
            {"poc_request": {"headers": {"Authorization": True}}},
            "details.poc_request.headers.Authorization",
        ),
        ({"poc_request": {"methd": "GET"}}, "details.poc_request.methd"),
        ({"timeline": ["not a timeline row"]}, "details.timeline[0]"),
        ({"iocs": [7]}, "details.iocs[0]"),
    ],
    ids=[
        "credential-nested-type",
        "credential-nested-typo",
        "web-deeply-nested-type",
        "web-nested-typo",
        "blue-timeline-item-type",
        "blue-ioc-item-type",
    ],
)
def test_invalid_nested_workflow_extension_values_are_rejected(
    details, expected_path
) -> None:
    with pytest.raises(HTTPException) as exc_info:
        validate_finding_details(details)

    assert exc_info.value.status_code == 400
    assert expected_path in str(exc_info.value.detail)


# ──────────────────────────────────────────────────────────────────────────
# A kill that admits the experiment never ran is `blocked`, not `false_positive`
# ──────────────────────────────────────────────────────────────────────────


def _completed_counter_check(seeded) -> dict:
    run = seeded.post(
        f"{_base()}/assessment-runs",
        json={
            "run_uuid": "run-details-verifier",
            "run_kind": "code",
            "producer_dispatch_agent_id": "VERIFY-1",
        },
    )
    assert run.status_code == 201, run.text
    linked = seeded.post(
        f"{_base()}/findings/VA-001/links",
        json={
            "link_kind": "proof_run", "target_kind": "assessment_run",
            "target_id": run.json()["id"],
        },
    )
    assert linked.status_code == 200, linked.text
    receipt = post_artifact_backed_source_observation(
        seeded,
        f"{_base()}/proof-receipts",
        json={
            "run_id": run.json()["id"],
            "evidence_kind": "source_observation",
            "expected_result": "an unguarded path reaches the sensitive read",
            "observed_result": "all paths are dominated by the authorization guard",
        },
    )
    assert receipt.status_code == 201, receipt.text
    completed = seeded.patch(
        f"{_base()}/assessment-runs/{run.json()['id']}",
        json={"status": "completed"},
    )
    assert completed.status_code == 200, completed.text
    receipt_id = receipt.json()["id"]
    return {
        "method": "authorization-dominance source proof",
        "expected_result": "an unguarded path reaches the sensitive read",
        "observed_result": "all paths are dominated by the authorization guard",
        "falsified_claim": "a path bypasses the authorization guard",
        "completed": True,
        "proof_receipt_ids": [receipt_id],
    }


def _kill(seeded, kill_reason: str, **details):
    payload = {"kill_reason": kill_reason, "kill_check": 2}
    payload.update(details)
    return seeded.post(
        f"{_base()}/findings/VA-001/verify",
        json={
            "verification_status": "false_positive",
            "reason_text": "Verifier disposition.",
            "details": payload,
            "counter_check": _completed_counter_check(seeded),
        },
    )


@pytest.mark.parametrize(
    "details",
    [
        {"kill_check": 2},
        {"kill_reason": "The authorization guard dominates every path."},
    ],
)
def test_false_positive_requires_kill_reason_and_kill_check(seeded, details) -> None:
    response = seeded.post(
        f"{_base()}/findings/VA-001/verify",
        json={
            "verification_status": "false_positive",
            "reason_text": "Verifier disposition.",
            "details": details,
            "counter_check": _completed_counter_check(seeded),
        },
    )

    assert response.status_code == 400, response.text
    assert "details.kill_reason and details.kill_check" in response.json()["detail"]
    assert "integer from 1 to 5" in response.json()["detail"]


def test_a_kill_citing_an_absent_capability_must_name_a_settling_test(seeded) -> None:
    """``false_positive`` is the path of least resistance — it is the only
    disposition the verify flow NAMES as the negative outcome — so nothing
    objected when a kill's own text said the experiment never ran."""
    refused = _kill(seeded, "Could not test: no second organization to pivot from.")

    assert refused.status_code == 400, refused.text
    detail = refused.json()["detail"]
    assert "`blocked`, not `false_positive`" in detail
    assert "required_followup" in detail


def test_naming_the_settling_test_satisfies_it(seeded) -> None:
    """Satisfiable by naming the test, never by rewording the kill."""
    accepted = _kill(
        seeded,
        "Could not test: no second organization to pivot from.",
        required_followup=["Provision a second tenant and replay the cross-org read."],
    )

    assert accepted.status_code == 200, accepted.text
    readiness = seeded.get(f"{_base()}/report-readiness").json()
    advisory = next(
        item
        for item in readiness["advisories"]
        if item["kind"] == "killed_finding_settling_test_outstanding"
    )
    assert advisory["slug"] == "VA-001"
    # Advisory, never a blocker: the kill itself is legitimate.
    assert not any(
        item["kind"] == "killed_finding_settling_test_outstanding"
        for item in readiness["blockers"]
    )


def test_a_plain_mechanism_based_kill_is_unaffected(seeded) -> None:
    accepted = _kill(seeded, "The upstream guard bounds the header to 8192 bytes.")

    assert accepted.status_code == 200, accepted.text
