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
from app import db as db_module

ENGAGEMENT_KEY = "2026-08-22-details-schema"


def _base() -> str:
    return f"/engagements/{ENGAGEMENT_KEY}/assessment"


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
        "provenance": {"agent_name": "vulnerability-analyst"},
    }
    payload.update(over)
    return payload


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
                "disposition": "confirmed",
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


def test_kill_check_is_bounded_at_the_verify_door(seeded) -> None:
    """The five-check protocol has five checks; a 6 is an authoring error, and
    verify was the door it walked through."""
    refused = seeded.post(
        f"{_base()}/findings/VA-001/verify",
        json={
            "disposition": "false_positive",
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


# ──────────────────────────────────────────────────────────────────────────
# A kill that admits the experiment never ran is `blocked`, not `false_positive`
# ──────────────────────────────────────────────────────────────────────────


def _kill(seeded, kill_reason: str, **details):
    payload = {"kill_reason": kill_reason, "kill_check": 2}
    payload.update(details)
    return seeded.post(
        f"{_base()}/findings/VA-001/verify",
        json={
            "disposition": "false_positive",
            "reason_text": "Verifier disposition.",
            "details": payload,
        },
    )


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
