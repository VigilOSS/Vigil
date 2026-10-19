"""A ``pending_runtime_proof`` verdict carries a structured runtime proof plan.

Parking a finding at ``pending_runtime_proof`` says "the source evidence is
accepted and a runtime test is still owed". Without a plan, the next worker had
to rediscover what to test and how to tell a confirmation from a refutation. The
plan (``next_test``) is required on that transition, rejected on every other
one, stored atomically with the transition that parks the finding, and read
back on the finding and its proof work. It is model-authored text: stored
losslessly and never treated as authorization.
"""
from __future__ import annotations

import sqlite3

import pytest

from app import db
from tests.test_engagements_api import _author_provenance, write_engagement

KEY = "2026-03-30-120000-example"
BASE = f"/engagements/{KEY}/assessment"

PLAN = {
    "hypothesis": "The Acme export job result is readable by any tenant that guesses its id.",
    "confirm_if": "A second tenant's session fetches /exports/42 and receives the first tenant's rows.",
    "falsify_if": "The second tenant receives 403 or an empty body for /exports/42.",
    "route_hint": "live",
    "prerequisites": "Two tenant accounts on example.com.\n## not a heading",
}


def _record(client, slug: str = "VA-050") -> None:
    response = client.post(f"{BASE}/findings", json={
        "slug": slug,
        "title": f"Acme export replay ({slug})",
        "severity": "high",
        "canonical_location": f"https://example.com/exports/{slug}",
        "summary": "Export results appear unbound to the requesting tenant.",
        "provenance": _author_provenance(client, slug),
    })
    assert response.status_code == 201, response.text


def _park(client, slug: str = "VA-050", **extra):
    return client.post(f"{BASE}/findings/{slug}/verify", json={
        "verification_status": "pending_runtime_proof",
        "reason_text": "Source evidence accepted; runtime proof still owed.",
        "source_name": "verifier",
        **extra,
    })


@pytest.fixture
def recorded(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"])
    _record(client)
    return client


def test_pending_runtime_proof_requires_a_plan(recorded):
    response = _park(recorded)
    assert response.status_code == 400, response.text
    assert "next_test" in response.json()["detail"]
    assert recorded.get(f"{BASE}/findings/VA-050").json()["verification_status"] == "unreviewed"


def test_plan_round_trips_losslessly_on_write_get_list_and_history(recorded):
    response = _park(recorded, next_test=PLAN)
    assert response.status_code == 200, response.text
    assert response.json()["finding"]["next_test"] == PLAN
    assert recorded.get(f"{BASE}/findings/VA-050").json()["next_test"] == PLAN
    listed = recorded.get(f"{BASE}/findings", params={"verification_status": "pending_runtime_proof"})
    assert [row["next_test"] for row in listed.json()] == [PLAN]
    history = recorded.get(f"{BASE}/findings/VA-050/transitions").json()
    parked = next(row for row in history if row["action"] == "verified_pending_runtime_proof")
    assert parked["next_test"] == PLAN
    created = next(row for row in history if row["action"] == "created")
    assert created["next_test"] is None
    one = recorded.get(f"{BASE}/findings/VA-050/transitions/{parked['id']}").json()
    assert one["next_test"] == PLAN


def test_prerequisites_are_optional_and_default_to_empty(recorded):
    plan = {key: value for key, value in PLAN.items() if key != "prerequisites"}
    response = _park(recorded, next_test=plan)
    assert response.status_code == 200, response.text
    assert response.json()["finding"]["next_test"] == {**plan, "prerequisites": ""}


@pytest.mark.parametrize("status", ["disputed", "blocked"])
def test_plan_is_rejected_on_every_other_transition(recorded, status):
    response = recorded.post(f"{BASE}/findings/VA-050/verify", json={
        "verification_status": status,
        "reason_text": "Not a runtime-proof park.",
        "details": {"block_reason": "No tenant account"} if status == "blocked" else {},
        "next_test": PLAN,
    })
    assert response.status_code == 400, response.text
    assert "next_test" in response.json()["detail"]
    assert recorded.get(f"{BASE}/findings/VA-050").json()["verification_status"] == "unreviewed"


@pytest.mark.parametrize(
    "plan",
    [
        {**PLAN, "owner": "acme"},
        {**PLAN, "route_hint": "remote"},
        {**PLAN, "hypothesis": 7},
        {**PLAN, "prerequisites": ["two accounts"]},
        {**PLAN, "confirm_if": "   "},
        {**PLAN, "falsify_if": ""},
        {key: value for key, value in PLAN.items() if key != "falsify_if"},
        {**PLAN, "hypothesis": "x" * 4097},
        "test the export",
    ],
    ids=[
        "unknown-key", "unknown-route", "non-string", "non-string-optional",
        "blank", "empty", "missing", "too-long", "not-an-object",
    ],
)
def test_malformed_plans_are_rejected_before_any_write(recorded, plan):
    response = _park(recorded, next_test=plan)
    assert response.status_code == 422, response.text
    assert recorded.get(f"{BASE}/findings/VA-050").json()["verification_status"] == "unreviewed"


def test_reparking_with_a_revised_plan_records_a_new_transition(recorded):
    assert _park(recorded, next_test=PLAN).status_code == 200
    revised = {**PLAN, "route_hint": "local", "hypothesis": "A unit-level replay reproduces it."}
    response = _park(recorded, next_test=revised)
    assert response.status_code == 200, response.text
    assert response.json()["transition"]["action"] == "verified_pending_runtime_proof"
    assert recorded.get(f"{BASE}/findings/VA-050").json()["next_test"] == revised
    history = recorded.get(f"{BASE}/findings/VA-050/transitions").json()
    plans = [row["next_test"] for row in history if row["action"] == "verified_pending_runtime_proof"]
    assert plans == [revised, PLAN]


def test_leaving_pending_runtime_proof_retires_the_current_plan(recorded):
    assert _park(recorded, next_test=PLAN).status_code == 200
    response = recorded.post(f"{BASE}/findings/VA-050/verify", json={
        "verification_status": "disputed", "reason_text": "Claim contested.",
    })
    assert response.status_code == 200, response.text
    assert response.json()["finding"]["next_test"] is None
    assert recorded.get(f"{BASE}/findings/VA-050").json()["next_test"] is None
    history = recorded.get(f"{BASE}/findings/VA-050/transitions").json()
    assert any(row["next_test"] == PLAN for row in history)


def test_existing_pending_finding_without_a_plan_reads_null(recorded):
    with db.get_connection() as connection:
        connection.execute(
            "UPDATE assessment_findings SET verification_status='pending_runtime_proof' "
            "WHERE slug='VA-050'"
        )
    finding = recorded.get(f"{BASE}/findings/VA-050").json()
    assert finding["verification_status"] == "pending_runtime_proof"
    assert finding["next_test"] is None
    owed = recorded.get(f"{BASE}/proof-work").json()["owed"]
    assert owed[0]["finding_slug"] == "VA-050"
    assert owed[0]["next_test"] is None
    # Unrelated writes keep working on a legacy parked row.
    patched = recorded.patch(f"{BASE}/findings/VA-050", json={"notes": "Still owed."})
    assert patched.status_code == 200, patched.text


def test_plan_does_not_authorize_live_proof(recorded):
    assert _park(recorded, next_test={**PLAN, "route_hint": "live"}).status_code == 200
    assert recorded.get(f"{BASE}/exploit-candidates").json() == []
    denied = recorded.post(f"{BASE}/proof-work", json={
        "finding_slug": "VA-050", "route": "web", "objective": "Challenge the export replay",
        "target_hosts": ["outside.example"],
    })
    assert denied.status_code == 400, denied.text


def test_proof_work_entries_carry_their_finding_plan(recorded):
    assert _park(recorded, next_test=PLAN).status_code == 200
    listed = recorded.get(f"{BASE}/proof-work").json()
    assert listed["owed"][0]["next_test"] == PLAN
    work = recorded.post(f"{BASE}/proof-work", json={
        "finding_slug": "VA-050", "route": "code", "objective": "Challenge the export replay",
    })
    assert work.status_code == 201, work.text
    assert work.json()["next_test"] == PLAN
    assert recorded.get(f"{BASE}/proof-work").json()["items"][0]["next_test"] == PLAN
    assert recorded.get(f"{BASE}/proof-work/{work.json()['id']}").json()["next_test"] == PLAN


def test_plan_storage_is_additive_idempotent_and_preserves_the_init_transaction(recorded):
    assert _park(recorded, next_test=PLAN).status_code == 200
    with db.get_connection() as connection:
        findings = [dict(row) for row in connection.execute("SELECT * FROM assessment_findings")]
        connection.execute("DROP TABLE assessment_finding_next_tests")
    db.close_thread_connection()
    db.init_db()
    db.init_db()
    with db.get_connection() as connection:
        assert [dict(row) for row in connection.execute("SELECT * FROM assessment_findings")] == findings
        assert connection.execute("SELECT COUNT(*) FROM assessment_finding_next_tests").fetchone()[0] == 0
    # The row whose plan predates the table reads null rather than a fabricated plan.
    assert recorded.get(f"{BASE}/findings/VA-050").json()["next_test"] is None

    memory = sqlite3.connect(":memory:")
    try:
        memory.execute("BEGIN IMMEDIATE")
        db._create_finding_next_test_table(memory)
        assert memory.in_transaction is True
    finally:
        memory.close()
