"""Imported sources a proof run never read cannot disappear from its outcome."""
from __future__ import annotations

import hashlib
import json
import sqlite3

import pytest

from app import db as db_module
from tests.test_run_accounting_api import (
    BASE,
    _create_scan,
    _recovery_parent_run,
    _recovery_receipt,
    _resume,
    _seal,
    _seed,
    _source,
)


def _import(client, run: dict, count: int) -> list[dict]:
    response = client.post(
        f"{BASE}/assessment-runs/{run['id']}/sources",
        json={
            "sources": [
                _source(
                    target_key="service-a",
                    path=f"src/module_{index}.py",
                    content=f"VALUE = {index}\n".encode(),
                )
                for index in range(count)
            ]
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _source_obligation(client, run: dict, source: dict) -> dict:
    page = client.get(
        f"{BASE}/assessment-runs/{run['id']}/obligations",
        params={"limit": 1000, "offset": 0},
    )
    assert page.status_code == 200, page.text
    [obligation] = [
        row
        for row in page.json()["items"]
        if row["identity_key"] == f"source_read:{source['id']}"
    ]
    return obligation


@pytest.fixture
def seeded_engagement(client, isolate_settings):
    """Seed the engagement the cases below run against.

    Requested last by each test so the seed happens after that test's other
    fixtures, exactly where the per-test ``_seed(...)`` call used to run.
    """
    return _seed(client, isolate_settings)


@pytest.mark.parametrize("closing_status", ["resolved", "accepted_gap"])
def test_manual_closure_cannot_retire_an_unread_source(
    client, closing_status, seeded_engagement
) -> None:
    run = _recovery_parent_run(client, run_uuid=f"unread-{closing_status}")
    receipt_id = _recovery_receipt(
        client, run, slug=f"unread-{closing_status}", observed="guard absent"
    )
    [source] = _import(client, run, 1)
    obligation = _source_obligation(client, run, source)

    refused = client.patch(
        f"{BASE}/assessment-runs/{run['id']}/obligations/{obligation['id']}",
        json={
            "status": closing_status,
            "resolution": "not needed for this proof",
            "proof_receipt_ids": [receipt_id],
        },
    )

    assert refused.status_code == 409, refused.text
    assert "source-read record" in refused.json()["detail"]
    assert "obligation release" in refused.json()["detail"]
    assert _source_obligation(client, run, source)["status"] == "open"


def test_recording_a_closed_source_read_obligation_is_refused(client, seeded_engagement) -> None:
    run = _recovery_parent_run(client, run_uuid="recorded-source-closure")
    receipt_id = _recovery_receipt(
        client, run, slug="recorded-source-closure", observed="guard absent"
    )

    refused = client.post(
        f"{BASE}/assessment-runs/{run['id']}/obligations",
        json={
            "identity_key": "source_read:manual",
            "obligation_kind": "source_read",
            "object_type": "source",
            "object_key": "service-a:src/never_read.py",
            "hard": True,
            "status": "resolved",
            "resolution": "assumed read",
            "proof_receipt_ids": [receipt_id],
        },
    )

    assert refused.status_code == 409, refused.text
    assert "source-read record" in refused.json()["detail"]


def _release(client, run: dict, obligation: dict, *, agent_id: str, reason: str):
    return client.post(
        f"{BASE}/assessment-runs/{run['id']}/obligations/{obligation['id']}/release",
        json={"dispatch_agent_id": agent_id, "reason": reason},
    )


def _obligation_digest(client, run: dict) -> str:
    """The seal's obligation digest, recomputed from the public listing."""

    page = client.get(
        f"{BASE}/assessment-runs/{run['id']}/obligations",
        params={"limit": 1000, "offset": 0},
    ).json()["items"]
    identity = [
        [
            row["identity_key"],
            row["obligation_kind"],
            row["object_type"],
            row["object_key"],
            int(row["hard"]),
            row["status"],
            row["resolution"],
            json.dumps(row["proof_receipt_ids"], separators=(",", ":")),
        ]
        for row in sorted(page, key=lambda row: row["identity_key"])
    ]
    return hashlib.sha256(
        json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def test_producer_release_closes_an_unread_source_with_an_audited_reason(
    client, seeded_engagement
) -> None:
    run = _recovery_parent_run(client, run_uuid="release-unread")
    _recovery_receipt(client, run, slug="release-unread", observed="guard absent")
    [source] = _import(client, run, 1)
    obligation = _source_obligation(client, run, source)
    reason = "generated fixture outside the claimed request path"

    released = _release(client, run, obligation, agent_id="HUNT-RUN-1", reason=reason)

    assert released.status_code == 200, released.text
    assert released.json()["status"] == "released"
    assert released.json()["resolution"] == reason
    retried = _release(client, run, obligation, agent_id="HUNT-RUN-1", reason=reason)
    assert retried.status_code == 200, retried.text
    assert retried.json() == released.json()
    history = client.get(
        f"{BASE}/assessment-runs/{run['id']}/obligations/{obligation['id']}/history"
    ).json()
    assert [(event["from_status"], event["to_status"]) for event in history] == [
        (None, "open"),
        ("open", "released"),
    ]
    assert history[-1]["resolution"] == reason
    assert history[-1]["actor_dispatch_id"] == run["producer_dispatch_id"]
    assert history[-1]["actor_dispatch_agent_id"] == "HUNT-RUN-1"
    decisions = client.get(
        f"{BASE}/assessment-runs/{run['id']}/decision-history",
        params={"limit": 10, "offset": 0},
    ).json()["items"]
    assert decisions[-1]["to_status"] == "released"
    assert decisions[-1]["actor_dispatch_agent_id"] == "HUNT-RUN-1"
    current = client.get(f"{BASE}/assessment-runs/{run['id']}").json()
    assert current["counts"]["released_sources"] == 1
    assert current["counts"]["open_hard_obligations"] == 0
    assert current["blockers"] == []

    sealed = _seal(client, run)

    assert sealed["status"] == "completed"
    assert sealed["seal"]["counts"]["released_sources"] == 1
    assert sealed["seal"]["obligation_digest"] == _obligation_digest(client, run)
    refused = _release(client, run, obligation, agent_id="HUNT-RUN-1", reason="later")
    assert refused.status_code == 409, refused.text


def test_release_rejects_a_different_reason_for_an_already_released_source(
    client, seeded_engagement
) -> None:
    run = _recovery_parent_run(client, run_uuid="release-immutable")
    [source] = _import(client, run, 1)
    obligation = _source_obligation(client, run, source)
    assert _release(
        client, run, obligation, agent_id="HUNT-RUN-1", reason="out of scope"
    ).status_code == 200

    rewritten = _release(
        client, run, obligation, agent_id="HUNT-RUN-1", reason="different story"
    )

    assert rewritten.status_code == 409, rewritten.text
    assert _source_obligation(client, run, source)["resolution"] == "out of scope"


def _second_dispatch(client) -> None:
    response = client.post(
        f"{BASE}/dispatches",
        json={
            "agent_id": "VERIFY-RUN-2",
            "agent_role": "code-vuln-verifier",
            "task": "verify an unrelated finding",
            "requested_model": "gpt-5.6-sol",
            "requested_reasoning": "xhigh",
            "client_name": "codex",
        },
    )
    assert response.status_code == 201, response.text


@pytest.mark.parametrize(
    "case", ["scan", "other_kind", "other_agent", "blank_reason", "sealed"]
)
def test_release_is_refused_outside_a_producer_proof_source_release(
    client, case, seeded_engagement
) -> None:
    agent_id = "HUNT-RUN-1"
    reason = "generated fixture outside the claimed request path"
    if case == "scan":
        run = _create_scan(client, run_uuid="release-scan")
        assert client.patch(
            f"{BASE}/assessment-runs/{run['id']}", json={"status": "running"}
        ).status_code == 200
    else:
        run = _recovery_parent_run(client, run_uuid=f"release-{case}")
    [source] = _import(client, run, 1)
    obligation = _source_obligation(client, run, source)
    if case == "other_kind":
        obligation = client.post(
            f"{BASE}/assessment-runs/{run['id']}/obligations",
            json={
                "identity_key": "coverage:service-a",
                "obligation_kind": "coverage",
                "object_type": "target",
                "object_key": "service-a",
                "hard": True,
                "status": "open",
                "resolution": "",
                "proof_receipt_ids": [],
            },
        ).json()
    elif case == "other_agent":
        _second_dispatch(client)
        agent_id = "VERIFY-RUN-2"
    elif case == "blank_reason":
        reason = "   "
    elif case == "sealed":
        _seal(client, run, "partial")

    refused = _release(client, run, obligation, agent_id=agent_id, reason=reason)

    assert refused.status_code == (400 if case == "blank_reason" else 409), refused.text
    after = client.get(
        f"{BASE}/assessment-runs/{run['id']}/obligations/{obligation['id']}/history"
    ).json()
    assert [event["to_status"] for event in after] == ["open"]


def test_resumed_proof_run_inherits_a_released_source(client, seeded_engagement) -> None:
    parent = _recovery_parent_run(client, run_uuid="release-parent")
    _recovery_receipt(client, parent, slug="release-parent", observed="guard absent")
    [source] = _import(client, parent, 1)
    reason = "vendored copy of an upstream library"
    assert _release(
        client,
        parent,
        _source_obligation(client, parent, source),
        agent_id="HUNT-RUN-1",
        reason=reason,
    ).status_code == 200
    assert _seal(client, parent)["status"] == "completed"

    child = _resume(client, parent, run_uuid="release-child")
    child_sources = client.get(
        f"{BASE}/assessment-runs/{child['id']}/sources",
        params={"limit": 10, "offset": 0},
    ).json()["items"]
    inherited = _source_obligation(client, child, child_sources[0])

    assert inherited["status"] == "released"
    assert inherited["resolution"] == reason
    assert child["counts"]["released_sources"] == 1
    _recovery_receipt(client, child, slug="release-child", observed="guard absent")
    assert client.get(f"{BASE}/assessment-runs/{child['id']}").json()["blockers"] == []
    assert _seal(client, child)["status"] == "completed"


def test_existing_obligation_history_gains_a_nullable_release_actor(
    client, isolate_settings, seeded_engagement
) -> None:
    run = _recovery_parent_run(client, run_uuid="release-upgrade")
    [source] = _import(client, run, 1)
    db_path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    db_module.close_thread_connection()
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            "ALTER TABLE assessment_run_obligation_events DROP COLUMN actor_dispatch_id"
        )

    db_module.init_db()

    obligation = _source_obligation(client, run, source)
    history = client.get(
        f"{BASE}/assessment-runs/{run['id']}/obligations/{obligation['id']}/history"
    ).json()
    assert [(event["to_status"], event["actor_dispatch_id"]) for event in history] == [
        ("open", None)
    ]
    assert _release(
        client, run, obligation, agent_id="HUNT-RUN-1", reason="out of scope"
    ).status_code == 200


def test_proof_run_completion_is_refused_while_imported_sources_are_unread(
    client, seeded_engagement
) -> None:
    run = _recovery_parent_run(client, run_uuid="unread-completion")
    _recovery_receipt(client, run, slug="unread-completion", observed="guard absent")
    sources = _import(client, run, 3)
    obligation_ids = [_source_obligation(client, run, source)["id"] for source in sources]
    before = client.get(f"{BASE}/assessment-runs/{run['id']}").json()

    refused = client.patch(
        f"{BASE}/assessment-runs/{run['id']}", json={"status": "completed"}
    )

    assert refused.status_code == 409, refused.text
    detail = refused.json()["detail"]
    assert detail.startswith(
        f"proof run {run['id']} cannot complete: 3 imported sources are unread "
        f"(obligations {', '.join(str(value) for value in obligation_ids)})."
    )
    assert "run-audit source-read record" in detail
    assert (
        f"run-audit obligation release {run['id']} <id> --agent-id HUNT-RUN-1 "
        "--reason <text>"
    ) in detail
    assert f"proof-run finish {run['id']} --status partial" in detail
    after = client.get(f"{BASE}/assessment-runs/{run['id']}").json()
    assert after["status"] == "running"
    assert after["seal"] is None
    assert after["lifecycle_history"] == before["lifecycle_history"]
    assert after["counts"]["unread_sources"] == 3
    assert {blocker["code"] for blocker in after["blockers"]} == {"unread_source"}

    for obligation_id in obligation_ids:
        assert _release(
            client,
            run,
            {"id": obligation_id},
            agent_id="HUNT-RUN-1",
            reason="generated fixtures outside the claimed path",
        ).status_code == 200
    completed = _seal(client, run)
    assert completed["status"] == "completed"
    assert completed["seal"]["counts"]["unread_sources"] == 0
    assert completed["seal"]["counts"]["released_sources"] == 3


def test_proof_run_refusal_names_other_blockers_after_unread_sources(
    client, seeded_engagement
) -> None:
    run = _recovery_parent_run(client, run_uuid="unread-and-unproved")
    [source] = _import(client, run, 1)
    obligation_id = _source_obligation(client, run, source)["id"]

    refused = client.patch(
        f"{BASE}/assessment-runs/{run['id']}", json={"status": "completed"}
    )

    assert refused.status_code == 409, refused.text
    detail = refused.json()["detail"]
    assert f"1 imported source is unread (obligation {obligation_id})" in detail
    assert detail.index("unread") < detail.index("Other blockers:")
    assert "Proof run has no recorded evidence receipt." in detail


def test_proof_run_can_still_seal_its_truthful_partial_outcome(client, seeded_engagement) -> None:
    run = _recovery_parent_run(client, run_uuid="explicit-partial")
    _import(client, run, 2)

    sealed = client.patch(
        f"{BASE}/assessment-runs/{run['id']}",
        json={"status": "partial", "reason": "time box ended before both files"},
    )

    assert sealed.status_code == 200, sealed.text
    body = sealed.json()
    assert body["status"] == "partial"
    assert body["seal"]["requested_status"] == "partial"
    assert body["seal"]["counts"]["unread_sources"] == 2
    assert body["lifecycle_history"][-1]["reason"] == "time box ended before both files"


def test_scan_completion_with_an_unread_source_still_seals_partial(
    client, seeded_engagement
) -> None:
    run = _create_scan(client, run_uuid="scan-unread")
    assert client.patch(
        f"{BASE}/assessment-runs/{run['id']}", json={"status": "running"}
    ).status_code == 200
    _import(client, run, 1)

    sealed = client.patch(
        f"{BASE}/assessment-runs/{run['id']}", json={"status": "completed"}
    )

    assert sealed.status_code == 200, sealed.text
    assert sealed.json()["status"] == "partial"
    assert sealed.json()["seal"]["counts"]["unread_sources"] == 1
    assert "unread_source" in {
        blocker["code"] for blocker in sealed.json()["seal"]["blockers"]
    }


def _close_by_legacy_write(obligation: dict, status_value: str, *, hard: bool = True) -> None:
    """Store a source_read obligation the way a write before the release verb did."""

    with db_module.get_connection() as connection:
        connection.execute(
            "UPDATE assessment_run_obligations SET status = ?, resolution = ?, hard = ? "
            "WHERE id = ?",
            (status_value, "accepted before release existed", int(hard), obligation["id"]),
        )
        connection.execute(
            """
            INSERT INTO assessment_run_obligation_events (
                engagement_id, run_id, obligation_id, from_status, to_status,
                resolution, proof_receipt_ids_json
            )
            SELECT engagement_id, run_id, id, 'open', ?, resolution, '[]'
            FROM assessment_run_obligations WHERE id = ?
            """,
            (status_value, obligation["id"]),
        )


def test_a_legacy_accepted_gap_source_is_released_by_its_proof_run_producer(
    client, seeded_engagement
) -> None:
    run = _recovery_parent_run(client, run_uuid="legacy-accepted-gap")
    _recovery_receipt(client, run, slug="legacy-accepted-gap", observed="guard absent")
    [source] = _import(client, run, 1)
    obligation = _source_obligation(client, run, source)
    _close_by_legacy_write(obligation, "accepted_gap")
    refused = client.patch(f"{BASE}/assessment-runs/{run['id']}", json={"status": "completed"})
    assert refused.status_code == 409, refused.text
    assert f"run-audit obligation release {run['id']} <id>" in refused.json()["detail"]
    reason = "vendored helper outside the claimed request path"

    released = _release(client, run, obligation, agent_id="HUNT-RUN-1", reason=reason)

    assert released.status_code == 200, released.text
    assert released.json()["status"] == "released"
    assert released.json()["resolution"] == reason
    history = client.get(
        f"{BASE}/assessment-runs/{run['id']}/obligations/{obligation['id']}/history"
    ).json()
    assert (history[-1]["from_status"], history[-1]["to_status"]) == ("accepted_gap", "released")
    assert history[-1]["actor_dispatch_agent_id"] == "HUNT-RUN-1"
    assert _seal(client, run)["status"] == "completed"


def test_a_legacy_accepted_gap_source_on_a_scan_is_still_refused(
    client, seeded_engagement
) -> None:
    run = _create_scan(client, run_uuid="legacy-accepted-gap-scan")
    assert client.patch(
        f"{BASE}/assessment-runs/{run['id']}", json={"status": "running"}
    ).status_code == 200
    [source] = _import(client, run, 1)
    obligation = _source_obligation(client, run, source)
    _close_by_legacy_write(obligation, "accepted_gap")

    refused = _release(client, run, obligation, agent_id="HUNT-RUN-1", reason="out of scope")

    assert refused.status_code == 409, refused.text
    assert _source_obligation(client, run, source)["status"] == "accepted_gap"


@pytest.mark.parametrize(
    "status_value, hard", [("resolved", True), ("released", True), ("accepted_gap", False)]
)
def test_other_closed_source_obligations_stay_immutable(
    client, status_value, hard, seeded_engagement
) -> None:
    run = _recovery_parent_run(client, run_uuid=f"legacy-{status_value}-{hard}")
    [source] = _import(client, run, 1)
    obligation = _source_obligation(client, run, source)
    _close_by_legacy_write(obligation, status_value, hard=hard)

    refused = _release(client, run, obligation, agent_id="HUNT-RUN-1", reason="out of scope")

    assert refused.status_code == 409, refused.text
    after = _source_obligation(client, run, source)
    assert (after["status"], after["resolution"]) == (
        status_value,
        "accepted before release existed",
    )


def test_the_completion_refusal_offers_only_moves_each_listed_obligation_allows(
    client, seeded_engagement
) -> None:
    run = _recovery_parent_run(client, run_uuid="refusal-accuracy")
    receipt_id = _recovery_receipt(client, run, slug="refusal-accuracy", observed="guard absent")
    [source] = _import(client, run, 1)
    _close_by_legacy_write(_source_obligation(client, run, source), "accepted_gap")
    gap = client.post(
        f"{BASE}/assessment-runs/{run['id']}/obligations",
        json={
            "identity_key": "coverage:service-a",
            "obligation_kind": "coverage",
            "object_type": "target",
            "object_key": "service-a",
            "hard": True,
            "status": "accepted_gap",
            "resolution": "the admin surface was out of reach",
            "proof_receipt_ids": [receipt_id],
        },
    )
    assert gap.status_code in (200, 201), gap.text

    refused = client.patch(f"{BASE}/assessment-runs/{run['id']}", json={"status": "completed"})

    assert refused.status_code == 409, refused.text
    detail = refused.json()["detail"]
    assert "obligation release" in detail
    assert f"proof-run finish {run['id']} --status partial" in detail
    released = _release(
        client, run, _source_obligation(client, run, source),
        agent_id="HUNT-RUN-1", reason="vendored helper outside the claimed path",
    )
    assert released.status_code == 200, released.text
    remaining = client.patch(f"{BASE}/assessment-runs/{run['id']}", json={"status": "completed"})
    assert remaining.status_code == 409, remaining.text
    assert "an accepted gap stays closed" in remaining.json()["detail"]
    blockers = {
        blocker["object_id"]: blocker
        for blocker in client.get(f"{BASE}/assessment-runs/{run['id']}").json()["blockers"]
    }
    accepted = blockers[gap.json()["id"]]
    assert "resolve with recorded evidence" not in accepted["action"]
    assert "partial" in accepted["action"]


@pytest.mark.parametrize("parked_status", ["deferred", "blocked", "accepted_gap"])
def test_a_full_read_resolves_a_parked_source_read(
    client, parked_status, seeded_engagement
) -> None:
    # A deferred or blocked source is still unread, and an accepted gap recorded
    # before releases existed still blocks the run; complete byte coverage is the
    # proof each of them is waiting for.
    run = _recovery_parent_run(client, run_uuid=f"parked-{parked_status}")
    content = b"VALUE = 1\n"
    [source] = client.post(
        f"{BASE}/assessment-runs/{run['id']}/sources",
        json={"sources": [_source(target_key="service-a", path="src/a.py", content=content)]},
    ).json()
    obligation = _source_obligation(client, run, source)
    if parked_status == "accepted_gap":
        with db_module.get_connection() as connection:
            connection.execute(
                "UPDATE assessment_run_obligations SET status = 'accepted_gap', "
                "resolution = 'recorded as a gap' WHERE id = ?",
                (obligation["id"],),
            )
    else:
        parked = client.patch(
            f"{BASE}/assessment-runs/{run['id']}/obligations/{obligation['id']}",
            json={"status": parked_status, "resolution": "later", "proof_receipt_ids": []},
        )
        assert parked.status_code == 200, parked.text

    read = client.post(
        f"{BASE}/assessment-runs/{run['id']}/source-reads",
        json={
            "source_id": source["id"],
            "dispatch_agent_id": "HUNT-RUN-1",
            "attempt": 1,
            "byte_start": 0,
            "byte_end": len(content),
            "line_start": 1,
            "line_end": 2,
        },
    )

    assert read.status_code == 201, read.text
    assert _source_obligation(client, run, source)["status"] == "resolved"
    blockers = client.get(f"{BASE}/assessment-runs/{run['id']}").json()["blockers"]
    assert not [blocker for blocker in blockers if blocker["code"] == "unread_source"]
    connection = sqlite3.connect(str(db_module.database_path()))
    try:
        [event] = connection.execute(
            "SELECT from_status, to_status FROM assessment_run_obligation_events "
            "WHERE obligation_id = ? AND to_status = 'resolved'",
            (obligation["id"],),
        ).fetchall()
    finally:
        connection.close()
    assert event == (parked_status, "resolved")
