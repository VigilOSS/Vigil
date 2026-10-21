"""Operator verdicts on OAST callbacks.

A probe whose payload called back is ``fired``: it waits for an operator to
review it. ``PATCH /oob-probes/{nonce}`` records that review as ``confirmed`` or
``ignored`` (the probe status vocabulary already owns both), writes the decision
— actor, note, previous status — to the audit log in the same transaction, and
leaves "to review" (``status=fired``) empty once every callback has a verdict.
A later poll never reverts a verdict.
"""
from __future__ import annotations

from tests.test_oob_probes_api import (
    ASSESSMENT_BASE,
    CLIENT_NAME,
    CLIENT_PAYLOAD_HOST,
    _mint_probe,
    _seed_engagement,
)


def _callback(client, nonce: str, observed_at: str = "2026-10-20 12:00:00") -> None:
    response = client.post(
        f"{ASSESSMENT_BASE}/oob-probes/interactions",
        json={
            "nonce": nonce,
            "protocol": "dns",
            "remote_address": "203.0.113.9",
            "query_type": "A",
            "raw_request": f"[{nonce}.oob.security.example] Received DNS interaction (A)",
            "observed_at": observed_at,
            "client_name": CLIENT_NAME,
            "client_payload_host": CLIENT_PAYLOAD_HOST,
        },
    )
    assert response.status_code == 200, response.text
    assert response.json()["matched"] is True


def _verdict(client, nonce: str, **body):
    return client.patch(f"{ASSESSMENT_BASE}/oob-probes/{nonce}", json=body)


def _verdict_entries(client) -> list[dict]:
    entries = client.get(
        f"/engagements/{ASSESSMENT_BASE.split('/')[2]}/activity-entries", params={"limit": 50}
    ).json()["items"]
    return [entry for entry in entries if entry["title"] == "oob probe verdict"]


def test_verdict_clears_the_review_queue_and_is_audited(client, isolate_settings):
    _seed_engagement(client, isolate_settings)
    confirmed = _mint_probe(client, nonce="acmeconfirm0001")
    ignored = _mint_probe(client, nonce="acmeignore00002")
    _callback(client, confirmed["nonce"])
    _callback(client, ignored["nonce"])
    assert len(client.get(f"{ASSESSMENT_BASE}/oob-probes", params={"status": "fired"}).json()) == 2

    response = _verdict(
        client,
        confirmed["nonce"],
        verdict="confirmed",
        note="Callback came from the Acme render farm egress.",
        actor="operator",
    )
    assert response.status_code == 200, response.text
    probe = response.json()
    assert probe["status"] == "confirmed"
    assert probe["verdict"]["verdict"] == "confirmed"
    assert probe["verdict"]["note"] == "Callback came from the Acme render farm egress."
    assert probe["verdict"]["actor"] == "operator"
    assert probe["verdict"]["recorded_at"]
    assert len(probe["interactions"]) == 1

    assert _verdict(client, ignored["nonce"], verdict="ignored").status_code == 200
    assert client.get(f"{ASSESSMENT_BASE}/oob-probes", params={"status": "fired"}).json() == []

    entries = _verdict_entries(client)
    assert len(entries) == 2
    by_nonce = {entry["metadata"]["nonce"]: entry for entry in entries}
    assert by_nonce[confirmed["nonce"]]["actor_kind"] == "operator"
    assert by_nonce[confirmed["nonce"]]["metadata"]["previous_status"] == "fired"
    assert by_nonce[confirmed["nonce"]]["metadata"]["verdict"] == "confirmed"
    assert by_nonce[ignored["nonce"]]["result"] == "ignored"

    # A late callback does not revert the verdict.
    _callback(client, confirmed["nonce"], observed_at="2026-10-20 13:00:00")
    assert client.get(f"{ASSESSMENT_BASE}/oob-probes/{confirmed['nonce']}").json()["status"] == "confirmed"


def test_verdict_can_be_changed_and_repeating_it_is_a_no_op(client, isolate_settings):
    _seed_engagement(client, isolate_settings)
    probe = _mint_probe(client, nonce="acmechange00003")
    _callback(client, probe["nonce"])
    assert _verdict(client, probe["nonce"], verdict="ignored").status_code == 200
    assert _verdict(client, probe["nonce"], verdict="ignored").status_code == 200
    changed = _verdict(client, probe["nonce"], verdict="confirmed", note="Re-checked: real egress.")
    assert changed.status_code == 200, changed.text
    assert changed.json()["status"] == "confirmed"
    assert changed.json()["verdict"]["note"] == "Re-checked: real egress."
    entries = _verdict_entries(client)
    assert [entry["metadata"]["verdict"] for entry in entries] == ["confirmed", "ignored"]
    assert entries[0]["metadata"]["previous_status"] == "ignored"


def test_verdict_needs_a_callback(client, isolate_settings):
    _seed_engagement(client, isolate_settings)
    pending = _mint_probe(client, nonce="acmepending0004")
    response = _verdict(client, pending["nonce"], verdict="confirmed")
    assert response.status_code == 409, response.text
    assert "callback" in response.json()["detail"]
    assert client.get(f"{ASSESSMENT_BASE}/oob-probes/{pending['nonce']}").json()["status"] == "pending"
    assert _verdict_entries(client) == []


def test_verdict_rejects_unknown_probes_and_values(client, isolate_settings):
    _seed_engagement(client, isolate_settings)
    probe = _mint_probe(client, nonce="acmevalues00005")
    _callback(client, probe["nonce"])
    assert _verdict(client, "acme-unknown-nonce", verdict="confirmed").status_code == 404
    assert _verdict(client, probe["nonce"], verdict="pending").status_code == 422
    assert _verdict(client, probe["nonce"], verdict="confirmed", actor="  ").status_code == 422
    assert _verdict(client, probe["nonce"], verdict="confirmed", status="ignored").status_code == 422


def test_point_read_without_a_verdict_reports_none(client, isolate_settings):
    _seed_engagement(client, isolate_settings)
    probe = _mint_probe(client, nonce="acmenoverdict06")
    _callback(client, probe["nonce"])
    assert client.get(f"{ASSESSMENT_BASE}/oob-probes/{probe['nonce']}").json()["verdict"] is None


def _feed_items(client, **params) -> list[dict]:
    response = client.get(f"/engagements/{ASSESSMENT_BASE.split('/')[2]}/activity", params=params)
    assert response.status_code == 200, response.text
    return response.json()["items"]


def _feed_verdicts(client, **params) -> list[dict]:
    return [item for item in _feed_items(client, **params) if item["kind"] == "oob probe verdict"]


def test_activity_feed_names_the_probe_and_verdict_and_links_the_probe(client, isolate_settings):
    _seed_engagement(client, isolate_settings)
    confirmed = _mint_probe(client, nonce="acmefeedconf007")
    switched = _mint_probe(client, nonce="acmefeedswap008")
    for probe in (confirmed, switched):
        _callback(client, probe["nonce"])
    assert _verdict(client, confirmed["nonce"], verdict="confirmed").status_code == 200
    assert _verdict(client, switched["nonce"], verdict="ignored").status_code == 200
    assert _verdict(client, switched["nonce"], verdict="confirmed").status_code == 200
    assert _verdict(client, switched["nonce"], verdict="confirmed", note="Egress owner agreed.").status_code == 200

    items = _feed_verdicts(client)
    assert [item["summary"] for item in items] == [
        "Added a note to the confirmed verdict on OAST probe acmefeedswap008",
        "Changed OAST probe acmefeedswap008 from ignored to confirmed",
        "Ignored OAST probe acmefeedswap008 as noise",
        "Confirmed OAST probe acmefeedconf007 as a real callback",
    ]
    for item, probe in zip(items, (switched, switched, switched, confirmed)):
        assert item["entities"] == [
            {
                "type": "oob_probe",
                "key": probe["nonce"],
                "label": f"OAST probe {probe['nonce']}",
                "ref": {"probe_id": probe["id"]},
                "unlinked_reason": "",
            }
        ]

    # Search matches the summary the operator reads.
    found = _feed_verdicts(client, q="Confirmed OAST probe acmefeedconf007")
    assert [item["summary"] for item in found] == ["Confirmed OAST probe acmefeedconf007 as a real callback"]


def test_activity_feed_verdict_for_an_unrecorded_probe_says_why_it_does_not_link(client, isolate_settings):
    from app import db

    _seed_engagement(client, isolate_settings)
    engagement_id = int(client.get(f"/engagements/{ASSESSMENT_BASE.split('/')[2]}").json()["id"])
    with db.get_connection() as connection:
        for actor_kind in ("operator", "agent"):
            connection.execute(
                """
                INSERT INTO activity_entries (
                    engagement_id, occurred_at, actor_kind, actor_name, title, action, result, metadata_json
                ) VALUES (?, '2026-10-20 12:00:00', ?, 'operator', 'oob probe verdict', 'probe acmegone0009', 'confirmed', ?)
                """,
                (
                    engagement_id,
                    actor_kind,
                    '{"nonce": "acmegone0009", "verdict": "confirmed", "previous_status": "fired"}',
                ),
            )
    by_actor = {item["detail"]["actor_kind"]: item for item in _feed_verdicts(client)}
    operator = by_actor["operator"]
    assert operator["summary"] == "Confirmed OAST probe acmegone0009 as a real callback"
    assert operator["entities"][0]["ref"] is None
    assert operator["entities"][0]["unlinked_reason"] == "This OAST probe is no longer recorded."
    # Only the backend verdict writer (an operator entry) is read as a verdict.
    assert by_actor["agent"]["summary"] == "oob probe verdict"
    assert by_actor["agent"]["entities"] == []


def test_point_read_verdict_comes_only_from_an_operator_verdict_entry(client, isolate_settings):
    """The probe's verdict and the Activity feed apply one rule: only an
    operator entry carrying a known verdict is a verdict. A later entry under
    the same title from anyone else, or with an unknown verdict, changes
    neither the note nor the actor shown on the probe."""
    _seed_engagement(client, isolate_settings)
    probe = _mint_probe(client, nonce="acmeoperator003")
    _callback(client, probe["nonce"])
    assert _verdict(client, probe["nonce"], verdict="confirmed", note="Operator note.").status_code == 200

    engagement_key = ASSESSMENT_BASE.split("/")[2]
    for actor_kind, verdict in (("agent", "ignored"), ("operator", "dismissed")):
        posted = client.post(
            f"/engagements/{engagement_key}/activity-entries",
            json={
                "occurred_at": "2099-01-01T00:00:00Z",
                "actor_kind": actor_kind,
                "actor_name": "va-acme-01",
                "title": "oob probe verdict",
                "metadata": {"nonce": probe["nonce"], "verdict": verdict, "note": "Not an operator verdict."},
            },
        )
        assert posted.status_code == 201, posted.text

    shown = client.get(f"{ASSESSMENT_BASE}/oob-probes/{probe['nonce']}").json()["verdict"]
    assert (shown["verdict"], shown["note"], shown["actor"]) == ("confirmed", "Operator note.", "operator")
