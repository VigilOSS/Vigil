from __future__ import annotations

import base64
import hashlib
import json
import sqlite3
from pathlib import Path

import pytest

from app.db import get_connection
from app.reply_render import REPLY_RENDERER_IDENTITY, REPLY_RENDERER_VERSION


ENGAGEMENT_KEY = "2026-09-12-sent-reply-bytes"
BASE = f"/engagements/{ENGAGEMENT_KEY}/assessment"


@pytest.fixture
def finding(client, isolate_settings) -> dict:
    engagement_dir: Path = isolate_settings["engagements_dir"] / ENGAGEMENT_KEY
    engagement_dir.mkdir(parents=True, exist_ok=True)
    (engagement_dir / "scope.json").write_text(
        json.dumps(
            {
                "engagement_name": "Sent reply byte integrity",
                "targets": ["https://app.example"],
            }
        ),
        encoding="utf-8",
    )
    (engagement_dir / "findings.md").write_text("# Findings\n", encoding="utf-8")
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200
    dispatched = client.post(
        f"{BASE}/dispatches",
        json={
            "agent_id": "HUNT-1",
            "agent_role": "vulnerability-analyst",
            "task": "Verify the authorization boundary.",
            "skills": "authorization-testing",
        },
    )
    assert dispatched.status_code == 201, dispatched.text
    created = client.post(
        f"{BASE}/findings",
        json={
            "slug": "VA-001",
            "title": "Authorization bypass",
            "severity": "high",
            "workflow_status": "active",
            "defect_family": "access-control",
            "root_cause_key": "missing-check",
            "canonical_location": "https://app.example/orders/1",
            "summary": "Authorization is not enforced.",
            "evidence_ref": "findings.md",
            "source_name": "vulnerability-analyst",
            "provenance": {
                "agent_id": "HUNT-1",
                "agent_name": "vulnerability-analyst",
            },
            "details": {
                "evidence": "The response disclosed another account's order.",
                "impact": "Cross-account disclosure.",
                "replies": [_draft_reply(1)],
            },
        },
    )
    assert created.status_code == 201, created.text
    return created.json()["finding"]


def _draft_reply(
    seq: int,
    *,
    body: str = "Retested with the supplied account; the issue still reproduces.",
    corrects_seq: int | None = None,
) -> dict:
    row = {
        "seq": seq,
        "platform": "hackerone",
        "in_response_to": "Please retest with the supplied account.",
        "reply_to_seq": seq - 1 if seq > 1 else None,
        "body": body,
        "new_evidence": "HTTP 200 returned the other account's order.",
        "new_evidence_ref": "",
        "sent_status": "draft",
        "created_at": "2026-09-12T12:00:00Z",
        "sent_at": None,
        "author": "report-writer",
    }
    if corrects_seq is not None:
        row["corrects_seq"] = corrects_seq
        row["event_type"] = "correction"
    return row


def _send_payload(finding: dict, **overrides) -> dict:
    payload = {
        "expected_row_version": finding["row_version"],
        "actor": "report-writer",
        "reason": "Sent after operator review.",
    }
    payload.update(overrides)
    return payload


def _send(client, finding: dict, seq: int = 1, **overrides):
    return client.post(
        f"{BASE}/submissions/VA-001/replies/{seq}/send",
        json=_send_payload(finding, **overrides),
    )


def test_send_persists_exact_bytes_and_every_read_verifies_them(
    client, finding
) -> None:
    reply = {
        **finding["details"]["replies"][0],
        "body": "Retested with Authorization: Bearer exact-operator-token.",
        "new_evidence": "HTTP 200 returned José's order.",
    }
    patched = client.patch(
        f"{BASE}/findings/VA-001",
        json={
            "details": {"replies": [reply]},
            "expected_row_version": finding["row_version"],
        },
    )
    assert patched.status_code == 200, patched.text
    current = patched.json()["finding"]
    outbound = (
        "Retested with Authorization: Bearer exact-operator-token.\n\n"
        "**New evidence:**\n\nHTTP 200 returned José's order.\n"
    ).encode("utf-8")

    response = _send(client, current)

    assert response.status_code == 201, response.text
    sent = response.json()
    assert sent["finding"]["details"]["replies"][0]["sent_status"] == "sent"
    assert sent["finding"]["details"]["replies"][0]["sent_at"]
    assert sent["sent_reply"] == {
        "id": sent["sent_reply"]["id"],
        "reply_sequence": 1,
        "availability": "captured",
        "size_bytes": len(outbound),
        "sha256": hashlib.sha256(outbound).hexdigest(),
        "renderer_identity": REPLY_RENDERER_IDENTITY,
        "renderer_version": REPLY_RENDERER_VERSION,
        "created_at": sent["sent_reply"]["created_at"],
        "idempotent_replay": False,
    }

    metadata = client.get(f"{BASE}/submissions/VA-001/replies/1/sent")
    assert metadata.status_code == 200, metadata.text
    assert metadata.json()["sha256"] == hashlib.sha256(outbound).hexdigest()
    download = client.get(
        f"{BASE}/submissions/VA-001/replies/1/sent/download"
    )
    assert download.status_code == 200, download.text
    assert download.content == outbound

    with get_connection() as connection:
        stored = connection.execute(
            "SELECT body_bytes FROM assessment_sent_reply_versions"
        ).fetchone()[0]
    assert stored == outbound

    replay = _send(client, sent["finding"])
    assert replay.status_code == 201, replay.text
    assert replay.json()["sent_reply"]["id"] == sent["sent_reply"]["id"]
    assert replay.json()["sent_reply"]["idempotent_replay"] is True


def test_send_rejects_caller_supplied_digest_without_marking_reply_sent(
    client, finding
) -> None:
    response = client.post(
        f"{BASE}/submissions/VA-001/replies/1/send",
        json={**_send_payload(finding), "sha256": "0" * 64},
    )

    assert response.status_code == 422, response.text
    assert any(item["loc"][-1] == "sha256" for item in response.json()["detail"])
    stored = client.get(f"{BASE}/findings/VA-001").json()
    assert stored["details"]["replies"][0]["sent_status"] == "draft"
    with get_connection() as connection:
        count = connection.execute(
            "SELECT COUNT(*) FROM assessment_sent_reply_versions"
        ).fetchone()[0]
    assert count == 0


def test_send_rejects_caller_supplied_bytes_and_renderer_provenance(
    client, finding
) -> None:
    unrelated = b"Caller-selected bytes unrelated to the stored draft.\n"
    response = client.post(
        f"{BASE}/submissions/VA-001/replies/1/send",
        json={
            **_send_payload(finding),
            "body_base64": base64.b64encode(unrelated).decode("ascii"),
            "size_bytes": len(unrelated),
            "sha256": hashlib.sha256(unrelated).hexdigest(),
            "renderer_identity": "caller/forged-renderer",
            "renderer_version": "999",
        },
    )

    assert response.status_code == 422, response.text
    detail = response.json()["detail"]
    rejected_fields = {item["loc"][-1] for item in detail}
    assert {
        "body_base64",
        "size_bytes",
        "sha256",
        "renderer_identity",
        "renderer_version",
    } <= rejected_fields
    stored = client.get(f"{BASE}/findings/VA-001").json()
    assert stored["details"]["replies"][0]["sent_status"] == "draft"


@pytest.mark.parametrize("body", ["", "   "])
def test_send_rejects_empty_authored_body(client, finding, body: str) -> None:
    reply = {**finding["details"]["replies"][0], "body": body}
    patched = client.patch(
        f"{BASE}/findings/VA-001",
        json={
            "details": {"replies": [reply]},
            "expected_row_version": finding["row_version"],
        },
    )
    assert patched.status_code == 200, patched.text

    response = _send(client, patched.json()["finding"])

    assert response.status_code == 400, response.text
    assert "authored body" in response.json()["detail"]
    stored = client.get(f"{BASE}/findings/VA-001").json()
    assert stored["details"]["replies"][0]["sent_status"] == "draft"


def test_sent_reply_routes_reject_nonpositive_sequence(client, finding) -> None:
    sent = _send(client, finding, seq=0)
    metadata = client.get(f"{BASE}/submissions/VA-001/replies/0/sent")
    download = client.get(f"{BASE}/submissions/VA-001/replies/0/sent/download")

    assert sent.status_code == 422, sent.text
    assert metadata.status_code == 422, metadata.text
    assert download.status_code == 422, download.text


def test_sent_bytes_are_database_immutable_and_digest_corruption_fails_reads(
    client, finding
) -> None:
    sent = _send(client, finding)
    assert sent.status_code == 201, sent.text
    record_id = sent.json()["sent_reply"]["id"]

    with pytest.raises(sqlite3.IntegrityError, match="sent reply versions are immutable"):
        with get_connection() as connection:
            connection.execute(
                "UPDATE assessment_sent_reply_versions SET body_bytes = ? WHERE id = ?",
                (b"rewritten", record_id),
            )
    with pytest.raises(sqlite3.IntegrityError, match="sent reply versions are immutable"):
        with get_connection() as connection:
            connection.execute(
                "DELETE FROM assessment_sent_reply_versions WHERE id = ?", (record_id,)
            )

    with get_connection() as connection:
        connection.execute("DROP TRIGGER assessment_sent_reply_versions_immutable_update")
        connection.execute(
            "UPDATE assessment_sent_reply_versions SET body_bytes = ? WHERE id = ?",
            (b"corrupt", record_id),
        )

    for suffix in ("sent", "sent/download"):
        read = client.get(f"{BASE}/submissions/VA-001/replies/1/{suffix}")
        assert read.status_code == 409, read.text
        assert "integrity" in read.json()["detail"]


def test_legacy_sent_reply_is_preserved_but_bytes_are_explicitly_unavailable(
    client, finding
) -> None:
    legacy = {**_draft_reply(1), "sent_status": "sent", "sent_at": "2026-08-01T00:00:00Z"}
    with get_connection() as connection:
        connection.execute(
            "UPDATE assessment_findings SET details_json = ? WHERE id = ?",
            (json.dumps({"evidence": "e", "impact": "i", "replies": [legacy]}), finding["id"]),
        )

    fetched = client.get(f"{BASE}/findings/VA-001")
    assert fetched.status_code == 200, fetched.text
    assert fetched.json()["details"]["replies"] == [legacy]
    metadata = client.get(f"{BASE}/submissions/VA-001/replies/1/sent")
    assert metadata.status_code == 200, metadata.text
    assert metadata.json() == {
        "reply_sequence": 1,
        "availability": "legacy_unavailable",
    }
    download = client.get(
        f"{BASE}/submissions/VA-001/replies/1/sent/download"
    )
    assert download.status_code == 409, download.text
    assert "legacy" in download.json()["detail"]
    assert "unavailable" in download.json()["detail"]

    reconstructed = _send(client, fetched.json())
    assert reconstructed.status_code == 409, reconstructed.text
    assert "legacy" in reconstructed.json()["detail"]


def test_generic_finding_patch_cannot_create_a_sent_reply_without_byte_capture(
    client, finding
) -> None:
    sent_without_bytes = {
        **finding["details"]["replies"][0],
        "sent_status": "sent",
        "sent_at": "2026-09-12T12:01:00Z",
    }

    response = client.patch(
        f"{BASE}/findings/VA-001",
        json={
            "details": {"replies": [sent_without_bytes]},
            "expected_row_version": finding["row_version"],
        },
    )

    assert response.status_code == 409, response.text
    assert "sent-reply byte capture" in response.json()["detail"]


def test_correction_gets_a_new_linked_sent_sequence(client, finding) -> None:
    first = _send(client, finding)
    assert first.status_code == 201, first.text
    current = first.json()["finding"]
    correction = _draft_reply(2, body="Correction: the affected route is /orders/2.", corrects_seq=1)
    patched = client.patch(
        f"{BASE}/findings/VA-001",
        json={
            "details": {"replies": [current["details"]["replies"][0], correction]},
            "expected_row_version": current["row_version"],
        },
    )
    assert patched.status_code == 200, patched.text

    second = _send(client, patched.json()["finding"], seq=2)

    assert second.status_code == 201, second.text
    replies = second.json()["finding"]["details"]["replies"]
    assert replies[0]["sent_status"] == "sent"
    assert replies[1]["sent_status"] == "sent"
    assert replies[1]["corrects_seq"] == 1
    with get_connection() as connection:
        sequences = [
            row[0]
            for row in connection.execute(
                "SELECT reply_sequence FROM assessment_sent_reply_versions ORDER BY reply_sequence"
            ).fetchall()
        ]
    assert sequences == [1, 2]
