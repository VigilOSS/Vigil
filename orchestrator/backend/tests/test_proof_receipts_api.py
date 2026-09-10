from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path

from app import db as db_module
from tests.test_engagements_api import write_engagement


ENGAGEMENT_KEY = "2026-09-08-proof-receipts"
BASE = f"/engagements/{ENGAGEMENT_KEY}/assessment"


def _seed(client, isolate_settings) -> Path:
    engagement_dir = write_engagement(
        isolate_settings["engagements_dir"], key=ENGAGEMENT_KEY
    )
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200
    for agent_id, role in (
        ("HUNT-1", "vulnerability-analyst"),
        ("VERIFY-1", "code-vuln-verifier"),
    ):
        response = client.post(
            f"{BASE}/dispatches",
            json={"agent_id": agent_id, "agent_role": role, "task": role},
        )
        assert response.status_code == 201, response.text
    return engagement_dir


def _run(client, agent_id: str = "VERIFY-1") -> dict:
    response = client.post(
        f"{BASE}/assessment-runs",
        json={
            "run_uuid": f"run-{agent_id.lower()}",
            "run_kind": "code",
            "producer_dispatch_agent_id": agent_id,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _complete_run(client, run: dict, status: str = "completed") -> dict:
    response = client.patch(
        f"{BASE}/assessment-runs/{run['id']}",
        json={"status": status},
    )
    assert response.status_code == 200, response.text
    return response.json()


def _artifact(client, engagement_dir: Path, path: str, content: str) -> dict:
    target = engagement_dir / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    response = client.post(f"{BASE}/artifacts", json={"path": path, "kind": "proof"})
    assert response.status_code == 201, response.text
    return response.json()


def _source_observation(client, run: dict, observed_result: str) -> dict:
    content = f"proof source for run {run['id']}\n".encode()
    source = client.post(
        f"{BASE}/assessment-runs/{run['id']}/sources",
        json={
            "sources": [
                {
                    "target_key": "proof-source",
                    "declared_root": ".",
                    "path": f"proof/run-{run['id']}.txt",
                    "content_sha256": hashlib.sha256(content).hexdigest(),
                    "byte_size": len(content),
                    "line_count": 2,
                    "encoding": "utf-8",
                    "inventory_status": "included",
                    "exclusion_reason": "",
                    "parser_status": "parsed",
                    "parser_error": "",
                }
            ]
        },
    )
    assert source.status_code == 201, source.text
    source_read = client.post(
        f"{BASE}/assessment-runs/{run['id']}/source-reads",
        json={
            "source_id": source.json()[0]["id"],
            "dispatch_agent_id": "VERIFY-1",
            "attempt": 1,
            "byte_start": 0,
            "byte_end": len(content),
            "line_start": 1,
            "line_end": 2,
        },
    )
    assert source_read.status_code == 201, source_read.text
    receipt = client.post(
        f"{BASE}/proof-receipts",
        json={
            "run_id": run["id"],
            "evidence_kind": "source_observation",
            "source_read_id": source_read.json()["id"],
            "observed_result": observed_result,
        },
    )
    assert receipt.status_code == 201, receipt.text
    return receipt.json()


def test_run_and_raw_derivative_receipts_retain_attribution_hash_and_health(
    client, isolate_settings
) -> None:
    engagement_dir = _seed(client, isolate_settings)
    run = _run(client)
    raw_artifact = _artifact(
        client, engagement_dir, "evidence/raw.txt", "raw response: secret=alpha"
    )

    raw_response = client.post(
        f"{BASE}/proof-receipts",
        json={
            "run_id": run["id"],
            "evidence_kind": "http_exchange",
            "expected_result": "cross-tenant request is denied",
            "observed_result": "cross-tenant response returned 200 with tenant data",
            "artifact_id": raw_artifact["id"],
            "redaction_status": "raw",
        },
    )
    assert raw_response.status_code == 201, raw_response.text
    raw = raw_response.json()
    assert raw["producer_dispatch_id"] == run["producer_dispatch_id"]
    assert raw["evidence_sha256"] == raw_artifact["sha256"]
    assert raw["evidence_health"] == "healthy"
    assert raw["artifact_relative_path"] == "evidence/raw.txt"

    redacted_artifact = _artifact(
        client, engagement_dir, "evidence/redacted.txt", "response: secret=[REDACTED]"
    )
    derivative_response = client.post(
        f"{BASE}/proof-receipts",
        json={
            "run_id": run["id"],
            "evidence_kind": "artifact",
            "expected_result": "shareable proof preserves the decisive response",
            "observed_result": "sensitive token redacted; status and body retained",
            "artifact_id": redacted_artifact["id"],
            "redaction_status": "redacted",
            "derivative_of_receipt_id": raw["id"],
        },
    )
    assert derivative_response.status_code == 201, derivative_response.text
    derivative = derivative_response.json()
    assert derivative["derivative_of_receipt_id"] == raw["id"]
    assert derivative["raw_receipt_id"] == raw["id"]

    run_evidence = client.get(
        f"{BASE}/assessment-runs/{run['id']}/proof-receipts",
        params={"limit": 1, "offset": 0},
    )
    assert run_evidence.status_code == 200, run_evidence.text
    assert run_evidence.json()["total"] == 2
    assert run_evidence.json()["has_more"] is True
    assert run_evidence.json()["items"][0]["producer_dispatch_agent_id"] == "VERIFY-1"
    assert run_evidence.json()["items"][0]["origin_run_id"] == run["id"]
    for evidence_kind in ("browser_action", "oob_event"):
        event = client.post(
            f"{BASE}/proof-receipts",
            json={
                "run_id": run["id"],
                "evidence_kind": evidence_kind,
                "observed_result": f"recorded {evidence_kind}",
                "artifact_id": raw_artifact["id"],
            },
        )
        assert event.status_code == 201, event.text
    observed_events = client.get(
        f"{BASE}/assessment-runs/{run['id']}/observed-events"
    )
    assert observed_events.status_code == 200, observed_events.text
    assert observed_events.json()["total"] == 3
    assert {
        row["evidence_kind"] for row in observed_events.json()["items"]
    } == {"http_exchange", "browser_action", "oob_event"}
    assert all(
        row["audit_run_id"] == run["id"]
        for row in observed_events.json()["items"]
    )

    with db_module.get_connection() as connection:
        connection.execute(
            "UPDATE assessment_artifacts SET present = 0 WHERE id = ?",
            (raw_artifact["id"],),
        )
    tombstoned = client.get(f"{BASE}/proof-receipts/{raw['id']}")
    assert tombstoned.status_code == 200, tombstoned.text
    assert tombstoned.json()["evidence_health"] == "tombstoned"
    assert tombstoned.json()["evidence_sha256"] == raw_artifact["sha256"]
    assert tombstoned.json()["artifact_relative_path"] == "evidence/raw.txt"


def test_receipts_reject_cross_engagement_or_invalid_derivative_links(
    client, isolate_settings
) -> None:
    engagement_dir = _seed(client, isolate_settings)
    run = _run(client)
    artifact = _artifact(client, engagement_dir, "evidence/one.txt", "proof")

    missing_run = client.post(
        f"{BASE}/proof-receipts",
        json={"run_id": 999999, "evidence_kind": "artifact", "artifact_id": artifact["id"]},
    )
    assert missing_run.status_code == 404, missing_run.text

    raw_with_parent = client.post(
        f"{BASE}/proof-receipts",
        json={
            "run_id": run["id"],
            "evidence_kind": "artifact",
            "artifact_id": artifact["id"],
            "redaction_status": "raw",
            "derivative_of_receipt_id": 1,
        },
    )
    assert raw_with_parent.status_code == 400, raw_with_parent.text

    redacted_without_parent = client.post(
        f"{BASE}/proof-receipts",
        json={
            "run_id": run["id"],
            "evidence_kind": "artifact",
            "artifact_id": artifact["id"],
            "redaction_status": "redacted",
        },
    )
    assert redacted_without_parent.status_code == 400, redacted_without_parent.text


def test_proof_receipts_require_a_durable_evidence_record(
    client, isolate_settings
) -> None:
    _seed(client, isolate_settings)
    run = _run(client)

    for evidence_kind in ("source_observation", "artifact", "http_exchange"):
        unbound = client.post(
            f"{BASE}/proof-receipts",
            json={
                "run_id": run["id"],
                "evidence_kind": evidence_kind,
                "observed_result": "caller-authored prose is not proof",
            },
        )
        assert unbound.status_code == 400, unbound.text

    content = b"guard = True\n"
    source = client.post(
        f"{BASE}/assessment-runs/{run['id']}/sources",
        json={
            "sources": [
                {
                    "target_key": "repository",
                    "declared_root": ".",
                    "path": "src/guard.py",
                    "content_sha256": hashlib.sha256(content).hexdigest(),
                    "byte_size": len(content),
                    "line_count": 2,
                    "encoding": "utf-8",
                    "inventory_status": "included",
                    "exclusion_reason": "",
                    "parser_status": "parsed",
                    "parser_error": "",
                }
            ]
        },
    )
    assert source.status_code == 201, source.text
    source_read = client.post(
        f"{BASE}/assessment-runs/{run['id']}/source-reads",
        json={
            "source_id": source.json()[0]["id"],
            "dispatch_agent_id": "VERIFY-1",
            "attempt": 1,
            "byte_start": 0,
            "byte_end": len(content),
            "line_start": 1,
            "line_end": 2,
        },
    )
    assert source_read.status_code == 201, source_read.text
    bound = client.post(
        f"{BASE}/proof-receipts",
        json={
            "run_id": run["id"],
            "evidence_kind": "source_observation",
            "source_read_id": source_read.json()["id"],
            "observed_result": "the exact recorded source range contains the guard",
        },
    )
    assert bound.status_code == 201, bound.text
    assert bound.json()["source_read_id"] == source_read.json()["id"]


def test_command_receipt_requires_and_exposes_an_actual_recorded_execution(
    client, isolate_settings
) -> None:
    _seed(client, isolate_settings)
    run = _run(client)
    command = client.post(
        f"{BASE}/command-runs",
        json={
            "command": "python -m compileall src",
            "argv": ["python", "-m", "compileall", "src"],
            "tool_name": "python",
            "agent_name": "VERIFY-1",
            "phase": "verify",
            "return_code": 0,
            "timed_out": False,
            "success": True,
            "started_at": "2026-09-09T12:00:00Z",
            "completed_at": "2026-09-09T12:00:01Z",
            "duration_ms": 1000,
            "stdout": "compiled",
            "stderr": "",
            "run_uuid": "proof-command-1",
        },
    )
    assert command.status_code == 201, command.text

    missing_link = client.post(
        f"{BASE}/proof-receipts",
        json={
            "run_id": run["id"],
            "evidence_kind": "command",
            "observed_result": "command completed",
        },
    )
    assert missing_link.status_code == 400, missing_link.text

    receipt = client.post(
        f"{BASE}/proof-receipts",
        json={
            "run_id": run["id"],
            "evidence_kind": "command",
            "command_run_id": command.json()["id"],
            "observed_result": "command completed",
        },
    )
    assert receipt.status_code == 201, receipt.text
    assert receipt.json()["command_run_id"] == command.json()["id"]

    run_evidence = client.get(
        f"{BASE}/assessment-runs/{run['id']}/proof-receipts"
    )
    assert run_evidence.status_code == 200, run_evidence.text
    run_receipt = run_evidence.json()["items"][0]
    assert run_receipt["command_run_id"] == command.json()["id"]
    assert run_receipt["command"] == {
        "id": command.json()["id"],
        "run_uuid": "proof-command-1",
        "command": "python -m compileall src",
        "argv": ["python", "-m", "compileall", "src"],
        "tool_name": "python",
        "agent_name": "VERIFY-1",
        "phase": "verify",
        "status": "completed",
        "return_code": 0,
        "timed_out": False,
        "success": True,
        "started_at": "2026-09-09T12:00:00Z",
        "completed_at": "2026-09-09T12:00:01Z",
        "duration_ms": 1000,
        "command_hash": command.json()["command_hash"],
        "stdout_sha256": command.json()["stdout_sha256"],
        "stderr_sha256": command.json()["stderr_sha256"],
        "output_retention_status": command.json()["output_retention_status"],
        "stdout_artifact_ref": command.json()["stdout_artifact_ref"],
        "stderr_artifact_ref": command.json()["stderr_artifact_ref"],
    }
    command_drilldown = client.get(
        f"{BASE}/assessment-runs/{run['id']}/commands"
    )
    assert command_drilldown.status_code == 200, command_drilldown.text
    assert command_drilldown.json()["total"] == 1
    assert command_drilldown.json()["items"][0]["audit_run_id"] == run["id"]
    assert command_drilldown.json()["items"][0]["command"] == run_receipt["command"]


def test_resumed_run_summary_preserves_parent_linked_findings(
    client, isolate_settings
) -> None:
    _seed(client, isolate_settings)
    finding = client.post(
        f"{BASE}/findings",
        json={
            "slug": "VA-902",
            "title": "Finding survives run recovery",
            "severity": "medium",
            "workflow_status": "active",
            "verification_status": "unreviewed",
            "source_name": "vulnerability-analyst",
            "provenance": {"agent_id": "HUNT-1"},
        },
    )
    assert finding.status_code == 201, finding.text
    parent = _run(client)
    receipt = _source_observation(
        client, parent, "independent review reproduced the finding"
    )
    _complete_run(client, parent)
    verified = client.post(
        f"{BASE}/findings/VA-902/verify",
        json={
            "verification_status": "confirmed",
            "reason_text": "independent review",
            "proof_receipt_ids": [receipt["id"]],
        },
    )
    assert verified.status_code == 200, verified.text

    resumed = client.post(
        f"{BASE}/assessment-runs",
        json={
            "run_uuid": "run-verify-1-resumed",
            "run_kind": "code",
            "producer_dispatch_agent_id": "VERIFY-1",
            "resumed_from_run_id": parent["id"],
        },
    )
    assert resumed.status_code == 201, resumed.text
    assert resumed.json()["counts"]["proof_receipts"] == 1
    assert resumed.json()["counts"]["findings"] == 1
    assert resumed.json()["finding_slugs"] == ["VA-902"]


def test_terminal_runs_are_sealed_against_post_hoc_receipts(
    client, isolate_settings
) -> None:
    engagement_dir = _seed(client, isolate_settings)
    post_hoc_artifact = _artifact(
        client, engagement_dir, "evidence/post-hoc.txt", "late evidence"
    )

    for terminal_status in ("completed", "failed", "interrupted", "canceled"):
        run = client.post(
            f"{BASE}/assessment-runs",
            json={
                "run_uuid": f"sealed-{terminal_status}",
                "run_kind": "shared",
                "producer_dispatch_agent_id": "VERIFY-1",
            },
        )
        assert run.status_code == 201, run.text
        if terminal_status == "completed":
            _source_observation(
                client,
                run.json(),
                "completed proof run has durable evidence",
            )
        _complete_run(client, run.json(), terminal_status)

        receipt = client.post(
            f"{BASE}/proof-receipts",
            json={
                    "run_id": run.json()["id"],
                    "evidence_kind": "source_observation",
                    "artifact_id": post_hoc_artifact["id"],
                    "observed_result": "post-hoc evidence must not join a sealed run",
            },
        )
        assert receipt.status_code == 409, receipt.text
        assert "sealed" in receipt.json()["detail"]


def test_artifact_receipt_rejects_present_artifact_without_content_digest(
    client, isolate_settings
) -> None:
    engagement_dir = _seed(client, isolate_settings)
    run = _run(client)
    (engagement_dir / "evidence" / "directory-proof").mkdir(parents=True)
    artifact = client.post(
        f"{BASE}/artifacts",
        json={"path": "evidence/directory-proof", "kind": "proof"},
    )
    assert artifact.status_code == 201, artifact.text
    assert artifact.json()["sha256"] == ""

    receipt = client.post(
        f"{BASE}/proof-receipts",
        json={
            "run_id": run["id"],
            "evidence_kind": "artifact",
            "artifact_id": artifact.json()["id"],
        },
    )

    assert receipt.status_code == 409, receipt.text
    assert "SHA-256" in receipt.json()["detail"]


def test_legacy_proof_links_gain_nullable_transition_without_losing_evidence(
    client, isolate_settings
) -> None:
    _seed(client, isolate_settings)
    created = client.post(
        f"{BASE}/findings",
        json={
            "slug": "VA-777",
            "title": "Legacy proof link",
            "severity": "medium",
            "workflow_status": "active",
            "verification_status": "unreviewed",
            "source_name": "vulnerability-analyst",
            "provenance": {"agent_id": "HUNT-1"},
        },
    )
    assert created.status_code == 201, created.text
    run = _run(client)
    receipt = _source_observation(
        client, run, "independent review reproduced the finding"
    )
    _complete_run(client, run)
    verified = client.post(
        f"{BASE}/findings/VA-777/verify",
        json={
            "verification_status": "confirmed",
            "reason_text": "independent review",
            "proof_receipt_ids": [receipt["id"]],
        },
    )
    assert verified.status_code == 200, verified.text

    db_path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    with sqlite3.connect(str(db_path)) as connection:
        connection.execute(
            "DROP INDEX idx_assessment_finding_proof_receipts_transition"
        )
        connection.execute(
            "DROP INDEX idx_assessment_finding_proof_receipts_finding"
        )
        connection.execute(
            "ALTER TABLE assessment_finding_proof_receipts "
            "RENAME TO assessment_finding_proof_receipts_legacy"
        )
        connection.execute(
            """
            CREATE TABLE assessment_finding_proof_receipts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                finding_id INTEGER NOT NULL,
                proof_receipt_id INTEGER NOT NULL,
                relation TEXT NOT NULL DEFAULT 'verification',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(finding_id, proof_receipt_id, relation)
            )
            """
        )
        connection.execute(
            """
            INSERT INTO assessment_finding_proof_receipts (
                id, engagement_id, finding_id, proof_receipt_id,
                relation, created_at
            )
            SELECT id, engagement_id, finding_id, proof_receipt_id,
                   relation, created_at
            FROM assessment_finding_proof_receipts_legacy
            """
        )
        connection.execute("DROP TABLE assessment_finding_proof_receipts_legacy")

    db_module.init_db()

    with sqlite3.connect(str(db_path)) as connection:
        connection.row_factory = sqlite3.Row
        columns = {
            str(row["name"])
            for row in connection.execute(
                "PRAGMA table_info(assessment_finding_proof_receipts)"
            ).fetchall()
        }
        link = connection.execute(
            "SELECT transition_id, proof_receipt_id "
            "FROM assessment_finding_proof_receipts"
        ).fetchone()
    assert "transition_id" in columns
    assert link is not None
    assert link["transition_id"] is None
    assert link["proof_receipt_id"] == receipt["id"]

    detail = client.get(f"{BASE}/findings/VA-777")
    assert detail.status_code == 200, detail.text
    assert [row["id"] for row in detail.json()["proof_receipts"]] == [receipt["id"]]


def test_legacy_findings_remain_readable_without_invented_runs_or_receipts(
    client, isolate_settings
) -> None:
    _seed(client, isolate_settings)
    created = client.post(
        f"{BASE}/findings",
        json={
            "slug": "VA-001",
            "title": "Legacy finding",
            "workflow_status": "active",
            "verification_status": "unreviewed",
            "canonical_location": "https://example.test/legacy",
            "source_name": "legacy-import",
        },
    )
    assert created.status_code == 201, created.text

    detail = client.get(f"{BASE}/findings/VA-001")
    assert detail.status_code == 200, detail.text
    assert detail.json()["verification_status"] == "unreviewed"
    assert detail.json()["proof_receipts"] == []

    listing = client.get(f"{BASE}/proof-receipts", params={"finding_slug": "VA-001"})
    assert listing.status_code == 200, listing.text
    assert listing.json() == []


def test_receipt_health_tracks_artifact_refresh_without_rewriting_recorded_hash(
    client, isolate_settings
) -> None:
    engagement_dir = _seed(client, isolate_settings)
    run = _run(client)
    artifact = _artifact(client, engagement_dir, "evidence/mutable.txt", "version one")
    receipt_response = client.post(
        f"{BASE}/proof-receipts",
        json={
            "run_id": run["id"],
            "evidence_kind": "artifact",
            "artifact_id": artifact["id"],
        },
    )
    assert receipt_response.status_code == 201, receipt_response.text
    receipt = receipt_response.json()
    recorded_sha256 = receipt["evidence_sha256"]

    (engagement_dir / "evidence/mutable.txt").write_text(
        "version two", encoding="utf-8"
    )
    refreshed = client.post(f"{BASE}/artifacts/refresh")
    assert refreshed.status_code == 200, refreshed.text

    detail = client.get(f"{BASE}/proof-receipts/{receipt['id']}")
    assert detail.status_code == 200, detail.text
    assert detail.json()["evidence_health"] == "stale"
    assert detail.json()["evidence_sha256"] == recorded_sha256

    listing = client.get(f"{BASE}/proof-receipts")
    assert listing.status_code == 200, listing.text
    listed = next(row for row in listing.json() if row["id"] == receipt["id"])
    assert listed["evidence_health"] == "stale"
    assert listed["evidence_sha256"] == recorded_sha256

    (engagement_dir / "evidence/mutable.txt").unlink()
    refreshed = client.post(f"{BASE}/artifacts/refresh")
    assert refreshed.status_code == 200, refreshed.text
    missing = client.get(f"{BASE}/proof-receipts/{receipt['id']}")
    assert missing.status_code == 200, missing.text
    assert missing.json()["evidence_health"] == "missing"
    assert missing.json()["evidence_sha256"] == recorded_sha256


def test_degraded_decision_receipt_blocks_readiness_without_rewriting_verification(
    client, isolate_settings
) -> None:
    engagement_dir = _seed(client, isolate_settings)
    finding = client.post(
        f"{BASE}/findings",
        json={
            "slug": "VA-901",
            "title": "Proof health follows immutable receipt",
            "severity": "high",
            "workflow_status": "active",
            "verification_status": "unreviewed",
            "canonical_location": "https://example.test/proof",
            "source_name": "vulnerability-analyst",
            "provenance": {"agent_id": "HUNT-1"},
            "details": {
                "cvss_score": 8.1,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                "steps_to_reproduce": ["Run the independent check"],
                "remediation": "Enforce authorization",
                "impact": "Unauthorized data modification",
                "evidence": "See the linked proof receipt",
            },
        },
    )
    assert finding.status_code == 201, finding.text
    run = _run(client)
    artifact = _artifact(client, engagement_dir, "evidence/decision.txt", "decisive")
    receipt_response = client.post(
        f"{BASE}/proof-receipts",
        json={
            "run_id": run["id"],
            "evidence_kind": "artifact",
            "artifact_id": artifact["id"],
        },
    )
    assert receipt_response.status_code == 201, receipt_response.text
    receipt_id = receipt_response.json()["id"]
    _complete_run(client, run)
    verified = client.post(
        f"{BASE}/findings/VA-901/verify",
        json={
            "verification_status": "confirmed",
            "reason_text": "Independent proof reproduced the claim.",
            "proof_receipt_ids": [receipt_id],
        },
    )
    assert verified.status_code == 200, verified.text

    (engagement_dir / "evidence/decision.txt").write_text(
        "materially changed", encoding="utf-8"
    )
    assert client.post(f"{BASE}/artifacts/refresh").status_code == 200

    finding_detail = client.get(f"{BASE}/findings/VA-901")
    assert finding_detail.status_code == 200, finding_detail.text
    assert finding_detail.json()["verification_status"] == "confirmed"
    assert finding_detail.json()["proof_receipts"][0]["evidence_health"] == "stale"

    readiness = client.get(f"{BASE}/report-readiness")
    assert readiness.status_code == 200, readiness.text
    blocker = next(
        item
        for item in readiness.json()["blockers"]
        if item["kind"] == "finding_proof_evidence_stale"
    )
    assert blocker["slug"] == "VA-901"
    assert blocker["proof_receipt_id"] == receipt_id

    (engagement_dir / "evidence/decision.txt").unlink()
    assert client.post(f"{BASE}/artifacts/refresh").status_code == 200
    missing_readiness = client.get(f"{BASE}/report-readiness")
    assert missing_readiness.status_code == 200, missing_readiness.text
    missing_blocker = next(
        item
        for item in missing_readiness.json()["blockers"]
        if item["kind"] == "finding_proof_evidence_missing"
    )
    assert missing_blocker["slug"] == "VA-901"
    assert client.get(f"{BASE}/findings/VA-901").json()["verification_status"] == "confirmed"


def test_assessment_runs_have_explicit_terminal_transitions_and_point_reads(
    client, isolate_settings
) -> None:
    _seed(client, isolate_settings)
    terminal_create = client.post(
        f"{BASE}/assessment-runs",
        json={
            "run_uuid": "run-bypassed-transition",
            "run_kind": "shared",
            "producer_dispatch_agent_id": "VERIFY-1",
            "status": "completed",
        },
    )
    assert terminal_create.status_code == 422, terminal_create.text

    started = client.post(
        f"{BASE}/assessment-runs",
        json={
            "run_uuid": "run-explicit-completion",
            "run_kind": "shared",
            "producer_dispatch_agent_id": "VERIFY-1",
        },
    )
    assert started.status_code == 201, started.text
    run = started.json()
    assert run["status"] == "running"
    assert run["producer_dispatch_agent_id"] == "VERIFY-1"

    detail = client.get(f"{BASE}/assessment-runs/{run['id']}")
    assert detail.status_code == 200, detail.text
    assert detail.json() == run

    _source_observation(
        client, run, "proof run completed with recorded evidence"
    )

    completed = client.patch(
        f"{BASE}/assessment-runs/{run['id']}", json={"status": "completed"}
    )
    assert completed.status_code == 200, completed.text
    assert completed.json()["id"] == run["id"]
    assert completed.json()["run_uuid"] == "run-explicit-completion"
    assert completed.json()["status"] == "completed"
    assert completed.json()["producer_dispatch_agent_id"] == "VERIFY-1"

    repeated = client.patch(
        f"{BASE}/assessment-runs/{run['id']}", json={"status": "completed"}
    )
    assert repeated.status_code == 200, repeated.text
    assert repeated.json() == completed.json()

    conflict = client.patch(
        f"{BASE}/assessment-runs/{run['id']}", json={"status": "failed"}
    )
    assert conflict.status_code == 409, conflict.text
    assert client.get(f"{BASE}/assessment-runs/{run['id']}").json()["status"] == "completed"

    failed_started = client.post(
        f"{BASE}/assessment-runs",
        json={
            "run_uuid": "run-explicit-failure",
            "run_kind": "web",
            "producer_dispatch_agent_id": "VERIFY-1",
        },
    )
    assert failed_started.status_code == 201, failed_started.text
    failed = client.patch(
        f"{BASE}/assessment-runs/{failed_started.json()['id']}",
        json={"status": "failed"},
    )
    assert failed.status_code == 200, failed.text
    assert failed.json()["status"] == "failed"

    listing = client.get(f"{BASE}/assessment-runs", params={"limit": 10, "offset": 0})
    assert listing.status_code == 200, listing.text
    assert [row["id"] for row in listing.json()[:2]] == [
        failed_started.json()["id"],
        run["id"],
    ]
    assert all(
        row["producer_dispatch_agent_id"] == "VERIFY-1"
        for row in listing.json()[:2]
    )
