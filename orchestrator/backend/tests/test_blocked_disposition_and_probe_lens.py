"""Phase-2 backend: the ``blocked`` verification status, its report
exclusion, the ``assessment_command_runs.finding_id`` / ``assessment_probe_runs``
``lens`` + ``finding_id`` schema additions, and the record-attempt writer that
emits the non-covering probe result_status vocabulary.

Covers:
- The shared seven-value verification-status vocabulary includes ``blocked``.
- verify-finding requires ``details.block_reason`` when status='blocked'
  (400 without / on the finding, ok with — from the verify OR the finding).
- report-projection exclusion of blocked findings (draft AND final) and the
  report-readiness gate (a blocked finding neither reports nor blocks).
- assessment_command_runs.finding_id round-trip + additive migration on a
  pre-existing DB.
- assessment_probe_runs.lens partitions _probe_key + record_probe_run round-trip
  (same target, different lens = distinct attempts), plus the lens/finding_id
  migration on a pre-existing DB.
- the record-attempt route: a non-covering result_status (attempted/blocked/
  no-signal) + lens + optional finding_id, persisted end-to-end.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3

from app import db as db_module
from app.services import state_manager
from app.services.state_manager._common import VERIFICATION_STATUSES, VerificationStatus
from app.services.state_manager.coverage import _probe_key

from tests.proof_fixtures import post_artifact_backed_source_observation
from tests.test_engagements_api import write_engagement


ENGAGEMENT_KEY = "2026-07-01-120000-blocked"
BASE = f"/engagements/{ENGAGEMENT_KEY}/assessment"


def _seed(client, isolate_settings) -> None:
    write_engagement(isolate_settings["engagements_dir"], key=ENGAGEMENT_KEY)
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200
    author = client.post(
        f"{BASE}/dispatches",
        json={
            "agent_id": "BLOCKED-AUTHOR",
            "agent_role": "vulnerability-analyst",
            "task": "record fixture findings",
        },
    )
    assert author.status_code == 201, author.text


def _finding_payload(slug, *, workflow_status="active", details=None, **overrides) -> dict:
    payload = {
        "slug": slug,
        "title": f"{slug} finding",
        "severity": "high",
        "workflow_status": workflow_status,
        "verification_status": "unreviewed",
        "defect_family": "access-control",
        "root_cause_key": f"rc-{slug}",
        "auth_context": "anonymous",
        "canonical_location": f"https://example.com/{slug}",
        "source_name": "vulnerability-analyst",
        "provenance": {"agent_id": "BLOCKED-AUTHOR"},
        "summary": "fixture finding",
        "evidence_ref": "findings.md",
        "details": details if details is not None else {"evidence": "e", "impact": "i"},
    }
    payload.update(overrides)
    return payload


def _create_finding(client, slug, **kwargs) -> dict:
    resp = client.post(f"{BASE}/findings", json=_finding_payload(slug, **kwargs))
    assert resp.status_code == 201, resp.text
    return resp.json()["finding"]


def _confirm_finding(client, slug: str) -> dict:
    dispatch = client.post(
        f"{BASE}/dispatches",
        json={
            "agent_id": f"VERIFY-{slug}",
            "agent_role": "code-vuln-verifier",
            "task": f"independently verify {slug}",
        },
    )
    assert dispatch.status_code == 201, dispatch.text
    run = client.post(
        f"{BASE}/assessment-runs",
        json={
            "run_uuid": f"verify-{slug}",
            "run_kind": "code",
            "producer_dispatch_agent_id": f"VERIFY-{slug}",
        },
    )
    assert run.status_code == 201, run.text
    receipt = post_artifact_backed_source_observation(
        client,
        f"{BASE}/proof-receipts",
        json={
            "run_id": run.json()["id"],
            "evidence_kind": "source_observation",
            "expected_result": "the finding survives independent review",
            "observed_result": "the finding was independently reproduced",
        },
    )
    assert receipt.status_code == 201, receipt.text
    completed = client.patch(
        f"{BASE}/assessment-runs/{run.json()['id']}",
        json={"status": "completed"},
    )
    assert completed.status_code == 200, completed.text
    verified = client.post(
        f"{BASE}/findings/{slug}/verify",
        json={
            "verification_status": "confirmed",
            "reason_text": "independently reproduced",
            "proof_receipt_ids": [receipt.json()["id"]],
        },
    )
    assert verified.status_code == 200, verified.text
    return verified.json()["finding"]


# ---------------------------------------------------------------------------
# 1) Shared verification-status vocabulary
# ---------------------------------------------------------------------------


def test_blocked_is_a_member_of_the_complete_verification_status_axis():
    assert VERIFICATION_STATUSES == frozenset(VerificationStatus)
    assert {status.value for status in VERIFICATION_STATUSES} == {
        "unreviewed",
        "confirmed",
        "downgraded",
        "pending_runtime_proof",
        "blocked",
        "false_positive",
        "disputed",
    }


# ---------------------------------------------------------------------------
# 2) verify-finding requires block_reason when status='blocked'
# ---------------------------------------------------------------------------


def test_verify_blocked_requires_block_reason(client, isolate_settings):
    _seed(client, isolate_settings)
    _create_finding(client, "VA-001")
    resp = client.post(
        f"{BASE}/findings/VA-001/verify",
        json={"verification_status": "blocked", "reason_text": "attempt could not start"},
    )
    assert resp.status_code == 400, resp.text
    assert "block_reason" in resp.json()["detail"]


def test_verify_blocked_with_block_reason_in_request_succeeds(client, isolate_settings):
    _seed(client, isolate_settings)
    _create_finding(client, "VA-001")
    resp = client.post(
        f"{BASE}/findings/VA-001/verify",
        json={
            "verification_status": "blocked",
            "reason_text": "no test account in the required group",
            "details": {
                "block_reason": "no test account provisioned",
                "unblock_requirements": {
                    "kind": "account",
                    "description": "member of finance-admins",
                    "requested_from": "client IT",
                },
            },
        },
    )
    assert resp.status_code == 200, resp.text
    finding = resp.json()["finding"]
    assert finding["verification_status"] == "blocked"


def test_verify_blocked_accepts_block_reason_already_on_finding(client, isolate_settings):
    _seed(client, isolate_settings)
    # block_reason recorded on the finding itself, not in the verify request.
    _create_finding(
        client, "VA-001",
        details={"evidence": "e", "impact": "i", "block_reason": "physical line unavailable"},
    )
    resp = client.post(
        f"{BASE}/findings/VA-001/verify",
        json={"verification_status": "blocked", "reason_text": "blocked for provisioning"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["finding"]["verification_status"] == "blocked"


def test_verify_blocked_rejects_oversized_block_reason(client, isolate_settings):
    _seed(client, isolate_settings)
    _create_finding(client, "VA-001")
    resp = client.post(
        f"{BASE}/findings/VA-001/verify",
        json={
            "verification_status": "blocked",
            "reason_text": "x",
            "details": {"block_reason": "z" * 501},
        },
    )
    assert resp.status_code == 400, resp.text
    assert "500" in resp.json()["detail"]


def test_create_finding_cannot_bypass_blocked_verification_gate(client, isolate_settings):
    _seed(client, isolate_settings)
    resp = client.post(
        f"{BASE}/findings",
        json=_finding_payload(
            "VA-010",
            verification_status="blocked",
            details={"evidence": "e", "impact": "i"},  # no block_reason
        ),
    )
    assert resp.status_code == 422, resp.text
    assert resp.json()["detail"][0]["loc"] == ["body", "verification_status"]


def test_verified_blocked_finding_with_reason_is_unreported(client, isolate_settings):
    _seed(client, isolate_settings)
    engagement_id = client.get(f"/engagements/{ENGAGEMENT_KEY}").json()["id"]
    _create_finding(client, "VA-011")
    resp = client.post(
        f"{BASE}/findings/VA-011/verify",
        json={
            "verification_status": "blocked",
            "reason_text": "no test account in the required group",
            "details": {"block_reason": "no test account provisioned"},
        },
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["finding"]["verification_status"] == "blocked"
    draft = {r["slug"] for r in state_manager.list_report_findings(engagement_id, mode="draft")}
    assert "VA-011" not in draft


# ---------------------------------------------------------------------------
# 3) report exclusion of blocked findings (draft AND final)
# ---------------------------------------------------------------------------


def test_blocked_finding_absent_from_both_report_modes(client, isolate_settings):
    _seed(client, isolate_settings)
    engagement = client.get(f"/engagements/{ENGAGEMENT_KEY}").json()
    engagement_id = engagement["id"]

    # A confirmed finding that DOES report.
    _create_finding(
        client, "VA-001",
        details={"evidence": "e", "impact": "i", "cvss_score": 7.5,
                 "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                     "steps_to_reproduce": ["a"], "remediation": "fix"},
    )
    _confirm_finding(client, "VA-001")
    # A blocked finding that must NOT report.
    _create_finding(client, "VA-002")
    assert client.post(
        f"{BASE}/findings/VA-002/verify",
        json={"verification_status": "blocked", "reason_text": "blocked",
              "details": {"block_reason": "missing credential"}},
    ).status_code == 200

    draft = {r["slug"] for r in state_manager.list_report_findings(engagement_id, mode="draft")}
    final = {r["slug"] for r in state_manager.list_report_findings(engagement_id, mode="final")}
    assert "VA-002" not in draft
    assert "VA-002" not in final
    assert "VA-001" in draft
    assert "VA-001" in final

    # A blocked finding must not raise a report-readiness verification blocker.
    readiness = state_manager.report_readiness(engagement_id)
    blocker_slugs = {b.get("slug") for b in readiness["blockers"]}
    assert "VA-002" not in blocker_slugs


def test_resume_brief_finding_summary_projects_block_reason(client, isolate_settings):
    # A blocked-for-provisioning finding is verified (leaves the unreviewed
    # queue) but held out of the report, so it renders in the brief as a bare
    # active/verified line. build_resume_brief must project block_reason so the
    # CLI can render "BLOCKED: ..." without the operator opening the finding.
    _seed(client, isolate_settings)
    _create_finding(client, "VA-030")
    assert client.post(
        f"{BASE}/findings/VA-030/verify",
        json={
            "verification_status": "blocked",
            "reason_text": "blocked for provisioning",
            "details": {"block_reason": "no finance-admin account provisioned"},
        },
    ).status_code == 200

    brief = client.get(f"{BASE}/resume-brief").json()
    verified = {row["slug"]: row for row in brief["findings"]["verified"]}
    assert "VA-030" in verified
    assert verified["VA-030"]["block_reason"] == "no finance-admin account provisioned"


def test_resume_brief_finding_summary_block_reason_empty_for_normal_finding(client, isolate_settings):
    _seed(client, isolate_settings)
    _create_finding(client, "VA-031")  # unreviewed, no block_reason
    brief = client.get(f"{BASE}/resume-brief").json()
    unreviewed = {row["slug"]: row for row in brief["findings"]["unreviewed"]}
    assert unreviewed["VA-031"]["block_reason"] == ""


# ---------------------------------------------------------------------------
# 4) command_runs.finding_id round-trip + FK validation
# ---------------------------------------------------------------------------


def _command_payload(**overrides) -> dict:
    payload = {
        "command": "curl https://example.com",
        "argv": ["curl", "https://example.com"],
        "tool_name": "curl",
        "agent_name": "operator",
        "phase": "exploit",
        "return_code": 0,
        "success": True,
        "started_at": "2026-07-01T12:00:00Z",
        "completed_at": "2026-07-01T12:00:01Z",
    }
    payload.update(overrides)
    return payload


def test_command_run_finding_id_round_trip(client, isolate_settings):
    _seed(client, isolate_settings)
    finding = _create_finding(client, "VA-001")
    finding_id = finding["id"]

    resp = client.post(f"{BASE}/command-runs", json=_command_payload(finding_id=finding_id))
    assert resp.status_code == 201, resp.text
    created = resp.json()
    assert created["finding_id"] == finding_id

    got = client.get(f"{BASE}/command-runs/{created['id']}").json()
    assert got["finding_id"] == finding_id


def test_command_run_unknown_finding_id_is_404(client, isolate_settings):
    _seed(client, isolate_settings)
    resp = client.post(f"{BASE}/command-runs", json=_command_payload(finding_id=999999))
    assert resp.status_code == 404, resp.text


def test_command_run_finding_id_defaults_null(client, isolate_settings):
    _seed(client, isolate_settings)
    created = client.post(f"{BASE}/command-runs", json=_command_payload()).json()
    assert created["finding_id"] is None


# ---------------------------------------------------------------------------
# 5) probe_runs.lens in _probe_key + record_probe_run
# ---------------------------------------------------------------------------


def test_probe_key_partitions_on_lens():
    common = dict(
        request_variant_id=None, service_id=None, coverage_item_id=None,
        auth_context="anonymous", input_slot="query", attack_family="sqli",
        payload_family="boolean", payload_value="1 OR 1=1", tool_name="sqlmap",
        target_host="example.com", target_path="/x", target_port=443,
    )
    _, key_a = _probe_key(**common, lens="")
    _, key_b = _probe_key(**common, lens="access-control-mindset")
    _, key_c = _probe_key(**common, lens="injection-mindset")
    assert key_a != key_b != key_c
    assert key_a != key_c


def test_probe_key_lens_empty_is_backward_compatible():
    # A lens-less probe (lens="" or omitted) MUST hash to the same key it had
    # before the lens field existed, so dedup survives the migration: a probe
    # recorded pre-lens and re-run post-lens with lens="" must collide on
    # UNIQUE(probe_key), not insert a duplicate. Guards against unconditionally
    # adding "lens" to the hashed dict (which would change the digest even for
    # lens="", breaking dedup for every row written before the migration).
    common = dict(
        request_variant_id=None, service_id=None, coverage_item_id=None,
        auth_context="anonymous", input_slot="query", attack_family="sqli",
        payload_family="boolean", payload_value="1 OR 1=1", tool_name="sqlmap",
        target_host="example.com", target_path="/x", target_port=443,
    )
    _, key_default = _probe_key(**common)
    _, key_empty = _probe_key(**common, lens="")
    assert key_default == key_empty
    # Pin the exact pre-migration digest (dict with NO lens field at all).
    legacy = hashlib.sha256(
        json.dumps(
            {
                "request_variant_id": None, "service_id": None,
                "coverage_item_id": None, "auth_context": "anonymous",
                "input_slot": "query", "attack_family": "sqli",
                "payload_family": "boolean",
                "payload_hash": hashlib.sha256(b"1 OR 1=1").hexdigest(),
                "tool_name": "sqlmap", "target_host": "example.com",
                "target_path": "/x", "target_port": 443,
            },
            sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    assert key_empty == legacy


def _probe_payload(**overrides) -> dict:
    payload = {
        "attack_family": "sqli",
        "tool_name": "sqlmap",
        "input_slot": "query",
        "payload_value": "1 OR 1=1",
        "target_host": "example.com",
        "target_path": "/x",
        "target_port": 443,
    }
    payload.update(overrides)
    return payload


def test_record_probe_run_same_target_different_lens_is_two_rows(client, isolate_settings):
    _seed(client, isolate_settings)
    r1 = client.post(f"{BASE}/probe-runs", json=_probe_payload(lens="mindset-A"))
    r2 = client.post(f"{BASE}/probe-runs", json=_probe_payload(lens="mindset-B"))
    assert r1.status_code == 201 and r2.status_code == 201, (r1.text, r2.text)
    assert r1.json()["id"] != r2.json()["id"]
    assert r1.json()["lens"] == "mindset-A"
    assert r2.json()["lens"] == "mindset-B"
    lenses = {row["lens"] for row in client.get(f"{BASE}/probe-runs").json()}
    assert {"mindset-A", "mindset-B"} <= lenses


def test_record_probe_run_same_lens_dedupes(client, isolate_settings):
    _seed(client, isolate_settings)
    r1 = client.post(f"{BASE}/probe-runs", json=_probe_payload(lens="mindset-A"))
    r2 = client.post(f"{BASE}/probe-runs", json=_probe_payload(lens="mindset-A"))
    assert r1.json()["id"] == r2.json()["id"]  # same probe_key → upsert


# ---------------------------------------------------------------------------
# 6) record-attempt route: non-covering status + lens + finding_id
# ---------------------------------------------------------------------------


def test_record_attempt_non_covering_status_with_lens_and_finding(client, isolate_settings):
    _seed(client, isolate_settings)
    finding = _create_finding(client, "VA-001")
    finding_id = finding["id"]
    for result_status in ("attempted", "blocked", "no-signal"):
        resp = client.post(
            f"{BASE}/probe-runs",
            json=_probe_payload(
                result_status=result_status,
                lens=f"lens-{result_status}",
                finding_id=finding_id,
                target_path=f"/{result_status}",
            ),
        )
        assert resp.status_code == 201, resp.text
        row = resp.json()
        assert row["result_status"] == result_status
        assert row["lens"] == f"lens-{result_status}"
        assert row["finding_id"] == finding_id


def test_record_attempt_finding_backfills_on_rerun(client, isolate_settings):
    _seed(client, isolate_settings)
    finding = _create_finding(client, "VA-001")
    first = client.post(f"{BASE}/probe-runs", json=_probe_payload(lens="L")).json()
    assert first["finding_id"] is None
    # Same probe_key (same lens/target/payload), now naming a finding: backfill.
    second = client.post(
        f"{BASE}/probe-runs", json=_probe_payload(lens="L", finding_id=finding["id"])
    ).json()
    assert second["id"] == first["id"]
    assert second["finding_id"] == finding["id"]


def test_record_attempt_unknown_finding_id_is_404(client, isolate_settings):
    _seed(client, isolate_settings)
    resp = client.post(f"{BASE}/probe-runs", json=_probe_payload(lens="L", finding_id=999999))
    assert resp.status_code == 404, resp.text


# ---------------------------------------------------------------------------
# migrations on a pre-existing DB (additive ALTER guards)
# ---------------------------------------------------------------------------


def _legacy_engagements(connection) -> None:
    connection.execute(
        """
        CREATE TABLE engagements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT NOT NULL UNIQUE,
            target TEXT NOT NULL,
            status TEXT NOT NULL,
            engagement_root TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    connection.execute(
        "INSERT INTO engagements (id, key, target, status, engagement_root) "
        "VALUES (1, 'legacy', 'https://example.com', 'in_progress', '/tmp/legacy')"
    )


def test_command_runs_finding_id_migration_on_preexisting_db(isolate_settings):
    db_path = db_module.database_path()
    with sqlite3.connect(str(db_path)) as connection:
        _legacy_engagements(connection)
        # Realistic pre-finding_id command_runs shape (no finding_id column; the
        # preview/suppression/notes columns must be present for the FTS rebuild
        # in init_db to succeed).
        connection.execute(
            """
            CREATE TABLE assessment_command_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                run_uuid TEXT NOT NULL UNIQUE,
                command TEXT NOT NULL,
                argv_json TEXT NOT NULL DEFAULT '[]',
                tool_name TEXT NOT NULL,
                route TEXT NOT NULL DEFAULT '',
                agent_name TEXT NOT NULL,
                phase TEXT NOT NULL,
                return_code INTEGER,
                timed_out INTEGER NOT NULL DEFAULT 0,
                success INTEGER NOT NULL DEFAULT 0,
                started_at TEXT NOT NULL,
                completed_at TEXT NOT NULL,
                duration_ms INTEGER NOT NULL DEFAULT 0,
                command_hash TEXT NOT NULL,
                stdout_sha256 TEXT NOT NULL DEFAULT '',
                stderr_sha256 TEXT NOT NULL DEFAULT '',
                stdout_preview TEXT NOT NULL DEFAULT '',
                stderr_preview TEXT NOT NULL DEFAULT '',
                output_retention_status TEXT NOT NULL DEFAULT 'retained',
                stdout_suppression_reason TEXT NOT NULL DEFAULT '',
                stderr_suppression_reason TEXT NOT NULL DEFAULT '',
                stdout_artifact_ref TEXT NOT NULL DEFAULT '',
                stderr_artifact_ref TEXT NOT NULL DEFAULT '',
                stdout_bytes INTEGER NOT NULL DEFAULT 0,
                stderr_bytes INTEGER NOT NULL DEFAULT 0,
                indexed_for_embeddings_at TEXT,
                notes TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE
            )
            """
        )
        connection.execute(
            "INSERT INTO assessment_command_runs "
            "(id, engagement_id, run_uuid, command, tool_name, agent_name, phase, "
            "started_at, completed_at, command_hash, stdout_preview) "
            "VALUES (1, 1, 'legacy-run', 'legacy scan', 'nmap', 'a', 'recon', "
            "'2026-07-01T12:00:00Z', '2026-07-01T12:00:01Z', 'h', 'legacy output')"
        )
        connection.commit()

    db_module.init_db()

    with db_module.get_connection() as connection:
        cols = db_module._table_columns(connection, "assessment_command_runs")
        assert "finding_id" in cols
        row = connection.execute(
            "SELECT command, finding_id FROM assessment_command_runs WHERE id = 1"
        ).fetchone()
        assert row["command"] == "legacy scan"  # legacy row preserved
        assert row["finding_id"] is None


def test_probe_runs_lens_and_finding_id_migration_on_preexisting_db(isolate_settings):
    db_path = db_module.database_path()
    with sqlite3.connect(str(db_path)) as connection:
        _legacy_engagements(connection)
        # Pre-lens/pre-finding_id probe_runs shape.
        connection.execute(
            """
            CREATE TABLE assessment_probe_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                request_variant_id INTEGER,
                service_id INTEGER,
                coverage_item_id INTEGER,
                auth_context TEXT NOT NULL DEFAULT 'anonymous',
                input_slot TEXT NOT NULL DEFAULT 'unknown',
                attack_family TEXT NOT NULL,
                payload_family TEXT NOT NULL DEFAULT '',
                payload_value_hash TEXT NOT NULL DEFAULT '',
                probe_key TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                agent_name TEXT NOT NULL DEFAULT '',
                result_status TEXT NOT NULL DEFAULT 'tested',
                observed_http_status INTEGER,
                signal_type TEXT NOT NULL DEFAULT '',
                evidence_ref TEXT NOT NULL DEFAULT '',
                notes TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(engagement_id, probe_key),
                FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE
            )
            """
        )
        connection.execute(
            "INSERT INTO assessment_probe_runs "
            "(id, engagement_id, attack_family, probe_key, tool_name) "
            "VALUES (1, 1, 'sqli', 'legacy-key', 'sqlmap')"
        )
        connection.commit()

    db_module.init_db()

    with db_module.get_connection() as connection:
        cols = db_module._table_columns(connection, "assessment_probe_runs")
        assert "lens" in cols
        assert "finding_id" in cols
        row = connection.execute(
            "SELECT attack_family, lens, finding_id "
            "FROM assessment_probe_runs WHERE id = 1"
        ).fetchone()
        assert row["attack_family"] == "sqli"  # legacy row preserved
        assert row["lens"] == ""  # NOT NULL DEFAULT '' backfill
        assert row["finding_id"] is None
