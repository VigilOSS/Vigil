from __future__ import annotations

import json
import sqlite3
from pathlib import Path


def write_engagement(engagements_dir: Path, key: str = "2026-03-30-120000-example") -> Path:
    engagement_dir = engagements_dir / key
    (engagement_dir / "sessions" / "session-a" / "proposals").mkdir(parents=True, exist_ok=True)
    (engagement_dir / "engagement.json").write_text(
        json.dumps(
            {
                "key": key,
                "target": "https://example.com",
                "hostname": "example.com",
                "created_at": "2026-03-30T12:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    (engagement_dir / "scope.json").write_text(
        json.dumps(
            {
                "hostname": "example.com",
                "scope_mode": "host_only",
                "scope_hosts": ["example.com"],
                "scope": ["example.com"],
                "out_of_scope_hosts": [],
                "exploit_policy": "selected",
                "exploit_review_state": "approved",
                "approved_findings": ["FINDING-VA-001"],
                "status": "in_progress",
                "current_phase": "exploit",
            }
        ),
        encoding="utf-8",
    )
    (engagement_dir / "log.md").write_text("# Engagement Log\n", encoding="utf-8")
    (engagement_dir / "findings.md").write_text("# Findings\n", encoding="utf-8")
    (engagement_dir / "sessions" / "index.json").write_text(
        json.dumps(
            [
                {
                    "session_id": "session-a",
                    "status": "active",
                    "merge_state": "pending",
                    "assigned_findings": ["FINDING-VA-001"],
                }
            ]
        ),
        encoding="utf-8",
    )
    return engagement_dir


def test_list_engagements_discovers_filesystem_engagements(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"])

    response = client.get("/engagements")
    assert response.status_code == 200
    payload = response.json()
    assert len(payload) == 1
    assert payload[0]["key"] == "2026-03-30-120000-example"
    assert payload[0]["current_phase"] == "exploit"
    assert payload[0]["session_count"] == 1


def test_engagement_artifacts_and_sessions_are_scoped_by_engagement_key(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"])

    artifacts = client.get("/engagements/2026-03-30-120000-example/artifacts")
    assert artifacts.status_code == 200
    artifact_names = {artifact["name"] for artifact in artifacts.json() if artifact["exists"]}
    assert {"scope.json", "log.md", "findings.md", "engagement.json"} <= artifact_names

    sessions = client.get("/engagements/2026-03-30-120000-example/sessions")
    assert sessions.status_code == 200
    payload = sessions.json()
    assert payload[0]["session_id"] == "session-a"
    assert payload[0]["assigned_findings"] == ["FINDING-VA-001"]


def test_engagement_event_and_assessment_routes_use_engagement_key(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"])

    create_event = client.post(
        "/engagements/2026-03-30-120000-example/events",
        json={
            "event_type": "task.started",
            "phase": "exploit",
            "task_name": "exploit-developer",
            "agent_name": "exploit-developer",
            "summary": "Exploit task started",
        },
    )
    assert create_event.status_code == 201

    create_surface = client.post(
        "/engagements/2026-03-30-120000-example/assessment/surfaces",
        json={
            "surface_type": "object_reference",
            "target_descriptor": "https://example.com/orders/7",
            "source_name": "source-analyzer",
            "rationale": "Observed direct object path",
            "evidence_ref": "log.md",
            "status": "covered",
        },
    )
    assert create_surface.status_code == 201

    invalid_surface = client.post(
        "/engagements/2026-03-30-120000-example/assessment/surfaces",
        json={
            "surface_type": "web_application",
            "target_descriptor": "https://example.com/",
            "source_name": "source-analyzer",
            "status": "covered",
        },
    )
    assert invalid_surface.status_code == 422

    create_finding = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings",
        json={
            "slug": "FINDING-VA-001",
            "title": "IDOR in orders",
            "severity": "high",
            "workflow_status": "active",
            "verification_state": "verified",
            "verification_disposition": "confirmed",
            "defect_family": "idor",
            "root_cause_key": "orders-idor",
            "auth_context": "anonymous",
            "canonical_location": "https://example.com/orders/7",
            "summary": "Order data can be accessed cross-tenant.",
            "evidence_ref": "findings.md",
            "notes": "Confirmed with adjacent object ids.",
            "source_name": "exploit-developer",
            "details": {
                "evidence": "GET /orders/7 returns order for user B when authenticated as user A",
                "impact": "cross-tenant access",
                "owasp_category": "A01:2021 Broken Access Control",
                "cwe_id": "CWE-639",
                "request_method": "GET",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
                "cvss_score": 6.5,
                "remediation": "Enforce server-side ownership checks on order retrieval",
                "steps_to_reproduce": [
                    "Authenticate as user A",
                    "GET /orders/7 (belongs to user B)",
                    "Observe full order data returned"
                ]
            },
            "provenance": {"agent_name": "exploit-developer"},
            "links": [],
        },
    )
    assert create_finding.status_code == 201
    assert create_finding.json()["finding"]["slug"] == "FINDING-VA-001"

    findings = client.get("/engagements/2026-03-30-120000-example/assessment/findings")
    assert findings.status_code == 200
    assert findings.json()[0]["slug"] == "FINDING-VA-001"

    summary = client.get("/engagements/2026-03-30-120000-example/assessment/summary")
    assert summary.status_code == 200
    assert summary.json()["finding_count"] == 1


def test_coverage_patch_normalizes_tested_to_covered_and_refreshes_service_status(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"])

    ingest = client.post(
        "/engagements/2026-03-30-120000-example/assessment/request-observations",
        json={
            "url": "https://example.com/search?q=test",
            "query_schema": {"q": {"type": "string"}},
            "discovery_source": "recon",
        },
    )
    assert ingest.status_code == 201

    coverage_items = client.get("/engagements/2026-03-30-120000-example/assessment/coverage-items")
    assert coverage_items.status_code == 200
    service_coverage = next(item for item in coverage_items.json() if item["input_slot"] == "service")

    patch = client.patch(
        f"/engagements/2026-03-30-120000-example/assessment/coverage-items/{service_coverage['id']}",
        json={"status": "tested", "notes": "Validated service reachability"},
    )
    assert patch.status_code == 200
    assert patch.json()["status"] == "covered"

    services = client.get("/engagements/2026-03-30-120000-example/assessment/services")
    assert services.status_code == 200
    assert services.json()[0]["coverage_status"] == "covered"

    summary = client.get("/engagements/2026-03-30-120000-example/assessment/summary")
    assert summary.status_code == 200
    assert summary.json()["service_coverage_gaps"] == []


def test_findings_verify_updates_existing_finding_and_records_transition(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"])

    created = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings",
        json={
            "slug": "FINDING-VA-001",
            "title": "IDOR in orders",
            "severity": "medium",
            "workflow_status": "draft",
            "verification_state": "unreviewed",
            "verification_disposition": "none",
            "defect_family": "idor",
            "root_cause_key": "orders-idor",
            "auth_context": "anonymous",
            "canonical_location": "https://example.com/orders/7",
            "summary": "Order data can be accessed cross-tenant.",
            "evidence_ref": "findings.md",
            "notes": "Initial triage.",
            "source_name": "vulnerability-analyst",
            "details": {
                "evidence": "Initial request/response pair",
                "impact": "Potential cross-tenant access",
            },
            "provenance": {"agent_name": "vulnerability-analyst"},
            "links": [],
        },
    )
    assert created.status_code == 201

    verified = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings/FINDING-VA-001/verify",
        json={
            "disposition": "confirmed",
            "reason_code": "reproduced",
            "reason_text": "Adjacent object identifiers reliably return cross-tenant orders.",
            "notes": "Verified with adjacent object identifiers.",
            "source_name": "code-vuln-verifier",
            "evidence_ref": "findings.md",
            "artifact_ref": "findings.md",
            "details": {"impact": "Confirmed cross-tenant order read"},
            "provenance": {"verified_by": "code-vuln-verifier"},
        },
    )
    assert verified.status_code == 200
    payload = verified.json()
    assert payload["finding"]["slug"] == "FINDING-VA-001"
    assert payload["finding"]["workflow_status"] == "draft"
    assert payload["finding"]["verification_state"] == "verified"
    assert payload["finding"]["verification_disposition"] == "confirmed"
    assert payload["finding"]["severity"] == "medium"
    assert payload["transition"]["action"] == "verified_confirmed"

    transitions = client.get(
        "/engagements/2026-03-30-120000-example/assessment/findings/FINDING-VA-001/transitions"
    )
    assert transitions.status_code == 200
    assert [item["action"] for item in transitions.json()] == ["verified_confirmed", "created"]

    findings = client.get("/engagements/2026-03-30-120000-example/assessment/findings")
    assert findings.status_code == 200
    finding = next(item for item in findings.json() if item["slug"] == "FINDING-VA-001")
    assert "Verified with adjacent object identifiers." in finding["notes"]
    assert finding["workflow_status"] == "draft"
    assert finding["verification_state"] == "verified"
    assert finding["verification_disposition"] == "confirmed"
    assert json.loads(finding["details_json"])["impact"] == "Confirmed cross-tenant order read"
    assert json.loads(finding["provenance_json"])["verified_by"] == "code-vuln-verifier"


def test_legacy_finding_status_field_is_rejected(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"])

    response = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings",
        json={
            "title": "Legacy status payload",
            "severity": "medium",
            "status": "confirmed",
            "defect_family": "idor",
            "root_cause_key": "legacy-status",
            "auth_context": "anonymous",
            "canonical_location": "https://example.com/orders/7",
            "summary": "Old clients should fail hard.",
            "evidence_ref": "findings.md",
            "notes": "This should be rejected.",
            "details": {"evidence": "legacy payload", "impact": "validation drift"},
        },
    )
    assert response.status_code == 422


def test_findings_patch_can_revive_false_positive_and_lower_severity(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"])

    created = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings",
        json={
            "slug": "FINDING-CH-009",
            "title": "Parser length overflow",
            "severity": "high",
            "workflow_status": "false_positive",
            "verification_state": "verified",
            "verification_disposition": "false_positive",
            "defect_family": "integer-overflow",
            "root_cause_key": "parser-length-overflow",
            "auth_context": "anonymous",
            "canonical_location": "file:src/parser.c:91",
            "summary": "Suppressed after verifier review.",
            "evidence_ref": "tools/analysis-state/verifier.json",
            "notes": "Killed during verification.",
            "source_name": "code-vuln-verifier",
            "details": {
                "kill_check": 2,
                "kill_reason": "validate_length() enforces an 8KB upper bound before arithmetic.",
                "evidence": "validate_length() rejects oversized input.",
                "impact": "Potential overflow avoided by guard.",
            },
            "provenance": {"verified_by": "code-vuln-verifier"},
            "links": [],
        },
    )
    assert created.status_code == 201

    revived = client.patch(
        "/engagements/2026-03-30-120000-example/assessment/findings/FINDING-CH-009",
        json={
            "workflow_status": "active",
            "severity": "low",
            "notes": "Operator reinstated after manual review.",
            "reason_code": "manual-override",
            "reason_text": "Manual review found the path is live with reduced impact.",
            "provenance": {"reviewed_by": "operator"},
        },
    )
    assert revived.status_code == 200
    assert revived.json()["finding"]["workflow_status"] == "active"
    assert revived.json()["finding"]["verification_state"] == "unreviewed"
    assert revived.json()["finding"]["verification_disposition"] == "none"
    assert revived.json()["finding"]["severity"] == "low"
    assert revived.json()["transition"]["action"] == "operator_override"


def test_findings_patch_rejects_direct_verification_bypass(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"])

    created = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings",
        json={
            "slug": "FINDING-CH-010",
            "title": "Direct patch bypass",
            "severity": "medium",
            "workflow_status": "active",
            "verification_state": "unreviewed",
            "verification_disposition": "none",
            "defect_family": "idor",
            "root_cause_key": "direct-patch-bypass",
            "auth_context": "anonymous",
            "canonical_location": "https://example.com/items/7",
            "summary": "Patch should not be able to persist verifier outcomes.",
            "evidence_ref": "findings.md",
            "notes": "Initial triage.",
            "source_name": "vulnerability-analyst",
            "details": {
                "evidence": "Initial request/response pair",
                "impact": "Potential unauthorized access",
            },
            "provenance": {"agent_name": "vulnerability-analyst"},
            "links": [],
        },
    )
    assert created.status_code == 201

    patched = client.patch(
        "/engagements/2026-03-30-120000-example/assessment/findings/FINDING-CH-010",
        json={
            "workflow_status": "false_positive",
            "reason_text": "Bypass verifier checks",
        },
    )
    assert patched.status_code == 400
    assert "must use POST /findings/{slug}/verify" in patched.json()["detail"]


def test_false_positive_findings_are_suppressed_but_semantically_sticky(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"])

    created = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings",
        json={
            "slug": "FINDING-CH-001",
            "title": "Header length overflow in parser",
            "severity": "high",
            "workflow_status": "active",
            "verification_state": "verified",
            "verification_disposition": "confirmed",
            "defect_family": "integer-overflow",
            "root_cause_key": "header-length-overflow",
            "auth_context": "anonymous",
            "canonical_location": "file:src/parser.c:128",
            "summary": "Header length appears to overflow before allocation.",
            "evidence_ref": "tools/analysis-state/findings.json",
            "notes": "Initial hunter report.",
            "source_name": "code-vuln-hunter",
            "details": {
                "evidence": "len * 4 appears attacker-controlled",
                "impact": "Potential heap corruption",
            },
            "provenance": {"agent_name": "code-vuln-hunter"},
            "links": [],
        },
    )
    assert created.status_code == 201

    killed = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings/FINDING-CH-001/verify",
        json={
            "disposition": "false_positive",
            "reason_code": "check-2-guard",
            "reason_text": "validate_header_length() bounds header length to 8192 bytes on all paths.",
            "artifact_ref": "tools/analysis-state/verifier.json",
            "source_name": "code-vuln-verifier",
            "notes": "Check 2 KILL: upstream guard bounds header length to 8192 bytes.",
            "details": {
                "kill_check": 2,
                "kill_reason": "upstream guard bounds header length to 8192 bytes.",
                "evidence": "validate_header_length() rejects oversized input before arithmetic."
            },
            "provenance": {"verified_by": "code-vuln-verifier"},
        },
    )
    assert killed.status_code == 200
    assert killed.json()["finding"]["workflow_status"] == "false_positive"
    assert killed.json()["finding"]["verification_state"] == "verified"
    assert killed.json()["finding"]["verification_disposition"] == "false_positive"
    assert killed.json()["transition"]["action"] == "verified_false_positive"

    summary = client.get("/engagements/2026-03-30-120000-example/assessment/summary")
    assert summary.status_code == 200
    assert summary.json()["finding_count"] == 0
    assert summary.json()["finding_workflow_statuses"]["false_positive"] == 1
    assert summary.json()["finding_verification_dispositions"]["false_positive"] == 1
    assert summary.json()["top_findings"] == []

    report_findings = client.get("/engagements/2026-03-30-120000-example/assessment/report-findings")
    assert report_findings.status_code == 200
    assert report_findings.json() == []

    rediscovered = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings",
        json={
            "title": "Header length overflow in parser",
            "severity": "critical",
            "workflow_status": "active",
            "verification_state": "unreviewed",
            "verification_disposition": "none",
            "defect_family": "integer-overflow",
            "root_cause_key": "header-length-overflow",
            "auth_context": "anonymous",
            "canonical_location": "file:src/parser.c:128",
            "summary": "Rediscovery attempt from later analysis pass.",
            "evidence_ref": "tools/analysis-state/rediscovery.json",
            "notes": "Re-raised by later LLM pass.",
            "source_name": "code-vuln-hunter",
            "details": {
                "impact": "Potential heap corruption",
            },
            "provenance": {"agent_name": "code-vuln-hunter"},
            "links": [],
        },
    )
    assert rediscovered.status_code == 201
    assert rediscovered.json()["finding"]["slug"] == "FINDING-CH-001"
    assert rediscovered.json()["finding"]["workflow_status"] == "false_positive"
    assert rediscovered.json()["finding"]["verification_disposition"] == "false_positive"

    findings = client.get("/engagements/2026-03-30-120000-example/assessment/findings")
    assert findings.status_code == 200
    payload = findings.json()
    assert len(payload) == 1
    assert payload[0]["workflow_status"] == "false_positive"
    assert "Re-raised by later LLM pass." in payload[0]["notes"]
    assert json.loads(payload[0]["details_json"])["kill_check"] == 2
    assert json.loads(payload[0]["details_json"])["kill_reason"] == "upstream guard bounds header length to 8192 bytes."


def test_false_positive_title_fallback_does_not_suppress_distinct_finding(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"])

    original = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings",
        json={
            "slug": "FINDING-CH-020",
            "title": "Shared parser bug title",
            "severity": "medium",
            "workflow_status": "false_positive",
            "verification_state": "verified",
            "verification_disposition": "false_positive",
            "defect_family": "integer-overflow",
            "root_cause_key": "overflow-a",
            "auth_context": "anonymous",
            "canonical_location": "file:src/parser.c:128",
            "summary": "Suppressed integer overflow hypothesis.",
            "evidence_ref": "tools/analysis-state/a.json",
            "notes": "Verifier killed the original hypothesis.",
            "source_name": "code-vuln-verifier",
            "details": {
                "kill_check": 2,
                "kill_reason": "size guard blocks the arithmetic path.",
                "evidence": "validate_length() blocks the original path.",
                "impact": "No live issue on this path.",
            },
            "provenance": {"verified_by": "code-vuln-verifier"},
            "links": [],
        },
    )
    assert original.status_code == 201

    distinct = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings",
        json={
            "title": "Shared parser bug title",
            "severity": "high",
            "workflow_status": "active",
            "verification_state": "verified",
            "verification_disposition": "confirmed",
            "defect_family": "buffer-overflow",
            "root_cause_key": "overflow-b",
            "auth_context": "anonymous",
            "canonical_location": "file:src/parser.c:128",
            "summary": "Different defect family at the same location.",
            "evidence_ref": "tools/analysis-state/b.json",
            "notes": "Newly verified buffer overwrite path.",
            "source_name": "code-vuln-hunter",
            "details": {
                "evidence": "memcpy() uses unchecked attacker length.",
                "impact": "Heap corruption",
            },
            "provenance": {"agent_name": "code-vuln-hunter"},
            "links": [],
        },
    )
    assert distinct.status_code == 201
    assert distinct.json()["finding"]["slug"] != "FINDING-CH-020"
    assert distinct.json()["finding"]["workflow_status"] == "active"
    assert distinct.json()["finding"]["verification_disposition"] == "confirmed"

    findings = client.get("/engagements/2026-03-30-120000-example/assessment/findings")
    assert findings.status_code == 200
    payload = findings.json()
    assert len(payload) == 2
    assert {item["workflow_status"] for item in payload} == {"false_positive", "active"}


def test_merge_into_false_positive_target_is_rejected(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"])

    source = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings",
        json={
            "slug": "FINDING-CH-030",
            "title": "Live parser issue",
            "severity": "high",
            "workflow_status": "active",
            "verification_state": "verified",
            "verification_disposition": "confirmed",
            "defect_family": "buffer-overflow",
            "root_cause_key": "live-parser-issue",
            "auth_context": "anonymous",
            "canonical_location": "file:src/parser.c:211",
            "summary": "Live finding.",
            "evidence_ref": "tools/analysis-state/live.json",
            "notes": "Confirmed by hunter.",
            "source_name": "code-vuln-hunter",
            "details": {"evidence": "Unchecked copy", "impact": "Heap corruption"},
            "provenance": {"agent_name": "code-vuln-hunter"},
            "links": [],
        },
    )
    assert source.status_code == 201

    target = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings",
        json={
            "slug": "FINDING-CH-031",
            "title": "Suppressed parser issue",
            "severity": "medium",
            "workflow_status": "false_positive",
            "verification_state": "verified",
            "verification_disposition": "false_positive",
            "defect_family": "integer-overflow",
            "root_cause_key": "suppressed-parser-issue",
            "auth_context": "anonymous",
            "canonical_location": "file:src/parser.c:333",
            "summary": "Suppressed by verifier.",
            "evidence_ref": "tools/analysis-state/suppressed.json",
            "notes": "Killed during verification.",
            "source_name": "code-vuln-verifier",
            "details": {
                "kill_check": 5,
                "kill_reason": "Build flag disables the path in production.",
                "evidence": "Code is behind a debug-only build flag.",
                "impact": "Not reachable in production.",
            },
            "provenance": {"verified_by": "code-vuln-verifier"},
            "links": [],
        },
    )
    assert target.status_code == 201

    merge = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings/merge",
        json={
            "source_slug": "FINDING-CH-030",
            "target_slug": "FINDING-CH-031",
            "reason": "Attempted merge into suppressed target.",
            "source_name": "operator",
        },
    )
    assert merge.status_code == 400
    assert "false_positive target" in merge.json()["detail"]


def test_findings_verify_downgrade_records_previous_severity_transition(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"])

    created = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings",
        json={
            "slug": "FINDING-CH-040",
            "title": "Privilege escalation via export endpoint",
            "severity": "critical",
            "workflow_status": "active",
            "verification_state": "unreviewed",
            "verification_disposition": "none",
            "defect_family": "access-control",
            "root_cause_key": "export-privesc",
            "auth_context": "user",
            "canonical_location": "https://example.com/api/export",
            "summary": "Privilege escalation path needs verification.",
            "evidence_ref": "tools/analysis-state/export.json",
            "notes": "Initial hunt output.",
            "source_name": "vulnerability-analyst",
            "details": {
                "evidence": "Role claim appears attacker-controlled.",
                "impact": "Potential admin export access.",
            },
            "provenance": {"agent_name": "vulnerability-analyst"},
            "links": [],
        },
    )
    assert created.status_code == 201

    verified = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings/FINDING-CH-040/verify",
        json={
            "disposition": "downgraded",
            "new_severity": "high",
            "reason_code": "limited-scope",
            "reason_text": "The export bug is real but constrained to project-scoped data.",
            "artifact_ref": "tools/analysis-state/code-verification/FINDING-CH-040.json",
            "evidence_ref": "tools/analysis-state/code-verification/FINDING-CH-040.json",
            "notes": "Severity reduced after tracing authorization boundaries.",
            "source_name": "code-vuln-verifier",
            "details": {
                "evidence": "Project scoping check limits the blast radius.",
                "impact": "Unauthorized project export, not full admin compromise.",
            },
            "provenance": {"verified_by": "code-vuln-verifier"},
        },
    )
    assert verified.status_code == 200
    payload = verified.json()
    assert payload["finding"]["severity"] == "high"
    assert payload["finding"]["workflow_status"] == "active"
    assert payload["finding"]["verification_state"] == "verified"
    assert payload["finding"]["verification_disposition"] == "downgraded"
    assert payload["transition"]["action"] == "verified_downgraded"

    transitions = client.get(
        "/engagements/2026-03-30-120000-example/assessment/findings/FINDING-CH-040/transitions"
    )
    assert transitions.status_code == 200
    latest = transitions.json()[0]
    assert latest["from_severity"] == "critical"
    assert latest["to_severity"] == "high"
    assert json.loads(latest["metadata_json"])["previous_severity"] == "critical"


def test_findings_verify_disputed_keeps_finding_live(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"])

    created = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings",
        json={
            "slug": "FINDING-CH-041",
            "title": "Ambiguous parser state confusion",
            "severity": "medium",
            "workflow_status": "active",
            "verification_state": "unreviewed",
            "verification_disposition": "none",
            "defect_family": "state-confusion",
            "root_cause_key": "parser-state-confusion",
            "auth_context": "anonymous",
            "canonical_location": "file:src/parser.c:411",
            "summary": "Verifier could not conclusively settle exploitability.",
            "evidence_ref": "tools/analysis-state/parser-state.json",
            "notes": "Needs further operator review.",
            "source_name": "code-vuln-hunter",
            "details": {
                "evidence": "State machine enters the suspicious branch with malformed input.",
                "impact": "Potential parse confusion with unclear reachability.",
            },
            "provenance": {"agent_name": "code-vuln-hunter"},
            "links": [],
        },
    )
    assert created.status_code == 201

    disputed = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings/FINDING-CH-041/verify",
        json={
            "disposition": "disputed",
            "reason_code": "conflicting-evidence",
            "reason_text": "Reachability differs between the static trace and runtime evidence.",
            "artifact_ref": "tools/analysis-state/code-verification/FINDING-CH-041.json",
            "notes": "Escalated for operator review.",
            "source_name": "code-vuln-verifier",
            "details": {
                "evidence": "Static path exists, but runtime repro did not reach the sink.",
                "impact": "Exploitability remains disputed.",
            },
            "provenance": {"verified_by": "code-vuln-verifier"},
        },
    )
    assert disputed.status_code == 200
    payload = disputed.json()
    assert payload["finding"]["workflow_status"] == "active"
    assert payload["finding"]["verification_state"] == "disputed"
    assert payload["finding"]["verification_disposition"] == "none"
    assert payload["transition"]["action"] == "verification_disputed"

    report_findings = client.get("/engagements/2026-03-30-120000-example/assessment/report-findings")
    assert report_findings.status_code == 200
    assert all(item["slug"] != "FINDING-CH-041" for item in report_findings.json())


def test_findings_verify_rejects_merged_records(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"])

    source = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings",
        json={
            "slug": "FINDING-CH-050",
            "title": "Merged source",
            "severity": "medium",
            "workflow_status": "active",
            "verification_state": "verified",
            "verification_disposition": "confirmed",
            "defect_family": "idor",
            "root_cause_key": "merged-source",
            "auth_context": "anonymous",
            "canonical_location": "https://example.com/source",
            "summary": "Source finding before merge.",
            "evidence_ref": "findings.md",
            "notes": "Created for merge test.",
            "source_name": "vulnerability-analyst",
            "details": {"evidence": "source evidence", "impact": "source impact"},
            "provenance": {"agent_name": "vulnerability-analyst"},
            "links": [],
        },
    )
    assert source.status_code == 201

    target = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings",
        json={
            "slug": "FINDING-CH-051",
            "title": "Merge target",
            "severity": "medium",
            "workflow_status": "active",
            "verification_state": "verified",
            "verification_disposition": "confirmed",
            "defect_family": "idor",
            "root_cause_key": "merge-target",
            "auth_context": "anonymous",
            "canonical_location": "https://example.com/target",
            "summary": "Target finding before merge.",
            "evidence_ref": "findings.md",
            "notes": "Created for merge test.",
            "source_name": "vulnerability-analyst",
            "details": {"evidence": "target evidence", "impact": "target impact"},
            "provenance": {"agent_name": "vulnerability-analyst"},
            "links": [],
        },
    )
    assert target.status_code == 201

    merge = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings/merge",
        json={
            "source_slug": "FINDING-CH-050",
            "target_slug": "FINDING-CH-051",
            "reason": "Merged duplicate.",
            "source_name": "operator",
        },
    )
    assert merge.status_code == 200

    verify = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings/FINDING-CH-050/verify",
        json={
            "disposition": "confirmed",
            "reason_text": "Should not revive merged finding.",
            "source_name": "code-vuln-verifier",
            "details": {"evidence": "n/a", "impact": "n/a"},
        },
    )
    assert verify.status_code == 400
    assert "merged findings cannot be re-verified" in verify.json()["detail"]


def test_coverage_patch_rejects_unknown_status_values(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"])

    ingest = client.post(
        "/engagements/2026-03-30-120000-example/assessment/request-observations",
        json={"url": "https://example.com/profile", "discovery_source": "recon"},
    )
    assert ingest.status_code == 201

    coverage_items = client.get("/engagements/2026-03-30-120000-example/assessment/coverage-items")
    assert coverage_items.status_code == 200
    coverage_item_id = coverage_items.json()[0]["id"]

    patch = client.patch(
        f"/engagements/2026-03-30-120000-example/assessment/coverage-items/{coverage_item_id}",
        json={"status": "complete-ish", "notes": "bad status"},
    )
    assert patch.status_code == 400
    assert "invalid coverage status" in patch.json()["detail"]


def test_incompatible_local_database_is_reset(client, isolate_settings):
    db_path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    with sqlite3.connect(str(db_path)) as connection:
        connection.execute("CREATE TABLE runs (id INTEGER PRIMARY KEY AUTOINCREMENT)")
        connection.execute(
            """
            CREATE TABLE events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER NOT NULL,
                event_type TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE assessment_attack_chains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER NOT NULL,
                chain_key TEXT NOT NULL
            )
            """
        )
        connection.commit()

    write_engagement(isolate_settings["engagements_dir"])

    response = client.get("/engagements")
    assert response.status_code == 200
    assert response.json()[0]["key"] == "2026-03-30-120000-example"

    with sqlite3.connect(str(db_path)) as connection:
        table_names = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()
        }
        assert "runs" not in table_names
        event_columns = {row[1] for row in connection.execute("PRAGMA table_info(events)").fetchall()}
        chain_columns = {row[1] for row in connection.execute("PRAGMA table_info(assessment_attack_chains)").fetchall()}
        assert "engagement_id" in event_columns
        assert "engagement_id" in chain_columns
        assert "run_id" not in event_columns
        assert "run_id" not in chain_columns


def test_deleted_filesystem_engagement_is_pruned_from_database(client, isolate_settings):
    engagement_dir = write_engagement(isolate_settings["engagements_dir"])

    response = client.get("/engagements")
    assert response.status_code == 200
    assert len(response.json()) == 1

    for path in sorted(engagement_dir.rglob("*"), reverse=True):
        if path.is_file():
            path.unlink()
        elif path.is_dir():
            path.rmdir()
    engagement_dir.rmdir()

    response = client.get("/engagements")
    assert response.status_code == 200
    assert response.json() == []


def test_deleted_session_is_pruned_from_database(client, isolate_settings):
    engagement_dir = write_engagement(isolate_settings["engagements_dir"])

    response = client.get("/engagements/2026-03-30-120000-example/sessions")
    assert response.status_code == 200
    assert len(response.json()) == 1

    (engagement_dir / "sessions" / "index.json").write_text("[]\n", encoding="utf-8")

    response = client.get("/engagements/2026-03-30-120000-example/sessions")
    assert response.status_code == 200
    assert response.json() == []
