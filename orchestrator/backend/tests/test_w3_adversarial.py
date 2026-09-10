"""Adversarial W3 gate verification tests."""
import json
from pathlib import Path

BASE_TMPL = "/engagements/{key}/assessment"

def _write_engagement(engagements_dir: Path, *, key: str, engagement_type: str) -> Path:
    eng = engagements_dir / key
    (eng / "sessions").mkdir(parents=True, exist_ok=True)
    (eng / "engagement.json").write_text(
        json.dumps(
            {
                "key": key,
                "target": "https://example.com",
                "hostname": "example.com",
                "created_at": "2026-06-20T09:00:00Z",
                "engagement_type": engagement_type,
            }
        ),
        encoding="utf-8",
    )
    (eng / "scope.json").write_text(
        json.dumps(
            {
                "hostname": "example.com",
                "hosts": ["example.com"],
                "scope_hosts": ["example.com"],
                "engagement_type": engagement_type,
                "status": "in_progress",
                "current_phase": "consume-test",
            }
        ),
        encoding="utf-8",
    )
    (eng / "findings.md").write_text("# Findings\n", encoding="utf-8")
    return eng

def _register(client, key: str) -> str:
    response = client.get(f"/engagements/{key}")
    assert response.status_code == 200, response.text
    return BASE_TMPL.format(key=key)

def _ingest_routes(client, base: str, *, host: str, paths: list[str]) -> None:
    for path in paths:
        resp = client.post(
            f"{base}/request-observations",
            json={
                "url": f"https://{host}{path}",
                "method": "GET",
                "discovery_source": "test",
                "response_status": 200,
            },
        )
        assert resp.status_code == 201, resp.text

def _readiness(client, base: str) -> dict:
    resp = client.get(f"{base}/report-readiness")
    assert resp.status_code == 200, resp.text
    return resp.json()

def _kinds(body: dict) -> set[str]:
    return {b.get("kind") for b in body.get("blockers", [])}

SIX_PATHS = ["/alpha", "/bravo", "/charlie", "/delta", "/echo", "/foxtrot"]

# ADVERSARIAL TEST (a): Can DEFERRAL be RESOLVED but still CLEAR the host?
def test_adversarial_resolved_deferral_does_not_clear_host(client, isolate_settings):
    """After resolving a deferral, the uncovered host should REBLOCK."""
    eng_key = "2026-06-20-090000-adv-a1"
    _write_engagement(isolate_settings["engagements_dir"], key=eng_key, engagement_type="web")
    base = _register(client, eng_key)
    _ingest_routes(client, base, host="app.example.com", paths=SIX_PATHS)

    # Initially blocked
    assert "uncovered_high_route_hosts" in _kinds(_readiness(client, base))

    # Add deferral
    resp = client.post(
        f"{base}/dispatch-decisions",
        json={
            "kind": "coverage_completeness_deferral",
            "payload": {"host": "app.example.com", "reason": "temp"},
            "surfaced_to_user": True,
        },
    )
    assert resp.status_code == 201, resp.text
    decision_id = int(resp.json()["id"])
    
    # Should be cleared now
    assert "uncovered_high_route_hosts" not in _kinds(_readiness(client, base))

    # Resolve the deferral
    patch = client.patch(
        f"{base}/dispatch-decisions/{decision_id}",
        json={"resolved": True, "resolution": {"choice": "covered-it"}},
    )
    assert patch.status_code == 200, patch.text

    # MUST reblock after resolution
    body = _readiness(client, base)
    assert "uncovered_high_route_hosts" in _kinds(body), "HOLE: resolved deferral still clears!"

# ADVERSARIAL TEST (b): Does deferral only clear NAMED hosts?
def test_adversarial_named_deferral_does_not_clear_others(client, isolate_settings):
    """A named-host deferral should NOT clear other uncovered hosts."""
    eng_key = "2026-06-20-090000-adv-b1"
    _write_engagement(isolate_settings["engagements_dir"], key=eng_key, engagement_type="web")
    base = _register(client, eng_key)
    _ingest_routes(client, base, host="app1.example.com", paths=SIX_PATHS)
    _ingest_routes(client, base, host="app2.example.com", paths=SIX_PATHS)

    # Both blocked
    body = _readiness(client, base)
    blk = [b for b in body["blockers"] if b["kind"] == "uncovered_high_route_hosts"]
    hosts = {b["host"] for b in blk}
    assert hosts == {"app1.example.com", "app2.example.com"}, f"Expected both hosts, got {hosts}"

    # Defer ONLY app1.example.com
    resp = client.post(
        f"{base}/dispatch-decisions",
        json={
            "kind": "coverage_completeness_deferral",
            "payload": {"host": "app1.example.com", "reason": "out of scope"},
            "surfaced_to_user": True,
        },
    )
    assert resp.status_code == 201, resp.text

    # MUST still have app2 blocked
    body = _readiness(client, base)
    blk = [b for b in body["blockers"] if b["kind"] == "uncovered_high_route_hosts"]
    hosts = {b["host"] for b in blk}
    assert "app2.example.com" in hosts, f"HOLE: named deferral cleared other hosts! {hosts}"
    assert "app1.example.com" not in hosts, f"HOLE: deferral did not clear named host! {hosts}"

# ADVERSARIAL TEST (c): Does unreviewed block ONLY medium+?
def test_adversarial_unreviewed_critical_blocks(client, isolate_settings):
    """Critical unreviewed should block (not just medium)."""
    eng_key = "2026-06-20-090000-adv-c1"
    _write_engagement(isolate_settings["engagements_dir"], key=eng_key, engagement_type="web")
    base = _register(client, eng_key)

    resp = client.post(
        f"{base}/findings",
        json={
            "slug": "VA-001",
            "title": "Ungraded critical",
            "severity": "critical",
            "workflow_status": "draft",
            "verification_status": "unreviewed",
            "canonical_location": "https://api.example.com/x",
            "summary": "needs a grade",
            "source_name": "vulnerability-analyst",
        },
    )
    assert resp.status_code == 201, resp.text

    body = _readiness(client, base)
    blk = [b for b in body["blockers"] if b["kind"] == "unreviewed_findings"]
    assert blk and blk[0]["slug"] == "VA-001", "HOLE: unreviewed critical did not block!"

def test_adversarial_unreviewed_high_blocks(client, isolate_settings):
    """High unreviewed should block (not just medium)."""
    eng_key = "2026-06-20-090000-adv-c2"
    _write_engagement(isolate_settings["engagements_dir"], key=eng_key, engagement_type="web")
    base = _register(client, eng_key)

    resp = client.post(
        f"{base}/findings",
        json={
            "slug": "VA-002",
            "title": "Ungraded high",
            "severity": "high",
            "workflow_status": "draft",
            "verification_status": "unreviewed",
            "canonical_location": "https://api.example.com/x",
            "summary": "needs a grade",
            "source_name": "vulnerability-analyst",
        },
    )
    assert resp.status_code == 201, resp.text

    body = _readiness(client, base)
    blk = [b for b in body["blockers"] if b["kind"] == "unreviewed_findings"]
    assert blk and blk[0]["slug"] == "VA-002", "HOLE: unreviewed high did not block!"

# ADVERSARIAL TEST (d): Verify scoping to WEB ONLY
def test_adversarial_code_engagement_not_blocked(client, isolate_settings):
    """CODE engagement must NOT be blocked by W3 gate."""
    eng_key = "2026-06-20-090000-adv-d1"
    _write_engagement(isolate_settings["engagements_dir"], key=eng_key, engagement_type="code")
    base = _register(client, eng_key)
    _ingest_routes(client, base, host="app.example.com", paths=SIX_PATHS)

    # Draft unreviewed finding
    resp = client.post(
        f"{base}/findings",
        json={
            "slug": "VA-003",
            "title": "Ungraded",
            "severity": "critical",
            "workflow_status": "draft",
            "verification_status": "unreviewed",
            "canonical_location": "https://api.example.com/x",
            "summary": "needs a grade",
            "source_name": "vulnerability-analyst",
        },
    )
    assert resp.status_code == 201, resp.text

    body = _readiness(client, base)
    kinds = _kinds(body)
    assert "uncovered_high_route_hosts" not in kinds, "HOLE: CODE engagement blocked by uncovered_high_route_hosts!"
    assert "unreviewed_findings" not in kinds, "HOLE: CODE engagement blocked by unreviewed_findings!"

def test_adversarial_blue_engagement_not_blocked(client, isolate_settings):
    """BLUE engagement must NOT be blocked by W3 gate."""
    eng_key = "2026-06-20-090000-adv-d2"
    _write_engagement(isolate_settings["engagements_dir"], key=eng_key, engagement_type="blue")
    base = _register(client, eng_key)
    _ingest_routes(client, base, host="app.example.com", paths=SIX_PATHS)

    # Draft unreviewed finding
    resp = client.post(
        f"{base}/findings",
        json={
            "slug": "VA-004",
            "title": "Ungraded",
            "severity": "critical",
            "workflow_status": "draft",
            "verification_status": "unreviewed",
            "canonical_location": "https://api.example.com/x",
            "summary": "needs a grade",
            "source_name": "vulnerability-analyst",
        },
    )
    assert resp.status_code == 201, resp.text

    body = _readiness(client, base)
    kinds = _kinds(body)
    assert "uncovered_high_route_hosts" not in kinds, "HOLE: BLUE engagement blocked by uncovered_high_route_hosts!"
    assert "unreviewed_findings" not in kinds, "HOLE: BLUE engagement blocked by unreviewed_findings!"

# EDGE CASE TEST: pending_runtime_proof handling
def test_pending_runtime_proof_clears_unreviewed_but_not_reportable(client, isolate_settings):
    """A finding with pending_runtime_proof should clear the unreviewed gate but not be in final report."""
    eng_key = "2026-06-20-090000-edge-prp"
    _write_engagement(isolate_settings["engagements_dir"], key=eng_key, engagement_type="web")
    base = _register(client, eng_key)

    # Create an active critical finding
    resp = client.post(
        f"{base}/findings",
        json={
            "slug": "VA-500",
            "title": "Critical pending proof",
            "severity": "critical",
            "workflow_status": "active",
            "verification_status": "unreviewed",
            "canonical_location": "https://api.example.com/x",
            "summary": "needs verification",
            "source_name": "vulnerability-analyst",
        },
    )
    assert resp.status_code == 201, resp.text

    # Should block on unreviewed
    body = _readiness(client, base)
    blk = [b for b in body["blockers"] if b["kind"] == "unreviewed_findings"]
    assert blk and blk[0]["slug"] == "VA-500"

    # Grade with pending_runtime_proof
    verify = client.post(
        f"{base}/findings/VA-500/verify",
        json={"verification_status": "pending_runtime_proof", "reason_text": "code looks bad, need runtime proof"},
    )
    assert verify.status_code == 200, verify.text

    # Should NOT block anymore (it's verified, even if pending)
    body = _readiness(client, base)
    blk = [b for b in body["blockers"] if b["kind"] == "unreviewed_findings"]
    assert not blk, "HOLE: pending_runtime_proof finding still blocks unreviewed!"

    # But it should NOT be in the report (final report only includes confirmed/downgraded)
    findings = client.get(f"{base}/findings?workflow_status=active")
    assert findings.status_code == 200
