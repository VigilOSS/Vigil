"""W3 — WEB coverage/grading gate at report_readiness.

Two BLOCK-WITH-OVERRIDE blocker kinds, scoped to WEB engagements
(``engagement_type`` web/both, i.e. anything that is NOT code/blue):

  * ``uncovered_high_route_hosts`` — an in-scope REAL-APP host (>= the route
    threshold of distinct recorded request-variant routes, OR an API/auth/
    GraphQL surface under the threshold) that has NO recorded VERDICT (a
    finding — including an evidence-backed-negative false_positive — on the
    host). Cleared by recording a verdict OR an active
    ``coverage_completeness_deferral`` naming the host (or engagement-wide).
  * ``unreviewed_findings`` — any finding severity in (critical, high, medium)
    AND verification_status='unreviewed' AND status not in (merged,
    false_positive), ANY auth_context. Cleared by grading it (record a
    verification verdict via POST /findings/{slug}/verify).

These NEVER fire on code or blue engagements. The gate is enforced both at
GET /report-readiness and (non-bypassably) at POST /report-export mode=final
(409 while blocked, 200 after clearing).
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.config import settings
from app.services import state_manager


BASE_TMPL = "/engagements/{key}/assessment"


# The single-file report template's data node, byte-for-byte. The backend
# anchors injection on the closing </script> tag so this fake exercises the
# real replacement path (mirrors tests/test_report_export.py).
_DATA_NODE = '<script id="vigil-report-data" type="application/json">"__VIGIL_REPORT_DATA__"</script>'
_FAKE_TEMPLATE = (
    "<!doctype html><html><head><title>Vigil Report</title>"
    f"{_DATA_NODE}"
    '</head><body><div id="root"></div>'
    '<script type="module">const SENTINEL="__VIGIL_REPORT_DATA__";</script>'
    "</body></html>"
)


@pytest.fixture
def fake_template(tmp_path):
    template_path = tmp_path / "template.html"
    template_path.write_text(_FAKE_TEMPLATE, encoding="utf-8")
    original = settings.report_template_path
    object.__setattr__(settings, "report_template_path", template_path)
    try:
        yield template_path
    finally:
        object.__setattr__(settings, "report_template_path", original)


def _write_engagement(
    engagements_dir: Path,
    *,
    key: str,
    engagement_type: str,
    out_of_scope: list[str] | None = None,
) -> Path:
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
    scope: dict = {
        "hostname": "example.com",
        "hosts": ["example.com"],
        "scope_hosts": ["example.com"],
        "engagement_type": engagement_type,
        "status": "in_progress",
        "current_phase": "consume-test",
    }
    if out_of_scope is not None:
        scope["out_of_scope"] = list(out_of_scope)
    (eng / "scope.json").write_text(json.dumps(scope), encoding="utf-8")
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


def _draft_unreviewed_finding(
    client, base: str, *, slug: str, host: str, severity: str = "medium"
) -> None:
    resp = client.post(
        f"{base}/findings",
        json={
            "slug": slug,
            "title": "Ungraded candidate",
            "severity": severity,
            "workflow_status": "draft",
            "verification_status": "unreviewed",
            "canonical_location": f"https://{host}/x",
            "summary": "needs a grade",
            "source_name": "vulnerability-analyst",
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


# ---------------------------------------------------------------------------
# uncovered_high_route_hosts
# ---------------------------------------------------------------------------
def test_web_uncovered_high_route_host_blocks(client, isolate_settings):
    eng_key = "2026-06-20-090000-w3a"
    _write_engagement(isolate_settings["engagements_dir"], key=eng_key, engagement_type="web")
    base = _register(client, eng_key)
    _ingest_routes(client, base, host="app.example.com", paths=SIX_PATHS)

    body = _readiness(client, base)
    assert body["ready"] is False, body
    blk = [b for b in body["blockers"] if b["kind"] == "uncovered_high_route_hosts"]
    assert blk, body
    assert blk[0]["host"] == "app.example.com"
    assert blk[0]["route_count"] == 6


def test_web_under_threshold_plain_host_does_not_block(client, isolate_settings):
    eng_key = "2026-06-20-090000-w3b"
    _write_engagement(isolate_settings["engagements_dir"], key=eng_key, engagement_type="web")
    base = _register(client, eng_key)
    # Five plain routes, no API/auth surface, no finding → not a real_app.
    _ingest_routes(client, base, host="thin.example.com", paths=SIX_PATHS[:5])

    body = _readiness(client, base)
    assert "uncovered_high_route_hosts" not in _kinds(body), body
    assert body["ready"] is True, body


def test_web_api_surface_under_threshold_is_real_app(client, isolate_settings):
    eng_key = "2026-06-20-090000-w3c"
    _write_engagement(isolate_settings["engagements_dir"], key=eng_key, engagement_type="web")
    base = _register(client, eng_key)
    # Only two routes, but one is an /api/ surface → real_app under threshold.
    _ingest_routes(client, base, host="micro.example.com", paths=["/api/v1/users", "/health"])

    body = _readiness(client, base)
    blk = [b for b in body["blockers"] if b["kind"] == "uncovered_high_route_hosts"]
    assert blk and blk[0]["host"] == "micro.example.com", body
    assert body["ready"] is False, body


def test_recording_a_verdict_clears_uncovered_host(client, isolate_settings):
    eng_key = "2026-06-20-090000-w3d"
    _write_engagement(isolate_settings["engagements_dir"], key=eng_key, engagement_type="web")
    base = _register(client, eng_key)
    _ingest_routes(client, base, host="app.example.com", paths=SIX_PATHS)

    # Record a verdict on the host: a low-severity finding (not med+, so it does
    # NOT itself trip unreviewed_findings) gives the host a recorded verdict.
    resp = client.post(
        f"{base}/findings",
        json={
            "slug": "VA-100",
            "title": "Recorded verdict on the host",
            "severity": "low",
            "workflow_status": "active",
            "verification_status": "unreviewed",
            "canonical_location": "https://app.example.com/alpha",
            "summary": "covered",
            "source_name": "vulnerability-analyst",
        },
    )
    assert resp.status_code == 201, resp.text

    body = _readiness(client, base)
    assert "uncovered_high_route_hosts" not in _kinds(body), body


def test_completeness_deferral_clears_named_host(client, isolate_settings):
    eng_key = "2026-06-20-090000-w3e"
    _write_engagement(isolate_settings["engagements_dir"], key=eng_key, engagement_type="web")
    base = _register(client, eng_key)
    _ingest_routes(client, base, host="app.example.com", paths=SIX_PATHS)

    assert "uncovered_high_route_hosts" in _kinds(_readiness(client, base))

    resp = client.post(
        f"{base}/dispatch-decisions",
        json={
            "kind": "coverage_completeness_deferral",
            "payload": {"host": "app.example.com", "reason": "out of testing window"},
            "surfaced_to_user": True,
        },
    )
    assert resp.status_code == 201, resp.text

    body = _readiness(client, base)
    assert "uncovered_high_route_hosts" not in _kinds(body), body


def test_engagement_wide_completeness_deferral_clears_all(client, isolate_settings):
    eng_key = "2026-06-20-090000-w3f"
    _write_engagement(isolate_settings["engagements_dir"], key=eng_key, engagement_type="web")
    base = _register(client, eng_key)
    _ingest_routes(client, base, host="app.example.com", paths=SIX_PATHS)
    _ingest_routes(client, base, host="edge.example.com", paths=SIX_PATHS)

    resp = client.post(
        f"{base}/dispatch-decisions",
        json={
            "kind": "coverage_completeness_deferral",
            "payload": {"engagement_wide": True, "reason": "report due, accept residual"},
            "surfaced_to_user": True,
        },
    )
    assert resp.status_code == 201, resp.text

    body = _readiness(client, base)
    assert "uncovered_high_route_hosts" not in _kinds(body), body


def test_resolved_completeness_deferral_no_longer_clears(client, isolate_settings):
    eng_key = "2026-06-20-090000-w3g"
    _write_engagement(isolate_settings["engagements_dir"], key=eng_key, engagement_type="web")
    base = _register(client, eng_key)
    _ingest_routes(client, base, host="app.example.com", paths=SIX_PATHS)

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
    assert "uncovered_high_route_hosts" not in _kinds(_readiness(client, base))

    patch = client.patch(
        f"{base}/dispatch-decisions/{decision_id}",
        json={"resolved": True, "resolution": {"choice": "covered-it"}},
    )
    assert patch.status_code == 200, patch.text

    body = _readiness(client, base)
    assert "uncovered_high_route_hosts" in _kinds(body), body


# ---------------------------------------------------------------------------
# Scope admission: out-of-scope hosts must never become uncovered blockers
# ---------------------------------------------------------------------------
def test_out_of_scope_host_does_not_block_but_in_scope_does(client, isolate_settings):
    """A third-party host (SSO/CDN/vendor API) recorded via archive/proxy/manual
    ingestion is NOT a scope literal nor a subdomain of one, so it must never be
    forced through the completeness gate — while an in-scope app host with the
    same route shape still blocks. Scope: example.com."""
    eng_key = "2026-06-20-090000-w3-oos"
    _write_engagement(isolate_settings["engagements_dir"], key=eng_key, engagement_type="web")
    base = _register(client, eng_key)
    # In scope (subdomain of the example.com apex) — must block.
    _ingest_routes(client, base, host="app.example.com", paths=SIX_PATHS)
    # Out of scope (unrelated third-party host) — must NOT block.
    _ingest_routes(client, base, host="sso.thirdparty.io", paths=SIX_PATHS)

    body = _readiness(client, base)
    blocked_hosts = {
        b["host"]
        for b in body["blockers"]
        if b["kind"] == "uncovered_high_route_hosts"
    }
    assert "app.example.com" in blocked_hosts, body
    assert "sso.thirdparty.io" not in blocked_hosts, body


def test_explicit_out_of_scope_carveout_host_does_not_block(client, isolate_settings):
    """A host that IS under the in-scope apex but is named in scope.json's
    ``out_of_scope`` carve-out is denied (the denylist wins) and must not become
    an uncovered blocker, while a sibling in-scope host still does."""
    eng_key = "2026-06-20-090000-w3-carveout"
    _write_engagement(
        isolate_settings["engagements_dir"],
        key=eng_key,
        engagement_type="web",
        out_of_scope=["legacy.example.com"],
    )
    base = _register(client, eng_key)
    _ingest_routes(client, base, host="app.example.com", paths=SIX_PATHS)
    _ingest_routes(client, base, host="legacy.example.com", paths=SIX_PATHS)

    body = _readiness(client, base)
    blocked_hosts = {
        b["host"]
        for b in body["blockers"]
        if b["kind"] == "uncovered_high_route_hosts"
    }
    assert "app.example.com" in blocked_hosts, body
    assert "legacy.example.com" not in blocked_hosts, body


def test_web_uncovered_high_route_hosts_helper_drops_out_of_scope(client, isolate_settings):
    """Direct projection coverage: the helper itself filters out-of-scope hosts."""
    eng_key = "2026-06-20-090000-w3-oos-unit"
    _write_engagement(isolate_settings["engagements_dir"], key=eng_key, engagement_type="web")
    base = _register(client, eng_key)
    engagement_id = int(client.get(f"/engagements/{eng_key}").json()["id"])
    _ingest_routes(client, base, host="app.example.com", paths=SIX_PATHS)
    _ingest_routes(client, base, host="cdn.fastly.net", paths=SIX_PATHS)

    rows = state_manager.web_uncovered_high_route_hosts(engagement_id)
    hosts = {r["host"] for r in rows}
    assert "app.example.com" in hosts
    assert "cdn.fastly.net" not in hosts


# ---------------------------------------------------------------------------
# unreviewed_findings
# ---------------------------------------------------------------------------
def test_web_unreviewed_medium_draft_finding_blocks(client, isolate_settings):
    eng_key = "2026-06-20-090000-w3h"
    _write_engagement(isolate_settings["engagements_dir"], key=eng_key, engagement_type="web")
    base = _register(client, eng_key)
    _draft_unreviewed_finding(client, base, slug="VA-200", host="api.example.com")

    body = _readiness(client, base)
    blk = [b for b in body["blockers"] if b["kind"] == "unreviewed_findings"]
    assert blk and blk[0]["slug"] == "VA-200", body
    assert body["ready"] is False, body


def test_web_unreviewed_low_finding_does_not_block(client, isolate_settings):
    eng_key = "2026-06-20-090000-w3i"
    _write_engagement(isolate_settings["engagements_dir"], key=eng_key, engagement_type="web")
    base = _register(client, eng_key)
    _draft_unreviewed_finding(client, base, slug="VA-201", host="api.example.com", severity="low")

    body = _readiness(client, base)
    assert "unreviewed_findings" not in _kinds(body), body
    assert body["ready"] is True, body


def test_grading_finding_clears_unreviewed_blocker(client, isolate_settings):
    eng_key = "2026-06-20-090000-w3j"
    _write_engagement(isolate_settings["engagements_dir"], key=eng_key, engagement_type="web")
    base = _register(client, eng_key)
    _draft_unreviewed_finding(client, base, slug="VA-202", host="api.example.com")
    assert "unreviewed_findings" in _kinds(_readiness(client, base))

    verify = client.post(
        f"{base}/findings/VA-202/verify",
        json={"verification_status": "disputed", "reason_text": "graded — not exploitable"},
    )
    assert verify.status_code == 200, verify.text

    body = _readiness(client, base)
    assert "unreviewed_findings" not in _kinds(body), body
    assert body["ready"] is True, body


# ---------------------------------------------------------------------------
# Combined scenario + report-export enforcement (the TDD acceptance case)
# ---------------------------------------------------------------------------
def test_both_blockers_then_cleared_and_export_gate(client, isolate_settings, fake_template):
    eng_key = "2026-06-20-090000-w3k"
    _write_engagement(isolate_settings["engagements_dir"], key=eng_key, engagement_type="web")
    base = _register(client, eng_key)
    _ingest_routes(client, base, host="app.example.com", paths=SIX_PATHS)
    _draft_unreviewed_finding(client, base, slug="VA-300", host="api.example.com")

    body = _readiness(client, base)
    assert body["ready"] is False, body
    kinds = _kinds(body)
    assert "uncovered_high_route_hosts" in kinds, body
    assert "unreviewed_findings" in kinds, body

    # The non-bypassable edge: report-export mode=final must 409 while blocked.
    blocked = client.post(f"{base}/report-export", json={"mode": "final"})
    assert blocked.status_code == 409, blocked.text
    assert blocked.json()["detail"]["ready"] is False

    # Clear both: deferral names the uncovered host; grade the finding.
    d = client.post(
        f"{base}/dispatch-decisions",
        json={
            "kind": "coverage_completeness_deferral",
            "payload": {"host": "app.example.com", "reason": "accepted residual"},
            "surfaced_to_user": True,
        },
    )
    assert d.status_code == 201, d.text
    v = client.post(
        f"{base}/findings/VA-300/verify",
        json={"verification_status": "disputed", "reason_text": "graded"},
    )
    assert v.status_code == 200, v.text

    body = _readiness(client, base)
    assert body["ready"] is True, body

    ok = client.post(f"{base}/report-export", json={"mode": "final"})
    assert ok.status_code == 200, ok.text
    assert ok.json()["mode"] == "final"


# ---------------------------------------------------------------------------
# Scope guard: code / blue engagements are unaffected
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("etype", ["code", "blue"])
def test_non_web_engagement_unaffected(client, isolate_settings, etype):
    eng_key = f"2026-06-20-090000-w3-{etype}"
    _write_engagement(isolate_settings["engagements_dir"], key=eng_key, engagement_type=etype)
    base = _register(client, eng_key)
    _ingest_routes(client, base, host="app.example.com", paths=SIX_PATHS)
    _draft_unreviewed_finding(client, base, slug="VA-400", host="api.example.com")

    body = _readiness(client, base)
    kinds = _kinds(body)
    assert "uncovered_high_route_hosts" not in kinds, body
    assert "unreviewed_findings" not in kinds, body


def test_both_engagement_type_fires(client, isolate_settings):
    """engagement_type='both' is a WEB engagement — the gate fires."""
    eng_key = "2026-06-20-090000-w3-both"
    _write_engagement(isolate_settings["engagements_dir"], key=eng_key, engagement_type="both")
    base = _register(client, eng_key)
    _ingest_routes(client, base, host="app.example.com", paths=SIX_PATHS)

    body = _readiness(client, base)
    assert "uncovered_high_route_hosts" in _kinds(body), body


# ---------------------------------------------------------------------------
# Direct unit coverage of the coverage.py projection
# ---------------------------------------------------------------------------
def test_web_uncovered_high_route_hosts_helper(client, isolate_settings):
    eng_key = "2026-06-20-090000-w3-unit"
    _write_engagement(isolate_settings["engagements_dir"], key=eng_key, engagement_type="web")
    base = _register(client, eng_key)
    engagement_id = int(client.get(f"/engagements/{eng_key}").json()["id"])
    _ingest_routes(client, base, host="app.example.com", paths=SIX_PATHS)

    rows = state_manager.web_uncovered_high_route_hosts(engagement_id)
    hosts = {r["host"] for r in rows}
    assert "app.example.com" in hosts
