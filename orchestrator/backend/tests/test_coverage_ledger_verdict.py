"""W2 — per-host finding-VERDICT join + server-side findings filters.

The coverage ledger (``vigil assess coverage``) needs to know, per in-scope
host, whether a RECORDED VERDICT exists — a finding (any disposition, since a
``false_positive`` finding is the canonical evidence-backed negative) — so a
host with real routes but no verdict shows up as an uncovered GAP rather than
silently "done".

This module asserts two backend contracts W2 adds:

1. ``state_manager.per_host_coverage`` exposes a per-host ``finding_verdict``
   plus a top-level ``finding_verdicts`` map that also covers finding-only hosts
   (a host with a finding but no recon service/surface). Existing per-host fields
   are unchanged.
2. ``GET /findings`` filters server-side by ``auth_context`` and
   ``verification_status`` so the ledger can drill into a host's verdict without
   pulling every finding to the client.
"""
from __future__ import annotations

from app.services import state_manager
from tests.proof_fixtures import post_artifact_backed_source_observation
from tests.test_engagements_api import write_engagement


ENGAGEMENT_KEY = "2026-05-17-100000-ledger"
ASSESSMENT_BASE = f"/engagements/{ENGAGEMENT_KEY}/assessment"


def _seed(client, isolate_settings) -> int:
    write_engagement(isolate_settings["engagements_dir"], key=ENGAGEMENT_KEY)
    response = client.get(f"/engagements/{ENGAGEMENT_KEY}")
    assert response.status_code == 200, response.text
    return int(response.json()["id"])


def _create_service(client, *, endpoint: str, state: str = "up") -> None:
    response = client.get(f"/engagements/{ENGAGEMENT_KEY}")
    engagement_id = int(response.json()["id"])
    state_manager.record_service(
        engagement_id,
        endpoint=endpoint,
        protocol="tcp",
        port=None,
        service="",
        state=state,
        coverage_status="pending",
        banner="",
        notes="",
        discovered_by="test",
        target_identity=None,
    )


def _create_finding(
    client,
    *,
    slug: str,
    canonical_location: str,
    severity: str = "high",
    workflow_status: str = "active",
    verification_status: str = "unreviewed",
    auth_context: str = "anonymous",
) -> None:
    author_id = f"AUTHOR-{slug}"
    author = client.post(
        f"{ASSESSMENT_BASE}/dispatches",
        json={
            "agent_id": author_id,
            "agent_role": "vulnerability-analyst",
            "task": f"Record {slug}",
        },
    )
    assert author.status_code == 201, author.text
    response = client.post(
        f"{ASSESSMENT_BASE}/findings",
        json={
            "slug": slug,
            "title": slug.replace("-", " ").title(),
            "severity": severity,
            "workflow_status": workflow_status,
            "verification_status": "unreviewed",
            "auth_context": auth_context,
            "canonical_location": canonical_location,
            "source_name": "vulnerability-analyst",
            "provenance": {"agent_id": author_id},
            "summary": "fixture finding",
        },
    )
    assert response.status_code == 201, response.text
    if verification_status == "confirmed":
        agent_id = f"VERIFY-{slug}"
        dispatch = client.post(
            f"{ASSESSMENT_BASE}/dispatches",
            json={
                "agent_id": agent_id,
                "agent_role": "coverage-ledger-verifier",
                "task": f"Independently verify {slug}",
            },
        )
        assert dispatch.status_code == 201, dispatch.text
        run = client.post(
            f"{ASSESSMENT_BASE}/assessment-runs",
            json={
                "run_uuid": f"coverage-ledger-{slug}",
                "run_kind": "shared",
                "producer_dispatch_agent_id": agent_id,
            },
        )
        assert run.status_code == 201, run.text
        receipt = post_artifact_backed_source_observation(
            client,
            f"{ASSESSMENT_BASE}/proof-receipts",
            json={
                "run_id": run.json()["id"],
                "evidence_kind": "source_observation",
                "expected_result": "the recorded finding is independently reproducible",
                "observed_result": "the independent review reproduced the finding",
            },
        )
        assert receipt.status_code == 201, receipt.text
        completed = client.patch(
            f"{ASSESSMENT_BASE}/assessment-runs/{run.json()['id']}",
            json={"status": "completed"},
        )
        assert completed.status_code == 200, completed.text
        verified = client.post(
            f"{ASSESSMENT_BASE}/findings/{slug}/verify",
            json={
                "verification_status": "confirmed",
                "reason_text": "independent coverage-ledger fixture proof",
                "proof_receipt_ids": [receipt.json()["id"]],
            },
        )
        assert verified.status_code == 200, verified.text


def _by_host(body: dict) -> dict:
    return {row["host"]: row for row in body["hosts"]}


# ---------------------------------------------------------------------------
# per-host finding-verdict join
# ---------------------------------------------------------------------------


def test_host_with_finding_gets_inline_verdict(client, isolate_settings):
    _seed(client, isolate_settings)
    _create_service(client, endpoint="api.target.example")
    _create_finding(
        client,
        slug="VA-001",
        canonical_location="https://api.target.example/v1/users",
        verification_status="confirmed",
        auth_context="authenticated",
    )

    body = client.get(f"{ASSESSMENT_BASE}/coverage-readiness/by-host").json()
    rows = _by_host(body)
    assert "api.target.example" in rows
    verdict = rows["api.target.example"]["finding_verdict"]
    assert verdict["has_finding"] is True
    assert verdict["finding_count"] == 1
    assert verdict["verified_count"] == 1
    assert verdict["strongest_status"] == "active"
    assert verdict["max_severity"] == "high"
    assert verdict["auth_contexts"] == ["authenticated"]
    assert "VA-001" in verdict["slugs"]

    # The top-level map mirrors the inline verdict.
    assert body["finding_verdicts"]["api.target.example"]["has_finding"] is True


def test_host_without_finding_has_empty_verdict(client, isolate_settings):
    _seed(client, isolate_settings)
    _create_service(client, endpoint="api.target.example")

    body = client.get(f"{ASSESSMENT_BASE}/coverage-readiness/by-host").json()
    rows = _by_host(body)
    verdict = rows["api.target.example"]["finding_verdict"]
    assert verdict["has_finding"] is False
    assert verdict["finding_count"] == 0
    assert "api.target.example" not in body["finding_verdicts"]


def test_finding_only_host_surfaces_in_top_level_map(client, isolate_settings):
    """A host with a finding but no recon service/surface is NOT silently
    dropped — it must be discoverable for the ledger so its crown-jewel
    verdict is not lost just because recon never recorded a surface."""
    _seed(client, isolate_settings)
    _create_finding(
        client,
        slug="VA-002",
        canonical_location="https://admin.target.example/login",
        auth_context="anonymous",
    )

    body = client.get(f"{ASSESSMENT_BASE}/coverage-readiness/by-host").json()
    # No service/surface for admin.target.example → not in the recon host table.
    assert "admin.target.example" not in _by_host(body)
    # …but its verdict is preserved in the top-level join.
    assert body["finding_verdicts"]["admin.target.example"]["has_finding"] is True


def test_merged_finding_excluded_from_verdict(client, isolate_settings):
    _seed(client, isolate_settings)
    _create_service(client, endpoint="api.target.example")
    _create_finding(
        client,
        slug="VA-003",
        canonical_location="https://api.target.example/v1/orders",
        workflow_status="merged",
    )

    body = client.get(f"{ASSESSMENT_BASE}/coverage-readiness/by-host").json()
    rows = _by_host(body)
    verdict = rows["api.target.example"]["finding_verdict"]
    assert verdict["has_finding"] is False
    assert verdict["finding_count"] == 0


def test_existing_per_host_fields_unchanged_by_verdict_join(client, isolate_settings):
    """The verdict join is purely additive — the recon objective fields a
    host already exposed must keep their shape/values."""
    _seed(client, isolate_settings)
    _create_service(client, endpoint="api.target.example")

    body = client.get(f"{ASSESSMENT_BASE}/coverage-readiness/by-host").json()
    row = _by_host(body)["api.target.example"]
    assert row["outcomes"]["service_inventory"]["met"] is True
    assert set(row["outcomes"].keys()) == {
        "waf_tier",
        "service_inventory",
        "directory_fuzz",
        "tech_fingerprint",
        "osint",
    }
    assert "unmet_objectives" in row
    assert "deferrals" in row


# ---------------------------------------------------------------------------
# server-side findings filters (auth_context + verification_status)
# ---------------------------------------------------------------------------


def test_findings_filter_by_auth_context(client, isolate_settings):
    _seed(client, isolate_settings)
    _create_finding(
        client,
        slug="VA-010",
        canonical_location="https://api.target.example/a",
        auth_context="anonymous",
    )
    _create_finding(
        client,
        slug="VA-011",
        canonical_location="https://api.target.example/b",
        auth_context="authenticated",
    )

    response = client.get(f"{ASSESSMENT_BASE}/findings?auth_context=authenticated")
    assert response.status_code == 200, response.text
    slugs = {row["slug"] for row in response.json()}
    assert slugs == {"VA-011"}


def test_findings_filter_by_auth_context_and_verification_status(client, isolate_settings):
    _seed(client, isolate_settings)
    _create_finding(
        client,
        slug="VA-020",
        canonical_location="https://api.target.example/c",
        auth_context="authenticated",
        verification_status="confirmed",
    )
    _create_finding(
        client,
        slug="VA-021",
        canonical_location="https://api.target.example/d",
        auth_context="authenticated",
        verification_status="unreviewed",
    )

    response = client.get(
        f"{ASSESSMENT_BASE}/findings?auth_context=authenticated&verification_status=confirmed"
    )
    assert response.status_code == 200, response.text
    slugs = {row["slug"] for row in response.json()}
    assert slugs == {"VA-020"}
