"""P1-C backend tests: blocked-technique round-trip (retry_state default),
the resume-brief Attempts do-today ledger, and the generalized finding-link
unblock path.

These exercise the backend HTTP surface directly (FastAPI TestClient) via the
shared ``client`` / ``isolate_settings`` fixtures in conftest.py.
"""
from __future__ import annotations

import json
from pathlib import Path

ENGAGEMENT_KEY = "2026-07-01-090000-attempts"
BASE = f"/engagements/{ENGAGEMENT_KEY}/assessment"


def _write_engagement(engagements_dir: Path) -> Path:
    eng = engagements_dir / ENGAGEMENT_KEY
    (eng / "sessions").mkdir(parents=True, exist_ok=True)
    (eng / "engagement.json").write_text(
        json.dumps(
            {
                "key": ENGAGEMENT_KEY,
                "target": "https://example.com",
                "hostname": "example.com",
                "created_at": "2026-07-01T09:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    (eng / "scope.json").write_text(
        json.dumps(
            {
                "hostname": "example.com",
                "hosts": ["example.com"],
                "status": "in_progress",
                "current_phase": "consume-test",
            }
        ),
        encoding="utf-8",
    )
    return eng


def _seed_finding(client, eng: Path, slug: str, *, details: dict | None = None) -> None:
    (eng / "notes").mkdir(parents=True, exist_ok=True)
    note = eng / "notes" / f"{slug}-note.md"
    note.write_text(f"{slug} evidence", encoding="utf-8")
    payload = {
        "slug": slug,
        "title": f"{slug} finding",
        "severity": "high",
        "workflow_status": "active",
        "verification_state": "verified",
        "verification_disposition": "confirmed",
        "canonical_location": f"https://example.com/{slug}",
        "summary": f"{slug} summary",
        "evidence_ref": f"notes/{slug}-note.md",
        "source_name": "vulnerability-analyst",
        "details": {
            "impact": "impact",
            "evidence": "evidence",
            **(details or {}),
        },
    }
    resp = client.post(f"{BASE}/findings", json=payload)
    assert resp.status_code == 201, resp.text


def test_blocked_technique_roundtrip_defaults_retry_state_pending(client, isolate_settings) -> None:
    """POST /blocked-techniques omitting retry_state now lands 'pending' (aligned
    with the SQL column default), not the old Pydantic 'no_retry' (LOW-12), and
    round-trips through GET."""
    _write_engagement(isolate_settings["engagements_dir"])
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200

    created = client.post(
        f"{BASE}/blocked-techniques",
        json={
            "technique_key": "ssrf:host:api-example-com",
            "technique": "SSRF",
            "target_kind": "host",
            "target_ref": "api.example.com",
            "reason": "egress firewalled; metadata endpoint unreachable",
            # retry_state intentionally omitted -> default must be "pending"
        },
    )
    assert created.status_code == 201, created.text
    assert created.json()["retry_state"] == "pending"

    listed = client.get(f"{BASE}/blocked-techniques")
    assert listed.status_code == 200, listed.text
    rows = listed.json()
    assert len(rows) == 1
    row = rows[0]
    assert row["technique"] == "SSRF"
    assert row["technique_key"] == "ssrf:host:api-example-com"
    assert row["retry_state"] == "pending"

    # An explicit retry_state still round-trips (upsert on technique_key).
    updated = client.post(
        f"{BASE}/blocked-techniques",
        json={
            "technique_key": "ssrf:host:api-example-com",
            "technique": "SSRF",
            "target_kind": "host",
            "target_ref": "api.example.com",
            "reason": "confirmed permanent egress wall",
            "retry_state": "no_retry",
        },
    )
    assert updated.status_code == 201, updated.text
    assert updated.json()["retry_state"] == "no_retry"
    assert len(client.get(f"{BASE}/blocked-techniques").json()) == 1  # upserted, not duplicated


def test_resume_brief_attempts_section_surfaces_all_three_sources(client, isolate_settings) -> None:
    """build_resume_brief.attempts surfaces (1) recorded blocked techniques,
    (2) non-covering probe runs (result_status NOT IN tested/signal), and
    (3) findings flagged roe_blocked in details_json."""
    eng = _write_engagement(isolate_settings["engagements_dir"])
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200

    # (1) blocked technique — notes carries the unblock requirement.
    assert client.post(
        f"{BASE}/blocked-techniques",
        json={
            "technique_key": "bfla:finding:va-101",
            "technique": "BFLA",
            "target_kind": "finding",
            "target_ref": "VA-101",
            "reason": "needs org-admin group account to reach role-grant",
            "retry_state": "pending",
            "notes": "retry after VA-101 yields an org-admin session token",
        },
    ).status_code == 201

    # (2) a no-signal probe run (non-covering) + a covering 'tested' run that
    # must NOT appear in attempts.
    assert client.post(
        f"{BASE}/probe-runs",
        json={
            "attack_family": "sqli",
            "tool_name": "sqlmap",
            "agent_name": "vulnerability-analyst",
            "result_status": "no-signal",
            "target_host": "example.com",
            "target_path": "/search",
        },
    ).status_code == 201
    assert client.post(
        f"{BASE}/probe-runs",
        json={
            "attack_family": "xss",
            "tool_name": "dalfox",
            "result_status": "tested",
            "target_host": "example.com",
            "target_path": "/covered",
        },
    ).status_code == 201

    # (3) a roe_blocked finding + an ordinary finding (no key) + a finding
    # carrying roe_blocked:false — value-aware json_extract must exclude the
    # last two (a value-blind LIKE '%roe_blocked%' would wrongly bucket VA-052).
    _seed_finding(client, eng, "VA-050", details={"roe_blocked": True, "block_reason": "policy forbids the final destructive step"})
    _seed_finding(client, eng, "VA-051", details={})
    _seed_finding(client, eng, "VA-052", details={"roe_blocked": False})

    attempts = client.get(f"{BASE}/resume-brief").json()["attempts"]

    blocked = attempts["blocked_techniques"]
    assert [row["technique"] for row in blocked] == ["BFLA"]
    assert attempts["blocked_techniques_count"] == 1
    # notes (the documented unblock-requirement home) is projected into the brief.
    assert blocked[0]["notes"] == "retry after VA-101 yields an org-admin session token"

    probes = attempts["noncovering_probe_runs"]
    assert [row["result_status"] for row in probes] == ["no-signal"]
    assert attempts["noncovering_probe_runs_count"] == 1
    assert all(row["result_status"] not in ("tested", "signal") for row in probes)

    roe = attempts["roe_blocked_findings"]
    roe_slugs = {row["slug"] for row in roe}
    assert "VA-050" in roe_slugs
    assert "VA-051" not in roe_slugs  # no roe_blocked key
    assert "VA-052" not in roe_slugs  # roe_blocked:false must NOT match
    assert attempts["roe_blocked_findings_count"] == 1
    assert attempts["roe_blocked_findings_count"] == len(roe)


def test_resume_brief_chain_required_bucket_is_value_aware(client, isolate_settings) -> None:
    """The findings.chain_required bucket uses a value-aware json_extract, not a
    value-blind LIKE '%chain_required%'. The canonical record-finding example ships
    chain_required:false, so an ordinary finding carrying the key set false (and a
    finding with no key) must NOT be bucketed as chain-gated; only chain_required:true
    lands. Mirrors _finding_summary's bool(details.get('chain_required'))."""
    eng = _write_engagement(isolate_settings["engagements_dir"])
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200

    _seed_finding(client, eng, "VA-090", details={"chain_required": True, "chain_rationale": "needs prior auth-bypass"})
    _seed_finding(client, eng, "VA-091", details={"chain_required": False})
    _seed_finding(client, eng, "VA-092", details={})

    chain = client.get(f"{BASE}/resume-brief").json()["findings"]["chain_required"]
    chain_slugs = {row["slug"] for row in chain}
    assert "VA-090" in chain_slugs           # chain_required:true
    assert "VA-091" not in chain_slugs       # chain_required:false must NOT match
    assert "VA-092" not in chain_slugs       # no chain_required key
    assert all(row["chain_required"] for row in chain)


def test_resume_brief_attempts_since_filters(client, isolate_settings) -> None:
    """The attempts lists are since-filtered like the other bounded worklists —
    a future cutoff yields nothing."""
    eng = _write_engagement(isolate_settings["engagements_dir"])
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200
    assert client.post(
        f"{BASE}/blocked-techniques",
        json={
            "technique_key": "ssrf:host:api",
            "technique": "SSRF",
            "target_kind": "host",
            "target_ref": "api.example.com",
            "reason": "wall",
        },
    ).status_code == 201
    assert client.post(
        f"{BASE}/probe-runs",
        json={"attack_family": "sqli", "tool_name": "sqlmap", "result_status": "blocked", "target_host": "example.com"},
    ).status_code == 201
    _seed_finding(client, eng, "VA-060", details={"roe_blocked": True})

    future = client.get(f"{BASE}/resume-brief", params={"since": "2099-01-01T00:00:00Z"}).json()["attempts"]
    assert future["blocked_techniques"] == []
    assert future["noncovering_probe_runs"] == []
    assert future["roe_blocked_findings"] == []


def test_finding_links_generic_unblocked_by(client, isolate_settings) -> None:
    """The generic POST /findings/{slug}/links accepts an arbitrary link_kind —
    the first-class unblock path links a blocked finding to the finding that
    would satisfy the wall."""
    eng = _write_engagement(isolate_settings["engagements_dir"])
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200
    _seed_finding(client, eng, "VA-070", details={"roe_blocked": True, "block_reason": "needs admin session"})
    _seed_finding(client, eng, "VA-071", details={})  # the finding that would unblock VA-070

    link = client.post(
        f"{BASE}/findings/VA-070/links",
        json={
            "link_kind": "unblocked_by",
            "target_kind": "finding",
            "target_ref": "VA-071",
            "notes": "VA-071 yields the admin session that unblocks VA-070",
        },
    )
    assert link.status_code == 200, link.text
    body = link.json()
    assert body["link_kind"] == "unblocked_by"
    assert body["target_kind"] == "finding"
    assert body["target_ref"] == "VA-071"
    assert body.get("id")


def test_finding_links_generic_rejects_root_cause_kind(client, isolate_settings) -> None:
    """link_kind=root_cause is refused on the generic route (must go through
    PUT /root-cause) — the client-side guard mirrors this."""
    eng = _write_engagement(isolate_settings["engagements_dir"])
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200
    _seed_finding(client, eng, "VA-080", details={})
    _seed_finding(client, eng, "VA-081", details={})

    resp = client.post(
        f"{BASE}/findings/VA-080/links",
        json={"link_kind": "root_cause", "target_kind": "finding", "target_ref": "VA-081"},
    )
    assert resp.status_code == 400, resp.text
