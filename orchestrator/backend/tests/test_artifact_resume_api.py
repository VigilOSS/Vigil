from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from app import db as db_module
from app.services.assessment_memory import _recommended_actions


ENGAGEMENT_KEY = "2026-05-19-120000-memory"
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
                "created_at": "2026-05-19T12:00:00Z",
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


def _register_note(client, path: str, **kwargs) -> dict:
    """POST /artifacts to register a note explicitly.

    The auto-walking ``artifacts/sync`` endpoint was removed; tests that
    previously relied on sync to bulk-index ``notes/``-style files now
    register each file with this helper to mirror what specialists do via
    ``vigil assess artifact register``.
    """
    payload = {"path": path, "kind": "note"}
    payload.update(kwargs)
    response = client.post(f"{BASE}/artifacts", json=payload)
    assert response.status_code == 201, response.text
    return response.json()


def _seed_finding(client, eng: Path, slug: str = "VA-047") -> None:
    (eng / "notes").mkdir(parents=True, exist_ok=True)
    (eng / "notes" / "VA-047-note.md").write_text(
        "VA-047 exploit chronology and OIDC static state notes",
        encoding="utf-8",
    )
    response = client.post(
        f"{BASE}/findings",
        json={
            "slug": slug,
            "title": "OIDC static state replay",
            "severity": "high",
            "workflow_status": "active",
            "verification_state": "verified",
            "verification_disposition": "confirmed",
            "canonical_location": "https://example.com/login",
            "summary": "Static state can be replayed",
            "evidence_ref": "notes/VA-047-note.md",
            "source_name": "vulnerability-analyst",
            "details": {
                "cvss_score": 8.1,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                "steps_to_reproduce": ["capture state", "replay state"],
                "remediation": "Bind state to a nonce",
                "impact": "Account takeover path",
                "evidence": "Captured request in linked artifact",
            },
        },
    )
    assert response.status_code == 201, response.text


def test_artifact_register_search_and_get(client, isolate_settings) -> None:
    """Registering a note explicitly indexes its preview for FTS and a
    finding-scoped search ranks the linked artifact first.

    Replaces the prior sync-driven version: with auto-walk gone, callers
    register each note via POST /artifacts (or via the implicit
    register-on-finding-write that fires when ``evidence_ref`` is set).
    """
    eng = _write_engagement(isolate_settings["engagements_dir"])
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200
    _seed_finding(client, eng)
    # _seed_finding posts a finding with evidence_ref=notes/VA-047-note.md,
    # which triggers register_reference_if_local — no explicit register call
    # needed for the linked evidence file.

    search = client.get(f"{BASE}/artifacts/search", params={"q": "VA047"})
    assert search.status_code == 200, search.text
    rows = search.json()
    assert any(row["relative_path"] == "notes/VA-047-note.md" for row in rows)
    assert all("indexed_text" not in row for row in rows)

    artifact_id = next(row["id"] for row in rows if row["relative_path"] == "notes/VA-047-note.md")
    detail = client.get(f"{BASE}/artifacts/{artifact_id}")
    assert detail.status_code == 200, detail.text
    assert "OIDC static state" in detail.json()["content"]

    # A note that mentions the finding slug but is not the linked evidence:
    # register it without --finding so it stays unlinked from VA-047.
    (eng / "notes" / "incidental-VA-047.md").write_text(
        "Incidental VA-047 mention that should not outrank the linked evidence artifact.",
        encoding="utf-8",
    )
    _register_note(client, "notes/incidental-VA-047.md")
    by_finding = client.get(f"{BASE}/artifacts/search", params={"finding": "VA047"})
    assert by_finding.status_code == 200, by_finding.text
    # The explicitly finding-linked artifact must rank ahead of the incidental
    # name-only match.
    assert by_finding.json()[0]["relative_path"] == "notes/VA-047-note.md"


def test_resume_brief_artifacts_omit_indexed_text(client, isolate_settings) -> None:
    eng = _write_engagement(isolate_settings["engagements_dir"])
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200
    _seed_finding(client, eng)

    brief = client.get(f"{BASE}/resume-brief", params={"q": "OIDC"})
    assert brief.status_code == 200, brief.text
    artifacts = brief.json()["artifacts"]
    assert artifacts
    assert all("indexed_text" not in row for row in artifacts)


def test_artifact_register_supports_blue_ir_artifact_roots(client, isolate_settings) -> None:
    eng = _write_engagement(isolate_settings["engagements_dir"])
    evidence_path = eng / "ir" / "evidence" / "network" / "beacons.tsv"
    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    evidence_path.write_text("src\tdest\tscore\n10.0.0.8\tc2.example\t0.98\n", encoding="utf-8")
    report_path = eng / "ir" / "reports" / "incident.md"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text("# Incident Report\n", encoding="utf-8")
    alert_path = eng / "ir" / "alerts" / "raw-alert.txt"
    alert_path.parent.mkdir(parents=True, exist_ok=True)
    alert_path.write_text("Suspicious sign-in\n", encoding="utf-8")

    for relative_path in (
        "ir/evidence/network/beacons.tsv",
        "ir/reports/incident.md",
        "ir/alerts/raw-alert.txt",
    ):
        registered = client.post(f"{BASE}/artifacts", json={"path": relative_path})
        assert registered.status_code == 201, registered.text

    search = client.get(f"{BASE}/artifacts/search", params={"q": "beacons"})
    assert search.status_code == 200, search.text
    paths = {row["relative_path"] for row in search.json()}
    assert "ir/evidence/network/beacons.tsv" in paths
    all_rows = client.get(f"{BASE}/artifacts/search", params={"limit": 1000})
    indexed = {row["relative_path"]: row["kind"] for row in all_rows.json()}
    assert {
        "ir/evidence/network/beacons.tsv": "ir-evidence",
        "ir/reports/incident.md": "ir-report",
        "ir/alerts/raw-alert.txt": "ir-alert",
    }.items() <= indexed.items()


def test_artifact_refresh_updates_missing_registered_files(client, isolate_settings) -> None:
    eng = _write_engagement(isolate_settings["engagements_dir"])
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200
    _seed_finding(client, eng)

    search = client.get(f"{BASE}/artifacts/search", params={"q": "OIDC"})
    artifact_id = next(row["id"] for row in search.json() if row["relative_path"] == "notes/VA-047-note.md")
    (eng / "notes" / "VA-047-note.md").unlink()

    readiness_before = client.get(f"{BASE}/report-readiness")
    assert readiness_before.status_code == 200, readiness_before.text
    assert readiness_before.json()["ready"] is True, readiness_before.json()

    refresh = client.post(f"{BASE}/artifacts/refresh")
    assert refresh.status_code == 200, refresh.text
    assert refresh.json()["missing"] >= 1

    detail = client.get(f"{BASE}/artifacts/{artifact_id}")
    assert detail.status_code == 200, detail.text
    assert detail.json()["present"] is False
    readiness_after = client.get(f"{BASE}/report-readiness")
    assert any(
        blocker["kind"] == "finding_evidence_missing_artifact" and blocker["slug"] == "VA-047"
        for blocker in readiness_after.json()["blockers"]
    )


def test_artifact_register_preserves_existing_legacy_finding_slug(client, isolate_settings) -> None:
    eng = _write_engagement(isolate_settings["engagements_dir"])
    (eng / "notes").mkdir(parents=True, exist_ok=True)
    (eng / "notes" / "legacy-note.md").write_text("legacy finding evidence", encoding="utf-8")
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200

    with sqlite3.connect(str(db_module.database_path())) as connection:
        engagement_id = connection.execute(
            "SELECT id FROM engagements WHERE key = ?",
            (ENGAGEMENT_KEY,),
        ).fetchone()[0]
        connection.execute(
            """
            INSERT INTO assessment_findings (
                engagement_id, slug, title, severity, status,
                verification_state, verification_disposition, canonical_location,
                source_name, summary, evidence_ref
            ) VALUES (?, 'legacy-title-slug', 'Legacy row', 'medium', 'active',
                'verified', 'confirmed', 'https://example.com/legacy',
                'legacy-import', 'Legacy row imported from an older database.',
                'notes/legacy-note.md')
            """,
            (engagement_id,),
        )
        connection.commit()

    registered = client.post(
        f"{BASE}/artifacts",
        json={
            "path": "notes/legacy-note.md",
            "kind": "note",
            "related_finding_slug": "legacy-title-slug",
        },
    )
    assert registered.status_code == 201, registered.text
    assert registered.json()["related_finding_slug"] == "legacy-title-slug"

    readiness = client.get(f"{BASE}/report-readiness")
    assert readiness.status_code == 200, readiness.text
    assert not any(
        blocker.get("kind") == "unlinked_markdown_note"
        and blocker.get("path") == "notes/legacy-note.md"
        for blocker in readiness.json()["blockers"]
    )


def test_artifact_register_preserves_explicit_kind_on_bare_reregister(client, isolate_settings) -> None:
    """A bare re-register (no kind/media_type) must not clobber explicit ones.

    Regression: the ON CONFLICT upsert guarded kind with
    ``COALESCE(NULLIF(excluded.kind, ''), ...)``, but ``excluded.kind`` carried
    the ``_guess_kind()`` result, which is never empty (it falls back to a
    path-inferred kind or ``artifact``). So the guard never fired and a bare
    ``artifact register <path>`` silently rewrote an explicit kind such as
    ``verification-narrative`` to the path-inferred default (``note``), making
    kind-filtered search and report/export paths miss the artifact.
    """
    eng = _write_engagement(isolate_settings["engagements_dir"])
    (eng / "notes").mkdir(parents=True, exist_ok=True)
    (eng / "notes" / "va-047-proof.md").write_text("baseline vs payload proof", encoding="utf-8")
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200

    # First registration carries an explicit kind that differs from what
    # _guess_kind() infers for a notes/ path ("note"), plus an explicit
    # media_type that differs from the mimetypes guess for .md.
    first = client.post(
        f"{BASE}/artifacts",
        json={
            "path": "notes/va-047-proof.md",
            "kind": "verification-narrative",
            "media_type": "application/x-vigil-proof",
        },
    )
    assert first.status_code == 201, first.text
    assert first.json()["kind"] == "verification-narrative"
    assert first.json()["media_type"] == "application/x-vigil-proof"

    # Bare re-register: no kind / no media_type (CLI --kind defaults to "").
    bare = client.post(f"{BASE}/artifacts", json={"path": "notes/va-047-proof.md"})
    assert bare.status_code == 201, bare.text
    assert bare.json()["kind"] == "verification-narrative", "bare re-register clobbered explicit kind"
    assert bare.json()["media_type"] == "application/x-vigil-proof", "bare re-register clobbered explicit media_type"

    # Search filtered by the original kind must still find it.
    by_kind = client.get(f"{BASE}/artifacts/search", params={"kind": "verification-narrative"})
    assert by_kind.status_code == 200, by_kind.text
    assert any(
        row["relative_path"] == "notes/va-047-proof.md" for row in by_kind.json()
    ), "kind-filtered search missed the artifact after bare re-register"

    # An explicit new kind on re-register still overrides (last-writer-wins).
    relabel = client.post(
        f"{BASE}/artifacts",
        json={"path": "notes/va-047-proof.md", "kind": "scan-report"},
    )
    assert relabel.status_code == 201, relabel.text
    assert relabel.json()["kind"] == "scan-report"


def test_resume_brief_returns_bounded_operating_picture(client, isolate_settings) -> None:
    eng = _write_engagement(isolate_settings["engagements_dir"])
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200
    _seed_finding(client, eng)

    command = client.post(
        f"{BASE}/command-runs",
        json={
            "command": "curl https://example.com/login # VA-047",
            "argv": ["curl", "https://example.com/login"],
            "tool_name": "execute_command",
            "agent_name": "vulnerability-analyst",
            "phase": "consume-test",
            "return_code": 0,
            "timed_out": False,
            "success": True,
            "started_at": "2026-05-19T12:01:00Z",
            "completed_at": "2026-05-19T12:01:01Z",
            "duration_ms": 1000,
            "stdout": "large preview should not be included in resume brief",
            "stderr": "",
            "intent": "validate VA-047 OIDC state",
            "target_host": "example.com",
        },
    )
    assert command.status_code == 201, command.text
    dispatch = client.post(
        f"{BASE}/dispatches",
        json={
            "agent_id": "va-memory",
            "agent_role": "vulnerability-analyst",
            "task": "continue VA-047",
            "skills": "auth-bypass",
            "finding_slugs": ["VA-047"],
        },
    )
    assert dispatch.status_code == 201, dispatch.text
    handoff = client.post(
        f"{BASE}/dispatch-handoffs",
        json={
            "agent_id": "va-memory",
            "agent_role": "vulnerability-analyst",
            "summary": "VA-047 ready for report",
            "finding_slugs": ["VA-047"],
            "handoff_status": "ready",
        },
    )
    assert handoff.status_code == 201, handoff.text

    brief = client.get(f"{BASE}/resume-brief", params={"finding": "VA047"})
    assert brief.status_code == 200, brief.text
    body = brief.json()
    assert body["target_finding"]["slug"] == "VA-047"
    assert body["command_runs"][0]["stdout_preview"] == ""
    assert any(row["relative_path"] == "notes/VA-047-note.md" for row in body["artifacts"])
    assert any("command-run list" in row["command"] for row in body["recommended_next_actions"])
    assert any(
        row["entity_kind"] == "command_run" and row["command"] == f"vigil assess command-run get {command.json()['id']}"
        for row in body["recommended_next_actions"]
    )
    artifact_id = next(row["id"] for row in body["artifacts"] if row["relative_path"] == "notes/VA-047-note.md")
    assert any(
        row["entity_kind"] == "artifact" and row["command"] == f"vigil assess artifact get {artifact_id}"
        for row in body["recommended_next_actions"]
    )


def test_resume_brief_surfaces_section_rolls_up_by_status_and_type(client, isolate_settings) -> None:
    """build_resume_brief.surfaces rolls up every surface by status and by
    status×type, and samples the most actionable still-open surfaces with the
    discovered/partially-covered-before-deferred priority (gap #1 root fix)."""
    _write_engagement(isolate_settings["engagements_dir"])
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200

    surfaces = [
        {"surface_type": "auth_entry", "target_descriptor": "https://example.com/login", "status": "discovered"},
        {"surface_type": "object_reference", "target_descriptor": "https://example.com/api/orders/{id}", "status": "discovered"},
        {"surface_type": "api_documentation", "target_descriptor": "https://example.com/swagger.json", "status": "covered", "rationale": "fully reviewed"},
        {"surface_type": "file_handling", "target_descriptor": "https://example.com/upload", "status": "deferred", "rationale": "out of time-box"},
    ]
    for payload in surfaces:
        resp = client.post(f"{BASE}/surfaces", json=payload)
        assert resp.status_code == 201, resp.text
    # `partially-covered` is not a create-time status (the POST Literal omits it);
    # reach it the way operators do — discover, then PATCH with a followup.
    partial = client.post(
        f"{BASE}/surfaces",
        json={"surface_type": "dynamic_render", "target_descriptor": "https://example.com/render", "status": "discovered"},
    )
    assert partial.status_code == 201, partial.text
    patched = client.patch(
        f"{BASE}/surfaces/{partial.json()['id']}",
        json={"status": "partially-covered", "rationale": "SSTI ruled out; XSS sink still pending", "followup_condition": "test the XSS sink"},
    )
    assert patched.status_code == 200, patched.text

    section = client.get(f"{BASE}/resume-brief").json()["surfaces"]
    assert section["total"] == 5
    assert section["open_count"] == 4  # covered is retired; discovered×2 + deferred + partially-covered stay open
    assert section["by_status"] == {"discovered": 2, "covered": 1, "deferred": 1, "partially-covered": 1}

    rollup = {(e["status"], e["surface_type"]): e["count"] for e in section["by_status_type"]}
    assert rollup[("discovered", "auth_entry")] == 1
    assert rollup[("covered", "api_documentation")] == 1
    assert rollup[("partially-covered", "dynamic_render")] == 1

    top = section["top_uncovered"]
    assert len(top) == 4  # the covered surface is never sampled
    assert all(entry["status"] != "covered" for entry in top)
    # All three priority tiers, in order: discovered (0) < partially-covered (1) < deferred (2).
    assert [entry["status"] for entry in top] == ["discovered", "discovered", "partially-covered", "deferred"]
    descriptors = {entry["target_descriptor"] for entry in top}
    assert "https://example.com/upload" in descriptors


def test_resume_brief_work_buffer_counts_pending_by_gf_bucket(client, isolate_settings) -> None:
    """build_resume_brief.work_buffer counts pending assessment_work_items keyed
    by cluster_key (the gf-bucket identity) and excludes non-pending / terminal
    rows. Reads the real dispatch queue folded into the backend ledger (ADR 0013),
    not a coverage-item proxy."""
    _write_engagement(isolate_settings["engagements_dir"])
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200

    def _observe(url, cluster, *, status="pending", terminal_reason=""):
        wi = {"case_type": "api", "cluster_key": cluster, "status": status}
        if terminal_reason:
            wi["terminal_reason"] = terminal_reason
        resp = client.post(
            f"{BASE}/request-observations",
            json={"url": url, "method": "GET", "work_item": wi},
        )
        assert resp.status_code == 201, resp.text

    _observe("https://example.com/api/a", "gf:idor")
    _observe("https://example.com/api/b", "gf:idor")
    _observe("https://example.com/api/c", "gf:ssrf")
    # A deferred/terminal row is excluded from the pending work buffer.
    _observe("https://example.com/api/d", "gf:sqli", status="skipped", terminal_reason="low-signal")

    work_buffer = client.get(f"{BASE}/resume-brief").json()["work_buffer"]
    assert work_buffer["pending_total"] == 3  # the skipped sqli row is excluded
    assert work_buffer["by_bucket"] == {"gf:idor": 2, "gf:ssrf": 1}
    # most_common ordering: the heaviest bucket comes first
    assert list(work_buffer["by_bucket"].keys())[0] == "gf:idor"
    assert "gf:sqli" not in work_buffer["by_bucket"]


def test_resume_brief_lists_coverage_and_read_first_intel_notes(client, isolate_settings) -> None:
    """build_resume_brief.intel.read_first_notes surfaces notes tagged coverage /
    read-first as bounded title pointers, and ignores untagged notes."""
    _write_engagement(isolate_settings["engagements_dir"])
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200

    notes_base = f"/engagements/{ENGAGEMENT_KEY}/intel/notes"
    posted = [
        {"title": "Coverage map: untested admin endpoints", "tags": ["coverage"]},
        {"title": "Read this first: known WAF bypass for /api", "tags": ["read-first", "waf"]},
        {"title": "Plain scratch note", "tags": ["misc"]},
    ]
    for payload in posted:
        resp = client.post(notes_base, json=payload)
        assert resp.status_code == 201, resp.text

    read_first = client.get(f"{BASE}/resume-brief").json()["intel"]["read_first_notes"]
    titles = {row["title"] for row in read_first}
    assert "Coverage map: untested admin endpoints" in titles
    assert "Read this first: known WAF bypass for /api" in titles
    assert "Plain scratch note" not in titles
    # only the matching tags are projected (not the note's full tag set)
    waf_note = next(row for row in read_first if row["title"].startswith("Read this first"))
    assert waf_note["tags"] == ["read-first"]
    assert "waf" not in waf_note["tags"]

    # read_first_notes is a bounded list, so it is since-filtered like the other
    # intel worklists: a future cutoff yields nothing new.
    future = client.get(f"{BASE}/resume-brief", params={"since": "2099-01-01T00:00:00Z"}).json()
    assert future["intel"]["read_first_notes"] == []


def test_resume_brief_surfaces_open_high_cves(client, isolate_settings) -> None:
    """build_resume_brief.intel.open_high_cves surfaces cvss>=7 non-terminal CVEs
    only, sorted by score, with the linkage/component projection — and respects
    `since`. summary counts are an absolute snapshot (not since-filtered)."""
    _write_engagement(isolate_settings["engagements_dir"])
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200
    intel_base = f"/engagements/{ENGAGEMENT_KEY}/intel"

    # Open high CVE with a public PoC — must surface.
    assert client.post(
        f"{intel_base}/cves",
        json={
            "cve_id": "CVE-2019-0227",
            "affected_component": "Apache Axis 1.x",
            "cvss_score": 7.5,
            "poc_available": True,
            "validation_status": "poc_available_unverified",
            "source_name": "osint-analyst",
        },
    ).status_code == 201
    # Another open high CVE (higher score) — must sort first.
    assert client.post(
        f"{intel_base}/cves",
        json={
            "cve_id": "CVE-2022-23855",
            "affected_component": "Eurekify",
            "cvss_score": 9.8,
            "validation_status": "unverified",
            "source_name": "osint-analyst",
        },
    ).status_code == 201
    # High CVE already dispositioned (ruled_out) — must NOT surface.
    assert client.post(
        f"{intel_base}/cves",
        json={
            "cve_id": "CVE-2024-36522",
            "affected_component": "Apache Wicket",
            "cvss_score": 9.8,
            "validation_status": "ruled_out",
            "source_name": "osint-analyst",
        },
    ).status_code == 201
    # Low-severity CVE (below cvss 7) — must NOT surface.
    assert client.post(
        f"{intel_base}/cves",
        json={
            "cve_id": "CVE-2017-9394",
            "affected_component": "CA Identity Governance",
            "cvss_score": 5.4,
            "validation_status": "unverified",
            "source_name": "osint-analyst",
        },
    ).status_code == 201

    body = client.get(f"{BASE}/resume-brief").json()
    intel = body["intel"]
    assert intel["summary"]["cves"] == 4  # snapshot count, all rows
    open_ids = [r["cve_id"] for r in intel["open_high_cves"]]
    assert open_ids == ["CVE-2022-23855", "CVE-2019-0227"], open_ids  # sorted desc, open+high only
    axis = intel["open_high_cves"][1]
    assert axis["linked_finding_slug"] == ""
    assert axis["affected_component"] == "Apache Axis 1.x"
    assert intel["open_leads"] == []  # stubbed until lead lifecycle lands

    # `since` with a Z (offset-aware, the documented format) must NOT crash
    # against naive intel CURRENT_TIMESTAMP rows, and must filter correctly.
    future = client.get(f"{BASE}/resume-brief", params={"since": "2099-01-01T00:00:00Z"})
    assert future.status_code == 200, future.text
    assert future.json()["intel"]["open_high_cves"] == []
    assert future.json()["intel"]["summary"]["cves"] == 4  # summary stays absolute
    past = client.get(f"{BASE}/resume-brief", params={"since": "2000-01-01T00:00:00Z"})
    assert past.status_code == 200, past.text
    assert [c["cve_id"] for c in past.json()["intel"]["open_high_cves"]] == [
        "CVE-2022-23855",
        "CVE-2019-0227",
    ]


def test_resume_brief_surfaces_open_leads(client, isolate_settings) -> None:
    """build_resume_brief.intel.open_leads surfaces only open/in_progress leads
    (not terminal ones, not plain reference notes), projected to title+status."""
    _write_engagement(isolate_settings["engagements_dir"])
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200
    intel_base = f"/engagements/{ENGAGEMENT_KEY}/intel"

    assert client.post(
        f"{intel_base}/notes",
        json={"title": "Lead: Axis SSRF untested", "lead_status": "open"},
    ).status_code == 201
    assert client.post(
        f"{intel_base}/notes",
        json={"title": "Lead: host-header SSRF hypothesis", "lead_status": "in_progress"},
    ).status_code == 201
    # Terminal lead — must NOT surface.
    assert client.post(
        f"{intel_base}/notes",
        json={"title": "Lead: jQuery XSS", "lead_status": "ruled_out"},
    ).status_code == 201
    # Plain reference note — must NOT surface.
    assert client.post(
        f"{intel_base}/notes", json={"title": "Reference: tech stack"}
    ).status_code == 201

    intel = client.get(f"{BASE}/resume-brief").json()["intel"]
    titles = sorted(row["title"] for row in intel["open_leads"])
    assert titles == ["Lead: Axis SSRF untested", "Lead: host-header SSRF hypothesis"], titles
    # id is included so the operator can disposition the exact row via update-intel.
    assert all(set(row) == {"id", "title", "lead_status"} for row in intel["open_leads"])
    assert all(isinstance(row["id"], int) for row in intel["open_leads"])
    assert intel["summary"]["notes"] == 4  # snapshot count includes all notes

    # Z-suffixed (offset-aware) cutoff must not crash against naive timestamps.
    future = client.get(f"{BASE}/resume-brief", params={"since": "2099-01-01T00:00:00Z"})
    assert future.status_code == 200, future.text
    assert future.json()["intel"]["open_leads"] == []


def test_intel_readiness_red_engagement(client, isolate_settings) -> None:
    """GET /intel/readiness buckets open PoC-backed high CVEs, exploited-but-
    unlinked CVEs, dangling linked_finding_slug refs, and open leads. Advisory."""
    eng = _write_engagement(isolate_settings["engagements_dir"])
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200
    _seed_finding(client, eng, slug="VA-047")  # a real active finding to link to
    intel_base = f"/engagements/{ENGAGEMENT_KEY}/intel"

    def cve(**kw):
        assert client.post(f"{intel_base}/cves", json=kw).status_code == 201, kw

    # open PoC-backed high CVE -> open_high_cves
    cve(cve_id="CVE-2019-0227", affected_component="Apache Axis 1.x", cvss_score=7.5,
        poc_available=True, validation_status="poc_available_unverified")
    # high but NO poc -> excluded from the (stricter) advisory
    cve(cve_id="CVE-2022-23855", affected_component="Eurekify", cvss_score=9.8,
        poc_available=False, validation_status="unverified")
    # exploited with no linked finding -> exploited_unlinked_cves
    cve(cve_id="CVE-2020-0001", affected_component="X", cvss_score=8.0, validation_status="exploited")
    # exploited linked to a REAL finding -> neither unlinked nor dangling
    cve(cve_id="CVE-2020-0002", affected_component="Y", cvss_score=8.0,
        validation_status="exploited", linked_finding_slug="VA-047")
    # exploited linked to a MISSING finding -> dangling (missing)
    cve(cve_id="CVE-2020-0003", affected_component="Z", cvss_score=8.0,
        validation_status="exploited", linked_finding_slug="VA-999")
    assert client.post(f"{intel_base}/notes", json={"title": "Lead: hosthdr SSRF", "lead_status": "open"}).status_code == 201

    data = client.get(f"{intel_base}/readiness").json()
    assert data["applicable"] is True
    assert [c["cve_id"] for c in data["open_high_cves"]] == ["CVE-2019-0227"]
    assert [c["cve_id"] for c in data["exploited_unlinked_cves"]] == ["CVE-2020-0001"]
    assert [d["cve_id"] for d in data["dangling_links"]] == ["CVE-2020-0003"]
    assert data["dangling_links"][0]["reason"] == "missing"
    assert [lead["title"] for lead in data["open_leads"]] == ["Lead: hosthdr SSRF"]
    # Every readiness row carries the backend id so update-intel <id> is directly runnable.
    for bucket in ("open_high_cves", "exploited_unlinked_cves", "dangling_links", "open_leads"):
        assert all(isinstance(row.get("id"), int) for row in data[bucket]), bucket


def test_intel_readiness_blue_engagement_not_applicable(client, isolate_settings) -> None:
    """Blue/IR engagements don't pursue CVE exploitation -> applicable=False,
    empty buckets, even with a high PoC CVE recorded."""
    key = "2026-05-19-130000-blue"
    eng = isolate_settings["engagements_dir"] / key
    (eng / "sessions").mkdir(parents=True, exist_ok=True)
    (eng / "engagement.json").write_text(
        json.dumps({
            "key": key, "target": "https://example.com", "hostname": "example.com",
            "created_at": "2026-05-19T13:00:00Z", "engagement_type": "blue",
        }),
        encoding="utf-8",
    )
    (eng / "scope.json").write_text(
        json.dumps({
            "hostname": "example.com", "hosts": ["example.com"], "status": "in_progress",
            "current_phase": "triage", "engagement_type": "blue",
        }),
        encoding="utf-8",
    )
    assert client.get(f"/engagements/{key}").status_code == 200
    intel_base = f"/engagements/{key}/intel"
    assert client.post(
        f"{intel_base}/cves",
        json={"cve_id": "CVE-2019-0227", "affected_component": "X", "cvss_score": 9.8,
              "poc_available": True, "validation_status": "unverified"},
    ).status_code == 201

    data = client.get(f"{intel_base}/readiness").json()
    assert data["applicable"] is False
    assert data["engagement_type"] == "blue"
    assert data["open_high_cves"] == []
    assert data["exploited_unlinked_cves"] == []
    assert data["open_leads"] == []


def test_resolve_linked_finding_join(client, isolate_settings) -> None:
    """intel.resolve_linked_finding reads linked_finding_slug back against
    assessment_findings — the read path for an otherwise write-only field."""
    from app.services import intel as intel_service

    eng = _write_engagement(isolate_settings["engagements_dir"])
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200
    _seed_finding(client, eng, slug="VA-047")  # workflow_status=active

    with sqlite3.connect(str(db_module.database_path())) as connection:
        engagement_id = connection.execute(
            "SELECT id FROM engagements WHERE key = ?", (ENGAGEMENT_KEY,)
        ).fetchone()[0]

    assert intel_service.resolve_linked_finding(engagement_id, "VA-047") == {
        "exists": True,
        "workflow_status": "active",
    }
    assert intel_service.resolve_linked_finding(engagement_id, "VA-999") == {
        "exists": False,
        "workflow_status": None,
    }
    assert intel_service.resolve_linked_finding(engagement_id, "") == {
        "exists": False,
        "workflow_status": None,
    }


def test_report_readiness_unlinked_markdown_notes_are_advisory(client, isolate_settings) -> None:
    eng = _write_engagement(isolate_settings["engagements_dir"])
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200
    _seed_finding(client, eng)
    (eng / "notes" / "scratch.md").write_text("Durable state that is not linked anywhere", encoding="utf-8")
    _register_note(client, "notes/scratch.md")

    readiness = client.get(f"{BASE}/report-readiness")
    assert readiness.status_code == 200, readiness.text
    body = readiness.json()
    assert not any(
        blocker["kind"] == "unlinked_markdown_note"
        for blocker in body["blockers"]
    ), body
    advisory = next(
        a for a in body["advisories"]
        if a["kind"] == "unlinked_markdown_note" and a["path"] == "notes/scratch.md"
    )
    assert "mark-scratch" in advisory["detail"]
    assert body["ready"] is True, body


def test_report_readiness_normalizes_absolute_evidence_ref(client, isolate_settings) -> None:
    eng = _write_engagement(isolate_settings["engagements_dir"])
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200
    evidence = eng / "notes" / "absolute-evidence.md"
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.write_text("absolute evidence path should index as relative", encoding="utf-8")
    created = client.post(
        f"{BASE}/findings",
        json={
            "slug": "VA-048",
            "title": "Absolute evidence ref",
            "severity": "medium",
            "workflow_status": "active",
            "verification_state": "verified",
            "verification_disposition": "confirmed",
            "canonical_location": "https://example.com/absolute",
            "summary": "A command-run emitted an absolute path to the evidence artifact.",
            "evidence_ref": str(evidence),
            "source_name": "vulnerability-analyst",
            "details": {
                "cvss_score": 5.4,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
                "steps_to_reproduce": ["capture output", "register artifact"],
                "remediation": "Normalize artifact references before readiness checks",
                "impact": "False readiness blocker",
                "evidence": "Absolute command-run artifact path",
            },
        },
    )
    assert created.status_code == 201, created.text
    # The POST /findings call above triggers register_reference_if_local on the
    # absolute evidence_ref, which normalizes the path and indexes the note.

    readiness = client.get(f"{BASE}/report-readiness")
    assert readiness.status_code == 200, readiness.text
    blockers = readiness.json()["blockers"]
    assert not any(
        blocker["kind"] == "finding_evidence_unindexed" and blocker["slug"] == "VA-048"
        for blocker in blockers
    )


def test_report_readiness_validates_evidence_ref_when_artifact_id_is_present(client, isolate_settings) -> None:
    eng = _write_engagement(isolate_settings["engagements_dir"])
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200
    _seed_finding(client, eng)
    replacement = eng / "notes" / "replacement-evidence.md"
    replacement.write_text("replacement evidence file", encoding="utf-8")
    _register_note(client, "notes/replacement-evidence.md", related_finding_slug="VA-047")

    with sqlite3.connect(str(db_module.database_path())) as connection:
        connection.execute(
            "UPDATE assessment_findings SET evidence_ref = ? WHERE slug = ?",
            ("notes/replacement-evidence.md", "VA-047"),
        )
        connection.commit()

    readiness = client.get(f"{BASE}/report-readiness")
    assert readiness.status_code == 200, readiness.text
    blockers = readiness.json()["blockers"]
    mismatch = next(
        blocker
        for blocker in blockers
        if blocker["kind"] == "finding_evidence_artifact_mismatch" and blocker["slug"] == "VA-047"
    )
    assert "vigil assess finding update VA-047 --evidence-ref notes/replacement-evidence.md" in mismatch["detail"]


def test_mark_scratch_clears_unlinked_markdown_advisory(client, isolate_settings) -> None:
    eng = _write_engagement(isolate_settings["engagements_dir"])
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200
    _seed_finding(client, eng)
    (eng / "notes" / "scratch.md").write_text("operator scratch", encoding="utf-8")
    _register_note(client, "notes/scratch.md")

    readiness_before = client.get(f"{BASE}/report-readiness")
    before = readiness_before.json()
    assert not any(
        b["kind"] == "unlinked_markdown_note" for b in before["blockers"]
    ), before
    note_advisory = next(
        a for a in before["advisories"]
        if a["kind"] == "unlinked_markdown_note" and a["path"] == "notes/scratch.md"
    )
    # LLM can fix without searching docs.
    assert "artifact register" in note_advisory["detail"]
    assert "mark-scratch" in note_advisory["detail"]

    flagged = client.post(
        f"{BASE}/artifacts/scratch-by-path",
        json={"path": "notes/scratch.md", "scratch": True},
    )
    assert flagged.status_code == 200, flagged.text
    assert flagged.json()["scratch"] is True

    readiness_after = client.get(f"{BASE}/report-readiness")
    assert readiness_after.status_code == 200, readiness_after.text
    assert not any(
        a["kind"] == "unlinked_markdown_note" and a["path"] == "notes/scratch.md"
        for a in readiness_after.json()["advisories"]
    )


def test_mark_scratch_under_prefix_clears_many_blockers(client, isolate_settings) -> None:
    eng = _write_engagement(isolate_settings["engagements_dir"])
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200
    _seed_finding(client, eng)
    scratch_dir = eng / "notes" / "scratch"
    scratch_dir.mkdir(parents=True, exist_ok=True)
    for name in ("a.md", "b.md", "c.md"):
        (scratch_dir / name).write_text("scratch", encoding="utf-8")
        _register_note(client, f"notes/scratch/{name}")

    bulk = client.post(
        f"{BASE}/artifacts/scratch-under",
        json={"prefix": "notes/scratch/", "scratch": True},
    )
    assert bulk.status_code == 200, bulk.text
    body = bulk.json()
    assert body["matched"] == 3
    assert set(body["updated"]) == {"notes/scratch/a.md", "notes/scratch/b.md", "notes/scratch/c.md"}

    readiness = client.get(f"{BASE}/report-readiness")
    body = readiness.json()
    assert not any(
        b["kind"] == "unlinked_markdown_note" and b["path"].startswith("notes/scratch/")
        for b in body["blockers"]
    )
    assert not any(
        a["kind"] == "unlinked_markdown_note" and a["path"].startswith("notes/scratch/")
        for a in body["advisories"]
    )


def test_mark_scratch_inline_registers_when_path_unindexed(client, isolate_settings) -> None:
    eng = _write_engagement(isolate_settings["engagements_dir"])
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200
    _seed_finding(client, eng)
    (eng / "notes" / "fresh.md").write_text("freshly-written note", encoding="utf-8")
    # No sync — exercise the inline register fallback.
    flagged = client.post(
        f"{BASE}/artifacts/scratch-by-path",
        json={"path": "notes/fresh.md", "scratch": True},
    )
    assert flagged.status_code == 200, flagged.text
    body = flagged.json()
    assert body["scratch"] is True
    assert body["relative_path"] == "notes/fresh.md"


def test_resume_brief_rejects_malformed_since(client, isolate_settings) -> None:
    _write_engagement(isolate_settings["engagements_dir"])
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200
    brief = client.get(f"{BASE}/resume-brief", params={"since": "today"})
    assert brief.status_code == 400, brief.text
    assert "not a valid ISO datetime" in brief.json()["detail"]


def test_mark_scratch_refuses_ghost_path(client, isolate_settings) -> None:
    _write_engagement(isolate_settings["engagements_dir"])
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200
    flagged = client.post(
        f"{BASE}/artifacts/scratch-by-path",
        json={"path": "notes/never-existed.md", "scratch": True},
    )
    assert flagged.status_code == 404, flagged.text
    assert "does not exist on disk" in flagged.json()["detail"]


def test_mark_scratch_under_escapes_like_metacharacters(client, isolate_settings) -> None:
    eng = _write_engagement(isolate_settings["engagements_dir"])
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200
    _seed_finding(client, eng)
    # Two directory siblings that would alias under unescaped LIKE: `_keep`
    # and `Xkeep` (the `_` is a SQL LIKE wildcard for any single char).
    keep = eng / "notes" / "_keep"
    other = eng / "notes" / "Xkeep"
    keep.mkdir(parents=True, exist_ok=True)
    other.mkdir(parents=True, exist_ok=True)
    (keep / "a.md").write_text("under _keep", encoding="utf-8")
    (other / "b.md").write_text("under Xkeep", encoding="utf-8")
    _register_note(client, "notes/_keep/a.md")
    _register_note(client, "notes/Xkeep/b.md")
    # Mark only the `_keep` prefix — must NOT match `Xkeep` even though `_` is a LIKE wildcard.
    bulk = client.post(
        f"{BASE}/artifacts/scratch-under",
        json={"prefix": "notes/_keep/", "scratch": True},
    )
    assert bulk.status_code == 200, bulk.text
    body = bulk.json()
    assert body["matched"] == 1
    assert body["updated"] == ["notes/_keep/a.md"]


def test_resume_brief_since_filters_old_findings(client, isolate_settings) -> None:
    eng = _write_engagement(isolate_settings["engagements_dir"])
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200
    _seed_finding(client, eng)
    # since after the seeded finding's updated_at should drop it
    brief = client.get(
        f"{BASE}/resume-brief",
        params={"since": "2099-01-01T00:00:00Z"},
    )
    assert brief.status_code == 200, brief.text
    body = brief.json()
    assert body["query"]["since"] == "2099-01-01T00:00:00Z"
    for bucket in ("active", "unreviewed", "verified", "killed", "merged", "chain_required"):
        assert body["findings"][bucket] == []


def test_resume_brief_stale_threshold_per_role(client, isolate_settings) -> None:
    _write_engagement(isolate_settings["engagements_dir"])
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200
    # Dispatch an exploit-developer 36h ago — under role default 48h, not stale.
    old_iso = "2026-05-18T00:00:00Z"  # ~36h before frozen test clock? actually deterministic check below
    dispatch = client.post(
        f"{BASE}/dispatches",
        json={
            "agent_id": "exp-old",
            "agent_role": "exploit-developer",
            "task": "deep chain",
            "skills": "exploit-playbook-authoring",
            "dispatched_at": old_iso,
        },
    )
    assert dispatch.status_code == 201, dispatch.text
    # Force --max-age-hours=12 — should now flag it stale regardless of role default.
    brief = client.get(
        f"{BASE}/resume-brief",
        params={"max_age_hours": "12"},
    )
    assert brief.status_code == 200, brief.text
    stale_ids = [s["agent_id"] for s in brief.json()["dispatches"].get("stale_in_progress_dispatches") or []]
    assert "exp-old" in stale_ids


def test_resume_brief_surfaces_terminal_handoff_less_dispatch(client, isolate_settings) -> None:
    """C4c: a dispatch that reads terminal (failed/aborted) with no handoff row
    is silent state-loss — pre-fix, `_recent_dispatch_picture` excluded any
    non-in-progress row before the handoff-gap check ever ran, so this case
    was structurally invisible to resume-brief. It must now appear in the new
    `terminal_no_handoff` list, while staying OUT of both `handoff_gaps` (which
    is in-progress-only, so a terminal row isn't double-reported) and
    `stale_in_progress_dispatches`."""
    _write_engagement(isolate_settings["engagements_dir"])
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200
    dispatch = client.post(
        f"{BASE}/dispatches",
        json={
            "agent_id": "recon-died-1",
            "agent_role": "recon-specialist",
            "task": "enumerate subdomains",
            "skills": "recon-methodology",
        },
    )
    assert dispatch.status_code == 201, dispatch.text
    closed = client.patch(
        f"{BASE}/dispatches/recon-died-1",
        json={"status": "failed", "completed_at": "2026-07-08T12:00:00Z"},
    )
    assert closed.status_code == 200, closed.text

    brief = client.get(f"{BASE}/resume-brief")
    assert brief.status_code == 200, brief.text
    dispatches = brief.json()["dispatches"]

    terminal_ids = [row["agent_id"] for row in dispatches.get("terminal_no_handoff") or []]
    assert "recon-died-1" in terminal_ids
    terminal_row = next(row for row in dispatches["terminal_no_handoff"] if row["agent_id"] == "recon-died-1")
    assert terminal_row["status"] == "failed"
    assert terminal_row["agent_role"] == "recon-specialist"

    # A terminal handoff-less dispatch is surfaced ONLY by terminal_no_handoff,
    # not double-reported in the in-progress-only handoff_gaps list.
    gap_ids = [row["agent_id"] for row in dispatches.get("handoff_gaps") or []]
    assert "recon-died-1" not in gap_ids

    stale_ids = [row["agent_id"] for row in dispatches.get("stale_in_progress_dispatches") or []]
    assert "recon-died-1" not in stale_ids


def test_recommended_actions_keep_lifecycle_items_before_inspect_cap() -> None:
    actions = _recommended_actions(
        finding="VA-047",
        agent_id="va-memory",
        artifacts=[{"id": 11}, {"id": 12}, {"id": 13}],
        command_matches=[{"id": 1}, {"id": 2}, {"id": 3}],
        stale_dispatches=[{"agent_id": "stale-va"}],
    )

    commands = [row["command"] for row in actions]
    assert len(actions) == 8
    assert "vigil assess agent render-handoff va-memory" in commands
    assert "vigil assess agent reconcile-stale --dry-run" in commands
