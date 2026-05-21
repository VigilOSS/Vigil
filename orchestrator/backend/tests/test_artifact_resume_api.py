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
    ``aith assess artifact register``.
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
    assert any("list-command-runs" in row["command"] for row in body["recommended_next_actions"])
    assert any(
        row["entity_kind"] == "command_run" and row["command"] == f"aith assess get-command-run {command.json()['id']}"
        for row in body["recommended_next_actions"]
    )
    artifact_id = next(row["id"] for row in body["artifacts"] if row["relative_path"] == "notes/VA-047-note.md")
    assert any(
        row["entity_kind"] == "artifact" and row["command"] == f"aith assess artifact get {artifact_id}"
        for row in body["recommended_next_actions"]
    )


def test_report_readiness_blocks_unlinked_markdown_notes(client, isolate_settings) -> None:
    eng = _write_engagement(isolate_settings["engagements_dir"])
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200
    _seed_finding(client, eng)
    (eng / "notes" / "scratch.md").write_text("Durable state that is not linked anywhere", encoding="utf-8")
    _register_note(client, "notes/scratch.md")

    readiness = client.get(f"{BASE}/report-readiness")
    assert readiness.status_code == 200, readiness.text
    blockers = readiness.json()["blockers"]
    assert any(
        blocker["kind"] == "unlinked_markdown_note" and blocker["path"] == "notes/scratch.md"
        for blocker in blockers
    )


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
    assert "aith assess update-finding VA-047 --evidence-ref notes/replacement-evidence.md" in mismatch["detail"]


def test_mark_scratch_clears_unlinked_markdown_blocker(client, isolate_settings) -> None:
    eng = _write_engagement(isolate_settings["engagements_dir"])
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200
    _seed_finding(client, eng)
    (eng / "notes" / "scratch.md").write_text("operator scratch", encoding="utf-8")
    _register_note(client, "notes/scratch.md")

    readiness_before = client.get(f"{BASE}/report-readiness")
    blockers_before = readiness_before.json()["blockers"]
    note_blocker = next(
        b for b in blockers_before
        if b["kind"] == "unlinked_markdown_note" and b["path"] == "notes/scratch.md"
    )
    # Blocker message must name the operator escape commands so a human or
    # LLM can fix without searching docs.
    assert "artifact register" in note_blocker["detail"]
    assert "mark-scratch" in note_blocker["detail"]

    flagged = client.post(
        f"{BASE}/artifacts/scratch-by-path",
        json={"path": "notes/scratch.md", "scratch": True},
    )
    assert flagged.status_code == 200, flagged.text
    assert flagged.json()["scratch"] is True

    readiness_after = client.get(f"{BASE}/report-readiness")
    assert readiness_after.status_code == 200, readiness_after.text
    blockers_after = readiness_after.json()["blockers"]
    assert not any(
        b["kind"] == "unlinked_markdown_note" and b["path"] == "notes/scratch.md"
        for b in blockers_after
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
    blockers = readiness.json()["blockers"]
    assert not any(
        b["kind"] == "unlinked_markdown_note" and b["path"].startswith("notes/scratch/")
        for b in blockers
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
    eng = _write_engagement(isolate_settings["engagements_dir"])
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
    assert "aith assess agent render-handoff va-memory" in commands
    assert "aith assess agent reconcile-stale --dry-run" in commands
