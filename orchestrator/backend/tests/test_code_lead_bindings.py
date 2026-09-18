"""B2: a prior-art lead bound to a code location, and the accounting that follows.

Research turns up "this project's SAML parser had a signature bypass in 2023".
Vigil already tracks that as a lead (``intel_notes.lead_status``); what it could
not do was say *where* in the reviewed source to look, turn that into analysis
work, or notice at completion time that the lead was never answered.

These tests own the three halves of that: the typed repository/file/line
binding, its generation identity as the snapshot advances, and the completeness
blocker a non-terminal bound lead raises. The lead primitive itself is
unchanged — a note with no ``lead_status`` is still a plain reference note and
a web/recon lead still owes nothing to the code track.
"""
from __future__ import annotations

from test_code_analysis_api import (
    _claim_file_for_analysis,
    _classify_file,
    _create_files,
    _create_repo,
    _refresh_repo_files,
    _source_hash,
    write_engagement,
)


def _base(engagement_key: str) -> str:
    return f"/engagements/{engagement_key}/assessment/code"


def _intel_base(engagement_key: str) -> str:
    return f"/engagements/{engagement_key}/intel"


def _record_lead(client, engagement_key: str, title: str, lead_status="open") -> dict:
    payload: dict[str, object] = {"title": title}
    if lead_status is not None:
        payload["lead_status"] = lead_status
    response = client.post(f"{_intel_base(engagement_key)}/notes", json=payload)
    assert response.status_code == 201, response.text
    return response.json()


def _bind(client, engagement_key: str, **payload):
    return client.post(f"{_base(engagement_key)}/lead-bindings", json=payload)


def _list_bindings(client, engagement_key: str, query: str = "") -> dict:
    suffix = f"?{query}" if query else ""
    response = client.get(f"{_base(engagement_key)}/lead-bindings{suffix}")
    assert response.status_code == 200, response.text
    return response.json()


def _readiness(client, engagement_key: str, target_phase: str = "complete") -> dict:
    response = client.get(
        f"{_base(engagement_key)}/readiness?target_phase={target_phase}"
    )
    assert response.status_code == 200, response.text
    return response.json()


def _blockers_by_code(readiness: dict) -> dict[str, dict]:
    return {blocker["code"]: blocker for blocker in readiness["blockers"]}


def _seed_repo_with_files(client, engagement_key: str, *, repo_role=None):
    repo = _create_repo(client, engagement_key, repo_key="app-repo", repo_role=repo_role)
    files = _create_files(client, engagement_key, int(repo["id"]))
    # Staging files promotes a second generation, so re-read the repo: the
    # binding is asserted against the CURRENT generation, not the empty one.
    refreshed = client.get(f"{_base(engagement_key)}/repos/{repo['id']}")
    assert refreshed.status_code == 200, refreshed.text
    return refreshed.json(), files


def _file_named(files: list[dict], file_path: str) -> dict:
    for row in files:
        if str(row["file_path"]) == file_path:
            return row
    raise AssertionError(f"{file_path} missing from {[r['file_path'] for r in files]}")


# ──────────────────────────────────────────────────────────────
# 1. The typed binding
# ──────────────────────────────────────────────────────────────


def test_binding_a_lead_records_repo_file_and_lines_at_the_current_generation(
    client, isolate_settings
):
    engagement_key = "2026-09-16-lead-bind-basic"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo, files = _seed_repo_with_files(client, engagement_key)
    parser = _file_named(files, "src/parser.py")
    lead = _record_lead(client, engagement_key, "SAML signature bypass, 2023")

    response = _bind(
        client,
        engagement_key,
        note_id=int(lead["id"]),
        repo_id=int(repo["id"]),
        file_path="src/parser.py",
        line_start=10,
        line_end=40,
        prior_art_ref="CVE-2023-9999",
        rationale="Upstream fix landed in the signature check.",
        bound_by="osint-analyst",
    )

    assert response.status_code == 201, response.text
    binding = response.json()
    assert binding["note_id"] == int(lead["id"])
    assert binding["repo_id"] == int(repo["id"])
    assert binding["file_id"] == int(parser["id"])
    assert binding["file_path"] == "src/parser.py"
    assert binding["repo_generation"] == int(repo["active_generation"])
    assert binding["file_hash"] == str(parser["file_hash"])
    assert binding["line_start"] == 10
    assert binding["line_end"] == 40
    assert binding["prior_art_ref"] == "CVE-2023-9999"
    assert binding["binding_status"] == "current"
    assert binding["lead_status"] == "open"
    assert binding["carries_obligation"] is True


def test_a_note_that_is_not_a_tracked_lead_cannot_be_bound_to_code(
    client, isolate_settings
):
    """A plain reference note stays a plain reference note.

    Binding asserts "there is code work here", which only a tracked lead can
    owe. Allowing it on a NULL-``lead_status`` note would quietly turn every
    scratch note into a completion obligation."""
    engagement_key = "2026-09-16-lead-bind-not-a-lead"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo, _files = _seed_repo_with_files(client, engagement_key)
    note = _record_lead(client, engagement_key, "Scratch note", lead_status=None)

    response = _bind(
        client,
        engagement_key,
        note_id=int(note["id"]),
        repo_id=int(repo["id"]),
        file_path="src/parser.py",
    )

    assert response.status_code == 400, response.text
    assert "lead_status" in response.json()["detail"]


def test_a_line_range_outside_the_bound_file_is_refused(client, isolate_settings):
    engagement_key = "2026-09-16-lead-bind-lines"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo, files = _seed_repo_with_files(client, engagement_key)
    parser = _file_named(files, "src/parser.py")
    lead = _record_lead(client, engagement_key, "Out of range prior art")

    beyond = int(parser["loc"]) + 5
    response = _bind(
        client,
        engagement_key,
        note_id=int(lead["id"]),
        repo_id=int(repo["id"]),
        file_path="src/parser.py",
        line_start=1,
        line_end=beyond,
    )

    assert response.status_code == 400, response.text
    assert str(parser["loc"]) in response.json()["detail"]


def test_rebinding_the_same_lead_and_file_refines_one_binding(client, isolate_settings):
    engagement_key = "2026-09-16-lead-bind-refine"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo, _files = _seed_repo_with_files(client, engagement_key)
    lead = _record_lead(client, engagement_key, "Refined prior art")

    first = _bind(
        client,
        engagement_key,
        note_id=int(lead["id"]),
        repo_id=int(repo["id"]),
        file_path="src/parser.py",
        line_start=1,
        line_end=10,
    )
    assert first.status_code == 201, first.text
    second = _bind(
        client,
        engagement_key,
        note_id=int(lead["id"]),
        repo_id=int(repo["id"]),
        file_path="src/parser.py",
        line_start=20,
        line_end=30,
        rationale="narrowed to the verify() body",
    )
    assert second.status_code == 201, second.text

    assert second.json()["id"] == first.json()["id"]
    assert second.json()["line_start"] == 20
    assert second.json()["line_end"] == 30
    listing = _list_bindings(client, engagement_key)
    assert listing["total"] == 1


# ──────────────────────────────────────────────────────────────
# 2. Consumption by the code queue
# ──────────────────────────────────────────────────────────────


def test_a_binding_projects_the_files_current_queue_attempt(client, isolate_settings):
    """The queue row is what turns a bound lead into claimable analysis work,
    so the binding listing must say whether one exists and which it is."""
    engagement_key = "2026-09-16-lead-queue-projection"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo, files = _seed_repo_with_files(client, engagement_key)
    parser = _file_named(files, "src/parser.py")
    _classify_file(client, engagement_key, int(parser["id"]), "critical", 90)
    lead = _record_lead(client, engagement_key, "Queue projection lead")
    bound = _bind(
        client,
        engagement_key,
        note_id=int(lead["id"]),
        repo_id=int(repo["id"]),
        file_path="src/parser.py",
    )
    assert bound.status_code == 201, bound.text

    before = _list_bindings(client, engagement_key)["items"][0]
    assert before["queued"] is False
    assert before["queue_item_id"] is None
    assert before["analysis_priority"] == 90

    queued = client.post(
        f"{_base(engagement_key)}/analysis-queue",
        json={
            "mode": "initial",
            "items": [
                {
                    "file_id": int(parser["id"]),
                    "priority": 90,
                    "batch_theme": "prior-art-lead",
                    "guidance_hypotheses": ["lead 1: Queue projection lead"],
                }
            ],
        },
    )
    assert queued.status_code == 201, queued.text

    after = _list_bindings(client, engagement_key)["items"][0]
    assert after["queued"] is True
    assert isinstance(after["queue_item_id"], int)
    assert after["queue_status"] == "pending"


def test_a_reference_repository_binding_is_citable_but_owes_nothing(
    client, isolate_settings
):
    """B8: reference source is indexed and citable and carries no obligation.
    A lead bound into it must not manufacture one."""
    engagement_key = "2026-09-16-lead-reference-repo"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo, _files = _seed_repo_with_files(client, engagement_key, repo_role="reference")
    lead = _record_lead(client, engagement_key, "Framework prior art")

    response = _bind(
        client,
        engagement_key,
        note_id=int(lead["id"]),
        repo_id=int(repo["id"]),
        file_path="src/parser.py",
    )

    assert response.status_code == 201, response.text
    binding = response.json()
    assert binding["repo_role"] == "reference"
    assert binding["carries_obligation"] is False
    assert "code_leads_unresolved" not in _blockers_by_code(
        _readiness(client, engagement_key)
    )


# ──────────────────────────────────────────────────────────────
# 3. The completeness gate
# ──────────────────────────────────────────────────────────────


def test_an_open_bound_lead_blocks_complete_until_it_reaches_a_terminal_disposition(
    client, isolate_settings
):
    engagement_key = "2026-09-16-lead-complete-gate"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo, _files = _seed_repo_with_files(client, engagement_key)
    lead = _record_lead(client, engagement_key, "Unanswered prior art")
    assert _bind(
        client,
        engagement_key,
        note_id=int(lead["id"]),
        repo_id=int(repo["id"]),
        file_path="src/parser.py",
    ).status_code == 201

    blocked = _blockers_by_code(_readiness(client, engagement_key))
    assert "code_leads_unresolved" in blocked
    blocker = blocked["code_leads_unresolved"]
    assert blocker["repo_id"] == int(repo["id"])
    assert blocker["overrideable"] is True
    assert "1" in blocker["message"]

    patched = client.patch(
        f"{_intel_base(engagement_key)}/notes/{lead['id']}",
        json={"payload": {"lead_status": "ruled_out"}},
    )
    assert patched.status_code == 200, patched.text

    assert "code_leads_unresolved" not in _blockers_by_code(
        _readiness(client, engagement_key)
    )


def test_an_unbound_lead_and_a_plain_note_never_reach_the_code_gate(
    client, isolate_settings
):
    """The generic lead primitive is unchanged: a web/recon lead with no code
    binding owes the code track nothing, and neither does a reference note."""
    engagement_key = "2026-09-16-lead-unbound"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    _seed_repo_with_files(client, engagement_key)
    _record_lead(client, engagement_key, "Web-only lead")
    _record_lead(client, engagement_key, "Reference note", lead_status=None)

    assert "code_leads_unresolved" not in _blockers_by_code(
        _readiness(client, engagement_key)
    )


def test_unbinding_releases_the_completion_obligation(client, isolate_settings):
    engagement_key = "2026-09-16-lead-unbind"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo, _files = _seed_repo_with_files(client, engagement_key)
    lead = _record_lead(client, engagement_key, "Mis-bound prior art")
    binding = _bind(
        client,
        engagement_key,
        note_id=int(lead["id"]),
        repo_id=int(repo["id"]),
        file_path="src/parser.py",
    ).json()
    assert "code_leads_unresolved" in _blockers_by_code(_readiness(client, engagement_key))

    released = client.post(
        f"{_base(engagement_key)}/lead-bindings/{binding['id']}/unbind",
        json={"reason": "bound to the wrong parser"},
    )
    assert released.status_code == 200, released.text
    assert released.json()["binding_status"] == "unbound"

    assert "code_leads_unresolved" not in _blockers_by_code(
        _readiness(client, engagement_key)
    )
    assert _list_bindings(client, engagement_key)["total"] == 0
    assert _list_bindings(client, engagement_key, "include_superseded=true")["total"] == 1


def test_a_second_unbind_cannot_rewrite_the_original_retraction(
    client, isolate_settings
):
    """"Retract without touching the lead" also means without touching the
    retraction: the reason and the time the operator recorded are the record.
    A second unbind is a stale write, not a correction — rebind and retract
    again if the story changed."""
    engagement_key = "2026-09-17-lead-unbind-twice"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo, _files = _seed_repo_with_files(client, engagement_key)
    lead = _record_lead(client, engagement_key, "Mis-bound prior art")
    binding = _bind(
        client,
        engagement_key,
        note_id=int(lead["id"]),
        repo_id=int(repo["id"]),
        file_path="src/parser.py",
    ).json()
    endpoint = f"{_base(engagement_key)}/lead-bindings/{binding['id']}/unbind"

    first = client.post(endpoint, json={"reason": "bound to the wrong parser"})
    assert first.status_code == 200, first.text

    second = client.post(endpoint, json={"reason": "clearing my worklist"})
    assert second.status_code == 409, second.text

    current = _list_bindings(client, engagement_key, "include_superseded=true")
    row = current["items"][0]
    assert row["unbound_reason"] == "bound to the wrong parser"
    assert row["unbound_at"] == first.json()["unbound_at"]


def test_superseding_a_lead_note_discharges_its_binding_obligation(
    client, isolate_settings
):
    """A lead lives in `intel_notes`, so superseding the note IS the disposition.

    `intel list-leads` already reports the superseded note as gone, and nothing
    may bind to it, yet its binding still fired the completion blocker and still
    rode into every claimed queue item — the operator was told to answer a lead
    the intel surface says does not exist. The obligation follows the canonical
    lead; the binding stays readable, and says which note replaced it.
    """
    engagement_key = "2026-09-17-lead-note-superseded"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo, files = _seed_repo_with_files(client, engagement_key)
    parser = _file_named(files, "src/parser.py")
    _classify_file(client, engagement_key, int(parser["id"]), "critical", 100)
    lead = _record_lead(client, engagement_key, "SAML signature bypass, 2023")
    replacement = _record_lead(client, engagement_key, "SAML signature bypass, restated")
    binding = _bind(
        client,
        engagement_key,
        note_id=int(lead["id"]),
        repo_id=int(repo["id"]),
        file_path="src/parser.py",
    ).json()
    assert binding["carries_obligation"] is True
    assert "code_leads_unresolved" in _blockers_by_code(_readiness(client, engagement_key))

    superseded = client.post(
        f"{_intel_base(engagement_key)}/notes/{lead['id']}/supersede",
        json={"to_existing_id": int(replacement["id"])},
    )
    assert superseded.status_code == 201, superseded.text

    assert "code_leads_unresolved" not in _blockers_by_code(
        _readiness(client, engagement_key)
    )
    claimed = _claim_file_for_analysis(
        client, engagement_key, int(parser["id"]), agent_name="hunter-a"
    )
    assert claimed["prior_art_leads"] == []

    # The binding itself is never hidden: it still names the file, and now names
    # the note that replaced the lead it pointed at.
    row = _list_bindings(client, engagement_key)["items"][0]
    assert row["lead_superseded_by_id"] == int(replacement["id"])
    assert row["carries_obligation"] is False


# ──────────────────────────────────────────────────────────────
# Generation identity
# ──────────────────────────────────────────────────────────────


def _manifest(files: list[dict]) -> list[dict]:
    fields = (
        "file_path", "language", "loc", "file_hash",
        "header_snippet", "git_churn_score", "has_past_cve_fix",
    )
    return [{key: row[key] for key in fields} for row in files]


def test_a_generation_advance_carries_an_unchanged_binding_and_stales_a_changed_one(
    client, isolate_settings
):
    """A file/line binding is only meaningful against the bytes it was read
    from. Identical bytes in the next generation keep it exactly valid;
    changed bytes make the line numbers a guess, so the binding goes stale and
    must be re-bound before it can be trusted again."""
    engagement_key = "2026-09-16-lead-generation"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo, files = _seed_repo_with_files(client, engagement_key)
    repo_id = int(repo["id"])
    first_generation = int(repo["active_generation"])
    unchanged_lead = _record_lead(client, engagement_key, "Helper prior art")
    changed_lead = _record_lead(client, engagement_key, "Parser prior art")
    for lead, file_path in (
        (unchanged_lead, "src/helpers.py"),
        (changed_lead, "src/parser.py"),
    ):
        assert _bind(
            client,
            engagement_key,
            note_id=int(lead["id"]),
            repo_id=repo_id,
            file_path=file_path,
            line_start=1,
            line_end=5,
        ).status_code == 201

    manifest = _manifest(files)
    for entry in manifest:
        if entry["file_path"] == "src/parser.py":
            entry["file_hash"] = _source_hash("parser-rewritten")
    _refresh_repo_files(client, engagement_key, repo_id, manifest)
    second_generation = int(
        client.get(f"{_base(engagement_key)}/repos/{repo_id}").json()["active_generation"]
    )
    assert second_generation > first_generation

    by_note = {
        int(row["note_id"]): row
        for row in _list_bindings(client, engagement_key, "include_superseded=true")[
            "items"
        ]
    }
    carried = by_note[int(unchanged_lead["id"])]
    assert carried["binding_status"] == "current"
    assert carried["repo_generation"] == second_generation

    stale = by_note[int(changed_lead["id"])]
    assert stale["binding_status"] == "stale"
    assert stale["repo_generation"] == first_generation
    assert stale["replacement_repo_generation"] == second_generation


def test_a_stale_binding_still_holds_the_lead_open_at_complete(client, isolate_settings):
    """Refreshing the snapshot must not silently retire a code obligation.
    The lead is the obligation; the binding only says where to look."""
    engagement_key = "2026-09-16-lead-generation-gate"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo, files = _seed_repo_with_files(client, engagement_key)
    repo_id = int(repo["id"])
    lead = _record_lead(client, engagement_key, "Prior art across a refresh")
    assert _bind(
        client,
        engagement_key,
        note_id=int(lead["id"]),
        repo_id=repo_id,
        file_path="src/parser.py",
    ).status_code == 201

    manifest = _manifest(files)
    for entry in manifest:
        if entry["file_path"] == "src/parser.py":
            entry["file_hash"] = _source_hash("parser-rewritten-again")
    _refresh_repo_files(client, engagement_key, repo_id, manifest)

    blocked = _blockers_by_code(_readiness(client, engagement_key))
    assert "code_leads_unresolved" in blocked
    assert "superseded" in blocked["code_leads_unresolved"]["message"]


# ──────────────────────────────────────────────────────────────
# Resume visibility
# ──────────────────────────────────────────────────────────────


def test_resume_hydration_shows_which_open_leads_carry_code_bindings(
    client, isolate_settings
):
    """Resume already lists open leads. Without the binding count an operator
    cannot tell which of them are code work waiting on them."""
    engagement_key = "2026-09-16-lead-resume"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo, files = _seed_repo_with_files(client, engagement_key)
    repo_id = int(repo["id"])
    bound = _record_lead(client, engagement_key, "Bound prior art")
    _record_lead(client, engagement_key, "Web-only lead")
    for file_path in ("src/parser.py", "src/helpers.py"):
        assert _bind(
            client,
            engagement_key,
            note_id=int(bound["id"]),
            repo_id=repo_id,
            file_path=file_path,
        ).status_code == 201

    manifest = _manifest(files)
    for entry in manifest:
        if entry["file_path"] == "src/parser.py":
            entry["file_hash"] = _source_hash("parser-drifted-for-resume")
    _refresh_repo_files(client, engagement_key, repo_id, manifest)

    brief = client.get(f"/engagements/{engagement_key}/assessment/resume-brief")
    assert brief.status_code == 200, brief.text
    payload = brief.json()
    leads = {int(row["id"]): row for row in payload["intel"]["open_leads"]}
    assert leads[int(bound["id"])]["code_bindings"] == 2
    assert leads[int(bound["id"])]["stale_code_bindings"] == 1
    unbound_lead = next(
        row for row in leads.values() if row["title"] == "Web-only lead"
    )
    assert unbound_lead["code_bindings"] == 0

    commands = [row["command"] for row in payload["recommended_next_actions"]]
    assert any(command.startswith("vigil assess code-lead list") for command in commands)


# ──────────────────────────────────────────────────────────────
# What the claiming specialist actually receives
# ──────────────────────────────────────────────────────────────


def test_a_claimed_queue_item_carries_the_prior_art_leads_bound_to_its_file(
    client, isolate_settings
):
    """A5 already requires every admitted file to hold a queue row before hunt,
    so a lead bound to one usually has no row of its own to create. The lead
    still has to reach whoever claims that file, or the binding is a note
    nobody reads."""
    engagement_key = "2026-09-16-lead-fetch-context"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo, files = _seed_repo_with_files(client, engagement_key)
    parser = _file_named(files, "src/parser.py")
    helpers = _file_named(files, "src/helpers.py")
    _classify_file(client, engagement_key, int(parser["id"]), "critical", 90)
    _classify_file(client, engagement_key, int(helpers["id"]), "low", 10)
    lead = _record_lead(client, engagement_key, "SAML signature bypass, 2023")
    closed = _record_lead(client, engagement_key, "Already answered", lead_status="resolved")
    for note in (lead, closed):
        assert _bind(
            client,
            engagement_key,
            note_id=int(note["id"]),
            repo_id=int(repo["id"]),
            file_path="src/parser.py",
            line_start=5,
            line_end=9,
            prior_art_ref="CVE-2023-9999",
        ).status_code == 201

    queued = client.post(
        f"{_base(engagement_key)}/analysis-queue",
        json={
            "mode": "initial",
            "items": [
                {"file_id": int(parser["id"]), "priority": 90},
                {"file_id": int(helpers["id"]), "priority": 10},
            ],
        },
    )
    assert queued.status_code == 201, queued.text

    claimed = client.post(
        f"{_base(engagement_key)}/analysis-queue/fetch",
        json={"limit": 2, "agent_name": "code-vuln-hunter"},
    )
    assert claimed.status_code == 200, claimed.text
    by_path = {item["file"]["file_path"]: item for item in claimed.json()}
    leads = by_path["src/parser.py"]["prior_art_leads"]
    assert [row["note_id"] for row in leads] == [int(lead["id"])]
    assert leads[0]["prior_art_ref"] == "CVE-2023-9999"
    assert leads[0]["line_start"] == 5
    assert leads[0]["binding_status"] == "current"
    assert by_path["src/helpers.py"]["prior_art_leads"] == []


def test_code_lead_binding_page_cap_mirrors_backend():
    """`code-lead list` asks for the backend maximum page, so the CLI mirror of
    that cap must not drift into a silently short worklist."""
    import sys
    from pathlib import Path

    scripts_root = Path(__file__).resolve().parents[3] / "agent" / "scripts"
    if str(scripts_root) not in sys.path:
        sys.path.insert(0, str(scripts_root))
    from app.services import code_analysis
    from assess.lib import contracts

    assert contracts.MAX_LEAD_BINDING_PAGE == code_analysis.MAX_LEAD_BINDING_PAGE
