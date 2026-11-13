"""Independent report-writer QC of every report-writer deliverable.

A ``submission_qc_verdict`` binds a separate report-writer dispatch's review to
one content-addressed triage packet; final export needs the latest one to pass
for the exact package being exported. A ``report_qc_verdict`` binds the same
kind of review to the registered bytes of the internal ``report.md``.
"""
from __future__ import annotations

import hashlib
import importlib
import json
import sys
from pathlib import Path

import pytest

from tests.test_report_export import ENGAGEMENT_KEY, _add_finding, _finding
from tests.test_submission_versions_api import (
    BASE,
    _approve_packet,
    _artifact,
    _banded_finding,
    _export,
    _qc_dispatch,
    _register_file,
    _seed_reportable_finding,
    _triage_dispatches,
    _write_workspace,
)


def _root(isolate_settings) -> Path:
    return (isolate_settings["engagements_dir"] / ENGAGEMENT_KEY).resolve()


def _packet(isolate_settings, slug: str, attachments: list[dict] | None = None) -> str:
    root = _root(isolate_settings)
    (root / "ENGAGEMENT.md").write_text("# Program facts\n", encoding="utf-8")
    scripts = Path(__file__).resolve().parents[3] / "agent" / "scripts"
    if str(scripts) not in sys.path:
        sys.path.insert(0, str(scripts))
    module = importlib.import_module("assess.commands.export_triage_packet")
    return module.build_packet(root, slug, attachment_rows=attachments)["packet_id"]


def _qc_payload(client, slug: str, packet_id: str, **overrides) -> dict:
    payload = {
        "finding_slug": slug,
        "packet_id": packet_id,
        "reviewer_dispatch_agent_id": _qc_dispatch(client, slug),
        "writer_dispatch_agent_id": _triage_dispatches(client, slug)["writer_dispatch_agent_id"],
        "verdict": "pass",
        "failed_rows": [],
    }
    payload.update(overrides)
    return payload


def _record(client, kind: str, payload: dict):
    return client.post(f"{BASE}/dispatch-decisions", json={"kind": kind, "payload": payload})


def _unreviewed_workspace(client, isolate_settings, **kwargs):
    finding = _seed_reportable_finding(client, isolate_settings, **kwargs)
    paths = _write_workspace(client, isolate_settings, finding, reviewed=False)
    return finding, paths


# -- recording a submission QC verdict ---------------------------------------


def test_submission_qc_records_separate_report_writer_review_of_a_packet(
    client, isolate_settings
) -> None:
    _unreviewed_workspace(client, isolate_settings)
    packet_id = _packet(isolate_settings, "VA-001")
    response = _record(client, "submission_qc_verdict", _qc_payload(client, "VA-001", packet_id))
    assert response.status_code == 201, response.text
    assert response.json()["payload"]["reviewer_dispatch_agent_id"] == "QC-VA-001"


@pytest.mark.parametrize(
    "change",
    [
        "reviewer_not_report_writer",
        "reviewer_is_writer",
        "reviewer_is_author",
        "reviewer_unknown",
        "writer_not_report_writer",
        "unknown_packet",
        "malformed_packet",
        "blocked_without_rows",
        "blocked_row_without_quote",
        "pass_with_rows",
        "unknown_verdict",
        "missing_writer",
    ],
)
def test_submission_qc_refuses_unattributed_or_incoherent_reviews(
    client, isolate_settings, change
) -> None:
    _unreviewed_workspace(client, isolate_settings)
    packet_id = _packet(isolate_settings, "VA-001")
    payload = _qc_payload(client, "VA-001", packet_id)
    if change == "reviewer_not_report_writer":
        payload["reviewer_dispatch_agent_id"] = "TRIAGE-VA-001"
    elif change == "reviewer_is_writer":
        payload["reviewer_dispatch_agent_id"] = payload["writer_dispatch_agent_id"]
    elif change == "reviewer_is_author":
        client.post(f"{BASE}/dispatches", json={
            "agent_id": "SOURCE-VA-001", "agent_role": "report-writer", "task": "write",
        })
        payload["reviewer_dispatch_agent_id"] = "SOURCE-VA-001"
    elif change == "reviewer_unknown":
        payload["reviewer_dispatch_agent_id"] = "QC-UNRECORDED"
    elif change == "writer_not_report_writer":
        payload["writer_dispatch_agent_id"] = "TRIAGE-VA-001"
    elif change == "unknown_packet":
        payload["packet_id"] = "a" * 64
    elif change == "malformed_packet":
        payload["packet_id"] = "not-a-packet"
    elif change == "blocked_without_rows":
        payload["verdict"] = "blocked"
    elif change == "blocked_row_without_quote":
        payload.update(verdict="blocked", failed_rows=[{"row": "Impact", "quote": ""}])
    elif change == "pass_with_rows":
        payload["failed_rows"] = [{"row": "Impact", "quote": "might allow"}]
    elif change == "unknown_verdict":
        payload["verdict"] = "Accept@P3"
    elif change == "missing_writer":
        payload.pop("writer_dispatch_agent_id")
    response = _record(client, "submission_qc_verdict", payload)
    assert response.status_code == 422, response.text


def test_submission_qc_names_every_problem_in_one_refusal(client, isolate_settings) -> None:
    # Nothing about the payload changes between refusals, so each defect is
    # knowable on the first read and one refusal names all of them.
    _unreviewed_workspace(client, isolate_settings)
    payload = _qc_payload(
        client, "VA-001", "a" * 64,
        reviewer_dispatch_agent_id="TRIAGE-VA-001", verdict="blocked",
    )

    response = _record(client, "submission_qc_verdict", payload)

    assert response.status_code == 422, response.text
    detail = response.json()["detail"]
    assert "failed_rows" in detail
    assert "report-writer" in detail
    assert "triage packet" in detail


def test_submission_qc_reviewer_must_not_have_edited_the_finding(
    client, isolate_settings
) -> None:
    _unreviewed_workspace(client, isolate_settings)
    packet_id = _packet(isolate_settings, "VA-001")
    reviewer = _qc_dispatch(client, "VA-001")
    edited = client.patch(
        f"{BASE}/findings/VA-001",
        json={"dispatch_agent_id": reviewer, "summary": "Admin API skips the Acme tenant check."},
    )
    assert edited.status_code == 200, edited.text
    response = _record(client, "submission_qc_verdict", _qc_payload(client, "VA-001", packet_id))
    assert response.status_code == 422, response.text
    assert "edited" in response.json()["detail"]


@pytest.mark.parametrize("scenario", ["latest_registration", "earlier_registration"])
def test_submission_qc_reviewer_who_registered_the_submission_is_refused(
    client, isolate_settings, scenario
) -> None:
    """Every dispatch that registered the submission workspace wrote it, not only the latest."""
    finding, (submission_path, _context) = _unreviewed_workspace(client, isolate_settings)
    reviewer = _qc_dispatch(client, "VA-001")
    writer = _triage_dispatches(client, "VA-001")["writer_dispatch_agent_id"]
    registrations = [reviewer] if scenario == "latest_registration" else [reviewer, writer]
    for producer in registrations:
        registered = _artifact(
            client, path=submission_path, kind="submission", media_type="text/markdown",
            related_finding_slug="VA-001", producer_agent_id=producer,
        )
        assert registered.status_code == 201, registered.text
    packet_id = _packet(isolate_settings, "VA-001")
    response = _record(client, "submission_qc_verdict", _qc_payload(client, "VA-001", packet_id))
    assert response.status_code == 422, response.text
    assert "registered" in response.json()["detail"]


def test_submission_registered_by_its_writer_passes_a_separate_qc(client, isolate_settings) -> None:
    _finding, (submission_path, _context) = _unreviewed_workspace(client, isolate_settings)
    writer = _triage_dispatches(client, "VA-001")["writer_dispatch_agent_id"]
    registered = _artifact(
        client, path=submission_path, kind="submission", media_type="text/markdown",
        related_finding_slug="VA-001", producer_agent_id=writer,
    )
    assert registered.status_code == 201, registered.text
    packet_id = _packet(isolate_settings, "VA-001")
    response = _record(client, "submission_qc_verdict", _qc_payload(client, "VA-001", packet_id))
    assert response.status_code == 201, response.text


def test_submission_qc_packet_must_belong_to_the_finding(client, isolate_settings) -> None:
    _unreviewed_workspace(client, isolate_settings)
    _add_finding(client, _finding("VA-002", "Second Acme finding"))
    _write_workspace(
        client, isolate_settings,
        client.get(f"{BASE}/findings/VA-002").json(), reviewed=False, rehearsed=False,
    )
    other_packet = _packet(isolate_settings, "VA-002")
    response = _record(
        client, "submission_qc_verdict", _qc_payload(client, "VA-001", other_packet)
    )
    assert response.status_code == 422, response.text


def test_blocked_submission_qc_records_failed_rows(client, isolate_settings) -> None:
    _unreviewed_workspace(client, isolate_settings)
    packet_id = _packet(isolate_settings, "VA-001")
    rows = [{"row": "Impact is demonstrated", "quote": "could potentially allow"}]
    response = _record(
        client, "submission_qc_verdict",
        _qc_payload(client, "VA-001", packet_id, verdict="blocked", failed_rows=rows),
    )
    assert response.status_code == 201, response.text
    assert response.json()["payload"]["failed_rows"] == rows


# -- the final-export gate ---------------------------------------------------


def test_final_export_requires_a_passing_qc_review_of_the_exported_package(
    client, isolate_settings
) -> None:
    finding, (submission_path, context_path) = _unreviewed_workspace(client, isolate_settings)
    packet_id = _packet(isolate_settings, "VA-001")
    accept = _record(client, "blind_triage_verdict", {
        "finding_slug": "VA-001", "verdict": "Accept@P3", "packet_id": packet_id,
        **_triage_dispatches(client, "VA-001"),
    })
    assert accept.status_code == 201, accept.text

    refused = _export(client, "VA-001", submission_path, context_path)
    assert refused.status_code == 409, refused.text
    assert "submission QC has no verdict" in refused.json()["detail"]

    passed = _record(client, "submission_qc_verdict", _qc_payload(client, "VA-001", packet_id))
    assert passed.status_code == 201, passed.text
    exported = _export(client, "VA-001", submission_path, context_path)
    assert exported.status_code == 201, exported.text


def test_low_severity_submission_still_needs_qc_but_not_blind_triage(
    client, isolate_settings
) -> None:
    from tests.test_report_export import _seed

    _seed(client, isolate_settings)
    _add_finding(client, _banded_finding("VA-001", "Verbose Acme error page", "low"))
    finding = client.get(f"{BASE}/findings/VA-001").json()
    submission_path, context_path = _write_workspace(
        client, isolate_settings, finding, reviewed=False,
    )
    refused = client.get(f"{BASE}/submissions/VA-001/readiness").json()
    assert any("submission QC" in item for item in refused["blockers"])
    assert not any("blind triage" in item for item in refused["blockers"])

    packet_id = _packet(isolate_settings, "VA-001")
    assert _record(
        client, "submission_qc_verdict", _qc_payload(client, "VA-001", packet_id)
    ).status_code == 201
    exported = _export(client, "VA-001", submission_path, context_path)
    assert exported.status_code == 201, exported.text


def test_latest_blocked_qc_supersedes_an_earlier_pass(client, isolate_settings) -> None:
    finding = _seed_reportable_finding(client, isolate_settings)
    submission_path, context_path = _write_workspace(client, isolate_settings, finding)
    with_pass = client.get(f"{BASE}/submissions/VA-001").json()
    packet_id = with_pass["submission_qc"]["packet_id"]
    assert with_pass["submission_qc"]["status"] == "current"
    blocked = _record(client, "submission_qc_verdict", _qc_payload(
        client, "VA-001", packet_id, verdict="blocked",
        failed_rows=[{"row": "Steps reproduce", "quote": "Replay the recorded request."}],
    ))
    assert blocked.status_code == 201, blocked.text

    detail = client.get(f"{BASE}/submissions/VA-001").json()
    assert detail["submission_qc"]["status"] == "blocked"
    assert detail["submission_qc"]["failed_rows"][0]["row"] == "Steps reproduce"
    refused = _export(client, "VA-001", submission_path, context_path)
    assert refused.status_code == 409, refused.text
    assert "submission QC" in refused.json()["detail"]


def test_qc_of_an_older_body_does_not_clear_a_changed_submission(
    client, isolate_settings
) -> None:
    finding = _seed_reportable_finding(client, isolate_settings)
    _write_workspace(client, isolate_settings, finding)
    changed_path, changed_context = _write_workspace(
        client, isolate_settings, finding, markdown=b"# Changed impact claim\n",
        reviewed=False, rehearsed=False,
    )
    detail = client.get(f"{BASE}/submissions/VA-001").json()
    assert detail["submission_qc"]["status"] == "stale"
    assert detail["submission_qc"]["issue"]
    refused = _export(client, "VA-001", changed_path, changed_context)
    assert refused.status_code == 409, refused.text


def test_qc_state_is_missing_until_a_verdict_is_recorded(client, isolate_settings) -> None:
    _unreviewed_workspace(client, isolate_settings)
    qc = client.get(f"{BASE}/submissions/VA-001").json()["submission_qc"]
    assert qc["status"] == "missing", qc
    assert qc["verdict"] is None and qc["packet_id"] is None


@pytest.mark.parametrize("change", ["program_brief_edited", "program_brief_deleted", "platform_changed"])
def test_qc_goes_stale_when_the_program_brief_or_platform_changes(
    client, isolate_settings, change
) -> None:
    finding = _seed_reportable_finding(client, isolate_settings)
    _write_workspace(client, isolate_settings, finding)
    assert client.get(f"{BASE}/submissions/VA-001").json()["submission_qc"]["status"] == "current"
    root = _root(isolate_settings)
    if change == "program_brief_edited":
        (root / "ENGAGEMENT.md").write_text("# Updated Acme recipient rules\n", encoding="utf-8")
    elif change == "program_brief_deleted":
        (root / "ENGAGEMENT.md").unlink()
    else:
        context_path = root / "submissions/VA-001/submission-context.json"
        context = json.loads(context_path.read_text(encoding="utf-8"))
        context["platform"] = "direct"
        context_path.write_text(json.dumps(context), encoding="utf-8")
    qc = client.get(f"{BASE}/submissions/VA-001").json()["submission_qc"]
    assert qc["status"] == "stale", qc
    assert qc["issue"]


def test_qc_state_tracks_the_selected_attachments(client, isolate_settings) -> None:
    finding = _seed_reportable_finding(client, isolate_settings)
    _write_workspace(client, isolate_settings, finding)
    attachment = _register_file(
        client, isolate_settings, "evidence/additional.txt", b"additional checked evidence",
    )
    selected = client.get(
        f"{BASE}/submissions/VA-001/readiness?attachment_id={attachment['id']}"
    ).json()
    assert selected["submission_qc"]["status"] == "stale"
    assert "attachments" in selected["submission_qc"]["issue"]
    _approve_packet(client, isolate_settings, "VA-001", [attachment])
    matched = client.get(
        f"{BASE}/submissions/VA-001/readiness?attachment_id={attachment['id']}"
    ).json()
    assert matched["submission_qc"]["status"] == "current"
    assert matched["final_ready"] is True


def test_finalization_rechecks_latest_qc_verdict(
    client, isolate_settings, monkeypatch
) -> None:
    from app.services import submission_versions

    finding = _seed_reportable_finding(client, isolate_settings)
    submission_path, context_path = _write_workspace(client, isolate_settings, finding)
    packet_id = client.get(f"{BASE}/submissions/VA-001").json()["submission_qc"]["packet_id"]
    original_complete = submission_versions._complete_version

    def block_before_complete(engagement_id, row):
        blocked = _record(client, "submission_qc_verdict", _qc_payload(
            client, "VA-001", packet_id, verdict="blocked",
            failed_rows=[{"row": "Title names the impact", "quote": "Issue in API"}],
        ))
        assert blocked.status_code == 201, blocked.text
        return original_complete(engagement_id, row)

    monkeypatch.setattr(submission_versions, "_complete_version", block_before_complete)
    result = _export(client, "VA-001", submission_path, context_path)
    assert result.status_code == 409, result.text
    assert "submission QC" in result.json()["detail"]


def test_blue_engagement_submissions_are_exempt_from_qc(client, isolate_settings) -> None:
    from app.services import submission_versions

    finding, _paths = _unreviewed_workspace(client, isolate_settings)
    engagement_id = int(finding["engagement_id"])

    def qc_blockers() -> list[str]:
        workspace, error = submission_versions._workspace_or_error(engagement_id, "VA-001")
        readiness = submission_versions._publication_readiness(
            engagement_id, "VA-001", [],
            root=_root(isolate_settings), workspace=workspace, workspace_error=error,
            verify_bytes=True, latest=None,
        )
        return [item for item in readiness["blockers"] if "submission QC" in item]

    assert qc_blockers()
    scope_path = _root(isolate_settings) / "scope.json"
    scope = json.loads(scope_path.read_text(encoding="utf-8"))
    scope_path.write_text(
        json.dumps({**scope, "tracks": {"blue": {"phase": "report"}}}), encoding="utf-8",
    )
    assert qc_blockers() == []


# -- the internal report.md --------------------------------------------------


def _report_writers(client, *agent_ids: str) -> None:
    for agent_id in agent_ids or ("WRITE-REPORT", "QC-REPORT"):
        client.post(f"{BASE}/dispatches", json={
            "agent_id": agent_id, "agent_role": "report-writer", "task": "internal report",
        })


def _register_report(
    client, isolate_settings, content: bytes = b"# Acme internal report\n",
    producer: str | None = "WRITE-REPORT",
) -> dict:
    _report_writers(client)
    (_root(isolate_settings) / "report.md").write_bytes(content)
    body = {"path": "report.md", "kind": "report", "media_type": "text/markdown"}
    if producer is not None:
        body["producer_agent_id"] = producer
    registered = _artifact(client, **body)
    assert registered.status_code == 201, registered.text
    return registered.json()


def _report_payload(client, artifact: dict, **overrides) -> dict:
    _report_writers(client)
    payload = {
        "artifact_id": artifact["id"],
        "sha256": artifact["sha256"],
        "reviewer_dispatch_agent_id": "QC-REPORT",
        "writer_dispatch_agent_id": "WRITE-REPORT",
        "verdict": "pass",
        "failed_rows": [],
    }
    payload.update(overrides)
    return payload


def test_report_qc_binds_review_to_the_registered_report_bytes(client, isolate_settings) -> None:
    _seed_reportable_finding(client, isolate_settings)
    artifact = _register_report(client, isolate_settings)
    response = _record(client, "report_qc_verdict", _report_payload(client, artifact))
    assert response.status_code == 201, response.text
    assert response.json()["payload"]["sha256"] == hashlib.sha256(
        b"# Acme internal report\n"
    ).hexdigest()
    # `vigil assess transition-phase complete` finds the report by its exact path.
    _register_file(client, isolate_settings, "notes/report.md", b"# Acme notes\n")
    found = client.get(f"{BASE}/artifacts/search?path=report.md&limit=2&offset=0")
    assert found.status_code == 200, found.text
    assert [row["id"] for row in found.json()] == [artifact["id"]]


@pytest.mark.parametrize(
    "change",
    ["other_artifact", "wrong_sha", "edited_after_registration", "reviewer_is_writer",
     "reviewer_not_report_writer", "blocked_without_rows"],
)
def test_report_qc_refuses_reviews_of_other_bytes_or_by_the_writer(
    client, isolate_settings, change
) -> None:
    _seed_reportable_finding(client, isolate_settings)
    artifact = _register_report(client, isolate_settings)
    payload = _report_payload(client, artifact)
    if change == "other_artifact":
        other = _register_file(client, isolate_settings, "notes/summary.md", b"# notes\n")
        payload.update(artifact_id=other["id"], sha256=other["sha256"])
    elif change == "wrong_sha":
        payload["sha256"] = "0" * 64
    elif change == "edited_after_registration":
        (_root(isolate_settings) / "report.md").write_bytes(b"# Edited after registration\n")
    elif change == "reviewer_is_writer":
        payload["reviewer_dispatch_agent_id"] = "WRITE-REPORT"
    elif change == "reviewer_not_report_writer":
        payload["reviewer_dispatch_agent_id"] = "TRIAGE-VA-001"
        _triage_dispatches(client, "VA-001")
    elif change == "blocked_without_rows":
        payload["verdict"] = "blocked"
    response = _record(client, "report_qc_verdict", payload)
    assert response.status_code == 422, response.text


def test_report_qc_names_every_problem_in_one_refusal(client, isolate_settings) -> None:
    _seed_reportable_finding(client, isolate_settings)
    artifact = _register_report(client, isolate_settings)
    payload = _report_payload(
        client, artifact, sha256="0" * 64, verdict="blocked",
        reviewer_dispatch_agent_id="WRITE-REPORT",
    )

    response = _record(client, "report_qc_verdict", payload)

    assert response.status_code == 422, response.text
    detail = response.json()["detail"]
    assert "failed_rows" in detail
    assert "separate from the writer" in detail
    assert "sha256" in detail


@pytest.mark.parametrize("scenario", ["earlier_drafter_reviews", "reviewer_reregisters_unattributed"])
def test_report_qc_reviewer_who_registered_any_report_bytes_is_refused(
    client, isolate_settings, scenario
) -> None:
    """Every producer in report.md's registration history drafted it, not only the latest."""
    _seed_reportable_finding(client, isolate_settings)
    _report_writers(client, "WRITE-1", "WRITE-2", "QC-REPORT")
    _register_report(client, isolate_settings, b"# Acme report v1\n", producer="WRITE-1")
    if scenario == "earlier_drafter_reviews":
        artifact = _register_report(client, isolate_settings, b"# Acme report v2\n", producer="WRITE-2")
        reviewer, writer = "WRITE-1", "WRITE-2"
    else:
        artifact = _register_report(client, isolate_settings, b"# Acme report edited\n", producer=None)
        assert artifact["producer_agent_id"] == "WRITE-1"
        reviewer, writer = "QC-REPORT", "WRITE-1"
    response = _record(client, "report_qc_verdict", _report_payload(
        client, artifact, reviewer_dispatch_agent_id=reviewer, writer_dispatch_agent_id=writer))
    assert response.status_code == 422, response.text


def test_a_registration_that_keeps_the_stored_bytes_records_no_new_content_producer(
    client, isolate_settings
) -> None:
    """A path re-registered while its file is missing keeps the indexed bytes, so
    the new registrant joins the history but is not the producer of those bytes."""
    _seed_reportable_finding(client, isolate_settings)
    _report_writers(client, "WRITE-1", "WRITE-2", "QC-REPORT")
    original = _register_report(client, isolate_settings, producer="WRITE-1")
    (_root(isolate_settings) / "report.md").unlink()
    kept = _artifact(client, path="report.md", kind="report", producer_agent_id="WRITE-2")
    assert kept.status_code == 201, kept.text
    row = kept.json()
    assert row["present"] is False and row["sha256"] == original["sha256"]
    assert row["content_producer_agent_id"] == "WRITE-1"
    assert "WRITE-2" in row["producer_history"]


def test_report_qc_needs_the_reviewed_bytes_registered_with_attribution(
    client, isolate_settings
) -> None:
    _seed_reportable_finding(client, isolate_settings)
    artifact = _register_report(client, isolate_settings, producer=None)
    response = _record(client, "report_qc_verdict", _report_payload(client, artifact))
    assert response.status_code == 422, response.text
    assert "--agent-id" in response.json()["detail"]
    attributed = _register_report(client, isolate_settings)
    response = _record(client, "report_qc_verdict", _report_payload(client, attributed))
    assert response.status_code == 201, response.text


def test_a_distinct_reviewer_passes_after_the_drafter_fixes_a_blocked_report(
    client, isolate_settings
) -> None:
    _seed_reportable_finding(client, isolate_settings)
    _register_report(client, isolate_settings, b"# Acme report v1\n")
    artifact = _register_report(client, isolate_settings, b"# Acme report v2\n")
    response = _record(client, "report_qc_verdict", _report_payload(client, artifact))
    assert response.status_code == 201, response.text


def test_writer_recorded_checklist_verdict_points_at_independent_qc(client, isolate_settings) -> None:
    """A self-recorded checklist verdict satisfies no gate, so it is refused with
    the kind that does; stored historical rows are untouched data."""
    _unreviewed_workspace(client, isolate_settings)
    packet_id = _packet(isolate_settings, "VA-001")
    writer = _triage_dispatches(client, "VA-001")["writer_dispatch_agent_id"]
    response = _record(client, "pass1_qa_verdict", {
        "finding_slug": "VA-001", "packet_id": packet_id,
        "auditor_dispatch_agent_id": writer, "verdict": "pass", "reason": "checked",
    })
    assert response.status_code == 422, response.text
    assert "submission_qc_verdict" in response.text


def test_checklist_verdict_in_the_qc_payload_shape_points_at_independent_qc(
    client, isolate_settings
) -> None:
    _seed_reportable_finding(client, isolate_settings)
    response = _record(client, "pass1_qa_verdict", {
        "finding_slug": "VA-001", "packet_id": "a" * 64,
        "reviewer_dispatch_agent_id": "QC-1", "writer_dispatch_agent_id": "WRITE-1",
        "verdict": "pass", "failed_rows": [],
    })
    assert response.status_code == 422, response.text
    assert "submission_qc_verdict" in response.text
