"""Per-finding external-submission tracking (``submission_status``).

``submission_status`` records external bug-bounty / program submission state and
is ORTHOGONAL to ``workflow_status`` (which tracks report-inclusion). A finding
can be ``workflow_status=reported`` AND ``submission_status=accepted`` at the
same time; neither axis derives from or mutates the other. ``report_readiness``
keys on ``workflow_status`` only and is intentionally untouched.

Canonical vocabulary (single source of truth, mirrored across the two packages):
``none`` | ``submitted`` | ``accepted`` | ``needs_info`` | ``rejected`` |
``duplicate``.

This module covers BOTH enforcement seams (the CLI ``update-finding`` argparse
boundary and the backend HTTP layer) plus the additive ALTER-TABLE migration,
mirroring the dual-enforcement convention of ``test_record_finding.py``.
"""
from __future__ import annotations

import argparse
import importlib
import json
import sqlite3
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

# The assess CLI package lives under agent/scripts; put it on the path so the
# CLI-boundary half of the dual enforcement is testable from the backend suite
# (mirrors test_record_finding.py).
_SCRIPTS_ROOT = Path(__file__).resolve().parents[3] / "agent" / "scripts"
if str(_SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_ROOT))

from app import db as db_module  # noqa: E402
from app.services.state_manager._common import (  # noqa: E402
    SUBMISSION_STATUSES as BACKEND_SUBMISSION_STATUSES,
)

ENGAGEMENT_KEY = "2026-06-30-120000-submission"

# The canonical vocabulary, written out literally here so the test pins the exact
# contract independently of either package's constant.
ALL_STATES = ["none", "submitted", "accepted", "needs_info", "rejected", "duplicate"]
NON_DEFAULT_STATES = ["submitted", "accepted", "needs_info", "rejected", "duplicate"]


def _seed(client, isolate_settings) -> None:
    engagement_dir = isolate_settings["engagements_dir"] / ENGAGEMENT_KEY
    (engagement_dir / "sessions").mkdir(parents=True, exist_ok=True)
    (engagement_dir / "scope.json").write_text(
        json.dumps({"engagement_name": "Submission Status", "targets": ["https://app.example"]}),
        encoding="utf-8",
    )
    (engagement_dir / "findings.md").write_text("# Findings\n", encoding="utf-8")
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200


def _base() -> str:
    return f"/engagements/{ENGAGEMENT_KEY}/assessment"


def _finding_payload(slug: str = "VA-001", **over) -> dict:
    payload = {
        "slug": slug,
        "title": "IDOR in /api/users/{id} allows anon read of any user PII",
        "severity": "high",
        "workflow_status": "active",
        "defect_family": "access-control",
        "root_cause_key": "missing-object-authz",
        "canonical_location": "https://app.example/api/users",
        "summary": "IDOR",
        "evidence_ref": "findings.md",
        "source_name": "vulnerability-analyst",
        "details": {"evidence": "Replayable request.", "impact": "PII disclosure."},
        "provenance": {"agent_name": "vulnerability-analyst"},
    }
    payload.update(over)
    return payload


def _update_finding_cmd():
    return importlib.import_module("assess.commands.update_finding")


# ──────────────────────────────────────────────────────────────────────────
# Vocabulary sync (the "locked in sync across packages" guarantee)
# ──────────────────────────────────────────────────────────────────────────


def test_canonical_vocabulary_is_the_single_documented_set():
    assert set(BACKEND_SUBMISSION_STATUSES) == set(ALL_STATES)


def test_cli_and_backend_vocabulary_stay_in_sync():
    from assess.lib.contracts import SUBMISSION_STATUSES as CLI_SUBMISSION_STATUSES

    assert set(CLI_SUBMISSION_STATUSES) == set(BACKEND_SUBMISSION_STATUSES)


# ──────────────────────────────────────────────────────────────────────────
# Backend HTTP enforcement (default, set, read projection, validation)
# ──────────────────────────────────────────────────────────────────────────


def test_default_submission_status_is_none(client, isolate_settings):
    _seed(client, isolate_settings)
    created = client.post(f"{_base()}/findings", json=_finding_payload())
    assert created.status_code in (200, 201), created.text
    assert created.json()["finding"]["submission_status"] == "none"

    fetched = client.get(f"{_base()}/findings/VA-001")
    assert fetched.status_code == 200, fetched.text
    assert fetched.json()["submission_status"] == "none"


def test_read_projection_includes_submission_status_in_list(client, isolate_settings):
    _seed(client, isolate_settings)
    assert client.post(f"{_base()}/findings", json=_finding_payload()).status_code in (200, 201)

    listing = client.get(f"{_base()}/findings")
    assert listing.status_code == 200, listing.text
    rows = listing.json()
    rows = rows["findings"] if isinstance(rows, dict) and "findings" in rows else rows
    assert rows, rows
    assert all("submission_status" in row for row in rows)
    assert rows[0]["submission_status"] == "none"


@pytest.mark.parametrize("state", NON_DEFAULT_STATES)
def test_patch_sets_each_valid_submission_state(client, isolate_settings, state):
    _seed(client, isolate_settings)
    assert client.post(f"{_base()}/findings", json=_finding_payload()).status_code in (200, 201)

    resp = client.patch(f"{_base()}/findings/VA-001", json={"submission_status": state})
    assert resp.status_code == 200, resp.text
    assert resp.json()["finding"]["submission_status"] == state

    fetched = client.get(f"{_base()}/findings/VA-001")
    assert fetched.json()["submission_status"] == state


def test_create_accepts_explicit_submission_status(client, isolate_settings):
    _seed(client, isolate_settings)
    created = client.post(
        f"{_base()}/findings", json=_finding_payload(submission_status="submitted")
    )
    assert created.status_code in (200, 201), created.text
    assert created.json()["finding"]["submission_status"] == "submitted"


def test_api_rejects_invalid_submission_status_on_create(client, isolate_settings):
    _seed(client, isolate_settings)
    resp = client.post(f"{_base()}/findings", json=_finding_payload(submission_status="bogus"))
    assert resp.status_code == 422, resp.text


def test_api_rejects_invalid_submission_status_on_patch(client, isolate_settings):
    _seed(client, isolate_settings)
    assert client.post(f"{_base()}/findings", json=_finding_payload()).status_code in (200, 201)

    resp = client.patch(f"{_base()}/findings/VA-001", json={"submission_status": "totally-made-up"})
    assert resp.status_code == 422, resp.text
    # The finding's submission_status is unchanged by the rejected patch.
    assert client.get(f"{_base()}/findings/VA-001").json()["submission_status"] == "none"


# ──────────────────────────────────────────────────────────────────────────
# Orthogonality: submission_status and workflow_status never bleed into each other
# ──────────────────────────────────────────────────────────────────────────


def test_setting_submission_status_does_not_change_workflow_status(client, isolate_settings):
    _seed(client, isolate_settings)
    assert client.post(f"{_base()}/findings", json=_finding_payload()).status_code in (200, 201)

    resp = client.patch(f"{_base()}/findings/VA-001", json={"submission_status": "accepted"})
    assert resp.status_code == 200, resp.text
    finding = resp.json()["finding"]
    assert finding["submission_status"] == "accepted"
    # workflow_status stays exactly where it was — submission is a separate axis.
    assert finding["workflow_status"] == "active"


def test_setting_workflow_status_does_not_change_submission_status(client, isolate_settings):
    _seed(client, isolate_settings)
    assert client.post(f"{_base()}/findings", json=_finding_payload()).status_code in (200, 201)

    # First park the finding at submission_status=accepted.
    assert (
        client.patch(f"{_base()}/findings/VA-001", json={"submission_status": "accepted"}).status_code
        == 200
    )

    # Now move the workflow axis only — submission_status must survive untouched.
    resp = client.patch(
        f"{_base()}/findings/VA-001",
        json={"workflow_status": "reported", "reason_text": "Published in report"},
    )
    assert resp.status_code == 200, resp.text
    finding = resp.json()["finding"]
    assert finding["workflow_status"] == "reported"
    assert finding["submission_status"] == "accepted"


def test_re_record_upsert_preserves_submission_status(client, isolate_settings):
    """record-finding is an upsert; re-recording a matched finding without a
    submission_status must NOT silently reset it (orthogonality on the create
    path, mirroring how evidence_type is preserved across checkpoints)."""
    _seed(client, isolate_settings)
    assert client.post(f"{_base()}/findings", json=_finding_payload()).status_code in (200, 201)
    assert (
        client.patch(f"{_base()}/findings/VA-001", json={"submission_status": "accepted"}).status_code
        == 200
    )

    # Re-record the same finding (dedup tuple match) with no submission_status.
    again = client.post(f"{_base()}/findings", json=_finding_payload(notes="re-seen"))
    assert again.status_code in (200, 201), again.text
    assert client.get(f"{_base()}/findings/VA-001").json()["submission_status"] == "accepted"


# ──────────────────────────────────────────────────────────────────────────
# CLI boundary enforcement (agent/scripts/assess/commands/update_finding.py)
# ──────────────────────────────────────────────────────────────────────────


def test_cli_register_adds_submission_status_choice():
    uf = _update_finding_cmd()
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers()
    uf.register(sub)
    args = parser.parse_args(["update-finding", "VA-001", "--submission-status", "accepted"])
    assert args.submission_status == "accepted"
    # Optional — defaults to no submission-status change.
    args_default = parser.parse_args(["update-finding", "VA-001", "--workflow-status", "reported"])
    assert getattr(args_default, "submission_status", None) is None


@pytest.mark.parametrize("state", ALL_STATES)
def test_cli_accepts_every_valid_submission_state(state):
    uf = _update_finding_cmd()
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers()
    uf.register(sub)
    args = parser.parse_args(["update-finding", "VA-001", "--submission-status", state])
    assert args.submission_status == state


def test_cli_rejects_invalid_submission_status():
    uf = _update_finding_cmd()
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers()
    uf.register(sub)
    with pytest.raises(SystemExit):
        parser.parse_args(["update-finding", "VA-001", "--submission-status", "bogus"])


def test_cli_plumbs_submission_status_into_patch_payload(monkeypatch):
    """--submission-status is plumbed into the JSON PATCH exactly like
    --workflow-status (same key name, same patch envelope)."""
    uf = _update_finding_cmd()
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers()
    uf.register(sub)
    args = parser.parse_args(["update-finding", "VA-001", "--submission-status", "accepted"])
    args.engagement_dir = "/tmp/does-not-matter"

    captured: dict = {}

    class _FakeClient:
        def __init__(self, *a, **k):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def patch(self, path, payload):
            captured["path"] = path
            captured["payload"] = payload
            return {"finding": {"slug": "VA-001", "submission_status": payload.get("submission_status")}}

    monkeypatch.setattr(uf, "AssessmentClient", _FakeClient)
    monkeypatch.setattr(
        uf, "load_config", lambda d: SimpleNamespace(base_url="http://x", engagement_key="k")
    )
    uf.run(args)
    assert captured["path"] == "findings/VA-001"
    assert captured["payload"]["submission_status"] == "accepted"
    # workflow_status is NOT smuggled in when only --submission-status is passed.
    assert "workflow_status" not in captured["payload"]


def test_contract_documents_submission_status_flag():
    from assess.lib import contracts

    text = contracts.render_contract("update-finding")
    assert "--submission-status" in text
    # The allowed vocabulary is surfaced in the contract.
    for state in ALL_STATES:
        assert state in text


# ──────────────────────────────────────────────────────────────────────────
# Additive ALTER-TABLE migration for pre-existing DBs
# ──────────────────────────────────────────────────────────────────────────


def test_alter_table_migration_adds_submission_status_to_legacy_db(isolate_settings):
    # Build the HEAD schema in the isolated temp DB.
    db_module.init_db()
    db_path = str(db_module.database_path())

    # Simulate a DB created BEFORE submission_status existed: insert a legacy
    # finding row, then drop the column. foreign_keys=OFF lets us seed a finding
    # row without standing up a full engagement graph — the migration only cares
    # about the column + its backfilled default.
    with sqlite3.connect(db_path) as connection:
        connection.execute("PRAGMA foreign_keys = OFF")
        connection.execute(
            "INSERT INTO assessment_findings (engagement_id, slug, title) VALUES (1, 'VA-001', 'legacy')"
        )
        connection.execute("ALTER TABLE assessment_findings DROP COLUMN submission_status")
        cols = {row[1] for row in connection.execute("PRAGMA table_info(assessment_findings)")}
        assert "submission_status" not in cols
        connection.commit()

    db_module.close_thread_connection()

    # Re-running init_db() must apply the additive ALTER TABLE migration.
    db_module.init_db()
    with sqlite3.connect(db_path) as connection:
        cols = {row[1] for row in connection.execute("PRAGMA table_info(assessment_findings)")}
        assert "submission_status" in cols
        value = connection.execute(
            "SELECT submission_status FROM assessment_findings WHERE slug = 'VA-001'"
        ).fetchone()[0]
        # Existing rows are backfilled to the NOT NULL DEFAULT 'none'.
        assert value == "none"
