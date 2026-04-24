"""Engagement deletion contract.

Two rules must hold:
  1. Filesystem drift (engagement dir vanished) MUST NOT cascade-delete DB rows.
     Renaming, archiving, or temporarily moving an engagement dir used to wipe
     every finding/probe/command-run/code-analysis row for that engagement.
  2. Explicit deletion routes through ``DELETE /engagements/{key}`` with a
     ``?confirm=<key>`` guard. Missing or mismatched confirm returns 400.
"""
from __future__ import annotations

import json
import shutil
import sqlite3
from pathlib import Path

import pytest

from app import db as db_module
from app.services import engagements as engagement_service

from tests.test_engagements_api import write_engagement


ENGAGEMENT_KEY = "2026-04-17-120000-retain-test"


def _write(engagements_dir: Path) -> Path:
    return write_engagement(engagements_dir, key=ENGAGEMENT_KEY)


def _force_sync() -> None:
    engagement_service.maybe_sync_engagements(force=True)


def _seed_finding_row(engagement_id: int) -> None:
    db_path = db_module.database_path()
    with sqlite3.connect(str(db_path)) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(
            """
            INSERT INTO assessment_findings
                (engagement_id, slug, title, severity, status,
                 source_name, canonical_location, summary)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                engagement_id,
                "VA-001",
                "Seed finding that must survive filesystem drift",
                "high",
                "draft",
                "test",
                "https://example.com/seed",
                "test",
            ),
        )
        connection.commit()


def _finding_count(engagement_id: int) -> int:
    with sqlite3.connect(str(db_module.database_path())) as connection:
        row = connection.execute(
            "SELECT COUNT(*) FROM assessment_findings WHERE engagement_id = ?",
            (engagement_id,),
        ).fetchone()
    return int(row[0])


def test_sync_does_not_cascade_delete_when_dir_vanishes(client, isolate_settings):
    engagement_dir = _write(isolate_settings["engagements_dir"])
    _force_sync()
    engagement = db_module.get_engagement_by_key(ENGAGEMENT_KEY)
    assert engagement is not None, "engagement was not created by sync"
    _seed_finding_row(engagement.id)
    assert _finding_count(engagement.id) == 1

    # Simulate operator moving/renaming the engagement dir. Under the old
    # behavior this cascade-deleted every finding row on the next sync tick.
    shutil.rmtree(engagement_dir)
    _force_sync()

    retained = db_module.get_engagement_by_key(ENGAGEMENT_KEY)
    assert retained is not None, "engagement row must not be deleted by sync"
    assert _finding_count(retained.id) == 1, "findings must not be cascade-deleted"


def test_delete_endpoint_requires_matching_confirm_token(client, isolate_settings):
    _write(isolate_settings["engagements_dir"])
    _force_sync()

    missing = client.delete(f"/engagements/{ENGAGEMENT_KEY}")
    assert missing.status_code == 400, missing.text

    wrong = client.delete(f"/engagements/{ENGAGEMENT_KEY}?confirm=not-the-key")
    assert wrong.status_code == 400, wrong.text

    still_exists = client.get(f"/engagements/{ENGAGEMENT_KEY}")
    assert still_exists.status_code == 200


def test_delete_endpoint_removes_engagement_and_findings(client, isolate_settings):
    _write(isolate_settings["engagements_dir"])
    _force_sync()
    engagement = db_module.get_engagement_by_key(ENGAGEMENT_KEY)
    assert engagement is not None
    _seed_finding_row(engagement.id)
    assert _finding_count(engagement.id) == 1

    response = client.delete(f"/engagements/{ENGAGEMENT_KEY}?confirm={ENGAGEMENT_KEY}")
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload == {"deleted": True, "key": ENGAGEMENT_KEY, "id": engagement.id}

    marker = isolate_settings["engagements_dir"] / ".deleted-engagements" / f"{ENGAGEMENT_KEY}.json"
    assert marker.exists()
    assert db_module.get_engagement_by_key(ENGAGEMENT_KEY) is None
    assert _finding_count(engagement.id) == 0

    _force_sync()
    assert db_module.get_engagement_by_key(ENGAGEMENT_KEY) is None


def test_delete_endpoint_404_for_unknown_key(client, isolate_settings):
    response = client.delete("/engagements/never-existed?confirm=never-existed")
    assert response.status_code == 404
