"""Contract tests for the durable operator checkpoint.

Every dispatched specialist writes an ``assessment_dispatch_handoffs`` row; the
operator never wrote one for itself, so operator state died with the session.
``assessment_operator_checkpoints`` is that missing row, and its governing
constraint is truth-safety: the record must be structurally incapable of
carrying a NEW factual claim about the target.

These pin the properties that make that true:
- every stored reference must resolve to a row the backend already holds, and
  the write is refused (400) naming the unknown ids when one does not;
- ``current_phase`` is server-derived, never caller-supplied;
- ``intent_note`` is the ONLY free-text field on the record;
- storage is append-only — a correction is a new version that stamps the prior
  current row's ``superseded_by_id``, so the wrong entry stays readable;
- exactly one current row per engagement, versions numbered 1..N per engagement;
- the chain read reports a truthful total.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.services import operator_checkpoints


ENGAGEMENT_KEY = "2026-09-13-090000-opcheckpoint"
BASE = f"/engagements/{ENGAGEMENT_KEY}/assessment"


def _write_engagement(
    engagements_dir: Path,
    key: str = ENGAGEMENT_KEY,
    *,
    scope_overrides: dict | None = None,
) -> Path:
    eng = engagements_dir / key
    (eng / "sessions").mkdir(parents=True, exist_ok=True)
    (eng / "engagement.json").write_text(
        json.dumps(
            {
                "key": key,
                "target": "https://example.com",
                "hostname": "example.com",
                "created_at": "2026-09-13T09:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    scope = {
        "hostname": "example.com",
        "hosts": ["example.com"],
        "status": "in_progress",
        "current_phase": "consume-test",
    }
    scope.update(scope_overrides or {})
    (eng / "scope.json").write_text(json.dumps(scope), encoding="utf-8")
    return eng


@pytest.fixture
def engagement(client, isolate_settings) -> Path:
    root = _write_engagement(isolate_settings["engagements_dir"])
    (root / "findings.md").write_text("# Findings\n", encoding="utf-8")
    response = client.get(f"/engagements/{ENGAGEMENT_KEY}")
    assert response.status_code == 200, response.text
    return root


def _record(client, **overrides) -> dict:
    payload = {
        "intent_note": "about to re-dispatch the vuln-analyst on the admin panel",
    }
    payload.update(overrides)
    return client.post(f"{BASE}/operator-checkpoints", json=payload)


AUTHOR_AGENT_ID = "vuln-analyst-1"


def _seed_dispatch(
    client, agent_id: str = AUTHOR_AGENT_ID, *, base: str = BASE
) -> str:
    response = client.post(
        f"{base}/dispatches",
        json={
            "agent_id": agent_id,
            "agent_role": "vulnerability-analyst",
            "task": f"operator-checkpoint reference seed for {agent_id}",
            "skills": "auth-bypass",
        },
    )
    assert response.status_code == 201, response.text
    return agent_id


def _seed_finding(client, slug: str = "VA-001", *, base: str = BASE) -> str:
    _seed_dispatch(client, base=base)
    response = client.post(
        f"{base}/findings",
        json={
            "slug": slug,
            "title": "Reflected XSS in search",
            "severity": "medium",
            "workflow_status": "active",
            "verification_status": "unreviewed",
            "canonical_location": "https://example.com/search",
            "summary": "Seed finding for checkpoint references",
            "evidence_ref": "findings.md",
            "source_name": "vulnerability-analyst",
            "provenance": {"agent_id": AUTHOR_AGENT_ID},
        },
    )
    assert response.status_code == 201, response.text
    return str(response.json()["finding"]["slug"])


def _seed_command_run(client, *, base: str = BASE) -> int:
    response = client.post(
        f"{base}/command-runs",
        json={
            "run_uuid": "operator-checkpoint-command",
            "command": "curl https://example.com/admin",
            "tool_name": "curl",
            "agent_name": "vuln-analyst-1",
            "phase": "consume-test",
            "status": "completed",
            "return_code": 0,
            "started_at": "2026-09-13T09:02:00Z",
            "completed_at": "2026-09-13T09:02:01Z",
        },
    )
    assert response.status_code == 201, response.text
    return int(response.json()["id"])


def _seed_artifact(client, engagement_root: Path, *, base: str = BASE) -> int:
    (engagement_root / "notes").mkdir(exist_ok=True)
    (engagement_root / "notes" / "checkpoint-proof.txt").write_text(
        "checkpoint reference seed", encoding="utf-8"
    )
    response = client.post(
        f"{base}/artifacts",
        json={"path": "notes/checkpoint-proof.txt", "kind": "note"},
    )
    assert response.status_code == 201, response.text
    return int(response.json()["id"])


def test_record_stores_only_backend_references_plus_one_intent_note(
    client, engagement
) -> None:
    response = _record(client)

    assert response.status_code == 201, response.text
    row = response.json()
    assert row["checkpoint_version"] == 1
    assert row["superseded_by_id"] is None
    assert row["superseded_by_checkpoint_version"] is None
    # Server-derived from scope.json, not from the request body.
    assert row["current_phase"] == "consume-test"
    assert row["intent_note"] == (
        "about to re-dispatch the vuln-analyst on the admin panel"
    )
    assert row["finding_slugs"] == []
    assert row["dispatch_agent_ids"] == []
    assert row["command_run_ids"] == []
    assert row["artifact_ids"] == []
    assert row["source"] == "operator"
    assert row["client_name"] == "unknown"

    # `intent_note` is the ONLY free-text field: every other value is either a
    # server-derived enum-ish token, an integer, or a reference list.
    free_text = {
        key
        for key, value in row.items()
        if isinstance(value, str) and key not in {
            "current_phase",
            "source",
            "client_name",
            "created_at",
        }
    }
    assert free_text == {"intent_note"}


def test_record_rejects_a_caller_supplied_current_phase(client, engagement) -> None:
    response = _record(client, current_phase="report")

    assert response.status_code == 422, response.text


def test_record_rejects_a_caller_supplied_code_phase(client, engagement) -> None:
    # The code-track phase is server-derived for the same reason the web one is:
    # a caller-assertable phase is a factual claim about engagement state.
    response = _record(client, code_phase="hunt")

    assert response.status_code == 422, response.text


@pytest.mark.parametrize("blank", ["   ", "\n", "\t\n ", ""])
def test_record_refuses_a_blank_intent_note(client, engagement, blank) -> None:
    """A blank note is not a harmless no-op — it supersedes the useful one.

    `min_length=1` accepted `"   "`, which a shell expansion of an unset
    variable produces easily. Every record supersedes the previous current row,
    so the blank became the CURRENT checkpoint and resume hydration — which
    reads the current one — stopped showing the operator's real save-my-place
    note. The record exists to survive a context boundary; silently losing it
    to an empty write is the one failure it cannot have.
    """
    response = _record(client, intent_note=blank)

    assert response.status_code == 422, response.text


def test_a_blank_intent_note_leaves_the_previous_checkpoint_current(
    client, engagement
) -> None:
    """The refusal must not have cost the operator the note they already had."""
    first = _record(client, intent_note="mid-dispatch on the admin panel")
    assert first.status_code == 201, first.text

    assert _record(client, intent_note="   ").status_code == 422

    current = client.get(f"{BASE}/operator-checkpoints").json()["checkpoints"]
    assert len(current) == 1
    assert current[0]["intent_note"] == "mid-dispatch on the admin panel"
    assert current[0]["checkpoint_version"] == 1


def test_record_keeps_a_meaningful_note_byte_for_byte(client, engagement) -> None:
    """Only the check strips. Operator-authored text is stored verbatim, so a
    note whose leading indentation carries meaning survives the round trip."""
    note = "  re-dispatching:\n    - admin panel\n    - tenant export\n"

    response = _record(client, intent_note=note)

    assert response.status_code == 201, response.text
    assert response.json()["intent_note"] == note


def test_record_refuses_an_unknown_finding_slug(client, engagement) -> None:
    known = _seed_finding(client)

    response = _record(client, finding_slugs=[known, "VA-999"])

    assert response.status_code == 400, response.text
    detail = response.json()["detail"]
    assert "VA-999" in detail
    assert known not in detail


def test_record_refuses_a_noncanonical_finding_alias(client, engagement) -> None:
    canonical = _seed_finding(client, slug="VA-047")

    response = _record(client, finding_slugs=["VA047"])

    assert response.status_code == 400, response.text
    assert "VA047" in response.json()["detail"]
    assert canonical == "VA-047"


def test_record_refuses_an_unknown_dispatch_agent_id(client, engagement) -> None:
    known = _seed_dispatch(client)

    response = _record(client, dispatch_agent_ids=[known, "ghost-agent"])

    assert response.status_code == 400, response.text
    assert "ghost-agent" in response.json()["detail"]


def test_record_refuses_an_unknown_command_run_id(client, engagement) -> None:
    response = _record(client, command_run_ids=[424242])

    assert response.status_code == 400, response.text
    assert "424242" in response.json()["detail"]


def test_record_refuses_an_unknown_artifact_id(client, engagement) -> None:
    response = _record(client, artifact_ids=[515151])

    assert response.status_code == 400, response.text
    assert "515151" in response.json()["detail"]


def test_record_accepts_references_that_all_resolve(client, engagement) -> None:
    slug = _seed_finding(client)
    agent_id = AUTHOR_AGENT_ID
    command_run_id = _seed_command_run(client)
    artifact_id = _seed_artifact(client, engagement)

    response = _record(
        client,
        finding_slugs=[slug],
        dispatch_agent_ids=[agent_id],
        command_run_ids=[command_run_id],
        artifact_ids=[artifact_id],
    )

    assert response.status_code == 201, response.text
    row = response.json()
    assert row["finding_slugs"] == [slug]
    assert row["dispatch_agent_ids"] == [agent_id]
    assert row["command_run_ids"] == [command_run_id]
    assert row["artifact_ids"] == [artifact_id]


def test_record_rejects_references_owned_by_another_engagement(
    client, engagement
) -> None:
    other_key = "2026-09-13-090300-opcheckpoint-other-refs"
    other_root = _write_engagement(engagement.parent, other_key)
    assert client.get(f"/engagements/{other_key}").status_code == 200
    other_base = f"/engagements/{other_key}/assessment"
    slug = _seed_finding(client, slug="VA-099", base=other_base)
    command_run_id = _seed_command_run(client, base=other_base)
    artifact_id = _seed_artifact(client, other_root, base=other_base)

    response = _record(
        client,
        finding_slugs=[slug],
        dispatch_agent_ids=[AUTHOR_AGENT_ID],
        command_run_ids=[command_run_id],
        artifact_ids=[artifact_id],
    )

    assert response.status_code == 400, response.text
    detail = response.json()["detail"]
    for value in (slug, AUTHOR_AGENT_ID, str(command_run_id), str(artifact_id)):
        assert value in detail


def test_correction_supersedes_rather_than_mutates(client, engagement) -> None:
    first = _record(client, intent_note="wrong: about to close the engagement").json()
    # Consume a global table id in another engagement. Checkpoint versions are
    # engagement-local, so the successor's database id must not be presented as
    # its human checkpoint number.
    other_key = "2026-09-13-090500-opcheckpoint-gap"
    _write_engagement(engagement.parent, other_key)
    assert client.get(f"/engagements/{other_key}").status_code == 200
    gap = client.post(
        f"/engagements/{other_key}/assessment/operator-checkpoints",
        json={"intent_note": "unrelated engagement"},
    )
    assert gap.status_code == 201, gap.text
    second = _record(
        client,
        intent_note="correcting checkpoint 1 — recon is not finished, re-dispatching",
    ).json()

    assert second["checkpoint_version"] == 2
    assert second["id"] != second["checkpoint_version"]
    assert second["superseded_by_id"] is None
    assert second["superseded_by_checkpoint_version"] is None

    chain = client.get(
        f"{BASE}/operator-checkpoints", params={"include_superseded": "true"}
    )
    assert chain.status_code == 200, chain.text
    body = chain.json()
    assert body["total_count"] == 2
    assert body["returned_count"] == 2
    versions = [row["checkpoint_version"] for row in body["checkpoints"]]
    assert versions == [2, 1]
    superseded = next(row for row in body["checkpoints"] if row["checkpoint_version"] == 1)
    # The wrong entry is still readable, and it points at its correction.
    assert superseded["superseded_by_id"] == second["id"]
    assert superseded["superseded_by_checkpoint_version"] == 2
    assert superseded["intent_note"] == "wrong: about to close the engagement"
    assert superseded["id"] == first["id"]


def test_get_returns_only_the_current_row_by_default(client, engagement) -> None:
    _record(client, intent_note="first")
    current = _record(client, intent_note="second").json()

    response = client.get(f"{BASE}/operator-checkpoints")

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["total_count"] == 2
    assert body["returned_count"] == 1
    assert [row["id"] for row in body["checkpoints"]] == [current["id"]]


def test_get_all_supports_stable_offset_pagination(client, engagement) -> None:
    for intent in ("first", "second", "third"):
        _record(client, intent_note=intent)

    response = client.get(
        f"{BASE}/operator-checkpoints",
        params={"include_superseded": "true", "limit": 1, "offset": 1},
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["total_count"] == 3
    assert body["returned_count"] == 1
    assert body["checkpoints"][0]["checkpoint_version"] == 2


def test_get_on_an_engagement_with_no_checkpoint_is_an_honest_empty(
    client, engagement
) -> None:
    response = client.get(f"{BASE}/operator-checkpoints")

    assert response.status_code == 200, response.text
    body = response.json()
    assert body == {"checkpoints": [], "returned_count": 0, "total_count": 0}


def test_versions_are_numbered_per_engagement(client, isolate_settings) -> None:
    _write_engagement(isolate_settings["engagements_dir"])
    other_key = "2026-09-13-091500-opcheckpoint-other"
    _write_engagement(isolate_settings["engagements_dir"], other_key)
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200
    assert client.get(f"/engagements/{other_key}").status_code == 200

    _record(client, intent_note="a")
    _record(client, intent_note="b")
    other = client.post(
        f"/engagements/{other_key}/assessment/operator-checkpoints",
        json={"intent_note": "first here"},
    )

    assert other.status_code == 201, other.text
    assert other.json()["checkpoint_version"] == 1


def test_over_long_intent_note_is_refused_not_truncated(client, engagement) -> None:
    oversized = "x" * (operator_checkpoints.MAX_INTENT_NOTE_CHARS + 1)

    response = _record(client, intent_note=oversized)

    assert response.status_code == 422, response.text


def test_over_long_reference_list_is_refused_not_truncated(client, engagement) -> None:
    response = _record(
        client,
        command_run_ids=list(range(1, operator_checkpoints.MAX_REFERENCES + 2)),
    )

    assert response.status_code == 422, response.text


def test_source_vocabulary_is_closed(client, engagement) -> None:
    # Automatic client lifecycle receipts belong in activity_entries and must
    # never supersede the operator's meaningful save-my-place note.
    assert _record(client, source="operator").status_code == 422
    assert _record(client, source="session_end_hook").status_code == 422
    assert _record(client, source="whatever-i-like").status_code == 422


def test_client_identity_cannot_be_self_attested_on_a_checkpoint(
    client, engagement
) -> None:
    assert _record(client, client_name="claude").status_code == 422


def test_stored_rows_cannot_be_edited_in_place(client, engagement) -> None:
    import sqlite3

    from app.db import get_connection

    row = _record(client, intent_note="original").json()
    with get_connection() as connection:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE assessment_operator_checkpoints SET intent_note = ? WHERE id = ?",
                ("rewritten", int(row["id"])),
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "DELETE FROM assessment_operator_checkpoints WHERE id = ?",
                (int(row["id"]),),
            )


# --- Two-track phase capture -------------------------------------------------
#
# A ``both`` engagement runs the web track (``scope.json.current_phase``) and
# the code track (``scope.json.code_phase``) INDEPENDENTLY. A checkpoint that
# stored only ``current_phase`` therefore recorded the web position for an
# operator who was working the code track — a continuity record naming a place
# the operator was never at, which is exactly the false claim this table is
# built to be incapable of.


def test_both_engagement_checkpoint_records_each_track_phase(
    client, isolate_settings
) -> None:
    key = "2026-09-13-091600-opcheckpoint-both"
    _write_engagement(
        isolate_settings["engagements_dir"],
        key,
        scope_overrides={
            "engagement_type": "both",
            "current_phase": "recon",
            "code_phase": "hunt",
        },
    )
    assert client.get(f"/engagements/{key}").status_code == 200

    response = client.post(
        f"/engagements/{key}/assessment/operator-checkpoints",
        json={"intent_note": "mid-hunt in the auth middleware; web recon is parked"},
    )

    assert response.status_code == 201, response.text
    row = response.json()
    assert row["current_phase"] == "recon"
    assert row["code_phase"] == "hunt"


def test_web_engagement_checkpoint_carries_no_code_phase(client, engagement) -> None:
    # A web engagement has no code track at all, so the record must not invent
    # one; renderers omit the field rather than printing an empty track.
    row = _record(client).json()

    assert row["current_phase"] == "consume-test"
    assert row["code_phase"] is None


def test_code_engagement_checkpoint_records_the_code_track_phase(
    client, isolate_settings
) -> None:
    # A code-only engagement persists its code-track phase in ``current_phase``
    # and has no ``code_phase`` key, so the single stored phase is already the
    # code one — there is no second track to record.
    key = "2026-09-13-091700-opcheckpoint-code"
    _write_engagement(
        isolate_settings["engagements_dir"],
        key,
        scope_overrides={"engagement_type": "code", "current_phase": "verify-variant"},
    )
    assert client.get(f"/engagements/{key}").status_code == 200

    response = client.post(
        f"/engagements/{key}/assessment/operator-checkpoints",
        json={"intent_note": "confirming the sink variant in the parser"},
    )

    assert response.status_code == 201, response.text
    row = response.json()
    assert row["current_phase"] == "verify-variant"
    assert row["code_phase"] is None


_LEGACY_CHECKPOINT_SCHEMA = """
CREATE TABLE engagements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT NOT NULL UNIQUE,
    target TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'active',
    engagement_root TEXT NOT NULL DEFAULT ''
);
CREATE TABLE assessment_operator_checkpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    checkpoint_version INTEGER NOT NULL CHECK(checkpoint_version >= 1),
    superseded_by_id INTEGER REFERENCES assessment_operator_checkpoints(id),
    current_phase TEXT NOT NULL,
    finding_slugs_json TEXT NOT NULL DEFAULT '[]',
    dispatch_agent_ids_json TEXT NOT NULL DEFAULT '[]',
    command_run_ids_json TEXT NOT NULL DEFAULT '[]',
    artifact_ids_json TEXT NOT NULL DEFAULT '[]',
    intent_note TEXT NOT NULL,
    source TEXT NOT NULL,
    client_name TEXT NOT NULL DEFAULT 'unknown',
    created_at TEXT NOT NULL,
    UNIQUE(engagement_id, checkpoint_version)
);
CREATE TRIGGER assessment_operator_checkpoints_append_only_update
BEFORE UPDATE ON assessment_operator_checkpoints
WHEN NOT (
    OLD.superseded_by_id IS NULL
    AND NEW.superseded_by_id IS NOT NULL
    AND NEW.id = OLD.id
    AND NEW.engagement_id = OLD.engagement_id
    AND NEW.checkpoint_version = OLD.checkpoint_version
    AND NEW.current_phase = OLD.current_phase
    AND NEW.finding_slugs_json = OLD.finding_slugs_json
    AND NEW.dispatch_agent_ids_json = OLD.dispatch_agent_ids_json
    AND NEW.command_run_ids_json = OLD.command_run_ids_json
    AND NEW.artifact_ids_json = OLD.artifact_ids_json
    AND NEW.intent_note = OLD.intent_note
    AND NEW.source = OLD.source
    AND NEW.client_name = OLD.client_name
    AND NEW.created_at = OLD.created_at
)
BEGIN
    SELECT RAISE(ABORT, 'operator checkpoints are append-only');
END;
INSERT INTO engagements (id, key) VALUES (1, 'legacy-checkpoint-engagement');
INSERT INTO assessment_operator_checkpoints (
    engagement_id, checkpoint_version, superseded_by_id, current_phase,
    finding_slugs_json, dispatch_agent_ids_json, command_run_ids_json,
    artifact_ids_json, intent_note, source, client_name, created_at
) VALUES (1, 1, NULL, 'exploit', '["VA-001"]', '[]', '[]', '[]',
          'legacy row written before the code track was recorded',
          'operator', 'unknown', '2026-07-01T00:00:00Z');
"""


def test_checkpoint_written_before_the_code_phase_column_still_loads(
    isolate_settings,
) -> None:
    """The column is additive, so rows that predate it stay readable.

    A legacy row has no code-track phase to report and must read back saying so,
    never borrowing the web phase. The same migration has to replace the
    append-only trigger, whose stale body could not see the new column.
    """
    import sqlite3
    from contextlib import closing

    from app import db as db_module

    path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    path.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(path)) as connection, connection:
        connection.executescript(_LEGACY_CHECKPOINT_SCHEMA)

    db_module.init_db()

    with db_module.get_connection() as connection:
        row = connection.execute(
            "SELECT * FROM assessment_operator_checkpoints WHERE checkpoint_version = 1"
        ).fetchone()
        record = operator_checkpoints._serialize(row)
        assert record["current_phase"] == "exploit"
        assert record["code_phase"] is None
        assert record["finding_slugs"] == ["VA-001"]

        # The rebuilt trigger covers the new column; the stale body did not
        # mention it, so it would have let an edit through.
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE assessment_operator_checkpoints "
                "SET code_phase = 'hunt', superseded_by_id = 2 WHERE id = ?",
                (int(record["id"]),),
            )
