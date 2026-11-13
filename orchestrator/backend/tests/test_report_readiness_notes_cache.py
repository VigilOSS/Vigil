"""Report readiness reads each registered note's text once per content, never once per call.

The missing-citation check reads the indexed text of every durable note.
Readiness runs on every summary refresh, resume brief, phase check and
submission listing, so re-reading unchanged notes each time made it slow in a
long engagement. Each note's cited paths are kept per content (the row id,
digest and last indexing), and whether a cited file exists is re-evaluated on
every call. These tests pin that the second call loads no note text, and that
every input change still changes the answer.
"""
from __future__ import annotations

import importlib

import pytest

from app import db as db_module
from app.services import state_manager
from tests.test_artifact_resume_api import (
    ENGAGEMENT_KEY,
    _register_note,
    _seed_finding,
    _write_engagement,
)

readiness_module = importlib.import_module("app.services.state_manager.report_readiness")

_MISSING = "missing_cited_markdown_artifact"


@pytest.fixture
def engagement(client, isolate_settings):
    eng = _write_engagement(isolate_settings["engagements_dir"])
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200
    _seed_finding(client, eng)  # records VA-047
    record = db_module.get_engagement_by_key(ENGAGEMENT_KEY)
    assert record is not None
    readiness_module.clear_notes_scan_cache()
    return eng, record.id


@pytest.fixture
def text_loads():
    """Run readiness and count the statements that load artifact text."""
    counts = {"text_loads": 0}

    def readiness(engagement_id: int):
        statements: list[str] = []
        with db_module.get_connection() as connection:
            connection.set_trace_callback(statements.append)
            try:
                result = state_manager.report_readiness(engagement_id)
            finally:
                connection.set_trace_callback(None)
        counts["text_loads"] = sum(
            1 for sql in statements if "indexed_text" in sql and sql.lstrip().upper().startswith("SELECT")
        )
        return result

    return counts, readiness


def _by_kind(result: dict, kind: str) -> dict[str, dict]:
    return {item["path"]: item for item in result["advisories"] if item["kind"] == kind}


def _write_note(eng, client, body: str) -> None:
    (eng / "notes" / "indexed.md").write_text(body, encoding="utf-8")
    _register_note(client, "notes/indexed.md", related_finding_slug="VA-047")


def test_a_repeated_readiness_call_loads_no_unchanged_note_text(engagement, client, text_loads) -> None:
    eng, engagement_id = engagement
    counts, readiness = text_loads
    _write_note(eng, client, "# Hunt\nSee `notes/MISSING.md`.\n")

    first = readiness(engagement_id)
    first_loads = counts["text_loads"]
    second = readiness(engagement_id)

    assert first_loads >= 1
    assert counts["text_loads"] == 0
    assert second["advisories"] == first["advisories"]
    assert second["blockers"] == first["blockers"]
    assert set(_by_kind(second, _MISSING)) == {"notes/MISSING.md"}


def test_every_input_change_reaches_the_answer(engagement, client, text_loads) -> None:
    eng, engagement_id = engagement
    _counts, readiness = text_loads
    _write_note(eng, client, "# Hunt\nSee `notes/MISSING.md`.\n")
    readiness(engagement_id)

    # A registered note re-registered with new bytes cites another file.
    _write_note(eng, client, "# Hunt\nSee `notes/GONE.md`.\n")
    assert set(_by_kind(readiness(engagement_id), _MISSING)) == {"notes/GONE.md"}

    # A cited file that now exists clears the advisory with no note change.
    (eng / "notes" / "GONE.md").write_text("restored\n", encoding="utf-8")
    _register_note(client, "notes/GONE.md", related_finding_slug="VA-047")
    assert "notes/GONE.md" not in _by_kind(readiness(engagement_id), _MISSING)
