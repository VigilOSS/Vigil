"""FTS5 trigger correctness tests (plan §1c).

The shadow table ``intel_search_index`` is the external-content source for
``intel_search_fts``; the three triggers (AI / AD / AU) keep the FTS
index in sync on every insert, update, and delete. These tests go through
the API (not raw SQL) so they don't depend on internal B1 helper names.

Scope:
  - Insert via API → a row appears in ``intel_search_index`` and MATCH
    finds it in ``intel_search_fts``.
  - Update via UPSERT API → the searchable text is refreshed.
  - Cascade delete (via ``DELETE /engagements/{key}``) clears the index.
  - MATCH against ``key``, ``body``, and ``source_name`` columns.
  - ``init_db`` drop+recreate on column drift: pre-seed an FTS table with
    a missing column and call ``init_db`` again; assert the table was
    rebuilt with the expected columns.
"""
from __future__ import annotations

import sqlite3

from app import db as db_module

from tests.test_engagements_api import write_engagement


ENGAGEMENT_KEY = "2026-04-17-120200-fts"
INTEL_BASE = f"/engagements/{ENGAGEMENT_KEY}/intel"


def _seed_engagement(client, isolate_settings) -> None:
    write_engagement(isolate_settings["engagements_dir"], key=ENGAGEMENT_KEY)
    response = client.get(f"/engagements/{ENGAGEMENT_KEY}")
    assert response.status_code == 200, response.text


def _db_path() -> str:
    return str(db_module.database_path())


def _fts_count(where_sql: str, params: tuple) -> int:
    """Count rows in ``intel_search_fts`` matching the given MATCH expression.

    FTS5 tables don't support arbitrary WHERE predicates the way regular
    tables do; this helper keeps MATCH queries on a single column.
    """
    with sqlite3.connect(_db_path()) as connection:
        row = connection.execute(
            f"SELECT COUNT(*) FROM intel_search_fts WHERE {where_sql}", params
        ).fetchone()
    return int(row[0])


def _shadow_rows() -> list[tuple]:
    with sqlite3.connect(_db_path()) as connection:
        return list(
            connection.execute(
                "SELECT entity_type, source_id, key, body, source_name "
                "FROM intel_search_index ORDER BY id"
            ).fetchall()
        )


# ──────────────────────────────────────────────────────────────
# Insert round-trips through shadow + FTS
# ──────────────────────────────────────────────────────────────


def test_insert_populates_shadow_and_fts(client, isolate_settings):
    _seed_engagement(client, isolate_settings)

    response = client.post(
        f"{INTEL_BASE}/tech-components",
        json={
            "component": "WordPress",
            "version": "6.5",
            "source_name": "wappalyzer",
            "notes": "Edge CMS stack",
        },
    )
    assert response.status_code == 201, response.text

    shadow = _shadow_rows()
    assert shadow, "intel_search_index must receive a row after API insert"
    assert any("WordPress" in (row[2] or "") or "WordPress" in (row[3] or "") for row in shadow), shadow

    # MATCH on the ``key`` column.
    assert _fts_count("key MATCH ?", ("WordPress",)) >= 1
    # MATCH on ``source_name``.
    assert _fts_count("source_name MATCH ?", ("wappalyzer",)) >= 1


# ──────────────────────────────────────────────────────────────
# UPSERT refreshes searchable text
# ──────────────────────────────────────────────────────────────


def test_update_refreshes_fts_text(client, isolate_settings):
    _seed_engagement(client, isolate_settings)

    first = client.post(
        f"{INTEL_BASE}/notes",
        json={
            "title": "Initial recon",
            "body_markdown": "Found legacy_phrase_alpha on homepage",
            "source_name": "osint-analyst",
        },
    )
    assert first.status_code == 201, first.text
    assert _fts_count("body MATCH ?", ("legacy_phrase_alpha",)) >= 1

    # UPSERT on the (engagement_id, title) natural key — the shadow row
    # must be updated, not duplicated; the AU trigger delete-then-inserts
    # the FTS payload.
    second = client.post(
        f"{INTEL_BASE}/notes",
        json={
            "title": "Initial recon",
            "body_markdown": "Replaced with newer_phrase_beta",
            "source_name": "osint-analyst",
        },
    )
    assert second.status_code == 201, second.text

    assert _fts_count("body MATCH ?", ("legacy_phrase_alpha",)) == 0
    assert _fts_count("body MATCH ?", ("newer_phrase_beta",)) >= 1


# ──────────────────────────────────────────────────────────────
# Engagement cascade delete clears the shadow + FTS index
# ──────────────────────────────────────────────────────────────


def test_engagement_cascade_delete_clears_fts(client, isolate_settings):
    _seed_engagement(client, isolate_settings)

    created = client.post(
        f"{INTEL_BASE}/tech-components",
        json={"component": "unique_marker_delta", "version": "1.0"},
    )
    assert created.status_code == 201, created.text
    assert _fts_count("key MATCH ?", ("unique_marker_delta",)) >= 1

    response = client.delete(
        f"/engagements/{ENGAGEMENT_KEY}",
        params={"confirm": ENGAGEMENT_KEY},
    )
    assert response.status_code == 200, response.text

    # Shadow rows cascade via FK ON DELETE; FTS clears via AD trigger.
    assert _shadow_rows() == []
    assert _fts_count("key MATCH ?", ("unique_marker_delta",)) == 0


# ──────────────────────────────────────────────────────────────
# MATCH works across the indexed columns (key / body / source_name /
# entity_type). We rely on the API to populate each column, then assert
# a query on that column finds the row.
# ──────────────────────────────────────────────────────────────


def test_fts_matches_across_columns(client, isolate_settings):
    _seed_engagement(client, isolate_settings)

    resp = client.post(
        f"{INTEL_BASE}/cves",
        json={
            "cve_id": "CVE-2026-99999",
            "affected_component": "examplelib",
            "source_name": "customfeed",
            "notes": "body_keyword_gamma appears here",
        },
    )
    assert resp.status_code == 201, resp.text

    # `key` column holds the CVE id (per the shadow helper contract).
    # FTS5 tokenises on ``-``; match against a quoted phrase of the tokens.
    assert _fts_count("key MATCH ?", ('"CVE 2026 99999"',)) >= 1
    # `body` column holds the notes / descriptive text.
    assert _fts_count("body MATCH ?", ("body_keyword_gamma",)) >= 1
    # `source_name` column holds the feed name.
    assert _fts_count("source_name MATCH ?", ("customfeed",)) >= 1
    # `entity_type` column must filter by record type.
    assert _fts_count("entity_type MATCH ?", ("cve",)) >= 1


# ──────────────────────────────────────────────────────────────
# init_db drop+recreate on column drift
# ──────────────────────────────────────────────────────────────


def test_init_db_rebuilds_intel_fts_on_column_drift(isolate_settings):
    """If the FTS table survives from a prior schema with fewer columns,
    ``init_db`` must drop and recreate it with the expected columns.
    This mirrors the pattern at db.py:724-801 (assessment_command_runs_fts).
    """
    # Start fresh — write the database first with the current schema, then
    # replace the intel_search_fts table with a column-drifted version,
    # then re-run init_db and assert it is rebuilt.
    db_module.init_db()

    db_path = _db_path()
    with sqlite3.connect(db_path) as connection:
        connection.execute("DROP TABLE IF EXISTS intel_search_fts")
        for trigger in (
            "intel_search_index_ai",
            "intel_search_index_ad",
            "intel_search_index_au",
        ):
            connection.execute(f"DROP TRIGGER IF EXISTS {trigger}")
        # Legacy shape missing ``entity_type``.
        connection.execute(
            """
            CREATE VIRTUAL TABLE intel_search_fts
            USING fts5(
                key,
                body,
                content='intel_search_index',
                content_rowid='id',
                tokenize='unicode61'
            )
            """
        )
        connection.commit()

        columns_before = {
            row[1]
            for row in connection.execute(
                "PRAGMA table_info(intel_search_fts)"
            ).fetchall()
        }
    assert "entity_type" not in columns_before
    assert "source_name" not in columns_before

    # Reinitialising must rebuild the table with the expected columns.
    db_module._startup_database_fingerprint = None
    db_module.init_db()

    with sqlite3.connect(db_path) as connection:
        columns_after = {
            row[1]
            for row in connection.execute(
                "PRAGMA table_info(intel_search_fts)"
            ).fetchall()
        }
    assert {"key", "body", "source_name", "entity_type"} <= columns_after, columns_after


def test_init_db_rebuilds_activity_fts_on_column_drift(isolate_settings):
    """Same drop+recreate guard as above, for ``activity_entries_fts``."""
    db_module.init_db()

    db_path = _db_path()
    with sqlite3.connect(db_path) as connection:
        connection.execute("DROP TABLE IF EXISTS activity_entries_fts")
        for trigger in (
            "activity_entries_ai",
            "activity_entries_ad",
            "activity_entries_au",
        ):
            connection.execute(f"DROP TRIGGER IF EXISTS {trigger}")
        connection.execute(
            """
            CREATE VIRTUAL TABLE activity_entries_fts
            USING fts5(
                title,
                action,
                content='activity_entries',
                content_rowid='id',
                tokenize='unicode61'
            )
            """
        )
        connection.commit()

        columns_before = {
            row[1]
            for row in connection.execute(
                "PRAGMA table_info(activity_entries_fts)"
            ).fetchall()
        }
    assert "body_markdown" not in columns_before

    db_module._startup_database_fingerprint = None
    db_module.init_db()

    with sqlite3.connect(db_path) as connection:
        columns_after = {
            row[1]
            for row in connection.execute(
                "PRAGMA table_info(activity_entries_fts)"
            ).fetchall()
        }
    assert {"title", "action", "result", "body_markdown", "actor_name"} <= columns_after, columns_after
