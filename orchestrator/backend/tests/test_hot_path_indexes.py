"""Hot read paths must seek through indexes rather than walk engagement rows.

``assessment_artifacts`` rows carry each file's full extracted text inline, and
the columns added after ``indexed_text`` sit behind that text's overflow chain.
A statement that visits every artifact row of an engagement therefore reads the
engagement's whole text corpus (gigabytes on a long engagement) even when it
selects only small columns. The same shape -- a per-engagement row walk where a
keyed seek was intended -- made the assessment summary, the runs list and code
readiness slow enough to stall the operator UI.

These tests pin the executable contract rather than SQL wording: each index the
hot paths rely on exists on fresh and upgraded databases, and the statements the
production helpers actually execute (captured with a trace callback) are planned
onto it. Without ``sqlite_stat1`` the planner's choice does not depend on table
size, so a plan on a small fixture database is the plan on a large one.
"""
from __future__ import annotations

import re
import sqlite3
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest

from app import db as db_module
from app.services import activity as activity_service
from app.services import activity_feed
from app.services import events as events_service
from app.services import code_analysis_support
from app.services import submission_versions
from app.services import state_manager
from app.services.state_manager import coverage as coverage_module
from app.services.state_manager import findings as findings_module
from app.services.state_manager import oob as oob_module
from app.services.state_manager import proof_work as proof_work_module
from app.services.state_manager import proofs as proofs_module
from tests import test_proof_work_api as proof_work_tests
from tests.test_artifact_resume_api import (
    BASE,
    ENGAGEMENT_KEY,
    _register_note,
    _seed_finding,
    _write_engagement,
)

# name -> (table, key columns). ``None`` marks an expression column.
_HOT_PATH_INDEXES: dict[str, tuple[str, list[str | None]]] = {
    "idx_assessment_artifacts_producer_run": (
        "assessment_artifacts",
        ["producer_command_run_id", "engagement_id"],
    ),
    "idx_assessment_artifacts_attachment_eligible": (
        "assessment_artifacts",
        ["engagement_id", "present", "scratch", "updated_at", "id", "kind", "sha256"],
    ),
    "idx_assessment_probe_runs_coverage_item": (
        "assessment_probe_runs",
        ["coverage_item_id", "engagement_id"],
    ),
    "idx_assessment_work_items_coverage_item": (
        "assessment_work_items",
        ["coverage_item_id", "engagement_id"],
    ),
    "idx_assessment_finding_transitions_finding": (
        "assessment_finding_transitions",
        ["engagement_id", "finding_id", "id"],
    ),
    "idx_activity_entries_engagement_julianday": (
        "activity_entries",
        ["engagement_id", None, "id"],
    ),
    "idx_activity_entries_engagement_kind_title": (
        "activity_entries",
        ["engagement_id", "actor_kind", "actor_name", "title"],
    ),
    "idx_activity_entries_oob_verdict": (
        "activity_entries",
        ["engagement_id", None, "id"],
    ),
    "idx_events_engagement_julianday": (
        "events",
        ["engagement_id", None, "id"],
    ),
    "idx_assessment_request_observations_variant": (
        "assessment_request_observations",
        ["request_variant_id", "created_at", "id"],
    ),
    "idx_code_analysis_results_queue_receipt": (
        "code_analysis_results",
        ["engagement_id", "queue_item_id", "file_id", "repo_generation"],
    ),
}


def _index_key_columns(connection: sqlite3.Connection, name: str) -> list[str | None]:
    return [
        row[2]
        for row in connection.execute(f"PRAGMA index_xinfo({name})").fetchall()
        if row[5]  # key columns only; the trailing rowid is auxiliary
    ]


def _assert_hot_path_indexes(db_path: Path) -> None:
    with sqlite3.connect(str(db_path)) as connection:
        for name, (table, columns) in _HOT_PATH_INDEXES.items():
            declared = {
                row[1]
                for row in connection.execute(f"PRAGMA index_list({table})").fetchall()
            }
            assert name in declared, f"{name} missing on {table}"
            assert _index_key_columns(connection, name) == columns, name
        for name, expression in (
            ("idx_activity_entries_engagement_julianday", "julianday(occurred_at)"),
            ("idx_events_engagement_julianday", "julianday(created_at)"),
        ):
            expression_sql = connection.execute(
                "SELECT sql FROM sqlite_master WHERE name = ?", (name,)
            ).fetchone()[0]
            assert expression in expression_sql, name


def test_fresh_database_creates_hot_path_indexes(client, isolate_settings) -> None:
    _assert_hot_path_indexes(db_module.database_path())


def test_existing_database_without_hot_path_indexes_gains_them_on_startup(
    client, isolate_settings
) -> None:
    db_path = db_module.database_path()
    with sqlite3.connect(str(db_path)) as connection:
        for name in _HOT_PATH_INDEXES:
            connection.execute(f"DROP INDEX {name}")
    db_module.close_thread_connection()

    db_module.init_db()

    _assert_hot_path_indexes(db_path)


# An artifacts table from before the scratch/integrity columns were added: the
# attachment index covers ``scratch``, so it must be created only after the
# column migration has run, never against the pre-migration table.
_LEGACY_ARTIFACT_SCHEMA = """
CREATE TABLE engagements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT NOT NULL DEFAULT '',
    target TEXT NOT NULL DEFAULT ''
);
CREATE TABLE assessment_artifacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    relative_path TEXT NOT NULL,
    kind TEXT NOT NULL DEFAULT '',
    media_type TEXT NOT NULL DEFAULT '',
    size_bytes INTEGER NOT NULL DEFAULT 0,
    sha256 TEXT NOT NULL DEFAULT '',
    preview_text TEXT NOT NULL DEFAULT '',
    indexed_text TEXT NOT NULL DEFAULT '',
    sensitive INTEGER NOT NULL DEFAULT 0,
    present INTEGER NOT NULL DEFAULT 1,
    producer_agent_id TEXT,
    producer_agent_role TEXT,
    producer_command_run_id INTEGER,
    related_finding_slug TEXT,
    related_chain_key TEXT,
    related_surface_id INTEGER,
    related_request_variant_id INTEGER,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_indexed_at TEXT,
    UNIQUE(engagement_id, relative_path)
);
"""


def test_pre_migration_artifacts_table_gains_hot_path_indexes(isolate_settings) -> None:
    db_path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(str(db_path)) as connection:
        connection.executescript(_LEGACY_ARTIFACT_SCHEMA)

    db_module.init_db()

    _assert_hot_path_indexes(db_path)


@contextmanager
def _captured_statements() -> Iterator[tuple[sqlite3.Connection, list[str]]]:
    """Trace every statement the production helpers run on this thread's connection."""
    statements: list[str] = []
    with db_module.get_connection() as connection:
        connection.set_trace_callback(statements.append)
        try:
            yield connection, statements
        finally:
            connection.set_trace_callback(None)


def _plan(connection: sqlite3.Connection, sql: str) -> list[str]:
    return [
        str(row[3])
        for row in connection.execute("EXPLAIN QUERY PLAN " + sql).fetchall()
    ]


def _plans_for(
    connection: sqlite3.Connection,
    statements: list[str],
    predicate: Callable[[str], bool],
) -> list[list[str]]:
    plans = [_plan(connection, sql) for sql in statements if predicate(sql)]
    assert plans, "the production helper did not execute the expected statement"
    return plans


_PLAN_LINE_RE = re.compile(
    r"^(?:SCAN|SEARCH) (?P<name>\w+)"
    r"(?: USING (?P<access>COVERING INDEX|INDEX|INTEGER PRIMARY KEY)"
    r"(?: (?P<index>\w+))?(?: \((?P<constraint>[^)]*)\))?)?"
)
_SQL_KEYWORDS = {"WHERE", "JOIN", "LEFT", "INNER", "ON", "AND", "GROUP", "ORDER", "LIMIT", "SET"}


def _artifact_aliases(sql: str) -> set[str]:
    aliases = {"assessment_artifacts"}
    for alias in re.findall(r"\bassessment_artifacts\s+(?:AS\s+)?(\w+)", sql, re.IGNORECASE):
        if alias.upper() not in _SQL_KEYWORDS:
            aliases.add(alias)
    return aliases


def _unbounded_artifact_walks(
    connection: sqlite3.Connection, statements: list[str]
) -> list[tuple[str, str]]:
    """Plan lines that visit artifact table rows bounded only by engagement.

    Index-only (covering) walks and rowid / path / producer / finding seeks are
    bounded; a row walk constrained by nothing finer than the engagement and its
    present/scratch flags reads every artifact's text.
    """
    offenders: list[tuple[str, str]] = []
    for sql in statements:
        if not re.search(r"\bassessment_artifacts\b", sql):
            continue
        if not sql.lstrip().upper().startswith(("SELECT", "WITH")):
            continue
        aliases = _artifact_aliases(sql)
        for detail in _plan(connection, sql):
            match = _PLAN_LINE_RE.match(detail)
            if match is None or match.group("name") not in aliases:
                continue
            if match.group("access") in {"COVERING INDEX", "INTEGER PRIMARY KEY"}:
                continue
            constrained = set(re.findall(r"(\w+)\s*[=<>]", match.group("constraint") or ""))
            if constrained - {"engagement_id", "present", "scratch"}:
                continue
            offenders.append((" ".join(sql.split())[:200], detail))
    return offenders


def test_command_output_evidence_health_seeks_artifacts_by_producer_run(
    client, isolate_settings
) -> None:
    with _captured_statements() as (connection, statements):
        proofs_module._command_output_evidence_healths(connection, 1, [3, 7])

    plans = _plans_for(
        connection,
        statements,
        lambda sql: "FROM assessment_artifacts" in sql and "producer_command_run_id IN" in sql,
    )

    assert all(
        any("idx_assessment_artifacts_producer_run" in line for line in plan)
        for plan in plans
    ), plans
    assert not _unbounded_artifact_walks(connection, statements)


def test_assessment_summary_never_walks_every_artifact_row(client, isolate_settings) -> None:
    """The overview summary reads artifact rows only by key, never the whole index.

    The seeded engagement exercises every artifact read on the summary path:
    durable markdown notes (citation and link checks), finding evidence lookups
    by path and id, and command-proof evidence health for a confirmed finding.
    """
    eng = _write_engagement(isolate_settings["engagements_dir"])
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200
    _seed_finding(client, eng)
    (eng / "RESUME.md").write_text("Deferred work is tracked in `MISSING.md`.", encoding="utf-8")
    _register_note(client, "RESUME.md", producer_agent_id="operator")
    capture = eng / "evidence" / "capture.txt"
    capture.parent.mkdir(parents=True, exist_ok=True)
    capture.write_text("captured response body\n" * 64, encoding="utf-8")
    registered = client.post(f"{BASE}/artifacts", json={"path": "evidence/capture.txt", "kind": "evidence"})
    assert registered.status_code == 201, registered.text
    engagement = db_module.get_engagement_by_key(ENGAGEMENT_KEY)
    assert engagement is not None
    state_manager.clear_assessment_summary_cache()

    with _captured_statements() as (connection, statements):
        summary = state_manager.assessment_summary(engagement.id)
    offenders = _unbounded_artifact_walks(connection, statements)

    assert summary["finding_count"] == 1
    assert any(
        "producer_command_run_id IN" in sql for sql in statements
    ), "the confirmed finding's command-proof health path did not run"
    assert not offenders, offenders


def test_pending_work_item_drain_seeks_by_coverage_item(client, isolate_settings) -> None:
    with _captured_statements() as (connection, statements):
        coverage_module._pending_work_item_ids_for_coverage_item(connection, 1, 5)

    plans = _plans_for(
        connection, statements, lambda sql: "FROM assessment_work_items" in sql
    )

    assert all(
        any("idx_assessment_work_items_coverage_item" in line for line in plan)
        for plan in plans
    ), plans


@pytest.mark.parametrize(
    ("parent_delete", "child", "index"),
    [
        (
            "DELETE FROM assessment_coverage_items WHERE id = 1",
            "assessment_probe_runs",
            "idx_assessment_probe_runs_coverage_item",
        ),
        (
            "DELETE FROM assessment_coverage_items WHERE id = 1",
            "assessment_work_items",
            "idx_assessment_work_items_coverage_item",
        ),
        (
            "DELETE FROM assessment_command_runs WHERE id = 1",
            "assessment_artifacts",
            "idx_assessment_artifacts_producer_run",
        ),
    ],
)
def test_parent_delete_seeks_set_null_children(
    client, isolate_settings, parent_delete: str, child: str, index: str
) -> None:
    """``ON DELETE SET NULL`` children are found by seek, not a table scan.

    Engagement deletion cascades into every coverage item and command run; an
    unindexed child key turns each parent row into a full scan of the child.
    """
    with sqlite3.connect(str(db_module.database_path())) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        plan = _plan(connection, parent_delete)

    child_lines = [line for line in plan if re.match(rf"^(?:SCAN|SEARCH) {child}\b", line)]
    assert child_lines, plan
    assert all(index in line for line in child_lines), plan


def test_claim_review_status_seeks_transitions_by_finding(client, isolate_settings) -> None:
    row = {
        "id": 11,
        "slug": "VA-011",
        "title": "Acme login replay",
        "verification_status": "confirmed",
        "details_json": "{}",
    }
    with _captured_statements() as (connection, statements):
        findings_module._claim_review_status(connection, 1, row)

    plans = _plans_for(
        connection,
        statements,
        lambda sql: "FROM assessment_finding_transitions" in sql,
    )

    assert len(plans) == 2
    assert all(
        any(
            "idx_assessment_finding_transitions_finding (engagement_id=? AND finding_id=?" in line
            for line in plan
        )
        for plan in plans
    ), plans


def test_activity_page_is_read_in_index_order(client, isolate_settings) -> None:
    _write_engagement(isolate_settings["engagements_dir"])
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200
    engagement = db_module.get_engagement_by_key(ENGAGEMENT_KEY)
    assert engagement is not None

    with _captured_statements() as (connection, statements):
        activity_service.list_activity_entries(engagement.id, limit=50)
        activity_service.list_activity_entries(
            engagement.id, since="2026-01-01T00:00:00Z", limit=50
        )

    plans = _plans_for(
        connection,
        statements,
        lambda sql: "ORDER BY julianday(a.occurred_at) DESC" in sql,
    )

    assert len(plans) == 2
    for plan in plans:
        assert any("idx_activity_entries_engagement_julianday" in line for line in plan), plan
        assert not any("TEMP B-TREE FOR ORDER BY" in line for line in plan), plan


def test_oob_probe_verdict_read_seeks_operator_verdict_entries(client, isolate_settings) -> None:
    """A probe point read finds its verdict without walking the audit log."""
    with _captured_statements() as (connection, statements):
        oob_module._latest_verdict(connection, 1, {"nonce": "acmenonce", "status": "confirmed"})

    plans = _plans_for(connection, statements, lambda sql: "FROM activity_entries" in sql)

    for plan in plans:
        assert any("idx_activity_entries_oob_verdict" in line for line in plan), plan
        assert not any("TEMP B-TREE FOR ORDER BY" in line for line in plan), plan


def test_proof_work_linked_run_receipt_counts_seek_by_engagement_and_run(
    client, isolate_settings
) -> None:
    """A proof-work entry counts each linked run's receipts by seek, not by a
    walk of every engagement's receipts."""
    proof_work_tests.seed(client, isolate_settings)
    work = proof_work_tests.prepare(client)
    engagement = db_module.get_engagement_by_key(proof_work_tests.KEY)
    assert engagement is not None

    with _captured_statements() as (connection, statements):
        proof_work_module.get_proof_work(engagement.id, work["id"])

    plans = _plans_for(
        connection, statements, lambda sql: "FROM assessment_proof_receipts p" in sql and "AS proof_receipts" in sql
    )

    for plan in plans:
        receipt_lines = [line for line in plan if re.match(r"^(?:SCAN|SEARCH) p\b", line)]
        assert receipt_lines, plan
        assert all("engagement_id=? AND run_id=?" in line for line in receipt_lines), plan


def _seeded_engagement_id(client, isolate_settings) -> int:
    _write_engagement(isolate_settings["engagements_dir"])
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200
    engagement = db_module.get_engagement_by_key(ENGAGEMENT_KEY)
    assert engagement is not None
    return engagement.id


def test_activity_feed_category_counts_read_only_the_actor_title_index(
    client, isolate_settings
) -> None:
    """Every Activity page load counts the audit log by category.

    The category and actor-kind expressions read only actor and title, so the
    unfiltered count stays index-only instead of visiting every audit row.
    """
    engagement_id = _seeded_engagement_id(client, isolate_settings)

    with _captured_statements() as (connection, statements):
        activity_feed.list_activity_feed(engagement_id)
        activity_feed.list_activity_feed(engagement_id, actor="agent")

    plans = _plans_for(
        connection,
        statements,
        lambda sql: "FROM activity_entries a" in sql and "GROUP BY category" in sql,
    )

    assert plans == [
        [
            "SEARCH a USING COVERING INDEX idx_activity_entries_engagement_kind_title "
            "(engagement_id=?)",
            "USE TEMP B-TREE FOR GROUP BY",
        ]
    ] * 2


def test_activity_feed_and_timeline_read_events_in_index_order(
    client, isolate_settings
) -> None:
    """Event pages walk the julianday index instead of sorting every event."""
    engagement_id = _seeded_engagement_id(client, isolate_settings)

    with _captured_statements() as (connection, statements):
        activity_feed.list_activity_feed(engagement_id, limit=1)
        activity_feed.list_activity_feed(
            engagement_id, before="2461000.5~event~10", limit=1
        )
        events_service.list_events_for_engagement(engagement_id, limit=5)

    feed_pages = _plans_for(
        connection,
        statements,
        lambda sql: "FROM events e" in sql and "ORDER BY julianday(e.created_at) DESC" in sql,
    )
    stored_timeline = _plans_for(
        connection,
        statements,
        lambda sql: sql.lstrip().startswith("SELECT id, engagement_id, event_type,")
        and "ORDER BY julianday(created_at) DESC" in sql,
    )

    plans = [*feed_pages, *stored_timeline]
    assert len(plans) == 3, plans
    for plan in plans:
        assert any("idx_events_engagement_julianday" in line for line in plan), plan
        assert not any("TEMP B-TREE FOR ORDER BY" in line for line in plan), plan


def test_submission_attachment_counts_seek_their_indexes(client, isolate_settings) -> None:
    """Each attachment count the submission detail runs stays bounded.

    The detail counts the finding's linked files, every eligible engagement
    file, and the internal workspace files subtracted from that total. The
    engagement-wide count must stay index-only; the other two may read rows
    only after seeking the finding's files or the ``submissions/`` path range.
    """
    eng = _write_engagement(isolate_settings["engagements_dir"])
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200
    _seed_finding(client, eng)
    engagement = db_module.get_engagement_by_key(ENGAGEMENT_KEY)
    assert engagement is not None

    with _captured_statements() as (connection, statements):
        submission_versions.submission_detail(engagement.id, "VA-047")

    def attachment_count(sql: str) -> bool:
        return (
            sql.lstrip().startswith("SELECT COUNT(*) FROM assessment_artifacts")
            and "length(sha256) = 64" in sql
        )

    def finding_linked(sql: str) -> bool:
        return "related_finding_slug =" in sql

    def internal_paths(sql: str) -> bool:
        return "relative_path >= 'submissions/'" in sql

    assert _plans_for(
        connection,
        statements,
        lambda sql: attachment_count(sql) and finding_linked(sql),
    ) == [
        [
            "SEARCH assessment_artifacts USING INDEX idx_assessment_artifacts_finding "
            "(engagement_id=? AND related_finding_slug=?)"
        ]
    ]
    assert _plans_for(
        connection,
        statements,
        lambda sql: attachment_count(sql)
        and not finding_linked(sql)
        and not internal_paths(sql),
    ) == [
        [
            "SEARCH assessment_artifacts USING COVERING INDEX "
            "idx_assessment_artifacts_attachment_eligible "
            "(engagement_id=? AND present=? AND scratch=?)"
        ]
    ]
    assert _plans_for(
        connection,
        statements,
        lambda sql: attachment_count(sql) and internal_paths(sql),
    ) == [
        [
            "SEARCH assessment_artifacts USING INDEX "
            "idx_assessment_artifacts_engagement_path "
            "(engagement_id=? AND relative_path>? AND relative_path<?)"
        ]
    ]


def test_suspicious_analysis_counts_seek_results_by_queue_item(
    client, isolate_settings
) -> None:
    """Correlated receipt lookups seek the attempt's own results.

    Planned onto the (engagement, generation) index instead, every queue
    attempt rescans every result of its repository generation -- quadratic in
    the size of a code engagement.
    """
    with _captured_statements() as (connection, statements):
        code_analysis_support._current_suspicious_analysis_counts(connection, 1)

    plans = _plans_for(
        connection, statements, lambda sql: "FROM code_analysis_results" in sql
    )

    with sqlite3.connect(str(db_module.database_path())) as inspection:
        result_indexes = {
            row[1]
            for row in inspection.execute("PRAGMA index_list(code_analysis_results)").fetchall()
        }
    result_lines = [
        line
        for plan in plans
        for line in plan
        if (match := _PLAN_LINE_RE.match(line)) and match.group("index") in result_indexes
    ]
    assert result_lines, plans
    assert all("queue_item_id=?" in line for line in result_lines), result_lines


def test_request_variant_reads_seek_observations_by_variant(client, isolate_settings) -> None:
    """Observation counts on an inventory page, one variant's count, and its
    observation list seek by variant instead of walking the engagement's
    observations (hundreds of thousands on a large web engagement)."""
    _write_engagement(isolate_settings["engagements_dir"])
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200
    ingested = client.post(
        f"{BASE}/request-observations",
        json={"url": "https://shop.acme.example/orders?id=1", "auto_generate_coverage": False},
    )
    assert ingested.status_code == 201, ingested.text
    variant_id = ingested.json()["request_variant"]["id"]
    engagement = db_module.get_engagement_by_key(ENGAGEMENT_KEY)
    assert engagement is not None

    with _captured_statements() as (connection, statements):
        page = coverage_module.page_request_variants(engagement.id, coverage_module.RequestVariantFilters())
        coverage_module.get_request_variant_detail(engagement.id, variant_id)
        coverage_module.page_request_variant_observations(engagement.id, variant_id)

    assert page["items"][0]["observation_count"] == 1
    plans = _plans_for(
        connection,
        statements,
        lambda sql: "FROM assessment_request_observations" in sql and "request_variant_id" in sql,
    )
    assert len(plans) >= 4, plans
    assert all(
        any("idx_assessment_request_observations_variant" in line for line in plan)
        for plan in plans
    ), plans
