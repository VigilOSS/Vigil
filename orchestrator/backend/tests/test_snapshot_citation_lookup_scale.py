"""Distinct citation lookup costs one basename projection per sealed roster."""

from __future__ import annotations

import difflib
import importlib
import sqlite3

import pytest

from app.services.state_manager import finding_snapshots as snapshots

report_readiness = importlib.import_module(
    "app.services.state_manager.report_readiness"
)


class _Rows:
    def __init__(self, rows):
        self.rows = rows

    def fetchall(self):
        return self.rows


class _MeasuredRoster:
    """Keep SQLite citation semantics and count path work on roster loads."""

    def __init__(self, paths):
        self.connection = sqlite3.connect(":memory:")
        self.connection.row_factory = sqlite3.Row
        self.connection.executescript(
            """
            CREATE TABLE code_source_generation_files (
                engagement_id INTEGER, repo_id INTEGER, repo_generation INTEGER,
                file_id INTEGER, file_path TEXT, file_hash TEXT, language TEXT, loc INTEGER
            );
            CREATE INDEX sealed_path ON code_source_generation_files (
                engagement_id, repo_id, repo_generation, file_path
            );
            CREATE TABLE code_analysis_triggers (
                engagement_id INTEGER, repo_id INTEGER,
                target_file_id INTEGER, target_file_path TEXT
            );
            """
        )
        self.connection.executemany(
            "INSERT INTO code_source_generation_files VALUES (1, 1, 3, ?, ?, 'hash', 'php', 20)",
            enumerate(paths, start=1),
        )
        self.roster_loads = 0
        self.basename_splits = 0
        measured = self

        class _Path(str):
            def __str__(self):
                return self

            def rsplit(self, *args, **kwargs):
                measured.basename_splits += 1
                assert measured.basename_splits <= len(paths) * 2, (
                    "distinct citations repeatedly rescan the entire sealed roster",
                    measured.basename_splits,
                )
                return super().rsplit(*args, **kwargs)

        self.path_type = _Path

    def execute(self, sql, params=()):
        cursor = self.connection.execute(sql, params)
        if "SELECT file_path FROM code_source_generation_files" in sql:
            self.roster_loads += 1
            return _Rows(
                [
                    {"file_path": self.path_type(row["file_path"])}
                    for row in cursor.fetchall()
                ]
            )
        return cursor


def _finding(citations):
    return {
        "slug": "VA-ACME",
        "title": "Acme source review",
        "provenance": {
            "code_snapshot": {
                "repo_id": 1,
                "repo_generation": 3,
                "source_manifest_digest": "a" * 64,
            }
        },
        "details": {"evidence": citations},
    }


@pytest.mark.parametrize("has_namesake", [True, False])
def test_distinct_citations_index_names_once_and_compare_only_namesakes(
    monkeypatch, has_namesake
):
    paths = [
        f"src/{directory}/file{number:05}.php"
        for directory in ("a", "b")
        for number in range(14000)
    ]
    roster = _MeasuredRoster(paths)
    citation_count = 5302
    citations = [
        f"legacy/branch{number}/{'file' if has_namesake else 'external'}{number:05}.php:9"
        for number in range(citation_count)
    ]
    compared = 0
    original = difflib.get_close_matches

    def measured_matches(word, possibilities, *args, **kwargs):
        nonlocal compared
        compared += len(possibilities)
        assert compared <= citation_count * 2, (
            "readiness compares paths whose basenames cannot produce a blocker",
            compared,
        )
        return original(word, possibilities, *args, **kwargs)

    monkeypatch.setattr(snapshots.difflib, "get_close_matches", measured_matches)
    blockers = report_readiness._details_citation_blockers(
        roster, 1, [_finding(citations)]
    )
    assert len(blockers) == (citation_count if has_namesake else 0)
    assert roster.roster_loads == 1
    assert roster.basename_splits <= len(paths) + citation_count
    assert compared == (citation_count * 2 if has_namesake else 0)
    if has_namesake:
        assert [blocker["path"] for blocker in blockers] == [
            cite.rsplit(":", 1)[0] for cite in citations
        ]
        for blocker in blockers:
            path = blocker["path"]
            namesakes = [
                f"src/{directory}/{path.rsplit('/', 1)[-1]}" for directory in ("a", "b")
            ]
            assert (
                blocker["closest_admitted_path"]
                == original(path, namesakes, n=1, cutoff=0)[0]
            )


def test_generic_lookup_keeps_spelling_fallback_and_namesake_tie_order():
    paths = ["src/a/parser.php", "src/b/parser.php", "src/router.php"]
    for path in ("old/parser.php", "src/routr.php", "vendor/external.missing"):
        roster = _MeasuredRoster(paths)
        namesakes = [
            candidate
            for candidate in paths
            if candidate.rsplit("/", 1)[-1] == path.rsplit("/", 1)[-1]
        ]
        expected = difflib.get_close_matches(
            path, namesakes or paths, n=1, cutoff=0 if namesakes else 0.6
        )
        assert snapshots.closest_snapshot_path(roster, 1, 1, 3, path) == (
            expected[0] if expected else None
        )


def test_request_memo_separates_readiness_namesakes_from_generic_spelling():
    roster = _MeasuredRoster(["src/router.php", "src/a/parser.php", "src/b/parser.php"])
    caches = {"roster_cache": {}, "basename_cache": {}, "closest_cache": {}}
    path = "src/routr.php"
    assert (
        snapshots.closest_snapshot_path(
            roster, 1, 1, 3, path, same_basename_only=True, **caches
        )
        is None
    )
    assert (
        snapshots.closest_snapshot_path(roster, 1, 1, 3, path, **caches)
        == "src/router.php"
    )
    assert (
        snapshots.closest_snapshot_path(
            roster, 1, 1, 3, path, same_basename_only=True, **caches
        )
        is None
    )
    assert roster.roster_loads == 1
    assert roster.basename_splits == 3
