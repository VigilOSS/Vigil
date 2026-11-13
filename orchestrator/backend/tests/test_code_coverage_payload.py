"""Coverage reads stay bounded: effort gaps arrive grouped, families are derived once.

The default `code/coverage` (and readiness `include_coverage`) carries effort
shortfalls as tier x family groups with counts, a few sample paths and the
exact read that lists every row; only `detail=cwe` carries the per-file rows.
"""
from __future__ import annotations

import json
import sqlite3

from app.services import code_analysis
from test_code_analysis_api import db_module
from test_code_review_depth import _seed

_SAMPLES = 3


def _lower_every_effort(engagement_key: str) -> None:
    """Rewrite every recorded effort to 10, below every tier's threshold."""
    with sqlite3.connect(str(db_module.database_path())) as connection:
        engagement_id = connection.execute(
            "SELECT id FROM engagements WHERE key = ?", (engagement_key,)
        ).fetchone()[0]
        for table in ("code_analysis_queue", "code_analysis_results"):
            rows = connection.execute(
                f"SELECT id, cwe_coverage_json FROM {table} WHERE engagement_id = ?",
                (engagement_id,),
            ).fetchall()
            for row_id, raw in rows:
                entries = json.loads(raw or "[]")
                for entry in entries:
                    if isinstance(entry, dict) and "effort" in entry:
                        entry["effort"] = 10
                connection.execute(
                    f"UPDATE {table} SET cwe_coverage_json = ? WHERE id = ?",
                    (json.dumps(entries), row_id),
                )
        connection.commit()


def test_default_coverage_groups_effort_gaps_and_names_the_full_read(client, isolate_settings):
    key = "2026-11-14-effort-gap-groups"
    base, _ids = _seed(client, isolate_settings, key)
    _lower_every_effort(key)

    detail = client.get(f"{base}/coverage?detail=cwe")
    assert detail.status_code == 200, detail.text
    full = detail.json()["gate"]["effort_gaps"]
    rows = full["rows"]
    assert rows and full["rows_omitted"] == 0
    assert full["total"] == len(rows)
    assert {"file_id", "file_path", "classification", "family", "effort", "threshold",
            "message"} <= set(rows[0])

    summary = client.get(f"{base}/coverage")
    assert summary.status_code == 200, summary.text
    grouped = summary.json()["gate"]["effort_gaps"]
    assert "rows" not in grouped
    assert grouped["total"] == len(rows)
    assert grouped["rows_omitted"] == len(rows)
    assert grouped["file_count"] == len({row["file_id"] for row in rows})
    assert "--cwe-matrix" in grouped["full_list"] and "detail=cwe" in grouped["full_list"]

    expected: dict[tuple[str, str], set[str]] = {}
    for row in rows:
        expected.setdefault((row["classification"], row["family"]), set()).add(row["file_path"])
    groups = grouped["groups"]
    assert {(group["classification"], group["family"]) for group in groups} == set(expected)
    for group in groups:
        paths = expected[(group["classification"], group["family"])]
        assert group["file_count"] == len(paths)
        assert group["threshold"] == code_analysis.EFFORT_THRESHOLDS[group["classification"]]
        assert len(group["sample_file_paths"]) == min(_SAMPLES, len(paths))
        assert set(group["sample_file_paths"]) <= paths
    assert sum(group["file_count"] for group in groups) == grouped["total"]
    # Tier order first (critical before high before medium), then the widest gap.
    tiers = [group["classification"] for group in groups]
    assert tiers == sorted(tiers, key=["critical", "high", "medium"].index)
    # Bounded by the groups, not by the rows: no per-file row is carried.
    assert len(json.dumps(grouped)) < len(json.dumps(full))
    # The `warnings` lines are one per group plus a header (asserted below).
    structure = {key: value for key, value in grouped.items() if key != "warnings"}
    assert len(json.dumps(structure)) <= 400 * len(groups) + 400

    # Each read names, structurally, which of its `effort_warnings` lines carry
    # the shortfalls, so the CLI never parses their wording: the per-file
    # messages on the full read, the grouped lines on the default read.
    gap_messages = [row["message"] for row in rows]
    assert full["warnings"] == gap_messages
    assert set(gap_messages) <= set(detail.json()["gate"]["effort_warnings"])

    default_warnings = summary.json()["gate"]["effort_warnings"]
    grouped_lines = grouped["warnings"]
    assert len(grouped_lines) == len(groups) + 1
    assert set(grouped_lines) <= set(default_warnings)
    assert all(
        line.startswith(code_analysis.EFFORT_GAP_WARNING_PREFIX) for line in grouped_lines
    )
    assert not set(gap_messages) & set(default_warnings)

    readiness = client.get(f"{base}/readiness?target_phase=complete&include_coverage=true")
    assert readiness.status_code == 200, readiness.text
    assert readiness.json()["coverage"]["gate"]["effort_gaps"] == grouped
    quality = readiness.json()["quality_gate"]
    assert quality["effort_gap_warnings"] == grouped_lines
    assert set(quality["effort_gap_warnings"]) <= set(quality["warnings"])


def test_cwe_matrix_derives_each_files_required_families_once(
    client, isolate_settings, monkeypatch
):
    base, _ids = _seed(client, isolate_settings, "2026-11-14-family-derivation-once")
    original = code_analysis._applicable_families_for_file
    calls: list[str] = []

    def counted(*args, **kwargs):
        calls.append("x")
        return original(*args, **kwargs)

    monkeypatch.setattr(code_analysis, "_applicable_families_for_file", counted)
    summary = client.get(f"{base}/coverage")
    assert summary.status_code == 200, summary.text
    summary_calls = len(calls)
    calls.clear()
    detail = client.get(f"{base}/coverage?detail=cwe")
    assert detail.status_code == 200, detail.text
    files = detail.json()["files"]
    assert files
    # The matrix embeds the summary, so it pays the summary's derivations plus
    # exactly one per listed file; the advisory hints reuse that one.
    assert len(calls) == summary_calls + len(files), (len(calls), summary_calls, len(files))


def test_default_effort_warnings_carry_the_gap_groups_not_every_row(client, isolate_settings):
    """`gate.effort_warnings`, and readiness `quality_gate.warnings` built from
    it, name each tier x family group once: its file count, up to three sample
    messages verbatim and the read that lists the rest. `detail=cwe` keeps every
    per-file message."""
    key = "2026-11-14-effort-warning-groups"
    base, _ids = _seed(client, isolate_settings, key)
    _lower_every_effort(key)

    rows = client.get(f"{base}/coverage?detail=cwe").json()["gate"]["effort_gaps"]["rows"]
    gap_messages = {row["message"] for row in rows}
    gate = client.get(f"{base}/coverage").json()["gate"]
    warnings = gate["effort_warnings"]
    groups = gate["effort_gaps"]["groups"]

    assert not gap_messages & set(warnings)
    lines = [w for w in warnings if w.startswith(code_analysis.EFFORT_GAP_WARNING_PREFIX)]
    assert len(lines) == len(groups) + 1
    header, *group_lines = lines
    assert f"{len(rows)} family gap(s)" in header
    assert f"{gate['effort_gaps']['file_count']} file(s)" in header
    assert "--cwe-matrix" in header
    for group, line in zip(groups, group_lines, strict=True):
        assert f"{group['classification'].capitalize()} x {group['family']}" in line
        assert f"{group['file_count']} file(s)" in line
        for path in group["sample_file_paths"]:
            message = next(
                row["message"] for row in rows
                if row["file_path"] == path and row["family"] == group["family"]
                and row["classification"] == group["classification"]
            )
            assert message in line
        hidden = group["file_count"] - len(group["sample_file_paths"])
        assert (f"+{hidden} more" in line) is (hidden > 0)

    readiness = client.get(f"{base}/readiness?target_phase=complete").json()
    assert set(lines) <= set(readiness["quality_gate"]["warnings"])
    assert not gap_messages & set(readiness["quality_gate"]["warnings"])
