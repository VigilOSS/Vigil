"""B9: the two read surfaces that must show a dispatch which died mid-file.

`code-coverage` is the report projection and `resume-brief` is what a resumed
session reads first. An open analysis lease is durable debt in both: the file is
claimed, receipts may already be recorded, and nothing has closed it — so a
picture that only counts "active queue items" hides the work that is at risk.
"""
from __future__ import annotations

from assess.commands import code_coverage, resume_brief


_OPEN_LEASE = {
    "queue_item_id": 41,
    "file_id": 7,
    "file_path": "src/parser.py",
    "classification": "critical",
    "repo_id": 1,
    "repo_key": "target-repo",
    "queue_mode": "initial",
    "batch_theme": "parser-core",
    "agent_name": "hunter-a",
    "lease_token": "lease-a",
    "consumed_at": "2026-09-16T07:00:00Z",
    "last_heartbeat_at": "2026-09-16T08:00:00Z",
    "lease_activity_at": "2026-09-16T08:00:00Z",
    "heartbeat_age_seconds": 5400,
    "current_result_count": 3,
    "adopted_leases": [],
}


def test_coverage_renders_open_leases_with_their_stranded_receipts(capsys):
    code_coverage._print_coverage(
        {
            "total_files": 2,
            "open_leases": [_OPEN_LEASE],
            "open_leases_count": 1,
        }
    )

    out = capsys.readouterr().out
    assert "src/parser.py" in out
    assert "hunter-a" in out
    # Verbatim lease token (ADR 0019) plus the receipt count that decides
    # between adopting the attempt and discarding it.
    assert "lease-a" in out
    assert "3 receipt" in out
    # One age vocabulary, shared with the `code-dispatch list` column.
    assert "1h30m" in out


def test_coverage_omits_the_section_when_no_lease_is_open(capsys):
    code_coverage._print_coverage({"total_files": 2, "open_leases": [], "open_leases_count": 0})

    assert "Open Analysis Leases" not in capsys.readouterr().out


def test_resume_brief_renders_open_code_leases(capsys):
    out = resume_brief._render_markdown(
        {
            "engagement": {"key": "eng"},
            "code_analysis": {"open_leases": [_OPEN_LEASE], "open_leases_count": 1},
        }
    )

    assert "## Code Analysis" in out
    assert "src/parser.py" in out
    assert "hunter-a" in out
    assert "lease-a" in out
    assert "receipts=3" in out


def test_resume_brief_code_section_is_a_noop_for_a_web_engagement():
    out = resume_brief._render_markdown(
        {
            "engagement": {"key": "eng"},
            "code_analysis": {"open_leases": [], "open_leases_count": 0},
        }
    )

    assert "## Code Analysis" not in out


def test_resume_brief_reports_the_true_total_behind_a_capped_lease_list():
    out = resume_brief._render_markdown(
        {
            "engagement": {"key": "eng"},
            "code_analysis": {"open_leases": [_OPEN_LEASE], "open_leases_count": 14},
        }
    )

    assert "showing 1 of 14" in out
