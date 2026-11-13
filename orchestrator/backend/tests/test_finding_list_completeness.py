"""`finding list` against a real backend never drops rows without saying so.

The ledger here is shaped like a late-phase engagement: more findings than one
default page, sixteen highs spread across workflow states that sort after the
bulk of active mediums (exploited, active, blocked, reported, draft, merged),
highs that are root-cause siblings of a low root, and highs parked on
pending_runtime_proof. The ledger orders by workflow state, not severity, so
an unfiltered default page shows only the highs that sort into it.

Each test drives the real CLI command through its argparse defaults against
the real route, and compares what it prints with the stored rows.
"""
from __future__ import annotations

import argparse
import json
import sqlite3

import pytest

from app import db as db_module

ENGAGEMENT_KEY = "2026-11-13-120000-list-completeness"
AUTHOR_AGENT_ID = "LIST-COMPLETENESS-FIXTURE-AUTHOR"
MEDIUM_ACTIVE = 110
# (slug, workflow status, verification status) for the sixteen highs.
HIGHS = (
    ("VA-301", "exploited", "confirmed"),
    ("VA-302", "exploited", "confirmed"),
    ("VA-303", "active", "confirmed"),
    ("VA-304", "active", "confirmed"),
    ("VA-305", "active", "confirmed"),
    ("VA-306", "active", "downgraded"),
    ("VA-307", "active", "confirmed"),
    ("VA-308", "active", "pending_runtime_proof"),
    ("VA-309", "active", "pending_runtime_proof"),
    ("VA-310", "blocked", "blocked"),
    ("VA-311", "reported", "confirmed"),
    ("VA-312", "reported", "confirmed"),
    ("VA-313", "reported", "confirmed"),
    ("VA-314", "draft", "unreviewed"),
    ("VA-315", "draft", "unreviewed"),
    ("VA-316", "merged", "confirmed"),
)
LOWS = ("VA-401", "VA-402", "VA-403", "VA-404")
TOTAL = MEDIUM_ACTIVE + len(HIGHS) + len(LOWS)


def _base() -> str:
    return f"/engagements/{ENGAGEMENT_KEY}/assessment"


def _payload(slug: str, severity: str) -> dict:
    return {
        "slug": slug,
        "title": f"Acme {severity} finding {slug}",
        "severity": severity,
        "workflow_status": "active",
        "defect_family": "access-control",
        "root_cause_key": f"root-{slug.lower()}",
        "canonical_location": f"https://app.example/api/{slug.lower()}",
        "summary": f"{severity} finding",
        "evidence_ref": "findings.md",
        "source_name": "vulnerability-analyst",
        "details": {"evidence": "Replayable request.", "impact": "Acme data exposure."},
        "provenance": {"agent_id": AUTHOR_AGENT_ID, "agent_name": "vulnerability-analyst"},
    }


@pytest.fixture
def ledger(client, isolate_settings):
    engagement_dir = isolate_settings["engagements_dir"] / ENGAGEMENT_KEY
    (engagement_dir / "sessions").mkdir(parents=True, exist_ok=True)
    (engagement_dir / "scope.json").write_text(
        json.dumps({"engagement_name": "Acme", "targets": ["https://app.example"]}),
        encoding="utf-8",
    )
    (engagement_dir / "findings.md").write_text("# Findings\n", encoding="utf-8")
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200
    dispatch = client.post(
        f"{_base()}/dispatches",
        json={
            "agent_id": AUTHOR_AGENT_ID,
            "agent_role": "vulnerability-analyst",
            "task": "Record list-completeness fixture rows",
        },
    )
    assert dispatch.status_code == 201, dispatch.text
    seeds = [(f"VA-{index}", "medium") for index in range(101, 101 + MEDIUM_ACTIVE)]
    seeds += [(slug, "high") for slug, _status, _verification in HIGHS]
    seeds += [(slug, "low") for slug in LOWS]
    for slug, severity in seeds:
        response = client.post(f"{_base()}/findings", json=_payload(slug, severity))
        assert response.status_code in (200, 201), response.text
    # Two highs are root-cause siblings of a low root.
    for sibling in ("VA-303", "VA-312"):
        link = client.put(
            f"{_base()}/findings/{sibling}/root-cause",
            json={
                "root_cause_slug": "VA-401",
                "root_cause_effect": "eliminates_attack_path",
                "note": "Shared Acme guard.",
            },
        )
        assert link.status_code == 200, link.text
    # Lifecycle states are set directly: this pins the listing over every
    # stored state, not the verify/merge write paths that reach them.
    with sqlite3.connect(str(db_module.database_path())) as connection:
        for slug, workflow_status, verification_status in HIGHS:
            connection.execute(
                "UPDATE assessment_findings SET status = ?, verification_status = ? WHERE slug = ?",
                (workflow_status, verification_status, slug),
            )
        connection.execute(
            "UPDATE assessment_findings SET merged_into_finding_id = "
            "(SELECT id FROM assessment_findings WHERE slug = 'VA-301') WHERE slug = 'VA-316'"
        )
        connection.commit()
    return client


def _run_cli(client, monkeypatch, capsys, *argv: str, verb: str = "list"):
    from assess.commands import list_findings, list_report_findings
    from assess.lib.client import AssessError

    module = list_report_findings if verb == "report" else list_findings

    class _Bridge:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_exc) -> bool:
            return False

        def get(self, endpoint: str):
            response = client.get(f"{_base()}/{endpoint}")
            if response.status_code >= 400:
                raise AssessError(f"HTTP {response.status_code}: {response.text}")
            return response.json()

    monkeypatch.setattr(module, "AssessmentClient", _Bridge)
    monkeypatch.setattr(
        module,
        "load_config",
        lambda _path: argparse.Namespace(base_url="http://backend.example", engagement_key=ENGAGEMENT_KEY),
    )
    parser = argparse.ArgumentParser()
    module.register(parser.add_subparsers(dest="action"))
    args = parser.parse_args([verb, *argv])
    args.engagement_dir = "/engagements/acme"
    capsys.readouterr()
    args.func(args)
    return capsys.readouterr()


def _table_slugs(stdout: str) -> list[str]:
    return [line.split(" | ", 1)[0] for line in stdout.splitlines() if " | " in line]


def test_severity_filter_lists_every_high_across_every_workflow_state(
    ledger, monkeypatch, capsys
):
    captured = _run_cli(ledger, monkeypatch, capsys, "--severity", "high")

    assert sorted(_table_slugs(captured.out)) == sorted(slug for slug, *_ in HIGHS)
    assert "showing 1-16 of 16 matching findings" in captured.out
    assert "INCOMPLETE" not in captured.out + captured.err


def test_filtered_default_is_complete_past_one_hundred_rows(ledger, monkeypatch, capsys):
    captured = _run_cli(ledger, monkeypatch, capsys, "--status", "active", "--json")

    rows = json.loads(captured.out)
    stored = ledger.get(f"{_base()}/findings", params={"workflow_status": "active"}).json()
    assert len(rows) == len(stored) == MEDIUM_ACTIVE + 7 + len(LOWS)
    assert f"of {len(stored)} matching findings" in captured.err
    assert "INCOMPLETE" not in captured.err


def test_unfiltered_default_page_states_exact_totals_on_stdout(ledger, monkeypatch, capsys):
    captured = _run_cli(ledger, monkeypatch, capsys)

    slugs = _table_slugs(captured.out)
    assert len(slugs) == 100
    shown_highs = [slug for slug in slugs if slug.startswith("VA-3")]
    assert len(shown_highs) < len(HIGHS)
    lines = captured.out.splitlines()
    # The notice heads and closes the table so neither end of a clipped read
    # hides it, and carries the true per-severity totals.
    for line in (lines[0], lines[-1]):
        assert line.startswith("INCOMPLETE: showing 1-100 of 130 matching findings")
        assert f"{TOTAL - 100} more after this page" in line
        assert "high 16" in line
        assert "`vigil assess finding list --limit 100 --offset 100`" in line


def test_unfiltered_json_page_reports_the_exact_total(ledger, monkeypatch, capsys):
    captured = _run_cli(ledger, monkeypatch, capsys, "--json")

    assert len(json.loads(captured.out)) == 100
    assert f"INCOMPLETE: showing 1-100 of {TOTAL} matching findings" in captured.err
    assert "high 16" in captured.err


def test_explicit_short_limit_on_a_filter_names_the_remaining_rows(
    ledger, monkeypatch, capsys
):
    captured = _run_cli(ledger, monkeypatch, capsys, "--severity", "high", "--limit", "10")

    assert len(_table_slugs(captured.out)) == 10
    assert "INCOMPLETE: showing 1-10 of 16 matching findings, 6 more after this page" in captured.out
    assert (
        "`vigil assess finding list --severity high --limit 10 --offset 10`" in captured.out
    )


def test_root_cause_siblings_above_their_root_stay_listed(ledger, monkeypatch, capsys):
    captured = _run_cli(
        ledger, monkeypatch, capsys, "--root-cause", "VA-401", "--severity", "high"
    )

    assert "VA-303" in captured.out and "VA-312" in captured.out
    assert "showing 1-2 of 2 matching root-cause siblings" in captured.out


def test_count_route_applies_the_listing_filters(ledger):
    unfiltered = ledger.get(f"{_base()}/findings/count")
    highs = ledger.get(f"{_base()}/findings/count", params={"severity": "high"})

    assert unfiltered.status_code == highs.status_code == 200
    assert unfiltered.json()["total"] == TOTAL
    assert unfiltered.json()["by_severity"] == {"high": 16, "medium": MEDIUM_ACTIVE, "low": 4}
    assert highs.json() == {"total": 16, "by_severity": {"high": 16}}


@pytest.mark.parametrize("route", ["findings", "findings/count"])
def test_misspelled_finding_filter_is_refused_not_ignored(ledger, route):
    response = ledger.get(f"{_base()}/{route}", params={"status": "active"})

    assert response.status_code == 400, response.text
    detail = response.json()["detail"]
    assert "status" in detail and "workflow_status" in detail


def test_resume_brief_buckets_rank_by_severity_and_carry_true_totals(ledger):
    brief = ledger.get(f"{_base()}/resume-brief")

    assert brief.status_code == 200, brief.text
    body = brief.json()
    active_highs = {
        slug for slug, status, _ in HIGHS if status in {"active", "exploited", "reported"}
    }
    shown = {row["slug"] for row in body["findings"]["active"]}
    # The bucket shows a bounded window; the highs come first, so lows and
    # mediums recorded later cannot push a high out of it.
    assert active_highs <= shown
    assert body["finding_bucket_counts"]["active"] == MEDIUM_ACTIVE + len(active_highs) + len(LOWS)
    assert body["finding_bucket_counts"]["merged"] == 1


def test_finding_report_header_counts_every_report_finding(ledger, monkeypatch, capsys):
    captured = _run_cli(ledger, monkeypatch, capsys, "--mode", "draft", verb="report")

    reportable = [
        slug
        for slug, status, verification in HIGHS
        if verification in {"confirmed", "downgraded"} and status not in {"draft", "merged"}
    ]
    header = captured.out.splitlines()[0]
    assert header.endswith(f"{len(reportable)} report findings in all")
