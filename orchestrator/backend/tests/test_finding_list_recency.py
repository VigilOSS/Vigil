"""Finding list rows carry their latest transition-ledger entry.

``updated_at`` / ``last_seen_at`` move whenever a finding is re-recorded, so
on a busy engagement whole batches share one timestamp and "recently changed"
loses meaning. The transition ledger records each real change, so the list
projection exposes the newest ledger row's time, action, and actor; the
Findings page sorts and filters on it.
"""

from __future__ import annotations

import json

from app import db as db_module

ENGAGEMENT_KEY = "2026-10-20-120000-finding-recency"
OTHER_ENGAGEMENT_KEY = "2026-10-20-120001-finding-recency-other"
AUTHOR_AGENT_ID = "RECENCY-FIXTURE-AUTHOR"


def _base(key: str = ENGAGEMENT_KEY) -> str:
    return f"/engagements/{key}/assessment"


def _seed(client, isolate_settings, key: str = ENGAGEMENT_KEY) -> None:
    engagement_dir = isolate_settings["engagements_dir"] / key
    (engagement_dir / "sessions").mkdir(parents=True, exist_ok=True)
    (engagement_dir / "scope.json").write_text(
        json.dumps({"engagement_name": "Acme recency", "targets": ["https://app.example"]}),
        encoding="utf-8",
    )
    (engagement_dir / "findings.md").write_text("# Findings\n", encoding="utf-8")
    assert client.get(f"/engagements/{key}").status_code == 200
    dispatch = client.post(
        f"{_base(key)}/dispatches",
        json={
            "agent_id": AUTHOR_AGENT_ID,
            "agent_role": "vulnerability-analyst",
            "task": "Record recency fixture findings",
        },
    )
    assert dispatch.status_code == 201, dispatch.text


def _record(client, slug: str, *, key: str = ENGAGEMENT_KEY, severity: str = "high") -> None:
    response = client.post(
        f"{_base(key)}/findings",
        json={
            "slug": slug,
            "title": f"Acme portal object authorization gap {slug}",
            "severity": severity,
            "workflow_status": "active",
            "defect_family": "access-control",
            "root_cause_key": f"missing-object-authz-{slug.lower()}",
            "canonical_location": f"https://app.example/api/{slug.lower()}",
            "summary": "Object-level authorization is missing.",
            "evidence_ref": "findings.md",
            "source_name": "vulnerability-analyst",
            "details": {"impact": "Cross-tenant read."},
            "provenance": {"agent_id": AUTHOR_AGENT_ID},
        },
    )
    assert response.status_code in (200, 201), response.text


def _set_transition_times(slug: str, created_at: str, *, key: str = ENGAGEMENT_KEY) -> None:
    with db_module.get_connection() as connection:
        connection.execute(
            """
            UPDATE assessment_finding_transitions SET created_at = ?
            WHERE finding_id = (
                SELECT findings.id FROM assessment_findings AS findings
                JOIN engagements ON engagements.id = findings.engagement_id
                WHERE engagements.key = ? AND findings.slug = ?
            )
            """,
            (created_at, key, slug),
        )


def _rows(client, **params) -> dict[str, dict]:
    response = client.get(f"{_base()}/findings", params=params)
    assert response.status_code == 200, response.text
    return {row["slug"]: row for row in response.json()}


def test_list_rows_report_the_newest_ledger_entry(client, isolate_settings):
    _seed(client, isolate_settings)
    _record(client, "VA-001")
    _record(client, "VA-002", severity="low")
    _set_transition_times("VA-001", "2026-10-01 09:00:00")
    _set_transition_times("VA-002", "2026-10-02 09:00:00")
    patched = client.patch(
        f"{_base()}/findings/VA-001", json={"details": {"impact": "Cross-tenant write."}}
    )
    assert patched.status_code == 200, patched.text

    rows = _rows(client)
    for slug in ("VA-001", "VA-002"):
        ledger = client.get(f"{_base()}/findings/{slug}/transitions").json()
        newest = ledger[0]
        assert rows[slug]["last_transition_at"] == newest["created_at"]
        assert rows[slug]["last_transition_action"] == newest["action"]
        assert rows[slug]["last_transition_actor"] == newest["actor"]
    assert rows["VA-001"]["last_transition_action"] == "details_patched"
    assert rows["VA-002"]["last_transition_action"] == "created"
    assert rows["VA-002"]["last_transition_at"] == "2026-10-02 09:00:00"


def test_point_read_reports_the_same_newest_entry_as_the_list(client, isolate_settings):
    # The Findings page swaps a list row for its point read when the drawer
    # opens; the recency fields must not disappear in that swap.
    _seed(client, isolate_settings)
    _record(client, "VA-001")
    assert client.patch(
        f"{_base()}/findings/VA-001", json={"details": {"impact": "Cross-tenant write."}}
    ).status_code == 200

    listed = _rows(client)["VA-001"]
    detail = client.get(f"{_base()}/findings/VA-001")
    assert detail.status_code == 200, detail.text
    for field in ("last_transition_at", "last_transition_action", "last_transition_actor"):
        assert detail.json()[field] == listed[field]
    assert detail.json()["last_transition_action"] == "details_patched"


def test_newest_entry_is_the_last_written_row_even_when_times_tie(client, isolate_settings):
    # CURRENT_TIMESTAMP has one-second resolution, so a create and a patch in
    # the same second tie on created_at; the ledger id decides which is newest.
    _seed(client, isolate_settings)
    _record(client, "VA-001")
    assert client.patch(
        f"{_base()}/findings/VA-001", json={"details": {"impact": "Cross-tenant write."}}
    ).status_code == 200
    _set_transition_times("VA-001", "2026-10-03 10:00:00")

    row = _rows(client)["VA-001"]
    assert row["last_transition_at"] == "2026-10-03 10:00:00"
    assert row["last_transition_action"] == "details_patched"


def test_a_finding_without_ledger_rows_reports_null(client, isolate_settings):
    _seed(client, isolate_settings)
    _record(client, "VA-001")
    with db_module.get_connection() as connection:
        connection.execute("DELETE FROM assessment_finding_transitions")

    row = _rows(client)["VA-001"]
    assert row["last_transition_at"] is None
    assert row["last_transition_action"] is None
    assert row["last_transition_actor"] is None


def test_recency_columns_survive_filters_and_paging(client, isolate_settings):
    # The ledger subquery adds a bound parameter ahead of the WHERE clause;
    # filters and LIMIT/OFFSET must still bind to their own placeholders.
    _seed(client, isolate_settings)
    _record(client, "VA-001")
    _record(client, "VA-002", severity="low")
    _set_transition_times("VA-002", "2026-10-02 09:00:00")

    filtered = _rows(client, severity="low", limit=1, offset=0)
    assert list(filtered) == ["VA-002"]
    assert filtered["VA-002"]["last_transition_at"] == "2026-10-02 09:00:00"
    searched = _rows(client, search="va-002")
    assert searched["VA-002"]["last_transition_action"] == "created"


def test_ledger_rows_never_cross_engagements(client, isolate_settings):
    _seed(client, isolate_settings)
    _seed(client, isolate_settings, key=OTHER_ENGAGEMENT_KEY)
    _record(client, "VA-001")
    _record(client, "VA-001", key=OTHER_ENGAGEMENT_KEY)
    _set_transition_times("VA-001", "2026-10-01 09:00:00")
    _set_transition_times("VA-001", "2026-10-09 09:00:00", key=OTHER_ENGAGEMENT_KEY)

    assert _rows(client)["VA-001"]["last_transition_at"] == "2026-10-01 09:00:00"
