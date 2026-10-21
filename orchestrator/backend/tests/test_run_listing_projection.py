"""The run listing is one projection per page, consistent with single-run reads.

The Runs workspace renders every run from the list response, so each row must
carry the dispatch intent, linked findings, evidence mix, and proof-work links
an operator filters on, and the page must cost a bounded number of statements
however many runs it holds.
"""
from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from app import db as db_module
from app.services import state_manager
from tests.test_engagements_api import _author_provenance, write_engagement


ENGAGEMENT_KEY = "2026-10-20-run-listing"
BASE = f"/engagements/{ENGAGEMENT_KEY}/assessment"


def _seed(client, isolate_settings) -> Path:
    engagement_dir = write_engagement(isolate_settings["engagements_dir"], key=ENGAGEMENT_KEY)
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200
    return engagement_dir


def _finding(client, slug: str) -> None:
    response = client.post(
        f"{BASE}/findings",
        json={
            "slug": slug,
            "title": f"Acme export hypothesis {slug}",
            "severity": "medium",
            "canonical_location": "https://example.com/export",
            "summary": "Another tenant's export may be readable",
            "provenance": _author_provenance(client, slug, key=ENGAGEMENT_KEY),
        },
    )
    assert response.status_code == 201, response.text


def _dispatch(client, agent_id: str, *, task: str, finding_slugs: list[str] | None) -> None:
    response = client.post(
        f"{BASE}/dispatches",
        json={
            "agent_id": agent_id,
            "agent_role": "vulnerability-analyst",
            "task": task,
            "finding_slugs": finding_slugs,
        },
    )
    assert response.status_code == 201, response.text


def _run(client, agent_id: str, run_uuid: str) -> dict:
    response = client.post(
        f"{BASE}/assessment-runs",
        json={"run_uuid": run_uuid, "run_kind": "web", "producer_dispatch_agent_id": agent_id},
    )
    assert response.status_code == 201, response.text
    return response.json()


def _artifact(client, engagement_dir: Path, path: str, content: str, agent_id: str) -> dict:
    target = engagement_dir / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    response = client.post(
        f"{BASE}/artifacts",
        json={"path": path, "kind": "proof", "producer_agent_id": agent_id},
    )
    assert response.status_code == 201, response.text
    return response.json()


def _receipt(client, engagement_dir: Path, run: dict, kind: str, agent_id: str, index: int) -> dict:
    artifact = _artifact(
        client,
        engagement_dir,
        f"evidence/{run['run_uuid']}-{kind}-{index}.txt",
        f"Acme {kind} evidence {index} for {run['run_uuid']}\n",
        agent_id,
    )
    response = client.post(
        f"{BASE}/proof-receipts",
        json={
            "run_id": run["id"],
            "evidence_kind": kind,
            "expected_result": "The Acme export denies another tenant",
            "observed_result": f"Observation {index} for {run['run_uuid']}",
            "artifact_id": artifact["id"],
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _seed_runs(client, engagement_dir: Path, count: int, *, start: int = 0) -> list[dict]:
    runs = []
    for index in range(start, start + count):
        agent_id = f"ACME-VA-{index}"
        _finding(client, f"VA-{index:03d}")
        _dispatch(
            client,
            agent_id,
            task=f"Replay the Acme export request across tenants ({index})",
            finding_slugs=[f"VA-{index:03d}"],
        )
        run = _run(client, agent_id, f"acme-export-{index}")
        _receipt(client, engagement_dir, run, "http_exchange", agent_id, 1)
        _receipt(client, engagement_dir, run, "http_exchange", agent_id, 2)
        _receipt(client, engagement_dir, run, "artifact", agent_id, 3)
        runs.append(run)
    return runs


@contextmanager
def _captured_statements() -> Iterator[list[str]]:
    """Trace the statements the service runs on this thread's connection."""
    statements: list[str] = []
    with db_module.get_connection() as connection:
        connection.set_trace_callback(statements.append)
    try:
        yield statements
    finally:
        with db_module.get_connection() as connection:
            connection.set_trace_callback(None)


def _engagement_id(client) -> int:
    return int(client.get(f"/engagements/{ENGAGEMENT_KEY}").json()["id"])


def test_run_rows_carry_dispatch_intent_evidence_mix_and_match_single_reads(
    client, isolate_settings
) -> None:
    engagement_dir = _seed(client, isolate_settings)
    _seed_runs(client, engagement_dir, 2)
    _dispatch(client, "ACME-VA-UNTARGETED", task="", finding_slugs=None)
    untargeted = _run(client, "ACME-VA-UNTARGETED", "acme-untargeted")
    parent = _seed_runs(client, engagement_dir, 1, start=2)[0]
    interrupted = client.patch(
        f"{BASE}/assessment-runs/{parent['id']}", json={"status": "interrupted"}
    )
    assert interrupted.status_code == 200, interrupted.text
    resumed = client.post(
        f"{BASE}/assessment-runs",
        json={
            "run_uuid": "acme-export-2-resumed",
            "run_kind": "web",
            "producer_dispatch_agent_id": "ACME-VA-2",
            "resumed_from_run_id": parent["id"],
        },
    )
    assert resumed.status_code == 201, resumed.text

    listed = client.get(f"{BASE}/assessment-runs", params={"limit": 50})
    assert listed.status_code == 200, listed.text
    rows = {row["run_uuid"]: row for row in listed.json()}

    first = rows["acme-export-0"]
    assert first["producer_dispatch_task"] == "Replay the Acme export request across tenants (0)"
    assert first["dispatch_finding_slugs"] == ["VA-000"]
    assert first["evidence_kind_counts"] == {"artifact": 1, "http_exchange": 2}
    assert first["counts"]["proof_receipts"] == 3
    assert first["proof_health"] == {"healthy": 3, "missing": 0, "stale": 0, "tombstoned": 0}
    assert first["proof_work_ids"] == []

    empty = rows["acme-untargeted"]
    assert empty["producer_dispatch_task"] == ""
    assert empty["dispatch_finding_slugs"] == []
    assert empty["evidence_kind_counts"] == {}
    assert [blocker["code"] for blocker in empty["blockers"]] == ["proof_missing"]

    # A resumed run reports its whole recovery lineage.
    child = rows["acme-export-2-resumed"]
    assert child["counts"]["proof_receipts"] == 3
    assert child["evidence_kind_counts"] == {"artifact": 1, "http_exchange": 2}

    # The list row is the same projection a single read returns.
    for row in listed.json():
        single = client.get(f"{BASE}/assessment-runs/{row['id']}")
        assert single.status_code == 200, single.text
        assert single.json() == row
    assert rows["acme-untargeted"]["id"] == untargeted["id"]


def test_run_listing_statement_count_does_not_grow_with_the_page(
    client, isolate_settings
) -> None:
    engagement_dir = _seed(client, isolate_settings)
    _seed_runs(client, engagement_dir, 2)
    engagement_id = _engagement_id(client)

    with _captured_statements() as small:
        small_page = state_manager.list_assessment_runs(engagement_id, limit=50)
    assert len(small_page) == 2

    _seed_runs(client, engagement_dir, 4, start=2)
    with _captured_statements() as large:
        large_page = state_manager.list_assessment_runs(engagement_id, limit=50)
    assert len(large_page) == 6

    assert len(large) == len(small), (len(small), len(large))
