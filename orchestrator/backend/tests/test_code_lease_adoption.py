"""B9: an orphaned analysis lease is visible, adoptable, and never silently lost.

`reset-stale` is the only recovery a stranded `processing` row had, and it
discards the receipts the dead lease already wrote — so a replacement agent
redid durable work. These tests pin the three halves of the fix: the queue
listing reports per-item lease age and accumulated receipts, adoption is an
audited compare-and-swap that refuses a live lease while preserving row state,
and an open authoring lease is queryable from report and resume state.
"""
from __future__ import annotations

from app import db as db_module
from app.services import assessment_memory

from test_code_analysis_api import (
    _claim_file_for_analysis,
    _create_files,
    _create_repo,
    _network_input_coverage,
    _owned,
    _publish_structural_callables,
    _classify_file,
    _structural_callable,
    write_engagement,
)


def _seed_claimed_parser(client, isolate_settings, engagement_key: str, repo_key: str):
    """One critical file, claimed by `hunter-a`, with a recorded clean receipt."""
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key=repo_key)
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser = next(row for row in files if row["file_path"] == "src/parser.py")
    helper = next(row for row in files if row["file_path"] == "src/helpers.py")
    _publish_structural_callables(
        client,
        engagement_key,
        int(repo["id"]),
        files,
        {
            int(parser["id"]): [_structural_callable("parse", start_line=1, end_line=2)],
            int(helper["id"]): [_structural_callable("helper", start_line=1, end_line=2)],
        },
    )
    _classify_file(client, engagement_key, int(parser["id"]), "critical", 100)
    _classify_file(client, engagement_key, int(helper["id"]), "low", 10)
    claim = _claim_file_for_analysis(
        client, engagement_key, int(parser["id"]), agent_name="hunter-a"
    )
    return repo, parser, claim


def _record_clean_receipt(client, engagement_key: str, claim: dict) -> dict:
    response = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-results",
        json=_owned(
            claim,
            queue_item_id=claim["id"],
            disposition="clean",
            evidence="parse() validates every decoded length before indexing.",
            cwe_coverage=_network_input_coverage(default_effort=80),
        ),
    )
    assert response.status_code == 201, response.text
    return response.json()


def _age_lease(engagement_key: str, item_id: int, *, minutes: int) -> None:
    """Push one lease's proof of life into the past, as a dead agent would."""
    with db_module.get_connection() as connection:
        connection.execute(
            """
            UPDATE code_analysis_queue
            SET consumed_at = datetime('now', ? || ' minutes'),
                last_heartbeat_at = datetime('now', ? || ' minutes')
            WHERE id = ? AND engagement_id = (
                SELECT id FROM engagements WHERE key = ?
            )
            """,
            (f"-{minutes}", f"-{minutes}", item_id, engagement_key),
        )


def test_queue_listing_reports_lease_age_and_accumulated_receipts(
    client, isolate_settings
) -> None:
    """Step 1: counts alone cannot tell a working lease from an abandoned one."""
    engagement_key = "2026-09-16-code-lease-age"
    _, _, claim = _seed_claimed_parser(
        client, isolate_settings, engagement_key, "lease-age-repo"
    )
    _record_clean_receipt(client, engagement_key, claim)
    base = f"/engagements/{engagement_key}/assessment/code"

    fresh = client.get(f"{base}/analysis-queue?status=processing").json()
    row = fresh["items"][0]
    assert row["lease_activity_at"] == claim["last_heartbeat_at"]
    assert row["heartbeat_age_seconds"] is not None
    assert row["heartbeat_age_seconds"] < 120
    assert row["current_result_count"] == 1
    assert row["adopted_leases"] == []

    _age_lease(engagement_key, int(claim["id"]), minutes=90)
    aged = client.get(f"{base}/analysis-queue?status=processing").json()["items"][0]
    assert aged["heartbeat_age_seconds"] >= 89 * 60


def test_queue_listing_stale_minutes_selects_only_abandoned_processing_rows(
    client, isolate_settings
) -> None:
    """Step 1: `list --stale-minutes N` previews the rows an N-minute recovery
    measures as abandoned, so an operator never has to guess which rows a
    window covers."""
    engagement_key = "2026-09-16-code-lease-stale-filter"
    _, _, claim = _seed_claimed_parser(
        client, isolate_settings, engagement_key, "lease-stale-repo"
    )
    base = f"/engagements/{engagement_key}/assessment/code"

    assert client.get(f"{base}/analysis-queue?stale_minutes=30").json()["total"] == 0
    _age_lease(engagement_key, int(claim["id"]), minutes=45)
    stale = client.get(f"{base}/analysis-queue?stale_minutes=30").json()
    assert stale["item_ids"] == [claim["id"]]
    # The pending helper row holds no lease and can never be stale work.
    assert all(item["status"] == "processing" for item in stale["items"])
    assert client.get(f"{base}/analysis-queue?stale_minutes=0").status_code == 422


def test_lease_adoption_refuses_a_lease_that_is_still_live(
    client, isolate_settings
) -> None:
    """Step 2: two agents writing one file's receipts is the failure mode this
    verb must never cause. A lease inside the declared window is live."""
    engagement_key = "2026-09-16-code-lease-live"
    _, _, claim = _seed_claimed_parser(
        client, isolate_settings, engagement_key, "lease-live-repo"
    )
    base = f"/engagements/{engagement_key}/assessment/code"

    refused = client.post(
        f"{base}/analysis-queue/adopt-lease",
        json={
            "item_id": claim["id"],
            "expected_agent": "hunter-a",
            "expected_lease_token": claim["lease_token"],
            "agent_name": "hunter-b",
            "stale_minutes": 10,
            "reason": "hunter-a stopped responding",
        },
    )
    assert refused.status_code == 409, refused.text
    assert "live" in refused.json()["detail"]

    still_owned = client.get(f"{base}/analysis-queue?status=processing").json()["items"][0]
    assert still_owned["agent_name"] == "hunter-a"
    assert still_owned["lease_token"] == claim["lease_token"]


def test_lease_adoption_preserves_receipts_and_closes_under_the_new_lease(
    client, isolate_settings
) -> None:
    """Step 2: the point of adoption is that the replacement does NOT redo the
    dead lease's durable work — the receipts stay current and still satisfy the
    critical/high source-receipt rule at closeout."""
    engagement_key = "2026-09-16-code-lease-adopt"
    _, parser, claim = _seed_claimed_parser(
        client, isolate_settings, engagement_key, "lease-adopt-repo"
    )
    receipt = _record_clean_receipt(client, engagement_key, claim)
    _age_lease(engagement_key, int(claim["id"]), minutes=60)
    base = f"/engagements/{engagement_key}/assessment/code"

    adopted = client.post(
        f"{base}/analysis-queue/adopt-lease",
        json={
            "item_id": claim["id"],
            "expected_agent": "hunter-a",
            "expected_lease_token": claim["lease_token"],
            "agent_name": "hunter-b",
            "stale_minutes": 10,
            "reason": "hunter-a died mid-file; adopting its recorded receipts",
        },
    )
    assert adopted.status_code == 200, adopted.text
    payload = adopted.json()
    assert payload["previous_agent_name"] == "hunter-a"
    assert payload["previous_lease_token"] == claim["lease_token"]
    assert payload["preserved_result_count"] == 1
    assert payload["item"]["agent_name"] == "hunter-b"
    assert payload["item"]["lease_token"] != claim["lease_token"]
    assert payload["item"]["status"] == "processing"
    assert payload["item"]["file"]["file_path"] == "src/parser.py"
    assert payload["adopted_leases"] == [
        {"agent_name": "hunter-a", "lease_token": claim["lease_token"]}
    ]

    # The dead lease's receipt is untouched, not superseded.
    results = client.get(
        f"{base}/analysis-results?queue_item_id={claim['id']}"
    ).json()
    assert [row["id"] for row in results] == [receipt["id"]]
    assert results[0]["lease_token"] == claim["lease_token"]

    # The adopter closes out without re-recording the receipt it inherited.
    completed = client.post(
        f"{base}/analysis-queue/done",
        json={
            "item_ids": [claim["id"]],
            "agent_name": "hunter-b",
            "lease_token": payload["item"]["lease_token"],
            "disposition": "clean",
            "notes": "Adopted hunter-a's reviewed call chain and confirmed closeout.",
            "cwe_coverage": _network_input_coverage(default_effort=80),
        },
    )
    assert completed.status_code == 200, completed.text
    assert completed.json()["coverage_integrity"]["current_receipt_rows"] == 1

    coverage = client.get(f"{base}/coverage").json()
    assert coverage["by_classification"]["critical"]["analyzed"] == 1

    activity = client.get(f"/engagements/{engagement_key}/activity-entries").json()
    audited = next(
        row for row in activity["items"] if row["title"] == "code-dispatch adopt-lease"
    )
    assert audited["actor_name"] == "hunter-b"
    assert claim["lease_token"] in str(audited["metadata"]["previous_lease_token"])


def test_lease_adoption_compare_and_swap_rejects_a_rotated_lease(
    client, isolate_settings
) -> None:
    """Step 2: the caller pins the exact lease it observed. If the row moved on
    between the read and the write, adoption fails instead of stealing it."""
    engagement_key = "2026-09-16-code-lease-cas"
    _, _, claim = _seed_claimed_parser(
        client, isolate_settings, engagement_key, "lease-cas-repo"
    )
    _age_lease(engagement_key, int(claim["id"]), minutes=60)
    base = f"/engagements/{engagement_key}/assessment/code"

    stale_token = client.post(
        f"{base}/analysis-queue/adopt-lease",
        json={
            "item_id": claim["id"],
            "expected_agent": "hunter-a",
            "expected_lease_token": "a-token-that-was-never-issued",
            "agent_name": "hunter-b",
            "stale_minutes": 10,
            "reason": "stale observation",
        },
    )
    assert stale_token.status_code == 409, stale_token.text

    wrong_agent = client.post(
        f"{base}/analysis-queue/adopt-lease",
        json={
            "item_id": claim["id"],
            "expected_agent": "hunter-z",
            "expected_lease_token": claim["lease_token"],
            "agent_name": "hunter-b",
            "stale_minutes": 10,
            "reason": "stale observation",
        },
    )
    assert wrong_agent.status_code == 409, wrong_agent.text

    unchanged = client.get(f"{base}/analysis-queue?status=processing").json()["items"][0]
    assert unchanged["agent_name"] == "hunter-a"
    assert unchanged["lease_token"] == claim["lease_token"]


def test_reset_stale_after_adoption_discards_the_whole_owner_chain(
    client, isolate_settings
) -> None:
    """Do-not-break: `reset-stale` still means "throw the attempt away". After
    an adoption it must discard the adopted ancestors' receipts too, or a later
    claim of the same row would inherit receipts nobody wrote for it."""
    engagement_key = "2026-09-16-code-lease-reset"
    _, _, claim = _seed_claimed_parser(
        client, isolate_settings, engagement_key, "lease-reset-repo"
    )
    _record_clean_receipt(client, engagement_key, claim)
    _age_lease(engagement_key, int(claim["id"]), minutes=60)
    base = f"/engagements/{engagement_key}/assessment/code"

    adopted = client.post(
        f"{base}/analysis-queue/adopt-lease",
        json={
            "item_id": claim["id"],
            "expected_agent": "hunter-a",
            "expected_lease_token": claim["lease_token"],
            "agent_name": "hunter-b",
            "stale_minutes": 10,
            "reason": "adopting a dead lease",
        },
    )
    assert adopted.status_code == 200, adopted.text
    _age_lease(engagement_key, int(claim["id"]), minutes=60)

    reset = client.post(f"{base}/analysis-queue/reset-stale", json={"minutes": 10})
    assert reset.status_code == 200, reset.text
    assert reset.json()["reset"] == 1

    pending = client.get(f"{base}/analysis-queue?status=pending").json()
    row = next(item for item in pending["items"] if item["id"] == claim["id"])
    assert row["agent_name"] == ""
    assert row["adopted_leases"] == []
    assert row["current_result_count"] == 0
    assert client.get(
        f"{base}/analysis-results?queue_item_id={claim['id']}"
    ).json() == []


def test_queue_item_progress_reports_recorded_and_missing_coverage(
    client, isolate_settings
) -> None:
    """Step 3: incremental recording is only safe if the hunter can read back
    what the claimed item already carries and what closeout still owes."""
    engagement_key = "2026-09-16-code-lease-progress"
    _, _, claim = _seed_claimed_parser(
        client, isolate_settings, engagement_key, "lease-progress-repo"
    )
    base = f"/engagements/{engagement_key}/assessment/code"

    empty = client.get(f"{base}/analysis-queue/{claim['id']}/progress")
    assert empty.status_code == 200, empty.text
    before = empty.json()
    assert before["receipt_count"] == 0
    assert before["recorded_cwe_families"] == []
    assert before["missing_cwe_families"] == before["applicable_vuln_classes"]
    assert before["applicable_vuln_classes"]

    _record_clean_receipt(client, engagement_key, claim)
    after = client.get(f"{base}/analysis-queue/{claim['id']}/progress").json()
    assert after["receipt_count"] == 1
    assert after["missing_cwe_families"] == []
    assert sorted(after["recorded_cwe_families"]) == sorted(
        after["applicable_vuln_classes"]
    )
    assert after["receipts"][0]["disposition"] == "clean"
    assert after["receipts"][0]["evidence_present"] is True
    assert after["coverage_integrity"]["current_receipt_rows"] == 1


def test_open_authoring_lease_is_visible_in_coverage_and_resume_state(
    client, isolate_settings
) -> None:
    """Step 4: a dispatch that died before closeout is durable debt. It has to
    be readable from the report surface and from the resume brief, not only by
    an operator who thinks to page the queue."""
    engagement_key = "2026-09-16-code-lease-report"
    _, parser, claim = _seed_claimed_parser(
        client, isolate_settings, engagement_key, "lease-report-repo"
    )
    _record_clean_receipt(client, engagement_key, claim)
    _age_lease(engagement_key, int(claim["id"]), minutes=120)
    base = f"/engagements/{engagement_key}/assessment/code"

    coverage = client.get(f"{base}/coverage").json()
    open_leases = coverage["open_leases"]
    assert coverage["open_leases_count"] == 1
    assert open_leases[0]["queue_item_id"] == claim["id"]
    assert open_leases[0]["file_path"] == "src/parser.py"
    assert open_leases[0]["agent_name"] == "hunter-a"
    assert open_leases[0]["lease_token"] == claim["lease_token"]
    assert open_leases[0]["current_result_count"] == 1
    assert open_leases[0]["heartbeat_age_seconds"] >= 119 * 60

    with db_module.get_connection() as connection:
        engagement_id = int(
            connection.execute(
                "SELECT id FROM engagements WHERE key = ?", (engagement_key,)
            ).fetchone()[0]
        )
    brief = assessment_memory.build_resume_brief(engagement_id)
    section = brief["code_analysis"]
    assert section["open_leases_count"] == 1
    assert section["open_leases"][0]["queue_item_id"] == claim["id"]
    assert section["open_leases"][0]["current_result_count"] == 1


def _adopt(client, engagement_key: str, claim: dict, *, agent_name: str) -> dict:
    response = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/adopt-lease",
        json={
            "item_id": claim["id"],
            "expected_agent": claim["agent_name"],
            "expected_lease_token": claim["lease_token"],
            "agent_name": agent_name,
            "stale_minutes": 10,
            "reason": "prior lease stopped heartbeating",
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_error_retry_after_adoption_discards_the_whole_owner_chain(
    client, isolate_settings
) -> None:
    """Do-not-break: `retry-error` also means "throw this attempt away". It
    resets the same row, so leaving the adoption chain behind would hand the
    inherited receipts to whoever claims the row next."""
    engagement_key = "2026-09-16-code-lease-retry-error"
    _, _, claim = _seed_claimed_parser(
        client, isolate_settings, engagement_key, "lease-retry-error-repo"
    )
    _record_clean_receipt(client, engagement_key, claim)
    _age_lease(engagement_key, int(claim["id"]), minutes=60)
    base = f"/engagements/{engagement_key}/assessment/code"
    adopted = _adopt(client, engagement_key, claim, agent_name="hunter-b")

    errored = client.post(
        f"{base}/analysis-queue/error",
        json={
            "item_ids": [claim["id"]],
            "agent_name": "hunter-b",
            "lease_token": adopted["item"]["lease_token"],
            "notes": "parser crashed the reviewer",
        },
    )
    assert errored.status_code == 200, errored.text
    retried = client.post(
        f"{base}/analysis-queue/retry-error",
        json={"item_ids": [claim["id"]], "reason": "transient"},
    )
    assert retried.status_code == 200, retried.text

    row = next(
        item
        for item in client.get(f"{base}/analysis-queue?status=pending").json()["items"]
        if item["id"] == claim["id"]
    )
    assert row["adopted_leases"] == []
    assert row["current_result_count"] == 0


def test_needs_context_retry_after_adoption_discards_the_whole_owner_chain(
    client, isolate_settings
) -> None:
    """Same invariant on the needs-context recovery path."""
    engagement_key = "2026-09-16-code-lease-retry-context"
    _, _, claim = _seed_claimed_parser(
        client, isolate_settings, engagement_key, "lease-retry-context-repo"
    )
    _record_clean_receipt(client, engagement_key, claim)
    _age_lease(engagement_key, int(claim["id"]), minutes=60)
    base = f"/engagements/{engagement_key}/assessment/code"
    adopted = _adopt(client, engagement_key, claim, agent_name="hunter-b")

    blocked = client.post(
        f"{base}/analysis-queue/needs-context",
        json={
            "item_ids": [claim["id"]],
            "agent_name": "hunter-b",
            "lease_token": adopted["item"]["lease_token"],
            "expansion_request": {"missing": "storage layer"},
        },
    )
    assert blocked.status_code == 200, blocked.text
    retried = client.post(
        f"{base}/analysis-queue/retry-needs-context",
        json={"item_ids": [claim["id"]], "reason": "storage source supplied"},
    )
    assert retried.status_code == 200, retried.text

    row = next(
        item
        for item in client.get(f"{base}/analysis-queue?status=pending").json()["items"]
        if item["id"] == claim["id"]
    )
    assert row["adopted_leases"] == []
    assert row["current_result_count"] == 0


def test_the_cli_and_api_agree_on_one_abandonment_window() -> None:
    """One definition of "abandoned", two declarations.

    `code-dispatch adopt-lease` validates the window before the round trip for
    clearer operator feedback, so its default and bounds are a mirror. A mirror
    without this guard is how `reset-stale N` and `adopt-lease --stale-minutes
    N` would quietly stop describing the same set of rows.
    """
    from app.api.code_analysis import QueueAdoptLeaseRequest, QueueResetStaleRequest
    from assess.commands import code_dispatch

    def bound(field, attribute: str) -> int:
        return next(
            getattr(metadata, attribute)
            for metadata in field.metadata
            if getattr(metadata, attribute, None) is not None
        )

    adopt_field = QueueAdoptLeaseRequest.model_fields["stale_minutes"]
    reset_field = QueueResetStaleRequest.model_fields["minutes"]

    assert adopt_field.default == reset_field.default
    assert code_dispatch._DEFAULT_ADOPTION_STALE_MINUTES == adopt_field.default
    for attribute, mirror in (
        ("ge", code_dispatch._MIN_ADOPTION_STALE_MINUTES),
        ("le", code_dispatch._MAX_ADOPTION_STALE_MINUTES),
    ):
        assert bound(adopt_field, attribute) == bound(reset_field, attribute) == mirror


def test_adopter_may_correct_a_receipt_it_inherited(client, isolate_settings) -> None:
    """Step 2: adoption exists so the replacement can finish the attempt — which
    includes correcting what the dead lease got wrong. A supersede identity
    pinned to the CURRENT lease refused exactly that write, leaving the adopter
    with a contradictory second receipt (closeout then deadlocks on conflicting
    candidate-bearing dispositions) or `reset-stale`, which discards the very
    receipts adoption preserved."""
    engagement_key = "2026-09-16-code-lease-adopt-supersede"
    _, _, claim = _seed_claimed_parser(
        client, isolate_settings, engagement_key, "lease-adopt-supersede-repo"
    )
    base = f"/engagements/{engagement_key}/assessment/code"
    endpoint = f"{base}/analysis-results"

    inherited = client.post(
        endpoint,
        json=_owned(
            claim,
            queue_item_id=claim["id"],
            disposition="suspicious",
            hypothesis="decoded length may index past the buffer",
            evidence="src/parser.py:1",
            cwe_coverage=_network_input_coverage(default_effort=80),
        ),
    )
    assert inherited.status_code == 201, inherited.text

    _age_lease(engagement_key, int(claim["id"]), minutes=60)
    adopted = _adopt(client, engagement_key, claim, agent_name="hunter-b")
    item = adopted["item"]
    assert adopted["preserved_result_count"] == 1

    # The inherited candidate pins closeout to `suspicious`: until the adopter
    # can correct the receipt, `clean` is unreachable.
    deadlocked = client.post(
        f"{base}/analysis-queue/done",
        json=_owned(
            item,
            item_ids=[claim["id"]],
            disposition="clean",
            notes="Reviewed hunter-a's chain; the guard rejects the input.",
            cwe_coverage=_network_input_coverage(default_effort=80),
        ),
    )
    assert deadlocked.status_code == 409, deadlocked.text
    assert "candidate-bearing" in deadlocked.json()["detail"]

    corrected = client.post(
        endpoint,
        json=_owned(
            item,
            queue_item_id=claim["id"],
            supersedes=int(inherited.json()["id"]),
            disposition="clean",
            hypothesis="the decoded length is bounds-checked before indexing",
            evidence="src/parser.py:1",
            cwe_coverage=_network_input_coverage(default_effort=80),
        ),
    )
    assert corrected.status_code == 201, corrected.text
    assert corrected.json()["supersedes"] == inherited.json()["id"]
    assert corrected.json()["lease_token"] == item["lease_token"]

    current = client.get(f"{endpoint}?queue_item_id={claim['id']}").json()
    assert [row["id"] for row in current] == [corrected.json()["id"]]

    completed = client.post(
        f"{base}/analysis-queue/done",
        json=_owned(
            item,
            item_ids=[claim["id"]],
            disposition="clean",
            notes="Reviewed hunter-a's chain; the guard rejects the input.",
            cwe_coverage=_network_input_coverage(default_effort=80),
        ),
    )
    assert completed.status_code == 200, completed.text
    assert completed.json()["coverage_integrity"]["current_receipt_rows"] == 1
