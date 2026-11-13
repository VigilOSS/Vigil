"""A file's closeout and its held leads, and every door that says which close is owed.

The queue item's disposition is the file's verdict: `finding` holds the file to
its root finding, `suspicious` sends it back for a targeted re-review. One
attempt can hold both — a recorded finding and a separate hypothesis the code
could not decide — and the finding takes precedence: the file closes as
`finding`, while each unreplaced `suspicious` receipt beside it stays awaiting a
verdict and blocks `verify-variant` until a targeted re-review settles it (a
reanalysis that answers it, or a correction that replaces it). A held finding
receipt stands, because its finding is decided by `finding verify`, and a close
that would bury a held candidate is refused naming the close it owes. `done`
with ``dry_run`` runs every check the close runs and writes nothing.
"""
from __future__ import annotations

import sqlite3

from app import db as db_module
from app.services import code_analysis
from tests.test_code_analysis_api import (
    _blocker_codes,
    _blocker_kinds,
    _claim_file_for_analysis,
    _claim_file_for_reanalysis,
    _classify_file,
    _create_code_parent_finding,
    _create_files,
    _network_input_coverage,
    _owned,
    _seed_repo,
)


def _claimed_parser(client, isolate_settings, engagement_key: str):
    repo = _seed_repo(client, isolate_settings, engagement_key, repo_key=f"{engagement_key}-repo")
    parser_file = next(
        row for row in _create_files(client, engagement_key, int(repo["id"]))
        if row["file_path"] == "src/parser.py"
    )
    _classify_file(client, engagement_key, int(parser_file["id"]), "high", 79)
    _create_code_parent_finding(client, engagement_key, int(repo["id"]), slug="CH-901")
    return _claim_file_for_analysis(
        client, engagement_key, int(parser_file["id"]), agent_name="candidate-agent"
    )


def _receipt(client, engagement_key: str, claim, disposition: str, **extra):
    return client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-results",
        json=_owned(
            claim,
            queue_item_id=claim["id"],
            disposition=disposition,
            evidence=f"Acme parser {disposition} evidence.",
            **({"finding_slug": "CH-901"} if disposition == "finding" else {}),
            **extra,
        ),
    )


def _done(client, engagement_key: str, claim, **payload):
    return client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/done",
        json=_owned(claim, item_ids=[claim["id"]], **payload),
    )


def _close_as(client, engagement_key: str, claim, disposition: str, **extra):
    return _done(
        client, engagement_key, claim, disposition=disposition,
        notes=f"Acme parser closed {disposition}.",
        cwe_coverage=_network_input_coverage(default_effort=80), **extra,
    )


def _queue_row(isolate_settings, item_id: int) -> tuple[str, str]:
    db_path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    with sqlite3.connect(str(db_path)) as connection:
        return connection.execute(
            "SELECT status, disposition FROM code_analysis_queue WHERE id = ?", (item_id,)
        ).fetchone()


def _queue_status(isolate_settings, item_id: int) -> str:
    return _queue_row(isolate_settings, item_id)[0]


def _verify_variant_readiness(client, engagement_key: str):
    return client.get(
        f"/engagements/{engagement_key}/assessment/code/readiness?target_phase=verify-variant"
    ).json()


def _awaiting_verdict(client, engagement_key: str, result_id: int) -> bool:
    record = client.get(
        f"/engagements/{engagement_key}/assessment/code/analysis-results/{result_id}"
    )
    assert record.status_code == 200, record.text
    return record.json()["awaiting_verdict"]


def _finding_closed_with_lead(client, isolate_settings, engagement_key: str):
    """An attempt holding a finding receipt and a separate suspicious lead, closed."""
    claim = _claimed_parser(client, isolate_settings, engagement_key)
    finding = _receipt(client, engagement_key, claim, "finding")
    assert finding.status_code == 201, finding.text
    lead = _receipt(
        client, engagement_key, claim, "suspicious",
        hypothesis="a second length field may index past the buffer",
    )
    assert lead.status_code == 201, lead.text
    closed = _close_as(client, engagement_key, claim, "finding")
    assert closed.status_code == 200, closed.text
    return claim, finding.json(), lead.json(), closed.json()


def test_a_suspicious_lead_beside_a_finding_closes_as_finding_and_awaits_a_verdict(
    client, isolate_settings
):
    engagement_key = "2026-11-14-code-candidate-lead-beside-finding"
    claim = _claimed_parser(client, isolate_settings, engagement_key)
    finding = _receipt(client, engagement_key, claim, "finding")
    assert finding.status_code == 201, finding.text

    lead = _receipt(
        client, engagement_key, claim, "suspicious",
        hypothesis="a second length field may index past the buffer",
    )
    assert lead.status_code == 201, lead.text

    # The finding takes precedence: neither a suspicious nor a clean close
    # buries it, and each refusal names the close the attempt owes.
    for buried in ("suspicious", "clean"):
        refused = _close_as(client, engagement_key, claim, buried)
        assert refused.status_code == 409, refused.text
        detail = refused.json()["detail"]
        assert "requires queue disposition='finding'" in detail
        assert f"finding receipt {finding.json()['id']}" in detail
        assert f"suspicious receipt {lead.json()['id']}" in detail
        assert _queue_status(isolate_settings, int(claim["id"])) == "processing"

    closed = _close_as(client, engagement_key, claim, "finding")

    assert closed.status_code == 200, closed.text
    assert closed.json()["open_lead_receipts"] == [lead.json()["id"]]
    assert _queue_row(isolate_settings, int(claim["id"])) == ("done", "finding")
    parser = client.get(
        f"/engagements/{engagement_key}/assessment/code/files/{claim['file_id']}"
    ).json()
    assert parser["analysis_status"] == "analyzed"
    assert _awaiting_verdict(client, engagement_key, int(lead.json()["id"])) is True
    assert _awaiting_verdict(client, engagement_key, int(finding.json()["id"])) is False
    page = client.get(
        f"/engagements/{engagement_key}/assessment/code/analysis-results/page"
        "?scope=awaiting_verdict"
    ).json()
    assert [row["id"] for row in page["items"]] == [lead.json()["id"]]
    assert page["awaiting_verdict"] == {"files": 1, "results": 1}
    # The current listing leaves the open lead out and says where it is listed.
    current = client.get(
        f"/engagements/{engagement_key}/assessment/code/analysis-results/page"
    ).json()
    assert lead.json()["id"] not in {row["id"] for row in current["items"]}
    [outside] = [entry for entry in current["not_listed"] if entry["code"] == "awaiting_verdict_not_current"]
    assert outside["count"] == 1
    assert "Needs attention" in outside["message"]

    hunt = client.get(
        f"/engagements/{engagement_key}/assessment/code/readiness?target_phase=hunt"
    ).json()
    assert "unresolved_suspicious_analysis" not in _blocker_codes(hunt)
    blocked = _verify_variant_readiness(client, engagement_key)
    [blocker] = [
        row for row in blocked["blockers"] if row["code"] == "unresolved_suspicious_analysis"
    ]
    assert blocker["overrideable"] is False
    assert blocker["message"].startswith("Repository has 1 file(s)")
    report = client.get(f"/engagements/{engagement_key}/assessment/report-readiness").json()
    assert "unresolved_suspicious_analysis" in _blocker_kinds(report)


def test_a_finding_recorded_after_a_held_lead_is_accepted_beside_it(client, isolate_settings):
    engagement_key = "2026-11-14-code-candidate-finding-after-lead"
    claim = _claimed_parser(client, isolate_settings, engagement_key)
    lead = _receipt(client, engagement_key, claim, "suspicious")
    assert lead.status_code == 201, lead.text

    finding = _receipt(client, engagement_key, claim, "finding")

    assert finding.status_code == 201, finding.text
    closed = _close_as(client, engagement_key, claim, "finding")
    assert closed.status_code == 200, closed.text
    assert closed.json()["open_lead_receipts"] == [lead.json()["id"]]


def test_a_targeted_reanalysis_that_rediscovers_the_finding_and_clears_the_lead_resolves_it(
    client, isolate_settings
):
    engagement_key = "2026-11-14-code-candidate-lead-reanalysis"
    claim, _finding, lead, _closed = _finding_closed_with_lead(
        client, isolate_settings, engagement_key
    )

    reanalysis = _claim_file_for_reanalysis(
        client, engagement_key, int(claim["file_id"]),
        reason="Phase 2B: settle the held length-field lead.",
        agent_name="resolution-agent",
    )

    # The re-review is handed the lead it exists to settle.
    [open_lead] = reanalysis["open_lead_receipts"]
    assert open_lead["id"] == lead["id"]
    assert open_lead["queue_item_id"] == claim["id"]
    assert open_lead["hypothesis"] == "a second length field may index past the buffer"
    # A queued or running re-review does not settle the lead.
    assert "unresolved_suspicious_analysis" in _blocker_codes(
        _verify_variant_readiness(client, engagement_key)
    )

    rediscovered = _receipt(client, engagement_key, reanalysis, "finding")
    assert rediscovered.status_code == 201, rediscovered.text
    cleared = _receipt(
        client, engagement_key, reanalysis, "clean",
        hypothesis="the second length field is bounds-checked by the frame guard",
    )
    assert cleared.status_code == 201, cleared.text
    closed = _close_as(client, engagement_key, reanalysis, "finding")
    assert closed.status_code == 200, closed.text
    assert "open_lead_receipts" not in closed.json()

    assert "unresolved_suspicious_analysis" not in _blocker_codes(
        _verify_variant_readiness(client, engagement_key)
    )
    assert _awaiting_verdict(client, engagement_key, int(lead["id"])) is False


def test_a_correction_that_supersedes_the_lead_keeps_the_row_finding(client, isolate_settings):
    engagement_key = "2026-11-14-code-candidate-lead-correction"
    claim, _finding, lead, _closed = _finding_closed_with_lead(
        client, isolate_settings, engagement_key
    )

    corrected = _receipt(
        client, engagement_key, claim, "clean",
        supersedes=lead["id"],
        hypothesis="the second length field is bounds-checked by the frame guard",
    )

    assert corrected.status_code == 201, corrected.text
    assert corrected.json()["queue_disposition"] == "finding"
    assert _queue_row(isolate_settings, int(claim["id"])) == ("done", "finding")
    assert "unresolved_suspicious_analysis" not in _blocker_codes(
        _verify_variant_readiness(client, engagement_key)
    )
    parser = client.get(
        f"/engagements/{engagement_key}/assessment/code/files/{claim['file_id']}"
    ).json()
    assert parser["analysis_status"] == "analyzed"


def test_a_finding_receipt_cannot_be_superseded_away(client, isolate_settings):
    engagement_key = "2026-11-14-code-candidate-finding-stands"
    claim = _claimed_parser(client, isolate_settings, engagement_key)
    finding = _receipt(client, engagement_key, claim, "finding")
    assert finding.status_code == 201, finding.text

    for replacement in ("suspicious", "clean"):
        refused = _receipt(
            client, engagement_key, claim, replacement, supersedes=finding.json()["id"],
        )
        assert refused.status_code == 409, refused.text
        assert "finding verify" in refused.json()["detail"]

    closed = _close_as(client, engagement_key, claim, "finding")
    assert closed.status_code == 200, closed.text
    # A correction on the completed item is held to the same rule.
    refused_correction = _receipt(
        client, engagement_key, claim, "clean", supersedes=finding.json()["id"],
    )
    assert refused_correction.status_code == 409, refused_correction.text
    assert _queue_row(isolate_settings, int(claim["id"])) == ("done", "finding")
    # A finding receipt answering the same anchors still replaces it.
    restated = _receipt(
        client, engagement_key, claim, "finding", supersedes=finding.json()["id"],
        hypothesis="the same overflow, restated with the full trigger path",
    )
    assert restated.status_code == 201, restated.text
    assert restated.json()["queue_disposition"] == "finding"


def test_a_held_lead_refuses_a_clean_close(client, isolate_settings):
    engagement_key = "2026-11-14-code-candidate-lead-only"
    claim = _claimed_parser(client, isolate_settings, engagement_key)
    lead = _receipt(client, engagement_key, claim, "suspicious")
    assert lead.status_code == 201, lead.text

    refused = _close_as(client, engagement_key, claim, "clean")

    assert refused.status_code == 409, refused.text
    detail = refused.json()["detail"]
    assert "requires queue disposition='suspicious'" in detail
    assert f"supersedes={lead.json()['id']}" in detail
    assert _close_as(client, engagement_key, claim, "suspicious").status_code == 200


def test_a_receipt_that_supersedes_the_lead_settles_it_in_the_attempt(client, isolate_settings):
    engagement_key = "2026-11-14-code-candidate-settle"
    claim = _claimed_parser(client, isolate_settings, engagement_key)
    lead = _receipt(client, engagement_key, claim, "suspicious")
    assert lead.status_code == 201, lead.text

    settled = _receipt(client, engagement_key, claim, "finding", supersedes=lead.json()["id"])

    assert settled.status_code == 201, settled.text
    closed = _close_as(client, engagement_key, claim, "finding")
    assert closed.status_code == 200, closed.text
    assert "open_lead_receipts" not in closed.json()
    assert "unresolved_suspicious_analysis" not in _blocker_codes(
        _verify_variant_readiness(client, engagement_key)
    )


def test_done_dry_run_runs_the_close_checks_and_writes_nothing(client, isolate_settings):
    engagement_key = "2026-11-14-code-done-dry-run"
    claim = _claimed_parser(client, isolate_settings, engagement_key)
    assert _receipt(client, engagement_key, claim, "finding").status_code == 201
    lead = _receipt(client, engagement_key, claim, "suspicious")
    assert lead.status_code == 201, lead.text
    coverage = _network_input_coverage(default_effort=80)

    mismatched = _done(
        client, engagement_key, claim, disposition="suspicious", notes="n",
        cwe_coverage=coverage, dry_run=True,
    )
    assert mismatched.status_code == 409, mismatched.text
    assert "candidate-bearing" in mismatched.json()["detail"]

    previewed = _done(
        client, engagement_key, claim, disposition="finding", notes="n",
        cwe_coverage=coverage, dry_run=True,
    )
    assert previewed.status_code == 200, previewed.text
    body = previewed.json()
    assert body["dry_run"] is True
    assert body["updated"] == 0 and body["would_update"] == 1
    assert body["open_lead_receipts"] == [lead.json()["id"]]
    assert _queue_status(isolate_settings, int(claim["id"])) == "processing"

    closed = _done(
        client, engagement_key, claim, disposition="finding", notes="n", cwe_coverage=coverage,
    )
    assert closed.status_code == 200, closed.text
    assert closed.json()["updated"] == 1
    assert _queue_status(isolate_settings, int(claim["id"])) == "done"


def test_a_dry_run_that_finds_the_item_closed_after_the_lock_says_dry_run(
    client, isolate_settings, monkeypatch
):
    engagement_key = "2026-11-14-code-done-dry-run-race"
    claim = _claimed_parser(client, isolate_settings, engagement_key)
    assert _receipt(client, engagement_key, claim, "finding").status_code == 201
    coverage = _network_input_coverage(default_effort=80)
    with db_module.get_connection() as connection:
        engagement_id = connection.execute(
            "SELECT engagement_id FROM code_analysis_queue WHERE id = ?", (int(claim["id"]),)
        ).fetchone()[0]
        before_close = code_analysis._get_queue_rows(
            connection, int(engagement_id), {int(claim["id"])}
        )
    closed = _done(
        client, engagement_key, claim, disposition="finding", notes="n", cwe_coverage=coverage,
    )
    assert closed.status_code == 200, closed.text

    # The first read sees the item still open (another close lands between it
    # and the lock); the re-read under the lock finds it done.
    real_get_queue_rows = code_analysis._get_queue_rows
    reads = iter([before_close])
    monkeypatch.setattr(
        code_analysis, "_get_queue_rows",
        lambda *args, **kwargs: next(reads, None) or real_get_queue_rows(*args, **kwargs),
    )

    replayed = _done(
        client, engagement_key, claim, disposition="finding", notes="n",
        cwe_coverage=coverage, dry_run=True,
    )

    assert replayed.status_code == 200, replayed.text
    assert replayed.json()["dry_run"] is True


def test_a_claim_reads_awaiting_verdict_state_for_its_own_files_only(client, isolate_settings):
    """Every claim lists the file's open leads, so the awaiting-verdict window
    it runs is scoped to the claimed files rather than every attempt in the
    engagement: a large repository pays per claim for what the claim hands over."""
    engagement_key = "2026-11-14-code-candidate-lead-claim-scope"
    claim, _finding, lead, _closed = _finding_closed_with_lead(
        client, isolate_settings, engagement_key
    )
    file_id = int(claim["file_id"])
    queued = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue",
        json={
            "mode": "reanalysis",
            "reason": "Phase 2B: settle the held length-field lead.",
            "items": [{"file_id": file_id, "priority": 79, "supersedes": int(claim["id"])}],
        },
    )
    assert queued.status_code == 201, queued.text
    engagement = db_module.get_engagement_by_key(engagement_key)
    assert engagement is not None

    statements: list[str] = []
    with db_module.get_connection() as connection:
        connection.set_trace_callback(statements.append)
    try:
        [reanalysis] = code_analysis.fetch_queue_items(engagement.id, 1, "resolution-agent")
    finally:
        with db_module.get_connection() as connection:
            connection.set_trace_callback(None)

    assert [row["id"] for row in reanalysis["open_lead_receipts"]] == [lead["id"]]
    windows = [" ".join(sql.split()) for sql in statements if "awaits_verdict" in sql]
    assert windows, statements
    assert all(
        f"semantic_attempt.file_id IN (SELECT value FROM json_each('[{file_id}]'))" in sql
        for sql in windows
    ), windows
