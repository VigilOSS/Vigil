"""Every code-track readiness blocker names the verb that clears it.

A blocker that states a condition and no remedy is a dead end, and two of them
are worse than that:

* `code_leads_unresolved` gates the code track's `complete` edge, which
  `transition_phase` refuses to `--force` at all — so an unanswered lead with no
  named clearing verb can leave an engagement unable to finish.
* `analysis_queue_active` counts `error` rows that `reset-stale` cannot touch
  (it sweeps `processing` only), so the only escape an operator could find was
  `--force`, which drops those files' coverage silently.

These pin the remedy, not the prose: each assertion names the verb an operator
has to run, and the active/errored split that says which one applies.
"""
from __future__ import annotations

from test_code_analysis_api import (
    _claim_file_for_analysis,
    _classify_file,
    _create_files,
    _create_repo,
    write_engagement,
)
from test_code_lead_bindings import (
    _bind,
    _blockers_by_code,
    _readiness,
    _record_lead,
    _seed_repo_with_files,
)


def test_unresolved_lead_blocker_names_the_disposition_verb(client, isolate_settings):
    engagement_key = "2026-11-06-code-lead-remedy"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo, _files = _seed_repo_with_files(client, engagement_key)
    lead = _record_lead(client, engagement_key, "Unanswered prior art")
    assert _bind(
        client,
        engagement_key,
        note_id=int(lead["id"]),
        repo_id=int(repo["id"]),
        file_path="src/parser.py",
    ).status_code == 201

    blocker = _blockers_by_code(_readiness(client, engagement_key))[
        "code_leads_unresolved"
    ]

    message = blocker["message"]
    assert "vigil assess intel update note" in message
    assert "lead_status" in message
    assert "resolved" in message


def test_errored_queue_blocker_separates_errored_rows_and_names_retry_error(
    client, isolate_settings
):
    engagement_key = "2026-11-06-code-errored-queue-remedy"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="errored-queue-remedy-repo")
    base = f"/engagements/{engagement_key}/assessment/code"
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser = next(row for row in files if row["file_path"] == "src/parser.py")
    helper = next(row for row in files if row["file_path"] == "src/helpers.py")
    _classify_file(client, engagement_key, int(parser["id"]), "high", 70)
    _classify_file(client, engagement_key, int(helper["id"]), "high", 60)

    pending_claim = _claim_file_for_analysis(
        client, engagement_key, int(helper["id"]), agent_name="hunter-pending"
    )
    assert pending_claim["status"] == "processing"
    errored_claim = _claim_file_for_analysis(
        client, engagement_key, int(parser["id"]), agent_name="hunter-errored"
    )
    errored = client.post(
        f"{base}/analysis-queue/error",
        json={
            "item_ids": [errored_claim["id"]],
            "agent_name": errored_claim["agent_name"],
            "lease_token": errored_claim["lease_token"],
            "notes": "the toolchain was unavailable",
        },
    )
    assert errored.status_code == 200, errored.text

    blocker = _blockers_by_code(_readiness(client, engagement_key, "verify-variant"))[
        "analysis_queue_active"
    ]
    message = blocker["message"]
    # The leading number stays the total the Code view counts, and the split
    # follows it because the two halves need different remedies.
    assert message.startswith("Repository has 2 active or errored")
    assert "1 active, 1 errored" in message
    assert "code-dispatch retry-error" in message
    assert "code-dispatch reset-stale" in message

    retried = client.post(
        f"{base}/analysis-queue/retry-error",
        json={"item_ids": [errored_claim["id"]], "reason": "toolchain restored"},
    )
    assert retried.status_code == 200, retried.text
    cleared = _blockers_by_code(_readiness(client, engagement_key, "verify-variant"))[
        "analysis_queue_active"
    ]["message"]
    assert "errored" not in cleared
    assert cleared.startswith("Repository has 2 active analysis queue item(s)")
    assert "code-dispatch retry-error" not in cleared
