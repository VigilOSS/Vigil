"""Which tiers the per-family effort floor *refuses* the coverage gate on.

`effort` is a number the reviewing agent writes into its own `cwe_coverage`
entry, and `code_record_analysis._validate_cwe_coverage` only checks that it
parses as a float. ADR 0001 decision 3 — left standing by ADR 0012 — says never
to gate on self-attested or free-text signal, so the effort floor is a harness
dimension: it reports, it ranks, it steers, and the one terminal hard block
stays the structural "never touched and never explicitly deferred" fact.

Critical and high keep refusing the gate: that scope predates this rule and is
what the dispatch contract promises. Medium is advisory — still computed, still
named in `gate.effort_warnings` and so in readiness `quality_gate.warnings` and
every review-quality rendering, but never a reason the gate withholds `passed`.
"""
from __future__ import annotations

import pytest

from tests.test_code_analysis_api import (
    _claim_file_for_analysis,
    _classify_file,
    _create_files,
    _create_repo,
    _network_input_coverage,
    _owned,
    _publish_structural_callables,
    _record_fixture_source_receipt,
    write_engagement,
)

# A medium file carries no slot-type obligation, so its applicable set is the
# language/role baseline both of these families sit in.
_MEDIUM_FAMILIES = ("algorithmic-dos", "error-handling")
_MEDIUM_THRESHOLD = 30
_UNDER_EVERY_THRESHOLD = 10


def _seed(client, isolate_settings, engagement_key):
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key=f"{engagement_key}-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    _publish_structural_callables(client, engagement_key, int(repo["id"]), files, {})
    return repo, files


def _classify_medium(client, engagement_key, file_id):
    response = client.post(
        f"/engagements/{engagement_key}/assessment/code/files/bulk-classify",
        json={
            "classifications": [
                {
                    "file_id": file_id,
                    "classification": "medium",
                    "role": "utility",
                    "analysis_priority": 40,
                }
            ]
        },
    )
    assert response.status_code == 200, response.text


def _close(client, engagement_key, file_row, *, priority, cwe_coverage):
    claim = _claim_file_for_analysis(
        client,
        engagement_key,
        int(file_row["id"]),
        priority=priority,
        agent_name=f"hunter-{file_row['id']}",
    )
    _record_fixture_source_receipt(client, engagement_key, claim)
    done = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/done",
        json=_owned(
            claim,
            item_ids=[claim["id"]],
            disposition="clean",
            notes="Reviewed.",
            cwe_coverage=cwe_coverage,
        ),
    )
    assert done.status_code == 200, done.text


def _gate(client, engagement_key, repo_id):
    response = client.get(
        f"/engagements/{engagement_key}/assessment/code/coverage?repo_id={repo_id}"
    )
    assert response.status_code == 200, response.text
    return response.json()["gate"]


def test_a_medium_file_under_its_effort_floor_reports_without_blocking(
    client, isolate_settings
):
    engagement_key = "2026-11-07-effort-medium-advisory"
    repo, files = _seed(client, isolate_settings, engagement_key)
    medium = next(row for row in files if row["file_path"] == "src/parser.py")
    _classify_medium(client, engagement_key, int(medium["id"]))
    _close(
        client,
        engagement_key,
        medium,
        priority=40,
        cwe_coverage=[
            {"family": family, "effort": _UNDER_EVERY_THRESHOLD}
            for family in _MEDIUM_FAMILIES
        ],
    )

    gate = _gate(client, engagement_key, int(repo["id"]))

    # The gap is still measured and still named — this is the instrument.
    for family in _MEDIUM_FAMILIES:
        expected = (
            f"Medium file src/parser.py: family '{family}' "
            f"effort {_UNDER_EVERY_THRESHOLD} < {_MEDIUM_THRESHOLD}"
        )
        assert any(
            expected in warning for warning in gate["effort_warnings"]
        ), gate["effort_warnings"]

    # ... and it is not a reason the gate withholds `passed` for.
    assert gate["passed"] is True, gate["reasons"]
    assert not [reason for reason in gate["reasons"] if "src/parser.py" in reason], (
        gate["reasons"]
    )

    # The closeout diagnostic still carries it, as an advisory that does not
    # refuse the transition.
    readiness = client.get(
        f"/engagements/{engagement_key}/assessment/code/readiness"
        "?target_phase=complete"
    )
    assert readiness.status_code == 200, readiness.text
    quality = readiness.json()["quality_gate"]
    assert any(
        "Medium file src/parser.py" in warning for warning in quality["warnings"]
    ), quality
    assert not [
        blocker
        for blocker in readiness.json()["blockers"]
        if "src/parser.py" in str(blocker)
    ], readiness.json()["blockers"]


@pytest.mark.parametrize(
    ("tier", "priority", "threshold"),
    [("critical", 100, 70), ("high", 60, 50)],
)
def test_a_blocking_tier_under_its_effort_floor_still_refuses_the_gate(
    client, isolate_settings, tier, priority, threshold
):
    engagement_key = f"2026-11-07-effort-{tier}-blocks"
    repo, files = _seed(client, isolate_settings, engagement_key)
    blocking = next(row for row in files if row["file_path"] == "src/parser.py")
    medium = next(row for row in files if row["file_path"] == "src/helpers.py")
    _classify_file(client, engagement_key, int(blocking["id"]), tier, priority)
    _classify_medium(client, engagement_key, int(medium["id"]))
    _close(
        client,
        engagement_key,
        blocking,
        priority=priority,
        cwe_coverage=_network_input_coverage(default_effort=_UNDER_EVERY_THRESHOLD),
    )
    _close(
        client,
        engagement_key,
        medium,
        priority=40,
        cwe_coverage=[
            {"family": family, "effort": _UNDER_EVERY_THRESHOLD}
            for family in _MEDIUM_FAMILIES
        ],
    )

    gate = _gate(client, engagement_key, int(repo["id"]))

    assert gate["passed"] is False
    assert any(
        f"{tier.capitalize()} file src/parser.py: family 'ssrf' "
        f"effort {_UNDER_EVERY_THRESHOLD} < {threshold}" in reason
        for reason in gate["reasons"]
    ), gate["reasons"]
    # The advisory medium rides along in the warning channel without ever
    # becoming one of the gate's refusal reasons.
    assert not [reason for reason in gate["reasons"] if "src/helpers.py" in reason], (
        gate["reasons"]
    )
    assert any(
        "Medium file src/helpers.py" in warning for warning in gate["effort_warnings"]
    ), gate["effort_warnings"]
    assert any(
        f"{tier.capitalize()} file src/parser.py" in warning
        for warning in gate["effort_warnings"]
    ), gate["effort_warnings"]
