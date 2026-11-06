"""A refused `code-dispatch done` names what is missing and where to read it.

Three closeout refusals cost a real hunt wave a round trip each because the
message described a rule without naming the state it was applied to:

* the coverage refusal named the missing families but not the full required
  set, nor the classification metadata that derives it — and a queue row
  carries its own ``slot_types`` batch metadata, which is *not* what closeout
  enforces, so the obvious field disagreed with the rule;
* the missing-source-receipt refusal named neither the file nor the lease it
  searched under, so a `code-record analysis` that had failed validation
  surfaced as an unrelated closeout error;
* a lost lease token reported "no lease with token ... exists" without naming
  the read-only verb that hands the owning dispatch its token back.
"""
from __future__ import annotations

from test_code_analysis_api import (
    _create_files,
    _create_repo,
    _owned,
    _publish_structural_callables,
    _structural_callable,
    write_engagement,
)


def _seed_claimed_file(
    client,
    isolate_settings,
    engagement_key: str,
    *,
    repo_key: str,
    role: str = "parser",
    slot_types: tuple[str, ...] = ("NETWORK-INPUT",),
    item_slot_types: tuple[str, ...] | None = None,
    agent_name: str = "hunter-a",
):
    """One critical file claimed for analysis, with the queue row's own
    ``slot_types`` set independently of the file's classification slots."""
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
    base = f"/engagements/{engagement_key}/assessment/code"
    classified = client.post(
        f"{base}/files/bulk-classify",
        json={
            "classifications": [
                {
                    "file_id": int(parser["id"]),
                    "classification": "critical",
                    "role": role,
                    "slot_types": list(slot_types),
                    "analysis_priority": 100,
                },
                {
                    "file_id": int(helper["id"]),
                    "classification": "low",
                    "role": "helper",
                    "slot_types": [],
                    "analysis_priority": 10,
                },
            ]
        },
    )
    assert classified.status_code == 200, classified.text
    item: dict[str, object] = {"file_id": int(parser["id"]), "priority": 100}
    if item_slot_types is not None:
        item["slot_types"] = list(item_slot_types)
    queued = client.post(f"{base}/analysis-queue", json={"items": [item]})
    assert queued.status_code == 201, queued.text
    claimed = client.post(
        f"{base}/analysis-queue/fetch", json={"limit": 1, "agent_name": agent_name}
    )
    assert claimed.status_code == 200, claimed.text
    return repo, parser, claimed.json()[0]


def _record_clean_receipt(client, engagement_key: str, claim, families):
    response = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-results",
        json=_owned(
            claim,
            queue_item_id=claim["id"],
            disposition="clean",
            evidence="parse() validates every decoded length before indexing.",
            cwe_coverage=[{"family": family, "effort": 80} for family in families],
        ),
    )
    assert response.status_code == 201, response.text
    return response.json()


def _close(client, engagement_key: str, claim, families, *, disposition="clean"):
    coverage = [{"family": family, "effort": 80} for family in families]
    return client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/done",
        json={
            "item_ids": [claim["id"]],
            "agent_name": claim["agent_name"],
            "lease_token": claim["lease_token"],
            "disposition": disposition,
            "notes": "Reviewed every decode path.",
            "cwe_coverage": coverage,
        },
    )


# ─────────────────────────────────────────────────────────────────────────────
# L1: the coverage refusal states the whole required set and what derives it
# ─────────────────────────────────────────────────────────────────────────────

def test_the_claim_publishes_exactly_the_family_set_closeout_enforces(
    client, isolate_settings
) -> None:
    """The claim's `applicable_vuln_classes` is the authoritative required set.

    Pinned against the families a real wave was rejected for: a transactional
    role plus file/callback slots require `business-logic`, `race-condition`,
    `type-confusion` and `web-app-data-exposure`, and all four reach the hunter
    on the claim rather than only in the rejection.
    """
    engagement_key = "2026-11-07-closeout-declared-set"
    _repo, _parser, claim = _seed_claimed_file(
        client,
        isolate_settings,
        engagement_key,
        repo_key="closeout-declared-repo",
        role="Checkout payment resolver",
        slot_types=("FILE-CONTENT", "CALLBACK-DATA"),
    )
    declared = list(claim["applicable_vuln_classes"])
    assert {
        "business-logic",
        "race-condition",
        "type-confusion",
        "web-app-data-exposure",
    } <= set(declared)

    _record_clean_receipt(client, engagement_key, claim, declared)
    closed = _close(client, engagement_key, claim, declared)
    assert closed.status_code == 200, closed.text


def test_the_coverage_refusal_names_the_required_set_and_its_basis(
    client, isolate_settings
) -> None:
    engagement_key = "2026-11-07-closeout-coverage-refusal"
    _repo, _parser, claim = _seed_claimed_file(
        client,
        isolate_settings,
        engagement_key,
        repo_key="closeout-coverage-repo",
        role="Checkout payment resolver",
        slot_types=("FILE-CONTENT", "CALLBACK-DATA"),
        # What the queue row itself declares: batch metadata the operator typed
        # at submission, NOT the review surface closeout enforces.
        item_slot_types=("NETWORK-INPUT",),
    )
    declared = list(claim["applicable_vuln_classes"])
    assert claim["slot_types"] == ["NETWORK-INPUT"]
    assert sorted(claim["file"]["slot_types"]) == ["CALLBACK-DATA", "FILE-CONTENT"]

    short = [family for family in declared if family != "type-confusion"]
    _record_clean_receipt(client, engagement_key, claim, short)
    refused = _close(client, engagement_key, claim, short)

    assert refused.status_code == 400, refused.text
    detail = refused.json()["detail"]
    # The missing family, as before.
    assert "type-confusion" in detail
    # The full required set, so one refusal ends the guessing.
    for family in declared:
        assert family in detail
    # What derived it, and the queue row's own narrower slot_types, which is
    # the field a lane mistakes for the review surface.
    assert "CALLBACK-DATA" in detail and "FILE-CONTENT" in detail
    assert "Checkout payment resolver" in detail
    assert "NETWORK-INPUT" in detail
    # Where to re-read the authoritative list without a rejection.
    assert f"code-dispatch progress {claim['id']}" in detail


# ─────────────────────────────────────────────────────────────────────────────
# L7: the missing-receipt refusal names the file, the lease and the re-read
# ─────────────────────────────────────────────────────────────────────────────

def test_the_missing_source_receipt_refusal_names_the_file_and_the_lease(
    client, isolate_settings
) -> None:
    engagement_key = "2026-11-07-closeout-missing-receipt"
    _repo, parser, claim = _seed_claimed_file(
        client,
        isolate_settings,
        engagement_key,
        repo_key="closeout-receipt-repo",
    )
    declared = list(claim["applicable_vuln_classes"])

    # No `code-record analysis` ever landed — exactly what a silently refused
    # receipt leaves behind.
    refused = _close(client, engagement_key, claim, declared)

    assert refused.status_code == 400, refused.text
    detail = refused.json()["detail"]
    assert "source-level receipt" in detail
    assert str(parser["file_path"]) in detail
    assert f"queue item {claim['id']}" in detail
    assert "clean" in detail
    assert str(claim["agent_name"]) in detail
    assert f"code-dispatch progress {claim['id']}" in detail
    assert "code-record analysis" in detail


# ─────────────────────────────────────────────────────────────────────────────
# I1: a lost lease token has a named, read-only recovery
# ─────────────────────────────────────────────────────────────────────────────

def test_an_unknown_lease_token_names_the_read_only_token_recovery(
    client, isolate_settings
) -> None:
    engagement_key = "2026-11-07-closeout-lost-token"
    _repo, _parser, claim = _seed_claimed_file(
        client,
        isolate_settings,
        engagement_key,
        repo_key="closeout-token-repo",
    )
    base = f"/engagements/{engagement_key}/assessment/code"

    refused = client.post(
        f"{base}/analysis-queue/heartbeat",
        json={
            "item_id": claim["id"],
            "agent_name": claim["agent_name"],
            "lease_token": "00000000-0000-4000-8000-000000000000",
        },
    )

    assert refused.status_code == 409, refused.text
    detail = refused.json()["detail"]
    assert f"code-dispatch progress {claim['id']}" in detail


def test_a_transposed_lease_token_still_names_the_typo_before_the_recovery(
    client, isolate_settings
) -> None:
    """The typo diagnosis is the more specific cause and stays first."""
    engagement_key = "2026-11-07-closeout-transposed-token"
    _repo, _parser, claim = _seed_claimed_file(
        client,
        isolate_settings,
        engagement_key,
        repo_key="closeout-transposed-repo",
    )
    token = str(claim["lease_token"])
    # Transpose the first ADJACENT PAIR THAT DIFFERS. A uuid4 repeats its first
    # two characters about once in sixteen draws, and swapping a repeated pair
    # reproduces the token exactly — a typo the diagnostic cannot be asked to
    # see, and a one-in-sixteen hard failure in a blocking gate. A uuid4 always
    # has such a pair (the hyphen at index 8 differs from the hex before it), so
    # the search is total rather than best-effort.
    swap = next(index for index in range(len(token) - 1) if token[index] != token[index + 1])
    transposed = (
        token[:swap] + token[swap + 1] + token[swap] + token[swap + 2:]
    )
    assert transposed != token
    assert sorted(transposed) == sorted(token)
    base = f"/engagements/{engagement_key}/assessment/code"

    refused = client.post(
        f"{base}/analysis-queue/heartbeat",
        json={
            "item_id": claim["id"],
            "agent_name": claim["agent_name"],
            "lease_token": transposed,
        },
    )

    assert refused.status_code == 409, refused.text
    detail = refused.json()["detail"]
    assert "character order" in detail
    assert f"code-dispatch progress {claim['id']}" in detail


def test_queue_progress_hands_the_owning_dispatch_its_lease_token_back(
    client, isolate_settings
) -> None:
    """The supported read-only recovery for a lost token, end to end."""
    engagement_key = "2026-11-07-closeout-progress-token"
    _repo, parser, claim = _seed_claimed_file(
        client,
        isolate_settings,
        engagement_key,
        repo_key="closeout-progress-repo",
    )
    base = f"/engagements/{engagement_key}/assessment/code"

    progress = client.get(f"{base}/analysis-queue/{claim['id']}/progress")
    assert progress.status_code == 200, progress.text
    payload = progress.json()
    assert payload["lease_token"] == claim["lease_token"]
    assert payload["agent_name"] == claim["agent_name"]
    assert payload["applicable_vuln_classes"] == claim["applicable_vuln_classes"]

    listed = client.get(f"{base}/analysis-queue?status=processing").json()
    row = next(item for item in listed["items"] if int(item["id"]) == int(claim["id"]))
    assert row["lease_token"] == claim["lease_token"]

    # The recovered token closes the attempt it was issued for.
    declared = list(payload["applicable_vuln_classes"])
    _record_clean_receipt(
        client, engagement_key, {**claim, "lease_token": payload["lease_token"]}, declared
    )
    closed = _close(
        client,
        engagement_key,
        {**claim, "lease_token": payload["lease_token"]},
        declared,
    )
    assert closed.status_code == 200, closed.text
    assert str(parser["file_path"]) == "src/parser.py"
