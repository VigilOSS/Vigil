"""B8: a reference repository is readable but owns no review obligation.

Reviewing a plugin means loading the host framework's source so a specialist
can look a symbol up and cite it exactly. Before the repository role existed,
that lookup silently bought a coverage, queue, receipt and phase-readiness
obligation over a second codebase nobody was reviewing — the Keycloak case.
``repo_role = 'reference'`` removes the *obligation* and never the *access*.
"""
from __future__ import annotations

import sqlite3

from test_code_analysis_api import (
    _classify_file,
    _create_code_parent_finding,
    _create_files,
    _create_repo,
    _refresh_repo_files,
    _publish_structural_callables,
    write_engagement,
)

from app import db as db_module


def _base(engagement_key: str) -> str:
    return f"/engagements/{engagement_key}/assessment/code"


def _threat_model(client, engagement_key: str, repo_id: int) -> None:
    base = _base(engagement_key)
    binding = client.get(f"{base}/repos/{repo_id}").json()
    response = client.post(
        f"{base}/threat-model",
        json={
            "repo_id": repo_id,
            "repo_generation": binding["active_generation"],
            "source_manifest_digest": binding["source_manifest_digest"],
            "threat_model": {"trust_boundaries": ["network"]},
        },
    )
    assert response.status_code == 200, response.text


def _blocker_codes(readiness: dict) -> set[str]:
    return {blocker["code"] for blocker in readiness["blockers"]}


_MANIFEST_FIELDS = (
    "file_path",
    "language",
    "loc",
    "file_hash",
    "header_snippet",
    "git_churn_score",
    "has_past_cve_fix",
)


def _manifest_of(client, engagement_key: str, repo_id: int) -> list[dict]:
    """The repository's current files in the shape a re-ingest re-posts."""
    rows = client.get(
        f"{_base(engagement_key)}/files?repo_id={repo_id}&limit=10000"
        "&include_header_snippet=true"
    ).json()["items"]
    return [{field: row[field] for field in _MANIFEST_FIELDS} for row in rows]


def _queued_analysis_repo(client, engagement_key: str) -> tuple[dict, list[dict]]:
    """An analysis repository with every admitted file pending in the queue."""
    repo = _create_repo(client, engagement_key, repo_key="plugin")
    files = _create_files(client, engagement_key, int(repo["id"]))
    for row in files:
        _classify_file(client, engagement_key, int(row["id"]), "critical", 100)
    response = client.post(
        f"{_base(engagement_key)}/analysis-queue",
        json={"items": [{"file_id": int(row["id"]), "priority": 100} for row in files]},
    )
    assert response.status_code == 201, response.text
    return client.get(f"{_base(engagement_key)}/repos/{repo['id']}").json(), files


def _reingest_with_role(client, engagement_key: str, repo_id: int, role: str) -> dict:
    """Re-ingest byte-identical source under an explicit role.

    Nothing about the source changes, so the generation does not move and no
    queue row is superseded — which is exactly the state a role change has to
    survive.
    """
    _refresh_repo_files(
        client,
        engagement_key,
        repo_id,
        _manifest_of(client, engagement_key, repo_id),
        repo_role=role,
    )
    return client.get(f"{_base(engagement_key)}/repos/{repo_id}").json()


def test_repo_role_defaults_to_analysis_and_accepts_reference(
    client, isolate_settings
):
    engagement_key = "2026-09-16-repo-role-default"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)

    default_repo = _create_repo(client, engagement_key, repo_key="app-repo")
    assert default_repo["repo_role"] == "analysis"

    reference_repo = _create_repo(
        client, engagement_key, repo_key="keycloak-repo", repo_role="reference"
    )
    assert reference_repo["repo_role"] == "reference"

    listed = client.get(f"{_base(engagement_key)}/repos").json()
    assert {row["repo_key"]: row["repo_role"] for row in listed} == {
        "app-repo": "analysis",
        "keycloak-repo": "reference",
    }


def test_a_re_ingest_without_a_role_keeps_the_recorded_role(
    client, isolate_settings
):
    """Forgetting --role on a refresh must not re-arm a coverage obligation.

    Refreshing reference source after an upstream update is routine. If an
    omitted role meant `analysis`, that routine refresh would hand the
    engagement coverage over the host framework — the exact failure B8 removes.
    """
    engagement_key = "2026-09-16-repo-role-reingest"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    base = _base(engagement_key)

    reference_repo = _create_repo(
        client, engagement_key, repo_key="host-framework", repo_role="reference"
    )
    files = _create_files(client, engagement_key, int(reference_repo["id"]))
    assert client.get(f"{base}/repos/{reference_repo['id']}").json()["repo_role"] == (
        "reference"
    )

    _refresh_repo_files(
        client,
        engagement_key,
        int(reference_repo["id"]),
        [
            {
                key: row[key]
                for key in (
                    "file_path", "language", "loc", "file_hash",
                    "header_snippet", "git_churn_score", "has_past_cve_fix",
                )
            }
            for row in files
        ],
    )

    assert client.get(f"{base}/repos/{reference_repo['id']}").json()["repo_role"] == (
        "reference"
    )


def test_an_explicit_role_promotion_restores_the_review_obligation(
    client, isolate_settings
):
    """Promotion is the deliberate opposite of the default: obligations return."""
    engagement_key = "2026-09-16-repo-role-promotion"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    base = _base(engagement_key)

    repo = _create_repo(
        client, engagement_key, repo_key="host-framework", repo_role="reference"
    )
    files = _create_files(client, engagement_key, int(repo["id"]))
    assert "admitted_files_unqueued" not in _blocker_codes(
        client.get(f"{base}/readiness?target_phase=hunt").json()
    )

    manifest = [
        {
            key: row[key]
            for key in (
                "file_path", "language", "loc", "file_hash",
                "header_snippet", "git_churn_score", "has_past_cve_fix",
            )
        }
        for row in files
    ]
    _refresh_repo_files(
        client, engagement_key, int(repo["id"]), manifest, repo_role="analysis"
    )

    assert client.get(f"{base}/repos/{repo['id']}").json()["repo_role"] == "analysis"
    promoted = client.get(f"{base}/readiness?target_phase=hunt").json()
    unqueued = [
        blocker
        for blocker in promoted["blockers"]
        if blocker["code"] == "admitted_files_unqueued"
    ]
    assert len(unqueued) == 1
    assert unqueued[0]["repo_id"] == repo["id"]


def test_unknown_repo_role_is_rejected(client, isolate_settings):
    engagement_key = "2026-09-16-repo-role-invalid"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)

    from test_code_analysis_api import _verified_repo_payload

    payload = _verified_repo_payload(client, engagement_key, "bad-role-repo")
    payload["repo_role"] = "vendored"
    response = client.post(f"{_base(engagement_key)}/repos/refresh/start", json=payload)

    assert response.status_code == 422, response.text


def test_reference_repo_creates_no_hunt_readiness_obligation(
    client, isolate_settings
):
    """The reference repo is deliberately left in its worst possible state."""
    engagement_key = "2026-09-16-reference-hunt-readiness"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    base = _base(engagement_key)

    analysis_repo = _create_repo(client, engagement_key, repo_key="plugin-repo")
    analysis_files = _create_files(client, engagement_key, int(analysis_repo["id"]))
    _publish_structural_callables(
        client, engagement_key, int(analysis_repo["id"]), analysis_files, {}
    )
    _threat_model(client, engagement_key, int(analysis_repo["id"]))
    for row in analysis_files:
        _classify_file(client, engagement_key, int(row["id"]), "skip", 0)
        queued = client.post(
            f"{base}/analysis-queue",
            json={"items": [{"file_id": row["id"], "priority": 0}]},
        )
        assert queued.status_code == 201, queued.text

    # No classification, no structural index, no threat model, no queue rows.
    reference_repo = _create_repo(
        client, engagement_key, repo_key="host-framework", repo_role="reference"
    )
    _create_files(client, engagement_key, int(reference_repo["id"]))

    readiness = client.get(f"{base}/readiness?target_phase=hunt").json()

    assert readiness["transition_ready"] is True, readiness["blockers"]
    assert not [
        blocker
        for blocker in readiness["blockers"]
        if blocker.get("repo_id") == reference_repo["id"]
    ]


def test_analysis_repo_still_blocks_alongside_a_reference_repo(
    client, isolate_settings
):
    """Do-not-break: role exempts only the repository that declared it."""
    engagement_key = "2026-09-16-reference-does-not-exempt-analysis"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    base = _base(engagement_key)

    analysis_repo = _create_repo(client, engagement_key, repo_key="plugin-repo")
    analysis_files = _create_files(client, engagement_key, int(analysis_repo["id"]))
    _publish_structural_callables(
        client, engagement_key, int(analysis_repo["id"]), analysis_files, {}
    )
    _threat_model(client, engagement_key, int(analysis_repo["id"]))
    for row in analysis_files:
        _classify_file(client, engagement_key, int(row["id"]), "skip", 0)

    reference_repo = _create_repo(
        client, engagement_key, repo_key="host-framework", repo_role="reference"
    )
    _create_files(client, engagement_key, int(reference_repo["id"]))

    readiness = client.get(f"{base}/readiness?target_phase=hunt").json()
    unqueued = [
        blocker
        for blocker in readiness["blockers"]
        if blocker["code"] == "admitted_files_unqueued"
    ]

    assert readiness["transition_ready"] is False
    assert len(unqueued) == 1
    assert unqueued[0]["repo_id"] == analysis_repo["id"]


def test_an_engagement_of_only_reference_repos_has_no_analysis_repository(
    client, isolate_settings
):
    engagement_key = "2026-09-16-reference-only-engagement"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    base = _base(engagement_key)

    reference_repo = _create_repo(
        client, engagement_key, repo_key="host-framework", repo_role="reference"
    )
    _create_files(client, engagement_key, int(reference_repo["id"]))

    readiness = client.get(f"{base}/readiness?target_phase=classify-map").json()

    assert readiness["transition_ready"] is False
    assert "no_repositories" in _blocker_codes(readiness)


def test_queue_population_refuses_a_reference_file(client, isolate_settings):
    engagement_key = "2026-09-16-reference-queue-refusal"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    base = _base(engagement_key)

    reference_repo = _create_repo(
        client, engagement_key, repo_key="host-framework", repo_role="reference"
    )
    files = _create_files(client, engagement_key, int(reference_repo["id"]))
    target = files[0]
    _classify_file(client, engagement_key, int(target["id"]), "critical", 100)

    response = client.post(
        f"{base}/analysis-queue",
        json={"items": [{"file_id": target["id"], "priority": 100}]},
    )

    assert response.status_code == 400, response.text
    assert "reference" in response.json()["detail"]
    listed = client.get(f"{base}/analysis-queue?repo_id={reference_repo['id']}").json()
    assert listed["items"] == []


def test_reference_files_stay_sealed_indexed_and_citable(client, isolate_settings):
    """B8 removes obligations, never access: the lookup path must still work."""
    engagement_key = "2026-09-16-reference-stays-readable"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    base = _base(engagement_key)

    reference_repo = _create_repo(
        client, engagement_key, repo_key="host-framework", repo_role="reference"
    )
    files = _create_files(client, engagement_key, int(reference_repo["id"]))
    assert len(files) == 2

    listed = client.get(f"{base}/files?repo_id={reference_repo['id']}&limit=20")
    assert listed.status_code == 200, listed.text
    assert {row["file_path"] for row in listed.json()["items"]} == {
        "src/parser.py",
        "src/helpers.py",
    }

    searched = client.get(f"{base}/files?search=parser&limit=20").json()
    assert "src/parser.py" in {row["file_path"] for row in searched["items"]}

    detail = client.get(f"{base}/files/{files[0]['id']}")
    assert detail.status_code == 200, detail.text
    body = detail.json()
    # Structured source identity is what makes a citation checkable.
    assert body["file_path"] == files[0]["file_path"]
    assert body["file_hash"] == files[0]["file_hash"]

    repo = client.get(f"{base}/repos/{reference_repo['id']}").json()
    assert repo["source_snapshot_quality"] == "verified"
    assert repo["snapshot_digest"]
    assert repo["source_manifest_digest"]

    # Structural indexing still binds to the sealed generation.
    published = _publish_structural_callables(
        client, engagement_key, int(reference_repo["id"]), files, {}
    )
    assert published["updated"] == len(files)


def test_coverage_excludes_reference_files_and_names_the_repository(
    client, isolate_settings
):
    engagement_key = "2026-09-16-reference-coverage"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    base = _base(engagement_key)

    analysis_repo = _create_repo(client, engagement_key, repo_key="plugin-repo")
    analysis_files = _create_files(client, engagement_key, int(analysis_repo["id"]))
    for row in analysis_files:
        _classify_file(client, engagement_key, int(row["id"]), "critical", 100)

    reference_repo = _create_repo(
        client, engagement_key, repo_key="host-framework", repo_role="reference"
    )
    reference_files = _create_files(client, engagement_key, int(reference_repo["id"]))
    for row in reference_files:
        _classify_file(client, engagement_key, int(row["id"]), "critical", 100)

    coverage = client.get(f"{base}/coverage").json()

    assert coverage["total_files"] == len(analysis_files)
    assert coverage["by_classification"]["critical"]["count"] == len(analysis_files)
    assert [entry["repo_id"] for entry in coverage["reference_repos"]] == [
        reference_repo["id"]
    ]
    assert coverage["reference_repos"][0]["admitted_files"] == len(reference_files)

    # Scoping to the reference repository reports no obligation rather than
    # 404ing: the repository is published and readable, it simply owes nothing.
    scoped = client.get(f"{base}/coverage?repo_id={reference_repo['id']}")
    assert scoped.status_code == 200, scoped.text
    assert scoped.json()["total_files"] == 0
    assert [entry["repo_id"] for entry in scoped.json()["reference_repos"]] == [
        reference_repo["id"]
    ]

    # Scoping to the analysis repository does not mention it at all.
    analysis_scoped = client.get(f"{base}/coverage?repo_id={analysis_repo['id']}").json()
    assert analysis_scoped["total_files"] == len(analysis_files)
    assert analysis_scoped["reference_repos"] == []


def test_verify_variant_readiness_ignores_reference_file_accounting(
    client, isolate_settings
):
    engagement_key = "2026-09-16-reference-unaccounted"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    base = _base(engagement_key)

    reference_repo = _create_repo(
        client, engagement_key, repo_key="host-framework", repo_role="reference"
    )
    files = _create_files(client, engagement_key, int(reference_repo["id"]))
    for row in files:
        _classify_file(client, engagement_key, int(row["id"]), "critical", 100)

    readiness = client.get(f"{base}/readiness?target_phase=verify-variant").json()

    assert "admitted_files_unaccounted" not in _blocker_codes(readiness)
    assert "critical_high_incomplete" not in _blocker_codes(readiness)


def test_requeue_blocks_a_reference_target_without_failing_the_batch(
    client, isolate_settings
):
    engagement_key = "2026-09-16-reference-requeue"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    base = _base(engagement_key)

    reference_repo = _create_repo(
        client, engagement_key, repo_key="host-framework", repo_role="reference"
    )
    files = _create_files(client, engagement_key, int(reference_repo["id"]))
    target = files[0]
    _classify_file(client, engagement_key, int(target["id"]), "critical", 100)

    response = client.post(
        f"{base}/analysis-queue/requeue",
        json={"items": [{"file_id": target["id"], "reason": "cross-file trigger"}]},
    )

    assert response.status_code == 201, response.text
    body = response.json()
    assert body["blocked"] == 1
    assert body["inserted"] == 0
    blocked = [row for row in body["outcomes"] if row["outcome"] == "blocked"]
    assert len(blocked) == 1
    assert "reference" in blocked[0]["detail"]


def test_a_draft_finding_in_reference_source_is_still_gated(
    client, isolate_settings
):
    """B8 drops coverage obligations, not the engagement's own evidence.

    A specialist reading framework source can find a real bug there. That draft
    is authored evidence, not an obligation over a second codebase, so the
    fuzz/complete gate must still make the operator promote, merge or kill it.
    """
    engagement_key = "2026-09-16-reference-draft-finding"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    base = _base(engagement_key)

    reference_repo = _create_repo(
        client, engagement_key, repo_key="host-framework", repo_role="reference"
    )
    _create_files(client, engagement_key, int(reference_repo["id"]))
    _create_code_parent_finding(
        client,
        engagement_key,
        int(reference_repo["id"]),
        slug="CH-810",
        workflow_status="draft",
    )

    readiness = client.get(f"{base}/readiness?target_phase=fuzz").json()
    drafts = [
        blocker
        for blocker in readiness["blockers"]
        if blocker["code"] == "draft_code_findings_unresolved"
    ]

    assert len(drafts) == 1
    assert drafts[0]["repo_id"] == reference_repo["id"]
    # And it is not mistaken for an unbindable finding.
    assert "unbound_draft_code_findings_unresolved" not in _blocker_codes(readiness)


def test_migration_defaults_every_existing_repository_to_analysis(
    client, isolate_settings
):
    """An engagement DB written before B8 must keep its exact meaning.

    A genuine published repository is created, the column is removed to make the
    file a pre-B8 database, and the real ``init_db`` upgrade path runs — the
    sequence an operator's existing database actually takes on the next start.
    """
    engagement_key = "2026-09-16-repo-role-migration"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="pre-b8-repo")
    assert repo["repo_role"] == "analysis"

    db_path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    with sqlite3.connect(str(db_path)) as legacy:
        legacy.execute("ALTER TABLE code_repos DROP COLUMN repo_role")
        assert "repo_role" not in {
            row[1] for row in legacy.execute("PRAGMA table_info(code_repos)")
        }

    db_module.init_db()
    # Idempotent: a second open of the already-migrated file changes nothing.
    db_module.init_db()

    with sqlite3.connect(str(db_path)) as connection:
        roles = [
            row[0]
            for row in connection.execute(
                "SELECT repo_role FROM code_repos ORDER BY id"
            )
        ]

    assert roles == ["analysis"]
    # And the migrated row behaves exactly as it did: still an obligation.
    readiness = client.get(f"{_base(engagement_key)}/readiness?target_phase=hunt")
    assert readiness.status_code == 200, readiness.text
    assert "no_repositories" not in _blocker_codes(readiness.json())


def test_repo_role_vocabulary_mirrors_the_cli():
    from assess.lib.contracts import CODE_REPO_ROLES as CLI_CODE_REPO_ROLES
    from app.services.code_analysis import CODE_REPO_ROLES

    assert tuple(CLI_CODE_REPO_ROLES) == tuple(CODE_REPO_ROLES)


def test_a_reference_repository_needs_no_fuzz_decision(client, isolate_settings):
    """The last obligation a reference repo could still raise.

    `fuzz_states` enumerates verified repositories independently of the
    readiness loop, so a reference repository kept emitting
    `fuzz_decision_missing` through both `code/readiness?target_phase=fuzz` and
    `GET /report-readiness` — an obligation to decide fuzzing for a codebase
    nobody is reviewing. Filtered at the source query so both consumers are
    corrected by one predicate rather than two copies of it.
    """
    engagement_key = "2026-09-16-reference-fuzz-decision"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    base = _base(engagement_key)

    reference_repo = _create_repo(
        client, engagement_key, repo_key="host-framework", repo_role="reference"
    )
    _create_files(client, engagement_key, int(reference_repo["id"]))

    readiness = client.get(f"{base}/readiness?target_phase=fuzz").json()
    assert "fuzz_decision_missing" not in _blocker_codes(readiness)

    report = client.get(f"/api/engagements/{engagement_key}/report-readiness").json()
    kinds = {row.get("kind") for row in report.get("blockers", []) if isinstance(row, dict)}
    assert "fuzz_decision_missing" not in kinds


# --------------------------------------------------------------------------- #
# Demotion: the role is evaluated live, at the point work is handed out
# --------------------------------------------------------------------------- #


def test_demoting_a_repository_stops_its_queue_rows_being_claimable(
    client, isolate_settings
):
    # Nothing retires the rows: re-ingesting unchanged source does not move the
    # generation, so they stay bound to the active one. The role is what must
    # keep them out of the claim.
    engagement_key = "2026-09-16-reference-demotion-claim"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    base = _base(engagement_key)
    repo, _files = _queued_analysis_repo(client, engagement_key)

    demoted = _reingest_with_role(client, engagement_key, int(repo["id"]), "reference")

    assert demoted["repo_role"] == "reference"
    assert demoted["active_generation"] == repo["active_generation"]
    claimed = client.post(
        f"{base}/analysis-queue/fetch",
        json={"limit": 10, "agent_name": "code-vuln-hunter"},
    )
    assert claimed.status_code == 200, claimed.text
    assert claimed.json() == []


def test_a_demoted_repositorys_queue_rows_stay_visible_to_the_operator(
    client, isolate_settings
):
    # The rows are unclaimable, not hidden: the listing is where an operator
    # recovers the exact IDs, and it now says which role each row belongs to.
    engagement_key = "2026-09-16-reference-demotion-listing"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    base = _base(engagement_key)
    repo, files = _queued_analysis_repo(client, engagement_key)

    _reingest_with_role(client, engagement_key, int(repo["id"]), "reference")

    listed = client.get(f"{base}/analysis-queue?repo_id={repo['id']}").json()
    assert sorted(row["file_id"] for row in listed["items"]) == sorted(
        int(row["id"]) for row in files
    )
    assert {row["status"] for row in listed["items"]} == {"pending"}
    assert {row["repo_role"] for row in listed["items"]} == {"reference"}


def test_queue_stats_excludes_a_demoted_repository_and_names_it(
    client, isolate_settings
):
    # `stats` is the "is there work left" signal. Counting rows `fetch` will
    # never hand out leaves a queue that reads as stuck forever, so the count
    # excludes them and the disclosure list says which repository holds them.
    engagement_key = "2026-09-16-reference-demotion-stats"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    base = _base(engagement_key)
    repo, files = _queued_analysis_repo(client, engagement_key)

    _reingest_with_role(client, engagement_key, int(repo["id"]), "reference")

    stats = client.get(f"{base}/analysis-queue/stats").json()
    assert stats["pending"] == 0
    assert stats["total"] == 0
    assert stats["historical_total"] == 0
    assert stats["reference_repo_items"] == [
        {
            "repo_id": int(repo["id"]),
            "repo_key": str(repo["repo_key"]),
            "name": str(repo["name"]),
            "queue_items": len(files),
        }
    ]


def test_promoting_a_demoted_repository_makes_its_rows_claimable_again(
    client, isolate_settings
):
    # Demotion must not destroy the queue. Promotion already restores every
    # other obligation by re-evaluating the role live; the claim has to match.
    engagement_key = "2026-09-16-reference-promotion-claim"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    base = _base(engagement_key)
    repo, files = _queued_analysis_repo(client, engagement_key)
    _reingest_with_role(client, engagement_key, int(repo["id"]), "reference")

    _reingest_with_role(client, engagement_key, int(repo["id"]), "analysis")

    claimed = client.post(
        f"{base}/analysis-queue/fetch",
        json={"limit": 10, "agent_name": "code-vuln-hunter"},
    )
    assert claimed.status_code == 200, claimed.text
    assert sorted(item["file_id"] for item in claimed.json()) == sorted(
        int(row["id"]) for row in files
    )


def test_a_metadata_refresh_of_a_reference_repo_creates_no_queue_row(
    client, isolate_settings
):
    # Changed churn metadata reopens a file's review. A reference repository
    # owes no review, so the reopen must not manufacture the claimable row that
    # `POST /analysis-queue` and `requeue` both refuse to create.
    engagement_key = "2026-09-16-reference-metadata-refresh"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    base = _base(engagement_key)
    reference_repo = _create_repo(
        client, engagement_key, repo_key="host-framework", repo_role="reference"
    )
    _create_files(client, engagement_key, int(reference_repo["id"]))

    manifest = _manifest_of(client, engagement_key, int(reference_repo["id"]))
    for row in manifest:
        row["git_churn_score"] = int(row["git_churn_score"]) + 7
    _refresh_repo_files(client, engagement_key, int(reference_repo["id"]), manifest)

    listed = client.get(
        f"{base}/analysis-queue?repo_id={reference_repo['id']}"
    ).json()
    assert listed["items"] == []
