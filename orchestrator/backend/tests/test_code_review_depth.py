"""Coverage reports how deep each file's review went, as a pointer and never a gate.

A pass counts when it is a successful terminal review of the current source
generation. It is deep when it was a reanalysis, ran under a `deep-manual`
dispatch, or ran under a packet whose `hunt_scope` is `deep`; a trigger
requeue or an ordinary first pass is wide. The depth columns are derived from
those receipts alone, so a file reads deep only when the queue says so, and a
critical/high file that produced signal on wide passes only is named in
`gate.depth_advisories` without entering `gate.reasons` or blocking a phase.
"""
from __future__ import annotations

import sqlite3

from test_code_analysis_api import (
    _classify_file,
    _create_repo,
    _ensure_finding_author_dispatch,
    _finding_code_snapshot,
    _network_input_coverage,
    _owned,
    _publish_structural_callables,
    _refresh_repo_files,
    _source_hash,
    db_module,
    write_engagement,
)

_PATHS = {
    "src/views.py": "critical",   # wide pass, clean, but a finding sits in it
    "src/auth.py": "high",        # wide pass, suspicious
    "src/parser.py": "critical",  # wide suspicious pass, then a reanalysis
    "src/export.py": "high",      # pass under a deep-manual dispatch
    "src/api.py": "high",         # pass under a packet with hunt_scope deep
    "src/util.py": "critical",    # suspicious pass, then a trigger requeue pass
    "src/clean.py": "high",       # wide pass, clean, no finding
    "src/todo.py": "high",        # never reviewed
    "lib/low.py": "low",          # wide pass, suspicious, but low tier
}


def _manifest() -> list[dict[str, object]]:
    return [
        {
            "file_path": path,
            "language": "python",
            "loc": 10 + index,
            "file_hash": _source_hash(path),
            "header_snippet": "",
            "git_churn_score": 0,
            "has_past_cve_fix": False,
        }
        for index, path in enumerate(_PATHS)
    ]


def _dispatch(client, engagement_key: str, agent_id: str, **fields) -> None:
    created = client.post(
        f"/engagements/{engagement_key}/assessment/dispatches",
        json={
            "agent_id": agent_id,
            "agent_role": "code-vuln-hunter",
            "task": "Review the assigned files.",
            "status": "in-progress",
            "skills": "code-review",
            **fields,
        },
    )
    assert created.status_code in (200, 201), created.text


def _seed(client, isolate_settings, engagement_key: str):
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    base = f"/engagements/{engagement_key}/assessment/code"
    repo = _create_repo(client, engagement_key, repo_key=f"{engagement_key}-app")
    repo_id = int(repo["id"])
    files = _refresh_repo_files(client, engagement_key, repo_id, _manifest())
    _publish_structural_callables(client, engagement_key, repo_id, files, {})
    ids = {str(row["file_path"]): int(row["id"]) for row in files}
    priority = {"critical": 90, "high": 70, "low": 10}
    for path, tier in _PATHS.items():
        _classify_file(client, engagement_key, ids[path], tier, priority[tier])

    _dispatch(client, engagement_key, "code-hunter-deep", dispatch_mode="deep-manual")
    _dispatch(
        client,
        engagement_key,
        "code-hunter-scoped",
        dispatch_mode="item-iterating",
        prompt_packet={
            "schema": "dispatch-prompt/v1",
            "context": {"hunt_scope": " Deep ", "target": "src/api.py"},
            "rendered_prompt": "## Dispatch Mindset\nhunt_scope: deep\n",
        },
    )

    def review(path: str, agent: str, disposition: str, *, mode: str = "initial", supersedes=None):
        item: dict[str, object] = {"file_id": ids[path], "priority": priority[_PATHS[path]]}
        body: dict[str, object] = {"items": [item]}
        if mode != "initial":
            item["supersedes"] = supersedes
            body.update(mode=mode, reason="Deeper read of the request handling")
        queued = client.post(f"{base}/analysis-queue", json=body)
        assert queued.status_code == 201, queued.text
        claimed = client.post(
            f"{base}/analysis-queue/fetch",
            json={"limit": 1, "agent_name": agent, "path_prefix": [path]},
        )
        assert claimed.status_code == 200, claimed.text
        attempt = claimed.json()[0]
        recorded = client.post(
            f"{base}/analysis-results",
            json=_owned(
                attempt,
                queue_item_id=attempt["id"],
                disposition=disposition,
                evidence="handler reads the request body before validation",
            ),
        )
        assert recorded.status_code == 201, recorded.text
        done = client.post(
            f"{base}/analysis-queue/done",
            json=_owned(
                attempt,
                item_ids=[attempt["id"]],
                disposition=disposition,
                notes="review complete",
                cwe_coverage=_network_input_coverage(default_effort=80),
            ),
        )
        assert done.status_code == 200, done.text
        return int(attempt["id"])

    review("src/views.py", "hunter-1", "clean")
    review("src/auth.py", "hunter-1", "suspicious")
    first = review("src/parser.py", "hunter-1", "suspicious")
    review("src/parser.py", "hunter-2", "clean", mode="reanalysis", supersedes=first)
    review("src/export.py", "code-hunter-deep", "suspicious")
    review("src/api.py", "code-hunter-scoped", "suspicious")
    first = review("src/util.py", "hunter-1", "suspicious")
    requeued = review("src/util.py", "hunter-2", "clean", mode="reanalysis", supersedes=first)
    review("src/clean.py", "hunter-1", "clean")
    review("lib/low.py", "hunter-1", "suspicious")
    # A trigger requeue is an ordinary follow-up pass, not a deep one; the
    # mode is the only thing that differs from the reanalysis just closed.
    with sqlite3.connect(str(db_module.database_path())) as connection:
        connection.execute(
            "UPDATE code_analysis_queue SET queue_mode = 'trigger' WHERE id = ?", (requeued,)
        )
        connection.commit()

    author = "AUTHOR-ACME-VIEWS"
    _ensure_finding_author_dispatch(client, engagement_key, author)
    finding = client.post(
        f"/engagements/{engagement_key}/assessment/findings",
        json={
            "slug": "CV-101",
            "title": "Stored XSS in the Acme views renderer",
            "severity": "high",
            "workflow_status": "active",
            "verification_status": "unreviewed",
            "defect_family": "xss",
            "root_cause_key": "acme-views-xss",
            "auth_context": "anonymous",
            "canonical_location": "file:src/views.py:4",
            "summary": "The renderer writes a stored title without escaping.",
            "evidence_ref": "notes/CV-101.md",
            "source_name": "code-vuln-hunter",
            "details": {"evidence": "render() interpolates title.", "impact": "Script runs."},
            "provenance": {
                "agent_id": author,
                "agent_name": "code-vuln-hunter",
                "code_snapshot": _finding_code_snapshot(client, engagement_key, repo_id),
            },
            "links": [],
        },
    )
    assert finding.status_code == 201, finding.text
    return base, ids


def test_cwe_matrix_rows_carry_each_files_review_depth(client, isolate_settings):
    base, _ids = _seed(client, isolate_settings, "2026-11-13-review-depth-matrix")

    detail = client.get(f"{base}/coverage?detail=cwe")
    assert detail.status_code == 200, detail.text
    depth = {row["file_path"]: row["review_depth"] for row in detail.json()["files"]}

    assert depth["src/views.py"] == {
        "depth": "wide_only", "passes": 1, "deep_passes": 0, "dispatches": 1, "signal_passes": 0,
    }
    assert depth["src/parser.py"] == {
        "depth": "deep", "passes": 2, "deep_passes": 1, "dispatches": 2, "signal_passes": 1,
    }
    assert depth["src/export.py"]["depth"] == "deep"
    assert depth["src/api.py"]["depth"] == "deep"
    # Two passes, neither deep: the second is a trigger requeue.
    assert depth["src/util.py"] == {
        "depth": "wide_only", "passes": 2, "deep_passes": 0, "dispatches": 2, "signal_passes": 1,
    }
    assert depth["src/todo.py"] == {
        "depth": "none", "passes": 0, "deep_passes": 0, "dispatches": 0, "signal_passes": 0,
    }


def test_depth_advisories_name_signal_files_reviewed_only_wide_and_never_gate(
    client, isolate_settings
):
    base, ids = _seed(client, isolate_settings, "2026-11-13-review-depth-advisory")

    summary = client.get(f"{base}/coverage").json()
    gate = summary["gate"]
    advisories = {row["file_path"]: row for row in gate["depth_advisories"]}
    # Suspicious wide-only passes, and a clean wide pass over a file a current
    # finding sits in. Deep files, a clean file with no finding, an unreviewed
    # file and a low-tier file are not named.
    assert set(advisories) == {"src/auth.py", "src/util.py", "src/views.py"}
    assert advisories["src/auth.py"] == {
        "file_id": ids["src/auth.py"],
        "file_path": "src/auth.py",
        "classification": "high",
        "passes": 1,
        "dispatches": 1,
        "signal_passes": 1,
        "findings": 0,
    }
    assert advisories["src/views.py"]["findings"] == 1
    assert advisories["src/views.py"]["signal_passes"] == 0
    assert not any("depth" in reason.lower() for reason in gate["reasons"])

    readiness = client.get(f"{base}/readiness?target_phase=verify-variant").json()
    assert {row["file_path"] for row in readiness["depth_advisories"]} == set(advisories)
    assert not any(
        "depth" in str(blocker.get("code", "")) for blocker in readiness["blockers"]
    )
    assert not any("deep pass" in warning for warning in readiness["quality_gate"]["warnings"])


def test_by_path_rows_count_review_depth_per_directory(client, isolate_settings):
    base, _ids = _seed(client, isolate_settings, "2026-11-13-review-depth-by-path")

    rows = {
        row["path"]: row
        for row in client.get(f"{base}/coverage/by-path?depth=1").json()["directories"]
    }
    assert rows["src"]["by_review_depth"] == {"deep": 3, "wide_only": 4, "none": 1}
    assert rows["src"]["critical_high_wide_only"] == 4
    assert rows["lib"]["by_review_depth"] == {"deep": 0, "wide_only": 1, "none": 0}
    assert rows["lib"]["critical_high_wide_only"] == 0
    for row in rows.values():
        assert sum(row["by_review_depth"].values()) == row["files"]
