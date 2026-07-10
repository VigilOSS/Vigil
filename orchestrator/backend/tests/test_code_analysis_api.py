from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Event

import pytest

from app import db as db_module
from app.services import code_analysis


def write_engagement(engagements_dir: Path, key: str) -> Path:
    engagement_dir = engagements_dir / key
    (engagement_dir / "sessions" / "session-a" / "proposals").mkdir(parents=True, exist_ok=True)
    (engagement_dir / "engagement.json").write_text(
        json.dumps(
            {
                "key": key,
                "target": "https://example.com",
                "hostname": "example.com",
                "created_at": "2026-03-30T12:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    (engagement_dir / "scope.json").write_text(
        json.dumps(
            {
                "hostname": "example.com",
                "scope_mode": "host_only",
                "scope_hosts": ["example.com"],
                "scope": ["example.com"],
                "out_of_scope_hosts": [],
                "exploit_policy": "selected",
                "exploit_review_state": "approved",
                "approved_targets": [],
                "status": "in_progress",
                "current_phase": "code-analysis",
            }
        ),
        encoding="utf-8",
    )
    (engagement_dir / "log.md").write_text("# Engagement Log\n", encoding="utf-8")
    (engagement_dir / "findings.md").write_text("# Findings\n", encoding="utf-8")
    (engagement_dir / "sessions" / "index.json").write_text("[]", encoding="utf-8")
    return engagement_dir


def _repo_payload(repo_key: str, repo_path: str) -> dict[str, object]:
    return {
        "repo_key": repo_key,
        "name": repo_key,
        "language": "python",
        "repo_path": repo_path,
        "total_files": 2,
        "analyzable_files": 2,
        "total_loc": 120,
        "commit_hash": "abc123",
        "branch": "main",
        "git_churn": {},
    }


def _create_repo(client, engagement_key: str, repo_key: str = "demo-repo") -> dict[str, object]:
    base = f"/engagements/{engagement_key}/assessment/code"
    started = client.post(
        f"{base}/repos/refresh/start",
        json=_repo_payload(repo_key, f"/tmp/{repo_key}"),
    )
    assert started.status_code == 201, started.text
    refresh = started.json()
    committed = client.post(
        f"{base}/repos/{refresh['repo_id']}/refresh/commit",
        json={"refresh_token": refresh["refresh_token"], "manifest_complete": True},
    )
    assert committed.status_code == 200, committed.text
    response = client.get(f"{base}/repos/{refresh['repo_id']}")
    assert response.status_code == 200, response.text
    return response.json()


def _create_root_finding(client, engagement_key: str, slug: str, *, source_name: str = "code-vuln-hunter") -> None:
    response = client.post(
        f"/engagements/{engagement_key}/assessment/findings",
        json={
            "slug": slug,
            "title": f"Root finding {slug}",
            "severity": "medium",
            "workflow_status": "active",
            "verification_state": "unreviewed",
            "verification_disposition": "none",
            "defect_family": "root-cause",
            "root_cause_key": slug.lower(),
            "auth_context": "anonymous",
            "canonical_location": f"https://example.com/root/{slug}",
            "summary": "Root finding for canonical variant link tests.",
            "evidence_ref": "findings.md",
            "notes": "",
            "source_name": source_name,
            "details": {"evidence": "root"},
            "provenance": {"agent_name": source_name},
            "links": [],
        },
    )
    assert response.status_code == 201, response.text


def _create_files(client, engagement_key: str, repo_id: int) -> list[dict[str, object]]:
    base = f"/engagements/{engagement_key}/assessment/code"
    repo_response = client.get(f"{base}/repos/{repo_id}")
    assert repo_response.status_code == 200, repo_response.text
    repo = repo_response.json()
    started = client.post(
        f"{base}/repos/refresh/start",
        json=_repo_payload(str(repo["repo_key"]), str(repo["repo_path"])),
    )
    assert started.status_code == 201, started.text
    refresh_token = started.json()["refresh_token"]
    response = client.post(
        f"{base}/repos/{repo_id}/refresh/files",
        json={
            "refresh_token": refresh_token,
            "files": [
                {
                    "file_path": "src/parser.py",
                    "language": "python",
                    "loc": 80,
                    "file_hash": "hash-a",
                    "header_snippet": "def parse(data):\n    return data\n",
                    "git_churn_score": 4,
                    "has_past_cve_fix": False,
                },
                {
                    "file_path": "src/helpers.py",
                    "language": "python",
                    "loc": 40,
                    "file_hash": "hash-b",
                    "header_snippet": "def helper(value):\n    return value\n",
                    "git_churn_score": 2,
                    "has_past_cve_fix": False,
                },
            ],
        },
    )
    assert response.status_code == 200, response.text
    committed = client.post(
        f"{base}/repos/{repo_id}/refresh/commit",
        json={"refresh_token": refresh_token, "manifest_complete": True},
    )
    assert committed.status_code == 200, committed.text

    files_response = client.get(
        f"/engagements/{engagement_key}/assessment/code/files?repo_id={repo_id}&limit=20"
    )
    assert files_response.status_code == 200
    return files_response.json()


def _refresh_repo_files(
    client,
    engagement_key: str,
    repo_id: int,
    files: list[dict[str, object]],
) -> list[dict[str, object]]:
    base = f"/engagements/{engagement_key}/assessment/code"
    repo = client.get(f"{base}/repos/{repo_id}").json()
    started = client.post(
        f"{base}/repos/refresh/start",
        json=_repo_payload(str(repo["repo_key"]), str(repo["repo_path"])),
    )
    assert started.status_code == 201, started.text
    token = started.json()["refresh_token"]
    if files:
        staged = client.post(
            f"{base}/repos/{repo_id}/refresh/files",
            json={"refresh_token": token, "files": files},
        )
        assert staged.status_code == 200, staged.text
    committed = client.post(
        f"{base}/repos/{repo_id}/refresh/commit",
        json={"refresh_token": token, "manifest_complete": True},
    )
    assert committed.status_code == 200, committed.text
    return client.get(f"{base}/files?repo_id={repo_id}&limit=10000").json()


def _append_repo_files(
    client,
    engagement_key: str,
    repo_id: int,
    additions: list[dict[str, object]],
) -> list[dict[str, object]]:
    base = f"/engagements/{engagement_key}/assessment/code"
    current = client.get(f"{base}/files?repo_id={repo_id}&limit=10000").json()
    fields = {
        "file_path", "language", "loc", "file_hash", "header_snippet",
        "git_churn_score", "has_past_cve_fix",
    }
    manifest = [{key: row[key] for key in fields} for row in current]
    manifest.extend(additions)
    return _refresh_repo_files(client, engagement_key, repo_id, manifest)


def _classify_file(
    client,
    engagement_key: str,
    file_id: int,
    classification: str,
    analysis_priority: int,
) -> None:
    response = client.post(
        f"/engagements/{engagement_key}/assessment/code/files/bulk-classify",
        json={
            "classifications": [
                {
                    "file_id": file_id,
                    "classification": classification,
                    "role": "parser" if classification != "low" else "helper",
                    "slot_types": ["NETWORK-INPUT"] if classification != "low" else [],
                    "analysis_priority": analysis_priority,
                }
            ]
        },
    )
    assert response.status_code == 200


def _claim_file_for_analysis(
    client,
    engagement_key: str,
    file_id: int,
    *,
    priority: int = 90,
    agent_name: str = "code-vuln-hunter",
) -> dict[str, object]:
    queue_response = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue",
        json={"items": [{"file_id": file_id, "priority": priority}]},
    )
    assert queue_response.status_code == 201
    claimed = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/fetch",
        json={"limit": 1, "agent_name": agent_name},
    )
    assert claimed.status_code == 200
    queue_item = claimed.json()[0]
    assert queue_item["file_id"] == file_id
    return queue_item


def _owned(queue_item: dict[str, object], **payload: object) -> dict[str, object]:
    """Build an explicit lease-owned mutation payload."""
    return {
        **payload,
        "agent_name": queue_item["assigned_agent"],
        "lease_token": queue_item["lease_token"],
    }


def _seed_reviewed_parser(client, isolate_settings, engagement_key: str):
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key=f"{engagement_key}-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser = next(row for row in files if row["file_path"] == "src/parser.py")
    patched = client.patch(
        f"/engagements/{engagement_key}/assessment/code/files/{parser['id']}",
        json={
            "analysis_depth": "deep",
            "variant_check_status": "done",
            "notes": "source review notes",
            "total_functions": 7,
            "total_entry_points": 2,
            "total_sinks": 3,
            "total_exports": 4,
        },
    )
    assert patched.status_code == 200, patched.text
    _classify_file(client, engagement_key, int(parser["id"]), "high", 83)
    queued = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue",
        json={
            "items": [
                {
                    "file_id": parser["id"],
                    "priority": 83,
                    "guidance_hypotheses": ["old metadata hypothesis"],
                }
            ]
        },
    )
    assert queued.status_code == 201, queued.text
    claim = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/fetch",
        json={"limit": 1, "agent_name": "code-vuln-hunter"},
    ).json()[0]
    result = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-results",
        json=_owned(
            claim,
            queue_item_id=claim["id"],
            disposition="clean",
            function_name="parse",
            evidence="source evidence",
        ),
    )
    assert result.status_code == 201, result.text
    done = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/done",
        json=_owned(
            claim,
            item_ids=[claim["id"]],
            disposition="clean",
            notes="review complete",
            cwe_coverage=_network_input_coverage(default_effort=80),
        ),
    )
    assert done.status_code == 200, done.text
    return repo, client.get(
        f"/engagements/{engagement_key}/assessment/code/files/{parser['id']}"
    ).json(), claim, result.json()


def _refresh_one_file_metadata(client, engagement_key: str, repo_id: int, file_id: int, **changes):
    base = f"/engagements/{engagement_key}/assessment/code"
    current = client.get(f"{base}/files?repo_id={repo_id}&limit=10000").json()
    fields = {
        "file_path", "language", "loc", "file_hash", "header_snippet",
        "git_churn_score", "has_past_cve_fix",
    }
    manifest = []
    for row in current:
        record = {key: row[key] for key in fields}
        if int(row["id"]) == file_id:
            record.update(changes)
        manifest.append(record)
    return _refresh_repo_files(client, engagement_key, repo_id, manifest)


def test_legacy_repo_and_file_create_routes_are_not_public(client, isolate_settings):
    engagement_key = "2026-07-14-code-refresh-only-api"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    base = f"/engagements/{engagement_key}/assessment/code"

    repo_response = client.post(
        f"{base}/repos",
        json=_repo_payload("legacy-route", "/tmp/legacy-route"),
    )
    files_response = client.post(
        f"{base}/files",
        json={"repo_id": 1, "files": []},
    )

    assert repo_response.status_code == 405
    assert files_response.status_code == 405


def test_refresh_start_does_not_promote_a_generation_before_commit(client, isolate_settings):
    engagement_key = "2026-07-14-code-refresh-crash"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    base = f"/engagements/{engagement_key}/assessment/code"
    first = client.post(
        f"{base}/repos/refresh/start",
        json=_repo_payload("crash-repo", "/tmp/crash-repo"),
    ).json()
    committed = client.post(
        f"{base}/repos/{first['repo_id']}/refresh/commit",
        json={"refresh_token": first["refresh_token"], "manifest_complete": True},
    )
    assert committed.status_code == 200

    second = client.post(
        f"{base}/repos/refresh/start",
        json=_repo_payload("crash-repo", "/tmp/crash-repo"),
    )
    assert second.status_code == 201
    repo = client.get(f"{base}/repos/{first['repo_id']}").json()
    assert repo["active_generation"] == 1


def test_legacy_repo_migration_marks_existing_snapshot_as_generation_one(client, isolate_settings):
    engagement_key = "2026-07-14-code-refresh-legacy-migration"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="legacy-generation-repo")
    db_path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    db_module.close_thread_connection()
    with sqlite3.connect(str(db_path)) as connection:
        connection.execute("ALTER TABLE code_repos DROP COLUMN active_generation")
        connection.execute("ALTER TABLE code_repos DROP COLUMN pending_refresh_token")
        connection.execute("ALTER TABLE code_repos DROP COLUMN pending_refresh_json")
        connection.commit()

    db_module.init_db()
    migrated = client.get(
        f"/engagements/{engagement_key}/assessment/code/repos/{repo['id']}"
    )
    assert migrated.status_code == 200, migrated.text
    assert migrated.json()["active_generation"] == 1


def test_generation_zero_repo_is_hidden_from_direct_authoritative_endpoints(client, isolate_settings):
    engagement_key = "2026-07-14-code-refresh-generation-zero-hidden"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    base = f"/engagements/{engagement_key}/assessment/code"
    first = client.post(
        f"{base}/repos/refresh/start",
        json=_repo_payload("hidden-repo", "/tmp/hidden-repo"),
    ).json()

    assert client.get(f"{base}/repos").json() == []
    assert client.get(f"{base}/repos/{first['repo_id']}").status_code == 404
    assert client.patch(
        f"{base}/repos/{first['repo_id']}", json={"analysis_status": "analyzed"}
    ).status_code == 404
    assert client.get(f"{base}/coverage?repo_id={first['repo_id']}").status_code == 404
    db_path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    with sqlite3.connect(str(db_path)) as connection:
        connection.execute(
            "UPDATE code_repos SET pending_refresh_token = '' WHERE id = ?",
            (first["repo_id"],),
        )
        connection.commit()
    assert client.get(f"{base}/repos").json() == []

    second = client.post(
        f"{base}/repos/refresh/start",
        json=_repo_payload("hidden-repo", "/tmp/hidden-repo"),
    )
    assert second.status_code == 201, second.text
    stale_stage = client.post(
        f"{base}/repos/{first['repo_id']}/refresh/files",
        json={
            "refresh_token": first["refresh_token"],
            "files": [{"file_path": "stale.py", "language": "python", "loc": 1, "file_hash": "old"}],
        },
    )
    assert stale_stage.status_code == 409
    assert client.get(f"{base}/repos").json() == []
    assert client.get(f"{base}/repos/{first['repo_id']}").status_code == 404
    assert client.get(f"{base}/coverage?repo_id={first['repo_id']}").status_code == 404

    second_payload = second.json()
    committed = client.post(
        f"{base}/repos/{first['repo_id']}/refresh/commit",
        json={"refresh_token": second_payload["refresh_token"], "manifest_complete": True},
    )
    assert committed.status_code == 200, committed.text
    published = client.get(f"{base}/repos/{first['repo_id']}")
    assert published.status_code == 200
    assert published.json()["active_generation"] == 1


def test_generation_zero_repo_children_are_hidden_and_immutable_across_public_api(
    client, isolate_settings
):
    engagement_key = "2026-07-14-code-refresh-generation-zero-children"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    base = f"/engagements/{engagement_key}/assessment/code"
    refresh = client.post(
        f"{base}/repos/refresh/start",
        json=_repo_payload("hidden-child-repo", "/tmp/hidden-child-repo"),
    ).json()
    repo_id = int(refresh["repo_id"])
    db_path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    with sqlite3.connect(str(db_path)) as connection:
        engagement_id = int(
            connection.execute(
                "SELECT id FROM engagements WHERE key = ?", (engagement_key,)
            ).fetchone()[0]
        )
        module_id = int(
            connection.execute(
                """
                INSERT INTO code_modules (engagement_id, repo_id, module_key, name)
                VALUES (?, ?, 'hidden-module', 'Hidden module')
                RETURNING id
                """,
                (engagement_id, repo_id),
            ).fetchone()[0]
        )
        hidden_file_id = int(
            connection.execute(
                """
                INSERT INTO code_files (
                    engagement_id, repo_id, module_id, file_path, language, loc,
                    classification, role, slot_types_json, analysis_priority,
                    analysis_status, total_functions
                )
                VALUES (?, ?, ?, 'src/hidden.py', 'python', 20, 'critical', 'parser',
                        '["NETWORK-INPUT"]', 90, 'analyzed', 2)
                RETURNING id
                """,
                (engagement_id, repo_id, module_id),
            ).fetchone()[0]
        )
        requeue_file_id = int(
            connection.execute(
                """
                INSERT INTO code_files (
                    engagement_id, repo_id, file_path, language, loc, analysis_status
                )
                VALUES (?, ?, 'src/requeue.py', 'python', 10, 'classified')
                RETURNING id
                """,
                (engagement_id, repo_id),
            ).fetchone()[0]
        )

        def insert_queue(status_name: str, suffix: str, *, stale: bool = False) -> int:
            return int(
                connection.execute(
                    """
                    INSERT INTO code_analysis_queue (
                        engagement_id, file_id, status, assigned_agent, lease_token,
                        consumed_at, last_heartbeat_at, batch_theme
                    )
                    VALUES (?, ?, ?, 'hidden-agent', ?, ?, ?, ?)
                    RETURNING id
                    """,
                    (
                        engagement_id,
                        hidden_file_id,
                        status_name,
                        f"hidden-lease-{suffix}",
                        "2020-01-01T00:00:00+00:00" if stale else None,
                        "2020-01-01T00:00:00+00:00" if stale else None,
                        suffix,
                    ),
                ).fetchone()[0]
            )

        pending_id = insert_queue("pending", "pending")
        complete_id = insert_queue("processing", "complete")
        error_transition_id = insert_queue("processing", "error-transition")
        needs_transition_id = insert_queue("processing", "needs-transition")
        heartbeat_id = insert_queue("processing", "heartbeat")
        result_queue_id = insert_queue("processing", "result")
        stale_id = insert_queue("processing", "stale", stale=True)
        retry_error_id = insert_queue("error", "retry-error")
        retry_context_id = insert_queue("needs_context", "retry-context")
        result_id = int(
            connection.execute(
                """
                INSERT INTO code_analysis_results (
                    engagement_id, queue_item_id, file_id, agent_name, disposition,
                    evidence, lease_token, result_fingerprint
                )
                VALUES (?, ?, ?, 'hidden-agent', 'clean', 'hidden evidence',
                        'hidden-lease-result', 'hidden-result')
                RETURNING id
                """,
                (engagement_id, result_queue_id, hidden_file_id),
            ).fetchone()[0]
        )
        trigger_id = int(
            connection.execute(
                """
                INSERT INTO code_analysis_triggers (
                    engagement_id, source_queue_item_id, source_file_id,
                    target_file_id, target_file_path, vuln_class, reason
                )
                VALUES (?, ?, ?, ?, 'src/requeue.py', 'ssrf', 'hidden trigger')
                RETURNING id
                """,
                (engagement_id, pending_id, hidden_file_id, requeue_file_id),
            ).fetchone()[0]
        )
        connection.commit()

    # Engagement-wide readers must project only children of published repos.
    assert client.get(f"{base}/files").json() == []
    assert client.get(f"{base}/files/{hidden_file_id}").status_code == 404
    assert client.get(f"{base}/modules").json() == []
    assert client.get(f"{base}/analysis-queue/stats").json() == {
        "pending": 0,
        "processing": 0,
        "done": 0,
        "error": 0,
        "needs_context": 0,
        "total": 0,
    }
    assert client.post(
        f"{base}/analysis-queue/fetch",
        json={"limit": 100, "agent_name": "public-agent"},
    ).json() == []
    assert client.get(f"{base}/analysis-results?include_superseded=true").json() == []
    assert client.get(f"{base}/triggers").json() == []
    summary = client.get(f"{base}/coverage").json()
    assert summary["total_files"] == 0
    assert summary["confidence"]["active_queue_items"] == 0
    assert summary["confidence"]["unresolved_needs_context"] == 0
    assert summary["trigger_summary"]["pending"] == 0
    assert client.get(f"{base}/coverage?detail=cwe").json()["files"] == []

    # ID-addressed writes return not-found; engagement-wide writes ignore the
    # unpublished children rather than changing their durable state.
    not_found_responses = [
        client.post(
            f"{base}/files/bulk-classify",
            json={"classifications": [{
                "file_id": hidden_file_id,
                "classification": "low",
                "analysis_priority": 1,
            }]},
        ),
        client.patch(f"{base}/files/{hidden_file_id}", json={"notes": "mutated"}),
        client.post(
            f"{base}/files/bulk-structural-metadata",
            json={"updates": [{
                "file_id": hidden_file_id,
                "total_functions": 99,
                "total_entry_points": 0,
                "total_sinks": 0,
                "total_exports": 0,
            }]},
        ),
        client.post(
            f"{base}/modules",
            json={"repo_id": repo_id, "modules": [{"module_key": "x", "name": "X"}]},
        ),
        client.post(
            f"{base}/analysis-queue",
            json={"items": [{"file_id": hidden_file_id}]},
        ),
        client.post(
            f"{base}/analysis-queue/done",
            json={
                "item_ids": [complete_id],
                "agent_name": "hidden-agent",
                "lease_token": "hidden-lease-complete",
                "disposition": "skipped",
                "skip_reason": "generated-code",
            },
        ),
        client.post(
            f"{base}/analysis-queue/error",
            json={
                "item_ids": [error_transition_id],
                "agent_name": "hidden-agent",
                "lease_token": "hidden-lease-error-transition",
            },
        ),
        client.post(
            f"{base}/analysis-queue/needs-context",
            json={
                "item_ids": [needs_transition_id],
                "agent_name": "hidden-agent",
                "lease_token": "hidden-lease-needs-transition",
                "expansion_request": {"reason": "hidden"},
            },
        ),
        client.post(
            f"{base}/analysis-queue/heartbeat",
            json={
                "item_id": heartbeat_id,
                "agent_name": "hidden-agent",
                "lease_token": "hidden-lease-heartbeat",
            },
        ),
        client.post(
            f"{base}/analysis-queue/retry-error",
            json={"item_ids": [retry_error_id], "reason": "hidden"},
        ),
        client.post(
            f"{base}/analysis-queue/retry-needs-context",
            json={"item_ids": [retry_context_id], "reason": "hidden"},
        ),
        client.post(
            f"{base}/analysis-results",
            json={
                "queue_item_id": result_queue_id,
                "agent_name": "hidden-agent",
                "lease_token": "hidden-lease-result",
                "disposition": "clean",
            },
        ),
    ]
    assert [response.status_code for response in not_found_responses] == [404] * len(
        not_found_responses
    )

    reset = client.post(f"{base}/analysis-queue/reset-stale", json={"minutes": 1})
    assert reset.status_code == 200
    assert reset.json() == {"reset": 0}
    requeue = client.post(
        f"{base}/analysis-queue/requeue",
        json={"items": [{"file_id": requeue_file_id}]},
    )
    assert requeue.status_code == 201
    assert requeue.json()["inserted"] == 0
    assert requeue.json()["not_found"] == [str(requeue_file_id)]
    resolved = client.post(
        f"{base}/triggers/resolve",
        json={
            "items": [{"trigger_id": trigger_id}],
            "resolution_status": "not_applicable",
            "resolution_note": "must remain hidden",
        },
    )
    assert resolved.status_code == 200
    assert resolved.json()["resolved"] == 0

    with sqlite3.connect(str(db_path)) as connection:
        file_state = connection.execute(
            "SELECT classification, notes, total_functions FROM code_files WHERE id = ?",
            (hidden_file_id,),
        ).fetchone()
        queue_states = dict(
            connection.execute(
                "SELECT id, status FROM code_analysis_queue WHERE engagement_id = ?",
                (engagement_id,),
            ).fetchall()
        )
        result_count = int(
            connection.execute(
                "SELECT COUNT(*) FROM code_analysis_results WHERE engagement_id = ?",
                (engagement_id,),
            ).fetchone()[0]
        )
        trigger_status = connection.execute(
            "SELECT status FROM code_analysis_triggers WHERE id = ?", (trigger_id,)
        ).fetchone()[0]
    assert file_state == ("critical", "", 2)
    assert queue_states[pending_id] == "pending"
    assert queue_states[complete_id] == "processing"
    assert queue_states[stale_id] == "processing"
    assert result_count == 1
    assert result_id > 0
    assert trigger_status == "pending"


def test_staging_and_refresh_replacement_serialize_without_leaving_stale_rows(
    client, isolate_settings, monkeypatch
):
    engagement_key = "2026-07-14-code-refresh-stage-race"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    base = f"/engagements/{engagement_key}/assessment/code"
    first = client.post(
        f"{base}/repos/refresh/start",
        json=_repo_payload("stage-race-repo", "/tmp/stage-race-repo"),
    ).json()
    stage_read = Event()
    allow_stage_write = Event()
    replacement_done = Event()
    original_get_repo_row = code_analysis._get_repo_row_raw

    def pause_after_stage_token_read(connection, engagement_id, repo_id):
        row = original_get_repo_row(connection, engagement_id, repo_id)
        stage_read.set()
        assert allow_stage_write.wait(2)
        return row

    monkeypatch.setattr(code_analysis, "_get_repo_row_raw", pause_after_stage_token_read)

    def stage_old_token():
        return client.post(
            f"{base}/repos/{first['repo_id']}/refresh/files",
            json={
                "refresh_token": first["refresh_token"],
                "files": [{"file_path": "stale.py", "language": "python", "loc": 1, "file_hash": "old"}],
            },
        )

    def replace_refresh():
        response = client.post(
            f"{base}/repos/refresh/start",
            json=_repo_payload("stage-race-repo", "/tmp/stage-race-repo"),
        )
        replacement_done.set()
        return response

    with ThreadPoolExecutor(max_workers=2) as pool:
        staged_future = pool.submit(stage_old_token)
        assert stage_read.wait(2)
        replacement_future = pool.submit(replace_refresh)
        replacement_finished_before_stage = replacement_done.wait(0.25)
        allow_stage_write.set()
        staged = staged_future.result(timeout=3)
        replacement = replacement_future.result(timeout=3)

    assert replacement.status_code == 201, replacement.text
    if replacement_finished_before_stage:
        assert staged.status_code == 409
    db_path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    with sqlite3.connect(str(db_path)) as connection:
        stale_count = connection.execute(
            "SELECT COUNT(*) FROM code_ingest_staging WHERE refresh_token = ?",
            (first["refresh_token"],),
        ).fetchone()[0]
    assert stale_count == 0


def test_analysis_result_list_hides_superseded_rows_by_default(client, isolate_settings):
    engagement_key = "2026-07-14-code-results-current-only"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="results-current-repo")
    parser_file = next(
        row for row in _create_files(client, engagement_key, int(repo["id"]))
        if row["file_path"] == "src/parser.py"
    )
    _classify_file(client, engagement_key, int(parser_file["id"]), "critical", 100)
    claim = _claim_file_for_analysis(client, engagement_key, int(parser_file["id"]))
    created = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-results",
        json=_owned(
            claim,
            queue_item_id=claim["id"],
            disposition="clean",
            function_name="parse",
            evidence="reviewed",
        ),
    )
    assert created.status_code == 201, created.text
    db_path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    with sqlite3.connect(str(db_path)) as connection:
        connection.execute(
            "UPDATE code_analysis_results SET superseded_at = CURRENT_TIMESTAMP WHERE id = ?",
            (created.json()["id"],),
        )
        connection.commit()

    current = client.get(
        f"/engagements/{engagement_key}/assessment/code/analysis-results"
    )
    historical = client.get(
        f"/engagements/{engagement_key}/assessment/code/analysis-results?include_superseded=true"
    )
    assert current.json() == []
    assert [row["id"] for row in historical.json()] == [created.json()["id"]]


def test_changed_file_refresh_clears_all_analysis_metadata(client, isolate_settings):
    engagement_key = "2026-07-14-code-refresh-clears-analysis"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="changed-metadata-repo")
    parser_file = next(
        row for row in _create_files(client, engagement_key, int(repo["id"]))
        if row["file_path"] == "src/parser.py"
    )
    patched = client.patch(
        f"/engagements/{engagement_key}/assessment/code/files/{parser_file['id']}",
        json={
            "classification": "low",
            "role": "parser",
            "analysis_priority": 77,
            "analysis_status": "done",
            "analysis_depth": "deep",
            "skip_reason": "generated-code",
            "variant_check_status": "done",
            "notes": "old analysis",
            "total_functions": 4,
            "total_entry_points": 2,
            "total_sinks": 1,
            "total_exports": 3,
        },
    )
    assert patched.status_code == 200, patched.text
    base = f"/engagements/{engagement_key}/assessment/code"
    started = client.post(
        f"{base}/repos/refresh/start",
        json=_repo_payload("changed-metadata-repo", "/tmp/changed-metadata-repo"),
    ).json()
    staged = client.post(
        f"{base}/repos/{repo['id']}/refresh/files",
        json={
            "refresh_token": started["refresh_token"],
            "files": [
                {"file_path": "src/parser.py", "language": "python", "loc": 81, "file_hash": "changed"},
                {"file_path": "src/helpers.py", "language": "python", "loc": 40, "file_hash": "hash-b"},
            ],
        },
    )
    assert staged.status_code == 200, staged.text
    assert client.post(
        f"{base}/repos/{repo['id']}/refresh/commit",
        json={"refresh_token": started["refresh_token"], "manifest_complete": True},
    ).status_code == 200

    refreshed = client.get(f"{base}/files/{parser_file['id']}").json()
    expected = {
        "classification": "unclassified",
        "role": "",
        "analysis_priority": 0,
        "analysis_status": "pending",
        "analysis_depth": "none",
        "skip_reason": "",
        "variant_check_status": "pending",
        "notes": "",
        "total_functions": 0,
        "total_entry_points": 0,
        "total_sinks": 0,
        "total_exports": 0,
    }
    assert {key: refreshed[key] for key in expected} == expected


@pytest.mark.parametrize(
    "metadata_changes",
    [
        pytest.param({"language": "ruby"}, id="language"),
        pytest.param({"loc": 81}, id="loc"),
        pytest.param(
            {"loc": 81, "header_snippet": "import changed", "has_past_cve_fix": True},
            id="strongest-combination",
        ),
    ],
)
def test_same_hash_language_or_loc_change_uses_full_invalidation(
    client, isolate_settings, metadata_changes
):
    engagement_key = "2026-07-14-code-refresh-metadata-full-" + next(iter(metadata_changes))
    repo, parser, _claim, _result = _seed_reviewed_parser(
        client, isolate_settings, engagement_key
    )
    refreshed = _refresh_one_file_metadata(
        client,
        engagement_key,
        int(repo["id"]),
        int(parser["id"]),
        **metadata_changes,
    )
    current = next(row for row in refreshed if row["id"] == parser["id"])
    assert current["id"] == parser["id"]
    assert current["classification"] == "unclassified"
    assert current["role"] == ""
    assert current["slot_types"] == []
    assert current["analysis_priority"] == 0
    assert current["analysis_depth"] == "none"
    assert current["variant_check_status"] == "pending"
    assert current["notes"] == ""
    assert current["total_functions"] == 0
    db_path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    with sqlite3.connect(str(db_path)) as connection:
        queue_count = connection.execute(
            "SELECT COUNT(*) FROM code_analysis_queue WHERE file_id = ?", (parser["id"],)
        ).fetchone()[0]
        result_count = connection.execute(
            "SELECT COUNT(*) FROM code_analysis_results WHERE file_id = ?", (parser["id"],)
        ).fetchone()[0]
    assert queue_count == 0
    assert result_count == 0


def test_same_hash_header_change_reopens_architecture_review_and_keeps_history(
    client, isolate_settings
):
    engagement_key = "2026-07-14-code-refresh-metadata-header"
    repo, parser, claim, result = _seed_reviewed_parser(client, isolate_settings, engagement_key)
    refreshed = _refresh_one_file_metadata(
        client,
        engagement_key,
        int(repo["id"]),
        int(parser["id"]),
        header_snippet="from changed import boundary",
    )
    current = next(row for row in refreshed if row["id"] == parser["id"])
    assert current["classification"] == "unclassified"
    assert current["role"] == ""
    assert current["slot_types"] == []
    assert current["analysis_priority"] == 0
    assert current["analysis_depth"] == "deep"
    assert current["notes"] == "source review notes"
    assert current["total_functions"] == 7
    base = f"/engagements/{engagement_key}/assessment/code"
    assert client.get(f"{base}/analysis-results?file_id={parser['id']}").json() == []
    history = client.get(
        f"{base}/analysis-results?file_id={parser['id']}&include_superseded=true"
    ).json()
    assert [row["id"] for row in history] == [result["id"]]
    assert history[0]["superseded_at"]
    db_path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    with sqlite3.connect(str(db_path)) as connection:
        rows = connection.execute(
            """
            SELECT id, status, priority, guidance_hypotheses_json
            FROM code_analysis_queue WHERE file_id = ? ORDER BY id
            """,
            (parser["id"],),
        ).fetchall()
    assert rows == [(claim["id"], "done", 83, "[]"), (claim["id"] + 1, "pending", 83, "[]")]


def test_same_hash_risk_metadata_change_reopens_review_at_prior_priority(
    client, isolate_settings
):
    engagement_key = "2026-07-14-code-refresh-metadata-risk"
    repo, parser, claim, result = _seed_reviewed_parser(client, isolate_settings, engagement_key)
    db_path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    with sqlite3.connect(str(db_path)) as connection:
        engagement_id = int(
            connection.execute(
                "SELECT engagement_id FROM code_files WHERE id = ?", (parser["id"],)
            ).fetchone()[0]
        )
        source_file_id = int(
            connection.execute(
                """
                SELECT id FROM code_files
                WHERE engagement_id = ? AND repo_id = ? AND id != ?
                ORDER BY id LIMIT 1
                """,
                (engagement_id, repo["id"], parser["id"]),
            ).fetchone()[0]
        )
        resolved_trigger_id = int(
            connection.execute(
                """
                INSERT INTO code_analysis_triggers (
                    engagement_id, source_file_id, target_file_id, target_file_path,
                    vuln_class, reason, status, resolved_queue_item_id
                ) VALUES (?, ?, ?, ?, 'ssrf', 'reanalyze target', 'resolved', ?)
                RETURNING id
                """,
                (
                    engagement_id,
                    source_file_id,
                    parser["id"],
                    parser["file_path"],
                    claim["id"],
                ),
            ).fetchone()[0]
        )
        accepted_gap_trigger_id = int(
            connection.execute(
                """
                INSERT INTO code_analysis_triggers (
                    engagement_id, source_file_id, target_file_id, target_file_path,
                    vuln_class, reason, status, resolved_queue_item_id, resolution_note
                ) VALUES (?, ?, ?, ?, 'path-traversal', 'accepted gap',
                          'not_applicable', ?, 'manual disposition')
                RETURNING id
                """,
                (
                    engagement_id,
                    source_file_id,
                    parser["id"],
                    parser["file_path"],
                    claim["id"],
                ),
            ).fetchone()[0]
        )
        connection.commit()
    refreshed = _refresh_one_file_metadata(
        client,
        engagement_key,
        int(repo["id"]),
        int(parser["id"]),
        git_churn_score=99,
        has_past_cve_fix=True,
    )
    current = next(row for row in refreshed if row["id"] == parser["id"])
    assert current["classification"] == "unclassified"
    assert current["analysis_priority"] == 0
    assert current["role"] == "parser"
    assert current["slot_types"] == ["NETWORK-INPUT"]
    assert current["analysis_depth"] == "deep"
    assert current["notes"] == "source review notes"
    base = f"/engagements/{engagement_key}/assessment/code"
    assert client.get(f"{base}/analysis-results?file_id={parser['id']}").json() == []
    history = client.get(
        f"{base}/analysis-results?file_id={parser['id']}&include_superseded=true"
    ).json()
    assert [row["id"] for row in history] == [result["id"]]
    assert history[0]["superseded_at"]
    with sqlite3.connect(str(db_path)) as connection:
        rows = connection.execute(
            """
            SELECT id, status, priority, guidance_hypotheses_json
            FROM code_analysis_queue WHERE file_id = ? ORDER BY id
            """,
            (parser["id"],),
        ).fetchall()
        trigger_rows = connection.execute(
            """
            SELECT id, status, resolved_queue_item_id, resolution_note
            FROM code_analysis_triggers WHERE id IN (?, ?) ORDER BY id
            """,
            (resolved_trigger_id, accepted_gap_trigger_id),
        ).fetchall()
    assert rows == [(claim["id"], "done", 83, "[]"), (claim["id"] + 1, "pending", 83, "[]")]
    assert trigger_rows == [
        (resolved_trigger_id, "queued", None, ""),
        (accepted_gap_trigger_id, "not_applicable", None, "manual disposition"),
    ]


def test_refresh_preview_reports_same_hash_metadata_changes(client, isolate_settings):
    engagement_key = "2026-07-14-code-refresh-metadata-preview"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="metadata-preview-repo")
    current = _create_files(client, engagement_key, int(repo["id"]))
    manifest = []
    for row in current:
        record = {
            key: row[key]
            for key in {
                "file_path", "language", "loc", "file_hash", "header_snippet",
                "git_churn_score", "has_past_cve_fix",
            }
        }
        if row["file_path"] == "src/parser.py":
            record["git_churn_score"] = 99
        manifest.append(record)
    preview = client.post(
        f"/engagements/{engagement_key}/assessment/code/repos/refresh/preview",
        json={"repo_key": repo["repo_key"], "files": manifest},
    )
    assert preview.status_code == 200, preview.text
    assert preview.json()["changed"] == ["src/parser.py"]
    assert preview.json()["unchanged"] == ["src/helpers.py"]


def test_rename_preserves_file_id_and_invalidates_path_sensitive_analysis(client, isolate_settings):
    engagement_key = "2026-07-14-code-refresh-rename-invalidates"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="rename-invalidate-repo")
    helper = next(
        row for row in _create_files(client, engagement_key, int(repo["id"]))
        if row["file_path"] == "src/helpers.py"
    )
    parser = next(
        row for row in client.get(
            f"/engagements/{engagement_key}/assessment/code/files?repo_id={repo['id']}"
        ).json()
        if row["file_path"] == "src/parser.py"
    )
    _classify_file(client, engagement_key, int(parser["id"]), "critical", 100)
    _classify_file(client, engagement_key, int(helper["id"]), "high", 80)
    parser_claim = _claim_file_for_analysis(client, engagement_key, int(parser["id"]), priority=100)
    parser_result = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-results",
        json=_owned(
            parser_claim,
            queue_item_id=parser_claim["id"],
            disposition="clean",
            function_name="parse",
            evidence="helper call observed",
            cross_file_triggers=[
                {
                    "file_path": "src/helpers.py",
                    "reason": "follow renamed helper",
                    "vuln_class": "web-app-injection",
                }
            ],
        ),
    )
    assert parser_result.status_code == 201, parser_result.text
    claim = _claim_file_for_analysis(client, engagement_key, int(helper["id"]))
    result = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-results",
        json=_owned(
            claim,
            queue_item_id=claim["id"],
            disposition="clean",
            function_name="helper",
            evidence="old path review",
        ),
    )
    assert result.status_code == 201, result.text
    base = f"/engagements/{engagement_key}/assessment/code"
    started = client.post(
        f"{base}/repos/refresh/start",
        json=_repo_payload("rename-invalidate-repo", "/tmp/rename-invalidate-repo"),
    ).json()
    assert client.post(
        f"{base}/repos/{repo['id']}/refresh/files",
        json={
            "refresh_token": started["refresh_token"],
                "files": [
                    {
                        "file_path": "src/parser.py", "language": "python", "loc": 80,
                        "file_hash": "hash-a", "header_snippet": "def parse(data):\n    return data\n",
                        "git_churn_score": 4, "has_past_cve_fix": False,
                    },
                    {
                        "file_path": "lib/helpers.rb", "language": "ruby", "loc": 40,
                        "file_hash": "hash-b", "header_snippet": "def helper(value):\n    return value\n",
                        "git_churn_score": 2, "has_past_cve_fix": False,
                    },
                ],
        },
    ).status_code == 200
    assert client.post(
        f"{base}/repos/{repo['id']}/refresh/commit",
        json={"refresh_token": started["refresh_token"], "manifest_complete": True},
    ).status_code == 200

    renamed = client.get(f"{base}/files/{helper['id']}").json()
    assert renamed["id"] == helper["id"]
    assert renamed["file_path"] == "lib/helpers.rb"
    assert renamed["language"] == "ruby"
    assert renamed["classification"] == "unclassified"
    assert renamed["analysis_status"] == "pending"
    assert client.get(
        f"{base}/analysis-results?file_id={helper['id']}&include_superseded=true"
    ).json() == []
    triggers = client.get(f"{base}/triggers").json()
    assert len(triggers) == 1
    assert triggers[0]["target_file_id"] == helper["id"]
    assert triggers[0]["target_file_path"] == "lib/helpers.rb"
    assert triggers[0]["status"] == "pending"


def test_queue_claim_issues_lease_and_heartbeat_requires_ownership(client, isolate_settings):
    engagement_key = "2026-07-14-code-queue-lease"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="lease-repo")
    parser_file = next(
        row for row in _create_files(client, engagement_key, int(repo["id"]))
        if row["file_path"] == "src/parser.py"
    )
    _classify_file(client, engagement_key, int(parser_file["id"]), "critical", 100)
    queue_item = _claim_file_for_analysis(client, engagement_key, int(parser_file["id"]))

    assert queue_item["lease_token"]
    assert queue_item["last_heartbeat_at"]

    rejected = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/heartbeat",
        json={
            "item_id": queue_item["id"],
            "agent_name": "reclaimed-agent",
            "lease_token": queue_item["lease_token"],
        },
    )
    assert rejected.status_code == 409

    accepted = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/heartbeat",
        json={
            "item_id": queue_item["id"],
            "agent_name": "code-vuln-hunter",
            "lease_token": queue_item["lease_token"],
        },
    )
    assert accepted.status_code == 200, accepted.text
    assert accepted.json()["item_id"] == queue_item["id"]


def test_reclaimed_queue_lease_rejects_stale_result_and_closeout(client, isolate_settings):
    engagement_key = "2026-07-14-code-queue-reclaimed-lease"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="reclaimed-lease-repo")
    parser_file = next(
        row for row in _create_files(client, engagement_key, int(repo["id"]))
        if row["file_path"] == "src/parser.py"
    )
    _classify_file(client, engagement_key, int(parser_file["id"]), "critical", 100)
    old_claim = _claim_file_for_analysis(client, engagement_key, int(parser_file["id"]), agent_name="old-agent")
    partial_result = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-results",
        json={
            "queue_item_id": old_claim["id"],
            "file_id": parser_file["id"],
            "agent_name": "old-agent",
            "lease_token": old_claim["lease_token"],
            "function_name": "partial_parse",
            "hypothesis": "partial result before worker loss",
            "evidence": "src/parser.py:1",
            "disposition": "clean",
        },
    )
    assert partial_result.status_code == 201, partial_result.text

    db_path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    with sqlite3.connect(str(db_path)) as connection:
        connection.execute(
            "UPDATE code_analysis_queue SET last_heartbeat_at = ? WHERE id = ?",
            ("2020-01-01T00:00:00Z", old_claim["id"]),
        )
        connection.commit()
    reset = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/reset-stale",
        json={"minutes": 30},
    )
    assert reset.status_code == 200
    with sqlite3.connect(str(db_path)) as connection:
        superseded_at = connection.execute(
            "SELECT superseded_at FROM code_analysis_results WHERE id = ?",
            (partial_result.json()["id"],),
        ).fetchone()[0]
    assert superseded_at
    new_claim = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/fetch",
        json={"limit": 1, "agent_name": "new-agent"},
    ).json()[0]
    assert new_claim["lease_token"] != old_claim["lease_token"]

    stale_result = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-results",
        json={
            "queue_item_id": old_claim["id"],
            "file_id": parser_file["id"],
            "agent_name": "old-agent",
            "lease_token": old_claim["lease_token"],
            "function_name": "parse",
            "hypothesis": "stale",
            "evidence": "stale",
            "disposition": "clean",
        },
    )
    assert stale_result.status_code == 409

    stale_closeout = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/error",
        json={
            "item_ids": [old_claim["id"]],
            "agent_name": "old-agent",
            "lease_token": old_claim["lease_token"],
            "notes": "late closeout",
        },
    )
    assert stale_closeout.status_code == 409


def test_analysis_result_retry_is_idempotent_within_lease(client, isolate_settings):
    engagement_key = "2026-07-14-code-result-idempotency"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="result-idempotency-repo")
    parser_file = next(
        row for row in _create_files(client, engagement_key, int(repo["id"]))
        if row["file_path"] == "src/parser.py"
    )
    _classify_file(client, engagement_key, int(parser_file["id"]), "critical", 100)
    claim = _claim_file_for_analysis(client, engagement_key, int(parser_file["id"]), agent_name="result-agent")
    payload = {
        "queue_item_id": claim["id"],
        "file_id": parser_file["id"],
        "agent_name": "result-agent",
        "lease_token": claim["lease_token"],
        "function_name": "parse",
        "hypothesis": "input reaches parser",
        "evidence": "src/parser.py:1",
        "disposition": "clean",
        "confidence": "high",
    }

    missing_owner = dict(payload)
    missing_owner.pop("agent_name")
    rejected = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-results", json=missing_owner
    )
    assert rejected.status_code == 422

    first = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-results", json=payload
    )
    second = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-results", json=payload
    )
    assert first.status_code == 201, first.text
    assert second.status_code == 201, second.text
    assert second.json()["id"] == first.json()["id"]


def test_needs_context_can_be_recovered_without_stale_coverage_blocker(client, isolate_settings):
    engagement_key = "2026-07-14-code-needs-context-recovery"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="needs-context-recovery-repo")
    parser_file = next(
        row for row in _create_files(client, engagement_key, int(repo["id"]))
        if row["file_path"] == "src/parser.py"
    )
    _classify_file(client, engagement_key, int(parser_file["id"]), "critical", 100)
    claim = _claim_file_for_analysis(client, engagement_key, int(parser_file["id"]), agent_name="context-agent")
    marked = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/needs-context",
        json={
            "item_ids": [claim["id"]],
            "agent_name": "context-agent",
            "lease_token": claim["lease_token"],
            "expansion_request": {"reason": "need caller"},
        },
    )
    assert marked.status_code == 200, marked.text

    recovered = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/retry-needs-context",
        json={"item_ids": [claim["id"]], "reason": "caller context attached"},
    )
    assert recovered.status_code == 200, recovered.text
    assert recovered.json()["retried"] == 1

    stats = client.get(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/stats"
    ).json()
    assert stats["needs_context"] == 0
    assert stats["pending"] == 1


def test_repo_refresh_is_atomic_and_reconciles_changed_deleted_and_renamed_files(client, isolate_settings):
    engagement_key = "2026-07-14-code-refresh"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="refresh-repo")
    original_files = _create_files(client, engagement_key, int(repo["id"]))
    parser = next(row for row in original_files if row["file_path"] == "src/parser.py")
    helper = next(row for row in original_files if row["file_path"] == "src/helpers.py")
    _classify_file(client, engagement_key, int(parser["id"]), "critical", 100)
    _claim_file_for_analysis(client, engagement_key, int(parser["id"]))
    db_path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    with sqlite3.connect(str(db_path)) as connection:
        connection.execute(
            """
            INSERT INTO code_analysis_results (
                engagement_id, queue_item_id, file_id, agent_name, function_name,
                disposition, lease_token, result_fingerprint
            ) SELECT engagement_id, NULL, ?, 'legacy-agent', 'legacy_direct',
                     'clean', '', '' FROM code_repos WHERE id = ?
            """,
            (parser["id"], repo["id"]),
        )
        connection.commit()

    started = client.post(
        f"/engagements/{engagement_key}/assessment/code/repos/refresh/start",
        json={**_repo_payload("refresh-repo", "/tmp/refresh-repo"), "total_files": 3, "analyzable_files": 3},
    )
    assert started.status_code == 201, started.text
    refresh_token = started.json()["refresh_token"]
    staged = client.post(
        f"/engagements/{engagement_key}/assessment/code/repos/{repo['id']}/refresh/files",
        json={
            "refresh_token": refresh_token,
            "files": [
                {"file_path": "src/parser.py", "language": "python", "loc": 81, "file_hash": "hash-a-changed"},
                {"file_path": "src/renamed_helpers.py", "language": "python", "loc": 40, "file_hash": "hash-b"},
                {"file_path": "src/new.py", "language": "python", "loc": 5, "file_hash": "hash-new"},
            ],
        },
    )
    assert staged.status_code == 200, staged.text

    # An interrupted refresh leaves the last committed tree authoritative.
    before_commit = client.get(
        f"/engagements/{engagement_key}/assessment/code/files?repo_id={repo['id']}&limit=20"
    ).json()
    assert {row["file_path"] for row in before_commit} == {"src/parser.py", "src/helpers.py"}
    visible_repos = client.get(
        f"/engagements/{engagement_key}/assessment/code/repos"
    ).json()
    assert [row["repo_key"] for row in visible_repos] == ["refresh-repo"]

    committed = client.post(
        f"/engagements/{engagement_key}/assessment/code/repos/{repo['id']}/refresh/commit",
        json={"refresh_token": refresh_token, "manifest_complete": True},
    )
    assert committed.status_code == 200, committed.text
    assert committed.json()["changed"] == 1
    assert committed.json()["renamed"] == 1
    assert committed.json()["inserted"] == 1
    assert committed.json()["deleted"] == 0

    after = client.get(
        f"/engagements/{engagement_key}/assessment/code/files?repo_id={repo['id']}&limit=20"
    ).json()
    by_path = {row["file_path"]: row for row in after}
    assert set(by_path) == {"src/parser.py", "src/renamed_helpers.py", "src/new.py"}
    assert by_path["src/renamed_helpers.py"]["id"] == helper["id"]
    assert by_path["src/parser.py"]["analysis_status"] == "pending"
    assert by_path["src/parser.py"]["classification"] == "unclassified"

    with sqlite3.connect(str(db_path)) as connection:
        queued = connection.execute(
            "SELECT COUNT(*) FROM code_analysis_queue WHERE file_id = ?", (parser["id"],)
        ).fetchone()[0]
        direct_results = connection.execute(
            "SELECT COUNT(*) FROM code_analysis_results WHERE file_id = ?", (parser["id"],)
        ).fetchone()[0]
    assert queued == 0
    assert direct_results == 0


def test_repo_refresh_complete_empty_manifest_deletes_last_file(client, isolate_settings):
    engagement_key = "2026-07-14-code-refresh-empty"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="refresh-empty-repo")
    _create_files(client, engagement_key, int(repo["id"]))
    started = client.post(
        f"/engagements/{engagement_key}/assessment/code/repos/refresh/start",
        json={**_repo_payload("refresh-empty-repo", "/tmp/refresh-empty-repo"), "total_files": 0, "analyzable_files": 0},
    ).json()

    committed = client.post(
        f"/engagements/{engagement_key}/assessment/code/repos/{repo['id']}/refresh/commit",
        json={"refresh_token": started["refresh_token"], "manifest_complete": True},
    )
    assert committed.status_code == 200, committed.text
    assert committed.json()["deleted"] == 2
    files = client.get(
        f"/engagements/{engagement_key}/assessment/code/files?repo_id={repo['id']}&limit=20"
    )
    assert files.json() == []


def test_interrupted_first_ingest_does_not_publish_generation_zero_repo(client, isolate_settings):
    engagement_key = "2026-07-14-code-refresh-first-ingest"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    base = f"/engagements/{engagement_key}/assessment/code"

    started = client.post(
        f"{base}/repos/refresh/start",
        json={
            **_repo_payload("first-ingest-repo", "/tmp/first-ingest-repo"),
            "total_files": 0,
            "analyzable_files": 0,
        },
    )
    assert started.status_code == 201, started.text

    # Starting a first ingest only creates staging metadata. It must not make an
    # empty generation look like an authoritative source tree after a crash.
    assert client.get(f"{base}/repos").json() == []

    committed = client.post(
        f"{base}/repos/{started.json()['repo_id']}/refresh/commit",
        json={"refresh_token": started.json()["refresh_token"], "manifest_complete": True},
    )
    assert committed.status_code == 200, committed.text
    repos = client.get(f"{base}/repos").json()
    assert [repo["repo_key"] for repo in repos] == ["first-ingest-repo"]
    assert repos[0]["active_generation"] == 1


def test_bulk_classify_rejects_unknown_fields(client, isolate_settings):
    engagement_key = "2026-04-09-code-classify-extra-fields"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="extra-fields-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser_file = next(item for item in files if item["file_path"] == "src/parser.py")

    response = client.post(
        f"/engagements/{engagement_key}/assessment/code/files/bulk-classify",
        json={
            "classifications": [
                {
                    "file_id": parser_file["id"],
                    "classification": "high",
                    "slot_types_json": ["NETWORK-INPUT"],
                }
            ]
        },
    )

    assert response.status_code == 422
    assert "slot_types_json" in response.text


def test_bulk_classify_rejects_invalid_slot_type(client, isolate_settings):
    engagement_key = "2026-04-09-code-classify-invalid-slot"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="invalid-slot-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser_file = next(item for item in files if item["file_path"] == "src/parser.py")

    response = client.post(
        f"/engagements/{engagement_key}/assessment/code/files/bulk-classify",
        json={
            "classifications": [
                {
                    "file_id": parser_file["id"],
                    "classification": "high",
                    "role": "parser",
                    "slot_types": ["NETWORK_INPUT"],
                }
            ]
        },
    )

    assert response.status_code == 422
    assert "NETWORK_INPUT" in response.text


def test_bulk_classify_rejects_high_without_slot_types(client, isolate_settings):
    engagement_key = "2026-04-09-code-classify-missing-slots"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="missing-slots-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser_file = next(item for item in files if item["file_path"] == "src/parser.py")

    response = client.post(
        f"/engagements/{engagement_key}/assessment/code/files/bulk-classify",
        json={
            "classifications": [
                {
                    "file_id": parser_file["id"],
                    "classification": "high",
                    "role": "parser",
                    "slot_types": [],
                }
            ]
        },
    )

    assert response.status_code == 400
    assert "slot_types" in response.json()["detail"]


def test_applicable_families_include_serialization_and_role_derived_contexts():
    serialized = code_analysis._applicable_families_for_file(
        ["SERIALIZED-DATA"],
        language="python",
        role="deserializer",
    )
    assert "deserialization" in serialized
    assert "algorithmic-dos" in serialized

    crypto = code_analysis._applicable_families_for_file(
        ["NETWORK-INPUT"],
        language="python",
        role="crypto_impl",
    )
    assert "crypto-misuse" in crypto

    auth = code_analysis._applicable_families_for_file(
        ["NETWORK-INPUT"],
        language="python",
        role="auth_handler",
    )
    assert "auth-bypass" in auth
    assert "web-app-auth" in auth

    error_handler = code_analysis._applicable_families_for_file(
        ["NETWORK-INPUT"],
        language="c",
        role="error_handler",
    )
    assert "error-handling" in error_handler
    assert "null-dereference" in error_handler

    allocator = code_analysis._applicable_families_for_file(
        ["NETWORK-INPUT"],
        language="c",
        role="memory_allocator",
    )
    assert "uninitialized-memory" in allocator
    assert "algorithmic-dos" in allocator

    graphql = code_analysis._applicable_families_for_file(
        ["URL-COMPONENT"],
        language="python",
        role="graphql_resolver",
    )
    assert "web-app-data-exposure" in graphql

    llm = code_analysis._applicable_families_for_file(
        ["NETWORK-INPUT"],
        language="python",
        role="llm_orchestrator",
    )
    assert "ai-ml-security" in llm


def _network_input_coverage(
    *,
    default_effort: int,
    overrides: dict[str, dict[str, object]] | None = None,
) -> list[dict[str, object]]:
    families = [
        "web-app-injection",
        "web-app-auth",
        "ssrf",
        "open-redirect",
        "path-traversal",
        "algorithmic-dos",
    ]
    payload: list[dict[str, object]] = []
    for family in families:
        entry: dict[str, object] = {"family": family, "effort": default_effort}
        if overrides and family in overrides:
            entry.update(overrides[family])
        payload.append(entry)
    return payload


def test_queue_fetch_returns_file_direct_work_items(client, isolate_settings):
    engagement_key = "2026-04-04-code-queue"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key)
    repo_patch = client.patch(
        f"/engagements/{engagement_key}/assessment/code/repos/{repo['id']}",
        json={"lsp_config_json": {"languages": {"python": {"available": False}}, "ctags": {"available": True}}},
    )
    assert repo_patch.status_code == 200
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser_file = next(item for item in files if item["file_path"] == "src/parser.py")
    _classify_file(client, engagement_key, int(parser_file["id"]), "critical", 95)

    queue_response = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue",
        json={"items": [{"file_id": parser_file["id"], "priority": 95}]},
    )
    assert queue_response.status_code == 201

    file_after_queue = client.get(
        f"/engagements/{engagement_key}/assessment/code/files/{parser_file['id']}"
    )
    assert file_after_queue.status_code == 200
    assert file_after_queue.json()["analysis_status"] == "queued"

    fetch_response = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/fetch",
        json={"limit": 10, "agent_name": "code-vuln-hunter"},
    )
    assert fetch_response.status_code == 200
    payload = fetch_response.json()
    assert len(payload) == 1

    item = payload[0]
    assert item["status"] == "processing"
    assert item["file"]["id"] == parser_file["id"]
    assert item["file"]["file_path"] == "src/parser.py"
    assert item["repo"]["id"] == repo["id"]
    assert item["repo"]["lsp_config"]["ctags"]["available"] is True
    assert "applicable_vuln_classes" in item
    assert "web-app-injection" in item["applicable_vuln_classes"]
    assert "context" not in item

    file_after_fetch = client.get(
        f"/engagements/{engagement_key}/assessment/code/files/{parser_file['id']}"
    )
    assert file_after_fetch.status_code == 200
    assert file_after_fetch.json()["analysis_status"] in ("queued", "in_progress")


def test_repo_patch_rejects_unknown_fields(client, isolate_settings):
    engagement_key = "2026-04-16-code-repo-patch-unknown"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="repo-patch-unknown")

    response = client.patch(
        f"/engagements/{engagement_key}/assessment/code/repos/{repo['id']}",
        json={"unsupported_field": "value"},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "repo patch does not accept fields: unsupported_field"


def test_queue_fetch_uses_backend_applicable_classes_with_role_and_language_overrides(client, isolate_settings):
    engagement_key = "2026-04-09-code-queue-applicable-vulns"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="queue-applicable-vulns-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser_file = next(item for item in files if item["file_path"] == "src/parser.py")

    classify = client.post(
        f"/engagements/{engagement_key}/assessment/code/files/bulk-classify",
        json={
            "classifications": [
                {
                    "file_id": parser_file["id"],
                    "classification": "critical",
                    "role": "crypto_impl",
                    "language": "c++",
                    "slot_types": ["SERIALIZED-DATA"],
                    "analysis_priority": 95,
                }
            ]
        },
    )
    assert classify.status_code == 200

    queue_response = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue",
        json={"items": [{"file_id": parser_file["id"], "priority": 95}]},
    )
    assert queue_response.status_code == 201

    fetch_response = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/fetch",
        json={"limit": 1, "agent_name": "code-vuln-hunter"},
    )
    assert fetch_response.status_code == 200
    item = fetch_response.json()[0]

    assert item["file"]["language"] == "c++"
    assert "crypto-misuse" in item["applicable_vuln_classes"]
    assert "deserialization" in item["applicable_vuln_classes"]
    assert "buffer-overflow" in item["applicable_vuln_classes"]
    assert "web-app-injection" not in item["applicable_vuln_classes"]


def test_analysis_completion_rolls_up_file_coverage(client, isolate_settings):
    engagement_key = "2026-04-04-code-coverage"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="coverage-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser_file = next(item for item in files if item["file_path"] == "src/parser.py")
    _classify_file(client, engagement_key, int(parser_file["id"]), "critical", 100)

    queue_response = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue",
        json={
            "items": [
                {
                    "file_id": parser_file["id"],
                    "priority": 100,
                }
            ]
        },
    )
    assert queue_response.status_code == 201

    claimed = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/fetch",
        json={"limit": 1, "agent_name": "code-vuln-hunter"},
    )
    queue_item = claimed.json()[0]

    analysis_result = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-results",
        json={
            "queue_item_id": queue_item["id"],
            "file_id": parser_file["id"],
            "agent_name": "code-vuln-hunter",
            "lease_token": queue_item["lease_token"],
            "function_name": "parse_message",
            "hypothesis": "Input is length checked before use.",
            "evidence": "Bounds are enforced before data is copied.",
            "disposition": "clean",
            "confidence": "high",
            "notes": "No exploitable issue found.",
            "audit_metadata": {"cross_ref_usage": {"tool": "lsp", "queries": ["references(parse_message)"]}},
        },
    )
    assert analysis_result.status_code == 201
    assert analysis_result.json()["audit_metadata"]["cross_ref_usage"]["tool"] == "lsp"

    file_before_done = client.get(
        f"/engagements/{engagement_key}/assessment/code/files/{parser_file['id']}"
    )
    assert file_before_done.status_code == 200
    assert file_before_done.json()["analysis_status"] == "in_progress"

    done = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/done",
        json={
            "item_ids": [queue_item["id"]],
            "agent_name": queue_item["assigned_agent"],
            "lease_token": queue_item["lease_token"],
            "disposition": "clean",
            "notes": "Reviewed",
            "cwe_coverage": _network_input_coverage(default_effort=80),
        },
    )
    assert done.status_code == 200
    assert done.json()["updated"] == 1

    file_row = client.get(
        f"/engagements/{engagement_key}/assessment/code/files/{parser_file['id']}"
    )
    assert file_row.status_code == 200
    assert file_row.json()["analysis_status"] == "analyzed"

    coverage = client.get(
        f"/engagements/{engagement_key}/assessment/code/coverage?repo_id={repo['id']}"
    )
    assert coverage.status_code == 200
    payload = coverage.json()
    assert payload["by_classification"]["critical"]["analyzed"] == 1
    assert payload["gate"]["passed"] is True

    activity = client.get(
        f"/engagements/{engagement_key}/activity-entries",
        params={"q": "code-record-analysis"},
    )
    assert activity.status_code == 200, activity.text
    assert any(row["title"] == "code-record-analysis" for row in activity.json()["items"])

    activity = client.get(
        f"/engagements/{engagement_key}/activity-entries",
        params={"q": "code-dispatch"},
    )
    assert activity.status_code == 200, activity.text
    assert any(row["title"] == "code-dispatch done" for row in activity.json()["items"])


def test_coverage_gate_stays_closed_until_queue_items_are_completed(client, isolate_settings):
    engagement_key = "2026-04-04-code-gate"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="gate-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser_file = next(item for item in files if item["file_path"] == "src/parser.py")
    _classify_file(client, engagement_key, int(parser_file["id"]), "critical", 100)

    queue_response = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue",
        json={"items": [{"file_id": parser_file["id"], "priority": 100}]},
    )
    assert queue_response.status_code == 201

    queue_item = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/fetch",
        json={"limit": 1, "agent_name": "code-vuln-hunter"},
    ).json()[0]

    analysis_result = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-results",
        json={
            "queue_item_id": queue_item["id"],
            "file_id": parser_file["id"],
            "agent_name": "code-vuln-hunter",
            "lease_token": queue_item["lease_token"],
            "function_name": "parse_message",
            "hypothesis": "Input is bounded.",
            "evidence": "Reviewed all sinks.",
            "disposition": "clean",
            "confidence": "high",
            "notes": "",
        },
    )
    assert analysis_result.status_code == 201

    coverage_before_done = client.get(
        f"/engagements/{engagement_key}/assessment/code/coverage?repo_id={repo['id']}"
    )
    assert coverage_before_done.status_code == 200
    payload = coverage_before_done.json()
    assert payload["by_classification"]["critical"]["analyzed"] == 0
    assert payload["gate"]["passed"] is False
    assert any("queue items still pending or processing" in reason.lower() for reason in payload["gate"]["reasons"])

    done = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/done",
        json=_owned(
            queue_item,
            item_ids=[queue_item["id"]],
            disposition="clean",
            notes="Reviewed",
        ),
    )
    assert done.status_code == 400
    assert "cwe_coverage is required" in done.json()["detail"]

    done = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/done",
        json={
            "item_ids": [queue_item["id"]],
            "agent_name": queue_item["assigned_agent"],
            "lease_token": queue_item["lease_token"],
            "disposition": "clean",
            "notes": "Reviewed",
            "cwe_coverage": _network_input_coverage(default_effort=80),
        },
    )
    assert done.status_code == 200

    coverage_after_done = client.get(
        f"/engagements/{engagement_key}/assessment/code/coverage?repo_id={repo['id']}"
    )
    assert coverage_after_done.status_code == 200
    assert coverage_after_done.json()["gate"]["passed"] is True


def test_queue_done_skipped_disposition_requires_skip_reason(client, isolate_settings):
    """C50: disposition='skipped' must carry a structured skip_reason; the
    cwe-coverage completeness check is bypassed for skipped items (analyst
    did not analyze)."""
    engagement_key = "2026-04-04-code-skipped"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="skip-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser_file = next(item for item in files if item["file_path"] == "src/parser.py")
    _classify_file(client, engagement_key, int(parser_file["id"]), "critical", 100)

    client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue",
        json={"items": [{"file_id": parser_file["id"], "priority": 100}]},
    )
    queue_item = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/fetch",
        json={"limit": 1, "agent_name": "code-vuln-hunter"},
    ).json()[0]

    # Missing skip_reason → 400
    rejected = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/done",
        json={
            "item_ids": [queue_item["id"]],
            "agent_name": queue_item["assigned_agent"],
            "lease_token": queue_item["lease_token"],
            "disposition": "skipped",
            "notes": "",
            "cwe_coverage": [],
        },
    )
    assert rejected.status_code == 400
    assert "skip_reason is required" in rejected.json()["detail"]

    # With skip_reason → 200 and cwe_coverage completeness check is bypassed
    accepted = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/done",
        json={
            "item_ids": [queue_item["id"]],
            "agent_name": queue_item["assigned_agent"],
            "lease_token": queue_item["lease_token"],
            "disposition": "skipped",
            "notes": "",
            "cwe_coverage": [],
            "skip_reason": "test-fixture",
        },
    )
    assert accepted.status_code == 200


def test_queue_done_rejects_multi_item_completion(client, isolate_settings):
    engagement_key = "2026-04-04-code-done-single-item"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="single-item-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser_file = next(item for item in files if item["file_path"] == "src/parser.py")
    helper_file = next(item for item in files if item["file_path"] == "src/helpers.py")
    _classify_file(client, engagement_key, int(parser_file["id"]), "critical", 100)
    _classify_file(client, engagement_key, int(helper_file["id"]), "high", 80)

    queue_response = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue",
        json={
            "items": [
                {"file_id": parser_file["id"], "priority": 100},
                {"file_id": helper_file["id"], "priority": 80},
            ]
        },
    )
    assert queue_response.status_code == 201

    claimed = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/fetch",
        json={"limit": 2, "agent_name": "code-vuln-hunter"},
    )
    assert claimed.status_code == 200
    queue_items = claimed.json()
    assert len(queue_items) == 2

    done = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/done",
        json={
            "item_ids": [queue_items[0]["id"], queue_items[1]["id"]],
            "disposition": "clean",
            "notes": "Reviewed",
            "cwe_coverage": _network_input_coverage(default_effort=80),
        },
    )
    assert done.status_code == 422


def test_queue_done_requires_processing_state(client, isolate_settings):
    engagement_key = "2026-04-04-code-done-processing-only"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="processing-only-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser_file = next(item for item in files if item["file_path"] == "src/parser.py")
    _classify_file(client, engagement_key, int(parser_file["id"]), "critical", 100)

    queue_response = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue",
        json={"items": [{"file_id": parser_file["id"], "priority": 100}]},
    )
    assert queue_response.status_code == 201

    db_path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    with sqlite3.connect(str(db_path)) as connection:
        queue_item_id = connection.execute(
            "SELECT id FROM code_analysis_queue WHERE file_id = ? ORDER BY id DESC LIMIT 1",
            (parser_file["id"],),
        ).fetchone()[0]

    done = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/done",
        json={
            "item_ids": [queue_item_id],
            "agent_name": "unclaimed-agent",
            "lease_token": "unclaimed-lease",
            "disposition": "clean",
            "notes": "Reviewed",
            "cwe_coverage": _network_input_coverage(default_effort=80),
        },
    )
    assert done.status_code == 409
    assert "unless they are processing" in done.json()["detail"]


def test_analysis_result_requires_processing_queue_item(client, isolate_settings):
    engagement_key = "2026-04-04-analysis-result-processing-only"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="analysis-result-processing-only-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser_file = next(item for item in files if item["file_path"] == "src/parser.py")
    _classify_file(client, engagement_key, int(parser_file["id"]), "critical", 100)

    queue_response = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue",
        json={"items": [{"file_id": parser_file["id"], "priority": 100}]},
    )
    assert queue_response.status_code == 201

    db_path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    with sqlite3.connect(str(db_path)) as connection:
        queue_item_id = connection.execute(
            "SELECT id FROM code_analysis_queue WHERE file_id = ? ORDER BY id DESC LIMIT 1",
            (parser_file["id"],),
        ).fetchone()[0]

    analysis_result = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-results",
        json={
            "queue_item_id": queue_item_id,
            "file_id": parser_file["id"],
            "agent_name": "code-vuln-hunter",
            "lease_token": "unclaimed-lease",
            "function_name": "parse_message",
            "hypothesis": "Input is bounded.",
            "evidence": "Reviewed sinks.",
            "disposition": "clean",
            "confidence": "high",
            "notes": "",
        },
    )
    assert analysis_result.status_code == 409
    assert "unless they are processing" in analysis_result.json()["detail"]


def test_reset_stale_queue_items_parses_iso_consumed_at(client, isolate_settings):
    engagement_key = "2026-04-04-code-reset-stale"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="reset-stale-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser_file = next(item for item in files if item["file_path"] == "src/parser.py")
    _classify_file(client, engagement_key, int(parser_file["id"]), "critical", 100)

    queue_response = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue",
        json={"items": [{"file_id": parser_file["id"], "priority": 100}]},
    )
    assert queue_response.status_code == 201

    claimed = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/fetch",
        json={"limit": 1, "agent_name": "code-vuln-hunter"},
    )
    assert claimed.status_code == 200
    queue_item = claimed.json()[0]

    db_path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    stale_iso = (datetime.now(timezone.utc) - timedelta(minutes=30)).isoformat()
    with sqlite3.connect(str(db_path)) as connection:
        connection.execute(
            "UPDATE code_analysis_queue SET consumed_at = ?, last_heartbeat_at = ? WHERE id = ?",
            (stale_iso, stale_iso, queue_item["id"]),
        )
        connection.commit()

    reset = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/reset-stale",
        json={"minutes": 5},
    )
    assert reset.status_code == 200
    assert reset.json()["reset"] == 1

    claimed_again = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/fetch",
        json={"limit": 1, "agent_name": "queue-reclaimer"},
    )
    assert claimed_again.status_code == 200
    assert claimed_again.json()[0]["id"] == queue_item["id"]


def test_reset_stale_does_not_supersede_results_when_heartbeat_wins_cas(
    client, isolate_settings, monkeypatch
):
    engagement_key = "2026-07-14-code-reset-heartbeat-race"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="reset-heartbeat-repo")
    parser_file = next(
        row for row in _create_files(client, engagement_key, int(repo["id"]))
        if row["file_path"] == "src/parser.py"
    )
    _classify_file(client, engagement_key, int(parser_file["id"]), "critical", 100)
    claim = _claim_file_for_analysis(client, engagement_key, int(parser_file["id"]))
    result = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-results",
        json=_owned(
            claim,
            queue_item_id=claim["id"],
            disposition="clean",
            function_name="parse",
            evidence="reviewed",
        ),
    )
    assert result.status_code == 201, result.text
    db_path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    stale_iso = (datetime.now(timezone.utc) - timedelta(minutes=30)).isoformat()
    with sqlite3.connect(str(db_path)) as connection:
        connection.execute(
            "UPDATE code_analysis_queue SET consumed_at = ?, last_heartbeat_at = ? WHERE id = ?",
            (stale_iso, stale_iso, claim["id"]),
        )
        connection.commit()

    original_get_connection = code_analysis.get_connection

    class CursorProxy:
        def __init__(self, cursor, connection):
            self._cursor = cursor
            self._connection = connection

        def fetchall(self):
            rows = self._cursor.fetchall()
            self._connection.execute(
                "UPDATE code_analysis_queue SET last_heartbeat_at = ? WHERE id = ?",
                (datetime.now(timezone.utc).isoformat(), claim["id"]),
            )
            return rows

    class ConnectionProxy:
        def __init__(self, connection):
            self._connection = connection

        def execute(self, sql, parameters=()):
            cursor = self._connection.execute(sql, parameters)
            if "SELECT id, file_id, lease_token" in sql and "lease_activity_at" in sql:
                return CursorProxy(cursor, self._connection)
            return cursor

    @contextmanager
    def raced_connection():
        with original_get_connection() as connection:
            yield ConnectionProxy(connection)

    monkeypatch.setattr(code_analysis, "get_connection", raced_connection)
    reset = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/reset-stale",
        json={"minutes": 5},
    )
    assert reset.status_code == 200, reset.text
    assert reset.json()["reset"] == 0
    with sqlite3.connect(str(db_path)) as connection:
        queue_status = connection.execute(
            "SELECT status FROM code_analysis_queue WHERE id = ?", (claim["id"],)
        ).fetchone()[0]
        superseded_at = connection.execute(
            "SELECT superseded_at FROM code_analysis_results WHERE id = ?",
            (result.json()["id"],),
        ).fetchone()[0]
    assert queue_status == "processing"
    assert superseded_at is None


def test_retry_error_queue_item_returns_to_pending_with_audit_row(client, isolate_settings):
    """C5.1: a queue item stuck at status='error' has no recovery path via
    `reset_stale_queue_items` (processing-only, time-windowed). `retry-error`
    is the id-scoped recovery: it flips 'error' -> 'pending', clears
    assigned_agent/consumed_at so the item re-enters the fetch rotation, and
    appends a `[retried: <reason>]` breadcrumb to the existing analysis_notes
    rather than overwriting the prior failure context. It also records a
    best-effort `activity_entries` audit row, matching the "queue completion
    appends activity_entries" convention for every other queue mutation."""
    engagement_key = "2026-07-08-code-retry-error"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="retry-error-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser_file = next(item for item in files if item["file_path"] == "src/parser.py")
    _classify_file(client, engagement_key, int(parser_file["id"]), "critical", 100)

    queue_response = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue",
        json={"items": [{"file_id": parser_file["id"], "priority": 100}]},
    )
    assert queue_response.status_code == 201

    claimed = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/fetch",
        json={"limit": 1, "agent_name": "code-vuln-hunter"},
    )
    assert claimed.status_code == 200
    queue_item = claimed.json()[0]

    errored = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/error",
        json=_owned(
            queue_item,
            item_ids=[queue_item["id"]],
            notes="agent crashed mid-parse",
        ),
    )
    assert errored.status_code == 200
    assert errored.json()["updated"] == 1

    db_path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    with sqlite3.connect(str(db_path)) as connection:
        row = connection.execute(
            "SELECT status, assigned_agent, analysis_notes FROM code_analysis_queue WHERE id = ?",
            (queue_item["id"],),
        ).fetchone()
    assert row[0] == "error"
    assert row[1] == "code-vuln-hunter"
    assert row[2] == "agent crashed mid-parse"

    retried = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/retry-error",
        json={"item_ids": [queue_item["id"]], "reason": "transient parser crash, retrying"},
    )
    assert retried.status_code == 200, retried.text
    assert retried.json()["retried"] == 1
    assert retried.json()["item_ids"] == [queue_item["id"]]

    with sqlite3.connect(str(db_path)) as connection:
        row = connection.execute(
            "SELECT status, assigned_agent, consumed_at, analysis_notes FROM code_analysis_queue WHERE id = ?",
            (queue_item["id"],),
        ).fetchone()
    assert row[0] == "pending"
    assert row[1] == ""
    assert row[2] is None
    # Prior failure context is preserved, not overwritten.
    assert row[3] == "agent crashed mid-parse\n[retried: transient parser crash, retrying]"

    # The item re-enters the fetch rotation like any other pending item.
    reclaimed = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/fetch",
        json={"limit": 1, "agent_name": "code-vuln-hunter-2"},
    )
    assert reclaimed.status_code == 200
    assert reclaimed.json()[0]["id"] == queue_item["id"]

    # Now 'processing' again — retry-error must refuse a non-'error' item.
    rejected = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/retry-error",
        json={"item_ids": [queue_item["id"]], "reason": "should not apply"},
    )
    assert rejected.status_code == 409
    assert "unless they are error" in rejected.json()["detail"]

    activity = client.get(
        f"/engagements/{engagement_key}/activity-entries",
        params={"q": "code-dispatch"},
    )
    assert activity.status_code == 200, activity.text
    assert any(row["title"] == "code-dispatch retry-error" for row in activity.json()["items"])


def test_retry_error_rejects_empty_reason_without_error(client, isolate_settings):
    """`reason` is optional: retrying without one still lands a bare
    `[retried]` breadcrumb rather than failing or leaving notes untouched."""
    engagement_key = "2026-07-08-code-retry-error-no-reason"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="retry-error-no-reason-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser_file = next(item for item in files if item["file_path"] == "src/parser.py")
    _classify_file(client, engagement_key, int(parser_file["id"]), "critical", 100)

    queue_response = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue",
        json={"items": [{"file_id": parser_file["id"], "priority": 100}]},
    )
    assert queue_response.status_code == 201

    claimed = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/fetch",
        json={"limit": 1, "agent_name": "code-vuln-hunter"},
    )
    assert claimed.status_code == 200
    queue_item = claimed.json()[0]

    errored = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/error",
        json=_owned(queue_item, item_ids=[queue_item["id"]]),
    )
    assert errored.status_code == 200

    retried = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/retry-error",
        json={"item_ids": [queue_item["id"]]},
    )
    assert retried.status_code == 200, retried.text
    assert retried.json()["retried"] == 1

    db_path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    with sqlite3.connect(str(db_path)) as connection:
        row = connection.execute(
            "SELECT status, analysis_notes FROM code_analysis_queue WHERE id = ?",
            (queue_item["id"],),
        ).fetchone()
    assert row[0] == "pending"
    assert row[1] == "\n[retried]"


def test_queue_done_rejects_needs_context_disposition(client, isolate_settings):
    engagement_key = "2026-04-04-code-done-needs-context"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="done-needs-context-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser_file = next(item for item in files if item["file_path"] == "src/parser.py")
    _classify_file(client, engagement_key, int(parser_file["id"]), "critical", 100)

    queue_response = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue",
        json={"items": [{"file_id": parser_file["id"], "priority": 100}]},
    )
    assert queue_response.status_code == 201

    claimed = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/fetch",
        json={"limit": 1, "agent_name": "code-vuln-hunter"},
    )
    queue_item = claimed.json()[0]

    done = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/done",
        json={
            "item_ids": [queue_item["id"]],
            "agent_name": queue_item["assigned_agent"],
            "lease_token": queue_item["lease_token"],
            "disposition": "needs_context",
            "cwe_coverage": _network_input_coverage(default_effort=80),
        },
    )
    assert done.status_code == 400
    assert "Invalid disposition" in done.json()["detail"]


def test_queue_done_rejects_legacy_trigger_payload(client, isolate_settings):
    engagement_key = "2026-04-04-code-done-no-trigger-payload"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="done-no-trigger-payload-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser_file = next(item for item in files if item["file_path"] == "src/parser.py")
    _classify_file(client, engagement_key, int(parser_file["id"]), "critical", 100)

    queue_response = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue",
        json={"items": [{"file_id": parser_file["id"], "priority": 100}]},
    )
    assert queue_response.status_code == 201

    claimed = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/fetch",
        json={"limit": 1, "agent_name": "code-vuln-hunter"},
    )
    queue_item = claimed.json()[0]

    done = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/done",
        json={
            "item_ids": [queue_item["id"]],
            "agent_name": queue_item["assigned_agent"],
            "lease_token": queue_item["lease_token"],
            "disposition": "clean",
            "cwe_coverage": _network_input_coverage(default_effort=80),
            "cross_file_triggers": [
                {
                    "file_path": "src/helpers.py",
                    "reason": "stale contract",
                    "vuln_class": "web-app-injection",
                }
            ],
        },
    )
    assert done.status_code == 422


def test_cross_file_triggers_block_gate_until_requeued_and_dedupe_targets(client, isolate_settings):
    engagement_key = "2026-04-04-code-triggers"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="trigger-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser_file = next(item for item in files if item["file_path"] == "src/parser.py")
    helper_file = next(item for item in files if item["file_path"] == "src/helpers.py")
    _classify_file(client, engagement_key, int(parser_file["id"]), "critical", 100)
    _classify_file(client, engagement_key, int(helper_file["id"]), "high", 80)

    queue_response = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue",
        json={"items": [{"file_id": parser_file["id"], "priority": 100}]},
    )
    assert queue_response.status_code == 201

    claimed = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/fetch",
        json={"limit": 1, "agent_name": "code-vuln-hunter"},
    )
    queue_item = claimed.json()[0]

    analysis_result = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-results",
        json={
            "queue_item_id": queue_item["id"],
            "file_id": parser_file["id"],
            "agent_name": "code-vuln-hunter",
            "lease_token": queue_item["lease_token"],
            "function_name": "parse_message",
            "hypothesis": "Shared helper may carry taint into a sink path.",
            "evidence": "parse_message delegates to helper before finishing validation.",
            "disposition": "clean",
            "confidence": "medium",
            "notes": "Need helper follow-up",
            "cross_file_triggers": [
                {
                    "file_path": "src/helpers.py",
                    "reason": "shared parser helper",
                    "vuln_class": "web-app-injection",
                }
            ],
        },
    )
    assert analysis_result.status_code == 201

    done = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/done",
        json={
            "item_ids": [queue_item["id"]],
            "agent_name": queue_item["assigned_agent"],
            "lease_token": queue_item["lease_token"],
            "disposition": "clean",
            "notes": "Reviewed parser",
            "cwe_coverage": _network_input_coverage(default_effort=80),
        },
    )
    assert done.status_code == 200

    coverage_with_pending_trigger = client.get(
        f"/engagements/{engagement_key}/assessment/code/coverage?repo_id={repo['id']}"
    )
    assert coverage_with_pending_trigger.status_code == 200
    pending_payload = coverage_with_pending_trigger.json()
    assert pending_payload["trigger_summary"]["pending"] == 1
    assert any(
        "unprocessed cross-file triggers" in reason.lower()
        for reason in pending_payload["gate"]["reasons"]
    )

    requeue_payload = {
        "items": [
            {
                "file_path": "src/helpers.py",
                "priority": 88,
                "reason": "shared parser helper",
                "trigger_context": {"vuln_class": "web-app-injection"},
            },
            {
                "file_path": "src/helpers.py",
                "priority": 70,
                "reason": "duplicate trigger for same helper",
                "trigger_context": {"vuln_class": "web-app-injection"},
            },
        ]
    }
    requeue = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/requeue",
        json=requeue_payload,
    )
    assert requeue.status_code == 201
    requeue_result = requeue.json()
    assert requeue_result["inserted"] == 1
    assert requeue_result["already_queued"] == 0
    assert requeue_result["already_completed"] == 0

    coverage_with_queued_trigger = client.get(
        f"/engagements/{engagement_key}/assessment/code/coverage?repo_id={repo['id']}"
    )
    queued_payload = coverage_with_queued_trigger.json()
    assert queued_payload["trigger_summary"]["pending"] == 0
    assert queued_payload["trigger_summary"]["queued"] == 1

    requeue_again = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/requeue",
        json=requeue_payload,
    )
    assert requeue_again.status_code == 201
    assert requeue_again.json()["inserted"] == 0
    assert requeue_again.json()["already_queued"] == 1

    helper_claim = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/fetch",
        json={"limit": 1, "agent_name": "follow-up-hunter"},
    )
    helper_item = helper_claim.json()[0]
    assert helper_item["file"]["file_path"] == "src/helpers.py"

    helper_done = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/done",
        json={
            "item_ids": [helper_item["id"]],
            "agent_name": helper_item["assigned_agent"],
            "lease_token": helper_item["lease_token"],
            "disposition": "clean",
            "notes": "Reviewed helper",
            "cwe_coverage": _network_input_coverage(default_effort=60),
        },
    )
    assert helper_done.status_code == 200

    requeue_after_completion = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/requeue",
        json=requeue_payload,
    )
    assert requeue_after_completion.status_code == 201
    assert requeue_after_completion.json()["inserted"] == 0
    assert requeue_after_completion.json()["already_completed"] == 1

    final_coverage = client.get(
        f"/engagements/{engagement_key}/assessment/code/coverage?repo_id={repo['id']}"
    )
    assert final_coverage.status_code == 200
    final_payload = final_coverage.json()
    assert final_payload["trigger_summary"]["resolved"] == 1
    assert final_payload["gate"]["passed"] is True


def test_pending_trigger_can_be_resolved_as_external_context_gap(client, isolate_settings):
    engagement_key = "2026-04-04-code-trigger-external-gap"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="trigger-external-gap-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser_file = next(item for item in files if item["file_path"] == "src/parser.py")
    _classify_file(client, engagement_key, int(parser_file["id"]), "critical", 100)

    queue_response = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue",
        json={"items": [{"file_id": parser_file["id"], "priority": 100}]},
    )
    assert queue_response.status_code == 201

    claimed = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/fetch",
        json={"limit": 1, "agent_name": "code-vuln-hunter"},
    )
    queue_item = claimed.json()[0]

    analysis_result = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-results",
        json={
            "queue_item_id": queue_item["id"],
            "file_id": parser_file["id"],
            "agent_name": "code-vuln-hunter",
            "lease_token": queue_item["lease_token"],
            "function_name": "parse_message",
            "evidence": "External DLL implements the storage call.",
            "disposition": "clean",
            "confidence": "medium",
            "cross_file_triggers": [
                {
                    "file_path": "bin/StorageService.dll",
                    "reason": "implementation not present in source snapshot",
                    "vuln_class": "web-app-injection",
                }
            ],
        },
    )
    assert analysis_result.status_code == 201

    done = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/done",
        json={
            "item_ids": [queue_item["id"]],
            "agent_name": queue_item["assigned_agent"],
            "lease_token": queue_item["lease_token"],
            "disposition": "clean",
            "notes": "Reviewed parser",
            "cwe_coverage": _network_input_coverage(default_effort=80),
        },
    )
    assert done.status_code == 200

    pending = client.get(f"/engagements/{engagement_key}/assessment/code/triggers?status=pending")
    assert pending.status_code == 200
    assert pending.json()[0]["target_file_path"] == "bin/StorageService.dll"

    coverage_before = client.get(
        f"/engagements/{engagement_key}/assessment/code/coverage?repo_id={repo['id']}"
    )
    assert coverage_before.json()["trigger_summary"]["pending"] == 1
    assert coverage_before.json()["gate"]["passed"] is False

    resolved = client.post(
        f"/engagements/{engagement_key}/assessment/code/triggers/resolve",
        json={
            "items": [{"file_path": "bin/StorageService.dll", "vuln_class": "web-app-injection"}],
            "resolution_status": "external_context_unavailable",
            "resolution_note": "Implementation is outside the provided source snapshot.",
        },
    )
    assert resolved.status_code == 200
    assert resolved.json()["resolved"] == 1

    resolve_again = client.post(
        f"/engagements/{engagement_key}/assessment/code/triggers/resolve",
        json={
            "items": [{"file_path": "bin/StorageService.dll", "vuln_class": "web-app-injection"}],
            "resolution_status": "not_applicable",
            "resolution_note": "Second resolution should not overwrite terminal status.",
        },
    )
    assert resolve_again.status_code == 200
    assert resolve_again.json()["resolved"] == 0

    coverage_after = client.get(
        f"/engagements/{engagement_key}/assessment/code/coverage?repo_id={repo['id']}"
    )
    payload = coverage_after.json()
    assert payload["trigger_summary"]["pending"] == 0
    assert payload["trigger_summary"]["external_context_unavailable"] == 1
    assert payload["gate"]["passed"] is True


def test_not_applicable_cwe_coverage_does_not_block_effort_gate(client, isolate_settings):
    engagement_key = "2026-04-04-code-cwe-not-applicable"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="cwe-not-applicable-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser_file = next(item for item in files if item["file_path"] == "src/parser.py")
    _classify_file(client, engagement_key, int(parser_file["id"]), "critical", 100)

    queue_response = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue",
        json={"items": [{"file_id": parser_file["id"], "priority": 100}]},
    )
    assert queue_response.status_code == 201
    claimed = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/fetch",
        json={"limit": 1, "agent_name": "code-vuln-hunter"},
    )
    queue_item = claimed.json()[0]

    coverage = _network_input_coverage(
        default_effort=80,
        overrides={
            "algorithmic-dos": {
                "effort": 0,
                "disposition": "not_applicable",
                "notes": "Static XML/config path has no executable parser loop in this file.",
            }
        },
    )
    done = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/done",
        json={
            "item_ids": [queue_item["id"]],
            "agent_name": queue_item["assigned_agent"],
            "lease_token": queue_item["lease_token"],
            "disposition": "clean",
            "notes": "Reviewed parser",
            "cwe_coverage": coverage,
        },
    )
    assert done.status_code == 200

    coverage_after = client.get(
        f"/engagements/{engagement_key}/assessment/code/coverage?repo_id={repo['id']}"
    )
    assert coverage_after.status_code == 200
    assert coverage_after.json()["gate"]["passed"] is True


def test_cwe_coverage_merge_clears_stale_not_applicable_entry():
    cwe_by_file: dict[int, dict[str, dict[str, object]]] = {}

    code_analysis._merge_cwe_coverage_entries(
        cwe_by_file,
        7,
        [{"family": "ssrf", "disposition": "not_applicable", "effort": 0}],
    )
    code_analysis._merge_cwe_coverage_entries(
        cwe_by_file,
        7,
        [{"family": "ssrf", "disposition": "clean", "effort": 70, "functions_analyzed": 3}],
    )

    merged = cwe_by_file[7]["ssrf"]
    assert merged.get("not_applicable") is not True
    assert merged["disposition"] == "clean"
    assert merged["effort"] == 70
    assert merged["functions_analyzed"] == 3


def test_reanalysis_effort_gate_does_not_skip_family_with_stale_not_applicable(
    client,
    isolate_settings,
):
    engagement_key = "2026-05-14-code-cwe-reanalysis-na"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="cwe-reanalysis-na-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser_file = next(item for item in files if item["file_path"] == "src/parser.py")
    file_id = int(parser_file["id"])
    _classify_file(client, engagement_key, file_id, "critical", 100)

    first_item = _claim_file_for_analysis(client, engagement_key, file_id, priority=100)
    first_done = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/done",
        json={
            "item_ids": [first_item["id"]],
            "agent_name": first_item["assigned_agent"],
            "lease_token": first_item["lease_token"],
            "disposition": "clean",
            "notes": "Initial pass misclassified SSRF as not applicable.",
            "cwe_coverage": _network_input_coverage(
                default_effort=80,
                overrides={
                    "ssrf": {
                        "effort": 0,
                        "disposition": "not_applicable",
                    }
                },
            ),
        },
    )
    assert first_done.status_code == 200

    second_item = _claim_file_for_analysis(client, engagement_key, file_id, priority=100)
    second_done = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/done",
        json={
            "item_ids": [second_item["id"]],
            "agent_name": second_item["assigned_agent"],
            "lease_token": second_item["lease_token"],
            "disposition": "clean",
            "notes": "Re-analysis found SSRF applicable but under-reviewed.",
            "cwe_coverage": _network_input_coverage(
                default_effort=80,
                overrides={"ssrf": {"effort": 10, "disposition": "clean"}},
            ),
        },
    )
    assert second_done.status_code == 200

    coverage_after = client.get(
        f"/engagements/{engagement_key}/assessment/code/coverage?repo_id={repo['id']}"
    )
    assert coverage_after.status_code == 200
    gate = coverage_after.json()["gate"]
    assert gate["passed"] is False
    assert any("family 'ssrf' effort 10 < 70" in reason for reason in gate["reasons"])


def test_analysis_result_triggers_are_recorded_before_requeue(client, isolate_settings):
    engagement_key = "2026-04-04-analysis-result-triggers"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="analysis-result-trigger-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser_file = next(item for item in files if item["file_path"] == "src/parser.py")
    helper_file = next(item for item in files if item["file_path"] == "src/helpers.py")
    _classify_file(client, engagement_key, int(parser_file["id"]), "critical", 100)
    _classify_file(client, engagement_key, int(helper_file["id"]), "high", 80)

    queue_response = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue",
        json={"items": [{"file_id": parser_file["id"], "priority": 100}]},
    )
    assert queue_response.status_code == 201

    claimed = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/fetch",
        json={"limit": 1, "agent_name": "code-vuln-hunter"},
    )
    queue_item = claimed.json()[0]

    analysis_result = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-results",
        json={
            "queue_item_id": queue_item["id"],
            "file_id": parser_file["id"],
            "agent_name": "code-vuln-hunter",
            "lease_token": queue_item["lease_token"],
            "function_name": "parse_message",
            "hypothesis": "Shared helper may reintroduce taint.",
            "evidence": "parse_message delegates to helper before sink handling.",
            "disposition": "clean",
            "confidence": "medium",
            "notes": "Need helper follow-up",
            "cross_file_triggers": [
                {
                    "file_path": "src/helpers.py",
                    "reason": "helper normalizes attacker-controlled input",
                    "vuln_class": "web-app-injection",
                }
            ],
        },
    )
    assert analysis_result.status_code == 201

    coverage_before_done = client.get(
        f"/engagements/{engagement_key}/assessment/code/coverage?repo_id={repo['id']}"
    )
    assert coverage_before_done.status_code == 200
    pending_payload = coverage_before_done.json()
    assert pending_payload["trigger_summary"]["pending"] == 1

    done = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/done",
        json={
            "item_ids": [queue_item["id"]],
            "agent_name": queue_item["assigned_agent"],
            "lease_token": queue_item["lease_token"],
            "disposition": "clean",
            "notes": "Reviewed parser",
            "cwe_coverage": _network_input_coverage(default_effort=80),
        },
    )
    assert done.status_code == 200

    coverage_after_done = client.get(
        f"/engagements/{engagement_key}/assessment/code/coverage?repo_id={repo['id']}"
    )
    assert coverage_after_done.status_code == 200
    assert coverage_after_done.json()["trigger_summary"]["pending"] == 1

    requeue = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/requeue",
        json={
            "items": [
                {
                    "file_path": "src/helpers.py",
                    "priority": 90,
                    "reason": "helper normalizes attacker-controlled input",
                    "trigger_context": {"vuln_class": "web-app-injection"},
                }
            ]
        },
    )
    assert requeue.status_code == 201
    assert requeue.json()["inserted"] == 1

    coverage_after_requeue = client.get(
        f"/engagements/{engagement_key}/assessment/code/coverage?repo_id={repo['id']}"
    )
    assert coverage_after_requeue.status_code == 200
    assert coverage_after_requeue.json()["trigger_summary"]["queued"] == 1


def test_requeue_triggered_files_rejects_non_numeric_ids(client, isolate_settings):
    engagement_key = "2026-04-04-code-requeue-invalid-ids"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="requeue-invalid-ids-repo")
    _create_files(client, engagement_key, int(repo["id"]))

    invalid_file_id = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/requeue",
        json={"items": [{"file_id": "abc"}]},
    )
    assert invalid_file_id.status_code == 400
    assert "file_id must be an integer" in invalid_file_id.json()["detail"]

    invalid_repo_id = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/requeue",
        json={"items": [{"file_path": "src/parser.py", "repo_id": "abc"}]},
    )
    assert invalid_repo_id.status_code == 400
    assert "repo_id must be an integer" in invalid_repo_id.json()["detail"]


def test_requeue_triggered_files_keeps_guidance_strings_separate_from_trigger_context(client, isolate_settings):
    engagement_key = "2026-04-16-code-requeue-guidance-shape"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="requeue-guidance-shape")
    files = _create_files(client, engagement_key, int(repo["id"]))
    helper_file = next(item for item in files if item["file_path"] == "src/helpers.py")
    _classify_file(client, engagement_key, int(helper_file["id"]), "high", 80)

    requeue = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/requeue",
        json={
            "items": [
                {
                    "file_path": "src/helpers.py",
                    "priority": 90,
                    "guidance_hypotheses": ["Trace helper input normalization"],
                    "reason": "helper normalizes attacker-controlled input",
                    "trigger_context": {"vuln_class": "web-app-injection"},
                }
            ]
        },
    )
    assert requeue.status_code == 201
    assert requeue.json()["inserted"] == 1

    fetched = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/fetch",
        json={"limit": 1, "agent_name": "follow-up-hunter"},
    )
    assert fetched.status_code == 200
    item = fetched.json()[0]
    assert item["guidance_hypotheses"] == ["Trace helper input normalization"]
    assert item["cross_file_triggers"] == [
        {
            "file_path": "src/helpers.py",
            "reason": "helper normalizes attacker-controlled input",
            "source": "cross_file_trigger",
            "vuln_class": "web-app-injection",
        }
    ]

    invalid_guidance = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/requeue",
        json={
            "items": [
                {
                    "file_path": "src/helpers.py",
                    "guidance_hypotheses": [{"text": "not a string"}],
                }
            ]
        },
    )
    assert invalid_guidance.status_code == 422


def test_coverage_summary_scopes_findings_to_repo_and_rejects_unknown_repo(client, isolate_settings):
    engagement_key = "2026-04-04-code-coverage-finding-scope"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo_a = _create_repo(client, engagement_key, repo_key="scope-repo-a")
    repo_b = _create_repo(client, engagement_key, repo_key="scope-repo-b")
    _create_files(client, engagement_key, int(repo_a["id"]))
    _create_files(client, engagement_key, int(repo_b["id"]))
    unique_files = _append_repo_files(
        client,
        engagement_key,
        int(repo_a["id"]),
        [
                {
                    "file_path": "repo_a_only.py",
                    "language": "python",
                    "loc": 10,
                    "file_hash": "repo-a-only",
                    "header_snippet": "",
                    "git_churn_score": 0,
                    "has_past_cve_fix": False,
                },
        ],
    )
    assert any(row["file_path"] == "repo_a_only.py" for row in unique_files)
    unique_files = _append_repo_files(
        client,
        engagement_key,
        int(repo_b["id"]),
        [
                {
                    "file_path": "repo_b_only.py",
                    "language": "python",
                    "loc": 10,
                    "file_hash": "repo-b-only",
                    "header_snippet": "",
                    "git_churn_score": 0,
                    "has_past_cve_fix": False,
                },
        ],
    )
    assert any(row["file_path"] == "repo_b_only.py" for row in unique_files)

    _create_root_finding(client, engagement_key, "CH-090")
    _create_root_finding(client, engagement_key, "CH-091")
    finding_a = client.post(
        f"/engagements/{engagement_key}/assessment/findings",
        json={
            "slug": "CH-001",
            "title": "Parser trust boundary bypass",
            "severity": "high",
            "workflow_status": "active",
            "verification_state": "unreviewed",
            "verification_disposition": "none",
            "defect_family": "trust-boundary-bypass",
            "root_cause_key": "scope-repo-a-parser",
            "auth_context": "anonymous",
            "canonical_location": "file:repo_a_only.py:12",
            "summary": "Repo A finding should stay scoped to repo A coverage.",
            "evidence_ref": "findings.md",
            "notes": "",
            "source_name": "code-vuln-hunter",
            "details": {"evidence": "A"},
            "provenance": {"agent_name": "code-vuln-hunter"},
            "links": [
                {
                    "link_kind": "variant_of",
                    "target_kind": "finding",
                    "target_ref": "CH-090",
                }
            ],
        },
    )
    assert finding_a.status_code == 201

    finding_b = client.post(
        f"/engagements/{engagement_key}/assessment/findings",
        json={
            "slug": "CH-002",
            "title": "Helper sink exposure",
            "severity": "critical",
            "workflow_status": "active",
            "verification_state": "unreviewed",
            "verification_disposition": "none",
            "defect_family": "sink-exposure",
            "root_cause_key": "scope-repo-b-helper",
            "auth_context": "anonymous",
            "canonical_location": "file:repo_b_only.py:20",
            "summary": "Repo B finding should stay scoped to repo B coverage.",
            "evidence_ref": "findings.md",
            "notes": "",
            "source_name": "code-vuln-hunter",
            "details": {"evidence": "B"},
            "provenance": {"agent_name": "code-vuln-hunter"},
            "links": [
                {
                    "link_kind": "variant_of",
                    "target_kind": "finding",
                    "target_ref": "CH-091",
                }
            ],
        },
    )
    assert finding_b.status_code == 201

    repo_a_coverage = client.get(
        f"/engagements/{engagement_key}/assessment/code/coverage?repo_id={repo_a['id']}"
    )
    assert repo_a_coverage.status_code == 200
    repo_a_payload = repo_a_coverage.json()
    assert repo_a_payload["findings_summary"]["total_code_findings"] == 1
    assert repo_a_payload["findings_summary"]["by_severity"] == {"high": 1}
    assert repo_a_payload["findings_summary"]["variant_count"] == 1

    repo_b_coverage = client.get(
        f"/engagements/{engagement_key}/assessment/code/coverage?repo_id={repo_b['id']}"
    )
    assert repo_b_coverage.status_code == 200
    repo_b_payload = repo_b_coverage.json()
    assert repo_b_payload["findings_summary"]["total_code_findings"] == 1
    assert repo_b_payload["findings_summary"]["by_severity"] == {"critical": 1}
    assert repo_b_payload["findings_summary"]["variant_count"] == 1

    missing_repo = client.get(f"/engagements/{engagement_key}/assessment/code/coverage?repo_id=999999")
    assert missing_repo.status_code == 404


def test_coverage_summary_tolerates_non_numeric_effort_values(client, isolate_settings):
    engagement_key = "2026-04-04-code-coverage-nonnumeric-effort"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="nonnumeric-effort-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser_file = next(item for item in files if item["file_path"] == "src/parser.py")
    _classify_file(client, engagement_key, int(parser_file["id"]), "critical", 100)

    queued = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue",
        json={"items": [{"file_id": parser_file["id"], "priority": 100}]},
    )
    assert queued.status_code == 201

    claimed = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/fetch",
        json={"limit": 1, "agent_name": "code-vuln-hunter"},
    )
    assert claimed.status_code == 200
    queue_item = claimed.json()[0]

    done = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/done",
        json={
            "item_ids": [queue_item["id"]],
            "agent_name": queue_item["assigned_agent"],
            "lease_token": queue_item["lease_token"],
            "disposition": "clean",
            "notes": "Reviewed",
            "cwe_coverage": _network_input_coverage(
                default_effort=80,
                overrides={"web-app-injection": {"effort": "unknown"}},
            ),
        },
    )
    assert done.status_code == 200

    coverage = client.get(
        f"/engagements/{engagement_key}/assessment/code/coverage?repo_id={repo['id']}"
    )
    assert coverage.status_code == 200
    payload = coverage.json()
    assert payload["gate"]["passed"] is False
    assert any("web-app-injection" in reason for reason in payload["gate"]["reasons"])


def test_coverage_summary_excludes_false_positive_variants(client, isolate_settings):
    engagement_key = "2026-04-09-code-coverage-variant-filter"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="variant-filter-repo")
    _create_files(client, engagement_key, int(repo["id"]))

    _create_root_finding(client, engagement_key, "CH-090")
    finding = client.post(
        f"/engagements/{engagement_key}/assessment/findings",
        json={
            "slug": "CH-001",
            "title": "Parser variant",
            "severity": "high",
            "workflow_status": "active",
            "verification_state": "unreviewed",
            "verification_disposition": "none",
            "defect_family": "trust-boundary-bypass",
            "root_cause_key": "variant-filter-parser",
            "auth_context": "anonymous",
            "canonical_location": "file:src/parser.py:12",
            "summary": "Variant should disappear from coverage after suppression.",
            "evidence_ref": "findings.md",
            "notes": "",
            "source_name": "code-vuln-hunter",
            "details": {"evidence": "A"},
            "provenance": {"agent_name": "code-vuln-hunter"},
            "links": [
                {
                    "link_kind": "variant_of",
                    "target_kind": "finding",
                    "target_ref": "CH-090",
                }
            ],
        },
    )
    assert finding.status_code == 201

    baseline = client.get(f"/engagements/{engagement_key}/assessment/code/coverage?repo_id={repo['id']}")
    assert baseline.status_code == 200
    assert baseline.json()["findings_summary"]["variant_count"] == 1

    verify = client.post(
        f"/engagements/{engagement_key}/assessment/findings/CH-001/verify",
        json={
            "disposition": "false_positive",
            "reason_code": "guarded-path",
            "reason_text": "Guard closes the variant in production.",
            "artifact_ref": "tools/analysis-state/code-verification/CH-001.json",
            "source_name": "code-vuln-verifier",
            "details": {
                "kill_check": 4,
                "kill_reason": "Guard closes the path in production.",
                "evidence": "Validation rejects the attacker-controlled branch.",
                "impact": "No reachable issue remains.",
            },
            "provenance": {"verified_by": "code-vuln-verifier"},
        },
    )
    assert verify.status_code == 200

    suppressed = client.get(f"/engagements/{engagement_key}/assessment/code/coverage?repo_id={repo['id']}")
    assert suppressed.status_code == 200
    payload = suppressed.json()
    assert payload["findings_summary"]["total_code_findings"] == 0
    assert payload["findings_summary"]["variant_count"] == 0


def test_coverage_summary_excludes_non_code_variants(client, isolate_settings):
    engagement_key = "2026-04-09-code-coverage-noncode-variants"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="noncode-variant-repo")
    _create_files(client, engagement_key, int(repo["id"]))

    _create_root_finding(client, engagement_key, "VA-090", source_name="vulnerability-analyst")
    finding = client.post(
        f"/engagements/{engagement_key}/assessment/findings",
        json={
            "slug": "VA-001",
            "title": "HTTP variant",
            "severity": "high",
            "workflow_status": "active",
            "verification_state": "unreviewed",
            "verification_disposition": "none",
            "defect_family": "authz-bypass",
            "root_cause_key": "http-variant",
            "auth_context": "anonymous",
            "canonical_location": "https://example.com/api/export",
            "summary": "Non-code finding should not inflate code variant counts.",
            "evidence_ref": "findings.md",
            "notes": "",
            "source_name": "vulnerability-analyst",
            "details": {"evidence": "A"},
            "provenance": {"agent_name": "vulnerability-analyst"},
            "links": [
                {
                    "link_kind": "variant_of",
                    "target_kind": "finding",
                    "target_ref": "VA-090",
                }
            ],
        },
    )
    assert finding.status_code == 201

    coverage = client.get(f"/engagements/{engagement_key}/assessment/code/coverage?repo_id={repo['id']}")
    assert coverage.status_code == 200
    assert coverage.json()["findings_summary"]["variant_count"] == 0


def test_repo_scoped_coverage_excludes_ambiguous_shared_file_paths(client, isolate_settings):
    engagement_key = "2026-04-09-code-coverage-ambiguous-shared-paths"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo_a = _create_repo(client, engagement_key, repo_key="shared-path-repo-a")
    repo_b = _create_repo(client, engagement_key, repo_key="shared-path-repo-b")

    shared_files_a = _refresh_repo_files(
        client,
        engagement_key,
        int(repo_a["id"]),
        [
                {
                    "file_path": "src/shared.py",
                    "language": "python",
                    "loc": 30,
                    "file_hash": "shared-a",
                    "header_snippet": "",
                    "git_churn_score": 0,
                    "has_past_cve_fix": False,
                },
        ],
    )
    assert shared_files_a[0]["file_path"] == "src/shared.py"
    shared_files_b = _refresh_repo_files(
        client,
        engagement_key,
        int(repo_b["id"]),
        [
                {
                    "file_path": "src/shared.py",
                    "language": "python",
                    "loc": 45,
                    "file_hash": "shared-b",
                    "header_snippet": "",
                    "git_churn_score": 0,
                    "has_past_cve_fix": False,
                },
        ],
    )
    assert shared_files_b[0]["file_path"] == "src/shared.py"

    _create_root_finding(client, engagement_key, "CH-090")
    finding = client.post(
        f"/engagements/{engagement_key}/assessment/findings",
        json={
            "slug": "CH-001",
            "title": "Shared path finding",
            "severity": "high",
            "workflow_status": "active",
            "verification_state": "unreviewed",
            "verification_disposition": "none",
            "defect_family": "trust-boundary-bypass",
            "root_cause_key": "shared-path-finding",
            "auth_context": "anonymous",
            "canonical_location": "file:src/shared.py:12",
            "summary": "Ambiguous file-path findings should not be double-attributed across repos.",
            "evidence_ref": "findings.md",
            "notes": "",
            "source_name": "code-vuln-hunter",
            "details": {"evidence": "A"},
            "provenance": {"agent_name": "code-vuln-hunter"},
            "links": [
                {
                    "link_kind": "variant_of",
                    "target_kind": "finding",
                    "target_ref": "CH-090",
                }
            ],
        },
    )
    assert finding.status_code == 201

    repo_a_coverage = client.get(
        f"/engagements/{engagement_key}/assessment/code/coverage?repo_id={repo_a['id']}"
    )
    assert repo_a_coverage.status_code == 200
    repo_a_payload = repo_a_coverage.json()
    assert repo_a_payload["findings_summary"]["total_code_findings"] == 0
    assert repo_a_payload["findings_summary"]["variant_count"] == 0

    repo_b_coverage = client.get(
        f"/engagements/{engagement_key}/assessment/code/coverage?repo_id={repo_b['id']}"
    )
    assert repo_b_coverage.status_code == 200
    repo_b_payload = repo_b_coverage.json()
    assert repo_b_payload["findings_summary"]["total_code_findings"] == 0
    assert repo_b_payload["findings_summary"]["variant_count"] == 0


def test_module_creation_assigns_files_and_supports_module_scoped_fetch(client, isolate_settings):
    engagement_key = "2026-04-04-code-modules"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="module-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser_file = next(item for item in files if item["file_path"] == "src/parser.py")
    helper_file = next(item for item in files if item["file_path"] == "src/helpers.py")
    _classify_file(client, engagement_key, int(parser_file["id"]), "critical", 90)
    _classify_file(client, engagement_key, int(helper_file["id"]), "high", 70)

    modules = client.post(
        f"/engagements/{engagement_key}/assessment/code/modules",
        json={
            "repo_id": repo["id"],
            "modules": [
                {
                    "module_key": "input-parser",
                    "name": "Input Parser",
                    "description": "Parses network input",
                    "trust_boundary": "Untrusted request data",
                    "files": ["src/parser.py", "src/helpers.py"],
                }
            ],
        },
    )
    assert modules.status_code == 201
    module = modules.json()[0]
    assert module["file_count"] == 2
    assert module["critical_file_count"] == 1

    scoped_files = client.get(
        f"/engagements/{engagement_key}/assessment/code/files?module_id={module['id']}&limit=20"
    )
    assert scoped_files.status_code == 200
    assert {item["file_path"] for item in scoped_files.json()} == {"src/parser.py", "src/helpers.py"}


def test_module_analysis_status_tracks_file_progress(client, isolate_settings):
    engagement_key = "2026-04-09-code-module-status"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="module-status-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser_file = next(item for item in files if item["file_path"] == "src/parser.py")
    _classify_file(client, engagement_key, int(parser_file["id"]), "critical", 95)

    modules = client.post(
        f"/engagements/{engagement_key}/assessment/code/modules",
        json={
            "repo_id": repo["id"],
            "modules": [
                {
                    "module_key": "input-parser",
                    "name": "Input Parser",
                    "description": "Parses network input",
                    "trust_boundary": "Untrusted request data",
                    "files": ["src/parser.py"],
                }
            ],
        },
    )
    assert modules.status_code == 201
    module = modules.json()[0]
    assert module["analysis_status"] == "classified"

    queued = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue",
        json={"items": [{"file_id": parser_file["id"], "priority": 95}]},
    )
    assert queued.status_code == 201

    queued_modules = client.get(
        f"/engagements/{engagement_key}/assessment/code/modules?repo_id={repo['id']}"
    )
    assert queued_modules.status_code == 200
    assert queued_modules.json()[0]["analysis_status"] == "queued"

    claimed = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/fetch",
        json={"limit": 1, "agent_name": "code-vuln-hunter"},
    )
    assert claimed.status_code == 200
    queue_item = claimed.json()[0]

    in_progress_modules = client.get(
        f"/engagements/{engagement_key}/assessment/code/modules?repo_id={repo['id']}"
    )
    assert in_progress_modules.status_code == 200
    assert in_progress_modules.json()[0]["analysis_status"] == "in_progress"

    done = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/done",
        json={
            "item_ids": [queue_item["id"]],
            "agent_name": queue_item["assigned_agent"],
            "lease_token": queue_item["lease_token"],
            "disposition": "clean",
            "notes": "Reviewed parser module",
            "cwe_coverage": _network_input_coverage(default_effort=80),
        },
    )
    assert done.status_code == 200

    analyzed_modules = client.get(
        f"/engagements/{engagement_key}/assessment/code/modules?repo_id={repo['id']}"
    )
    assert analyzed_modules.status_code == 200
    assert analyzed_modules.json()[0]["analysis_status"] == "analyzed"


def test_file_patch_rejects_module_ids_from_other_repos(client, isolate_settings):
    engagement_key = "2026-04-04-code-module-patch-scope"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo_a = _create_repo(client, engagement_key, repo_key="repo-a")
    repo_b = _create_repo(client, engagement_key, repo_key="repo-b")
    files_a = _create_files(client, engagement_key, int(repo_a["id"]))
    _create_files(client, engagement_key, int(repo_b["id"]))
    parser_file = next(item for item in files_a if item["file_path"] == "src/parser.py")

    modules = client.post(
        f"/engagements/{engagement_key}/assessment/code/modules",
        json={
            "repo_id": repo_b["id"],
            "modules": [
                {
                    "module_key": "foreign-module",
                    "name": "Foreign Module",
                    "description": "Owned by repo-b",
                    "trust_boundary": "internal",
                    "files": ["src/parser.py"],
                }
            ],
        },
    )
    assert modules.status_code == 201
    foreign_module = modules.json()[0]

    patched = client.patch(
        f"/engagements/{engagement_key}/assessment/code/files/{parser_file['id']}",
        json={"module_id": foreign_module["id"]},
    )
    assert patched.status_code == 400
    assert "same repo" in patched.json()["detail"]


def test_file_patch_rejects_unknown_fields(client, isolate_settings):
    engagement_key = "2026-04-16-code-file-patch-unknown"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="file-patch-unknown")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser_file = next(item for item in files if item["file_path"] == "src/parser.py")

    response = client.patch(
        f"/engagements/{engagement_key}/assessment/code/files/{parser_file['id']}",
        json={"unsupported_field": "value"},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "file patch does not accept fields: unsupported_field"


def test_file_patch_rejects_non_integer_structural_metadata(client, isolate_settings):
    engagement_key = "2026-04-15-code-file-patch-structural-invalid"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="patch-structural-invalid")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser_file = next(item for item in files if item["file_path"] == "src/parser.py")

    response = client.patch(
        f"/engagements/{engagement_key}/assessment/code/files/{parser_file['id']}",
        json={"total_functions": "not-a-number"},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "total_functions must be an integer"


def test_file_patch_rejects_negative_structural_metadata(client, isolate_settings):
    engagement_key = "2026-04-15-code-file-patch-structural-negative"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="patch-structural-negative")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser_file = next(item for item in files if item["file_path"] == "src/parser.py")

    response = client.patch(
        f"/engagements/{engagement_key}/assessment/code/files/{parser_file['id']}",
        json={"total_sinks": -1},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "total_sinks must be >= 0"


def test_file_patch_rejects_fractional_structural_metadata(client, isolate_settings):
    engagement_key = "2026-04-15-code-file-patch-structural-fractional"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="patch-structural-fractional")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser_file = next(item for item in files if item["file_path"] == "src/parser.py")

    response = client.patch(
        f"/engagements/{engagement_key}/assessment/code/files/{parser_file['id']}",
        json={"total_functions": 3.9},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "total_functions must be an integer"


def test_bulk_structural_metadata_requires_all_totals(client, isolate_settings):
    engagement_key = "2026-04-15-code-bulk-structural-required"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="bulk-structural-required")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser_file = next(item for item in files if item["file_path"] == "src/parser.py")

    response = client.post(
        f"/engagements/{engagement_key}/assessment/code/files/bulk-structural-metadata",
        json={"updates": [{"file_id": parser_file["id"], "total_functions": 3}]},
    )

    assert response.status_code == 422
    assert "total_entry_points" in response.text
    assert "total_sinks" in response.text
    assert "total_exports" in response.text


def test_bulk_structural_metadata_rejects_unknown_fields(client, isolate_settings):
    engagement_key = "2026-04-16-code-bulk-structural-unknown"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="bulk-structural-unknown")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser_file = next(item for item in files if item["file_path"] == "src/parser.py")

    response = client.post(
        f"/engagements/{engagement_key}/assessment/code/files/bulk-structural-metadata",
        json={
            "updates": [
                {
                    "file_id": parser_file["id"],
                    "total_functions": 3,
                    "total_entry_points": 1,
                    "total_sinks": 2,
                    "total_exports": 0,
                    "unexpected_total": 99,
                }
            ]
        },
    )

    assert response.status_code == 422
    assert "unexpected_total" in response.text


def test_code_analysis_endpoints_reject_foreign_engagement_ids(client, isolate_settings):
    first_key = "2026-04-04-code-owner-a"
    second_key = "2026-04-04-code-owner-b"
    write_engagement(isolate_settings["engagements_dir"], first_key)
    write_engagement(isolate_settings["engagements_dir"], second_key)

    repo = _create_repo(client, first_key, repo_key="owned-repo")
    files = _create_files(client, first_key, int(repo["id"]))
    parser_file = next(item for item in files if item["file_path"] == "src/parser.py")
    _classify_file(client, first_key, int(parser_file["id"]), "critical", 95)

    queue_response = client.post(
        f"/engagements/{first_key}/assessment/code/analysis-queue",
        json={"items": [{"file_id": parser_file["id"], "priority": 90}]},
    )
    assert queue_response.status_code == 201
    queue_item = client.post(
        f"/engagements/{first_key}/assessment/code/analysis-queue/fetch",
        json={"limit": 1, "agent_name": "code-vuln-hunter"},
    ).json()[0]

    refresh = client.post(
        f"/engagements/{first_key}/assessment/code/repos/refresh/start",
        json=_repo_payload("owned-repo", "/tmp/owned-repo"),
    ).json()
    foreign_files = client.post(
        f"/engagements/{second_key}/assessment/code/repos/{repo['id']}/refresh/files",
        json={
            "refresh_token": refresh["refresh_token"],
            "files": [
                {
                    "file_path": "src/foreign.py",
                    "language": "python",
                    "loc": 10,
                    "file_hash": "hash-c",
                    "header_snippet": "",
                    "git_churn_score": 0,
                    "has_past_cve_fix": False,
                }
            ],
        },
    )
    assert foreign_files.status_code == 404

    foreign_queue = client.post(
        f"/engagements/{second_key}/assessment/code/analysis-queue",
        json={"items": [{"file_id": parser_file["id"], "priority": 50}]},
    )
    assert foreign_queue.status_code == 404

    foreign_threat_model = client.post(
        f"/engagements/{second_key}/assessment/code/threat-model",
        json={"repo_id": repo["id"], "threat_model": {"targets": ["parser"]}},
    )
    assert foreign_threat_model.status_code == 404

    foreign_result = client.post(
        f"/engagements/{second_key}/assessment/code/analysis-results",
        json={
            "queue_item_id": queue_item["id"],
            "file_id": parser_file["id"],
            "agent_name": "code-vuln-hunter",
            "lease_token": queue_item["lease_token"],
            "function_name": "parse_message",
            "hypothesis": "",
            "evidence": "",
            "disposition": "clean",
            "confidence": "medium",
            "notes": "",
        },
    )
    assert foreign_result.status_code == 404


def test_repo_refresh_reuses_existing_repo_key_within_engagement(client, isolate_settings):
    engagement_key = "2026-04-04-code-upsert"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)

    base = f"/engagements/{engagement_key}/assessment/code"
    first_started = client.post(
        f"{base}/repos/refresh/start",
        json=_repo_payload("same-repo", "/tmp/same-repo"),
    )
    assert first_started.status_code == 201
    first_refresh = first_started.json()
    assert client.post(
        f"{base}/repos/{first_refresh['repo_id']}/refresh/commit",
        json={"refresh_token": first_refresh["refresh_token"], "manifest_complete": True},
    ).status_code == 200

    second_started = client.post(
        f"{base}/repos/refresh/start",
        json={
            **_repo_payload("same-repo", "/tmp/updated-same-repo"),
            "branch": "release",
            "total_loc": 999,
        },
    )
    assert second_started.status_code == 201
    second_refresh = second_started.json()
    assert client.post(
        f"{base}/repos/{second_refresh['repo_id']}/refresh/commit",
        json={"refresh_token": second_refresh["refresh_token"], "manifest_complete": True},
    ).status_code == 200

    second_payload = client.get(f"{base}/repos/{second_refresh['repo_id']}").json()
    assert second_payload["id"] == first_refresh["repo_id"]
    assert second_payload["repo_path"] == "/tmp/updated-same-repo"
    assert second_payload["branch"] == "release"
    assert second_payload["total_loc"] == 999


def test_file_only_queue_create_and_fetch(client, isolate_settings):
    """Queue items with only file_id (no context_id) + batch_theme + slot_types
    should be created, fetched with context=None, and completed with cwe_coverage."""
    engagement_key = "2026-04-04-file-only-queue"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="file-only-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser_file = next(item for item in files if item["file_path"] == "src/parser.py")
    _classify_file(client, engagement_key, int(parser_file["id"]), "critical", 95)

    # Create queue item with ONLY file_id (no context_id) + new fields
    queue_response = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue",
        json={
            "items": [
                {
                    "file_id": parser_file["id"],
                    "priority": 90,
                    "batch_theme": "network-input-analysis",
                    "slot_types": ["NETWORK-INPUT", "FILE-CONTENT"],
                    "guidance_hypotheses": ["Check for buffer overflow in parse()"],
                }
            ]
        },
    )
    assert queue_response.status_code == 201
    assert queue_response.json()["inserted"] == 1

    # File status should transition to queued
    file_after_queue = client.get(
        f"/engagements/{engagement_key}/assessment/code/files/{parser_file['id']}"
    )
    assert file_after_queue.status_code == 200
    assert file_after_queue.json()["analysis_status"] == "queued"

    # Fetch the item — context should be None, batch_theme preserved
    fetch_response = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/fetch",
        json={"limit": 1, "agent_name": "code-vuln-hunter"},
    )
    assert fetch_response.status_code == 200
    payload = fetch_response.json()
    assert len(payload) == 1
    work_item = payload[0]
    assert "context" not in work_item
    assert work_item["batch_theme"] == "network-input-analysis"
    assert work_item["slot_types"] == ["NETWORK-INPUT", "FILE-CONTENT"]
    assert work_item["guidance_hypotheses"] == ["Check for buffer overflow in parse()"]
    assert work_item["file"]["id"] == parser_file["id"]
    assert work_item["file"]["file_path"] == "src/parser.py"
    assert work_item["repo"]["id"] == repo["id"]

    # Complete with cwe_coverage payload
    cwe_coverage_data = _network_input_coverage(
        default_effort=70,
        overrides={
            "web-app-injection": {"effort": 85, "entry_chains_traced": 3},
            "path-traversal": {"effort": 70, "entry_chains_traced": 2},
        },
    )
    done = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/done",
        json={
            "item_ids": [work_item["id"]],
            "agent_name": work_item["assigned_agent"],
            "lease_token": work_item["lease_token"],
            "disposition": "clean",
            "notes": "Reviewed all sinks",
            "cwe_coverage": cwe_coverage_data,
        },
    )
    assert done.status_code == 200
    assert done.json()["updated"] == 1

    # File status should transition to analyzed (no contexts, all queue done)
    file_after_done = client.get(
        f"/engagements/{engagement_key}/assessment/code/files/{parser_file['id']}"
    )
    assert file_after_done.status_code == 200
    assert file_after_done.json()["analysis_status"] == "analyzed"


def test_cwe_coverage_passthrough_on_queue_done(client, isolate_settings):
    """Completing a queue item with cwe_coverage persists it and is visible
    via the coverage detail endpoint."""
    engagement_key = "2026-04-04-cwe-passthrough"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="cwe-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser_file = next(item for item in files if item["file_path"] == "src/parser.py")
    _classify_file(client, engagement_key, int(parser_file["id"]), "critical", 95)

    # Create and fetch a file-only queue item
    queue_response = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue",
        json={
            "items": [
                {
                    "file_id": parser_file["id"],
                    "priority": 90,
                    "batch_theme": "cwe-test-batch",
                    "slot_types": ["NETWORK-INPUT"],
                }
            ]
        },
    )
    assert queue_response.status_code == 201

    claimed = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/fetch",
        json={"limit": 1, "agent_name": "code-vuln-hunter"},
    )
    queue_item = claimed.json()[0]

    # Complete with cwe_coverage
    cwe_coverage = _network_input_coverage(
        default_effort=60,
        overrides={
            "web-app-injection": {"effort": 90, "entry_chains_traced": 5},
            "ssrf": {"effort": 60, "entry_chains_traced": 1},
        },
    )
    done = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/done",
        json={
            "item_ids": [queue_item["id"]],
            "agent_name": queue_item["assigned_agent"],
            "lease_token": queue_item["lease_token"],
            "disposition": "clean",
            "notes": "All clear",
            "cwe_coverage": cwe_coverage,
        },
    )
    assert done.status_code == 200

    # Verify via coverage detail endpoint
    coverage = client.get(
        f"/engagements/{engagement_key}/assessment/code/coverage?repo_id={repo['id']}&detail=cwe"
    )
    assert coverage.status_code == 200
    payload = coverage.json()
    assert "files" in payload
    cwe_file = next(f for f in payload["files"] if f["file_id"] == parser_file["id"])
    assert cwe_file["classification"] == "critical"
    assert "NETWORK-INPUT" in cwe_file["slot_types"]
    assert len(cwe_file["applicable_families"]) > 0
    # Check that the persisted cwe_coverage entries are present
    families_covered = {e["family"] for e in cwe_file["cwe_coverage"]}
    assert "web-app-injection" in families_covered
    assert "ssrf" in families_covered


def test_queue_done_rejects_items_reset_out_of_processing(client, isolate_settings):
    engagement_key = "2026-04-09-code-queue-completion-race"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="queue-race-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser_file = next(item for item in files if item["file_path"] == "src/parser.py")
    _classify_file(client, engagement_key, int(parser_file["id"]), "critical", 95)

    queue_response = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue",
        json={"items": [{"file_id": parser_file["id"], "priority": 90}]},
    )
    assert queue_response.status_code == 201

    claimed = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/fetch",
        json={"limit": 1, "agent_name": "code-vuln-hunter"},
    )
    assert claimed.status_code == 200
    queue_item = claimed.json()[0]

    db_path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    with sqlite3.connect(str(db_path)) as connection:
        connection.execute(
            "UPDATE code_analysis_queue SET consumed_at = ?, last_heartbeat_at = ? WHERE id = ?",
            ("2020-01-01T00:00:00Z", "2020-01-01T00:00:00Z", queue_item["id"]),
        )
        connection.commit()

    reset = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/reset-stale",
        json={"minutes": 30},
    )
    assert reset.status_code == 200
    assert reset.json()["reset"] == 1

    done = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/done",
        json={
            "item_ids": [queue_item["id"]],
            "agent_name": queue_item["assigned_agent"],
            "lease_token": queue_item["lease_token"],
            "disposition": "clean",
            "notes": "Stale worker should not complete this item",
            "cwe_coverage": _network_input_coverage(default_effort=80),
        },
    )
    assert done.status_code == 409
    assert "unless they are processing" in done.json()["detail"]
    assert "pending" in done.json()["detail"]


def test_queue_error_rejects_items_reclaimed_after_validation(client, isolate_settings, monkeypatch):
    engagement_key = "2026-04-09-code-queue-error-race"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="queue-error-race-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser_file = next(item for item in files if item["file_path"] == "src/parser.py")
    _classify_file(client, engagement_key, int(parser_file["id"]), "critical", 95)

    queue_response = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue",
        json={"items": [{"file_id": parser_file["id"], "priority": 90}]},
    )
    assert queue_response.status_code == 201

    claimed = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/fetch",
        json={"limit": 1, "agent_name": "code-vuln-hunter"},
    )
    assert claimed.status_code == 200
    queue_item = claimed.json()[0]

    from app.services import code_analysis as code_analysis_service

    original_require_queue_status = code_analysis_service._require_queue_status
    db_path = isolate_settings["data_dir"] / "orchestrator.sqlite3"

    def race(queue_rows, *, expected_status, action):
        original_require_queue_status(queue_rows, expected_status=expected_status, action=action)
        with sqlite3.connect(str(db_path)) as connection:
            connection.execute(
                "UPDATE code_analysis_queue SET status = 'pending', assigned_agent = '', consumed_at = NULL WHERE id = ?",
                (queue_item["id"],),
            )
            connection.commit()

    monkeypatch.setattr(code_analysis_service, "_require_queue_status", race)

    error = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/error",
        json={
            "item_ids": [queue_item["id"]],
            "agent_name": queue_item["assigned_agent"],
            "lease_token": queue_item["lease_token"],
            "notes": "Late worker should not mark reclaimed work as error",
        },
    )
    assert error.status_code == 409
    assert "changed state before error transition" in error.json()["detail"]


def test_queue_needs_context_rejects_items_reclaimed_after_validation(client, isolate_settings, monkeypatch):
    engagement_key = "2026-04-09-code-queue-needs-context-race"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="queue-needs-context-race-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser_file = next(item for item in files if item["file_path"] == "src/parser.py")
    _classify_file(client, engagement_key, int(parser_file["id"]), "critical", 95)

    queue_response = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue",
        json={"items": [{"file_id": parser_file["id"], "priority": 90}]},
    )
    assert queue_response.status_code == 201

    claimed = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/fetch",
        json={"limit": 1, "agent_name": "code-vuln-hunter"},
    )
    assert claimed.status_code == 200
    queue_item = claimed.json()[0]

    from app.services import code_analysis as code_analysis_service

    original_require_queue_status = code_analysis_service._require_queue_status
    db_path = isolate_settings["data_dir"] / "orchestrator.sqlite3"

    def race(queue_rows, *, expected_status, action):
        original_require_queue_status(queue_rows, expected_status=expected_status, action=action)
        with sqlite3.connect(str(db_path)) as connection:
            connection.execute(
                "UPDATE code_analysis_queue SET status = 'pending', assigned_agent = '', consumed_at = NULL WHERE id = ?",
                (queue_item["id"],),
            )
            connection.commit()

    monkeypatch.setattr(code_analysis_service, "_require_queue_status", race)

    needs_context = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/needs-context",
        json={
            "item_ids": [queue_item["id"]],
            "agent_name": queue_item["assigned_agent"],
            "lease_token": queue_item["lease_token"],
            "expansion_request": {
                "reason": "Need additional surrounding code to settle the path",
                "functions": ["parse_message"],
            },
        },
    )
    assert needs_context.status_code == 409
    assert "changed state before needs_context transition" in needs_context.json()["detail"]


def test_analysis_result_rejects_queue_item_reclaimed_after_validation(client, isolate_settings, monkeypatch):
    engagement_key = "2026-04-09-analysis-result-race"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="analysis-result-race-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser_file = next(item for item in files if item["file_path"] == "src/parser.py")
    _classify_file(client, engagement_key, int(parser_file["id"]), "critical", 95)

    queue_response = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue",
        json={"items": [{"file_id": parser_file["id"], "priority": 90}]},
    )
    assert queue_response.status_code == 201

    claimed = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/fetch",
        json={"limit": 1, "agent_name": "code-vuln-hunter"},
    )
    assert claimed.status_code == 200
    queue_item = claimed.json()[0]

    from app.services import code_analysis as code_analysis_service

    original_require_queue_status = code_analysis_service._require_queue_status
    db_path = isolate_settings["data_dir"] / "orchestrator.sqlite3"

    def race(queue_rows, *, expected_status, action):
        original_require_queue_status(queue_rows, expected_status=expected_status, action=action)
        with sqlite3.connect(str(db_path)) as connection:
            connection.execute(
                """
                UPDATE code_analysis_queue
                SET status = 'pending',
                    assigned_agent = '',
                    consumed_at = NULL,
                    updated_at = '2099-01-01 00:00:00'
                WHERE id = ?
                """,
                (queue_item["id"],),
            )
            connection.commit()

    monkeypatch.setattr(code_analysis_service, "_require_queue_status", race)

    result = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-results",
        json={
            "queue_item_id": queue_item["id"],
            "file_id": parser_file["id"],
            "agent_name": "code-vuln-hunter",
            "lease_token": queue_item["lease_token"],
            "function_name": "parse_message",
            "hypothesis": "Late worker should not attach results to reclaimed work.",
            "evidence": "Queue row was reclaimed after validation.",
            "disposition": "clean",
            "confidence": "medium",
            "notes": "Should reject stale result writes.",
        },
    )
    assert result.status_code == 409
    assert "changed state before recording analysis result" in result.json()["detail"]


def test_analysis_result_requires_queue_item_id(client, isolate_settings):
    """Analysis results must be tied to a claimed queue item."""
    engagement_key = "2026-04-04-result-no-queue"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="result-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser_file = next(item for item in files if item["file_path"] == "src/parser.py")
    _classify_file(client, engagement_key, int(parser_file["id"]), "critical", 95)

    result_response = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-results",
        json={
            "file_id": parser_file["id"],
            "agent_name": "code-vuln-hunter",
            "function_name": "parse_message",
            "hypothesis": "Unchecked input from network socket",
            "evidence": "No length validation before memcpy at line 42",
            "disposition": "suspicious",
            "confidence": "medium",
            "cwe_id": "CWE-120",
            "slot_type": "NETWORK-INPUT",
            "notes": "Needs manual review",
            "cwe_coverage": _network_input_coverage(default_effort=80),
            "cross_file_triggers": [
                {
                    "file_path": "src/helpers.py",
                    "reason": "helper receives attacker-controlled bytes",
                    "vuln_class": "buffer-overflow",
                }
            ],
        },
    )
    assert result_response.status_code == 422
    assert "queue_item_id" in result_response.text


def test_analysis_result_uses_queue_item_file_id_for_coverage_gate(client, isolate_settings):
    engagement_key = "2026-04-04-direct-result-coverage"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="direct-coverage-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser_file = next(item for item in files if item["file_path"] == "src/parser.py")
    _classify_file(client, engagement_key, int(parser_file["id"]), "critical", 95)
    queue_item = _claim_file_for_analysis(
        client,
        engagement_key,
        int(parser_file["id"]),
        priority=100,
    )

    result_response = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-results",
        json={
            "queue_item_id": queue_item["id"],
            "agent_name": "code-vuln-hunter",
            "lease_token": queue_item["lease_token"],
            "function_name": "parse_message",
            "hypothesis": "All applicable network-input families were reviewed.",
            "evidence": "Direct static pass covered parser entry chains.",
            "disposition": "clean",
            "confidence": "high",
            "slot_type": "NETWORK-INPUT",
            "cwe_coverage": _network_input_coverage(default_effort=80),
        },
    )
    assert result_response.status_code == 201
    assert result_response.json()["file_id"] == parser_file["id"]

    done = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/done",
        json={
            "item_ids": [queue_item["id"]],
            "agent_name": queue_item["assigned_agent"],
            "lease_token": queue_item["lease_token"],
            "disposition": "clean",
            "cwe_coverage": _network_input_coverage(default_effort=80),
            "notes": "Reviewed",
        },
    )
    assert done.status_code == 200

    coverage = client.get(
        f"/engagements/{engagement_key}/assessment/code/coverage?repo_id={repo['id']}"
    )
    assert coverage.status_code == 200
    payload = coverage.json()
    assert payload["by_classification"]["critical"]["analyzed"] == 1
    assert payload["confidence"]["unresolved_needs_context"] == 0
    assert payload["gate"]["passed"] is True


def test_analysis_result_rejects_file_id_mismatched_with_queue_item(client, isolate_settings):
    engagement_key = "2026-04-04-result-file-mismatch"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="file-mismatch-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser_file = next(item for item in files if item["file_path"] == "src/parser.py")
    helper_file = next(item for item in files if item["file_path"] == "src/helpers.py")
    _classify_file(client, engagement_key, int(parser_file["id"]), "critical", 95)
    queue_item = _claim_file_for_analysis(client, engagement_key, int(parser_file["id"]))

    result_response = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-results",
        json={
            "queue_item_id": queue_item["id"],
            "file_id": helper_file["id"],
            "agent_name": "code-vuln-hunter",
            "lease_token": queue_item["lease_token"],
            "function_name": "parse_message",
            "hypothesis": "Payload file_id should not override the queue item.",
            "evidence": "The queue item belongs to src/parser.py.",
            "disposition": "clean",
            "confidence": "medium",
        },
    )
    assert result_response.status_code == 400
    assert "does not match the queue item" in result_response.json()["detail"]


def test_analysis_results_dedupe_cross_file_triggers_across_writers(client, isolate_settings):
    engagement_key = "2026-04-09-analysis-result-trigger-dedupe"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="trigger-dedupe-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser_file = next(item for item in files if item["file_path"] == "src/parser.py")
    helper_file = next(item for item in files if item["file_path"] == "src/helpers.py")
    _classify_file(client, engagement_key, int(parser_file["id"]), "critical", 95)
    _classify_file(client, engagement_key, int(helper_file["id"]), "high", 80)
    queue_item = _claim_file_for_analysis(client, engagement_key, int(parser_file["id"]))

    payload = {
        "queue_item_id": queue_item["id"],
        "agent_name": "code-vuln-hunter",
        "lease_token": queue_item["lease_token"],
        "function_name": "parse_message",
        "hypothesis": "Shared helper may reintroduce taint.",
        "evidence": "helper normalizes attacker-controlled bytes.",
        "disposition": "clean",
        "confidence": "medium",
        "notes": "follow-up helper review needed",
        "cross_file_triggers": [
            {
                "file_path": "src/helpers.py",
                "reason": "shared parser helper",
                "vuln_class": "web-app-injection",
            }
        ],
    }

    first = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-results",
        json=payload,
    )
    assert first.status_code == 201

    second = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-results",
        json=payload | {"notes": "second writer confirmed the same follow-up"},
    )
    assert second.status_code == 201

    coverage = client.get(
        f"/engagements/{engagement_key}/assessment/code/coverage?repo_id={repo['id']}"
    )
    assert coverage.status_code == 200
    assert coverage.json()["trigger_summary"]["pending"] == 1

    # Verify it shows up in results listing
    results_list = client.get(
        f"/engagements/{engagement_key}/assessment/code/analysis-results?file_id={parser_file['id']}"
    )
    assert results_list.status_code == 200
    assert len(results_list.json()) == 2


def test_analysis_results_include_linked_finding_lifecycle(client, isolate_settings):
    engagement_key = "2026-04-04-analysis-result-finding-lifecycle"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="finding-lifecycle-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser_file = next(item for item in files if item["file_path"] == "src/parser.py")

    finding = client.post(
        f"/engagements/{engagement_key}/assessment/findings",
        json={
            "slug": "CH-777",
            "title": "Suppressed parser finding",
            "severity": "medium",
            "workflow_status": "false_positive",
            "verification_state": "verified",
            "verification_disposition": "false_positive",
            "defect_family": "integer-overflow",
            "root_cause_key": "suppressed-parser-finding",
            "auth_context": "anonymous",
            "canonical_location": "file:src/parser.py:10",
            "summary": "Verifier suppressed the finding.",
            "evidence_ref": "tools/analysis-state/finding.json",
            "notes": "Killed by verifier.",
            "source_name": "code-vuln-verifier",
            "details": {
                "kill_check": 2,
                "kill_reason": "Upper-bound guard is complete.",
                "evidence": "validate_length() blocks the arithmetic path.",
                "impact": "No live issue.",
            },
            "provenance": {"verified_by": "code-vuln-verifier"},
            "links": [],
        },
    )
    assert finding.status_code == 201
    _classify_file(client, engagement_key, int(parser_file["id"]), "critical", 95)
    queue_item = _claim_file_for_analysis(client, engagement_key, int(parser_file["id"]))

    result_response = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-results",
        json={
            "queue_item_id": queue_item["id"],
            "agent_name": "code-vuln-hunter",
            "lease_token": queue_item["lease_token"],
            "function_name": "parse_message",
            "hypothesis": "Potential parser overflow",
            "evidence": "Attacker-controlled data reaches arithmetic.",
            "disposition": "finding",
            "confidence": "high",
            "finding_slug": "CH-777",
            "cwe_id": "CWE-190",
            "slot_type": "NETWORK-INPUT",
            "notes": "Original hunt output.",
        },
    )
    assert result_response.status_code == 201
    assert result_response.json()["finding_workflow_status"] == "false_positive"
    assert result_response.json()["finding_verification_state"] == "verified"
    assert result_response.json()["finding_verification_disposition"] == "false_positive"

    results_list = client.get(
        f"/engagements/{engagement_key}/assessment/code/analysis-results?file_id={parser_file['id']}"
    )
    assert results_list.status_code == 200
    assert len(results_list.json()) == 1
    assert results_list.json()[0]["finding_workflow_status"] == "false_positive"
    assert results_list.json()[0]["finding_verification_state"] == "verified"
    assert results_list.json()[0]["finding_verification_disposition"] == "false_positive"


def test_coverage_detail_cwe(client, isolate_settings):
    """GET coverage?detail=cwe returns files with applicable_families and
    cwe_coverage, using max-effort merge semantics across multiple queue done calls."""
    engagement_key = "2026-04-04-cwe-detail"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="cwe-detail-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser_file = next(item for item in files if item["file_path"] == "src/parser.py")
    helper_file = next(item for item in files if item["file_path"] == "src/helpers.py")
    _classify_file(client, engagement_key, int(parser_file["id"]), "critical", 95)
    _classify_file(client, engagement_key, int(helper_file["id"]), "high", 70)

    # Create two queue items for parser_file to test max-effort merge
    queue_response = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue",
        json={
            "items": [
                {"file_id": parser_file["id"], "priority": 90, "slot_types": ["NETWORK-INPUT"]},
                {"file_id": parser_file["id"], "priority": 85, "slot_types": ["NETWORK-INPUT"]},
            ]
        },
    )
    assert queue_response.status_code == 201

    # Fetch and complete first item with partial coverage
    claimed1 = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/fetch",
        json={"limit": 1, "agent_name": "hunter-a"},
    )
    item1 = claimed1.json()[0]
    client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/done",
        json={
            "item_ids": [item1["id"]],
            "agent_name": item1["assigned_agent"],
            "lease_token": item1["lease_token"],
            "disposition": "clean",
            "notes": "Pass 1",
            "cwe_coverage": _network_input_coverage(
                default_effort=70,
                overrides={
                    "web-app-injection": {
                        "effort": 60,
                        "entry_chains_traced": 2,
                        "functions_analyzed": 5,
                        "total_entry_chains": 8,
                    },
                    "ssrf": {
                        "effort": 80,
                        "entry_chains_traced": 1,
                        "functions_analyzed": 2,
                        "total_entry_chains": 3,
                    },
                },
            ),
        },
    )

    # Fetch and complete second item with better coverage for one family
    claimed2 = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/fetch",
        json={"limit": 1, "agent_name": "hunter-b"},
    )
    item2 = claimed2.json()[0]
    client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/done",
        json={
            "item_ids": [item2["id"]],
            "agent_name": item2["assigned_agent"],
            "lease_token": item2["lease_token"],
            "disposition": "clean",
            "notes": "Pass 2",
            "cwe_coverage": _network_input_coverage(
                default_effort=70,
                overrides={
                    "web-app-injection": {
                        "effort": 90,
                        "entry_chains_traced": 3,
                        "functions_analyzed": 7,
                        "total_entry_chains": 8,
                        "notes": "full trace",
                    },
                    "ssrf": {
                        "effort": 70,
                        "entry_chains_traced": 2,
                        "functions_analyzed": 3,
                        "total_entry_chains": 3,
                    },
                },
            ),
        },
    )

    # Get CWE detail
    coverage = client.get(
        f"/engagements/{engagement_key}/assessment/code/coverage?repo_id={repo['id']}&detail=cwe"
    )
    assert coverage.status_code == 200
    payload = coverage.json()
    assert "files" in payload

    # Parser file should have max-effort merged coverage
    parser_entry = next(f for f in payload["files"] if f["file_id"] == parser_file["id"])
    assert parser_entry["classification"] == "critical"
    assert "NETWORK-INPUT" in parser_entry["slot_types"]
    assert len(parser_entry["applicable_families"]) > 0

    # Check max-effort merge: web-app-injection should be 90 (max of 60, 90)
    injection_entry = next(e for e in parser_entry["cwe_coverage"] if e["family"] == "web-app-injection")
    assert injection_entry["effort"] == 90
    # entry_chains_traced should be summed: 2 + 3 = 5
    assert injection_entry["entry_chains_traced"] == 5
    # functions_analyzed takes max: max(5, 7) = 7
    assert injection_entry["functions_analyzed"] == 7
    # total_entry_chains takes max: max(8, 8) = 8
    assert injection_entry["total_entry_chains"] == 8
    # notes takes latest non-empty
    assert injection_entry["notes"] == "full trace"

    # ssrf should be 80 (max of 80, 70)
    ssrf_entry = next(e for e in parser_entry["cwe_coverage"] if e["family"] == "ssrf")
    assert ssrf_entry["effort"] == 80
    # entry_chains_traced summed: 1 + 2 = 3
    assert ssrf_entry["entry_chains_traced"] == 3
    # functions_analyzed takes max: max(2, 3) = 3
    assert ssrf_entry["functions_analyzed"] == 3
    # total_entry_chains takes max: max(3, 3) = 3
    assert ssrf_entry["total_entry_chains"] == 3

    # Helper file should appear (classified as high) but with empty cwe_coverage
    helper_entry = next(f for f in payload["files"] if f["file_id"] == helper_file["id"])
    assert helper_entry["classification"] == "high"
    assert helper_entry["cwe_coverage"] == []

    # Standard coverage fields should still be present
    assert "total_files" in payload
    assert "by_classification" in payload
    assert "gate" in payload


def test_coverage_integrity_warns_when_no_results_recorded(client, isolate_settings):
    """Completing a queue item with high effort but zero analysis results triggers a warning."""
    engagement_key = "2026-05-12-integrity-no-results"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="integrity-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser_file = next(item for item in files if item["file_path"] == "src/parser.py")

    # Set total_functions so the integrity check has something to compare
    client.patch(
        f"/engagements/{engagement_key}/assessment/code/files/{parser_file['id']}",
        json={"total_functions": 10},
    )
    _classify_file(client, engagement_key, int(parser_file["id"]), "critical", 95)
    queue_item = _claim_file_for_analysis(client, engagement_key, int(parser_file["id"]))

    # Complete WITHOUT recording any analysis results
    done = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/done",
        json={
            "item_ids": [queue_item["id"]],
            "agent_name": queue_item["assigned_agent"],
            "lease_token": queue_item["lease_token"],
            "disposition": "clean",
            "cwe_coverage": _network_input_coverage(
                default_effort=80,
                overrides={"web-app-injection": {"effort": 80, "functions_analyzed": 8}},
            ),
            "notes": "Reviewed",
        },
    )
    assert done.status_code == 200
    integrity = done.json()["coverage_integrity"]
    assert integrity["plausible"] is False
    assert integrity["actual_result_rows"] == 0
    assert len(integrity["warnings"]) > 0


def test_coverage_integrity_passes_with_matching_results(client, isolate_settings):
    """Proper analysis results backing the coverage claims produces no warnings."""
    engagement_key = "2026-05-12-integrity-passes"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="integrity-pass-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser_file = next(item for item in files if item["file_path"] == "src/parser.py")

    client.patch(
        f"/engagements/{engagement_key}/assessment/code/files/{parser_file['id']}",
        json={"total_functions": 5},
    )
    _classify_file(client, engagement_key, int(parser_file["id"]), "critical", 95)
    queue_item = _claim_file_for_analysis(client, engagement_key, int(parser_file["id"]))

    # Record analysis results for distinct functions
    for func_name in ["parse_message", "validate_input", "handle_request", "process_data"]:
        client.post(
            f"/engagements/{engagement_key}/assessment/code/analysis-results",
            json={
                "queue_item_id": queue_item["id"],
                "agent_name": "code-vuln-hunter",
                "lease_token": queue_item["lease_token"],
                "function_name": func_name,
                "hypothesis": f"Check {func_name}",
                "evidence": "No issues found",
                "disposition": "clean",
                "confidence": "high",
            },
        )

    done = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/done",
        json={
            "item_ids": [queue_item["id"]],
            "agent_name": queue_item["assigned_agent"],
            "lease_token": queue_item["lease_token"],
            "disposition": "clean",
            "cwe_coverage": _network_input_coverage(
                default_effort=80,
                overrides={"web-app-injection": {"effort": 85, "functions_analyzed": 5}},
            ),
            "notes": "Thorough review",
        },
    )
    assert done.status_code == 200
    integrity = done.json()["coverage_integrity"]
    assert integrity["plausible"] is True
    assert integrity["actual_result_rows"] == 4
    assert integrity["distinct_functions_with_results"] == 4
    assert len(integrity["warnings"]) == 0


def test_coverage_integrity_warns_claimed_exceeds_total(client, isolate_settings):
    """Claiming more functions_analyzed than total_functions on file triggers a warning."""
    engagement_key = "2026-05-12-integrity-exceeds"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="integrity-exceeds-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser_file = next(item for item in files if item["file_path"] == "src/parser.py")

    client.patch(
        f"/engagements/{engagement_key}/assessment/code/files/{parser_file['id']}",
        json={"total_functions": 3},
    )
    _classify_file(client, engagement_key, int(parser_file["id"]), "critical", 95)
    queue_item = _claim_file_for_analysis(client, engagement_key, int(parser_file["id"]))

    # Record 2 results
    for func_name in ["func_a", "func_b"]:
        client.post(
            f"/engagements/{engagement_key}/assessment/code/analysis-results",
            json={
                "queue_item_id": queue_item["id"],
                "agent_name": "code-vuln-hunter",
                "lease_token": queue_item["lease_token"],
                "function_name": func_name,
                "hypothesis": "Check",
                "evidence": "Clean",
                "disposition": "clean",
            },
        )

    done = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/done",
        json={
            "item_ids": [queue_item["id"]],
            "agent_name": queue_item["assigned_agent"],
            "lease_token": queue_item["lease_token"],
            "disposition": "clean",
            "cwe_coverage": _network_input_coverage(
                default_effort=70,
                overrides={"web-app-injection": {"effort": 70, "functions_analyzed": 10}},
            ),
            "notes": "Done",
        },
    )
    assert done.status_code == 200
    integrity = done.json()["coverage_integrity"]
    assert integrity["plausible"] is False
    assert any("exceeds" in w for w in integrity["warnings"])


def test_coverage_integrity_skips_not_applicable_entries(client, isolate_settings):
    """Not-applicable entries do not trigger integrity warnings."""
    engagement_key = "2026-05-12-integrity-na"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="integrity-na-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser_file = next(item for item in files if item["file_path"] == "src/parser.py")

    client.patch(
        f"/engagements/{engagement_key}/assessment/code/files/{parser_file['id']}",
        json={"total_functions": 5},
    )
    _classify_file(client, engagement_key, int(parser_file["id"]), "critical", 95)
    queue_item = _claim_file_for_analysis(client, engagement_key, int(parser_file["id"]))

    # Record 2 results — covers the non-NA families adequately
    for func_name in ["main_handler", "auth_check"]:
        client.post(
            f"/engagements/{engagement_key}/assessment/code/analysis-results",
            json={
                "queue_item_id": queue_item["id"],
                "agent_name": "code-vuln-hunter",
                "lease_token": queue_item["lease_token"],
                "function_name": func_name,
                "hypothesis": "Check",
                "evidence": "Clean",
                "disposition": "clean",
            },
        )

    # Coverage with some families as not_applicable
    coverage = [
        {"family": "web-app-injection", "effort": 70, "functions_analyzed": 2},
        {"family": "web-app-auth", "effort": 70, "functions_analyzed": 2},
        {"family": "ssrf", "disposition": "not_applicable", "effort": 0, "functions_analyzed": 0},
        {"family": "open-redirect", "disposition": "not_applicable", "effort": 0, "functions_analyzed": 0},
        {"family": "path-traversal", "effort": 70, "functions_analyzed": 2},
        {"family": "algorithmic-dos", "disposition": "not_applicable", "effort": 0, "functions_analyzed": 0},
    ]

    done = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/done",
        json={
            "item_ids": [queue_item["id"]],
            "agent_name": queue_item["assigned_agent"],
            "lease_token": queue_item["lease_token"],
            "disposition": "clean",
            "cwe_coverage": coverage,
            "notes": "Done",
        },
    )
    assert done.status_code == 200
    integrity = done.json()["coverage_integrity"]
    assert integrity["plausible"] is True
    assert len(integrity["warnings"]) == 0


def test_coverage_integrity_graceful_when_total_functions_zero(client, isolate_settings):
    """Files without structural index (total_functions=0) degrade gracefully."""
    engagement_key = "2026-05-12-integrity-no-index"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="integrity-no-index-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser_file = next(item for item in files if item["file_path"] == "src/parser.py")

    # Do NOT set total_functions — defaults to 0
    _classify_file(client, engagement_key, int(parser_file["id"]), "critical", 95)
    queue_item = _claim_file_for_analysis(client, engagement_key, int(parser_file["id"]))

    # Record 1 result
    client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-results",
        json={
            "queue_item_id": queue_item["id"],
            "agent_name": "code-vuln-hunter",
            "lease_token": queue_item["lease_token"],
            "function_name": "main_entry",
            "hypothesis": "Check",
            "evidence": "Clean",
            "disposition": "clean",
        },
    )

    done = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/done",
        json={
            "item_ids": [queue_item["id"]],
            "agent_name": queue_item["assigned_agent"],
            "lease_token": queue_item["lease_token"],
            "disposition": "clean",
            "cwe_coverage": _network_input_coverage(
                default_effort=70,
                overrides={"web-app-injection": {"effort": 70, "functions_analyzed": 5}},
            ),
            "notes": "Done",
        },
    )
    assert done.status_code == 200
    integrity = done.json()["coverage_integrity"]
    # total_functions=0 means "exceeds" and "effort with 0 rows" checks are skipped
    assert integrity["total_functions_on_file"] == 0
    # May still warn about ratio (1 distinct function vs 5 claimed = 0.2 < 0.3)
    # but no "exceeds total_functions" warning
    assert not any("exceeds" in w for w in integrity["warnings"])
