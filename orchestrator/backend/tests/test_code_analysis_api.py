from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

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
    response = client.post(
        f"/engagements/{engagement_key}/assessment/code/repos",
        json=_repo_payload(repo_key, f"/tmp/{repo_key}"),
    )
    assert response.status_code == 201
    return response.json()


def _create_files(client, engagement_key: str, repo_id: int) -> list[dict[str, object]]:
    response = client.post(
        f"/engagements/{engagement_key}/assessment/code/files",
        json={
            "repo_id": repo_id,
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
    assert response.status_code == 201

    files_response = client.get(
        f"/engagements/{engagement_key}/assessment/code/files?repo_id={repo_id}&limit=20"
    )
    assert files_response.status_code == 200
    return files_response.json()


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
        json={"item_ids": [queue_item["id"]], "disposition": "clean", "notes": "Reviewed"},
    )
    assert done.status_code == 400
    assert "cwe_coverage is required" in done.json()["detail"]

    done = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/done",
        json={
            "item_ids": [queue_item["id"]],
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
            "UPDATE code_analysis_queue SET consumed_at = ? WHERE id = ?",
            (stale_iso, queue_item["id"]),
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
    unique_files = client.post(
        f"/engagements/{engagement_key}/assessment/code/files",
        json={
            "repo_id": repo_a["id"],
            "files": [
                {
                    "file_path": "repo_a_only.py",
                    "language": "python",
                    "loc": 10,
                    "file_hash": "repo-a-only",
                    "header_snippet": "",
                    "git_churn_score": 0,
                    "has_past_cve_fix": False,
                }
            ],
        },
    )
    assert unique_files.status_code == 201
    unique_files = client.post(
        f"/engagements/{engagement_key}/assessment/code/files",
        json={
            "repo_id": repo_b["id"],
            "files": [
                {
                    "file_path": "repo_b_only.py",
                    "language": "python",
                    "loc": 10,
                    "file_hash": "repo-b-only",
                    "header_snippet": "",
                    "git_churn_score": 0,
                    "has_past_cve_fix": False,
                }
            ],
        },
    )
    assert unique_files.status_code == 201

    finding_a = client.post(
        f"/engagements/{engagement_key}/assessment/findings",
        json={
            "slug": "CODE-A-001",
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
                    "target_ref": "ROOT-A",
                }
            ],
        },
    )
    assert finding_a.status_code == 201

    finding_b = client.post(
        f"/engagements/{engagement_key}/assessment/findings",
        json={
            "slug": "CODE-B-001",
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
                    "target_ref": "ROOT-B",
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

    finding = client.post(
        f"/engagements/{engagement_key}/assessment/findings",
        json={
            "slug": "CODE-VARIANT-001",
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
                    "target_ref": "ROOT-PARSER",
                }
            ],
        },
    )
    assert finding.status_code == 201

    baseline = client.get(f"/engagements/{engagement_key}/assessment/code/coverage?repo_id={repo['id']}")
    assert baseline.status_code == 200
    assert baseline.json()["findings_summary"]["variant_count"] == 1

    verify = client.post(
        f"/engagements/{engagement_key}/assessment/findings/CODE-VARIANT-001/verify",
        json={
            "disposition": "false_positive",
            "reason_code": "guarded-path",
            "reason_text": "Guard closes the variant in production.",
            "artifact_ref": "tools/analysis-state/code-verification/CODE-VARIANT-001.json",
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

    finding = client.post(
        f"/engagements/{engagement_key}/assessment/findings",
        json={
            "slug": "WEB-VARIANT-001",
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
                    "target_ref": "ROOT-HTTP",
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

    shared_files_a = client.post(
        f"/engagements/{engagement_key}/assessment/code/files",
        json={
            "repo_id": repo_a["id"],
            "files": [
                {
                    "file_path": "src/shared.py",
                    "language": "python",
                    "loc": 30,
                    "file_hash": "shared-a",
                    "header_snippet": "",
                    "git_churn_score": 0,
                    "has_past_cve_fix": False,
                }
            ],
        },
    )
    assert shared_files_a.status_code == 201
    shared_files_b = client.post(
        f"/engagements/{engagement_key}/assessment/code/files",
        json={
            "repo_id": repo_b["id"],
            "files": [
                {
                    "file_path": "src/shared.py",
                    "language": "python",
                    "loc": 45,
                    "file_hash": "shared-b",
                    "header_snippet": "",
                    "git_churn_score": 0,
                    "has_past_cve_fix": False,
                }
            ],
        },
    )
    assert shared_files_b.status_code == 201

    finding = client.post(
        f"/engagements/{engagement_key}/assessment/findings",
        json={
            "slug": "SHARED-PATH-001",
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
                    "target_ref": "ROOT-SHARED",
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

    foreign_files = client.post(
        f"/engagements/{second_key}/assessment/code/files",
        json={
            "repo_id": repo["id"],
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
            "function_name": "parse_message",
            "hypothesis": "",
            "evidence": "",
            "disposition": "clean",
            "confidence": "medium",
            "notes": "",
        },
    )
    assert foreign_result.status_code == 404


def test_create_repo_upserts_existing_repo_key_within_engagement(client, isolate_settings):
    engagement_key = "2026-04-04-code-upsert"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)

    first = client.post(
        f"/engagements/{engagement_key}/assessment/code/repos",
        json=_repo_payload("same-repo", "/tmp/same-repo"),
    )
    assert first.status_code == 201

    second = client.post(
        f"/engagements/{engagement_key}/assessment/code/repos",
        json={
            **_repo_payload("same-repo", "/tmp/updated-same-repo"),
            "branch": "release",
            "total_loc": 999,
        },
    )
    assert second.status_code == 201

    first_payload = first.json()
    second_payload = second.json()
    assert second_payload["id"] == first_payload["id"]
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
            "UPDATE code_analysis_queue SET consumed_at = ? WHERE id = ?",
            ("2020-01-01T00:00:00Z", queue_item["id"]),
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


def test_analysis_result_with_optional_queue_item_id(client, isolate_settings):
    """Analysis results can be recorded with queue_item_id=None."""
    engagement_key = "2026-04-04-result-no-queue"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="result-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser_file = next(item for item in files if item["file_path"] == "src/parser.py")
    _classify_file(client, engagement_key, int(parser_file["id"]), "critical", 95)

    # Record an analysis result without a queue_item_id
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
    assert result_response.status_code == 201
    result = result_response.json()
    assert result["queue_item_id"] is None
    assert result["file_id"] == parser_file["id"]
    assert result["cwe_coverage"] == _network_input_coverage(default_effort=80)
    assert result["cross_file_triggers"] == [
        {
            "file_path": "src/helpers.py",
            "reason": "helper receives attacker-controlled bytes",
            "vuln_class": "buffer-overflow",
        }
    ]

    file_row = client.get(
        f"/engagements/{engagement_key}/assessment/code/files/{parser_file['id']}"
    )
    assert file_row.status_code == 200
    assert file_row.json()["analysis_status"] == "analyzed"

    coverage = client.get(
        f"/engagements/{engagement_key}/assessment/code/coverage?repo_id={repo['id']}"
    )
    assert coverage.status_code == 200
    coverage_payload = coverage.json()
    assert coverage_payload["by_classification"]["critical"]["analyzed"] == 1
    assert coverage_payload["gate"]["passed"] is False
    assert coverage_payload["trigger_summary"]["pending"] == 1

    cwe_detail = client.get(
        f"/engagements/{engagement_key}/assessment/code/coverage?repo_id={repo['id']}&detail=cwe"
    )
    assert cwe_detail.status_code == 200
    parser_detail = next(f for f in cwe_detail.json()["files"] if f["file_id"] == parser_file["id"])
    assert parser_detail["cwe_coverage"]
    assert next(e for e in parser_detail["cwe_coverage"] if e["family"] == "web-app-injection")["effort"] == 80


def test_direct_analysis_result_without_queue_can_satisfy_coverage_gate(client, isolate_settings):
    engagement_key = "2026-04-04-direct-result-coverage"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="direct-coverage-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser_file = next(item for item in files if item["file_path"] == "src/parser.py")
    _classify_file(client, engagement_key, int(parser_file["id"]), "critical", 95)

    result_response = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-results",
        json={
            "file_id": parser_file["id"],
            "agent_name": "code-vuln-hunter",
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

    coverage = client.get(
        f"/engagements/{engagement_key}/assessment/code/coverage?repo_id={repo['id']}"
    )
    assert coverage.status_code == 200
    payload = coverage.json()
    assert payload["by_classification"]["critical"]["analyzed"] == 1
    assert payload["confidence"]["unresolved_needs_context"] == 0
    assert payload["gate"]["passed"] is True


def test_analysis_results_dedupe_cross_file_triggers_across_writers(client, isolate_settings):
    engagement_key = "2026-04-09-analysis-result-trigger-dedupe"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="trigger-dedupe-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser_file = next(item for item in files if item["file_path"] == "src/parser.py")
    helper_file = next(item for item in files if item["file_path"] == "src/helpers.py")
    _classify_file(client, engagement_key, int(parser_file["id"]), "critical", 95)
    _classify_file(client, engagement_key, int(helper_file["id"]), "high", 80)

    payload = {
        "file_id": parser_file["id"],
        "agent_name": "code-vuln-hunter",
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

    result_response = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-results",
        json={
            "file_id": parser_file["id"],
            "agent_name": "code-vuln-hunter",
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
