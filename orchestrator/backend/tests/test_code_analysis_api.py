from __future__ import annotations

import json
from pathlib import Path


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
                "approved_findings": [],
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


def test_context_creation_returns_ids_and_queue_fetch_returns_joined_work_items(client, isolate_settings):
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

    contexts_response = client.post(
        f"/engagements/{engagement_key}/assessment/code/contexts",
        json={
            "contexts": [
                {
                    "file_id": parser_file["id"],
                    "function_name": "parse_message",
                    "start_line": 10,
                    "end_line": 30,
                    "slot_types": ["NETWORK-INPUT"],
                    "call_chain": {"callers": [], "callees": [{"function": "sink"}]},
                    "data_flow": {"untrusted_params": ["data"]},
                    "cross_refs": [],
                    "guard_annotations": [{"type": "length_check", "line": 12}],
                    "sink_annotations": [{"type": "BUFFER-WRITE", "line": 22}],
                    "audit_metadata": {"cross_ref_usage": {"tool": "grep", "queries": ["rg parse_message"]}},
                    "context_text": "def parse_message(data):\n    sink(data)\n",
                }
            ]
        },
    )
    assert contexts_response.status_code == 201
    contexts_payload = contexts_response.json()
    assert contexts_payload["inserted"] == 1
    assert len(contexts_payload["contexts"]) == 1
    context = contexts_payload["contexts"][0]
    assert context["id"] > 0
    assert context["audit_metadata"]["cross_ref_usage"]["tool"] == "grep"

    file_after_context = client.get(
        f"/engagements/{engagement_key}/assessment/code/files/{parser_file['id']}"
    )
    assert file_after_context.status_code == 200
    assert file_after_context.json()["analysis_status"] == "context_built"

    # File-only queue items (no context_id) are now valid for the file-direct flow
    queue_without_context = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue",
        json={"items": [{"file_id": parser_file["id"], "priority": 95}]},
    )
    assert queue_without_context.status_code == 201

    queue_response = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue",
        json={
            "items": [
                {
                    "context_id": context["id"],
                    "file_id": parser_file["id"],
                    "priority": 95,
                }
            ]
        },
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
    assert len(payload) == 2

    # One item should be file-only (context=None), the other has a context
    file_only_item = next(item for item in payload if item["context"] is None)
    context_item = next(item for item in payload if item["context"] is not None)

    # Verify the file-only item
    assert file_only_item["status"] == "processing"
    assert file_only_item["file"]["id"] == parser_file["id"]
    assert file_only_item["repo"]["id"] == repo["id"]

    # Verify the context-backed item
    assert context_item["status"] == "processing"
    assert context_item["context"]["id"] == context["id"]
    assert context_item["context"]["slot_types"] == ["NETWORK-INPUT"]
    assert context_item["context"]["call_chain"]["callees"][0]["function"] == "sink"
    assert context_item["context"]["audit_metadata"]["cross_ref_usage"]["tool"] == "grep"
    assert context_item["file"]["id"] == parser_file["id"]
    assert context_item["file"]["file_path"] == "src/parser.py"
    assert context_item["repo"]["id"] == repo["id"]
    assert context_item["repo"]["lsp_config"]["ctags"]["available"] is True

    file_after_fetch = client.get(
        f"/engagements/{engagement_key}/assessment/code/files/{parser_file['id']}"
    )
    assert file_after_fetch.status_code == 200
    assert file_after_fetch.json()["analysis_status"] in ("queued", "in_progress")


def test_analysis_completion_rolls_up_context_and_file_coverage(client, isolate_settings):
    engagement_key = "2026-04-04-code-coverage"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="coverage-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser_file = next(item for item in files if item["file_path"] == "src/parser.py")
    _classify_file(client, engagement_key, int(parser_file["id"]), "critical", 100)

    contexts_response = client.post(
        f"/engagements/{engagement_key}/assessment/code/contexts",
        json={
            "contexts": [
                {
                    "file_id": parser_file["id"],
                    "function_name": "parse_message",
                    "start_line": 10,
                    "end_line": 30,
                    "slot_types": ["NETWORK-INPUT"],
                    "call_chain": {"callers": [], "callees": []},
                    "data_flow": {"untrusted_params": ["data"]},
                    "cross_refs": [],
                    "guard_annotations": [],
                    "sink_annotations": [],
                    "audit_metadata": {"cross_ref_usage": {"tool": "lsp", "queries": ["go-to-definition(parse_message)"]}},
                    "context_text": "def parse_message(data):\n    return data\n",
                }
            ]
        },
    )
    context = contexts_response.json()["contexts"][0]

    queue_response = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue",
        json={
            "items": [
                {
                    "context_id": context["id"],
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
            "context_id": context["id"],
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
        json={"item_ids": [queue_item["id"]], "disposition": "clean", "notes": "Reviewed"},
    )
    assert done.status_code == 200
    assert done.json()["updated"] == 1

    context_rows = client.get(
        f"/engagements/{engagement_key}/assessment/code/contexts?file_id={parser_file['id']}"
    )
    assert context_rows.status_code == 200
    assert context_rows.json()[0]["analysis_status"] == "analyzed"

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
    assert payload["function_level"]["analyzed"] == 1
    assert payload["gate"]["passed"] is True


def test_coverage_gate_stays_closed_until_queue_items_are_completed(client, isolate_settings):
    engagement_key = "2026-04-04-code-gate"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="gate-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser_file = next(item for item in files if item["file_path"] == "src/parser.py")
    _classify_file(client, engagement_key, int(parser_file["id"]), "critical", 100)

    contexts_response = client.post(
        f"/engagements/{engagement_key}/assessment/code/contexts",
        json={
            "contexts": [
                {
                    "file_id": parser_file["id"],
                    "function_name": "parse_message",
                    "start_line": 10,
                    "end_line": 30,
                    "slot_types": ["NETWORK-INPUT"],
                    "call_chain": {"callers": [], "callees": []},
                    "data_flow": {"untrusted_params": ["data"]},
                    "cross_refs": [],
                    "guard_annotations": [],
                    "sink_annotations": [],
                    "context_text": "def parse_message(data):\n    return data\n",
                }
            ]
        },
    )
    context = contexts_response.json()["contexts"][0]

    queue_response = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue",
        json={"items": [{"context_id": context["id"], "file_id": parser_file["id"], "priority": 100}]},
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
            "context_id": context["id"],
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
    assert done.status_code == 200

    coverage_after_done = client.get(
        f"/engagements/{engagement_key}/assessment/code/coverage?repo_id={repo['id']}"
    )
    assert coverage_after_done.status_code == 200
    assert coverage_after_done.json()["gate"]["passed"] is True


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


def test_code_analysis_endpoints_reject_foreign_engagement_ids(client, isolate_settings):
    first_key = "2026-04-04-code-owner-a"
    second_key = "2026-04-04-code-owner-b"
    write_engagement(isolate_settings["engagements_dir"], first_key)
    write_engagement(isolate_settings["engagements_dir"], second_key)

    repo = _create_repo(client, first_key, repo_key="owned-repo")
    files = _create_files(client, first_key, int(repo["id"]))
    parser_file = next(item for item in files if item["file_path"] == "src/parser.py")
    _classify_file(client, first_key, int(parser_file["id"]), "critical", 95)

    contexts_response = client.post(
        f"/engagements/{first_key}/assessment/code/contexts",
        json={
            "contexts": [
                {
                    "file_id": parser_file["id"],
                    "function_name": "parse_message",
                    "start_line": 1,
                    "end_line": 2,
                    "slot_types": ["NETWORK-INPUT"],
                    "call_chain": {},
                    "data_flow": {},
                    "cross_refs": [],
                    "guard_annotations": [],
                    "sink_annotations": [],
                    "context_text": "def parse_message(data):\n    return data\n",
                }
            ]
        },
    )
    context = contexts_response.json()["contexts"][0]

    queue_response = client.post(
        f"/engagements/{first_key}/assessment/code/analysis-queue",
        json={"items": [{"context_id": context["id"], "file_id": parser_file["id"], "priority": 90}]},
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

    foreign_context = client.post(
        f"/engagements/{second_key}/assessment/code/contexts",
        json={
            "contexts": [
                {
                    "file_id": parser_file["id"],
                    "function_name": "foreign",
                    "start_line": 1,
                    "end_line": 1,
                    "slot_types": [],
                    "call_chain": {},
                    "data_flow": {},
                    "cross_refs": [],
                    "guard_annotations": [],
                    "sink_annotations": [],
                    "context_text": "pass\n",
                }
            ]
        },
    )
    assert foreign_context.status_code == 404

    foreign_queue = client.post(
        f"/engagements/{second_key}/assessment/code/analysis-queue",
        json={"items": [{"context_id": context["id"], "file_id": parser_file["id"], "priority": 50}]},
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
            "context_id": context["id"],
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
    assert work_item["context"] is None
    assert work_item["batch_theme"] == "network-input-analysis"
    assert work_item["slot_types"] == ["NETWORK-INPUT", "FILE-CONTENT"]
    assert work_item["guidance_hypotheses"] == ["Check for buffer overflow in parse()"]
    assert work_item["file"]["id"] == parser_file["id"]
    assert work_item["file"]["file_path"] == "src/parser.py"
    assert work_item["repo"]["id"] == repo["id"]

    # Complete with cwe_coverage payload
    cwe_coverage_data = [
        {"family": "web-app-injection", "effort": 85, "entry_chains_traced": 3},
        {"family": "path-traversal", "effort": 70, "entry_chains_traced": 2},
    ]
    done = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/done",
        json={
            "item_ids": [work_item["id"]],
            "disposition": "clean",
            "notes": "Reviewed all sinks",
            "cwe_coverage": cwe_coverage_data,
            "cross_file_triggers": [{"file_path": "src/helpers.py", "reason": "shared parser util"}],
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
    cwe_coverage = [
        {"family": "sql-injection", "effort": 90, "entry_chains_traced": 5},
        {"family": "ssrf", "effort": 60, "entry_chains_traced": 1},
    ]
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
    assert "sql-injection" in families_covered
    assert "ssrf" in families_covered


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
            "cwe_coverage": [{"family": "buffer-overflow", "effort": 75}],
            "cross_file_triggers": [{"file_path": "src/helpers.py"}],
        },
    )
    assert result_response.status_code == 201
    result = result_response.json()
    assert result["queue_item_id"] is None
    assert result["context_id"] is None
    assert result["file_id"] == parser_file["id"]
    assert result["cwe_coverage"] == [{"family": "buffer-overflow", "effort": 75}]
    assert result["cross_file_triggers"] == [{"file_path": "src/helpers.py"}]

    # Verify it shows up in results listing
    results_list = client.get(
        f"/engagements/{engagement_key}/assessment/code/analysis-results?file_id={parser_file['id']}"
    )
    assert results_list.status_code == 200
    assert len(results_list.json()) == 1


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
            "cwe_coverage": [
                {"family": "web-app-injection", "effort": 60, "entry_chains_traced": 2},
                {"family": "ssrf", "effort": 80, "entry_chains_traced": 1},
            ],
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
            "cwe_coverage": [
                {"family": "web-app-injection", "effort": 90, "entry_chains_traced": 3},
                {"family": "ssrf", "effort": 70, "entry_chains_traced": 2},
            ],
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

    # ssrf should be 80 (max of 80, 70)
    ssrf_entry = next(e for e in parser_entry["cwe_coverage"] if e["family"] == "ssrf")
    assert ssrf_entry["effort"] == 80
    # entry_chains_traced summed: 1 + 2 = 3
    assert ssrf_entry["entry_chains_traced"] == 3

    # Helper file should appear (classified as high) but with empty cwe_coverage
    helper_entry = next(f for f in payload["files"] if f["file_id"] == helper_file["id"])
    assert helper_entry["classification"] == "high"
    assert helper_entry["cwe_coverage"] == []

    # Standard coverage fields should still be present
    assert "total_files" in payload
    assert "by_classification" in payload
    assert "gate" in payload
