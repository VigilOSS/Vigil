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

    queue_without_context = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue",
        json={"items": [{"file_id": parser_file["id"], "priority": 95}]},
    )
    assert queue_without_context.status_code == 422

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

    fetch_response = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/fetch",
        json={"limit": 1, "agent_name": "code-vuln-hunter"},
    )
    assert fetch_response.status_code == 200
    payload = fetch_response.json()
    assert len(payload) == 1
    work_item = payload[0]
    assert work_item["status"] == "processing"
    assert work_item["context"]["id"] == context["id"]
    assert work_item["context"]["slot_types"] == ["NETWORK-INPUT"]
    assert work_item["context"]["call_chain"]["callees"][0]["function"] == "sink"
    assert work_item["file"]["id"] == parser_file["id"]
    assert work_item["file"]["file_path"] == "src/parser.py"


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
        },
    )
    assert analysis_result.status_code == 201

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
    assert payload["by_classification"]["critical"]["analyzed"] == 1
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
