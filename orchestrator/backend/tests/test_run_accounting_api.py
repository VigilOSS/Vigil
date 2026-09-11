from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3

import pytest

from app import db as db_module
from app.config import settings
from app.services import state_manager
from tests.test_engagements_api import write_engagement


ENGAGEMENT_KEY = "2026-09-09-run-accounting"
BASE = f"/engagements/{ENGAGEMENT_KEY}/assessment"


def _seed(client, isolate_settings) -> None:
    write_engagement(isolate_settings["engagements_dir"], key=ENGAGEMENT_KEY)
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200
    response = client.post(
        f"{BASE}/dispatches",
        json={
            "agent_id": "HUNT-RUN-1",
            "agent_role": "code-vuln-hunter",
            "task": "review declared source roots",
            "requested_model": "gpt-5.6-sol",
            "requested_reasoning": "xhigh",
            "client_name": "codex",
            "requested_client": "claude",
            "launcher_effective_client": "codex",
            "provider_observed_client": "unknown",
            "source_revision": "revision-123",
            "operator_instruction_path": "AGENTS.md",
            "operator_instruction_sha256": "a" * 64,
            "specialist_instruction_path": ".codex/agents/code-vuln-hunter.md",
            "specialist_instruction_sha256": "b" * 64,
            "instruction_identity_status": "verified",
            "instructions_stale": False,
        },
    )
    assert response.status_code == 201, response.text


def _observe_provider_client(client, value: str) -> None:
    engagement_id = client.get(f"/engagements/{ENGAGEMENT_KEY}").json()["id"]
    with db_module.get_connection() as connection:
        connection.execute(
            """
            UPDATE assessment_dispatches
            SET provider_observed_client = ?
            WHERE engagement_id = ? AND agent_id = 'HUNT-RUN-1'
            """,
            (value, engagement_id),
        )


def _inventory_commitment(target_key: str, sources: list[dict]) -> dict:
    identities = sorted(
        hashlib.sha256(
            json.dumps(
                source,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")
        ).hexdigest()
        for source in sources
        if source["target_key"] == target_key
    )
    digest = hashlib.sha256(
        json.dumps(
            {
                "version": "v1",
                "target_key": target_key,
                "source_identity_sha256": identities,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()
    return {
        "inventory_commitment_version": "v1",
        "inventory_count": len(identities),
        "inventory_digest": digest,
    }


def _create_scan(
    client,
    *,
    run_uuid: str = "scan-001",
    committed_sources: list[dict] | None = None,
) -> dict:
    source_generations = [
        {
            "target_key": "service-a",
            "generation": 4,
            "manifest_digest": "c" * 64,
        },
        {
            "target_key": "shared-library",
            "generation": 2,
            "manifest_digest": "d" * 64,
        },
    ]
    if committed_sources is not None:
        for generation in source_generations:
            generation.update(
                _inventory_commitment(generation["target_key"], committed_sources)
            )
    response = client.post(
        f"{BASE}/assessment-runs",
        json={
            "run_uuid": run_uuid,
            "run_kind": "code",
            "run_purpose": "scan",
            "producer_dispatch_agent_id": "HUNT-RUN-1",
            "target_identity": {
                "scope": "repository",
                "repositories": ["service-a", "shared-library"],
            },
            "source_generations": source_generations,
            "exclusions": [
                {
                    "target_key": "service-a",
                    "path": "vendor/",
                    "reason": "declared vendor boundary",
                }
            ],
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _replace_run_accounting_with_phase2_schema(db_path) -> None:
    with sqlite3.connect(db_path) as connection:
        dispatch_id = connection.execute(
            "SELECT id FROM assessment_dispatches WHERE agent_id = 'HUNT-RUN-1'"
        ).fetchone()[0]
        for table in (
            "assessment_run_comparisons",
            "assessment_run_code_receipt_links",
            "assessment_run_discovery_passes",
            "assessment_run_tool_signals",
            "assessment_run_candidate_events",
            "assessment_run_candidates",
            "assessment_run_obligation_events",
            "assessment_run_obligations",
            "assessment_run_source_reads",
            "assessment_run_sources",
            "assessment_run_lifecycle_events",
            "assessment_finding_proof_receipts",
            "assessment_proof_receipts",
            "assessment_runs",
        ):
            connection.execute(f"DROP TABLE {table}")
        connection.execute(
            """
            CREATE TABLE assessment_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                run_uuid TEXT NOT NULL,
                run_kind TEXT NOT NULL,
                producer_dispatch_id INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'started',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(engagement_id, run_uuid)
            )
            """
        )
        connection.execute(
            """
            INSERT INTO assessment_runs (
                engagement_id, run_uuid, run_kind, producer_dispatch_id, status
            ) VALUES (1, 'phase2-existing', 'shared', ?, 'started')
            """,
            (dispatch_id,),
        )


def _source(
    *,
    target_key: str,
    path: str,
    content: bytes,
    encoding: str = "utf-8",
    parser_status: str = "parsed",
    parser_error: str = "",
) -> dict:
    return {
        "target_key": target_key,
        "declared_root": ".",
        "path": path,
        "content_sha256": hashlib.sha256(content).hexdigest(),
        "byte_size": len(content),
        "line_count": content.count(b"\n") + 1,
        "encoding": encoding,
        "inventory_status": "included",
        "exclusion_reason": "",
        "parser_status": parser_status,
        "parser_error": parser_error,
    }


def _record_discovery_pass(
    client,
    run: dict,
    *,
    identity_key: str,
    terminal_reason: str = "frontier_exhausted",
) -> dict:
    command = client.post(
        f"{BASE}/command-runs",
        json={
            "run_uuid": f"discovery-command-{run['id']}-{identity_key}",
            "agent_name": "HUNT-RUN-1",
            "command": "review declared discovery frontier",
            "tool_name": "review",
            "phase": "code-hunt",
            "status": "completed",
            "return_code": 0,
            "started_at": "2026-09-10T12:00:00Z",
            "completed_at": "2026-09-10T12:00:01Z",
        },
    )
    assert command.status_code == 201, command.text
    proof = client.post(
        f"{BASE}/proof-receipts",
        json={
            "run_id": run["id"],
            "evidence_kind": "command",
            "command_run_id": command.json()["id"],
            "expected_result": "execute the pass against its recorded frontier",
            "observed_result": "pass completed with attributed workflow evidence",
        },
    )
    assert proof.status_code == 201, proof.text
    response = client.post(
        f"{BASE}/assessment-runs/{run['id']}/discovery-passes",
        json={
            "identity_key": identity_key,
            "dispatch_agent_id": "HUNT-RUN-1",
            "frontier_identity_sha256": hashlib.sha256(
                identity_key.encode()
            ).hexdigest(),
            "terminal_reason": terminal_reason,
            "candidate_identity_keys": [],
            "proof_receipt_ids": [proof.json()["id"]],
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_code_scan_completion_requires_evidence_backed_terminal_discovery(
    client, isolate_settings
) -> None:
    _seed(client, isolate_settings)
    inventory = [
        {
            "target_key": "service-a",
            "declared_root": ".",
            "path": "generated/manifest.json",
            "content_sha256": "f" * 64,
            "byte_size": 0,
            "line_count": 0,
            "encoding": "utf-8",
            "inventory_status": "excluded",
            "exclusion_reason": "declared generated boundary",
            "parser_status": "not_applicable",
            "parser_error": "",
        },
        {
            "target_key": "shared-library",
            "declared_root": ".",
            "path": "generated/manifest.json",
            "content_sha256": "e" * 64,
            "byte_size": 0,
            "line_count": 0,
            "encoding": "utf-8",
            "inventory_status": "excluded",
            "exclusion_reason": "declared generated boundary",
            "parser_status": "not_applicable",
            "parser_error": "",
        },
    ]

    missing = _create_scan(
        client, run_uuid="discovery-terminal-missing", committed_sources=inventory
    )
    assert client.patch(
        f"{BASE}/assessment-runs/{missing['id']}", json={"status": "running"}
    ).status_code == 200
    assert client.post(
        f"{BASE}/assessment-runs/{missing['id']}/sources", json={"sources": inventory}
    ).status_code == 201
    missing_terminal = client.patch(
        f"{BASE}/assessment-runs/{missing['id']}", json={"status": "completed"}
    )
    assert missing_terminal.status_code == 200, missing_terminal.text
    assert missing_terminal.json()["status"] == "partial"
    assert any(
        blocker["code"] == "discovery_terminal_missing"
        for blocker in missing_terminal.json()["seal"]["blockers"]
    )

    failed = _create_scan(
        client, run_uuid="discovery-terminal-failed", committed_sources=inventory
    )
    assert client.patch(
        f"{BASE}/assessment-runs/{failed['id']}", json={"status": "running"}
    ).status_code == 200
    assert client.post(
        f"{BASE}/assessment-runs/{failed['id']}/sources", json={"sources": inventory}
    ).status_code == 201
    _record_discovery_pass(
        client,
        failed,
        identity_key="failed-pass",
        terminal_reason="failed",
    )
    failed_terminal = client.patch(
        f"{BASE}/assessment-runs/{failed['id']}", json={"status": "completed"}
    )
    assert failed_terminal.status_code == 200, failed_terminal.text
    assert failed_terminal.json()["status"] == "partial"
    assert any(
        blocker["code"] == "discovery_unresolved"
        for blocker in failed_terminal.json()["seal"]["blockers"]
    )

    capped = _create_scan(
        client, run_uuid="discovery-terminal-capped", committed_sources=inventory
    )
    assert client.patch(
        f"{BASE}/assessment-runs/{capped['id']}", json={"status": "running"}
    ).status_code == 200
    assert client.post(
        f"{BASE}/assessment-runs/{capped['id']}/sources", json={"sources": inventory}
    ).status_code == 201
    _record_discovery_pass(
        client,
        capped,
        identity_key="capped-pass",
        terminal_reason="cap_reached",
    )
    capped_terminal = client.patch(
        f"{BASE}/assessment-runs/{capped['id']}", json={"status": "completed"}
    )
    assert capped_terminal.status_code == 200, capped_terminal.text
    assert capped_terminal.json()["status"] == "partial"
    assert any(
        blocker["code"] == "discovery_unresolved"
        for blocker in capped_terminal.json()["seal"]["blockers"]
    )

    completed = _create_scan(
        client, run_uuid="discovery-terminal-complete", committed_sources=inventory
    )
    assert client.patch(
        f"{BASE}/assessment-runs/{completed['id']}", json={"status": "running"}
    ).status_code == 200
    assert client.post(
        f"{BASE}/assessment-runs/{completed['id']}/sources", json={"sources": inventory}
    ).status_code == 201
    _record_discovery_pass(client, completed, identity_key="complete-pass")
    completed_terminal = client.patch(
        f"{BASE}/assessment-runs/{completed['id']}", json={"status": "completed"}
    )
    assert completed_terminal.status_code == 200, completed_terminal.text
    assert completed_terminal.json()["status"] == "completed"


def test_terminal_seal_freezes_dispatch_and_instruction_provenance(
    client, isolate_settings
) -> None:
    _seed(client, isolate_settings)
    _observe_provider_client(client, "opencode")
    engagement_id = client.get(f"/engagements/{ENGAGEMENT_KEY}").json()["id"]
    state_manager.update_dispatch(
        engagement_id,
        agent_id="HUNT-RUN-1",
        actual_model="gpt-5.6-sol",
        actual_reasoning="high",
    )

    run = _create_scan(client, run_uuid="dispatch-seal")
    terminal = client.patch(
        f"{BASE}/assessment-runs/{run['id']}",
        json={"status": "failed", "reason": "pinned provenance"},
    )
    assert terminal.status_code == 200, terminal.text
    provenance = terminal.json()["seal"]["dispatch_provenance"]
    assert provenance == {
        "dispatch_id": run["producer_dispatch_id"],
        "agent_id": "HUNT-RUN-1",
        "agent_role": "code-vuln-hunter",
        "requested_model": "gpt-5.6-sol",
        "actual_model": "gpt-5.6-sol",
        "requested_reasoning": "xhigh",
        "actual_reasoning": "high",
        "client_name": "codex",
        "requested_client": "claude",
        "launcher_effective_client": "codex",
        "provider_observed_client": "opencode",
        "source_revision": "revision-123",
        "operator_instruction_path": "AGENTS.md",
        "operator_instruction_sha256": "a" * 64,
        "specialist_instruction_path": ".codex/agents/code-vuln-hunter.md",
        "specialist_instruction_sha256": "b" * 64,
        "instruction_identity_status": "verified",
        "instructions_stale": False,
    }

    state_manager.update_dispatch(
        engagement_id,
        agent_id="HUNT-RUN-1",
        actual_model="different-model",
        actual_reasoning="low",
    )
    reread = client.get(f"{BASE}/assessment-runs/{run['id']}")
    assert reread.status_code == 200, reread.text
    assert reread.json()["seal"]["dispatch_provenance"] == provenance


def test_live_run_projection_preserves_distinct_client_identities(
    client, isolate_settings
) -> None:
    _seed(client, isolate_settings)
    _observe_provider_client(client, "opencode")

    run = _create_scan(client, run_uuid="client-identity-projection")
    expected = {
        "client_name": "codex",
        "requested_client": "claude",
        "launcher_effective_client": "codex",
        "provider_observed_client": "opencode",
    }
    assert {key: run[key] for key in expected} == expected

    fetched = client.get(f"{BASE}/assessment-runs/{run['id']}")
    listed = client.get(f"{BASE}/assessment-runs")
    assert fetched.status_code == 200, fetched.text
    assert listed.status_code == 200, listed.text
    assert {key: fetched.json()[key] for key in expected} == expected
    listed_run = next(row for row in listed.json() if row["id"] == run["id"])
    assert {key: listed_run[key] for key in expected} == expected


def test_run_dispatch_listing_includes_producer_and_linked_reader(
    client, isolate_settings
) -> None:
    _seed(client, isolate_settings)
    reader = client.post(
        f"{BASE}/dispatches",
        json={
            "agent_id": "READ-RUN-2",
            "agent_role": "code-vuln-verifier",
            "task": "read exact source range",
            "requested_model": "gpt-5.6-sol",
            "requested_reasoning": "high",
            "client_name": "codex",
            "source_revision": "revision-123",
            "operator_instruction_path": "AGENTS.md",
            "operator_instruction_sha256": "a" * 64,
            "specialist_instruction_path": ".codex/agents/code-vuln-verifier.md",
            "specialist_instruction_sha256": "e" * 64,
            "instruction_identity_status": "verified",
            "instructions_stale": False,
            "skills": "code-finding-verification",
        },
    )
    assert reader.status_code == 201, reader.text

    run = _create_scan(client, run_uuid="linked-dispatches")
    assert client.patch(
        f"{BASE}/assessment-runs/{run['id']}", json={"status": "running"}
    ).status_code == 200
    content = b"linked dispatch\n"
    sources = client.post(
        f"{BASE}/assessment-runs/{run['id']}/sources",
        json={"sources": [_source(target_key="service-a", path="src/read.py", content=content)]},
    )
    assert sources.status_code == 201, sources.text
    source_id = sources.json()[0]["id"]
    observed = client.post(
        f"{BASE}/assessment-runs/{run['id']}/source-reads",
        json={
            "source_id": source_id,
            "dispatch_agent_id": "READ-RUN-2",
            "attempt": 1,
            "byte_start": 0,
            "byte_end": len(content),
            "line_start": 1,
            "line_end": 2,
        },
    )
    assert observed.status_code == 201, observed.text

    dispatches = client.get(
        f"{BASE}/assessment-runs/{run['id']}/dispatches?limit=1&offset=0"
    )
    assert dispatches.status_code == 200, dispatches.text
    first_page = dispatches.json()
    assert first_page["total"] == 2
    assert first_page["has_more"] is True
    second_page = client.get(
        f"{BASE}/assessment-runs/{run['id']}/dispatches?limit=1&offset=1"
    ).json()
    assert second_page["has_more"] is False
    records = first_page["items"] + second_page["items"]
    assert [row["agent_id"] for row in records] == ["HUNT-RUN-1", "READ-RUN-2"]
    assert records[1]["specialist_instruction_sha256"] == "e" * 64
    assert records[1]["instructions_stale"] is False


def test_scan_lifecycle_inventory_reads_and_parser_debt_are_durable(
    client, isolate_settings
) -> None:
    _seed(client, isolate_settings)
    run = _create_scan(client)
    assert run["status"] == "queued"
    assert run["run_purpose"] == "scan"
    assert run["target_identity"]["repositories"] == [
        "service-a",
        "shared-library",
    ]

    running = client.patch(
        f"{BASE}/assessment-runs/{run['id']}", json={"status": "running"}
    )
    assert running.status_code == 200, running.text
    assert running.json()["status"] == "running"

    powershell = "Write-Output 'ok'\n".encode("utf-16")
    inventory = client.post(
        f"{BASE}/assessment-runs/{run['id']}/sources",
        json={
            "sources": [
                _source(
                    target_key="service-a",
                    path="scripts/Inspect.ps1",
                    content=powershell,
                    encoding="utf-16",
                ),
                _source(
                    target_key="shared-library",
                    path="src/broken.py",
                    content=b"def broken(:\n",
                    parser_status="failed",
                    parser_error="syntax error at byte 11",
                ),
                {
                    "target_key": "service-a",
                    "declared_root": ".",
                    "path": "vendor/generated.js",
                    "content_sha256": "e" * 64,
                    "byte_size": 9_000_001,
                    "line_count": 300_000,
                    "encoding": "utf-8",
                    "inventory_status": "excluded",
                    "exclusion_reason": "declared vendor boundary",
                    "parser_status": "not_applicable",
                    "parser_error": "",
                },
            ]
        },
    )
    assert inventory.status_code == 201, inventory.text
    rows = inventory.json()
    assert len(rows) == 3
    powershell_row = next(row for row in rows if row["path"].endswith("Inspect.ps1"))

    read = client.post(
        f"{BASE}/assessment-runs/{run['id']}/source-reads",
        json={
            "source_id": powershell_row["id"],
            "dispatch_agent_id": "HUNT-RUN-1",
            "attempt": 1,
            "byte_start": 0,
            "byte_end": len(powershell),
            "line_start": 1,
            "line_end": 2,
        },
    )
    assert read.status_code == 201, read.text
    assert read.json()["source_sha256"] == powershell_row["content_sha256"]
    assert read.json()["encoding"] == "utf-16"

    obligations = client.get(
        f"{BASE}/assessment-runs/{run['id']}/obligations",
        params={"limit": 10, "offset": 0},
    )
    assert obligations.status_code == 200, obligations.text
    manual = next(
        row
        for row in obligations.json()["items"]
        if row["obligation_kind"] == "manual_enumeration"
    )
    assert manual["status"] == "open"
    assert manual["hard"] is True
    assert manual["object_key"] == "shared-library:src/broken.py"

    detail = client.get(f"{BASE}/assessment-runs/{run['id']}")
    assert detail.status_code == 200, detail.text
    assert [event["to_status"] for event in detail.json()["lifecycle_history"]] == [
        "queued",
        "running",
    ]
    assert detail.json()["counts"]["inventory_total"] == 3
    assert detail.json()["counts"]["source_reads"] == 1


def test_source_read_ranges_cannot_claim_lines_outside_the_inventory(
    client, isolate_settings
) -> None:
    _seed(client, isolate_settings)
    run = _create_scan(client, run_uuid="line-range")
    assert client.patch(
        f"{BASE}/assessment-runs/{run['id']}", json={"status": "running"}
    ).status_code == 200
    source = client.post(
        f"{BASE}/assessment-runs/{run['id']}/sources",
        json={
            "sources": [
                _source(
                    target_key="service-a",
                    path="src/two-lines.py",
                    content=b"ONE = 1\n",
                )
            ]
        },
    ).json()[0]
    invalid = client.post(
        f"{BASE}/assessment-runs/{run['id']}/source-reads",
        json={
            "source_id": source["id"],
            "dispatch_agent_id": "HUNT-RUN-1",
            "attempt": 1,
            "byte_start": 0,
            "byte_end": source["byte_size"],
            "line_start": 1,
            "line_end": source["line_count"] + 1,
        },
    )
    assert invalid.status_code == 400, invalid.text


def test_scan_cannot_complete_when_a_declared_source_generation_has_no_inventory(
    client, isolate_settings
) -> None:
    _seed(client, isolate_settings)
    run = _create_scan(client, run_uuid="missing-target-inventory")
    assert client.patch(
        f"{BASE}/assessment-runs/{run['id']}", json={"status": "running"}
    ).status_code == 200
    source = client.post(
        f"{BASE}/assessment-runs/{run['id']}/sources",
        json={
            "sources": [
                _source(
                    target_key="service-a",
                    path="src/only-target.py",
                    content=b"ONLY = True\n",
                )
            ]
        },
    ).json()[0]
    source_read = client.post(
        f"{BASE}/assessment-runs/{run['id']}/source-reads",
        json={
            "source_id": source["id"],
            "dispatch_agent_id": "HUNT-RUN-1",
            "attempt": 1,
            "byte_start": 0,
            "byte_end": source["byte_size"],
            "line_start": 1,
            "line_end": source["line_count"],
        },
    )
    assert source_read.status_code == 201, source_read.text

    terminal = client.patch(
        f"{BASE}/assessment-runs/{run['id']}", json={"status": "completed"}
    )
    assert terminal.status_code == 200, terminal.text
    assert terminal.json()["status"] == "partial"
    blocker = next(
        row
        for row in terminal.json()["seal"]["blockers"]
        if row["code"] == "source_inventory_missing"
    )
    assert blocker["object_type"] == "source_generation"
    assert blocker["object_id"] == "shared-library"


def test_scan_cannot_complete_with_malformed_source_generation_identity(
    client, isolate_settings
) -> None:
    _seed(client, isolate_settings)
    created = client.post(
        f"{BASE}/assessment-runs",
        json={
            "run_uuid": "malformed-generation",
            "run_kind": "code",
            "run_purpose": "scan",
            "producer_dispatch_agent_id": "HUNT-RUN-1",
            "target_identity": {"repositories": ["service-a"]},
            "source_generations": [{"target_key": "service-a"}],
        },
    )
    assert created.status_code == 201, created.text
    run = created.json()
    assert client.patch(
        f"{BASE}/assessment-runs/{run['id']}", json={"status": "running"}
    ).status_code == 200
    source = client.post(
        f"{BASE}/assessment-runs/{run['id']}/sources",
        json={
            "sources": [
                _source(
                    target_key="service-a",
                    path="src/current.py",
                    content=b"CURRENT = True\n",
                )
            ]
        },
    ).json()[0]
    source_read = client.post(
        f"{BASE}/assessment-runs/{run['id']}/source-reads",
        json={
            "source_id": source["id"],
            "dispatch_agent_id": "HUNT-RUN-1",
            "attempt": 1,
            "byte_start": 0,
            "byte_end": source["byte_size"],
            "line_start": 1,
            "line_end": source["line_count"],
        },
    )
    assert source_read.status_code == 201, source_read.text

    terminal = client.patch(
        f"{BASE}/assessment-runs/{run['id']}", json={"status": "completed"}
    )
    assert terminal.status_code == 200, terminal.text
    assert terminal.json()["status"] == "partial"
    assert any(
        blocker["code"] == "source_generation_invalid"
        for blocker in terminal.json()["seal"]["blockers"]
    )


def test_scan_completion_requires_the_exact_declared_inventory_commitment(
    client, isolate_settings
) -> None:
    _seed(client, isolate_settings)
    expected_sources = [
        _source(
            target_key="service-a",
            path="src/first.py",
            content=b"FIRST = True\n",
        ),
        _source(
            target_key="service-a",
            path="src/omitted.py",
            content=b"OMITTED = True\n",
        ),
        {
            "target_key": "shared-library",
            "declared_root": ".",
            "path": "generated/manifest.json",
            "content_sha256": "f" * 64,
            "byte_size": 0,
            "line_count": 0,
            "encoding": "utf-8",
            "inventory_status": "excluded",
            "exclusion_reason": "declared generated boundary",
            "parser_status": "not_applicable",
            "parser_error": "",
        },
    ]
    run = _create_scan(
        client,
        run_uuid="strict-subset",
        committed_sources=expected_sources,
    )
    assert client.patch(
        f"{BASE}/assessment-runs/{run['id']}", json={"status": "running"}
    ).status_code == 200
    uploaded = client.post(
        f"{BASE}/assessment-runs/{run['id']}/sources",
        json={"sources": [expected_sources[0], expected_sources[2]]},
    )
    assert uploaded.status_code == 201, uploaded.text
    included = uploaded.json()[0]
    assert client.post(
        f"{BASE}/assessment-runs/{run['id']}/source-reads",
        json={
            "source_id": included["id"],
            "dispatch_agent_id": "HUNT-RUN-1",
            "attempt": 1,
            "byte_start": 0,
            "byte_end": included["byte_size"],
            "line_start": 1,
            "line_end": included["line_count"],
        },
    ).status_code == 201

    terminal = client.patch(
        f"{BASE}/assessment-runs/{run['id']}", json={"status": "completed"}
    )
    assert terminal.status_code == 200, terminal.text
    assert terminal.json()["status"] == "partial"
    blocker = next(
        item
        for item in terminal.json()["seal"]["blockers"]
        if item["code"] == "source_inventory_incomplete"
    )
    assert blocker["object_id"] == "service-a"
    assert "expected 2" in blocker["message"]
    assert "recorded 1" in blocker["message"]


def test_interrupted_batched_inventory_preserves_rows_and_commitment_debt(
    client, isolate_settings
) -> None:
    _seed(client, isolate_settings)
    expected_sources = [
        _source(
            target_key="service-a",
            path="src/first.py",
            content=b"FIRST = True\n",
        ),
        _source(
            target_key="service-a",
            path="src/pending.py",
            content=b"PENDING = True\n",
        ),
        {
            "target_key": "shared-library",
            "declared_root": ".",
            "path": "generated/manifest.json",
            "content_sha256": "f" * 64,
            "byte_size": 0,
            "line_count": 0,
            "encoding": "utf-8",
            "inventory_status": "excluded",
            "exclusion_reason": "declared generated boundary",
            "parser_status": "not_applicable",
            "parser_error": "",
        },
    ]
    run = _create_scan(
        client,
        run_uuid="interrupted-inventory-batches",
        committed_sources=expected_sources,
    )
    assert client.patch(
        f"{BASE}/assessment-runs/{run['id']}", json={"status": "running"}
    ).status_code == 200
    first_batch = client.post(
        f"{BASE}/assessment-runs/{run['id']}/sources",
        json={"sources": [expected_sources[0], expected_sources[2]]},
    )
    assert first_batch.status_code == 201, first_batch.text

    interrupted = client.patch(
        f"{BASE}/assessment-runs/{run['id']}",
        json={"status": "interrupted", "reason": "uploader stopped"},
    )
    assert interrupted.status_code == 200, interrupted.text
    assert interrupted.json()["status"] == "interrupted"
    assert interrupted.json()["seal"]["counts"]["inventory_total"] == 2
    assert any(
        blocker["code"] == "source_inventory_incomplete"
        and blocker["object_id"] == "service-a"
        for blocker in interrupted.json()["seal"]["blockers"]
    )
    page = client.get(
        f"{BASE}/assessment-runs/{run['id']}/sources",
        params={"limit": 10, "offset": 0},
    )
    assert page.status_code == 200, page.text
    assert page.json()["total"] == 2


def test_inventory_over_request_limit_completes_after_bounded_batch_reconciliation(
    client, isolate_settings
) -> None:
    _seed(client, isolate_settings)
    sources = [
        {
            "target_key": "shared-library" if index == 10_000 else "service-a",
            "declared_root": ".",
            "path": f"excluded/generated-{index:05d}.js",
            "content_sha256": hashlib.sha256(str(index).encode()).hexdigest(),
            "byte_size": 0,
            "line_count": 0,
            "encoding": "utf-8",
            "inventory_status": "excluded",
            "exclusion_reason": "declared generated boundary",
            "parser_status": "not_applicable",
            "parser_error": "",
        }
        for index in range(10_001)
    ]
    run = _create_scan(
        client,
        run_uuid="large-inventory",
        committed_sources=sources,
    )
    assert client.patch(
        f"{BASE}/assessment-runs/{run['id']}", json={"status": "running"}
    ).status_code == 200
    for offset in range(0, len(sources), 1000):
        response = client.post(
            f"{BASE}/assessment-runs/{run['id']}/sources",
            json={"sources": sources[offset : offset + 1000]},
        )
        assert response.status_code == 201, response.text
    _record_discovery_pass(client, run, identity_key="large-inventory-terminal")

    terminal = client.patch(
        f"{BASE}/assessment-runs/{run['id']}", json={"status": "completed"}
    )
    assert terminal.status_code == 200, terminal.text
    assert terminal.json()["status"] == "completed"
    assert terminal.json()["seal"]["counts"]["inventory_total"] == 10_001


def test_completion_seals_partial_with_open_debt_and_preserves_all_records(
    client, isolate_settings
) -> None:
    _seed(client, isolate_settings)
    run = _create_scan(client)
    assert client.patch(
        f"{BASE}/assessment-runs/{run['id']}", json={"status": "running"}
    ).status_code == 200
    inventory = client.post(
        f"{BASE}/assessment-runs/{run['id']}/sources",
        json={
            "sources": [
                _source(
                    target_key="service-a",
                    path="src/broken.py",
                    content=b"def broken(:\n",
                    parser_status="failed",
                    parser_error="syntax error",
                )
            ]
        },
    )
    assert inventory.status_code == 201, inventory.text

    terminal = client.patch(
        f"{BASE}/assessment-runs/{run['id']}", json={"status": "completed"}
    )
    assert terminal.status_code == 200, terminal.text
    body = terminal.json()
    assert body["status"] == "partial"
    assert body["seal"]["requested_status"] == "completed"
    assert body["seal"]["effective_status"] == "partial"
    # The parser failure creates two independent debts: the source was never
    # fully delivered and its structure still needs manual enumeration.
    assert body["seal"]["counts"]["open_hard_obligations"] == 2
    assert any(
        blocker["object_type"] == "obligation"
        for blocker in body["seal"]["blockers"]
    )
    assert len(body["seal_sha256"]) == 64
    assert body["seal"]["lifecycle_history"] == body["lifecycle_history"]
    assert body["finished_at"] == body["lifecycle_history"][-1]["created_at"]
    repeated = client.patch(
        f"{BASE}/assessment-runs/{run['id']}", json={"status": "completed"}
    )
    assert repeated.status_code == 200, repeated.text
    assert repeated.json() == body

    after = client.get(f"{BASE}/assessment-runs/{run['id']}").json()
    assert after["counts"]["inventory_total"] == 1
    assert after["counts"]["open_hard_obligations"] == 2
    refused = client.post(
        f"{BASE}/assessment-runs/{run['id']}/sources",
        json={
            "sources": [
                _source(
                    target_key="service-a",
                    path="src/late.py",
                    content=b"late = True\n",
                )
            ]
        },
    )
    assert refused.status_code == 409, refused.text


def test_promoted_candidate_cannot_complete_before_its_finding_is_verified(
    client, isolate_settings
) -> None:
    _seed(client, isolate_settings)
    run = _create_scan(client, run_uuid="promoted-unverified")
    assert client.patch(
        f"{BASE}/assessment-runs/{run['id']}", json={"status": "running"}
    ).status_code == 200
    source = client.post(
        f"{BASE}/assessment-runs/{run['id']}/sources",
        json={
            "sources": [
                _source(
                    target_key="service-a",
                    path="src/candidate.py",
                    content=b"VALUE = input()\n",
                )
            ]
        },
    ).json()[0]
    source_read = client.post(
        f"{BASE}/assessment-runs/{run['id']}/source-reads",
        json={
            "source_id": source["id"],
            "dispatch_agent_id": "HUNT-RUN-1",
            "attempt": 1,
            "byte_start": 0,
            "byte_end": source["byte_size"],
            "line_start": 1,
            "line_end": source["line_count"],
        },
    )
    assert source_read.status_code == 201, source_read.text
    proof = client.post(
        f"{BASE}/proof-receipts",
        json={
            "run_id": run["id"],
            "evidence_kind": "source_observation",
            "source_read_id": source_read.json()["id"],
            "observed_result": "candidate source anchor was observed",
        },
    )
    assert proof.status_code == 201, proof.text
    db_path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    with sqlite3.connect(str(db_path)) as connection:
        engagement_id = connection.execute(
            "SELECT id FROM engagements WHERE key = ?", (ENGAGEMENT_KEY,)
        ).fetchone()[0]
        cursor = connection.execute(
            """
            INSERT INTO code_repos (
                engagement_id, repo_key, name, repo_path, active_generation,
                source_manifest_digest, source_snapshot_quality
            ) VALUES (?, 'service-a', 'service-a', '/source/service-a', 4, ?, 'verified')
            """,
            (engagement_id, "c" * 64),
        )
        repo_id = int(cursor.lastrowid)
        connection.commit()
    finding = client.post(
        f"{BASE}/findings",
        json={
            "slug": "VA-900",
            "title": "Candidate requiring verification",
            "severity": "medium",
            "workflow_status": "active",
                "verification_status": "unreviewed",
                "canonical_location": "file:src/candidate.py:1",
                "source_name": "code-vuln-hunter",
                "provenance": {
                    "agent_id": "HUNT-RUN-1",
                    "code_snapshot": {
                        "repo_id": repo_id,
                        "repo_generation": 4,
                        "source_manifest_digest": "c" * 64,
                    },
                },
        },
    )
    assert finding.status_code == 201, finding.text
    candidate = client.post(
        f"{BASE}/assessment-runs/{run['id']}/candidates",
        json={
            "identity_key": "candidate:unverified",
            "target_key": "service-a",
            "source_id": source["id"],
            "source_anchor": "src/candidate.py:1",
            "vulnerability_family": "CWE-20",
            "hypothesis": "requires independent verification",
            "originating_result_id": None,
            "dispatch_agent_id": "HUNT-RUN-1",
            "proof_receipt_ids": [],
            "state": "open",
        },
    )
    assert candidate.status_code == 201, candidate.text
    promoted = client.patch(
        f"{BASE}/assessment-runs/{run['id']}/candidates/{candidate.json()['id']}",
        json={
            "state": "promoted",
            "reason": "linked for verification",
            "proof_receipt_ids": [proof.json()["id"]],
            "finding_slug": "VA-900",
        },
    )
    assert promoted.status_code == 200, promoted.text

    terminal = client.patch(
        f"{BASE}/assessment-runs/{run['id']}", json={"status": "completed"}
    )
    assert terminal.status_code == 200, terminal.text
    assert terminal.json()["status"] == "partial"
    blocker = next(
        row
        for row in terminal.json()["seal"]["blockers"]
        if row["code"] == "promoted_finding_unverified"
    )
    assert blocker["object_type"] == "finding"
    assert blocker["object_id"] == "VA-900"


def test_obligation_and_candidate_retries_are_exact_and_never_similarity_merged(
    client, isolate_settings
) -> None:
    _seed(client, isolate_settings)
    run = _create_scan(client)
    assert client.patch(
        f"{BASE}/assessment-runs/{run['id']}", json={"status": "running"}
    ).status_code == 200
    source = client.post(
        f"{BASE}/assessment-runs/{run['id']}/sources",
        json={
            "sources": [
                _source(
                    target_key="service-a",
                    path="src/path.py",
                    content=b"open(user_path)\n",
                )
            ]
        },
    ).json()[0]
    source_read = client.post(
        f"{BASE}/assessment-runs/{run['id']}/source-reads",
        json={
            "source_id": source["id"],
            "dispatch_agent_id": "HUNT-RUN-1",
            "attempt": 1,
            "byte_start": 0,
            "byte_end": source["byte_size"],
            "line_start": 1,
            "line_end": source["line_count"],
        },
    )
    assert source_read.status_code == 201, source_read.text
    proof = client.post(
        f"{BASE}/proof-receipts",
        json={
            "run_id": run["id"],
            "evidence_kind": "source_observation",
            "source_read_id": source_read.json()["id"],
            "observed_result": "exact source range settles the recorded decision",
        },
    )
    assert proof.status_code == 201, proof.text
    proof_ids = [proof.json()["id"]]

    obligation_payload = {
        "identity_key": "flow:path-input-to-open",
        "obligation_kind": "cross_file_flow",
        "object_type": "source",
        "object_key": "service-a:src/path.py",
        "hard": True,
        "status": "open",
        "resolution": "",
        "proof_receipt_ids": [],
    }
    first = client.post(
        f"{BASE}/assessment-runs/{run['id']}/obligations",
        json=obligation_payload,
    )
    retry = client.post(
        f"{BASE}/assessment-runs/{run['id']}/obligations",
        json=obligation_payload,
    )
    assert first.status_code == retry.status_code == 201
    assert retry.json()["id"] == first.json()["id"]
    unsupported_resolution = client.patch(
        f"{BASE}/assessment-runs/{run['id']}/obligations/{first.json()['id']}",
        json={
            "status": "resolved",
            "resolution": "cross-file path reviewed",
            "proof_receipt_ids": [],
        },
    )
    assert unsupported_resolution.status_code == 400, unsupported_resolution.text
    resolved = client.patch(
        f"{BASE}/assessment-runs/{run['id']}/obligations/{first.json()['id']}",
        json={
            "status": "resolved",
            "resolution": "cross-file path reviewed",
            "proof_receipt_ids": proof_ids,
        },
    )
    resolved_retry = client.patch(
        f"{BASE}/assessment-runs/{run['id']}/obligations/{first.json()['id']}",
        json={
            "status": "resolved",
            "resolution": "cross-file path reviewed",
            "proof_receipt_ids": proof_ids,
        },
    )
    assert resolved.status_code == resolved_retry.status_code == 200
    obligation_history = client.get(
        f"{BASE}/assessment-runs/{run['id']}/obligations/{first.json()['id']}/history"
    )
    assert obligation_history.status_code == 200, obligation_history.text
    assert [row["to_status"] for row in obligation_history.json()] == ["open", "resolved"]

    candidate_payload = {
        "identity_key": "candidate:path-traversal:open:line-1",
        "target_key": "service-a",
        "source_id": source["id"],
        "source_anchor": "src/path.py:1",
        "vulnerability_family": "CWE-22",
        "hypothesis": "user path reaches open",
        "originating_result_id": None,
        "dispatch_agent_id": "HUNT-RUN-1",
        "proof_receipt_ids": [],
        "state": "open",
    }
    terminal_create = client.post(
        f"{BASE}/assessment-runs/{run['id']}/candidates",
        json={
            **candidate_payload,
            "identity_key": "candidate:terminal-create",
            "state": "rejected",
        },
    )
    assert terminal_create.status_code == 422, terminal_create.text
    candidate = client.post(
        f"{BASE}/assessment-runs/{run['id']}/candidates",
        json=candidate_payload,
    )
    exact_retry = client.post(
        f"{BASE}/assessment-runs/{run['id']}/candidates",
        json=candidate_payload,
    )
    similar = client.post(
        f"{BASE}/assessment-runs/{run['id']}/candidates",
        json={
            **candidate_payload,
            "identity_key": "candidate:path-traversal:open:line-2",
            "source_anchor": "src/path.py:2",
        },
    )
    assert candidate.status_code == exact_retry.status_code == similar.status_code == 201
    assert exact_retry.json()["id"] == candidate.json()["id"]
    assert similar.json()["id"] != candidate.json()["id"]

    rejected = client.patch(
        f"{BASE}/assessment-runs/{run['id']}/candidates/{candidate.json()['id']}",
        json={
            "state": "rejected",
            "reason": "decisive invariant review",
            "proof_receipt_ids": proof_ids,
        },
    )
    rejected_retry = client.patch(
        f"{BASE}/assessment-runs/{run['id']}/candidates/{candidate.json()['id']}",
        json={
            "state": "rejected",
            "reason": "decisive invariant review",
            "proof_receipt_ids": proof_ids,
        },
    )
    assert rejected.status_code == rejected_retry.status_code == 200
    inexact_retry = client.patch(
        f"{BASE}/assessment-runs/{run['id']}/candidates/{candidate.json()['id']}",
        json={
            "state": "rejected",
            "reason": "different reason under the same terminal state",
            "proof_receipt_ids": proof_ids,
        },
    )
    assert inexact_retry.status_code == 409, inexact_retry.text
    candidate_history = client.get(
        f"{BASE}/assessment-runs/{run['id']}/candidates/{candidate.json()['id']}/history"
    )
    assert candidate_history.status_code == 200, candidate_history.text
    assert [row["to_state"] for row in candidate_history.json()] == ["open", "rejected"]
    decision_history = client.get(
        f"{BASE}/assessment-runs/{run['id']}/decision-history",
        params={"limit": 3, "offset": 0},
    )
    assert decision_history.status_code == 200, decision_history.text
    assert decision_history.json()["total"] >= 4
    assert decision_history.json()["has_more"] is True
    first_page = decision_history.json()["items"]
    second_page = client.get(
        f"{BASE}/assessment-runs/{run['id']}/decision-history",
        params={"limit": decision_history.json()["total"], "offset": 3},
    )
    assert second_page.status_code == 200, second_page.text
    assert second_page.json()["has_more"] is False
    assert {
        (row["object_type"], row["to_status"])
        for row in [*first_page, *second_page.json()["items"]]
    } >= {
        ("obligation", "open"),
        ("obligation", "resolved"),
        ("candidate", "open"),
        ("candidate", "rejected"),
    }

    conflict = client.post(
        f"{BASE}/assessment-runs/{run['id']}/candidates",
        json={**candidate_payload, "hypothesis": "different payload under same identity"},
    )
    assert conflict.status_code == 409, conflict.text


def test_typed_tool_signal_atomically_creates_one_deterministic_candidate(
    client, isolate_settings
) -> None:
    _seed(client, isolate_settings)
    run = _create_scan(client, run_uuid="typed-signal")
    assert client.patch(
        f"{BASE}/assessment-runs/{run['id']}", json={"status": "running"}
    ).status_code == 200
    source_bytes = b"int main(void) { return crash(); }\n"
    source = client.post(
        f"{BASE}/assessment-runs/{run['id']}/sources",
        json={
            "sources": [
                _source(
                    target_key="service-a",
                    path="src/crash.c",
                    content=source_bytes,
                )
            ]
        },
    ).json()[0]
    command = client.post(
        f"{BASE}/command-runs",
        json={
            "run_uuid": "typed-signal-command",
            "agent_name": "HUNT-RUN-1",
            "command": "./reproducer < crash-input",
            "tool_name": "reproducer",
            "phase": "code-verify",
            "status": "completed",
            "return_code": 1,
            "started_at": "2026-09-10T12:00:00Z",
            "completed_at": "2026-09-10T12:00:01Z",
        },
    )
    assert command.status_code == 201, command.text
    proof = client.post(
        f"{BASE}/proof-receipts",
        json={
            "run_id": run["id"],
            "evidence_kind": "command",
            "command_run_id": command.json()["id"],
            "expected_result": "the exact input reproduces the same crash",
            "observed_result": "ASan heap-use-after-free at parser.c:41",
        },
    )
    assert proof.status_code == 201, proof.text
    stale_signal_proof = client.post(
        f"{BASE}/proof-receipts",
        json={
            "run_id": run["id"],
            "evidence_kind": "command",
            "command_run_id": command.json()["id"],
            "observed_result": "a stale copy of the command result",
            "evidence_health": "stale",
        },
    )
    assert stale_signal_proof.status_code == 201, stale_signal_proof.text
    payload = {
        "identity_key": "asan:parser.c:41:heap-use-after-free",
        "signal_kind": "reproducible_crash",
        "dispatch_agent_id": "HUNT-RUN-1",
        "target_key": "service-a",
        "source_id": source["id"],
        "source_anchor": "src/crash.c:1",
        "vulnerability_family": "memory-safety",
        "hypothesis": "reproducible heap use after free",
        "observed_signature": "ASan heap-use-after-free at parser.c:41",
        "exact_input_sha256": hashlib.sha256(b"crash-input").hexdigest(),
        "command_run_id": command.json()["id"],
        "proof_receipt_ids": [proof.json()["id"]],
    }
    missing_source = client.post(
        f"{BASE}/assessment-runs/{run['id']}/tool-signals",
        json={**payload, "identity_key": "asan:missing-source", "source_id": None},
    )
    assert missing_source.status_code == 409, missing_source.text
    wrong_anchor = client.post(
        f"{BASE}/assessment-runs/{run['id']}/tool-signals",
        json={
            **payload,
            "identity_key": "asan:wrong-anchor",
            "source_anchor": "src/other.c:1",
        },
    )
    assert wrong_anchor.status_code == 409, wrong_anchor.text
    stale_signal = client.post(
        f"{BASE}/assessment-runs/{run['id']}/tool-signals",
        json={
            **payload,
            "identity_key": "asan:stale-proof",
            "proof_receipt_ids": [stale_signal_proof.json()["id"]],
        },
    )
    assert stale_signal.status_code == 400, stale_signal.text
    first = client.post(
        f"{BASE}/assessment-runs/{run['id']}/tool-signals", json=payload
    )
    retry = client.post(
        f"{BASE}/assessment-runs/{run['id']}/tool-signals", json=payload
    )
    assert first.status_code == retry.status_code == 201
    assert retry.json()["id"] == first.json()["id"]
    assert retry.json()["candidate_id"] == first.json()["candidate_id"]
    candidates = client.get(
        f"{BASE}/assessment-runs/{run['id']}/candidates?limit=10&offset=0"
    ).json()
    assert candidates["total"] == 1
    assert candidates["items"][0]["identity_key"].startswith(
        "candidate:v1:"
    )
    assert candidates["items"][0]["originating_signal_id"] == first.json()["id"]
    distinct_signal = client.post(
        f"{BASE}/assessment-runs/{run['id']}/tool-signals",
        json={**payload, "identity_key": "asan:independent-observation"},
    )
    assert distinct_signal.status_code == 201, distinct_signal.text
    assert distinct_signal.json()["candidate_id"] != first.json()["candidate_id"]

    generic_exit = client.post(
        f"{BASE}/assessment-runs/{run['id']}/tool-signals",
        json={**payload, "identity_key": "generic-exit", "signal_kind": "nonzero_exit"},
    )
    assert generic_exit.status_code == 422
    oob_artifact_path = (
        isolate_settings["engagements_dir"]
        / ENGAGEMENT_KEY
        / "evidence"
        / "oob-callback.json"
    )
    oob_artifact_path.parent.mkdir(parents=True, exist_ok=True)
    oob_artifact_path.write_text('{"interaction_id":"oob-1"}\n')
    artifact = client.post(
        f"{BASE}/artifacts",
        json={
            "path": "evidence/oob-callback.json",
            "kind": "oob_callback",
            "media_type": "application/json",
            "producer_agent_id": "HUNT-RUN-1",
            "producer_command_run_id": command.json()["id"],
        },
    )
    assert artifact.status_code == 201, artifact.text
    oob_proof = client.post(
        f"{BASE}/proof-receipts",
        json={
            "run_id": run["id"],
            "evidence_kind": "oob_event",
            "artifact_id": artifact.json()["id"],
            "observed_result": "callback artifact correlated to the exact command",
        },
    )
    assert oob_proof.status_code == 201, oob_proof.text
    oob_payload = {
        **payload,
        "identity_key": "oob:callback:1",
        "signal_kind": "attributed_oob_callback",
        "observed_signature": "oob-1",
        "exact_input_sha256": "",
        "proof_receipt_ids": [proof.json()["id"], oob_proof.json()["id"]],
    }
    missing_command = client.post(
        f"{BASE}/assessment-runs/{run['id']}/tool-signals",
        json={**oob_payload, "command_run_id": None},
    )
    assert missing_command.status_code == 400, missing_command.text
    unrelated_oob_path = (
        isolate_settings["engagements_dir"]
        / ENGAGEMENT_KEY
        / "evidence"
        / "unrelated-oob-callback.json"
    )
    unrelated_oob_path.write_text('{"interaction_id":"unrelated"}\n')
    unrelated_oob_command = client.post(
        f"{BASE}/command-runs",
        json={
            "run_uuid": "unrelated-oob-command",
            "agent_name": "HUNT-RUN-1",
            "command": "run another callback probe",
            "tool_name": "probe",
            "phase": "code-verify",
            "status": "completed",
            "return_code": 0,
            "started_at": "2026-09-10T12:00:02Z",
            "completed_at": "2026-09-10T12:00:03Z",
        },
    )
    assert unrelated_oob_command.status_code == 201, unrelated_oob_command.text
    unrelated_oob_artifact = client.post(
        f"{BASE}/artifacts",
        json={
            "path": "evidence/unrelated-oob-callback.json",
            "kind": "oob_callback",
            "media_type": "application/json",
            "producer_agent_id": "HUNT-RUN-1",
            "producer_command_run_id": unrelated_oob_command.json()["id"],
        },
    )
    assert unrelated_oob_artifact.status_code == 201, unrelated_oob_artifact.text
    unrelated_oob_proof = client.post(
        f"{BASE}/proof-receipts",
        json={
            "run_id": run["id"],
            "evidence_kind": "oob_event",
            "artifact_id": unrelated_oob_artifact.json()["id"],
            "observed_result": "a different callback probe completed",
        },
    )
    assert unrelated_oob_proof.status_code == 201, unrelated_oob_proof.text
    unrelated_oob = client.post(
        f"{BASE}/assessment-runs/{run['id']}/tool-signals",
        json={
            **oob_payload,
            "identity_key": "oob:callback:unrelated",
            "proof_receipt_ids": [
                proof.json()["id"],
                unrelated_oob_proof.json()["id"],
            ],
        },
    )
    assert unrelated_oob.status_code == 400, unrelated_oob.text
    oob_signal = client.post(
        f"{BASE}/assessment-runs/{run['id']}/tool-signals", json=oob_payload
    )
    assert oob_signal.status_code == 201, oob_signal.text


def test_automatic_tool_candidate_identity_persists_across_equivalent_scans(
    client, isolate_settings
) -> None:
    _seed(client, isolate_settings)
    source_bytes = b"int main(void) { return crash(); }\n"

    def record_signal(run_uuid: str) -> tuple[dict, str]:
        run = _create_scan(client, run_uuid=run_uuid)
        assert client.patch(
            f"{BASE}/assessment-runs/{run['id']}", json={"status": "running"}
        ).status_code == 200
        source_response = client.post(
            f"{BASE}/assessment-runs/{run['id']}/sources",
            json={
                "sources": [
                    _source(
                        target_key="service-a",
                        path="src/crash.c",
                        content=source_bytes,
                    )
                ]
            },
        )
        assert source_response.status_code == 201, source_response.text
        source = source_response.json()[0]
        command = client.post(
            f"{BASE}/command-runs",
            json={
                "run_uuid": f"{run_uuid}-signal-command",
                "agent_name": "HUNT-RUN-1",
                "command": "./reproducer < crash-input",
                "tool_name": "reproducer",
                "phase": "code-verify",
                "status": "completed",
                "return_code": 1,
                "started_at": "2026-09-10T12:00:00Z",
                "completed_at": "2026-09-10T12:00:01Z",
            },
        )
        assert command.status_code == 201, command.text
        proof = client.post(
            f"{BASE}/proof-receipts",
            json={
                "run_id": run["id"],
                "evidence_kind": "command",
                "command_run_id": command.json()["id"],
                "expected_result": "the exact input reproduces the same crash",
                "observed_result": "ASan heap-use-after-free at parser.c:41",
            },
        )
        assert proof.status_code == 201, proof.text
        signal = client.post(
            f"{BASE}/assessment-runs/{run['id']}/tool-signals",
            json={
                "identity_key": "asan:parser.c:41:heap-use-after-free",
                "signal_kind": "reproducible_crash",
                "dispatch_agent_id": "HUNT-RUN-1",
                "target_key": "service-a",
                "source_id": source["id"],
                "source_anchor": "src/crash.c:1",
                "vulnerability_family": "memory-safety",
                "hypothesis": "reproducible heap use after free",
                "observed_signature": "ASan heap-use-after-free at parser.c:41",
                "exact_input_sha256": hashlib.sha256(b"crash-input").hexdigest(),
                "command_run_id": command.json()["id"],
                "proof_receipt_ids": [proof.json()["id"]],
            },
        )
        assert signal.status_code == 201, signal.text
        candidates = client.get(
            f"{BASE}/assessment-runs/{run['id']}/candidates",
            params={"limit": 10, "offset": 0},
        )
        assert candidates.status_code == 200, candidates.text
        assert candidates.json()["total"] == 1
        return run, candidates.json()["items"][0]["identity_key"]

    baseline, baseline_identity = record_signal("stable-signal-baseline")
    current, current_identity = record_signal("stable-signal-current")

    assert current_identity == baseline_identity
    comparison = client.get(
        f"{BASE}/assessment-runs/{current['id']}/comparison",
        params={"baseline_run_id": baseline["id"]},
    )
    assert comparison.status_code == 200, comparison.text
    assert comparison.json()["classifications"] == {
        "new": [],
        "persisting": [current_identity],
        "resolved": [],
        "unknown": [],
    }


def test_cross_repository_debt_and_discovery_passes_are_explicit_and_evidence_bound(
    client, isolate_settings
) -> None:
    _seed(client, isolate_settings)
    created = client.post(
        f"{BASE}/assessment-runs",
        json={
            "run_uuid": "cross-repo-discovery",
            "run_kind": "code",
            "run_purpose": "scan",
            "producer_dispatch_agent_id": "HUNT-RUN-1",
            "target_identity": {
                "scope": "repository",
                "repositories": ["service-a"],
                "security_relevant_repositories": ["control-plane", "service-a"],
            },
            "source_generations": [
                {
                    "target_key": "service-a",
                    "generation": 4,
                    "manifest_digest": "c" * 64,
                }
            ],
        },
    )
    assert created.status_code == 201, created.text
    run = created.json()
    assert client.patch(
        f"{BASE}/assessment-runs/{run['id']}", json={"status": "running"}
    ).status_code == 200
    obligations = client.get(
        f"{BASE}/assessment-runs/{run['id']}/obligations?limit=20&offset=0"
    ).json()["items"]
    missing = next(row for row in obligations if row["object_key"] == "control-plane")
    assert missing["obligation_kind"] == "missing_dependency"
    assert missing["hard"] is True
    assert missing["status"] == "open"
    discovery_dispatch = client.post(
        f"{BASE}/dispatches",
        json={
            "agent_id": "DISCOVERY-1",
            "agent_role": "code-variant-hunter",
            "task": "review the declared discovery frontier",
            "skills": "code-variant-analysis",
        },
    )
    assert discovery_dispatch.status_code == 201, discovery_dispatch.text

    pass_command = client.post(
        f"{BASE}/command-runs",
        json={
            "run_uuid": "discovery-pass-command",
            "agent_name": "DISCOVERY-1",
            "command": "review declared frontier",
            "tool_name": "review",
            "phase": "code-hunt",
            "status": "completed",
            "return_code": 0,
            "started_at": "2026-09-10T12:00:00Z",
            "completed_at": "2026-09-10T12:00:01Z",
        },
    )
    assert pass_command.status_code == 201, pass_command.text
    proof = client.post(
        f"{BASE}/proof-receipts",
        json={
            "run_id": run["id"],
            "evidence_kind": "command",
            "command_run_id": pass_command.json()["id"],
            "expected_result": "execute the pass against the declared frontier digest",
            "observed_result": "pass process completed; comprehension is not inferred",
        },
    )
    assert proof.status_code == 201, proof.text
    unrelated_command = client.post(
        f"{BASE}/command-runs",
        json={
            "run_uuid": "unrelated-discovery-command",
            "agent_name": "HUNT-RUN-1",
            "command": "perform unrelated work",
            "tool_name": "review",
            "phase": "code-hunt",
            "status": "completed",
            "return_code": 0,
            "started_at": "2026-09-10T12:00:02Z",
            "completed_at": "2026-09-10T12:00:03Z",
        },
    )
    assert unrelated_command.status_code == 201, unrelated_command.text
    unrelated_proof = client.post(
        f"{BASE}/proof-receipts",
        json={
            "run_id": run["id"],
            "evidence_kind": "command",
            "command_run_id": unrelated_command.json()["id"],
            "observed_result": "unrelated command completed",
        },
    )
    assert unrelated_proof.status_code == 201, unrelated_proof.text
    stale_proof = client.post(
        f"{BASE}/proof-receipts",
        json={
            "run_id": run["id"],
            "evidence_kind": "command",
            "command_run_id": pass_command.json()["id"],
            "observed_result": "stale discovery artifact",
            "evidence_health": "stale",
        },
    )
    assert stale_proof.status_code == 201, stale_proof.text
    first_candidate = client.post(
        f"{BASE}/assessment-runs/{run['id']}/candidates",
        json={
            "identity_key": "candidate:pass-a",
            "target_key": "service-a",
            "source_anchor": "module:first",
            "vulnerability_family": "CWE-20",
            "hypothesis": "first pass candidate",
            "dispatch_agent_id": "HUNT-RUN-1",
        },
    )
    assert first_candidate.status_code == 201, first_candidate.text
    pass_payload = {
        "identity_key": "pass-1",
        "dispatch_agent_id": "DISCOVERY-1",
        "frontier_identity_sha256": "e" * 64,
        "terminal_reason": "frontier_exhausted",
        "candidate_identity_keys": ["candidate:pass-a"],
        "proof_receipt_ids": [proof.json()["id"]],
    }
    wrong_dispatch_proof = client.post(
        f"{BASE}/assessment-runs/{run['id']}/discovery-passes",
        json={
            **pass_payload,
            "identity_key": "pass-wrong-dispatch-proof",
            "proof_receipt_ids": [unrelated_proof.json()["id"]],
        },
    )
    assert wrong_dispatch_proof.status_code == 400, wrong_dispatch_proof.text
    mixed_dispatch_proof = client.post(
        f"{BASE}/assessment-runs/{run['id']}/discovery-passes",
        json={
            **pass_payload,
            "identity_key": "pass-mixed-dispatch-proof",
            "proof_receipt_ids": [
                proof.json()["id"],
                unrelated_proof.json()["id"],
            ],
        },
    )
    assert mixed_dispatch_proof.status_code == 400, mixed_dispatch_proof.text
    unhealthy_proof = client.post(
        f"{BASE}/assessment-runs/{run['id']}/discovery-passes",
        json={
            **pass_payload,
            "identity_key": "pass-unhealthy-proof",
            "proof_receipt_ids": [stale_proof.json()["id"]],
        },
    )
    assert unhealthy_proof.status_code == 400, unhealthy_proof.text
    discovery = client.post(
        f"{BASE}/assessment-runs/{run['id']}/discovery-passes", json=pass_payload
    )
    assert discovery.status_code == 201, discovery.text
    assert discovery.json()["candidate_delta"] == 1
    second_candidate = client.post(
        f"{BASE}/assessment-runs/{run['id']}/candidates",
        json={
            "identity_key": "candidate:pass-b",
            "target_key": "service-a",
            "source_anchor": "module:second",
            "vulnerability_family": "CWE-22",
            "hypothesis": "second pass candidate",
            "dispatch_agent_id": "HUNT-RUN-1",
        },
    )
    assert second_candidate.status_code == 201, second_candidate.text
    later = client.post(
        f"{BASE}/assessment-runs/{run['id']}/discovery-passes",
        json={
            **pass_payload,
            "identity_key": "pass-2",
            "candidate_identity_keys": ["candidate:pass-a", "candidate:pass-b"],
        },
    )
    assert later.status_code == 201, later.text
    assert later.json()["candidate_delta"] == 1
    retry = client.post(
        f"{BASE}/assessment-runs/{run['id']}/discovery-passes", json=pass_payload
    )
    assert retry.status_code == 201, retry.text
    assert retry.json()["id"] == discovery.json()["id"]
    assert retry.json()["candidate_delta"] == 1
    page = client.get(
        f"{BASE}/assessment-runs/{run['id']}/discovery-passes?limit=10&offset=0"
    )
    assert page.status_code == 200
    assert page.json()["items"][0]["terminal_reason"] == "frontier_exhausted"
    dispatches = client.get(
        f"{BASE}/assessment-runs/{run['id']}/dispatches?limit=20&offset=0"
    )
    assert dispatches.status_code == 200, dispatches.text
    assert {row["agent_id"] for row in dispatches.json()["items"]} >= {
        "HUNT-RUN-1",
        "DISCOVERY-1",
    }
    oversized_identity = client.post(
        f"{BASE}/assessment-runs/{run['id']}/discovery-passes",
        json={
            **pass_payload,
            "identity_key": "pass-oversized",
            "candidate_identity_keys": ["x" * 1025],
        },
    )
    assert oversized_identity.status_code == 422, oversized_identity.text


def test_finding_record_can_atomically_promote_its_underlying_run_candidate(
    client, isolate_settings
) -> None:
    _seed(client, isolate_settings)
    run = _create_scan(client, run_uuid="atomic-promotion")
    assert client.patch(
        f"{BASE}/assessment-runs/{run['id']}", json={"status": "running"}
    ).status_code == 200
    source = client.post(
        f"{BASE}/assessment-runs/{run['id']}/sources",
        json={
            "sources": [
                _source(
                    target_key="service-a",
                    path="src/parser.c",
                    content=b"candidate source\n",
                )
            ]
        },
    ).json()[0]
    db_path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    with sqlite3.connect(str(db_path)) as connection:
        engagement_id = connection.execute(
            "SELECT id FROM engagements WHERE key = ?", (ENGAGEMENT_KEY,)
        ).fetchone()[0]
        cursor = connection.execute(
            """
            INSERT INTO code_repos (
                engagement_id, repo_key, name, repo_path, active_generation,
                source_manifest_digest, source_snapshot_quality
            ) VALUES (?, 'service-a', 'service-a', '/source/service-a', 4, ?, 'verified')
            """,
            (engagement_id, "c" * 64),
        )
        repo_id = int(cursor.lastrowid)
        connection.commit()
    command = client.post(
        f"{BASE}/command-runs",
        json={
            "run_uuid": "atomic-promotion-command",
            "agent_name": "HUNT-RUN-1",
            "command": "review parser candidate",
            "tool_name": "review",
            "phase": "code-verify",
            "status": "completed",
            "return_code": 0,
            "started_at": "2026-09-10T12:00:00Z",
            "completed_at": "2026-09-10T12:00:01Z",
        },
    )
    assert command.status_code == 201, command.text
    proof_response = client.post(
        f"{BASE}/proof-receipts",
        json={
            "run_id": run["id"],
            "evidence_kind": "command",
            "command_run_id": command.json()["id"],
            "observed_result": "exact candidate evidence retained",
        },
    )
    assert proof_response.status_code == 201, proof_response.text
    proof = proof_response.json()
    candidate = client.post(
        f"{BASE}/assessment-runs/{run['id']}/candidates",
        json={
            "identity_key": "candidate:atomic-promotion",
            "target_key": "service-a",
            "source_id": source["id"],
            "source_anchor": "src/parser.c:1",
            "vulnerability_family": "CWE-20",
            "hypothesis": "untrusted length reaches parser",
            "dispatch_agent_id": "HUNT-RUN-1",
            "proof_receipt_ids": [proof["id"]],
        },
    ).json()
    mismatched = client.post(
        f"{BASE}/findings",
        json={
            "slug": "CH-900",
            "title": "Unrelated source finding",
            "severity": "medium",
            "workflow_status": "active",
            "canonical_location": "file:src/other.c:1",
            "summary": "This finding belongs to a different file.",
            "source_name": "HUNT-RUN-1",
            "provenance": {
                "agent_id": "HUNT-RUN-1",
                "code_snapshot": {
                    "repo_id": repo_id,
                    "repo_generation": 4,
                    "source_manifest_digest": "c" * 64,
                }
            },
            "run_candidate": {
                "run_id": run["id"],
                "candidate_id": candidate["id"],
                "reason": "incorrect cross-file promotion",
                "proof_receipt_ids": [proof["id"]],
            },
        },
    )
    assert mismatched.status_code == 409, mismatched.text
    assert client.get(f"{BASE}/findings/CH-900").status_code == 404
    recorded = client.post(
        f"{BASE}/findings",
        json={
            "slug": "CH-901",
            "title": "Untrusted length reaches parser",
            "severity": "medium",
            "workflow_status": "active",
            "canonical_location": "file:src/parser.c:1",
            "summary": "The parser trusts an attacker-controlled length.",
            "source_name": "HUNT-RUN-1",
            "provenance": {
                "agent_id": "HUNT-RUN-1",
                "code_snapshot": {
                    "repo_id": repo_id,
                    "repo_generation": 4,
                    "source_manifest_digest": "c" * 64,
                }
            },
            "run_candidate": {
                "run_id": run["id"],
                "candidate_id": candidate["id"],
                "reason": "promoted after source review",
                "proof_receipt_ids": [proof["id"]],
            },
        },
    )
    assert recorded.status_code == 201, recorded.text
    assert recorded.json()["finding"]["slug"] == "CH-901"
    assert recorded.json()["run_candidate"]["state"] == "promoted"
    assert recorded.json()["run_candidate"]["target_key"] == "service-a"
    assert recorded.json()["run_candidate"]["source_id"] == source["id"]
    assert recorded.json()["run_candidate"]["source_anchor"] == "src/parser.c:1"
    assert recorded.json()["run_candidate"]["proof_receipt_ids"] == [proof["id"]]
    reread = client.get(
        f"{BASE}/assessment-runs/{run['id']}/candidates?limit=10&offset=0"
    ).json()["items"][0]
    assert reread["finding_slug"] == "CH-901"


def test_existing_variant_receipt_resolves_its_exact_run_obligation(
    client, isolate_settings
) -> None:
    _seed(client, isolate_settings)
    run = _create_scan(client, run_uuid="variant-accounting")
    assert client.patch(
        f"{BASE}/assessment-runs/{run['id']}", json={"status": "running"}
    ).status_code == 200
    source = client.post(
        f"{BASE}/assessment-runs/{run['id']}/sources",
        json={
            "sources": [
                _source(
                    target_key="service-a",
                    path="src/parser.c",
                    content=b"b",
                )
            ]
        },
    )
    assert source.status_code == 201, source.text
    obligation = client.post(
        f"{BASE}/assessment-runs/{run['id']}/obligations",
        json={
            "identity_key": "variant:src/parser.c",
            "obligation_kind": "variant_check",
            "object_type": "source",
            "object_key": "service-a:src/parser.c",
        },
    ).json()
    fuzz_decision_obligation = client.post(
        f"{BASE}/assessment-runs/{run['id']}/obligations",
        json={
            "identity_key": "fuzz-decision:service-a",
            "obligation_kind": "fuzz_decision",
            "object_type": "repository",
            "object_key": "service-a",
        },
    ).json()
    fuzz_campaign_obligation = client.post(
        f"{BASE}/assessment-runs/{run['id']}/obligations",
        json={
            "identity_key": "fuzz-campaign:parser-fuzz",
            "obligation_kind": "fuzz_campaign",
            "object_type": "fuzz_target",
            "object_key": "service-a:parser-fuzz",
        },
    ).json()
    unrelated_candidate = client.post(
        f"{BASE}/assessment-runs/{run['id']}/candidates",
        json={
            "identity_key": "candidate:unrelated-repository",
            "target_key": "shared-library",
            "source_anchor": "src/unrelated.c:1",
            "vulnerability_family": "CWE-20",
            "hypothesis": "belongs to a different repository",
            "dispatch_agent_id": "HUNT-RUN-1",
        },
    )
    assert unrelated_candidate.status_code == 201, unrelated_candidate.text
    command = client.post(
        f"{BASE}/command-runs",
        json={
            "run_uuid": "variant-accounting-command",
            "agent_name": "HUNT-RUN-1",
            "command": "review variants",
            "tool_name": "review",
            "phase": "code-verify",
            "status": "completed",
            "return_code": 0,
            "started_at": "2026-09-10T12:00:00Z",
            "completed_at": "2026-09-10T12:00:01Z",
        },
    ).json()
    unrelated_proof = client.post(
        f"{BASE}/proof-receipts",
        json={
            "run_id": run["id"],
            "evidence_kind": "command",
            "command_run_id": command["id"],
            "observed_result": "variant receipt execution retained",
        },
    ).json()
    evidence_path = (
        isolate_settings["engagements_dir"]
        / ENGAGEMENT_KEY
        / "evidence"
        / "variant.json"
    )
    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    evidence_path.write_text('{"checked":["src/parser.c"]}\n')
    artifact = client.post(
        f"{BASE}/artifacts",
        json={
            "path": "evidence/variant.json",
            "kind": "variant_check",
            "media_type": "application/json",
            "producer_agent_id": "HUNT-RUN-1",
            "producer_command_run_id": command["id"],
        },
    )
    assert artifact.status_code == 201, artifact.text
    receipt_proof = client.post(
        f"{BASE}/proof-receipts",
        json={
            "run_id": run["id"],
            "evidence_kind": "artifact",
            "artifact_id": artifact.json()["id"],
            "observed_result": "the exact variant receipt artifact was retained",
        },
    )
    assert receipt_proof.status_code == 201, receipt_proof.text
    db_path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    with sqlite3.connect(str(db_path)) as connection:
        engagement_id = connection.execute(
            "SELECT id FROM engagements WHERE key = ?", (ENGAGEMENT_KEY,)
        ).fetchone()[0]
        dispatch_id = connection.execute(
            "SELECT id FROM assessment_dispatches WHERE engagement_id = ? AND agent_id = ?",
            (engagement_id, "HUNT-RUN-1"),
        ).fetchone()[0]
        connection.execute(
            """
            INSERT INTO code_repos (
                id, engagement_id, repo_key, name, repo_path,
                active_generation, source_manifest_digest
            ) VALUES (1, ?, 'service-a', 'service-a', '/source/service-a', 4, ?)
            """,
            (engagement_id, "c" * 64),
        )
        receipt_ids = []
        for repo_generation, manifest_digest, fingerprint in (
            (3, "c" * 64, "1" * 64),
            (4, "f" * 64, "2" * 64),
            (4, "c" * 64, "3" * 64),
        ):
            cursor = connection.execute(
                """
                INSERT INTO code_variant_check_receipts (
                    engagement_id, dispatch_id, dispatch_agent_id,
                    dispatch_agent_role, current_file_id, repo_id, repo_generation,
                    source_manifest_digest, file_path, file_sha256, language,
                    classification, role, slot_types_json,
                    parent_finding_slugs_json, parent_finding_set_digest,
                    variant_input_digest, status, evidence_ref, rationale,
                    receipt_fingerprint
                ) VALUES (?, ?, ?, ?, NULL, 1, ?, ?, ?, ?, ?, ?, ?, '[]', '[]', ?, ?,
                          'completed', ?, ?, ?)
                """,
                (
                    engagement_id,
                    dispatch_id,
                    "HUNT-RUN-1",
                    "code-variant-hunter",
                    repo_generation,
                    manifest_digest,
                    "src/parser.c",
                    hashlib.sha256(b"b").hexdigest(),
                    "c",
                    "high",
                    "parser",
                    "c" * 64,
                    "d" * 64,
                    "evidence/variant.json",
                    "checked exact siblings",
                    fingerprint,
                ),
            )
            receipt_ids.append(int(cursor.lastrowid))
        fuzz_decision_ids = []
        for evidence_sha256, fingerprint in (
            ("9" * 64, "4" * 64),
            (artifact.json()["sha256"], "5" * 64),
        ):
            cursor = connection.execute(
                """
                INSERT INTO code_fuzz_decisions (
                    engagement_id, repo_id, repo_generation,
                    source_manifest_digest, decision, target_ids_json,
                    evidence_ref, evidence_sha256, rationale, decision_fingerprint
                ) VALUES (?, 1, 4, ?, 'not_required', '[]', ?, ?, ?, ?)
                """,
                (
                    engagement_id,
                    "c" * 64,
                    "evidence/variant.json",
                    evidence_sha256,
                    "exact applicability decision",
                    fingerprint,
                ),
            )
            fuzz_decision_ids.append(int(cursor.lastrowid))
        fuzz_campaign_ids = []
        for evidence_sha256, fingerprint in (
            ("8" * 64, "6" * 64),
            (artifact.json()["sha256"], "7" * 64),
        ):
            cursor = connection.execute(
                """
                INSERT INTO code_fuzz_campaign_receipts (
                    engagement_id, dispatch_id, dispatch_agent_id,
                    repo_id, repo_generation, source_manifest_digest,
                    target_id, covered_finding_slugs_json, engine,
                    sanitizers_json, run_budget_seconds, executions,
                    outcome, crash_count, triage_summary, evidence_ref,
                    evidence_sha256, rationale, receipt_fingerprint
                ) VALUES (?, ?, 'HUNT-RUN-1', 1, 4, ?, 'parser-fuzz', '[]',
                          'libFuzzer', '["address"]', 60, 100,
                          'completed_no_crash', 0, 'no crash', ?, ?, ?, ?)
                """,
                (
                    engagement_id,
                    dispatch_id,
                    "c" * 64,
                    "evidence/variant.json",
                    evidence_sha256,
                    "exact campaign receipt",
                    fingerprint,
                ),
            )
            fuzz_campaign_ids.append(int(cursor.lastrowid))
        connection.commit()
    payload = {
        "receipt_kind": "variant_check",
        "receipt_id": receipt_ids[-1],
        "target_key": "service-a",
        "obligation_id": obligation["id"],
        "candidate_ids": [],
        "signal_ids": [],
        "proof_receipt_ids": [receipt_proof.json()["id"]],
    }
    for stale_receipt_id in receipt_ids[:-1]:
        stale = client.post(
            f"{BASE}/assessment-runs/{run['id']}/code-receipts",
            json={**payload, "receipt_id": stale_receipt_id},
        )
        assert stale.status_code == 409, stale.text
    unrelated = client.post(
        f"{BASE}/assessment-runs/{run['id']}/code-receipts",
        json={**payload, "candidate_ids": [unrelated_candidate.json()["id"]]},
    )
    assert unrelated.status_code == 409, unrelated.text
    mismatched_proof = client.post(
        f"{BASE}/assessment-runs/{run['id']}/code-receipts",
        json={**payload, "proof_receipt_ids": [unrelated_proof["id"]]},
    )
    assert mismatched_proof.status_code == 400, mismatched_proof.text
    linked = client.post(
        f"{BASE}/assessment-runs/{run['id']}/code-receipts", json=payload
    )
    retry = client.post(
        f"{BASE}/assessment-runs/{run['id']}/code-receipts", json=payload
    )
    assert linked.status_code == 201, linked.text
    assert retry.status_code == 201, retry.text
    assert retry.json()["id"] == linked.json()["id"]
    assert linked.json()["obligation_status"] == "resolved"
    obligations = client.get(
        f"{BASE}/assessment-runs/{run['id']}/obligations?limit=10&offset=0"
    ).json()["items"]
    updated = next(row for row in obligations if row["id"] == obligation["id"])
    assert updated["status"] == "resolved"

    for kind, obligation_id, receipt_pair in (
        ("fuzz_decision", fuzz_decision_obligation["id"], fuzz_decision_ids),
        ("fuzz_campaign", fuzz_campaign_obligation["id"], fuzz_campaign_ids),
    ):
        fuzz_payload = {
            "receipt_kind": kind,
            "receipt_id": receipt_pair[0],
            "target_key": "service-a",
            "obligation_id": obligation_id,
            "candidate_ids": [],
            "signal_ids": [],
            "proof_receipt_ids": [receipt_proof.json()["id"]],
        }
        mismatched_digest = client.post(
            f"{BASE}/assessment-runs/{run['id']}/code-receipts",
            json=fuzz_payload,
        )
        assert mismatched_digest.status_code == 400, mismatched_digest.text
        exact = client.post(
            f"{BASE}/assessment-runs/{run['id']}/code-receipts",
            json={**fuzz_payload, "receipt_id": receipt_pair[1]},
        )
        assert exact.status_code == 201, exact.text
        assert exact.json()["obligation_status"] == "resolved"


def test_hard_accepted_gap_and_unproved_candidate_closure_cannot_claim_completion(
    client, isolate_settings
) -> None:
    _seed(client, isolate_settings)
    run = _create_scan(client, run_uuid="unsupported-closure")
    assert client.patch(
        f"{BASE}/assessment-runs/{run['id']}", json={"status": "running"}
    ).status_code == 200
    content = b"value = source()\n"
    source = client.post(
        f"{BASE}/assessment-runs/{run['id']}/sources",
        json={"sources": [_source(target_key="service-a", path="src/gap.py", content=content)]},
    ).json()[0]
    assert client.post(
        f"{BASE}/assessment-runs/{run['id']}/source-reads",
        json={
            "source_id": source["id"],
            "dispatch_agent_id": "HUNT-RUN-1",
            "attempt": 1,
            "byte_start": 0,
            "byte_end": len(content),
            "line_start": 1,
            "line_end": 2,
        },
    ).status_code == 201
    gap = client.post(
        f"{BASE}/assessment-runs/{run['id']}/obligations",
        json={
            "identity_key": "dependency:missing",
            "obligation_kind": "missing_dependency",
            "object_type": "repository",
            "object_key": "shared-library",
            "hard": True,
            "status": "accepted_gap",
            "resolution": "not available in this checkout",
            "proof_receipt_ids": [],
        },
    )
    assert gap.status_code == 201, gap.text
    candidate = client.post(
        f"{BASE}/assessment-runs/{run['id']}/candidates",
        json={
            "identity_key": "candidate:unproved-rejection",
            "target_key": "service-a",
            "source_id": source["id"],
            "source_anchor": "src/gap.py:1",
            "vulnerability_family": "CWE-20",
            "hypothesis": "unresolved flow",
            "originating_result_id": None,
            "dispatch_agent_id": "HUNT-RUN-1",
            "proof_receipt_ids": [],
            "state": "open",
        },
    )
    assert candidate.status_code == 201, candidate.text
    rejected = client.patch(
        f"{BASE}/assessment-runs/{run['id']}/candidates/{candidate.json()['id']}",
        json={
            "state": "rejected",
            "reason": "unsupported prose assertion",
            "proof_receipt_ids": [],
        },
    )
    assert rejected.status_code == 400, rejected.text

    terminal = client.patch(
        f"{BASE}/assessment-runs/{run['id']}", json={"status": "completed"}
    )
    assert terminal.status_code == 200, terminal.text
    assert terminal.json()["status"] == "partial"
    blocker_codes = {row["code"] for row in terminal.json()["seal"]["blockers"]}
    assert "unresolved_obligation" in blocker_codes
    assert "unresolved_candidate" in blocker_codes


def test_read_endpoints_are_paginated_and_have_no_status_side_effects(
    client, isolate_settings
) -> None:
    _seed(client, isolate_settings)
    run = _create_scan(client)
    assert client.patch(
        f"{BASE}/assessment-runs/{run['id']}", json={"status": "running"}
    ).status_code == 200
    sources = [
        _source(
            target_key="service-a",
            path=f"src/file_{index:04d}.py",
            content=f"VALUE = {index}\n".encode(),
        )
        for index in range(105)
    ]
    created = client.post(
        f"{BASE}/assessment-runs/{run['id']}/sources", json={"sources": sources}
    )
    assert created.status_code == 201, created.text

    page = client.get(
        f"{BASE}/assessment-runs/{run['id']}/sources",
        params={"limit": 25, "offset": 100},
    )
    assert page.status_code == 200, page.text
    assert page.json()["total"] == 105
    assert len(page.json()["items"]) == 5
    assert page.json()["has_more"] is False

    before = client.get(f"{BASE}/assessment-runs/{run['id']}").json()
    for _ in range(3):
        point = client.get(f"{BASE}/assessment-runs/{run['id']}")
        assert point.status_code == 200
    after = client.get(f"{BASE}/assessment-runs/{run['id']}").json()
    assert after["updated_at"] == before["updated_at"]
    assert after["lifecycle_history"] == before["lifecycle_history"]


def test_comparison_is_deterministic_and_conservative_under_source_drift(
    client, isolate_settings
) -> None:
    _seed(client, isolate_settings)
    baseline = _create_scan(client, run_uuid="baseline")
    current = _create_scan(client, run_uuid="current")
    moved = _create_scan(client, run_uuid="moved")
    drifted = _create_scan(client, run_uuid="drifted")

    for run, digest, path in (
        (baseline, b"same", "src/path.py"),
        (current, b"same", "src/path.py"),
        (moved, b"same", "src/renamed/path.py"),
        (drifted, b"changed", "src/path.py"),
    ):
        assert client.patch(
            f"{BASE}/assessment-runs/{run['id']}", json={"status": "running"}
        ).status_code == 200
        created = client.post(
            f"{BASE}/assessment-runs/{run['id']}/sources",
            json={
                "sources": [
                    _source(
                        target_key="service-a",
                        path=path,
                        content=digest,
                    )
                ]
            },
        )
        assert created.status_code == 201, created.text

    def add_candidate(run: dict, identity: str) -> None:
        source_id = client.get(
            f"{BASE}/assessment-runs/{run['id']}/sources",
            params={"limit": 10, "offset": 0},
        ).json()["items"][0]["id"]
        response = client.post(
            f"{BASE}/assessment-runs/{run['id']}/candidates",
            json={
                "identity_key": identity,
                "target_key": "service-a",
                "source_id": source_id,
                "source_anchor": "src/path.py:1",
                "vulnerability_family": "CWE-22",
                "hypothesis": identity,
                "originating_result_id": None,
                "dispatch_agent_id": "HUNT-RUN-1",
                "proof_receipt_ids": [],
                "state": "open",
            },
        )
        assert response.status_code == 201, response.text

    add_candidate(baseline, "persisting")
    add_candidate(baseline, "baseline-only")
    add_candidate(current, "persisting")
    add_candidate(current, "new")
    add_candidate(moved, "persisting")
    add_candidate(drifted, "persisting")

    comparison = client.get(
        f"{BASE}/assessment-runs/{current['id']}/comparison",
        params={"baseline_run_id": baseline["id"]},
    )
    assert comparison.status_code == 200, comparison.text
    assert comparison.json()["classifications"] == {
        "new": ["new"],
        "persisting": ["persisting"],
        "resolved": [],
        "unknown": ["baseline-only"],
    }

    moved_comparison = client.get(
        f"{BASE}/assessment-runs/{moved['id']}/comparison",
        params={"baseline_run_id": baseline["id"]},
    )
    assert moved_comparison.status_code == 200, moved_comparison.text
    assert moved_comparison.json()["source_compatible"] is True

    drift = client.get(
        f"{BASE}/assessment-runs/{drifted['id']}/comparison",
        params={"baseline_run_id": baseline["id"]},
    )
    assert drift.status_code == 200, drift.text
    assert drift.json()["source_compatible"] is False
    assert drift.json()["classifications"]["unknown"] == ["baseline-only"]

    computed_only = client.get(
        f"{BASE}/assessment-runs/{current['id']}/comparisons",
        params={"limit": 10, "offset": 0},
    )
    assert computed_only.status_code == 200, computed_only.text
    assert computed_only.json()["total"] == 0


def test_terminal_scan_persists_one_automatic_comparison_with_exact_retry(
    client, isolate_settings
) -> None:
    _seed(client, isolate_settings)
    baseline = _create_scan(client, run_uuid="sealed-baseline")
    assert client.patch(
        f"{BASE}/assessment-runs/{baseline['id']}", json={"status": "running"}
    ).status_code == 200
    inventory = {
        "sources": [
            _source(
                target_key="service-a",
                path="src/stable.py",
                content=b"STABLE = True\n",
            )
        ]
    }
    assert client.post(
        f"{BASE}/assessment-runs/{baseline['id']}/sources", json=inventory
    ).status_code == 201
    baseline_terminal = client.patch(
        f"{BASE}/assessment-runs/{baseline['id']}", json={"status": "partial"}
    )
    assert baseline_terminal.status_code == 200, baseline_terminal.text

    current = _create_scan(client, run_uuid="sealed-current")
    assert client.patch(
        f"{BASE}/assessment-runs/{current['id']}", json={"status": "running"}
    ).status_code == 200
    assert client.post(
        f"{BASE}/assessment-runs/{current['id']}/sources", json=inventory
    ).status_code == 201
    current_terminal = client.patch(
        f"{BASE}/assessment-runs/{current['id']}", json={"status": "partial"}
    )
    assert current_terminal.status_code == 200, current_terminal.text

    page = client.get(
        f"{BASE}/assessment-runs/{current['id']}/comparisons",
        params={"limit": 10, "offset": 0},
    )
    assert page.status_code == 200, page.text
    assert page.json()["total"] == 1
    automatic = page.json()["items"][0]
    assert automatic["baseline_run_id"] == baseline["id"]
    assert automatic["selection"] == "automatic"
    assert automatic["source_compatible"] is True

    retried = client.post(
        f"{BASE}/assessment-runs/{current['id']}/comparisons",
        json={"baseline_run_id": baseline["id"]},
    )
    assert retried.status_code == 201, retried.text
    assert retried.json()["id"] == automatic["id"]
    assert retried.json()["comparison_sha256"] == automatic["comparison_sha256"]
    assert client.get(
        f"{BASE}/assessment-runs/{current['id']}/comparisons"
    ).json()["total"] == 1


def test_comparison_marks_absent_candidate_resolved_only_with_equivalent_clean_proof(
    client, isolate_settings
) -> None:
    _seed(client, isolate_settings)
    inventory = {
        "sources": [
            _source(
                target_key="service-a",
                path="src/equivalent.py",
                content=b"SAFE = True\n",
            ),
            {
                "target_key": "shared-library",
                "declared_root": ".",
                "path": "generated/manifest.json",
                "content_sha256": "f" * 64,
                "byte_size": 0,
                "line_count": 0,
                "encoding": "utf-8",
                "inventory_status": "excluded",
                "exclusion_reason": "declared generated boundary",
                "parser_status": "not_applicable",
                "parser_error": "",
            },
        ]
    }

    baseline = _create_scan(
        client,
        run_uuid="resolved-baseline",
        committed_sources=inventory["sources"],
    )
    assert client.patch(
        f"{BASE}/assessment-runs/{baseline['id']}", json={"status": "running"}
    ).status_code == 200
    baseline_source = client.post(
        f"{BASE}/assessment-runs/{baseline['id']}/sources", json=inventory
    ).json()[0]
    assert client.post(
        f"{BASE}/assessment-runs/{baseline['id']}/candidates",
        json={
            "identity_key": "candidate:prior",
            "target_key": "service-a",
            "source_id": baseline_source["id"],
            "source_anchor": "src/equivalent.py:1",
            "vulnerability_family": "CWE-20",
            "hypothesis": "prior candidate",
            "originating_result_id": None,
            "dispatch_agent_id": "HUNT-RUN-1",
            "proof_receipt_ids": [],
            "state": "open",
        },
    ).status_code == 201
    assert client.patch(
        f"{BASE}/assessment-runs/{baseline['id']}", json={"status": "partial"}
    ).status_code == 200

    current = _create_scan(
        client,
        run_uuid="resolved-current",
        committed_sources=inventory["sources"],
    )
    assert client.patch(
        f"{BASE}/assessment-runs/{current['id']}", json={"status": "running"}
    ).status_code == 200
    current_source = client.post(
        f"{BASE}/assessment-runs/{current['id']}/sources", json=inventory
    ).json()[0]
    current_read = client.post(
        f"{BASE}/assessment-runs/{current['id']}/source-reads",
        json={
            "source_id": current_source["id"],
            "dispatch_agent_id": "HUNT-RUN-1",
            "attempt": 1,
            "byte_start": 0,
            "byte_end": current_source["byte_size"],
            "line_start": 1,
            "line_end": current_source["line_count"],
        },
    )
    assert current_read.status_code == 201, current_read.text
    receipt = client.post(
        f"{BASE}/proof-receipts",
        json={
            "run_id": current["id"],
            "evidence_kind": "source_observation",
            "source_read_id": current_read.json()["id"],
            "expected_result": "prior candidate remains reachable",
            "observed_result": "equivalent source range proves the flow is absent",
        },
    )
    assert receipt.status_code == 201, receipt.text
    recheck = client.post(
        f"{BASE}/assessment-runs/{current['id']}/obligations",
        json={
            "identity_key": "candidate-recheck:prior",
            "obligation_kind": "candidate_recheck",
            "object_type": "candidate",
            "object_key": "candidate:prior",
            "hard": True,
            "status": "resolved",
            "resolution": "equivalent source reviewed with contrary evidence",
            "proof_receipt_ids": [receipt.json()["id"]],
        },
    )
    assert recheck.status_code == 201, recheck.text
    _record_discovery_pass(client, current, identity_key="resolved-current-terminal")
    completed = client.patch(
        f"{BASE}/assessment-runs/{current['id']}", json={"status": "completed"}
    )
    assert completed.status_code == 200, completed.text
    assert completed.json()["status"] == "completed"

    comparison = client.get(
        f"{BASE}/assessment-runs/{current['id']}/comparison",
        params={"baseline_run_id": baseline["id"]},
    )
    assert comparison.status_code == 200, comparison.text
    assert comparison.json()["classifications"]["resolved"] == ["candidate:prior"]
    assert comparison.json()["classifications"]["unknown"] == []

    with db_module.get_connection() as connection:
        connection.execute(
            "UPDATE assessment_proof_receipts SET recorded_health = 'stale' WHERE id = ?",
            (receipt.json()["id"],),
        )
    degraded = client.get(
        f"{BASE}/assessment-runs/{current['id']}/comparison",
        params={"baseline_run_id": baseline["id"]},
    )
    assert degraded.status_code == 200, degraded.text
    assert degraded.json()["classifications"]["resolved"] == []
    assert degraded.json()["classifications"]["unknown"] == ["candidate:prior"]


def test_interrupted_run_is_sealed_and_resume_creates_a_linked_run_without_loss(
    client, isolate_settings
) -> None:
    _seed(client, isolate_settings)
    original = _create_scan(client, run_uuid="interrupted-parent")
    assert client.patch(
        f"{BASE}/assessment-runs/{original['id']}", json={"status": "running"}
    ).status_code == 200
    source = client.post(
        f"{BASE}/assessment-runs/{original['id']}/sources",
        json={
            "sources": [
                _source(
                    target_key="service-a",
                    path="src/kept.py",
                    content=b"KEPT = True\n",
                )
            ]
        },
    )
    assert source.status_code == 201, source.text
    command = client.post(
        f"{BASE}/command-runs",
        json={
            "run_uuid": "interrupted-signal-command",
            "agent_name": "HUNT-RUN-1",
            "command": "reproduce retained crash",
            "tool_name": "reproducer",
            "phase": "code-verify",
            "status": "completed",
            "return_code": 1,
            "started_at": "2026-09-10T12:00:00Z",
            "completed_at": "2026-09-10T12:00:01Z",
        },
    )
    assert command.status_code == 201, command.text
    proof = client.post(
        f"{BASE}/proof-receipts",
        json={
            "run_id": original["id"],
            "evidence_kind": "command",
            "command_run_id": command.json()["id"],
            "observed_result": "retained crash reproduced",
        },
    )
    assert proof.status_code == 201, proof.text
    signal = client.post(
        f"{BASE}/assessment-runs/{original['id']}/tool-signals",
        json={
            "identity_key": "kept-signal",
            "signal_kind": "reproducible_crash",
            "dispatch_agent_id": "HUNT-RUN-1",
            "target_key": "service-a",
            "source_id": source.json()[0]["id"],
            "source_anchor": "src/kept.py:1",
            "vulnerability_family": "CWE-20",
            "hypothesis": "retained across interruption",
            "observed_signature": "retained crash signature",
            "exact_input_sha256": hashlib.sha256(b"retained-input").hexdigest(),
            "command_run_id": command.json()["id"],
            "proof_receipt_ids": [proof.json()["id"]],
        },
    )
    assert signal.status_code == 201, signal.text
    interrupted = client.patch(
        f"{BASE}/assessment-runs/{original['id']}",
        json={"status": "interrupted", "reason": "worker process exited"},
    )
    assert interrupted.status_code == 200, interrupted.text
    assert interrupted.json()["status"] == "interrupted"
    assert interrupted.json()["seal"]["counts"]["candidates"] == 1

    resumed = client.post(
        f"{BASE}/assessment-runs",
        json={
            "run_uuid": "interrupted-child",
            "run_kind": "code",
            "run_purpose": "scan",
            "producer_dispatch_agent_id": "HUNT-RUN-1",
            "resumed_from_run_id": original["id"],
        },
    )
    assert resumed.status_code == 201, resumed.text
    assert resumed.json()["resumed_from_run_id"] == original["id"]
    assert resumed.json()["target_identity"] == original["target_identity"]
    assert resumed.json()["source_generations"] == original["source_generations"]
    assert resumed.json()["status"] == "queued"
    assert resumed.json()["counts"]["inventory_total"] == 1
    assert resumed.json()["counts"]["open_hard_obligations"] == 1
    assert resumed.json()["counts"]["candidates"] == 1
    resumed_candidates = client.get(
        f"{BASE}/assessment-runs/{resumed.json()['id']}/candidates",
        params={"limit": 10, "offset": 0},
    ).json()["items"]
    assert resumed_candidates[0]["originating_signal_id"] == signal.json()["id"]

    assert client.patch(
        f"{BASE}/assessment-runs/{resumed.json()['id']}",
        json={"status": "running"},
    ).status_code == 200
    resumed_source = client.get(
        f"{BASE}/assessment-runs/{resumed.json()['id']}/sources",
        params={"limit": 10, "offset": 0},
    ).json()["items"][0]
    resumed_read = client.post(
        f"{BASE}/assessment-runs/{resumed.json()['id']}/source-reads",
        json={
            "source_id": resumed_source["id"],
            "dispatch_agent_id": "HUNT-RUN-1",
            "attempt": 2,
            "byte_start": 0,
            "byte_end": resumed_source["byte_size"],
            "line_start": 1,
            "line_end": resumed_source["line_count"],
        },
    )
    assert resumed_read.status_code == 201, resumed_read.text
    resumed_obligations = client.get(
        f"{BASE}/assessment-runs/{resumed.json()['id']}/obligations",
        params={"limit": 10, "offset": 0},
    )
    assert resumed_obligations.status_code == 200, resumed_obligations.text
    source_read_debt = next(
        row
        for row in resumed_obligations.json()["items"]
        if row["obligation_kind"] == "source_read"
    )
    assert source_read_debt["status"] == "resolved"

    preserved_sources = client.get(
        f"{BASE}/assessment-runs/{original['id']}/sources",
        params={"limit": 10, "offset": 0},
    )
    preserved_candidates = client.get(
        f"{BASE}/assessment-runs/{original['id']}/candidates",
        params={"limit": 10, "offset": 0},
    )
    preserved_signals = client.get(
        f"{BASE}/assessment-runs/{original['id']}/tool-signals",
        params={"limit": 10, "offset": 0},
    )
    assert preserved_sources.json()["total"] == 1
    assert preserved_candidates.json()["items"][0]["originating_signal_id"] == signal.json()["id"]
    assert preserved_signals.json()["items"][0]["candidate_id"] == signal.json()["candidate_id"]


@pytest.mark.parametrize(
    "identity_override",
    [
        {
            "target_identity": {
                "scope": "repository",
                "repositories": ["unrelated-service"],
            }
        },
        {
            "source_generations": [
                {
                    "target_key": "unrelated-service",
                    "generation": 1,
                    "manifest_digest": "e" * 64,
                }
            ]
        },
        {
            "exclusions": [
                {
                    "target_key": "unrelated-service",
                    "path": "ignored/",
                    "reason": "unrelated boundary",
                }
            ]
        },
    ],
    ids=["target-identity", "source-generations", "exclusions"],
)
def test_resumed_run_rejects_identity_that_differs_from_its_parent(
    client, isolate_settings, identity_override
) -> None:
    _seed(client, isolate_settings)
    parent = _create_scan(client, run_uuid="resume-identity-parent")
    terminal = client.patch(
        f"{BASE}/assessment-runs/{parent['id']}",
        json={"status": "interrupted", "reason": "worker exited"},
    )
    assert terminal.status_code == 200, terminal.text

    resumed = client.post(
        f"{BASE}/assessment-runs",
        json={
            "run_uuid": "resume-identity-child",
            "run_kind": "code",
            "run_purpose": "scan",
            "producer_dispatch_agent_id": "HUNT-RUN-1",
            "resumed_from_run_id": parent["id"],
            **identity_override,
        },
    )

    assert resumed.status_code == 409, resumed.text
    assert resumed.json()["detail"] == "resumed run must preserve its parent's identity"
    runs = client.get(f"{BASE}/assessment-runs", params={"limit": 100, "offset": 0})
    assert runs.status_code == 200, runs.text
    assert {run["run_uuid"] for run in runs.json()} == {"resume-identity-parent"}


def test_resumed_run_accepts_explicit_parent_identity(client, isolate_settings) -> None:
    _seed(client, isolate_settings)
    parent = _create_scan(client, run_uuid="resume-exact-identity-parent")
    terminal = client.patch(
        f"{BASE}/assessment-runs/{parent['id']}",
        json={"status": "interrupted", "reason": "worker exited"},
    )
    assert terminal.status_code == 200, terminal.text

    resumed = client.post(
        f"{BASE}/assessment-runs",
        json={
            "run_uuid": "resume-exact-identity-child",
            "run_kind": "code",
            "run_purpose": "scan",
            "producer_dispatch_agent_id": "HUNT-RUN-1",
            "target_identity": parent["target_identity"],
            "source_generations": parent["source_generations"],
            "exclusions": parent["exclusions"],
            "resumed_from_run_id": parent["id"],
        },
    )

    assert resumed.status_code == 201, resumed.text
    assert resumed.json()["target_identity"] == parent["target_identity"]
    assert resumed.json()["source_generations"] == parent["source_generations"]
    assert resumed.json()["exclusions"] == parent["exclusions"]


def test_proof_run_without_evidence_cannot_be_sealed_completed(
    client, isolate_settings
) -> None:
    _seed(client, isolate_settings)
    run = client.post(
        f"{BASE}/assessment-runs",
        json={
            "run_uuid": "empty-proof-run",
            "run_kind": "shared",
            "producer_dispatch_agent_id": "HUNT-RUN-1",
        },
    )
    assert run.status_code == 201, run.text
    terminal = client.patch(
        f"{BASE}/assessment-runs/{run.json()['id']}", json={"status": "completed"}
    )
    assert terminal.status_code == 200, terminal.text
    assert terminal.json()["status"] == "partial"
    assert terminal.json()["seal"]["blockers"][0]["code"] == "proof_missing"


def test_resumed_proof_run_replaces_unhealthy_parent_evidence_without_erasing_it(
    client, isolate_settings
) -> None:
    _seed(client, isolate_settings)
    parent = client.post(
        f"{BASE}/assessment-runs",
        json={
            "run_uuid": "proof-recovery-parent",
            "run_kind": "shared",
            "producer_dispatch_agent_id": "HUNT-RUN-1",
        },
    ).json()
    parent_command = client.post(
        f"{BASE}/command-runs",
        json={
            "run_uuid": "proof-recovery-parent-command",
            "agent_name": "HUNT-RUN-1",
            "command": "run parent reproducer",
            "tool_name": "reproducer",
            "phase": "verify",
            "status": "completed",
            "return_code": 0,
            "started_at": "2026-09-11T12:00:00Z",
            "completed_at": "2026-09-11T12:00:01Z",
            "stdout": "parent reproduction succeeded\n",
        },
    )
    assert parent_command.status_code == 201, parent_command.text
    parent_receipt = client.post(
        f"{BASE}/proof-receipts",
        json={
            "run_id": parent["id"],
            "evidence_kind": "command",
            "command_run_id": parent_command.json()["id"],
            "observed_result": "parent reproduction succeeded",
        },
    )
    assert parent_receipt.status_code == 201, parent_receipt.text
    sealed_parent = client.patch(
        f"{BASE}/assessment-runs/{parent['id']}", json={"status": "completed"}
    )
    assert sealed_parent.status_code == 200, sealed_parent.text
    assert sealed_parent.json()["status"] == "completed"
    with db_module.get_connection() as connection:
        connection.execute(
            "UPDATE assessment_proof_receipts SET recorded_health = 'stale' "
            "WHERE id = ?",
            (parent_receipt.json()["id"],),
        )

    child_response = client.post(
        f"{BASE}/assessment-runs",
        json={
            "run_uuid": "proof-recovery-child",
            "run_kind": "shared",
            "producer_dispatch_agent_id": "HUNT-RUN-1",
            "resumed_from_run_id": parent["id"],
        },
    )
    assert child_response.status_code == 201, child_response.text
    child = child_response.json()
    assert child["proof_health"]["stale"] == 1
    assert {blocker["code"] for blocker in child["blockers"]} == {"proof_missing"}

    child_command = client.post(
        f"{BASE}/command-runs",
        json={
            "run_uuid": "proof-recovery-child-command",
            "agent_name": "HUNT-RUN-1",
            "command": "run replacement reproducer",
            "tool_name": "reproducer",
            "phase": "verify",
            "status": "completed",
            "return_code": 0,
            "started_at": "2026-09-11T12:01:00Z",
            "completed_at": "2026-09-11T12:01:01Z",
            "stdout": "replacement reproduction succeeded\n",
        },
    )
    assert child_command.status_code == 201, child_command.text
    child_receipt = client.post(
        f"{BASE}/proof-receipts",
        json={
            "run_id": child["id"],
            "evidence_kind": "command",
            "command_run_id": child_command.json()["id"],
            "observed_result": "replacement reproduction succeeded",
        },
    )
    assert child_receipt.status_code == 201, child_receipt.text

    completed = client.patch(
        f"{BASE}/assessment-runs/{child['id']}", json={"status": "completed"}
    )
    assert completed.status_code == 200, completed.text
    assert completed.json()["status"] == "completed"
    assert completed.json()["seal"]["proof_health"] == {
        "healthy": 1,
        "missing": 0,
        "stale": 1,
        "tombstoned": 0,
    }
    lineage_receipts = client.get(
        f"{BASE}/assessment-runs/{child['id']}/proof-receipts",
        params={"limit": 10, "offset": 0},
    )
    assert lineage_receipts.status_code == 200, lineage_receipts.text
    assert {receipt["id"] for receipt in lineage_receipts.json()["items"]} == {
        parent_receipt.json()["id"],
        child_receipt.json()["id"],
    }


# ──────────────────────────────────────────────────────────────────────────
# Resume recovery: a resumed run inherits only proof that is still healthy.
#
# Every copy path the resume walks — source reads, obligations, candidates —
# follows one rule: an unhealthy binding is not inherited, a closed disposition
# that rested on one reopens, and the child's own event history names what was
# dropped. Each rule below is pinned from both sides: the unhealthy case proves
# the child is repairable, the healthy case proves the rule does not fire on
# evidence that still holds (a predicate that always fired would erase recovery
# state with a green suite, because unresolvable ids default to stale).
# ──────────────────────────────────────────────────────────────────────────


def _recovery_parent_run(client, *, run_uuid: str) -> dict:
    """Return a proof run to be sealed and then resumed from."""

    parent = client.post(
        f"{BASE}/assessment-runs",
        json={
            "run_uuid": run_uuid,
            "run_kind": "shared",
            "producer_dispatch_agent_id": "HUNT-RUN-1",
        },
    )
    assert parent.status_code == 201, parent.text
    return parent.json()


def _recovery_receipt(client, run: dict, *, slug: str, observed: str) -> int:
    """Return a healthy command-backed proof receipt id owned by ``run``."""

    command = client.post(
        f"{BASE}/command-runs",
        json={
            "run_uuid": f"{slug}-command",
            "agent_name": "HUNT-RUN-1",
            "command": f"capture {slug}",
            "tool_name": "reviewer",
            "phase": "verify",
            "status": "completed",
            "return_code": 0,
            "started_at": "2026-09-11T12:00:00Z",
            "completed_at": "2026-09-11T12:00:01Z",
            "stdout": f"{observed}\n",
        },
    )
    assert command.status_code == 201, command.text
    receipt = client.post(
        f"{BASE}/proof-receipts",
        json={
            "run_id": run["id"],
            "evidence_kind": "command",
            "command_run_id": command.json()["id"],
            "observed_result": observed,
        },
    )
    assert receipt.status_code == 201, receipt.text
    return int(receipt.json()["id"])


def _recovery_source(client, run: dict) -> dict:
    recorded = client.post(
        f"{BASE}/assessment-runs/{run['id']}/sources",
        json={
            "sources": [
                _source(
                    target_key="service-a", path="src/read.py", content=b"KEPT = True\n"
                )
            ]
        },
    )
    assert recorded.status_code == 201, recorded.text
    return recorded.json()[0]


def _decay_receipt(receipt_id: int) -> None:
    """Age one recorded receipt out of health, as real evidence decay does."""

    with db_module.get_connection() as connection:
        connection.execute(
            "UPDATE assessment_proof_receipts SET recorded_health = 'stale' WHERE id = ?",
            (receipt_id,),
        )


def _seal(client, run: dict, status_value: str = "completed") -> dict:
    sealed = client.patch(
        f"{BASE}/assessment-runs/{run['id']}", json={"status": status_value}
    )
    assert sealed.status_code == 200, sealed.text
    return sealed.json()


def _resume(client, parent: dict, *, run_uuid: str) -> dict:
    child = client.post(
        f"{BASE}/assessment-runs",
        json={
            "run_uuid": run_uuid,
            "run_kind": "shared",
            "producer_dispatch_agent_id": "HUNT-RUN-1",
            "resumed_from_run_id": parent["id"],
        },
    )
    assert child.status_code == 201, child.text
    return child.json()


def _close_candidate(
    client,
    run: dict,
    *,
    identity_key: str,
    receipt_id: int,
    state: str = "rejected",
    finding_slug: str = "",
) -> dict:
    candidate = client.post(
        f"{BASE}/assessment-runs/{run['id']}/candidates",
        json={
            "identity_key": identity_key,
            "target_key": "service-a",
            "source_id": None,
            "source_anchor": "/resource/1",
            "vulnerability_family": "CWE-639",
            "hypothesis": "cross-tenant access is possible",
            "originating_result_id": None,
            "dispatch_agent_id": "HUNT-RUN-1",
            "proof_receipt_ids": [],
            "state": "open",
        },
    )
    assert candidate.status_code == 201, candidate.text
    closed = client.patch(
        f"{BASE}/assessment-runs/{run['id']}/candidates/{candidate.json()['id']}",
        json={
            "state": state,
            "reason": f"parent proof makes the candidate {state}",
            "proof_receipt_ids": [receipt_id],
            "finding_slug": finding_slug,
        },
    )
    assert closed.status_code == 200, closed.text
    return closed.json()


def _resolve_obligation(client, run: dict, *, receipt_id: int) -> dict:
    obligation = client.post(
        f"{BASE}/assessment-runs/{run['id']}/obligations",
        json={
            "identity_key": "coverage:service-a",
            "obligation_kind": "coverage",
            "object_type": "target",
            "object_key": "service-a",
            "hard": True,
            "status": "resolved",
            "resolution": "parent proved complete coverage",
            "proof_receipt_ids": [receipt_id],
        },
    )
    assert obligation.status_code == 201, obligation.text
    return obligation.json()


def _read_source(client, run: dict, source: dict, *, attempt: int, receipt_id: int) -> dict:
    read = client.post(
        f"{BASE}/assessment-runs/{run['id']}/source-reads",
        json={
            "source_id": source["id"],
            "dispatch_agent_id": "HUNT-RUN-1",
            "attempt": attempt,
            "byte_start": 0,
            "byte_end": source["byte_size"],
            "line_start": 1,
            "line_end": source["line_count"],
            "proof_receipt_id": receipt_id,
        },
    )
    assert read.status_code == 201, read.text
    return read.json()


def _first(client, child: dict, ledger: str) -> dict:
    page = client.get(
        f"{BASE}/assessment-runs/{child['id']}/{ledger}",
        params={"limit": 10, "offset": 0},
    )
    assert page.status_code == 200, page.text
    return page.json()["items"][0]


def _blocker_codes(run: dict) -> set[str]:
    return {blocker["code"] for blocker in run["blockers"]}


def test_resumed_run_reopens_terminal_candidate_with_unhealthy_proof(
    client, isolate_settings
) -> None:
    _seed(client, isolate_settings)
    parent = _recovery_parent_run(client, run_uuid="candidate-recovery-parent")
    parent_receipt_id = _recovery_receipt(
        client, parent, slug="candidate-recovery-parent", observed="candidate rejected"
    )
    _close_candidate(
        client, parent, identity_key="candidate:recovery", receipt_id=parent_receipt_id
    )
    assert _seal(client, parent)["status"] == "completed"
    _decay_receipt(parent_receipt_id)

    child = _resume(client, parent, run_uuid="candidate-recovery-child")
    child_candidate = _first(client, child, "candidates")
    assert child_candidate["state"] == "open"
    assert child_candidate["proof_receipt_ids"] == []
    assert child_candidate["finding_slug"] == ""
    assert "proof_stale" not in _blocker_codes(child)

    child_receipt_id = _recovery_receipt(
        client,
        child,
        slug="candidate-recovery-child",
        observed="candidate independently rejected",
    )
    repaired = client.patch(
        f"{BASE}/assessment-runs/{child['id']}/candidates/{child_candidate['id']}",
        json={
            "state": "rejected",
            "reason": "replacement proof rejects the candidate",
            "proof_receipt_ids": [child_receipt_id],
        },
    )
    assert repaired.status_code == 200, repaired.text
    assert _seal(client, child)["status"] == "completed"

    history = client.get(
        f"{BASE}/assessment-runs/{child['id']}/candidates/{child_candidate['id']}/history"
    )
    assert history.status_code == 200, history.text
    assert [event["to_state"] for event in history.json()] == ["open", "rejected"]
    assert history.json()[0]["from_state"] == "rejected"
    assert history.json()[0]["proof_receipt_ids"] == [parent_receipt_id]
    assert str(parent_receipt_id) in history.json()[0]["reason"]

    preserved = _first(client, parent, "candidates")
    assert preserved["state"] == "rejected"
    assert preserved["proof_receipt_ids"] == [parent_receipt_id]


def test_resumed_run_keeps_terminal_candidate_whose_proof_is_healthy(
    client, isolate_settings
) -> None:
    _seed(client, isolate_settings)
    parent = _recovery_parent_run(client, run_uuid="candidate-healthy-parent")
    parent_receipt_id = _recovery_receipt(
        client, parent, slug="candidate-healthy-parent", observed="candidate rejected"
    )
    _close_candidate(
        client, parent, identity_key="candidate:healthy", receipt_id=parent_receipt_id
    )
    assert _seal(client, parent)["status"] == "completed"

    child = _resume(client, parent, run_uuid="candidate-healthy-child")
    child_candidate = _first(client, child, "candidates")
    assert child_candidate["state"] == "rejected"
    assert child_candidate["proof_receipt_ids"] == [parent_receipt_id]
    assert child["blockers"] == []
    history = client.get(
        f"{BASE}/assessment-runs/{child['id']}/candidates/{child_candidate['id']}/history"
    ).json()
    assert [event["to_state"] for event in history] == ["rejected"]
    assert history[0]["reason"] == "resumed from terminal run"
    assert _seal(client, child)["status"] == "completed"


def test_reopened_candidate_event_names_the_parent_finding_slug(
    client, isolate_settings
) -> None:
    """Reopening retires the finding pointer; the event has to keep it readable.

    The candidate event table has no slug column, so if the reason did not carry
    it the child agent would inherit a bare open candidate with no way back to
    the finding its parent already produced.
    """

    _seed(client, isolate_settings)
    parent = _recovery_parent_run(client, run_uuid="candidate-slug-parent")
    parent_receipt_id = _recovery_receipt(
        client, parent, slug="candidate-slug-parent", observed="candidate duplicated"
    )
    _close_candidate(
        client,
        parent,
        identity_key="candidate:slug",
        receipt_id=parent_receipt_id,
        state="duplicate",
        finding_slug="VA-001",
    )
    assert _seal(client, parent)["status"] == "completed"
    _decay_receipt(parent_receipt_id)

    child = _resume(client, parent, run_uuid="candidate-slug-child")
    child_candidate = _first(client, child, "candidates")
    assert child_candidate["state"] == "open"
    assert child_candidate["finding_slug"] == ""
    history = client.get(
        f"{BASE}/assessment-runs/{child['id']}/candidates/{child_candidate['id']}/history"
    ).json()
    assert history[0]["reason"] == (
        f"resumed from terminal run with proof requiring replacement; dropped "
        f"unhealthy proof receipts [{parent_receipt_id}] from parent "
        f"state='duplicate' finding_slug='VA-001'"
    )


def test_resumed_run_reopens_closed_obligation_with_unhealthy_proof(
    client, isolate_settings
) -> None:
    _seed(client, isolate_settings)
    parent = _recovery_parent_run(client, run_uuid="obligation-recovery-parent")
    parent_receipt_id = _recovery_receipt(
        client, parent, slug="obligation-recovery-parent", observed="coverage proven"
    )
    _resolve_obligation(client, parent, receipt_id=parent_receipt_id)
    assert _seal(client, parent)["status"] == "completed"
    _decay_receipt(parent_receipt_id)

    child = _resume(client, parent, run_uuid="obligation-recovery-child")
    child_obligation = _first(client, child, "obligations")
    assert child_obligation["status"] == "open"
    assert child_obligation["proof_receipt_ids"] == []
    assert child_obligation["resolution"] == ""
    assert "proof_stale" not in _blocker_codes(child)

    child_receipt_id = _recovery_receipt(
        client, child, slug="obligation-recovery-child", observed="coverage reproven"
    )
    repaired = client.patch(
        f"{BASE}/assessment-runs/{child['id']}/obligations/{child_obligation['id']}",
        json={
            "status": "resolved",
            "resolution": "replacement proof shows complete coverage",
            "proof_receipt_ids": [child_receipt_id],
        },
    )
    assert repaired.status_code == 200, repaired.text
    assert _seal(client, child)["status"] == "completed"

    history = client.get(
        f"{BASE}/assessment-runs/{child['id']}/obligations/{child_obligation['id']}/history"
    )
    assert history.status_code == 200, history.text
    assert [event["to_status"] for event in history.json()] == ["open", "resolved"]
    assert history.json()[0]["from_status"] == "resolved"
    assert history.json()[0]["proof_receipt_ids"] == [parent_receipt_id]
    assert "parent proved complete coverage" in history.json()[0]["resolution"]

    preserved = _first(client, parent, "obligations")
    assert preserved["status"] == "resolved"
    assert preserved["proof_receipt_ids"] == [parent_receipt_id]


def test_resumed_run_keeps_closed_obligation_whose_proof_is_healthy(
    client, isolate_settings
) -> None:
    _seed(client, isolate_settings)
    parent = _recovery_parent_run(client, run_uuid="obligation-healthy-parent")
    parent_receipt_id = _recovery_receipt(
        client, parent, slug="obligation-healthy-parent", observed="coverage proven"
    )
    _resolve_obligation(client, parent, receipt_id=parent_receipt_id)
    assert _seal(client, parent)["status"] == "completed"

    child = _resume(client, parent, run_uuid="obligation-healthy-child")
    child_obligation = _first(client, child, "obligations")
    assert child_obligation["status"] == "resolved"
    assert child_obligation["resolution"] == "parent proved complete coverage"
    assert child_obligation["proof_receipt_ids"] == [parent_receipt_id]
    assert child["blockers"] == []
    history = client.get(
        f"{BASE}/assessment-runs/{child['id']}/obligations/{child_obligation['id']}/history"
    ).json()
    assert [event["to_status"] for event in history] == ["resolved"]
    assert history[0]["resolution"] == "resumed from terminal run"
    assert _seal(client, child)["status"] == "completed"


def test_resumed_run_drops_unhealthy_source_read_proof_binding(
    client, isolate_settings
) -> None:
    _seed(client, isolate_settings)
    parent = _recovery_parent_run(client, run_uuid="source-read-recovery-parent")
    source = _recovery_source(client, parent)
    parent_receipt_id = _recovery_receipt(
        client, parent, slug="source-read-recovery-parent", observed="source observed"
    )
    _read_source(client, parent, source, attempt=1, receipt_id=parent_receipt_id)
    assert _seal(client, parent)["status"] == "completed"
    _decay_receipt(parent_receipt_id)

    child = _resume(client, parent, run_uuid="source-read-recovery-child")
    # The read itself survives: its observed byte coverage is still true, and
    # only the proof it was bound to has decayed.
    assert _first(client, child, "source-reads")["proof_receipt_id"] is None
    assert "proof_stale" not in _blocker_codes(child)
    assert [event["reason"] for event in child["lifecycle_history"]] == [
        "resumed from terminal run",
        f"resumed from terminal run with proof requiring replacement; dropped "
        f"unhealthy proof receipts [{parent_receipt_id}] from parent source-read "
        f"proof bindings",
    ]

    child_receipt_id = _recovery_receipt(
        client, child, slug="source-read-recovery-child", observed="source re-observed"
    )
    _read_source(
        client,
        child,
        _first(client, child, "sources"),
        attempt=2,
        receipt_id=child_receipt_id,
    )
    assert _seal(client, child)["status"] == "completed"

    preserved = _first(client, parent, "source-reads")
    assert preserved["proof_receipt_id"] == parent_receipt_id


def test_resumed_run_keeps_source_read_proof_binding_that_is_healthy(
    client, isolate_settings
) -> None:
    _seed(client, isolate_settings)
    parent = _recovery_parent_run(client, run_uuid="source-read-healthy-parent")
    source = _recovery_source(client, parent)
    parent_receipt_id = _recovery_receipt(
        client, parent, slug="source-read-healthy-parent", observed="source observed"
    )
    _read_source(client, parent, source, attempt=1, receipt_id=parent_receipt_id)
    assert _seal(client, parent)["status"] == "completed"

    child = _resume(client, parent, run_uuid="source-read-healthy-child")
    assert _first(client, child, "source-reads")["proof_receipt_id"] == parent_receipt_id
    assert child["blockers"] == []
    assert [event["reason"] for event in child["lifecycle_history"]] == [
        "resumed from terminal run"
    ]
    assert _seal(client, child)["status"] == "completed"


def test_resumed_run_collapses_source_reads_that_differ_only_by_dropped_proof(
    client, isolate_settings
) -> None:
    """Dropping a binding must not make two parent reads collide in the child.

    A read recorded before its proof exists and re-recorded once the receipt is
    minted is two parent rows over the same bytes, distinguished only by
    ``proof_receipt_id`` — which is exactly what the read fingerprint keys on.
    When that receipt decays both rows copy down to the same fingerprint, and
    ``UNIQUE(run_id, read_fingerprint)`` would abort the entire resume with a
    500, leaving the run unresumable at the one moment recovery is needed.
    """

    _seed(client, isolate_settings)
    parent = _recovery_parent_run(client, run_uuid="source-read-collapse-parent")
    source = _recovery_source(client, parent)
    parent_receipt_id = _recovery_receipt(
        client, parent, slug="source-read-collapse-parent", observed="source observed"
    )
    read_body = {
        "source_id": source["id"],
        "dispatch_agent_id": "HUNT-RUN-1",
        "attempt": 1,
        "byte_start": 0,
        "byte_end": source["byte_size"],
        "line_start": 1,
        "line_end": source["line_count"],
    }
    unproven = client.post(
        f"{BASE}/assessment-runs/{parent['id']}/source-reads", json=read_body
    )
    assert unproven.status_code == 201, unproven.text
    proven = client.post(
        f"{BASE}/assessment-runs/{parent['id']}/source-reads",
        json={**read_body, "proof_receipt_id": parent_receipt_id},
    )
    assert proven.status_code == 201, proven.text
    assert unproven.json()["id"] != proven.json()["id"]

    assert _seal(client, parent)["status"] == "completed"
    _decay_receipt(parent_receipt_id)

    child = _resume(client, parent, run_uuid="source-read-collapse-child")
    reads = client.get(
        f"{BASE}/assessment-runs/{child['id']}/source-reads",
        params={"limit": 10, "offset": 0},
    )
    assert reads.status_code == 200, reads.text
    assert [row["proof_receipt_id"] for row in reads.json()["items"]] == [None]
    assert "proof_stale" not in _blocker_codes(child)
    # The collapse is not silent: the dropped receipt is named in the child's own
    # lifecycle history, which is the only place a resume records lost bindings.
    assert any(
        str(parent_receipt_id) in event["reason"]
        for event in child["lifecycle_history"]
    )

    # Both parent rows survive untouched — a resume never edits its parent.
    parent_reads = client.get(
        f"{BASE}/assessment-runs/{parent['id']}/source-reads",
        params={"limit": 10, "offset": 0},
    )
    assert sorted(
        (row["proof_receipt_id"] or 0) for row in parent_reads.json()["items"]
    ) == [0, parent_receipt_id]


def test_resumed_run_tolerates_a_malformed_stored_proof_binding(
    client, isolate_settings
) -> None:
    """A row that predates the write-time receipt gate must not break recovery.

    The health lookup and the consumers that dereference it read the stored JSON
    through one filter, so a malformed entry is dropped by both rather than
    counted by one and cast by the other.
    """

    _seed(client, isolate_settings)
    parent = _recovery_parent_run(client, run_uuid="malformed-binding-parent")
    parent_receipt_id = _recovery_receipt(
        client, parent, slug="malformed-binding-parent", observed="candidate rejected"
    )
    candidate = _close_candidate(
        client, parent, identity_key="candidate:malformed", receipt_id=parent_receipt_id
    )
    obligation = _resolve_obligation(client, parent, receipt_id=parent_receipt_id)
    assert _seal(client, parent)["status"] == "completed"
    with db_module.get_connection() as connection:
        connection.execute(
            "UPDATE assessment_run_candidates SET proof_receipt_ids_json = ? WHERE id = ?",
            (json.dumps(["not-an-id"]), candidate["id"]),
        )
        connection.execute(
            "UPDATE assessment_run_obligations SET proof_receipt_ids_json = ? WHERE id = ?",
            (json.dumps([0, None]), obligation["id"]),
        )

    child = _resume(client, parent, run_uuid="malformed-binding-child")
    # The malformed entries are dropped, not dereferenced: the child simply has
    # no inherited evidence left, which is the ordinary empty-proof blocker.
    assert _blocker_codes(child) == {"proof_missing"}
    assert _first(client, child, "candidates")["proof_receipt_ids"] == []
    assert _first(client, child, "obligations")["proof_receipt_ids"] == []


def test_phase2_run_schema_migrates_on_a_disposable_database_without_inventing_audit(
    client, isolate_settings
) -> None:
    _seed(client, isolate_settings)
    db_path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    _replace_run_accounting_with_phase2_schema(db_path)

    db_module.close_thread_connection()
    db_module.init_db()

    with sqlite3.connect(db_path) as connection:
        connection.row_factory = sqlite3.Row
        columns = {
            str(row["name"])
            for row in connection.execute("PRAGMA table_info(assessment_runs)")
        }
        migrated = connection.execute(
            "SELECT * FROM assessment_runs WHERE run_uuid = 'phase2-existing'"
        ).fetchone()
        history = connection.execute(
            "SELECT * FROM assessment_run_lifecycle_events WHERE run_id = ?",
            (migrated["id"],),
        ).fetchall()
        source_count = connection.execute(
            "SELECT COUNT(*) FROM assessment_run_sources WHERE run_id = ?",
            (migrated["id"],),
        ).fetchone()[0]
        migration = connection.execute(
            "SELECT * FROM schema_migrations WHERE migration_id = ?",
            (db_module._RUN_ACCOUNTING_MIGRATION_ID,),
        ).fetchone()
        proof_columns = {
            str(row["name"])
            for row in connection.execute(
                "PRAGMA table_info(assessment_proof_receipts)"
            )
        }
    assert {
        "run_purpose",
        "target_identity_json",
        "source_generations_json",
        "exclusions_json",
        "resumed_from_run_id",
        "seal_json",
        "seal_sha256",
    } <= columns
    assert migrated["status"] == "running"
    assert len(history) == 1
    assert history[0]["to_status"] == "running"
    assert history[0]["reason"] == "migrated Phase 2 run state"
    assert source_count == 0
    assert {"source_read_id", "command_run_id"} <= proof_columns
    assert migration is not None
    backup_path = migration["backup_path"]
    report = json.loads(migration["report_json"])
    assert report["backup_path"] == backup_path
    assert report["preserved_counts"] == {"assessment_runs": 1}
    assert report["status_mappings"] == [
        {
            "from_status": "started",
            "run_id": migrated["id"],
            "run_uuid": "phase2-existing",
            "to_status": "running",
        }
    ]
    with sqlite3.connect(backup_path) as backup:
        assert backup.execute("PRAGMA quick_check").fetchone()[0] == "ok"
        assert backup.execute(
            "SELECT status FROM assessment_runs WHERE run_uuid = 'phase2-existing'"
        ).fetchone()[0] == "started"

    backups_before_retry = sorted(db_path.parent.glob("*.pre-run-accounting.*.bak"))
    db_module.close_thread_connection()
    db_module.init_db()
    backups_after_retry = sorted(db_path.parent.glob("*.pre-run-accounting.*.bak"))
    assert backups_after_retry == backups_before_retry
    with sqlite3.connect(db_path) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM schema_migrations WHERE migration_id = ?",
            (db_module._RUN_ACCOUNTING_MIGRATION_ID,),
        ).fetchone()[0] == 1

    restore_dir = isolate_settings["data_dir"] / "restore-rehearsal"
    restore_dir.mkdir()
    restored_db = restore_dir / db_path.name
    shutil.copy2(backup_path, restored_db)
    original_data_dir = settings.data_dir
    db_module.close_thread_connection()
    object.__setattr__(settings, "data_dir", restore_dir)
    try:
        db_module.init_db()
        with sqlite3.connect(restored_db) as restored:
            assert restored.execute(
                "SELECT status FROM assessment_runs "
                "WHERE run_uuid = 'phase2-existing'"
            ).fetchone()[0] == "running"
            assert restored.execute("PRAGMA quick_check").fetchone()[0] == "ok"
    finally:
        db_module.close_thread_connection()
        object.__setattr__(settings, "data_dir", original_data_dir)


def test_completed_run_accounting_v1_history_upgrades_with_a_distinct_v2_migration(
    client, isolate_settings
) -> None:
    _seed(client, isolate_settings)
    db_path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    with sqlite3.connect(db_path) as connection:
        for table_name in (
            "assessment_run_discovery_passes",
            "assessment_run_tool_signals",
        ):
            connection.execute(f"DROP TABLE {table_name}")
        connection.execute(
            "ALTER TABLE assessment_run_candidates DROP COLUMN originating_signal_id"
        )
        connection.execute(
            "ALTER TABLE assessment_run_code_receipt_links DROP COLUMN target_key"
        )
        connection.execute(
            """
            INSERT INTO schema_migrations (
                migration_id, from_version, to_version, migrated_rows,
                warning_count, backup_path, report_json
            ) VALUES (?, 'phase-2-run-proof-ledger', 'phase-3-run-accounting-v1',
                      0, 0, '/verified/v1.bak', '{}')
            """,
            (db_module._RUN_ACCOUNTING_MIGRATION_ID,),
        )

    db_module.close_thread_connection()
    db_module.init_db()

    expected_reasons = {
        "assessment_run_candidates.missing_column:originating_signal_id",
        "assessment_run_code_receipt_links.missing_column:target_key",
        "missing_table:assessment_run_discovery_passes",
        "missing_table:assessment_run_tool_signals",
    }
    with sqlite3.connect(db_path) as connection:
        connection.row_factory = sqlite3.Row
        migrations = connection.execute(
            "SELECT * FROM schema_migrations WHERE migration_id IN (?, ?) ORDER BY migration_id",
            (
                db_module._RUN_ACCOUNTING_MIGRATION_ID,
                db_module._RUN_ACCOUNTING_V2_MIGRATION_ID,
            ),
        ).fetchall()
        tables = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
        candidate_columns = {
            str(row[1])
            for row in connection.execute(
                "PRAGMA table_info(assessment_run_candidates)"
            ).fetchall()
        }
    assert [row["migration_id"] for row in migrations] == [
        db_module._RUN_ACCOUNTING_MIGRATION_ID,
        db_module._RUN_ACCOUNTING_V2_MIGRATION_ID,
    ]
    assert migrations[0]["backup_path"] == "/verified/v1.bak"
    report = json.loads(migrations[1]["report_json"])
    assert set(report["reasons"]) == expected_reasons
    assert {
        "assessment_run_code_receipt_links",
        "assessment_run_discovery_passes",
        "assessment_run_tool_signals",
    } <= tables
    assert "originating_signal_id" in candidate_columns

    backup_path = migrations[1]["backup_path"]
    with sqlite3.connect(backup_path) as backup:
        assert backup.execute("PRAGMA quick_check").fetchone()[0] == "ok"
        backup_tables = {
            str(row[0])
            for row in backup.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
        backup_candidate_columns = {
            str(row[1])
            for row in backup.execute(
                "PRAGMA table_info(assessment_run_candidates)"
            ).fetchall()
        }
        backup_receipt_columns = {
            str(row[1])
            for row in backup.execute(
                "PRAGMA table_info(assessment_run_code_receipt_links)"
            ).fetchall()
        }
    assert not {
        "assessment_run_discovery_passes",
        "assessment_run_tool_signals",
    }.intersection(backup_tables)
    assert "assessment_run_code_receipt_links" in backup_tables
    assert "originating_signal_id" not in backup_candidate_columns
    assert "target_key" not in backup_receipt_columns

    backups_before_retry = sorted(
        db_path.parent.glob("*.pre-run-accounting-v2.*.bak")
    )
    db_module.close_thread_connection()
    db_module.init_db()
    backups_after_retry = sorted(
        db_path.parent.glob("*.pre-run-accounting-v2.*.bak")
    )
    assert backups_after_retry == backups_before_retry


def test_run_accounting_migration_rolls_back_on_interruption(
    client, isolate_settings, monkeypatch
) -> None:
    _seed(client, isolate_settings)
    db_path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    _replace_run_accounting_with_phase2_schema(db_path)
    original_migration = db_module._create_verification_evidence_tables

    def interrupted_migration(connection) -> None:
        original_migration(connection)
        raise RuntimeError("simulated migration interruption")

    monkeypatch.setattr(
        db_module, "_create_verification_evidence_tables", interrupted_migration
    )
    db_module.close_thread_connection()
    with pytest.raises(RuntimeError, match="simulated migration interruption"):
        db_module.init_db()

    backups = sorted(db_path.parent.glob("*.pre-run-accounting.*.bak"))
    assert len(backups) == 1
    with sqlite3.connect(db_path) as connection:
        columns = {
            str(row[1])
            for row in connection.execute("PRAGMA table_info(assessment_runs)")
        }
        assert "run_purpose" not in columns
        assert connection.execute(
            "SELECT status FROM assessment_runs WHERE run_uuid = 'phase2-existing'"
        ).fetchone()[0] == "started"
        assert connection.execute("PRAGMA quick_check").fetchone()[0] == "ok"
    with sqlite3.connect(backups[0]) as backup:
        assert backup.execute(
            "SELECT status FROM assessment_runs WHERE run_uuid = 'phase2-existing'"
        ).fetchone()[0] == "started"
        assert backup.execute("PRAGMA quick_check").fetchone()[0] == "ok"
