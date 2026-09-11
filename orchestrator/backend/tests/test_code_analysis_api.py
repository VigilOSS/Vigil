from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import sys
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Barrier, Event
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest
from app import db as db_module
from app.api.code_analysis import QueueItemsBulkCreateRequest
from app.services import code_analysis, code_fuzz_completion
from fastapi import HTTPException
from pydantic import ValidationError
from tests.proof_fixtures import post_artifact_backed_source_observation

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPTS_ROOT = REPO_ROOT / "agent" / "scripts"
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

from assess.lib.code_snapshot import SnapshotBuilder, capture_regular_file  # noqa: E402
from assess.commands import code_dispatch  # noqa: E402
from assess.lib.code_structural_identity import (  # noqa: E402
    STRUCTURAL_INDEX_SCHEMA as CLI_STRUCTURAL_INDEX_SCHEMA,
    structural_input_digest as cli_structural_input_digest,
)


_SEALED_TEST_BYTES_BY_HASH: dict[str, bytes] = {}


def test_million_file_inventory_dispatch_and_queue_retry_qualification(
    client, isolate_settings, monkeypatch, tmp_path, capsys
) -> None:
    """Exercise production listing and dispatch without materializing 1M DB rows."""

    engagement_key = "million-file-qualification"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    assert client.get("/engagements").status_code == 200
    repo = _create_repo(client, engagement_key, "million-file-repo")
    repo_id = int(repo["id"])
    selected_manifest = [
        {
            "file_path": f"src/selected-{index:03d}.py",
            "language": "python",
            "loc": 1,
            "file_hash": _source_hash(f"million-selected-{index}"),
            "header_snippet": "pass\n",
            "git_churn_score": 0,
            "has_past_cve_fix": False,
        }
        for index in range(200)
    ]
    selected_rows = _refresh_repo_files(
        client, engagement_key, repo_id, selected_manifest
    )
    selected_paths_by_id = {
        int(row["id"]): str(row["file_path"]) for row in selected_rows
    }
    assert len(selected_paths_by_id) == 200
    total_files = 1_000_000
    selected_ids = sorted(selected_paths_by_id)
    selected_positions = [
        1 + (index * (total_files - 1) // (len(selected_ids) - 1))
        for index in range(len(selected_ids))
    ]
    selected_id_by_position = dict(zip(selected_positions, selected_ids, strict=True))
    assert selected_positions[0] == 1
    assert selected_positions[-1] == total_files
    assert any(
        total_files // 2 <= position < total_files // 2 + 10_000
        for position in selected_positions
    )

    selectors = [
        {
            "file_path": selected_paths_by_id[file_id],
            "repo_id": repo_id,
            "priority": 0,
        }
        for file_id in sorted(selected_paths_by_id)
    ]
    # The production dispatcher must compile exact selectors once. A per-row
    # scan of all 200 selectors turns this qualification into 200M comparisons.
    code_dispatch._compile_queue_lookup(selectors)

    class VirtualCursor:
        def __init__(self, rows):
            self.rows = rows

        def fetchone(self):
            return self.rows[0] if self.rows else None

        def fetchall(self):
            return self.rows

    class VirtualInventory:
        scan = 0
        opened = 0
        closed = 0
        returned_rows = {1: 0, 2: 0}
        requested_offsets = {1: [], 2: []}
        max_page_rows = 0

        def execute(self, statement: str, _params=()):
            if "SELECT COUNT(*)" in statement:
                return VirtualCursor([(total_files,)])
            if "SELECT files.*" in statement:
                limit_match = re.search(r"LIMIT (\d+)", statement)
                offset_match = re.search(r"OFFSET (\d+)", statement)
                assert limit_match is not None
                limit = int(limit_match.group(1))
                offset = int(offset_match.group(1)) if offset_match else 0
                if offset == 0:
                    type(self).scan += 1
                scan = type(self).scan
                type(self).requested_offsets[scan].append(offset)
                if scan == 1 and offset == total_files // 2:
                    raise KeyboardInterrupt
                stop = min(total_files, offset + limit)
                rows = []
                for position in range(offset + 1, stop + 1):
                    selected_id = selected_id_by_position.get(position)
                    file_id = selected_id or 1_000_000_000 + position
                    type(self).returned_rows[scan] += 1
                    rows.append(
                        {
                            "id": file_id,
                            "engagement_id": 1,
                            "repo_id": repo_id,
                            "file_path": (
                                selected_paths_by_id[selected_id]
                                if selected_id is not None
                                else f"virtual/{position:07d}.py"
                            ),
                            "analysis_priority": 0,
                            "slot_types_json": "[]",
                            "structural_unavailable_dimensions_json": "[]",
                            "structural_truncated_dimensions_json": "[]",
                            "structural_signal_counts_json": "{}",
                            "structural_artifact_truncated": 0,
                            "variant_check_status": "pending",
                        }
                    )
                type(self).max_page_rows = max(
                    type(self).max_page_rows, len(rows)
                )
                return VirtualCursor(rows)
            if "SELECT queue.*, repos.active_generation" in statement:
                return VirtualCursor([])
            raise AssertionError(f"unexpected virtual inventory query: {statement}")

    inventory = VirtualInventory()

    @contextmanager
    def virtual_connection():
        type(inventory).opened += 1
        try:
            yield inventory
        finally:
            type(inventory).closed += 1

    class InventoryClient:
        def __init__(self, *_args) -> None:
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def get(self, endpoint: str):
            query = parse_qs(urlsplit(endpoint).query)
            return code_analysis.list_code_files(
                int(repo["engagement_id"]),
                limit=int(query["limit"][0]),
                offset=int(query["offset"][0]),
            )

    cfg = SimpleNamespace(
        base_url="http://example.test",
        engagement_key=engagement_key,
        engagement_dir=str(tmp_path),
    )
    with monkeypatch.context() as inventory_patch:
        inventory_patch.setattr(code_analysis, "get_connection", virtual_connection)
        inventory_patch.setattr(
            code_dispatch, "AssessmentClient", InventoryClient
        )
        with pytest.raises(KeyboardInterrupt):
            code_dispatch._normalize_queue_items(cfg, selectors)
        normalized = code_dispatch._normalize_queue_items(cfg, selectors)

    expected_offsets = list(
        range(0, total_files, code_dispatch._CODE_FILE_LOOKUP_PAGE_SIZE)
    )
    assert {
        (position - 1) // code_dispatch._CODE_FILE_LOOKUP_PAGE_SIZE
        * code_dispatch._CODE_FILE_LOOKUP_PAGE_SIZE
        for position in selected_positions
    } == set(expected_offsets)
    assert VirtualInventory.requested_offsets == {
        1: expected_offsets[: total_files // 2 // 10_000 + 1],
        2: expected_offsets,
    }
    assert VirtualInventory.returned_rows == {
        1: total_files // 2,
        2: total_files,
    }
    assert VirtualInventory.opened == VirtualInventory.closed
    assert VirtualInventory.max_page_rows == code_dispatch._CODE_FILE_LOOKUP_PAGE_SIZE
    assert len(normalized) == 200
    assert {item["file_id"] for item in normalized} == set(selected_paths_by_id)

    queue_path = tmp_path / "million-qualified-queue.json"
    queue_path.write_text(json.dumps(normalized), encoding="utf-8")
    snapshots = iter(range(10))

    def snapshot(*_args, **_kwargs):
        path = tmp_path / f"queue-snapshot-{next(snapshots)}.json"
        path.write_text("{}", encoding="utf-8")
        return path

    posted_sizes: list[int] = []

    class QueueClient:
        cancel_after_commit = True

        def __init__(self, *_args) -> None:
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def post(self, endpoint: str, payload: dict[str, object]):
            assert endpoint == "code/analysis-queue"
            request = QueueItemsBulkCreateRequest.model_validate(payload)
            posted_sizes.append(len(request.items))
            response = client.post(
                f"/engagements/{engagement_key}/assessment/code/analysis-queue",
                json=payload,
            )
            assert response.status_code == 201, response.text
            if type(self).cancel_after_commit:
                type(self).cancel_after_commit = False
                raise KeyboardInterrupt
            return response.json()

    monkeypatch.setattr(code_dispatch, "write_json_snapshot", snapshot)
    monkeypatch.setattr(code_dispatch, "AssessmentClient", QueueClient)
    with pytest.raises(KeyboardInterrupt):
        code_dispatch._queue(cfg, str(queue_path))
    code_dispatch._queue(cfg, str(queue_path))

    output = capsys.readouterr().out
    assert posted_sizes == [200, 200]
    assert "inserted=0, updated=0, already-active=200, conflicts=0" in output
    assert '"outcomes_truncated": false' in output
    with db_module.get_connection() as connection:
        stored_count = int(
            connection.execute(
                "SELECT COUNT(*) FROM code_analysis_queue"
            ).fetchone()[0]
        )
    assert stored_count == 200


def test_queue_bulk_request_rejects_more_than_one_bounded_submission() -> None:
    with pytest.raises(ValidationError):
        QueueItemsBulkCreateRequest.model_validate(
            {
                "items": [
                    {"file_id": file_id, "priority": 90}
                    for file_id in range(1, 202)
                ]
            }
        )


def _source_hash(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


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
        "source_origin_path": repo_path,
        "source_kind": "directory",
        "snapshot_manifest_path": "tools/analysis-state/source-snapshot-manifest.json",
        "snapshot_digest": "a" * 64,
        "source_manifest_version": "v1",
        "source_snapshot_quality": "verified",
        "worktree_dirty": False,
        "total_files": 2,
        "analyzable_files": 2,
        "total_loc": 120,
        "commit_hash": "abc123",
        "branch": "main",
        "git_churn": {},
    }


def _test_source_bytes(record: dict[str, object]) -> bytes:
    supplied_hash = str(record.get("file_hash") or "")
    retained = _SEALED_TEST_BYTES_BY_HASH.get(supplied_hash)
    if retained is not None:
        return retained
    line_count = int(record.get("loc") or 0)
    if line_count <= 0:
        content = b""
    else:
        first_line = (
            f"# vigil-test-source {record['file_path']} {supplied_hash}\n".encode(
                "utf-8"
            )
        )
        content = first_line + b"# filler\n" * (line_count - 1)
    _SEALED_TEST_BYTES_BY_HASH[hashlib.sha256(content).hexdigest()] = content
    return content


def _verified_repo_payload(
    client,
    engagement_key: str,
    repo_key: str,
    files: list[dict[str, object]] | None = None,
    *,
    source_origin_path: str | None = None,
    repo_name: str | None = None,
    git: dict[str, object] | None = None,
    excluded_entries: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    """Materialize one genuine engagement-owned read-only v2 test snapshot."""
    assert client.get("/engagements").status_code == 200
    with db_module.get_connection() as connection:
        row = connection.execute(
            "SELECT engagement_root FROM engagements WHERE key = ?",
            (engagement_key,),
        ).fetchone()
    assert row is not None
    engagement_root = Path(str(row["engagement_root"])).resolve()
    records = files if files is not None else []
    exclusions = excluded_entries or []
    input_identity = hashlib.sha256(
        json.dumps(
            {"files": records, "excluded_entries": exclusions},
            sort_keys=True,
            default=str,
        ).encode("utf-8")
    ).hexdigest()[:16]
    origin = (
        engagement_root
        / "tools"
        / "analysis-state"
        / "test-source-origins"
        / repo_key
        / input_identity
    )
    origin.mkdir(parents=True, exist_ok=True)
    builder = SnapshotBuilder(
        engagement_root / "tools" / "analysis-state" / "code-snapshots",
        repo_key,
    )
    try:
        for record in sorted(records, key=lambda item: str(item["file_path"])):
            relative = Path(str(record["file_path"]))
            source_file = origin.joinpath(*relative.parts)
            source_file.parent.mkdir(parents=True, exist_ok=True)
            source_file.write_bytes(_test_source_bytes(record))
            captured = capture_regular_file(source_file)
            record["file_hash"] = captured.sha256
            record["loc"] = captured.loc
            record["header_snippet"] = captured.header
            builder.add(
                str(record["file_path"]),
                captured,
                language=str(record.get("language") or ""),
            )
        origin_identity = source_origin_path or f"/tmp/{repo_key}"
        git_provenance = (
            git
            if git is not None
            else {"head": "", "branch": "", "dirty": None}
        )
        sealed = builder.finish(
            repo_key=repo_key,
            repo_name=repo_name or repo_key,
            source_origin_path=origin_identity,
            git=git_provenance,
            excluded_entries=exclusions,
        )
    except BaseException:
        builder.abort()
        raise
    return {
        "repo_key": repo_key,
        "name": repo_name or repo_key,
        "language": "python",
        "repo_path": str(sealed.source_path),
        "source_origin_path": origin_identity,
        "source_kind": "git" if git_provenance["head"] else "directory",
        "snapshot_manifest_path": str(sealed.manifest_path),
        "snapshot_digest": sealed.snapshot_digest,
        "source_manifest_version": "v1",
        "source_snapshot_quality": "verified",
        "worktree_dirty": git_provenance["dirty"],
        "total_files": len(records)
        + sum(1 for record in exclusions if record.get("kind") != "directory"),
        "analyzable_files": len(records),
        "total_loc": sum(int(record.get("loc") or 0) for record in records),
        "commit_hash": git_provenance["head"],
        "branch": git_provenance["branch"],
        "git_churn": {},
    }


def _create_repo(client, engagement_key: str, repo_key: str = "demo-repo") -> dict[str, object]:
    base = f"/engagements/{engagement_key}/assessment/code"
    started = client.post(
        f"{base}/repos/refresh/start",
        json=_verified_repo_payload(client, engagement_key, repo_key),
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


def _finding_code_snapshot(client, engagement_key: str, repo_id: int) -> dict[str, object]:
    response = client.get(
        f"/engagements/{engagement_key}/assessment/code/repos/{repo_id}"
    )
    assert response.status_code == 200, response.text
    repo = response.json()
    return {
        "repo_id": repo_id,
        "repo_generation": repo["active_generation"],
        "source_manifest_digest": repo["source_manifest_digest"],
    }


def _ensure_finding_author_dispatch(
    client, engagement_key: str, agent_id: str
) -> None:
    base = f"/engagements/{engagement_key}/assessment/dispatches"
    existing = client.get(f"{base}/{agent_id}")
    if existing.status_code == 200:
        return
    assert existing.status_code == 404, existing.text
    response = client.post(
        base,
        json={
            "agent_id": agent_id,
            "agent_role": "code-vuln-hunter",
            "task": "Record the fixture finding from the sealed source snapshot.",
        },
    )
    assert response.status_code == 201, response.text


def _create_root_finding(client, engagement_key: str, slug: str, *, source_name: str = "code-vuln-hunter") -> None:
    author_agent_id = f"AUTHOR-{slug}"
    _ensure_finding_author_dispatch(client, engagement_key, author_agent_id)
    response = client.post(
        f"/engagements/{engagement_key}/assessment/findings",
        json={
            "slug": slug,
            "title": f"Root finding {slug}",
            "severity": "medium",
            "workflow_status": "active",
            "verification_status": "unreviewed",
            "defect_family": "root-cause",
            "root_cause_key": slug.lower(),
            "auth_context": "anonymous",
            "canonical_location": f"https://example.com/root/{slug}",
            "summary": "Root finding for canonical variant link tests.",
            "evidence_ref": "findings.md",
            "notes": "",
            "source_name": source_name,
            "details": {"evidence": "root"},
            "provenance": {
                "agent_id": author_agent_id,
                "agent_name": source_name,
            },
            "links": [],
        },
    )
    assert response.status_code == 201, response.text


def _create_files(client, engagement_key: str, repo_id: int) -> list[dict[str, object]]:
    base = f"/engagements/{engagement_key}/assessment/code"
    repo_response = client.get(f"{base}/repos/{repo_id}")
    assert repo_response.status_code == 200, repo_response.text
    repo = repo_response.json()
    files: list[dict[str, object]] = [
        {
            "file_path": "src/parser.py",
            "language": "python",
            "loc": 80,
            "file_hash": _source_hash("hash-a"),
            "header_snippet": "def parse(data):\n    return data\n",
            "git_churn_score": 4,
            "has_past_cve_fix": False,
        },
        {
            "file_path": "src/helpers.py",
            "language": "python",
            "loc": 40,
            "file_hash": _source_hash("hash-b"),
            "header_snippet": "def helper(value):\n    return value\n",
            "git_churn_score": 2,
            "has_past_cve_fix": False,
        },
    ]
    started = client.post(
        f"{base}/repos/refresh/start",
        json=_verified_repo_payload(
            client,
            engagement_key,
            str(repo["repo_key"]),
            files,
            source_origin_path=str(repo["source_origin_path"]),
            repo_name=str(repo["name"]),
        ),
    )
    assert started.status_code == 201, started.text
    refresh_token = started.json()["refresh_token"]
    response = client.post(
        f"{base}/repos/{repo_id}/refresh/files",
        json={
            "refresh_token": refresh_token,
            "files": files,
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
        "&include_header_snippet=true"
    )
    assert files_response.status_code == 200
    return files_response.json()["items"]


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
        json=_verified_repo_payload(
            client,
            engagement_key,
            str(repo["repo_key"]),
            files,
            source_origin_path=str(repo["source_origin_path"]),
            repo_name=str(repo["name"]),
        ),
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
    return client.get(
        f"{base}/files?repo_id={repo_id}&limit=10000&include_header_snippet=true"
    ).json()["items"]


def _append_repo_files(
    client,
    engagement_key: str,
    repo_id: int,
    additions: list[dict[str, object]],
) -> list[dict[str, object]]:
    base = f"/engagements/{engagement_key}/assessment/code"
    current = client.get(
        f"{base}/files?repo_id={repo_id}&limit=10000&include_header_snippet=true"
    ).json()["items"]
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


def _create_code_parent_finding(
    client,
    engagement_key: str,
    repo_id: int,
    *,
    slug: str,
    file_path: str = "src/parser.py",
    source_name: str = "code-vuln-hunter",
    severity: str = "high",
    workflow_status: str = "active",
    line: int = 10,
    allow_remint: bool = False,
    links: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    author_agent_id = f"AUTHOR-{slug}"
    _ensure_finding_author_dispatch(client, engagement_key, author_agent_id)
    response = client.post(
        f"/engagements/{engagement_key}/assessment/findings",
        json={
            "slug": slug,
            "title": f"Parent pattern {slug}",
            "severity": severity,
            "workflow_status": workflow_status,
            "verification_status": "unreviewed",
            "defect_family": "parser-memory-safety",
            "root_cause_key": f"parser-memory-safety-{slug.lower()}",
            "auth_context": "anonymous",
            "canonical_location": f"file:{file_path}:{line}",
            "summary": "Current code finding assigned for variant analysis.",
            "evidence_ref": f"tools/analysis-state/{slug.lower()}.json",
            "notes": "",
            "source_name": source_name,
            "details": {"evidence": "Attacker-controlled parser path."},
            "provenance": {
                "agent_id": author_agent_id,
                "agent_name": source_name,
                "code_snapshot": _finding_code_snapshot(
                    client,
                    engagement_key,
                    repo_id,
                ),
            },
            "links": links or [],
            "allow_remint": allow_remint,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _verify_code_finding(
    client,
    engagement_key: str,
    repo_id: int,
    slug: str,
    *,
    disposition: str = "confirmed",
    reason_code: str = "source-proof",
    reason_text: str = "Verified against the current sealed source snapshot.",
    artifact_ref: str | None = None,
    details: dict[str, object] | None = None,
    new_severity: str | None = None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "verification_status": disposition,
        "reason_code": reason_code,
        "reason_text": reason_text,
        "source_name": "code-vuln-verifier",
        "provenance": {
            "agent_name": "code-vuln-verifier",
            "code_snapshot": _finding_code_snapshot(client, engagement_key, repo_id),
        },
    }
    if artifact_ref is not None:
        payload["artifact_ref"] = artifact_ref
    if details is not None:
        payload["details"] = details

    if disposition in {"confirmed", "downgraded", "false_positive"}:
        verifier_id = f"VERIFY-{slug}-{disposition}"
        dispatch = client.post(
            f"/engagements/{engagement_key}/assessment/dispatches",
            json={
                "agent_id": verifier_id,
                "agent_role": "code-vuln-verifier",
                "task": f"Independently verify {slug} against the sealed source snapshot.",
                "skills": "code-finding-verification",
            },
        )
        assert dispatch.status_code == 201, dispatch.text
        run = client.post(
            f"/engagements/{engagement_key}/assessment/assessment-runs",
            json={
                "run_uuid": f"verify-{slug.lower()}-{disposition}",
                "run_kind": "code",
                "producer_dispatch_agent_id": verifier_id,
            },
        )
        assert run.status_code == 201, run.text
        receipt = post_artifact_backed_source_observation(
            client,
            f"/engagements/{engagement_key}/assessment/proof-receipts",
            json={
                "run_id": run.json()["id"],
                "evidence_kind": "source_observation",
                "expected_result": "the suspected source path survives an independent counter-check",
                "observed_result": reason_text,
            },
        )
        assert receipt.status_code == 201, receipt.text
        completed = client.patch(
            f"/engagements/{engagement_key}/assessment/assessment-runs/{run.json()['id']}",
            json={"status": "completed"},
        )
        assert completed.status_code == 200, completed.text
        receipt_id = receipt.json()["id"]
        payload["proof_receipt_ids"] = [receipt_id]
        if disposition == "false_positive":
            payload["counter_check"] = {
                "method": "sealed-source reachability review",
                "expected_result": "an attacker-controlled path reaches the suspected sink",
                "observed_result": reason_text,
                "falsified_claim": "the suspected path is attacker reachable",
                "completed": True,
                "proof_receipt_ids": [receipt_id],
            }
        elif disposition == "downgraded":
            chosen_severity = new_severity or "medium"
            payload["new_severity"] = chosen_severity
            payload["severity_variance"] = {
                "normal_band": "high",
                "chosen_severity": chosen_severity,
                "actor": verifier_id,
                "reason": "Independent source review supports a lower impact band.",
                "proof_receipt_id": receipt_id,
            }

    response = client.post(
        f"/engagements/{engagement_key}/assessment/findings/{slug}/verify",
        json=payload,
    )
    assert response.status_code == 200, response.text
    return response.json()


def _register_variant_dispatch(
    client,
    engagement_key: str,
    *,
    agent_id: str,
    finding_slugs: list[str],
    role: str = "code-variant-hunter",
    status: str = "in-progress",
) -> dict[str, object]:
    response = client.post(
        f"/engagements/{engagement_key}/assessment/dispatches",
        json={
            "agent_id": agent_id,
            "agent_role": role,
            "task": "Search for variants of the dispatch-registered code findings.",
            "status": status,
            "dispatch_mode": "hypothesis-driven",
            "finding_slugs": finding_slugs,
            "skills": "code-variant-analysis",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _variant_receipt_payload(
    client,
    engagement_key: str,
    repo_id: int,
    file_row: dict[str, object],
    dispatch: dict[str, object],
    *,
    parent_finding_slugs: list[str],
) -> dict[str, object]:
    binding = client.get(
        f"/engagements/{engagement_key}/assessment/code/repos/{repo_id}"
    ).json()
    return {
        "dispatch_id": dispatch["id"],
        "file_id": file_row["id"],
        "repo_id": repo_id,
        "repo_generation": binding["active_generation"],
        "source_manifest_digest": binding["source_manifest_digest"],
        "file_sha256": file_row["file_hash"],
        "parent_finding_slugs": parent_finding_slugs,
        "status": "completed",
        "evidence_ref": "tools/analysis-state/variant-check.json",
        "rationale": "Reviewed sibling parser paths against every assigned parent pattern.",
    }


def _bind_structural_identity(payload: dict[str, object]) -> dict[str, object]:
    bound = json.loads(json.dumps(payload))
    bound.setdefault("structural_index_schema", "structural-index/v6")
    repo_id = int(bound["repo_id"])
    with db_module.get_connection() as connection:
        current_files = [
            dict(row)
            for row in connection.execute(
                "SELECT * FROM code_files WHERE repo_id = ? ORDER BY file_path",
                (repo_id,),
            ).fetchall()
        ]
    current_by_id = {int(row["id"]): row for row in current_files}
    for update in bound.get("updates", []):
        file_row = current_by_id[int(update["file_id"])]
        update["indexed_language"] = code_analysis.canonical_structural_language(
            file_row["language"]
        )
    bound["structural_input_digest"] = code_analysis.structural_input_identity_digest(
        repo_id=repo_id,
        repo_generation=int(bound["repo_generation"]),
        source_manifest_digest_value=str(bound["source_manifest_digest"]),
        files=current_files,
    )
    return bound


def _complete_structural_payload(
    *,
    repo_id: int,
    repo_generation: int,
    source_manifest_digest: str,
    updates: list[dict[str, object]],
    structural_index_manifest_path: str = "tools/analysis-state/structural-index/manifest.json",
) -> dict[str, object]:
    enriched_updates = [
        {
            **item,
            "structural_analysis_status": "complete",
            "structural_analysis_mode": "tree_sitter",
            "structural_degradation_reason": None,
            "structural_source_size": 1,
            "structural_bytes_scanned": 1,
            "structural_unavailable_dimensions": [],
            "structural_artifact_truncated": False,
            "structural_truncated_dimensions": [],
            "structural_signal_counts": {
                "entry_points": int(item["total_entry_points"]),
                "imports": 0,
                "security_sinks": int(item["total_sinks"]),
                "security_sources": 0,
            },
        }
        for item in updates
    ]
    return _bind_structural_identity({
        "repo_id": repo_id,
        "repo_generation": repo_generation,
        "source_manifest_digest": source_manifest_digest,
        "structural_index_manifest_path": structural_index_manifest_path,
        "degraded_files": 0,
        "degraded_file_paths": [],
        "artifact_truncated_files": 0,
        "artifact_truncated_file_paths": [],
        "analysis_status_counts": {
            "complete": len(enriched_updates),
            "degraded": 0,
            "unsupported": 0,
        },
        "updates": enriched_updates,
    })


def _publish_structural_totals(
    client,
    engagement_key: str,
    repo_id: int,
    files: list[dict[str, object]],
    totals_by_file_id: dict[int, dict[str, int]],
) -> dict[str, object]:
    """Publish parser-owned totals through the complete structural-index boundary."""
    base = f"/engagements/{engagement_key}/assessment/code"
    binding = client.get(f"{base}/repos/{repo_id}").json()
    updates: list[dict[str, object]] = []
    for file_row in files:
        totals = {
            "total_functions": 0,
            "total_entry_points": 0,
            "total_sinks": 0,
            "total_exports": 0,
            **totals_by_file_id.get(int(file_row["id"]), {}),
        }
        updates.append(
            {
                "file_id": file_row["id"],
                "source_sha256": file_row["file_hash"],
                **totals,
            }
        )
    response = client.post(
        f"{base}/files/bulk-structural-metadata",
        json=_complete_structural_payload(
            repo_id=repo_id,
            repo_generation=int(binding["active_generation"]),
            source_manifest_digest=str(binding["source_manifest_digest"]),
            updates=updates,
        ),
    )
    assert response.status_code == 200, response.text
    return response.json()


def _claim_file_for_analysis(
    client,
    engagement_key: str,
    file_id: int,
    *,
    priority: int | None = None,
    agent_name: str = "code-vuln-hunter",
) -> dict[str, object]:
    if priority is None:
        file_response = client.get(
            f"/engagements/{engagement_key}/assessment/code/files/{file_id}"
        )
        assert file_response.status_code == 200, file_response.text
        priority = int(file_response.json()["analysis_priority"])
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


def _claim_file_for_reanalysis(
    client,
    engagement_key: str,
    file_id: int,
    *,
    reason: str,
    priority: int | None = None,
    agent_name: str = "code-vuln-hunter",
) -> dict[str, object]:
    if priority is None:
        file_response = client.get(
            f"/engagements/{engagement_key}/assessment/code/files/{file_id}"
        )
        assert file_response.status_code == 200, file_response.text
        priority = int(file_response.json()["analysis_priority"])
    with db_module.get_connection() as connection:
        predecessor = connection.execute(
            """
            SELECT queue.id
            FROM code_analysis_queue AS queue
            JOIN code_files AS files ON files.id = queue.file_id
            JOIN code_repos AS repos ON repos.id = files.repo_id
            WHERE queue.engagement_id = (
                SELECT id FROM engagements WHERE key = ?
            )
              AND queue.file_id = ?
              AND queue.repo_generation = repos.active_generation
            ORDER BY queue.id DESC LIMIT 1
            """,
            (engagement_key, file_id),
        ).fetchone()
    assert predecessor is not None
    queue_response = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue",
        json={
            "mode": "reanalysis",
            "reason": reason,
            "items": [
                {
                    "file_id": file_id,
                    "priority": priority,
                    "supersedes": int(predecessor["id"]),
                }
            ],
        },
    )
    assert queue_response.status_code == 201, queue_response.text
    assert queue_response.json()["reanalysis"] == 1
    claimed = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/fetch",
        json={"limit": 1, "agent_name": agent_name},
    )
    assert claimed.status_code == 200, claimed.text
    queue_item = claimed.json()[0]
    assert queue_item["file_id"] == file_id
    return queue_item


def _owned(queue_item: dict[str, object], **payload: object) -> dict[str, object]:
    """Build an explicit lease-owned mutation payload."""
    return {
        **payload,
        "agent_name": queue_item["agent_name"],
        "lease_token": queue_item["lease_token"],
    }


def _seed_reviewed_parser(client, isolate_settings, engagement_key: str):
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key=f"{engagement_key}-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser = next(row for row in files if row["file_path"] == "src/parser.py")
    _publish_structural_totals(
        client,
        engagement_key,
        int(repo["id"]),
        files,
        {
            int(parser["id"]): {
                "total_functions": 7,
                "total_entry_points": 2,
                "total_sinks": 3,
                "total_exports": 4,
            }
        },
    )
    patched = client.patch(
        f"/engagements/{engagement_key}/assessment/code/files/{parser['id']}",
        json={
            "analysis_depth": "deep",
            "notes": "source review notes",
        },
    )
    assert patched.status_code == 200, patched.text
    db_path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    with sqlite3.connect(str(db_path)) as connection:
        connection.execute(
            "UPDATE code_files SET variant_check_status = 'done' WHERE id = ?",
            (parser["id"],),
        )
        connection.commit()
    _classify_file(client, engagement_key, int(parser["id"]), "high", 79)
    queued = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue",
        json={
            "items": [
                {
                    "file_id": parser["id"],
                    "priority": 79,
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


def _refresh_one_file_metadata(
    client,
    engagement_key: str,
    repo_id: int,
    file_id: int,
    *,
    legacy_unverified: bool = False,
    **changes,
):
    base = f"/engagements/{engagement_key}/assessment/code"
    current = client.get(
        f"{base}/files?repo_id={repo_id}&limit=10000&include_header_snippet=true"
    ).json()["items"]
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
    if not legacy_unverified:
        return _refresh_repo_files(client, engagement_key, repo_id, manifest)

    repo = client.get(f"{base}/repos/{repo_id}").json()
    payload = {
        **_repo_payload(str(repo["repo_key"]), str(repo["repo_path"])),
        "name": str(repo["name"]),
        "source_origin_path": str(repo["source_origin_path"]),
        "source_kind": "legacy",
        "snapshot_manifest_path": "",
        "snapshot_digest": "",
        "source_snapshot_quality": "legacy-unverified",
        "worktree_dirty": None,
        "total_files": len(manifest),
        "analyzable_files": len(manifest),
        "total_loc": sum(int(record.get("loc") or 0) for record in manifest),
        "commit_hash": "",
        "branch": "",
    }
    started = client.post(f"{base}/repos/refresh/start", json=payload)
    assert started.status_code == 201, started.text
    token = started.json()["refresh_token"]
    staged = client.post(
        f"{base}/repos/{repo_id}/refresh/files",
        json={"refresh_token": token, "files": manifest},
    )
    assert staged.status_code == 200, staged.text
    committed = client.post(
        f"{base}/repos/{repo_id}/refresh/commit",
        json={"refresh_token": token, "manifest_complete": True},
    )
    assert committed.status_code == 200, committed.text
    return client.get(
        f"{base}/files?repo_id={repo_id}&limit=10000&include_header_snippet=true"
    ).json()["items"]


@pytest.mark.parametrize(
    "repo_key",
    ["/tmp/escape", "../escape", "nested/escape", r"nested\escape", ".", ".."],
)
def test_repo_refresh_and_preview_reject_repo_keys_that_are_not_safe_components(
    client, isolate_settings, repo_key
):
    engagement_key = "2026-08-04-code-repo-key-validation"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    base = f"/engagements/{engagement_key}/assessment/code"

    start = client.post(
        f"{base}/repos/refresh/start",
        json={**_repo_payload("safe-repo", "/tmp/source"), "repo_key": repo_key},
    )
    preview = client.post(
        f"{base}/repos/refresh/preview",
        json={"repo_key": repo_key, "files": []},
    )

    assert start.status_code == 422
    assert preview.status_code == 422
    assert client.get(f"{base}/repos").json() == []


@pytest.mark.parametrize("repo_key", ["a" * 256, "é" * 128])
def test_repo_refresh_and_preview_reject_repo_keys_over_portable_component_limit(
    client, isolate_settings, repo_key
):
    engagement_key = "2026-08-04-code-repo-key-length"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    base = f"/engagements/{engagement_key}/assessment/code"

    start = client.post(
        f"{base}/repos/refresh/start",
        json={**_repo_payload("safe-repo", "/tmp/source"), "repo_key": repo_key},
    )
    preview = client.post(
        f"{base}/repos/refresh/preview",
        json={"repo_key": repo_key, "files": []},
    )

    assert start.status_code == 422
    assert preview.status_code == 422
    assert client.get(f"{base}/repos").json() == []


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


def test_code_file_listing_is_bounded_envelope_with_current_queue_join(
    client, isolate_settings
):
    engagement_key = "2026-09-11-code-file-envelope"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="file-envelope-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser_file = next(row for row in files if row["file_path"] == "src/parser.py")
    _classify_file(client, engagement_key, int(parser_file["id"]), "critical", 95)
    queue = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue",
        json={"items": [{"file_id": parser_file["id"], "priority": 95}]},
    )
    assert queue.status_code == 201, queue.text
    queue_id = queue.json()["outcomes"][0]["queue_item_id"]

    endpoint = (
        f"/engagements/{engagement_key}/assessment/code/files"
        f"?repo_id={repo['id']}&limit=1&offset=0"
    )
    response = client.get(endpoint)

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload.keys() == {"total", "offset", "count", "has_more", "items"}
    assert payload["total"] == 2
    assert payload["offset"] == 0
    assert payload["count"] == 1
    assert payload["has_more"] is True
    assert len(payload["items"]) == 1
    item = payload["items"][0]
    assert "header_snippet" not in item
    assert item["queue"] == {
        "state": "current",
        "current_attempt": {
            "id": queue_id,
            "status": "pending",
            "priority": 95,
            "queue_mode": "initial",
            "batch_theme": "",
            "repo_generation": 2,
            "agent_name": "",
            "lease_token": "",
        },
        "historical_attempts": 0,
    }

    with_snippet = client.get(endpoint + "&include_header_snippet=true").json()
    assert "header_snippet" in with_snippet["items"][0]


def test_refresh_start_does_not_promote_a_generation_before_commit(client, isolate_settings):
    engagement_key = "2026-07-14-code-refresh-crash"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    base = f"/engagements/{engagement_key}/assessment/code"
    first = client.post(
        f"{base}/repos/refresh/start",
        json=_verified_repo_payload(client, engagement_key, "crash-repo"),
    ).json()
    committed = client.post(
        f"{base}/repos/{first['repo_id']}/refresh/commit",
        json={"refresh_token": first["refresh_token"], "manifest_complete": True},
    )
    assert committed.status_code == 200

    second = client.post(
        f"{base}/repos/refresh/start",
        json=_verified_repo_payload(client, engagement_key, "crash-repo"),
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


def test_review_identity_migration_seeds_exact_snapshot_without_reopening_review(
    client, isolate_settings
):
    engagement_key = "2026-08-06-code-review-identity-migration"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="review-identity-migration")
    files = _create_files(client, engagement_key, int(repo["id"]))
    base = f"/engagements/{engagement_key}/assessment/code"
    binding = client.get(f"{base}/repos/{repo['id']}").json()
    generation = int(binding["active_generation"])

    structural = client.post(
        f"{base}/files/bulk-structural-metadata",
        json=_complete_structural_payload(
            repo_id=int(repo["id"]),
            repo_generation=generation,
            source_manifest_digest=str(binding["source_manifest_digest"]),
            updates=[
                {
                    "file_id": row["id"],
                    "source_sha256": row["file_hash"],
                    "total_functions": 1,
                    "total_entry_points": 0,
                    "total_sinks": 0,
                    "total_exports": 0,
                }
                for row in files
            ],
        ),
    )
    assert structural.status_code == 200, structural.text

    db_path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    db_module.close_thread_connection()
    with sqlite3.connect(str(db_path)) as connection:
        connection.execute(
            "ALTER TABLE code_repos DROP COLUMN source_review_identity_digest"
        )
        connection.commit()
    db_module.init_db()
    with sqlite3.connect(str(db_path)) as connection:
        migrated_identity = connection.execute(
            "SELECT source_review_identity_digest FROM code_repos WHERE id = ?",
            (repo["id"],),
        ).fetchone()
    assert migrated_identity == ("",)

    manifest_fields = {
        "file_path", "language", "loc", "file_hash", "header_snippet",
        "git_churn_score", "has_past_cve_fix",
    }
    unchanged_manifest = [{key: row[key] for key in manifest_fields} for row in files]
    exact_snapshot = _verified_repo_payload(
        client,
        engagement_key,
        str(binding["repo_key"]),
        unchanged_manifest,
        source_origin_path=str(binding["source_origin_path"]),
        repo_name=str(binding["name"]),
    )
    assert exact_snapshot["snapshot_digest"] == binding["snapshot_digest"]
    started = client.post(f"{base}/repos/refresh/start", json=exact_snapshot)
    assert started.status_code == 201, started.text
    token = started.json()["refresh_token"]
    assert client.post(
        f"{base}/repos/{repo['id']}/refresh/files",
        json={"refresh_token": token, "files": unchanged_manifest},
    ).status_code == 200
    committed = client.post(
        f"{base}/repos/{repo['id']}/refresh/commit",
        json={"refresh_token": token, "manifest_complete": True},
    )

    assert committed.status_code == 200, committed.text
    assert committed.json()["generation_changed"] is False
    assert committed.json()["repo_generation"] == generation
    refreshed = client.get(f"{base}/repos/{repo['id']}").json()
    assert refreshed["structural_index_generation"] == generation
    assert refreshed["structural_index_manifest_path"]
    with sqlite3.connect(str(db_path)) as connection:
        seeded_identity = connection.execute(
            "SELECT source_review_identity_digest FROM code_repos WHERE id = ?",
            (repo["id"],),
        ).fetchone()
    assert seeded_identity is not None
    assert len(str(seeded_identity[0])) == 64


def test_unseeded_review_identity_advances_on_ambiguous_snapshot_change(
    client, isolate_settings
):
    engagement_key = "2026-08-06-code-review-identity-ambiguous-migration"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="ambiguous-review-identity")
    files = _create_files(client, engagement_key, int(repo["id"]))
    base = f"/engagements/{engagement_key}/assessment/code"
    binding = client.get(f"{base}/repos/{repo['id']}").json()

    db_path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    db_module.close_thread_connection()
    with sqlite3.connect(str(db_path)) as connection:
        connection.execute(
            "ALTER TABLE code_repos DROP COLUMN source_review_identity_digest"
        )
        connection.commit()
    db_module.init_db()

    manifest_fields = {
        "file_path", "language", "loc", "file_hash", "header_snippet",
        "git_churn_score", "has_past_cve_fix",
    }
    unchanged_manifest = [{key: row[key] for key in manifest_fields} for row in files]
    ambiguous_snapshot = _verified_repo_payload(
        client,
        engagement_key,
        str(binding["repo_key"]),
        unchanged_manifest,
        source_origin_path="/tmp/ambiguous-review-identity-next",
        repo_name=str(binding["name"]),
    )
    assert ambiguous_snapshot["snapshot_digest"] != binding["snapshot_digest"]
    started = client.post(f"{base}/repos/refresh/start", json=ambiguous_snapshot)
    assert started.status_code == 201, started.text
    token = started.json()["refresh_token"]
    assert client.post(
        f"{base}/repos/{repo['id']}/refresh/files",
        json={"refresh_token": token, "files": unchanged_manifest},
    ).status_code == 200
    committed = client.post(
        f"{base}/repos/{repo['id']}/refresh/commit",
        json={"refresh_token": token, "manifest_complete": True},
    )

    assert committed.status_code == 200, committed.text
    assert committed.json()["generation_changed"] is True
    assert committed.json()["repo_generation"] == int(binding["active_generation"]) + 1


def test_snapshot_binding_is_deterministic_and_noop_refresh_retains_generation(
    client, isolate_settings
):
    engagement_key = "2026-08-04-code-snapshot-binding"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="snapshot-binding-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    base = f"/engagements/{engagement_key}/assessment/code"

    bound = client.get(f"{base}/repos/{repo['id']}").json()
    generation = int(bound["active_generation"])
    digest = bound["source_manifest_digest"]
    assert bound["source_origin_path"] == "/tmp/snapshot-binding-repo"
    assert bound["source_kind"] == "directory"
    assert bound["repo_path"].endswith(f"/{bound['snapshot_digest']}/source")
    assert bound["snapshot_manifest_path"].endswith(
        f"/{bound['snapshot_digest']}/manifest.json"
    )
    assert len(bound["snapshot_digest"]) == 64
    assert bound["source_manifest_version"] == "v1"
    assert bound["source_snapshot_quality"] == "verified"
    assert bound["worktree_dirty"] is None
    assert len(digest) == 64

    manifest_fields = {
        "file_path", "language", "loc", "file_hash", "header_snippet",
        "git_churn_score", "has_past_cve_fix",
    }
    unchanged_manifest = [
        {key: row[key] for key in manifest_fields}
        for row in reversed(files)
    ]
    started = client.post(
        f"{base}/repos/refresh/start",
        json=_verified_repo_payload(
            client,
            engagement_key,
            "snapshot-binding-repo",
            unchanged_manifest,
        ),
    ).json()
    assert client.post(
        f"{base}/repos/{repo['id']}/refresh/files",
        json={"refresh_token": started["refresh_token"], "files": unchanged_manifest},
    ).status_code == 200
    committed = client.post(
        f"{base}/repos/{repo['id']}/refresh/commit",
        json={"refresh_token": started["refresh_token"], "manifest_complete": True},
    )
    assert committed.status_code == 200, committed.text
    assert committed.json()["repo_generation"] == generation
    assert committed.json()["source_manifest_digest"] == digest
    assert committed.json()["generation_changed"] is False

    changed_manifest = [dict(row) for row in unchanged_manifest]
    changed_manifest[0]["file_hash"] = _source_hash("hash-source-changed")
    started = client.post(
        f"{base}/repos/refresh/start",
        json=_verified_repo_payload(
            client,
            engagement_key,
            "snapshot-binding-repo",
            changed_manifest,
        ),
    ).json()
    assert client.post(
        f"{base}/repos/{repo['id']}/refresh/files",
        json={"refresh_token": started["refresh_token"], "files": changed_manifest},
    ).status_code == 200
    committed = client.post(
        f"{base}/repos/{repo['id']}/refresh/commit",
        json={"refresh_token": started["refresh_token"], "manifest_complete": True},
    )
    assert committed.status_code == 200, committed.text
    assert committed.json()["repo_generation"] == generation + 1
    assert committed.json()["source_manifest_digest"] != digest
    assert committed.json()["generation_changed"] is True


def test_provenance_only_snapshot_change_preserves_generation_and_derived_bindings(
    client, isolate_settings
):
    engagement_key = "2026-08-04-code-snapshot-identity-generation"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="snapshot-identity-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    base = f"/engagements/{engagement_key}/assessment/code"
    binding = client.get(f"{base}/repos/{repo['id']}").json()

    structural = client.post(
        f"{base}/files/bulk-structural-metadata",
        json=_complete_structural_payload(
            repo_id=int(repo["id"]),
            repo_generation=int(binding["active_generation"]),
            source_manifest_digest=str(binding["source_manifest_digest"]),
            updates=[
                {
                    "file_id": row["id"],
                    "source_sha256": row["file_hash"],
                    "total_functions": 1,
                    "total_entry_points": 0,
                    "total_sinks": 0,
                    "total_exports": 0,
                }
                for row in files
            ],
        ),
    )
    assert structural.status_code == 200, structural.text
    lsp = client.post(
        f"{base}/repos/{repo['id']}/lsp-config",
        json={
            "repo_generation": binding["active_generation"],
            "source_manifest_digest": binding["source_manifest_digest"],
            "lsp_config": {"ctags": {"tags_path": "old-snapshot/tags"}},
        },
    )
    assert lsp.status_code == 200, lsp.text
    threat = client.post(
        f"{base}/threat-model",
        json={
            "repo_id": repo["id"],
            "repo_generation": binding["active_generation"],
            "source_manifest_digest": binding["source_manifest_digest"],
            "threat_model": {"trust_boundaries": ["network"]},
        },
    )
    assert threat.status_code == 200, threat.text

    manifest_fields = {
        "file_path", "language", "loc", "file_hash", "header_snippet",
        "git_churn_score", "has_past_cve_fix",
    }
    unchanged_manifest = [{key: row[key] for key in manifest_fields} for row in files]
    next_snapshot = _verified_repo_payload(
        client,
        engagement_key,
        "snapshot-identity-repo",
        unchanged_manifest,
        source_origin_path="/tmp/snapshot-identity-repo-next",
    )
    started = client.post(f"{base}/repos/refresh/start", json=next_snapshot)
    assert started.status_code == 201, started.text
    refresh_token = started.json()["refresh_token"]
    staged = client.post(
        f"{base}/repos/{repo['id']}/refresh/files",
        json={"refresh_token": refresh_token, "files": unchanged_manifest},
    )
    assert staged.status_code == 200, staged.text
    committed = client.post(
        f"{base}/repos/{repo['id']}/refresh/commit",
        json={"refresh_token": refresh_token, "manifest_complete": True},
    )

    assert committed.status_code == 200, committed.text
    assert committed.json()["generation_changed"] is False
    assert committed.json()["repo_generation"] == int(binding["active_generation"])
    assert committed.json()["source_manifest_digest"] == binding["source_manifest_digest"]
    refreshed = client.get(f"{base}/repos/{repo['id']}").json()
    assert refreshed["snapshot_digest"] == next_snapshot["snapshot_digest"]
    assert refreshed["structural_index_generation"] == binding["active_generation"]
    assert refreshed["structural_index_manifest_path"]
    assert refreshed["lsp_config"] == {"ctags": {"tags_path": "old-snapshot/tags"}}
    current_threat = client.get(f"{base}/threat-model/{repo['id']}").json()
    assert current_threat["current"] is True
    assert current_threat["repo_generation"] == binding["active_generation"]
    assert current_threat["active_generation"] == binding["active_generation"]


def test_exclusion_boundary_change_advances_generation_with_identical_admitted_bytes(
    client, isolate_settings
):
    engagement_key = "2026-08-06-code-snapshot-exclusion-generation"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="snapshot-exclusion-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    base = f"/engagements/{engagement_key}/assessment/code"
    binding = client.get(f"{base}/repos/{repo['id']}").json()
    manifest_fields = {
        "file_path", "language", "loc", "file_hash", "header_snippet",
        "git_churn_score", "has_past_cve_fix",
    }
    unchanged_manifest = [{key: row[key] for key in manifest_fields} for row in files]
    next_snapshot = _verified_repo_payload(
        client,
        engagement_key,
        "snapshot-exclusion-repo",
        unchanged_manifest,
        excluded_entries=[
            {"path": "generated/bundle.js", "kind": "file", "reason": "generated"}
        ],
    )

    started = client.post(f"{base}/repos/refresh/start", json=next_snapshot)
    assert started.status_code == 201, started.text
    refresh_token = started.json()["refresh_token"]
    staged = client.post(
        f"{base}/repos/{repo['id']}/refresh/files",
        json={"refresh_token": refresh_token, "files": unchanged_manifest},
    )
    assert staged.status_code == 200, staged.text
    committed = client.post(
        f"{base}/repos/{repo['id']}/refresh/commit",
        json={"refresh_token": refresh_token, "manifest_complete": True},
    )

    assert committed.status_code == 200, committed.text
    assert committed.json()["generation_changed"] is True
    assert committed.json()["repo_generation"] == int(binding["active_generation"]) + 1
    assert committed.json()["source_manifest_digest"] == binding["source_manifest_digest"]


def test_snapshot_quality_and_identity_transitions_advance_generation_monotonically(
    client, isolate_settings
):
    engagement_key = "2026-08-04-code-snapshot-quality-generation"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="snapshot-quality-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    base = f"/engagements/{engagement_key}/assessment/code"
    binding = client.get(f"{base}/repos/{repo['id']}").json()

    indexed = client.post(
        f"{base}/files/bulk-structural-metadata",
        json=_complete_structural_payload(
            repo_id=int(repo["id"]),
            repo_generation=int(binding["active_generation"]),
            source_manifest_digest=str(binding["source_manifest_digest"]),
            updates=[
                {
                    "file_id": row["id"],
                    "source_sha256": row["file_hash"],
                    "total_functions": 1,
                    "total_entry_points": 0,
                    "total_sinks": 0,
                    "total_exports": 0,
                }
                for row in files
            ],
        ),
    )
    assert indexed.status_code == 200, indexed.text
    assert client.post(
        f"{base}/repos/{repo['id']}/lsp-config",
        json={
            "repo_generation": binding["active_generation"],
            "source_manifest_digest": binding["source_manifest_digest"],
            "lsp_config": {"ctags": {"tags_path": "old-generation/tags"}},
        },
    ).status_code == 200
    assert client.post(
        f"{base}/threat-model",
        json={
            "repo_id": repo["id"],
            "repo_generation": binding["active_generation"],
            "source_manifest_digest": binding["source_manifest_digest"],
            "threat_model": {"trust_boundaries": ["network"]},
        },
    ).status_code == 200

    manifest_fields = {
        "file_path", "language", "loc", "file_hash", "header_snippet",
        "git_churn_score", "has_past_cve_fix",
    }
    unchanged_manifest = [
        {key: row[key] for key in manifest_fields}
        for row in files
    ]
    unverified_identity = {
        **_repo_payload("snapshot-quality-repo", "/tmp/snapshot-quality-repo"),
        "snapshot_digest": "b" * 64,
        "source_snapshot_quality": "legacy-unverified",
    }
    started = client.post(f"{base}/repos/refresh/start", json=unverified_identity)
    assert started.status_code == 201, started.text
    token = started.json()["refresh_token"]
    assert client.post(
        f"{base}/repos/{repo['id']}/refresh/files",
        json={"refresh_token": token, "files": unchanged_manifest},
    ).status_code == 200
    downgraded = client.post(
        f"{base}/repos/{repo['id']}/refresh/commit",
        json={"refresh_token": token, "manifest_complete": True},
    )
    assert downgraded.status_code == 200, downgraded.text
    assert downgraded.json()["generation_changed"] is True
    assert downgraded.json()["repo_generation"] == int(binding["active_generation"]) + 1
    after_downgrade = client.get(f"{base}/repos/{repo['id']}").json()
    assert after_downgrade["source_snapshot_quality"] == "legacy-unverified"
    assert after_downgrade["structural_index_generation"] is None
    assert after_downgrade["structural_index_manifest_path"] == ""
    assert after_downgrade["lsp_config"] == {}
    assert after_downgrade["threat_model_generation"] == binding["active_generation"]

    verified_identity = _verified_repo_payload(
        client,
        engagement_key,
        "snapshot-quality-repo",
        unchanged_manifest,
        source_origin_path="/tmp/snapshot-quality-repo-upgraded",
    )
    started = client.post(f"{base}/repos/refresh/start", json=verified_identity)
    assert started.status_code == 201, started.text
    token = started.json()["refresh_token"]
    assert client.post(
        f"{base}/repos/{repo['id']}/refresh/files",
        json={"refresh_token": token, "files": unchanged_manifest},
    ).status_code == 200
    upgraded = client.post(
        f"{base}/repos/{repo['id']}/refresh/commit",
        json={"refresh_token": token, "manifest_complete": True},
    )
    assert upgraded.status_code == 200, upgraded.text
    assert upgraded.json()["generation_changed"] is True
    assert upgraded.json()["repo_generation"] == int(binding["active_generation"]) + 2
    after_upgrade = client.get(f"{base}/repos/{repo['id']}").json()
    assert after_upgrade["source_snapshot_quality"] == "verified"
    assert after_upgrade["structural_index_generation"] is None
    assert after_upgrade["structural_index_manifest_path"] == ""
    assert after_upgrade["lsp_config"] == {}


def test_verified_directory_snapshot_preserves_unknown_worktree_dirty(
    client, isolate_settings
):
    engagement_key = "2026-08-04-directory-dirty-unknown"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    base = f"/engagements/{engagement_key}/assessment/code"
    payload = _verified_repo_payload(
        client,
        engagement_key,
        "directory-dirty-unknown",
        git={"head": "a" * 40, "branch": "main", "dirty": False},
    )

    started = client.post(f"{base}/repos/refresh/start", json=payload)

    assert started.status_code == 201, started.text
    committed = client.post(
        f"{base}/repos/{started.json()['repo_id']}/refresh/commit",
        json={"refresh_token": started.json()["refresh_token"], "manifest_complete": True},
    )
    assert committed.status_code == 200, committed.text
    repo = client.get(f"{base}/repos/{started.json()['repo_id']}").json()
    assert repo["source_kind"] == "git"
    assert repo["source_snapshot_quality"] == "verified"
    assert repo["worktree_dirty"] is False

    # A genuine directory snapshot's explicit unknown value must clear Git
    # provenance from the earlier verified generation.
    refreshed_payload = _verified_repo_payload(
        client,
        engagement_key,
        "directory-dirty-unknown",
    )
    refreshed = client.post(f"{base}/repos/refresh/start", json=refreshed_payload)
    assert refreshed.status_code == 201, refreshed.text
    recommitted = client.post(
        f"{base}/repos/{refreshed.json()['repo_id']}/refresh/commit",
        json={
            "refresh_token": refreshed.json()["refresh_token"],
            "manifest_complete": True,
        },
    )
    assert recommitted.status_code == 200, recommitted.text
    reread = client.get(f"{base}/repos/{refreshed.json()['repo_id']}").json()
    assert reread["worktree_dirty"] is None


def test_verified_refresh_commit_rejects_self_asserted_nonexistent_snapshot(
    client, isolate_settings
):
    engagement_key = "2026-08-04-self-asserted-verified-snapshot"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    base = f"/engagements/{engagement_key}/assessment/code"
    payload = _repo_payload(
        "self-asserted-verified-snapshot",
        "/definitely/missing/vigil/source",
    )
    payload["snapshot_manifest_path"] = (
        "/definitely/missing/vigil/manifest.json"
    )

    started = client.post(f"{base}/repos/refresh/start", json=payload)
    assert started.status_code == 201, started.text
    committed = client.post(
        f"{base}/repos/{started.json()['repo_id']}/refresh/commit",
        json={
            "refresh_token": started.json()["refresh_token"],
            "manifest_complete": True,
        },
    )

    assert committed.status_code == 409, committed.text
    assert "attestation" in committed.json()["detail"].lower()
    assert client.get(f"{base}/repos").json() == []


def test_verified_refresh_commit_rejects_foreign_engagement_snapshot(
    client, isolate_settings
):
    owner_key = "2026-08-04-snapshot-owner"
    foreign_key = "2026-08-04-snapshot-foreign"
    write_engagement(isolate_settings["engagements_dir"], owner_key)
    write_engagement(isolate_settings["engagements_dir"], foreign_key)
    payload = _verified_repo_payload(client, owner_key, "foreign-snapshot-repo")
    base = f"/engagements/{foreign_key}/assessment/code"

    started = client.post(f"{base}/repos/refresh/start", json=payload)
    assert started.status_code == 201, started.text
    committed = client.post(
        f"{base}/repos/{started.json()['repo_id']}/refresh/commit",
        json={
            "refresh_token": started.json()["refresh_token"],
            "manifest_complete": True,
        },
    )

    assert committed.status_code == 409, committed.text
    assert "engagement-owned" in committed.json()["detail"]
    assert client.get(f"{base}/repos").json() == []


def test_verified_refresh_commit_rejects_staged_drift_without_promoting(
    client, isolate_settings
):
    engagement_key = "2026-08-04-staged-snapshot-drift"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, "staged-snapshot-drift")
    base = f"/engagements/{engagement_key}/assessment/code"
    before = client.get(f"{base}/repos/{repo['id']}").json()
    files: list[dict[str, object]] = [
        {
            "file_path": "src/main.py",
            "language": "python",
            "loc": 1,
            "file_hash": _source_hash("staged-snapshot-drift"),
            "header_snippet": "",
            "git_churn_score": 0,
            "has_past_cve_fix": False,
        }
    ]
    payload = _verified_repo_payload(
        client,
        engagement_key,
        str(repo["repo_key"]),
        files,
        source_origin_path=str(repo["source_origin_path"]),
        repo_name=str(repo["name"]),
    )
    started = client.post(f"{base}/repos/refresh/start", json=payload)
    assert started.status_code == 201, started.text
    files[0]["file_hash"] = "b" * 64
    staged = client.post(
        f"{base}/repos/{repo['id']}/refresh/files",
        json={"refresh_token": started.json()["refresh_token"], "files": files},
    )
    assert staged.status_code == 200, staged.text

    committed = client.post(
        f"{base}/repos/{repo['id']}/refresh/commit",
        json={
            "refresh_token": started.json()["refresh_token"],
            "manifest_complete": True,
        },
    )

    assert committed.status_code == 409, committed.text
    assert "file_hash" in committed.json()["detail"]
    after = client.get(f"{base}/repos/{repo['id']}").json()
    assert after["active_generation"] == before["active_generation"]
    assert after["snapshot_digest"] == before["snapshot_digest"]
    assert after["source_manifest_digest"] == before["source_manifest_digest"]
    assert client.get(f"{base}/files?repo_id={repo['id']}&limit=20").json()["items"] == []


def test_verified_refresh_final_manifest_race_rolls_back_as_conflict(
    client, isolate_settings, monkeypatch
):
    engagement_key = "2026-08-04-final-manifest-race"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    payload = _verified_repo_payload(client, engagement_key, "manifest-race-repo")
    base = f"/engagements/{engagement_key}/assessment/code"
    original_verify = code_analysis.VerifiedSnapshotAttestation.verify_unchanged

    def remove_manifest_then_verify(attestation):
        snapshot_root = attestation._snapshot_path
        snapshot_root.chmod(0o755)
        (snapshot_root / "manifest.json").unlink()
        snapshot_root.chmod(0o555)
        original_verify(attestation)

    monkeypatch.setattr(
        code_analysis.VerifiedSnapshotAttestation,
        "verify_unchanged",
        remove_manifest_then_verify,
    )
    started = client.post(f"{base}/repos/refresh/start", json=payload)
    assert started.status_code == 201, started.text

    committed = client.post(
        f"{base}/repos/{started.json()['repo_id']}/refresh/commit",
        json={
            "refresh_token": started.json()["refresh_token"],
            "manifest_complete": True,
        },
    )

    assert committed.status_code == 409, committed.text
    assert "changed after attestation" in committed.json()["detail"]
    assert client.get(f"{base}/repos").json() == []


def test_verified_refresh_deep_manifest_is_conflict_without_promotion(
    client, isolate_settings
):
    engagement_key = "2026-08-04-deep-snapshot-manifest"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    payload = _verified_repo_payload(client, engagement_key, "deep-manifest-repo")
    manifest_path = Path(str(payload["snapshot_manifest_path"]))
    manifest_path.chmod(0o644)
    manifest_path.write_bytes(
        b'{"nested":' + (b"[" * 20_000) + b"0" + (b"]" * 20_000) + b"}"
    )
    manifest_path.chmod(0o444)
    base = f"/engagements/{engagement_key}/assessment/code"
    started = client.post(f"{base}/repos/refresh/start", json=payload)
    assert started.status_code == 201, started.text

    committed = client.post(
        f"{base}/repos/{started.json()['repo_id']}/refresh/commit",
        json={
            "refresh_token": started.json()["refresh_token"],
            "manifest_complete": True,
        },
    )

    assert committed.status_code == 409, committed.text
    assert "nesting exceeds" in committed.json()["detail"]
    assert client.get(f"{base}/repos").json() == []


def test_verified_git_snapshot_requires_worktree_dirty_in_api_and_service(
    client, isolate_settings
):
    engagement_key = "2026-08-04-git-dirty-required"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    assert client.get("/engagements").status_code == 200
    payload = _repo_payload("git-dirty-required", "/tmp/git-dirty-required")
    payload["source_kind"] = "git"
    payload["worktree_dirty"] = None

    response = client.post(
        f"/engagements/{engagement_key}/assessment/code/repos/refresh/start",
        json=payload,
    )

    assert response.status_code == 422
    assert "worktree_dirty" in response.text
    with db_module.get_connection() as connection:
        engagement_id = int(
            connection.execute(
                "SELECT id FROM engagements WHERE key = ?", (engagement_key,)
            ).fetchone()["id"]
        )
    with pytest.raises(HTTPException) as exc_info:
        code_analysis.start_code_repo_refresh(engagement_id, payload)
    assert exc_info.value.status_code == 400
    assert "worktree_dirty" in str(exc_info.value.detail)


def test_verified_snapshot_service_rejects_uppercase_digest(
    client, isolate_settings
):
    engagement_key = "2026-08-04-uppercase-snapshot-digest"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    assert client.get("/engagements").status_code == 200
    with db_module.get_connection() as connection:
        engagement_id = int(
            connection.execute(
                "SELECT id FROM engagements WHERE key = ?", (engagement_key,)
            ).fetchone()["id"]
        )
    payload = _repo_payload("uppercase-digest", "/tmp/uppercase-digest")
    payload["snapshot_digest"] = "A" * 64

    with pytest.raises(HTTPException) as exc_info:
        code_analysis.start_code_repo_refresh(engagement_id, payload)

    assert exc_info.value.status_code == 400
    assert "lowercase" in str(exc_info.value.detail)


def test_refresh_rejects_untrusted_manifest_digest_and_non_sha256_file_hash(
    client, isolate_settings
):
    engagement_key = "2026-08-04-code-snapshot-input-validation"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    base = f"/engagements/{engagement_key}/assessment/code"
    untrusted_digest = client.post(
        f"{base}/repos/refresh/start",
        json={
            **_repo_payload("untrusted-digest-repo", "/tmp/untrusted-digest-repo"),
            "source_manifest_digest": "b" * 64,
        },
    )
    assert untrusted_digest.status_code == 422

    started = client.post(
        f"{base}/repos/refresh/start",
        json=_repo_payload("invalid-file-hash-repo", "/tmp/invalid-file-hash-repo"),
    )
    assert started.status_code == 201, started.text
    invalid_file = client.post(
        f"{base}/repos/{started.json()['repo_id']}/refresh/files",
        json={
            "refresh_token": started.json()["refresh_token"],
            "files": [
                {
                    "file_path": "src/parser.py",
                    "language": "python",
                    "loc": 1,
                    "file_hash": "not-a-sha256",
                }
            ],
        },
    )
    assert invalid_file.status_code == 422


def test_language_change_advances_generation_and_clears_derived_bindings(
    client, isolate_settings
):
    engagement_key = "2026-08-04-code-language-generation"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="language-generation-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    base = f"/engagements/{engagement_key}/assessment/code"
    binding = client.get(f"{base}/repos/{repo['id']}").json()
    indexed = client.post(
        f"{base}/files/bulk-structural-metadata",
        json=_complete_structural_payload(
            repo_id=int(repo["id"]),
            repo_generation=int(binding["active_generation"]),
            source_manifest_digest=str(binding["source_manifest_digest"]),
            updates=[
                {
                    "file_id": row["id"],
                    "source_sha256": row["file_hash"],
                    "total_functions": 1,
                    "total_entry_points": 0,
                    "total_sinks": 0,
                    "total_exports": 0,
                }
                for row in files
            ],
        ),
    )
    assert indexed.status_code == 200, indexed.text
    lsp_publish = client.post(
        f"{base}/repos/{repo['id']}/lsp-config",
        json={
            "repo_generation": binding["active_generation"],
            "source_manifest_digest": binding["source_manifest_digest"],
            "lsp_config": {"ctags": {"tags_path": "old-generation/tags"}},
        },
    )
    assert lsp_publish.status_code == 200, lsp_publish.text
    threat = client.post(
        f"{base}/threat-model",
        json={
            "repo_id": repo["id"],
            "repo_generation": binding["active_generation"],
            "source_manifest_digest": binding["source_manifest_digest"],
            "threat_model": {"trust_boundaries": ["network"]},
        },
    )
    assert threat.status_code == 200, threat.text

    fields = {
        "file_path", "language", "loc", "file_hash", "header_snippet",
        "git_churn_score", "has_past_cve_fix",
    }
    manifest = [{key: row[key] for key in fields} for row in files]
    noop = client.post(
        f"{base}/repos/refresh/start",
        json=_verified_repo_payload(
            client,
            engagement_key,
            "language-generation-repo",
            manifest,
        ),
    ).json()
    assert client.post(
        f"{base}/repos/{repo['id']}/refresh/files",
        json={"refresh_token": noop["refresh_token"], "files": manifest},
    ).status_code == 200
    noop_commit = client.post(
        f"{base}/repos/{repo['id']}/refresh/commit",
        json={"refresh_token": noop["refresh_token"], "manifest_complete": True},
    )
    assert noop_commit.status_code == 200, noop_commit.text
    assert noop_commit.json()["generation_changed"] is False
    after_noop = client.get(f"{base}/repos/{repo['id']}").json()
    assert after_noop["structural_index_schema"] == "structural-index/v6"
    assert after_noop["structural_index_generation"] == binding["active_generation"]
    assert after_noop["structural_index_manifest_path"].endswith("manifest.json")
    assert after_noop["lsp_config"]["ctags"]["tags_path"] == "old-generation/tags"

    next(row for row in manifest if row["file_path"] == "src/parser.py")["language"] = "ruby"
    started = client.post(
        f"{base}/repos/refresh/start",
        json=_verified_repo_payload(
            client,
            engagement_key,
            "language-generation-repo",
            manifest,
        ),
    ).json()
    assert client.post(
        f"{base}/repos/{repo['id']}/refresh/files",
        json={"refresh_token": started["refresh_token"], "files": manifest},
    ).status_code == 200
    committed = client.post(
        f"{base}/repos/{repo['id']}/refresh/commit",
        json={"refresh_token": started["refresh_token"], "manifest_complete": True},
    )
    assert committed.status_code == 200, committed.text
    assert committed.json()["generation_changed"] is True
    assert committed.json()["repo_generation"] == int(binding["active_generation"]) + 1
    assert committed.json()["source_manifest_digest"] != binding["source_manifest_digest"]
    refreshed = client.get(f"{base}/repos/{repo['id']}").json()
    assert refreshed["structural_index_schema"] == ""
    assert refreshed["structural_index_generation"] is None
    assert refreshed["structural_index_manifest_path"] == ""
    assert refreshed["lsp_config"] == {}
    assert refreshed["threat_model_generation"] == binding["active_generation"]
    assert refreshed["threat_model"] == {"trust_boundaries": ["network"]}


@pytest.mark.parametrize("mutation_mode", ["bulk-classify", "file-patch"])
def test_language_correction_invalidates_structural_index_until_rebuilt(
    client, isolate_settings, mutation_mode
):
    engagement_key = f"2026-08-05-code-language-correction-{mutation_mode}"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key=f"language-correction-{mutation_mode}")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser = next(row for row in files if row["file_path"] == "src/parser.py")
    base = f"/engagements/{engagement_key}/assessment/code"
    binding = client.get(f"{base}/repos/{repo['id']}").json()
    updates = [
        {
            "file_id": row["id"],
            "source_sha256": row["file_hash"],
            "total_functions": 2,
            "total_entry_points": 1,
            "total_sinks": 1,
            "total_exports": 0,
        }
        for row in files
    ]
    indexed = client.post(
        f"{base}/files/bulk-structural-metadata",
        json=_complete_structural_payload(
            repo_id=int(repo["id"]),
            repo_generation=int(binding["active_generation"]),
            source_manifest_digest=str(binding["source_manifest_digest"]),
            updates=updates,
        ),
    )
    assert indexed.status_code == 200, indexed.text
    _classify_file(client, engagement_key, int(parser["id"]), "high", 79)
    claim = _claim_file_for_analysis(client, engagement_key, int(parser["id"]))
    result = client.post(
        f"{base}/analysis-results",
        json=_owned(
            claim,
            queue_item_id=claim["id"],
            disposition="clean",
            function_name="parse",
            evidence="Reviewed under the original language classification.",
        ),
    )
    assert result.status_code == 201, result.text
    completed = client.post(
        f"{base}/analysis-queue/done",
        json=_owned(
            claim,
            item_ids=[claim["id"]],
            disposition="clean",
            notes="Original-language review complete.",
            cwe_coverage=_network_input_coverage(default_effort=80),
        ),
    )
    assert completed.status_code == 200, completed.text
    coverage_before = client.get(f"{base}/coverage?repo_id={repo['id']}").json()
    assert sum(
        classification["analyzed"]
        for classification in coverage_before["by_classification"].values()
    ) == 1

    if mutation_mode == "bulk-classify":
        corrected = client.post(
            f"{base}/files/bulk-classify",
            json={
                "classifications": [
                    {
                        "file_id": parser["id"],
                        "classification": "low",
                        "language": "c++",
                        "analysis_priority": 10,
                    }
                ]
            },
        )
    else:
        corrected = client.patch(
            f"{base}/files/{parser['id']}",
            json={"language": "c++"},
        )
    assert corrected.status_code == 200, corrected.text

    invalidated_repo = client.get(f"{base}/repos/{repo['id']}").json()
    assert invalidated_repo["structural_index_schema"] == ""
    assert invalidated_repo["structural_index_generation"] is None
    assert invalidated_repo["structural_index_manifest_path"] == ""
    assert invalidated_repo["structural_analysis_status_counts"] == {}
    invalidated_files = client.get(f"{base}/files?repo_id={repo['id']}&limit=20").json()["items"]
    assert {row["structural_analysis_status"] for row in invalidated_files} == {"pending"}
    assert {row["total_functions"] for row in invalidated_files} == {0}
    current_results = client.get(f"{base}/analysis-results?file_id={parser['id']}").json()
    assert current_results == []
    result_history = client.get(
        f"{base}/analysis-results?file_id={parser['id']}&include_superseded=true"
    ).json()
    assert [row["id"] for row in result_history] == [result.json()["id"]]
    assert result_history[0]["superseded_at"]
    coverage_after = client.get(f"{base}/coverage?repo_id={repo['id']}").json()
    assert sum(
        classification["analyzed"]
        for classification in coverage_after["by_classification"].values()
    ) == 0
    readiness = client.get(f"{base}/readiness?target_phase=classify-map").json()
    assert "structural_index_stale" in {blocker["code"] for blocker in readiness["blockers"]}

    rebuilt_files = client.get(f"{base}/files?repo_id={repo['id']}&limit=20").json()["items"]
    rebuilt = client.post(
        f"{base}/files/bulk-structural-metadata",
        json=_complete_structural_payload(
            repo_id=int(repo["id"]),
            repo_generation=int(binding["active_generation"]),
            source_manifest_digest=str(binding["source_manifest_digest"]),
            updates=[
                {
                    "file_id": row["id"],
                    "source_sha256": row["file_hash"],
                    "total_functions": 2,
                    "total_entry_points": 1,
                    "total_sinks": 1,
                    "total_exports": 0,
                }
                for row in rebuilt_files
            ],
        ),
    )
    assert rebuilt.status_code == 200, rebuilt.text
    rebuilt_readiness = client.get(f"{base}/readiness?target_phase=classify-map").json()
    assert "structural_index_stale" not in {
        blocker["code"] for blocker in rebuilt_readiness["blockers"]
    }


@pytest.mark.parametrize(
    ("mutation_mode", "mutation"),
    [
        ("file-patch", {"classification": "critical", "analysis_priority": 80}),
        ("file-patch", {"role": "crypto_impl"}),
        ("file-patch", {"slot_types_json": ["SERIALIZED-DATA"]}),
        (
            "bulk-classify",
            {
                "classification": "high",
                "role": "crypto_impl",
                "slot_types": ["SERIALIZED-DATA"],
                "analysis_priority": 79,
            },
        ),
    ],
)
def test_review_identity_change_retires_current_semantic_receipt(
    client, isolate_settings, mutation_mode, mutation
):
    engagement_key = (
        "2026-08-05-code-review-identity-"
        + mutation_mode
        + "-"
        + next(iter(mutation))
    )
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key=f"{engagement_key}-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser = next(row for row in files if row["file_path"] == "src/parser.py")
    base = f"/engagements/{engagement_key}/assessment/code"
    _classify_file(client, engagement_key, int(parser["id"]), "high", 79)
    claim = _claim_file_for_analysis(client, engagement_key, int(parser["id"]))
    result = client.post(
        f"{base}/analysis-results",
        json=_owned(
            claim,
            queue_item_id=claim["id"],
            disposition="clean",
            function_name="parse",
            evidence="Reviewed against the original file identity.",
        ),
    )
    assert result.status_code == 201, result.text
    completed = client.post(
        f"{base}/analysis-queue/done",
        json=_owned(
            claim,
            item_ids=[claim["id"]],
            disposition="clean",
            notes="Original review identity completed.",
            cwe_coverage=_network_input_coverage(default_effort=80),
        ),
    )
    assert completed.status_code == 200, completed.text
    before = client.get(f"{base}/coverage?repo_id={repo['id']}").json()
    assert before["by_classification"]["high"]["analyzed"] == 1

    if mutation_mode == "bulk-classify":
        changed = client.post(
            f"{base}/files/bulk-classify",
            json={"classifications": [{"file_id": parser["id"], **mutation}]},
        )
    else:
        changed = client.patch(f"{base}/files/{parser['id']}", json=mutation)
    assert changed.status_code == 200, changed.text
    current_file = client.get(f"{base}/files/{parser['id']}").json()
    expected_classification = str(mutation.get("classification", "high"))
    expected_role = str(mutation.get("role", "parser"))
    expected_slots = mutation.get(
        "slot_types",
        mutation.get("slot_types_json", ["NETWORK-INPUT"]),
    )
    expected_priority = int(mutation.get("analysis_priority", 79))
    assert current_file["classification"] == expected_classification
    assert current_file["role"] == expected_role
    assert current_file["slot_types"] == expected_slots
    assert current_file["analysis_priority"] == expected_priority

    assert client.get(f"{base}/analysis-results?file_id={parser['id']}").json() == []
    history = client.get(
        f"{base}/analysis-results?file_id={parser['id']}&include_superseded=true"
    ).json()
    assert [row["id"] for row in history] == [result.json()["id"]]
    assert history[0]["superseded_at"]
    coverage = client.get(f"{base}/coverage?repo_id={repo['id']}").json()
    assert sum(
        classification["analyzed"]
        for classification in coverage["by_classification"].values()
    ) == 0
    readiness = client.get(f"{base}/readiness?target_phase=verify-variant").json()
    assert "admitted_files_unaccounted" in {
        blocker["code"] for blocker in readiness["blockers"]
    }
    db_path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    with sqlite3.connect(str(db_path)) as connection:
        replacement = connection.execute(
            """
            SELECT id, status, repo_generation, queue_mode
            FROM code_analysis_queue
            WHERE file_id = ? AND batch_theme = 'metadata-refresh-review'
            ORDER BY id DESC LIMIT 1
            """,
            (parser["id"],),
        ).fetchone()
    assert replacement is not None
    assert replacement[1] == "pending"
    assert replacement[2] == claim["repo_generation"]
    assert replacement[3] == "metadata-refresh"
    fetched = client.post(
        f"{base}/analysis-queue/fetch",
        json={
            "limit": 1,
            "agent_name": "metadata-review-agent",
            "item_ids": [replacement[0]],
        },
    )
    assert fetched.status_code == 200, fetched.text
    assert [row["id"] for row in fetched.json()] == [replacement[0]]
    replacement_claim = fetched.json()[0]
    assert replacement_claim["file"]["classification"] == expected_classification
    assert replacement_claim["file"]["role"] == expected_role
    assert replacement_claim["file"]["slot_types"] == expected_slots
    assert replacement_claim["priority"] == expected_priority
    assert replacement_claim["slot_types"] == expected_slots
    closed = client.post(
        f"{base}/analysis-queue/done",
        json=_owned(
            replacement_claim,
            item_ids=[replacement_claim["id"]],
            disposition="skipped",
            skip_reason="out-of-scope-language",
        ),
    )
    assert closed.status_code == 200, closed.text


def test_lsp_publish_rejects_a_stale_repository_generation(
    client, isolate_settings
):
    engagement_key = "2026-08-04-code-lsp-cas"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="lsp-cas-repo")
    base = f"/engagements/{engagement_key}/assessment/code"
    stale_binding = {
        "repo_generation": repo["active_generation"],
        "source_manifest_digest": repo["source_manifest_digest"],
    }

    _create_files(client, engagement_key, int(repo["id"]))
    stale = client.post(
        f"{base}/repos/{repo['id']}/lsp-config",
        json={
            **stale_binding,
            "lsp_config": {"ctags": {"tags_path": "stale/tags"}},
        },
    )

    assert stale.status_code == 409, stale.text
    current = client.get(f"{base}/repos/{repo['id']}").json()
    assert current["lsp_config"] == {}
    published = client.post(
        f"{base}/repos/{repo['id']}/lsp-config",
        json={
            "repo_generation": current["active_generation"],
            "source_manifest_digest": current["source_manifest_digest"],
            "lsp_config": {"ctags": {"tags_path": "current/tags"}},
        },
    )
    assert published.status_code == 200, published.text
    assert published.json()["lsp_config"]["ctags"]["tags_path"] == "current/tags"


def test_wave_one_migration_backfills_legacy_snapshot_identity(client, isolate_settings):
    engagement_key = "2026-08-04-code-snapshot-legacy-migration"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="snapshot-legacy-repo")
    _create_files(client, engagement_key, int(repo["id"]))
    active_repo = client.get(
        f"/engagements/{engagement_key}/assessment/code/repos/{repo['id']}"
    ).json()
    db_path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    new_columns = (
        "source_origin_path",
        "source_kind",
        "snapshot_manifest_path",
        "snapshot_digest",
        "source_manifest_version",
        "source_manifest_digest",
        "source_snapshot_quality",
        "worktree_dirty",
        "structural_index_schema",
        "structural_index_generation",
        "structural_index_manifest_path",
        "threat_model_generation",
    )
    db_module.close_thread_connection()
    with sqlite3.connect(str(db_path)) as connection:
        for column in new_columns:
            connection.execute(f"ALTER TABLE code_repos DROP COLUMN {column}")
        connection.commit()

    db_module.init_db()
    migrated = client.get(
        f"/engagements/{engagement_key}/assessment/code/repos/{repo['id']}"
    )
    assert migrated.status_code == 200, migrated.text
    record = migrated.json()
    assert record["source_origin_path"] == active_repo["repo_path"]
    assert record["source_kind"] == "legacy"
    assert record["source_manifest_version"] == "v1"
    assert len(record["source_manifest_digest"]) == 64
    assert record["source_snapshot_quality"] == "legacy-unverified"
    assert record["worktree_dirty"] is None
    assert record["structural_index_schema"] == ""
    assert record["structural_index_generation"] is None
    assert record["threat_model_generation"] is None
    readiness = client.get(
        f"/engagements/{engagement_key}/assessment/code/readiness?target_phase=classify-map"
    ).json()
    identity_blocker = next(
        blocker
        for blocker in readiness["blockers"]
        if blocker["code"] == "source_snapshot_unverified"
    )
    assert identity_blocker["repo_id"] == repo["id"]
    assert identity_blocker["overrideable"] is False


def test_structural_schema_migration_keeps_legacy_index_identity_but_marks_it_stale(
    client, isolate_settings
):
    engagement_key = "2026-08-05-code-structural-schema-migration"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="structural-schema-migration")
    _create_files(client, engagement_key, int(repo["id"]))
    base = f"/engagements/{engagement_key}/assessment/code"
    binding = client.get(f"{base}/repos/{repo['id']}").json()
    legacy_path = "tools/analysis-state/structural-index/legacy-v4/manifest.json"
    db_path = isolate_settings["data_dir"] / "orchestrator.sqlite3"

    db_module.close_thread_connection()
    with sqlite3.connect(str(db_path)) as connection:
        connection.execute(
            """
            UPDATE code_repos
            SET structural_index_generation = ?, structural_index_manifest_path = ?
            WHERE id = ?
            """,
            (binding["active_generation"], legacy_path, repo["id"]),
        )
        connection.execute("ALTER TABLE code_repos DROP COLUMN structural_index_schema")
        connection.commit()

    db_module.init_db()
    migrated = client.get(f"{base}/repos/{repo['id']}").json()
    assert migrated["structural_index_generation"] == binding["active_generation"]
    assert migrated["structural_index_manifest_path"] == legacy_path
    assert migrated["structural_index_schema"] == ""

    readiness = client.get(f"{base}/readiness?target_phase=classify-map").json()
    blocker = next(
        item for item in readiness["blockers"] if item["code"] == "structural_index_stale"
    )
    assert blocker["repo_id"] == repo["id"]
    assert blocker["overrideable"] is False


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
        json=_verified_repo_payload(client, engagement_key, "hidden-repo"),
    )
    assert second.status_code == 201, second.text
    stale_stage = client.post(
        f"{base}/repos/{first['repo_id']}/refresh/files",
        json={
            "refresh_token": first["refresh_token"],
            "files": [{"file_path": "stale.py", "language": "python", "loc": 1, "file_hash": _source_hash("old")}],
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
    assert client.get(f"{base}/files").json()["items"] == []
    assert client.get(f"{base}/files/{hidden_file_id}").status_code == 404
    assert client.get(f"{base}/modules").json() == []
    assert client.get(f"{base}/analysis-queue/stats").json() == {
        "pending": 0,
        "processing": 0,
        "done": 0,
        "error": 0,
        "needs_context": 0,
        "total": 0,
        "historical_total": 0,
            "superseded_history": 0,
            "invalid_active_identity": 0,
            "invalid_active_history": 0,
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
            json=_complete_structural_payload(
                repo_id=repo_id,
                repo_generation=1,
                source_manifest_digest="0" * 64,
                structural_index_manifest_path="tools/analysis-state/hidden-index.json",
                updates=[{
                    "file_id": hidden_file_id,
                    "source_sha256": _source_hash("hidden-source-hash"),
                    "total_functions": 99,
                    "total_entry_points": 0,
                    "total_sinks": 0,
                    "total_exports": 0,
                }],
            ),
        ),
        client.post(
            f"{base}/modules",
            json={"repo_id": repo_id, "modules": [{"module_key": "x", "name": "X"}]},
        ),
        client.post(
            f"{base}/analysis-queue",
            json={"items": [{"file_id": hidden_file_id, "priority": 0}]},
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
                "files": [{"file_path": "stale.py", "language": "python", "loc": 1, "file_hash": _source_hash("old")}],
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


@pytest.mark.parametrize(
    ("field_name", "forged_value"),
    [
        ("analysis_status", "analyzed"),
        ("variant_check_status", "done"),
        ("skip_reason", "generated-code"),
    ],
)
def test_public_file_patch_rejects_derived_or_receipt_owned_state(
    client, isolate_settings, field_name, forged_value
):
    engagement_key = f"2026-08-05-code-file-state-derived-{field_name}"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key=f"derived-{field_name}-repo")
    parser_file = next(
        row for row in _create_files(client, engagement_key, int(repo["id"]))
        if row["file_path"] == "src/parser.py"
    )
    base = f"/engagements/{engagement_key}/assessment/code"

    forged = client.patch(
        f"{base}/files/{parser_file['id']}",
        json={field_name: forged_value},
    )

    assert forged.status_code == 400
    assert field_name in forged.json()["detail"]
    persisted = client.get(f"{base}/files/{parser_file['id']}").json()
    expected = "pending" if field_name in {
        "analysis_status",
        "variant_check_status",
    } else ""
    assert persisted[field_name] == expected


def test_changed_file_refresh_clears_all_analysis_metadata(client, isolate_settings):
    engagement_key = "2026-07-14-code-refresh-clears-analysis"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="changed-metadata-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser_file = next(
        row for row in files
        if row["file_path"] == "src/parser.py"
    )
    _publish_structural_totals(
        client,
        engagement_key,
        int(repo["id"]),
        files,
        {
            int(parser_file["id"]): {
                "total_functions": 4,
                "total_entry_points": 2,
                "total_sinks": 1,
                "total_exports": 3,
            }
        },
    )
    patched = client.patch(
        f"/engagements/{engagement_key}/assessment/code/files/{parser_file['id']}",
        json={
            "classification": "low",
            "role": "parser",
            "analysis_priority": 19,
            "analysis_depth": "deep",
            "notes": "old analysis",
        },
    )
    assert patched.status_code == 200, patched.text
    db_path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    with sqlite3.connect(str(db_path)) as connection:
        connection.execute(
            """
            UPDATE code_files
            SET skip_reason = 'generated-code', variant_check_status = 'done'
            WHERE id = ?
            """,
            (parser_file["id"],),
        )
        connection.commit()
    base = f"/engagements/{engagement_key}/assessment/code"
    refreshed_manifest = [
        {
            "file_path": "src/parser.py",
            "language": "python",
            "loc": 81,
            "file_hash": _source_hash("changed"),
        },
        {
            "file_path": "src/helpers.py",
            "language": "python",
            "loc": 40,
            "file_hash": _source_hash("hash-b"),
        },
    ]
    started = client.post(
        f"{base}/repos/refresh/start",
        json=_verified_repo_payload(
            client,
            engagement_key,
            "changed-metadata-repo",
            refreshed_manifest,
        ),
    ).json()
    staged = client.post(
        f"{base}/repos/{repo['id']}/refresh/files",
        json={
            "refresh_token": started["refresh_token"],
            "files": refreshed_manifest,
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
    ("metadata_changes", "legacy_unverified"),
    [
        pytest.param({"language": "ruby"}, False, id="verified-language"),
        pytest.param({"loc": 81}, True, id="legacy-loc"),
        pytest.param(
            {"loc": 81, "header_snippet": "import changed", "has_past_cve_fix": True},
            True,
            id="legacy-strongest-combination",
        ),
    ],
)
def test_verified_language_or_legacy_metadata_change_uses_full_invalidation(
    client, isolate_settings, metadata_changes, legacy_unverified
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
        legacy_unverified=legacy_unverified,
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


def test_legacy_unverified_header_change_reopens_architecture_review_and_keeps_history(
    client, isolate_settings
):
    engagement_key = "2026-07-14-code-refresh-metadata-header"
    repo, parser, claim, result = _seed_reviewed_parser(client, isolate_settings, engagement_key)
    refreshed = _refresh_one_file_metadata(
        client,
        engagement_key,
        int(repo["id"]),
        int(parser["id"]),
        legacy_unverified=True,
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
    assert rows == [(claim["id"], "done", 79, "[]"), (claim["id"] + 1, "pending", 79, "[]")]


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
    assert rows == [(claim["id"], "done", 79, "[]"), (claim["id"] + 1, "pending", 79, "[]")]
    assert trigger_rows == [
        (resolved_trigger_id, "pending", None, ""),
        (accepted_gap_trigger_id, "not_applicable", None, "manual disposition"),
    ]
    with db_module.get_connection() as connection:
        wrong_file_queue_id = int(
            connection.execute(
                """
                INSERT INTO code_analysis_queue (
                    engagement_id, file_id, status, cross_file_triggers_json,
                    repo_generation
                )
                SELECT ?, ?, 'pending', ?, active_generation
                FROM code_repos WHERE engagement_id = ? AND id = ?
                RETURNING id
                """,
                (
                    engagement_id,
                    source_file_id,
                    json.dumps(
                        [
                            {
                                "trigger_id": resolved_trigger_id,
                                "source": "code_analysis_trigger",
                            }
                        ]
                    ),
                    engagement_id,
                    repo["id"],
                ),
            ).fetchone()["id"]
        )
        connection.execute(
            """
            UPDATE code_analysis_triggers
            SET status = 'queued', resolved_queue_item_id = ?
            WHERE id = ?
            """,
            (wrong_file_queue_id, resolved_trigger_id),
        )
        code_analysis._sync_trigger_status_for_file(
            connection,
            engagement_id,
            int(parser["id"]),
        )
        after_wrong_file_binding = connection.execute(
            """
            SELECT status, resolved_queue_item_id
            FROM code_analysis_triggers WHERE id = ?
            """,
            (resolved_trigger_id,),
        ).fetchone()
    assert tuple(after_wrong_file_binding) == ("pending", None)

    metadata_claim_response = client.post(
        f"{base}/analysis-queue/fetch",
        json={
            "limit": 1,
            "agent_name": "metadata-reviewer",
            "item_ids": [claim["id"] + 1],
        },
    )
    assert metadata_claim_response.status_code == 200, metadata_claim_response.text
    metadata_claim = metadata_claim_response.json()[0]
    assert metadata_claim["cross_file_triggers"] == []
    with db_module.get_connection() as connection:
        connection.execute(
            """
            UPDATE code_analysis_triggers
            SET status = 'queued', resolved_queue_item_id = ?
            WHERE id = ?
            """,
            (metadata_claim["id"], resolved_trigger_id),
        )
    metadata_done = client.post(
        f"{base}/analysis-queue/done",
        json=_owned(
            metadata_claim,
            item_ids=[metadata_claim["id"]],
            disposition="clean",
            notes="Reviewed changed risk metadata, without an assigned trigger hypothesis.",
            cwe_coverage=_network_input_coverage(default_effort=80),
        ),
    )
    assert metadata_done.status_code == 200, metadata_done.text
    after_unseen_review = client.get(f"{base}/triggers").json()[0]
    assert after_unseen_review["status"] == "pending"
    assert after_unseen_review["resolved_queue_item_id"] is None

    _classify_file(client, engagement_key, int(parser["id"]), "high", 79)

    trigger_requeue = client.post(
        f"{base}/analysis-queue/requeue",
        json={"items": [{"file_id": parser["id"], "priority": 79}]},
    )
    assert trigger_requeue.status_code == 201, trigger_requeue.text
    assert trigger_requeue.json()["already_queued"] == 1
    trigger_claim_response = client.post(
        f"{base}/analysis-queue/fetch",
        json={"limit": 1, "agent_name": "trigger-reviewer"},
    )
    assert trigger_claim_response.status_code == 200, trigger_claim_response.text
    trigger_claim = trigger_claim_response.json()[0]
    assert [
        row["trigger_id"]
        for row in trigger_claim["cross_file_triggers"]
        if row.get("source") == "code_analysis_trigger"
    ] == [resolved_trigger_id]
    trigger_skipped = client.post(
        f"{base}/analysis-queue/done",
        json=_owned(
            trigger_claim,
            item_ids=[trigger_claim["id"]],
            disposition="skipped",
            skip_reason="generated-code",
        ),
    )
    assert trigger_skipped.status_code == 200, trigger_skipped.text
    after_valid_skip = next(
        row
        for row in client.get(f"{base}/triggers").json()
        if row["id"] == resolved_trigger_id
    )
    assert after_valid_skip["status"] == "pending"
    assert after_valid_skip["resolved_queue_item_id"] == trigger_claim["id"]

    final_requeue = client.post(
        f"{base}/analysis-queue/requeue",
        json={"items": [{"file_id": parser["id"], "priority": 79}]},
    )
    assert final_requeue.status_code == 201, final_requeue.text
    assert final_requeue.json()["inserted"] == 1
    rebound_trigger = next(
        row
        for row in client.get(f"{base}/triggers").json()
        if row["id"] == resolved_trigger_id
    )
    assert rebound_trigger["resolved_queue_item_id"] != trigger_claim["id"]
    final_claim_response = client.post(
        f"{base}/analysis-queue/fetch",
        json={
            "limit": 1,
            "agent_name": "final-trigger-reviewer",
            "item_ids": [rebound_trigger["resolved_queue_item_id"]],
        },
    )
    assert final_claim_response.status_code == 200, final_claim_response.text
    final_claim = final_claim_response.json()[0]
    final_done = client.post(
        f"{base}/analysis-queue/done",
        json=_owned(
            final_claim,
            item_ids=[final_claim["id"]],
            disposition="clean",
            notes="Reviewed the explicitly supplied trigger hypothesis.",
            cwe_coverage=_network_input_coverage(default_effort=80),
        ),
    )
    assert final_done.status_code == 200, final_done.text
    trigger_statuses = {
        row["id"]: row["status"] for row in client.get(f"{base}/triggers").json()
    }
    assert trigger_statuses[resolved_trigger_id] == "resolved"
    assert trigger_statuses[accepted_gap_trigger_id] == "not_applicable"


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
            "&include_header_snippet=true"
        ).json()["items"]
        if row["file_path"] == "src/parser.py"
    )
    _classify_file(client, engagement_key, int(parser["id"]), "medium", 49)
    _classify_file(client, engagement_key, int(helper["id"]), "high", 79)
    parser_claim = _claim_file_for_analysis(client, engagement_key, int(parser["id"]))
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
    manifest_fields = {
        "file_path",
        "language",
        "loc",
        "file_hash",
        "header_snippet",
        "git_churn_score",
        "has_past_cve_fix",
    }
    renamed_manifest = [
        {key: parser[key] for key in manifest_fields},
        {
            **{key: helper[key] for key in manifest_fields},
            "file_path": "lib/helpers.rb",
            "language": "ruby",
        },
    ]
    started = client.post(
        f"{base}/repos/refresh/start",
        json=_verified_repo_payload(
            client,
            engagement_key,
            "rename-invalidate-repo",
            renamed_manifest,
        ),
    ).json()
    assert client.post(
        f"{base}/repos/{repo['id']}/refresh/files",
        json={
            "refresh_token": started["refresh_token"],
            "files": renamed_manifest,
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


def test_repo_refresh_invalidates_claim_generation_for_all_agent_writes(
    client, isolate_settings
):
    engagement_key = "2026-07-15-code-queue-repo-generation"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="generation-lease-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser_file = next(row for row in files if row["file_path"] == "src/parser.py")
    _classify_file(client, engagement_key, int(parser_file["id"]), "critical", 100)
    claim = _claim_file_for_analysis(client, engagement_key, int(parser_file["id"]))
    partial = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-results",
        json=_owned(
            claim,
            queue_item_id=claim["id"],
            disposition="clean",
            function_name="parse_partial",
            evidence="review started against prior generation",
        ),
    )
    assert partial.status_code == 201, partial.text

    manifest_fields = {
        "file_path", "language", "loc", "file_hash", "header_snippet",
        "git_churn_score", "has_past_cve_fix",
    }
    refreshed_manifest = [
        {key: row[key] for key in manifest_fields}
        for row in files
    ]
    next(row for row in refreshed_manifest if row["file_path"] == "src/helpers.py")[
        "file_hash"
    ] = _source_hash("hash-b-next-generation")
    _refresh_repo_files(
        client,
        engagement_key,
        int(repo["id"]),
        refreshed_manifest,
    )

    heartbeat = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/heartbeat",
        json=_owned(claim, item_id=claim["id"]),
    )
    assert heartbeat.status_code == 409
    assert "repository generation" in heartbeat.json()["detail"]

    result = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-results",
        json=_owned(
            claim,
            queue_item_id=claim["id"],
            disposition="clean",
            function_name="parse",
            evidence="reviewed old generation",
        ),
    )
    assert result.status_code == 409
    assert "repository generation" in result.json()["detail"]

    closeout = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/done",
        json=_owned(
            claim,
            item_ids=[claim["id"]],
            disposition="clean",
            notes="reviewed stale generation",
            cwe_coverage=_network_input_coverage(default_effort=80),
        ),
    )
    assert closeout.status_code == 409
    assert "repository generation" in closeout.json()["detail"]

    current_queue = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue",
        json={"items": [{"file_id": parser_file["id"], "priority": 100}]},
    )
    assert current_queue.status_code == 201, current_queue.text
    current_queue_id = current_queue.json()["outcomes"][0]["queue_item_id"]

    reclaimed = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/fetch",
        json={"limit": 1, "agent_name": "fresh-generation-agent"},
    )
    assert reclaimed.status_code == 200, reclaimed.text
    assert len(reclaimed.json()) == 1
    assert reclaimed.json()[0]["id"] == current_queue_id
    assert reclaimed.json()[0]["repo_generation"] == int(claim["repo_generation"]) + 1
    assert reclaimed.json()[0]["lease_token"] != claim["lease_token"]
    db_path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    with sqlite3.connect(str(db_path)) as connection:
        superseded_at = connection.execute(
            "SELECT superseded_at FROM code_analysis_results WHERE id = ?",
            (partial.json()["id"],),
        ).fetchone()[0]
    assert superseded_at


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


def test_analysis_result_explicit_supersession_replaces_one_function_result(
    client, isolate_settings
):
    engagement_key = "2026-09-11-code-result-explicit-supersession"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="result-supersession-repo")
    parser_file = next(
        row for row in _create_files(client, engagement_key, int(repo["id"]))
        if row["file_path"] == "src/parser.py"
    )
    _classify_file(client, engagement_key, int(parser_file["id"]), "critical", 100)
    claim = _claim_file_for_analysis(
        client, engagement_key, int(parser_file["id"]), agent_name="result-agent"
    )
    endpoint = f"/engagements/{engagement_key}/assessment/code/analysis-results"
    payload = {
        "queue_item_id": claim["id"],
        "file_id": parser_file["id"],
        "agent_name": "result-agent",
        "lease_token": claim["lease_token"],
        "function_name": "parse",
        "hypothesis": "input may reach parser",
        "evidence": "src/parser.py:1",
        "disposition": "suspicious",
        "confidence": "medium",
    }
    original = client.post(endpoint, json=payload)
    assert original.status_code == 201, original.text

    replacement_payload = payload | {
        "supersedes": original.json()["id"],
        "hypothesis": "guard rejects the input",
        "disposition": "clean",
        "confidence": "high",
    }
    replacement = client.post(endpoint, json=replacement_payload)
    assert replacement.status_code == 201, replacement.text
    assert replacement.json()["supersedes"] == original.json()["id"]
    assert client.post(endpoint, json=replacement_payload).json()["id"] == replacement.json()["id"]

    current = client.get(
        endpoint
        + f"?queue_item_id={claim['id']}&lease_token={claim['lease_token']}"
        + "&function_name=parse"
    )
    assert current.status_code == 200, current.text
    assert [row["id"] for row in current.json()] == [replacement.json()["id"]]

    history = client.get(endpoint + "?include_superseded=true")
    assert history.status_code == 200, history.text
    history_by_id = {row["id"]: row for row in history.json()}
    assert history_by_id[original.json()["id"]]["superseded_at"] is None
    assert history_by_id[original.json()["id"]]["replaced_by_result_id"] == replacement.json()["id"]

    conflicting = client.post(
        endpoint,
        json=payload
        | {
            "supersedes": original.json()["id"],
            "hypothesis": "a second correction",
            "disposition": "clean",
        },
    )
    assert conflicting.status_code == 409
    assert "already replaced" in conflicting.json()["detail"]

    done = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/done",
        json=_owned(
            claim,
            item_ids=[claim["id"]],
            disposition="clean",
            notes="Corrected function result is authoritative for this lease.",
            cwe_coverage=_network_input_coverage(default_effort=80),
        ),
    )
    assert done.status_code == 200, done.text


def test_suspicious_result_atomically_materializes_its_run_candidate(
    client, isolate_settings
) -> None:
    engagement_key = "2026-09-10-suspicious-run-candidate"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="candidate-repo")
    parser_file = next(
        row for row in _create_files(client, engagement_key, int(repo["id"]))
        if row["file_path"] == "src/parser.py"
    )
    repo = client.get(
        f"/engagements/{engagement_key}/assessment/code/repos/{repo['id']}"
    ).json()
    _classify_file(client, engagement_key, int(parser_file["id"]), "critical", 100)
    claim = _claim_file_for_analysis(
        client, engagement_key, int(parser_file["id"]), agent_name="result-agent"
    )
    assessment_base = f"/engagements/{engagement_key}/assessment"
    dispatch = client.post(
        f"{assessment_base}/dispatches",
        json={
            "agent_id": "result-agent",
            "agent_role": "code-vuln-hunter",
            "task": "review candidate source",
        },
    )
    assert dispatch.status_code == 201, dispatch.text
    run = client.post(
        f"{assessment_base}/assessment-runs",
        json={
            "run_uuid": "suspicious-candidate-run",
            "run_kind": "code",
            "run_purpose": "scan",
            "producer_dispatch_agent_id": "result-agent",
            "target_identity": {"repositories": ["candidate-repo"]},
            "source_generations": [
                {
                    "target_key": "candidate-repo",
                    "generation": repo["active_generation"],
                    "manifest_digest": repo["source_manifest_digest"],
                }
            ],
        },
    ).json()
    assert client.patch(
        f"{assessment_base}/assessment-runs/{run['id']}", json={"status": "running"}
    ).status_code == 200
    sources = client.post(
        f"{assessment_base}/assessment-runs/{run['id']}/sources",
        json={
            "sources": [
                {
                    "target_key": "candidate-repo",
                    "declared_root": ".",
                    "path": "src/parser.py",
                    "content_sha256": parser_file["file_hash"],
                    "byte_size": 1,
                    "line_count": parser_file["loc"],
                    "encoding": "utf-8",
                    "inventory_status": "included",
                    "exclusion_reason": "",
                    "parser_status": "parsed",
                    "parser_error": "",
                },
                {
                    "target_key": "candidate-repo",
                    "declared_root": ".",
                    "path": "src/helpers.py",
                    "content_sha256": "f" * 64,
                    "byte_size": 1,
                    "line_count": 1,
                    "encoding": "utf-8",
                    "inventory_status": "included",
                    "exclusion_reason": "",
                    "parser_status": "parsed",
                    "parser_error": "",
                },
            ]
        },
    ).json()
    source = next(row for row in sources if row["path"] == "src/parser.py")
    wrong_source = next(row for row in sources if row["path"] == "src/helpers.py")
    payload = {
        "queue_item_id": claim["id"],
        "file_id": parser_file["id"],
        "agent_name": "result-agent",
        "lease_token": claim["lease_token"],
        "function_name": "parse",
        "hypothesis": "attacker length reaches allocation",
        "evidence": "src/parser.py:1",
        "disposition": "suspicious",
        "confidence": "high",
        "assessment_run_id": run["id"],
        "assessment_source_id": source["id"],
    }
    missing_run_identity = client.post(
        f"{assessment_base}/code/analysis-results",
        json={
            key: value
            for key, value in payload.items()
            if key not in {"assessment_run_id", "assessment_source_id"}
        },
    )
    assert missing_run_identity.status_code == 409, missing_run_identity.text
    mismatched = client.post(
        f"{assessment_base}/code/analysis-results",
        json={**payload, "assessment_source_id": wrong_source["id"]},
    )
    assert mismatched.status_code == 409, mismatched.text
    unbound_finding = client.post(
        f"{assessment_base}/findings",
        json={
            "slug": "CH-990",
            "title": "Current code finding without candidate promotion",
            "severity": "medium",
            "workflow_status": "active",
            "canonical_location": "file:src/parser.py:1",
            "summary": "A current finding exists, but it did not enter the run candidate lifecycle.",
            "source_name": "result-agent",
                "provenance": {
                    "agent_id": "result-agent",
                    "code_snapshot": {
                    "repo_id": repo["id"],
                    "repo_generation": repo["active_generation"],
                    "source_manifest_digest": repo["source_manifest_digest"],
                }
            },
        },
    )
    assert unbound_finding.status_code == 201, unbound_finding.text
    bypassed_finding_result = client.post(
        f"{assessment_base}/code/analysis-results",
        json={
            **{
                key: value
                for key, value in payload.items()
                if key not in {"assessment_run_id", "assessment_source_id"}
            },
            "disposition": "finding",
            "finding_slug": "CH-990",
        },
    )
    assert bypassed_finding_result.status_code == 409, bypassed_finding_result.text
    first = client.post(
        f"{assessment_base}/code/analysis-results", json=payload
    )
    retry = client.post(
        f"{assessment_base}/code/analysis-results", json=payload
    )
    assert first.status_code == 201, first.text
    assert retry.status_code == 201, retry.text
    assert first.json()["run_candidate"]["originating_result_id"] == first.json()["id"]
    assert retry.json()["run_candidate"]["id"] == first.json()["run_candidate"]["id"]
    candidates = client.get(
        f"{assessment_base}/assessment-runs/{run['id']}/candidates?limit=10&offset=0"
    ).json()
    assert candidates["total"] == 1
    assert candidates["items"][0]["identity_key"].startswith("candidate:v1:")
    generic_mismatch = client.post(
        f"{assessment_base}/assessment-runs/{run['id']}/candidates",
        json={
            "identity_key": "candidate:generic-mismatched-result",
            "target_key": "candidate-repo",
            "source_id": wrong_source["id"],
            "source_anchor": "src/parser.py:parse",
            "vulnerability_family": "unclassified",
            "hypothesis": "attacker length reaches allocation",
            "originating_result_id": first.json()["id"],
            "dispatch_agent_id": "result-agent",
        },
    )
    assert generic_mismatch.status_code == 409, generic_mismatch.text
    command = client.post(
        f"{assessment_base}/command-runs",
        json={
            "run_uuid": "candidate-promotion-proof",
            "agent_name": "result-agent",
            "command": "verify exact parser source",
            "tool_name": "review",
            "phase": "code-verify",
            "status": "completed",
            "return_code": 0,
            "started_at": "2026-09-10T12:00:00Z",
            "completed_at": "2026-09-10T12:00:01Z",
        },
    )
    assert command.status_code == 201, command.text
    proof = client.post(
        f"{assessment_base}/proof-receipts",
        json={
            "run_id": run["id"],
            "evidence_kind": "command",
            "command_run_id": command.json()["id"],
            "observed_result": "exact parser source supports candidate promotion",
        },
    )
    assert proof.status_code == 201, proof.text
    promoted_finding = client.post(
        f"{assessment_base}/findings",
        json={
            "slug": "CH-991",
            "title": "Current code finding with atomic candidate promotion",
            "severity": "medium",
            "workflow_status": "active",
            "canonical_location": "file:src/parser.py:1",
            "summary": "The exact analysis candidate was promoted with this finding.",
                "source_name": "result-agent",
                "provenance": {
                    "agent_id": "result-agent",
                    "code_snapshot": {
                    "repo_id": repo["id"],
                    "repo_generation": repo["active_generation"],
                    "source_manifest_digest": repo["source_manifest_digest"],
                }
            },
            "run_candidate": {
                "run_id": run["id"],
                "candidate_id": first.json()["run_candidate"]["id"],
                "reason": "promoted after exact source verification",
                "proof_receipt_ids": [proof.json()["id"]],
            },
        },
    )
    assert promoted_finding.status_code == 201, promoted_finding.text
    linked_finding_result = client.post(
        f"{assessment_base}/code/analysis-results",
        json={
            **{
                key: value
                for key, value in payload.items()
                if key not in {"assessment_run_id", "assessment_source_id"}
            },
            "disposition": "finding",
            "finding_slug": "CH-991",
        },
    )
    assert linked_finding_result.status_code == 201, linked_finding_result.text
    assert linked_finding_result.json()["run_candidate"]["id"] == first.json()[
        "run_candidate"
    ]["id"]
    assert linked_finding_result.json()["run_candidate"]["state"] == "promoted"


def test_automatic_analysis_candidate_identity_persists_across_equivalent_scans(
    client, isolate_settings
) -> None:
    engagement_key = "2026-09-10-stable-analysis-candidate"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="stable-candidate-repo")
    parser_file = next(
        row
        for row in _create_files(client, engagement_key, int(repo["id"]))
        if row["file_path"] == "src/parser.py"
    )
    repo = client.get(
        f"/engagements/{engagement_key}/assessment/code/repos/{repo['id']}"
    ).json()
    _classify_file(client, engagement_key, int(parser_file["id"]), "critical", 100)
    assessment_base = f"/engagements/{engagement_key}/assessment"
    dispatch = client.post(
        f"{assessment_base}/dispatches",
        json={
            "agent_id": "stable-result-agent",
            "agent_role": "code-vuln-hunter",
            "task": "review stable candidate source",
        },
    )
    assert dispatch.status_code == 201, dispatch.text

    def create_run(run_uuid: str) -> tuple[dict, dict]:
        run_response = client.post(
            f"{assessment_base}/assessment-runs",
            json={
                "run_uuid": run_uuid,
                "run_kind": "code",
                "run_purpose": "scan",
                "producer_dispatch_agent_id": "stable-result-agent",
                "target_identity": {"repositories": ["stable-candidate-repo"]},
                "source_generations": [
                    {
                        "target_key": "stable-candidate-repo",
                        "generation": repo["active_generation"],
                        "manifest_digest": repo["source_manifest_digest"],
                    }
                ],
            },
        )
        assert run_response.status_code == 201, run_response.text
        run = run_response.json()
        assert client.patch(
            f"{assessment_base}/assessment-runs/{run['id']}",
            json={"status": "running"},
        ).status_code == 200
        source_response = client.post(
            f"{assessment_base}/assessment-runs/{run['id']}/sources",
            json={
                "sources": [
                    {
                        "target_key": "stable-candidate-repo",
                        "declared_root": ".",
                        "path": "src/parser.py",
                        "content_sha256": parser_file["file_hash"],
                        "byte_size": 1,
                        "line_count": parser_file["loc"],
                        "encoding": "utf-8",
                        "inventory_status": "included",
                        "exclusion_reason": "",
                        "parser_status": "parsed",
                        "parser_error": "",
                    }
                ]
            },
        )
        assert source_response.status_code == 201, source_response.text
        return run, source_response.json()[0]

    def record_result(claim: dict, run: dict, source: dict) -> dict:
        response = client.post(
            f"{assessment_base}/code/analysis-results",
            json={
                "queue_item_id": claim["id"],
                "file_id": parser_file["id"],
                "agent_name": "stable-result-agent",
                "lease_token": claim["lease_token"],
                "function_name": "parse",
                "hypothesis": "attacker length reaches allocation",
                "evidence": "src/parser.py:1",
                "disposition": "suspicious",
                "confidence": "high",
                "assessment_run_id": run["id"],
                "assessment_source_id": source["id"],
            },
        )
        assert response.status_code == 201, response.text
        return response.json()

    baseline_run, baseline_source = create_run("stable-analysis-baseline")
    baseline_claim = _claim_file_for_analysis(
        client,
        engagement_key,
        int(parser_file["id"]),
        agent_name="stable-result-agent",
    )
    baseline_result = record_result(baseline_claim, baseline_run, baseline_source)
    baseline_identity = baseline_result["run_candidate"]["identity_key"]
    closeout = client.post(
        f"{assessment_base}/code/analysis-queue/done",
        json=_owned(
            baseline_claim,
            item_ids=[baseline_claim["id"]],
            disposition="suspicious",
            notes="stable suspicious result recorded",
            cwe_coverage=_network_input_coverage(default_effort=80),
        ),
    )
    assert closeout.status_code == 200, closeout.text

    current_run, current_source = create_run("stable-analysis-current")
    current_claim = _claim_file_for_reanalysis(
        client,
        engagement_key,
        int(parser_file["id"]),
        reason="compare an equivalent independent scan",
        agent_name="stable-result-agent",
    )
    current_result = record_result(current_claim, current_run, current_source)
    current_identity = current_result["run_candidate"]["identity_key"]

    assert current_identity == baseline_identity
    comparison = client.get(
        f"{assessment_base}/assessment-runs/{current_run['id']}/comparison",
        params={"baseline_run_id": baseline_run["id"]},
    )
    assert comparison.status_code == 200, comparison.text
    assert comparison.json()["classifications"] == {
        "new": [],
        "persisting": [current_identity],
        "resolved": [],
        "unknown": [],
    }
    current_closeout = client.post(
        f"{assessment_base}/code/analysis-queue/done",
        json=_owned(
            current_claim,
            item_ids=[current_claim["id"]],
            disposition="suspicious",
            notes="current suspicious result recorded",
            cwe_coverage=_network_input_coverage(default_effort=80),
        ),
    )
    assert current_closeout.status_code == 200, current_closeout.text
    repeated_claim = _claim_file_for_reanalysis(
        client,
        engagement_key,
        int(parser_file["id"]),
        reason="repeat equivalent analysis inside the current scan",
        agent_name="stable-result-agent",
    )
    repeated_result = record_result(repeated_claim, current_run, current_source)
    repeated_retry = record_result(repeated_claim, current_run, current_source)
    assert repeated_result["run_candidate"]["id"] == current_result["run_candidate"]["id"]
    assert repeated_retry["id"] == repeated_result["id"]
    assert repeated_retry["run_candidate"]["id"] == current_result["run_candidate"]["id"]
    candidates = client.get(
        f"{assessment_base}/assessment-runs/{current_run['id']}/candidates",
        params={"limit": 10, "offset": 0},
    )
    assert candidates.status_code == 200, candidates.text
    assert candidates.json()["total"] == 1


def test_filtered_queue_claim_applies_every_lane_inside_atomic_selection(
    client, isolate_settings
):
    engagement_key = "2026-07-15-code-filtered-claim"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo_a = _create_repo(client, engagement_key, repo_key="lane-repo-a")
    repo_b = _create_repo(client, engagement_key, repo_key="lane-repo-b")
    file_a = next(
        row for row in _create_files(client, engagement_key, int(repo_a["id"]))
        if row["file_path"] == "src/parser.py"
    )
    files_b = _create_files(client, engagement_key, int(repo_b["id"]))
    target = next(row for row in files_b if row["file_path"] == "src/parser.py")
    wrong_class = next(row for row in files_b if row["file_path"] == "src/helpers.py")
    _classify_file(client, engagement_key, int(file_a["id"]), "critical", 100)
    _classify_file(client, engagement_key, int(target["id"]), "high", 79)
    _classify_file(client, engagement_key, int(wrong_class["id"]), "low", 19)
    queued = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue",
        json={
            "items": [
                {"file_id": file_a["id"], "priority": 100, "batch_theme": "targeted"},
                {"file_id": target["id"], "priority": 79, "batch_theme": "targeted"},
                {"file_id": wrong_class["id"], "priority": 19, "batch_theme": "targeted"},
            ]
        },
    )
    assert queued.status_code == 201, queued.text
    db_path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    with sqlite3.connect(str(db_path)) as connection:
        target_queue_id = int(
            connection.execute(
                """
                SELECT id FROM code_analysis_queue
                WHERE file_id = ? AND batch_theme = 'targeted'
                """,
                (target["id"],),
            ).fetchone()[0]
        )

    claimed = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/fetch",
        json={
            "limit": 1,
            "agent_name": "lane-agent",
            "repo_id": repo_b["id"],
            "classification": "high",
            "batch_theme": "targeted",
            "item_ids": [target_queue_id, 999999],
        },
    )
    assert claimed.status_code == 200, claimed.text
    assert [row["id"] for row in claimed.json()] == [target_queue_id]
    assert claimed.json()[0]["file_id"] == target["id"]
    assert claimed.json()[0]["repo_generation"] == 2
    assert claimed.json()[0]["agent_name"] == "lane-agent"
    assert claimed.json()[0]["lease_token"]

    next_claim = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/fetch",
        json={"limit": 1, "agent_name": "next-agent"},
    )
    assert next_claim.status_code == 200
    assert next_claim.json()[0]["file_id"] == file_a["id"]


@pytest.mark.parametrize("disposition", ["finding", "suspicious"])
def test_signal_closeout_requires_current_result_with_evidence_or_artifact(
    client, isolate_settings, disposition
):
    engagement_key = f"2026-07-15-code-closeout-{disposition}"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key=f"closeout-{disposition}-repo")
    parser_file = next(
        row for row in _create_files(client, engagement_key, int(repo["id"]))
        if row["file_path"] == "src/parser.py"
    )
    _classify_file(client, engagement_key, int(parser_file["id"]), "high", 79)
    finding_binding: dict[str, str] = {}
    if disposition == "finding":
        _create_code_parent_finding(
            client,
            engagement_key,
            int(repo["id"]),
            slug="CH-704",
        )
        finding_binding["finding_slug"] = "CH-704"
    claim = _claim_file_for_analysis(
        client, engagement_key, int(parser_file["id"]), agent_name="evidence-agent"
    )
    closeout_payload = _owned(
        claim,
        item_ids=[claim["id"]],
        disposition=disposition,
        notes="signal reviewed",
        cwe_coverage=_network_input_coverage(default_effort=80),
    )
    missing_result = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/done",
        json=closeout_payload,
    )
    assert missing_result.status_code == 400
    assert "current analysis result with evidence or evidence_ref" in missing_result.json()["detail"]

    empty_result = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-results",
        json=_owned(
            claim,
            queue_item_id=claim["id"],
            disposition=disposition,
            function_name="parse",
            **finding_binding,
        ),
    )
    assert empty_result.status_code == 201, empty_result.text
    still_missing = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/done",
        json=closeout_payload,
    )
    assert still_missing.status_code == 400

    evidenced_result = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-results",
        json=_owned(
            claim,
            queue_item_id=claim["id"],
            disposition=disposition,
            function_name="parse",
            evidence_ref="tools/analysis-state/parser-trace.json",
            **finding_binding,
        ),
    )
    assert evidenced_result.status_code == 201, evidenced_result.text
    assert evidenced_result.json()["evidence_ref"].endswith("parser-trace.json")
    assert evidenced_result.json()["repo_generation"] == claim["repo_generation"]
    accepted = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/done",
        json=closeout_payload,
    )
    assert accepted.status_code == 200, accepted.text


@pytest.mark.parametrize("result_disposition", ["finding", "suspicious"])
@pytest.mark.parametrize("close_disposition", ["clean", "skipped"])
def test_candidate_result_cannot_be_downcast_by_queue_closeout(
    client, isolate_settings, result_disposition, close_disposition
):
    engagement_key = (
        f"2026-08-05-code-closeout-downcast-{result_disposition}-{close_disposition}"
    )
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key=f"{engagement_key}-repo")
    parser_file = next(
        row for row in _create_files(client, engagement_key, int(repo["id"]))
        if row["file_path"] == "src/parser.py"
    )
    _classify_file(client, engagement_key, int(parser_file["id"]), "high", 79)
    finding_binding: dict[str, str] = {}
    if result_disposition == "finding":
        _create_code_parent_finding(
            client,
            engagement_key,
            int(repo["id"]),
            slug="CH-705",
        )
        finding_binding["finding_slug"] = "CH-705"
    claim = _claim_file_for_analysis(
        client, engagement_key, int(parser_file["id"]), agent_name="candidate-agent"
    )
    candidate = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-results",
        json=_owned(
            claim,
            queue_item_id=claim["id"],
            disposition=result_disposition,
            function_name="parse",
            evidence="Attacker-controlled bytes reach a candidate sink.",
            **finding_binding,
        ),
    )
    assert candidate.status_code == 201, candidate.text

    closeout = {
        "item_ids": [claim["id"]],
        "disposition": close_disposition,
        "notes": "Attempted lower-signal closeout.",
    }
    if close_disposition == "clean":
        closeout["cwe_coverage"] = _network_input_coverage(default_effort=80)
    else:
        closeout["skip_reason"] = "generated-code"
    rejected = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/done",
        json=_owned(claim, **closeout),
    )

    assert rejected.status_code == 409
    assert "candidate-bearing analysis result" in rejected.json()["detail"]
    db_path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    with sqlite3.connect(str(db_path)) as connection:
        queue_status = connection.execute(
            "SELECT status FROM code_analysis_queue WHERE id = ?", (claim["id"],)
        ).fetchone()[0]
    assert queue_status == "processing"
    current_results = client.get(
        f"/engagements/{engagement_key}/assessment/code/analysis-results"
        f"?file_id={parser_file['id']}"
    ).json()
    assert [row["id"] for row in current_results] == [candidate.json()["id"]]


def test_conflicting_candidate_result_dispositions_fail_closed(
    client, isolate_settings
):
    engagement_key = "2026-08-05-code-closeout-conflicting-candidates"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="conflicting-candidates-repo")
    parser_file = next(
        row for row in _create_files(client, engagement_key, int(repo["id"]))
        if row["file_path"] == "src/parser.py"
    )
    _classify_file(client, engagement_key, int(parser_file["id"]), "high", 79)
    _create_code_parent_finding(
        client,
        engagement_key,
        int(repo["id"]),
        slug="CH-706",
    )
    claim = _claim_file_for_analysis(
        client, engagement_key, int(parser_file["id"]), agent_name="candidate-agent"
    )
    for disposition in ("finding", "suspicious"):
        created = client.post(
            f"/engagements/{engagement_key}/assessment/code/analysis-results",
            json=_owned(
                claim,
                queue_item_id=claim["id"],
                disposition=disposition,
                function_name=f"parse_{disposition}",
                evidence=f"Current evidenced {disposition} candidate.",
                **({"finding_slug": "CH-706"} if disposition == "finding" else {}),
            ),
        )
        assert created.status_code == 201, created.text

    rejected = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/done",
        json=_owned(
            claim,
            item_ids=[claim["id"]],
            disposition="finding",
            notes="Cannot choose between contradictory candidate receipts.",
            cwe_coverage=_network_input_coverage(default_effort=80),
        ),
    )

    assert rejected.status_code == 409
    assert "conflicting candidate-bearing analysis result dispositions" in rejected.json()[
        "detail"
    ]
    db_path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    with sqlite3.connect(str(db_path)) as connection:
        queue_status = connection.execute(
            "SELECT status FROM code_analysis_queue WHERE id = ?", (claim["id"],)
        ).fetchone()[0]
    assert queue_status == "processing"


def test_clean_closeout_requires_nonempty_review_notes(client, isolate_settings):
    engagement_key = "2026-07-15-code-clean-closeout-notes"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="clean-closeout-repo")
    parser_file = next(
        row for row in _create_files(client, engagement_key, int(repo["id"]))
        if row["file_path"] == "src/parser.py"
    )
    _classify_file(client, engagement_key, int(parser_file["id"]), "medium", 49)
    claim = _claim_file_for_analysis(client, engagement_key, int(parser_file["id"]))
    payload = _owned(
        claim,
        item_ids=[claim["id"]],
        disposition="clean",
        cwe_coverage=_network_input_coverage(default_effort=70),
    )
    rejected = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/done", json=payload
    )
    assert rejected.status_code == 400
    assert "notes are required" in rejected.json()["detail"]
    accepted = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/done",
        json={**payload, "notes": "Reviewed every applicable family and found no issue."},
    )
    assert accepted.status_code == 200, accepted.text


def test_cwe_detail_surfaces_effort_derived_from_current_results(client, isolate_settings):
    engagement_key = "2026-07-15-code-derived-effort"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="derived-effort-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser_file = next(
        row for row in files
        if row["file_path"] == "src/parser.py"
    )
    _classify_file(client, engagement_key, int(parser_file["id"]), "high", 79)
    _publish_structural_totals(
        client,
        engagement_key,
        int(repo["id"]),
        files,
        {int(parser_file["id"]): {"total_functions": 4}},
    )
    claim = _claim_file_for_analysis(client, engagement_key, int(parser_file["id"]))
    for index in range(2):
        result = client.post(
            f"/engagements/{engagement_key}/assessment/code/analysis-results",
            json=_owned(
                claim,
                queue_item_id=claim["id"],
                disposition="clean",
                function_name=f"parse_{index}",
                evidence=f"src/parser.py:{index + 1}",
                cwe_coverage=[{
                    "family": "ssrf",
                    "effort": 99,
                    "functions_analyzed": 999,
                }],
            ),
        )
        assert result.status_code == 201, result.text

    detail = client.get(
        f"/engagements/{engagement_key}/assessment/code/coverage?repo_id={repo['id']}&detail=cwe"
    )
    assert detail.status_code == 200, detail.text
    parser_detail = next(row for row in detail.json()["files"] if row["file_id"] == parser_file["id"])
    assert parser_detail["analysis_effort"] == {
        "current_result_rows": 2,
        "evidenced_result_rows": 2,
        "distinct_functions_with_results": 2,
        "total_functions": 4,
        "function_coverage_pct": 50.0,
    }


def test_coverage_projections_exclude_receipts_from_an_unrelated_file_refresh_generation(
    client, isolate_settings
):
    engagement_key = "2026-08-05-code-coverage-stale-generation"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="coverage-stale-generation-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser = next(row for row in files if row["file_path"] == "src/parser.py")
    helper = next(row for row in files if row["file_path"] == "src/helpers.py")
    base = f"/engagements/{engagement_key}/assessment/code"
    _classify_file(client, engagement_key, int(parser["id"]), "high", 79)
    claim = _claim_file_for_analysis(client, engagement_key, int(parser["id"]))
    result = client.post(
        f"{base}/analysis-results",
        json=_owned(
            claim,
            queue_item_id=claim["id"],
            disposition="clean",
            function_name="parse",
            evidence="Current only for the original repository generation.",
            cwe_coverage=[
                {"family": family, "effort": 1, "functions_analyzed": 1}
                for family in (
                    "web-app-injection",
                    "web-app-auth",
                    "ssrf",
                    "open-redirect",
                    "path-traversal",
                )
            ],
        ),
    )
    assert result.status_code == 201, result.text
    completed = client.post(
        f"{base}/analysis-queue/done",
        json=_owned(
            claim,
            item_ids=[claim["id"]],
            disposition="clean",
            notes="Original generation review.",
            cwe_coverage=_network_input_coverage(default_effort=1),
        ),
    )
    assert completed.status_code == 200, completed.text
    previous_generation = int(claim["repo_generation"])

    manifest_fields = {
        "file_path",
        "language",
        "loc",
        "file_hash",
        "header_snippet",
        "git_churn_score",
        "has_past_cve_fix",
    }
    refreshed = _refresh_repo_files(
        client,
        engagement_key,
        int(repo["id"]),
        [
            {key: parser[key] for key in manifest_fields},
            {
                **{key: helper[key] for key in manifest_fields},
                "file_hash": _source_hash("helpers-generation-two"),
            },
        ],
    )
    current_parser = next(row for row in refreshed if row["id"] == parser["id"])
    current_repo = client.get(f"{base}/repos/{repo['id']}").json()
    assert int(current_repo["active_generation"]) == previous_generation + 1
    assert current_parser["classification"] == "high"

    summary = client.get(f"{base}/coverage?repo_id={repo['id']}").json()
    assert summary["by_classification"]["high"]["analyzed"] == 0
    assert summary["by_status"].get("analyzed", 0) == 0
    assert summary["confidence"]["overall_loc_analyzed"] == 0
    assert not any(
        "src/parser.py" in warning
        for warning in summary["gate"]["effort_warnings"]
    )
    detail = client.get(
        f"{base}/coverage?repo_id={repo['id']}&detail=cwe"
    ).json()
    parser_detail = next(row for row in detail["files"] if row["file_id"] == parser["id"])
    assert parser_detail["cwe_coverage"] == []
    assert parser_detail["analysis_effort"]["current_result_rows"] == 0
    assert parser_detail["analysis_effort"]["evidenced_result_rows"] == 0
    assert parser_detail["analysis_effort"]["distinct_functions_with_results"] == 0
    assert parser_detail["analysis_effort"]["function_coverage_pct"] == 0.0
    assert client.get(f"{base}/analysis-results?file_id={parser['id']}").json() == []
    history = client.get(
        f"{base}/analysis-results?file_id={parser['id']}&include_superseded=true"
    ).json()
    assert [row["id"] for row in history] == [result.json()["id"]]


def test_coverage_projections_require_result_lease_identity(client, isolate_settings):
    engagement_key = "2026-08-05-code-coverage-result-lease"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="coverage-result-lease-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser = next(row for row in files if row["file_path"] == "src/parser.py")
    base = f"/engagements/{engagement_key}/assessment/code"
    _classify_file(client, engagement_key, int(parser["id"]), "high", 79)
    claim = _claim_file_for_analysis(client, engagement_key, int(parser["id"]))
    with db_module.get_connection() as connection:
        engagement_id = connection.execute(
            "SELECT id FROM engagements WHERE key = ?", (engagement_key,)
        ).fetchone()[0]
        connection.execute(
            """
            INSERT INTO code_analysis_results (
                engagement_id, queue_item_id, file_id, agent_name, function_name,
                evidence, disposition, cwe_coverage_json, lease_token,
                repo_generation, result_fingerprint
            ) VALUES (?, ?, ?, 'forged-agent', 'parse', 'forged evidence', 'clean',
                      ?, 'wrong-lease', ?, 'forged-result')
            """,
            (
                engagement_id,
                claim["id"],
                parser["id"],
                json.dumps(
                    [
                        {"family": family, "effort": 1, "functions_analyzed": 1}
                        for family in (
                            "web-app-injection",
                            "web-app-auth",
                            "ssrf",
                            "open-redirect",
                            "path-traversal",
                        )
                    ]
                ),
                claim["repo_generation"],
            ),
        )

    summary = client.get(f"{base}/coverage?repo_id={repo['id']}").json()
    assert not any(
        "src/parser.py" in warning
        for warning in summary["gate"]["effort_warnings"]
    )
    detail = client.get(
        f"{base}/coverage?repo_id={repo['id']}&detail=cwe"
    ).json()
    parser_detail = next(row for row in detail["files"] if row["file_id"] == parser["id"])
    assert parser_detail["cwe_coverage"] == []
    assert parser_detail["analysis_effort"]["current_result_rows"] == 0
    assert parser_detail["analysis_effort"]["function_coverage_pct"] == 0.0


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

    manifest_fields = {
        "file_path",
        "language",
        "loc",
        "file_hash",
        "header_snippet",
        "git_churn_score",
        "has_past_cve_fix",
    }
    next_files = [
        {
            **{key: parser[key] for key in manifest_fields},
            "loc": 81,
            "file_hash": _source_hash("hash-a-changed"),
        },
        {
            **{key: helper[key] for key in manifest_fields},
            "file_path": "src/renamed_helpers.py",
        },
        {
            "file_path": "src/new.py",
            "language": "python",
            "loc": 5,
            "file_hash": _source_hash("hash-new"),
        },
    ]
    started = client.post(
        f"/engagements/{engagement_key}/assessment/code/repos/refresh/start",
        json=_verified_repo_payload(
            client,
            engagement_key,
            "refresh-repo",
            next_files,
        ),
    )
    assert started.status_code == 201, started.text
    refresh_token = started.json()["refresh_token"]
    staged = client.post(
        f"/engagements/{engagement_key}/assessment/code/repos/{repo['id']}/refresh/files",
        json={
            "refresh_token": refresh_token,
            "files": next_files,
        },
    )
    assert staged.status_code == 200, staged.text

    # An interrupted refresh leaves the last committed tree authoritative.
    before_commit = client.get(
        f"/engagements/{engagement_key}/assessment/code/files?repo_id={repo['id']}&limit=20"
    ).json()["items"]
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
    ).json()["items"]
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
        json=_verified_repo_payload(
            client,
            engagement_key,
            "refresh-empty-repo",
        ),
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
    assert files.json()["items"] == []


def test_interrupted_first_ingest_does_not_publish_generation_zero_repo(client, isolate_settings):
    engagement_key = "2026-07-14-code-refresh-first-ingest"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    base = f"/engagements/{engagement_key}/assessment/code"

    started = client.post(
        f"{base}/repos/refresh/start",
        json=_verified_repo_payload(
            client,
            engagement_key,
            "first-ingest-repo",
        ),
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
                    "analysis_priority": 70,
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


@pytest.mark.parametrize("slot_type", ["NETWORK-INPUT", "PROTOCOL-FIELD", "URL-COMPONENT"])
def test_untrusted_transport_slots_include_resource_and_error_handling_families(slot_type):
    families = code_analysis._applicable_families_for_file(
        [slot_type],
        language="c++",
        role="http-client-core",
    )

    assert "algorithmic-dos" in families
    assert "error-handling" in families


@pytest.mark.parametrize("slot_types", [[], ["FILE-CONTENT"]])
def test_native_files_include_resource_and_error_handling_families_with_sparse_context(slot_types):
    families = code_analysis._applicable_families_for_file(
        slot_types,
        language="c++",
        role="",
    )

    assert "algorithmic-dos" in families
    assert "error-handling" in families


def test_managed_supported_file_has_real_resource_and_error_handling_floor():
    families = code_analysis._applicable_families_for_file(
        ["FILE-CONTENT"],
        language="python",
        role="storage",
    )

    assert "algorithmic-dos" in families
    assert "error-handling" in families


def test_unknown_language_does_not_receive_a_synthetic_family_floor():
    families = code_analysis._applicable_families_for_file(
        [],
        language="",
        role="",
    )

    assert families == []


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
        "error-handling",
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
    files = _create_files(client, engagement_key, int(repo["id"]))
    base = f"/engagements/{engagement_key}/assessment/code"
    binding = client.get(f"{base}/repos/{repo['id']}").json()
    repo_patch = client.post(
        f"{base}/repos/{repo['id']}/lsp-config",
        json={
            "repo_generation": binding["active_generation"],
            "source_manifest_digest": binding["source_manifest_digest"],
            "lsp_config": {
                "languages": {"python": {"available": False}},
                "ctags": {"available": True},
            },
        },
    )
    assert repo_patch.status_code == 200
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


@pytest.mark.parametrize(
    ("field_name", "replacement"),
    [
        ("repo_key", "replacement-key"),
        ("repo_path", "/tmp/replacement-path"),
        ("source_origin_path", "/tmp/replacement-origin"),
        ("source_kind", "git"),
        ("snapshot_manifest_path", "replacement/manifest.json"),
        ("snapshot_digest", "b" * 64),
        ("source_manifest_version", "replacement-version"),
        ("source_manifest_digest", "c" * 64),
        ("source_snapshot_quality", "legacy-unverified"),
        ("worktree_dirty", True),
        ("active_generation", 99),
    ],
)
def test_repo_patch_rejects_sealed_source_identity(
    client, isolate_settings, field_name, replacement
):
    engagement_key = "2026-08-04-code-repo-patch-sealed-source"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="repo-patch-sealed-source")
    endpoint = (
        f"/engagements/{engagement_key}/assessment/code/repos/{repo['id']}"
    )

    response = client.patch(endpoint, json={field_name: replacement})

    assert response.status_code == 400, response.text
    assert response.json()["detail"] == (
        f"repo patch does not accept fields: {field_name}"
    )
    assert client.get(endpoint).json()[field_name] == repo[field_name]


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
            "agent_name": queue_item["agent_name"],
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
            "agent_name": queue_item["agent_name"],
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
            "agent_name": queue_item["agent_name"],
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
            "agent_name": queue_item["agent_name"],
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
    _classify_file(client, engagement_key, int(helper_file["id"]), "high", 79)

    queue_response = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue",
        json={
            "items": [
                {"file_id": parser_file["id"], "priority": 100},
                    {"file_id": helper_file["id"], "priority": 79},
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
    assert done.json()["detail"] == (
        f"Cannot complete queue item {queue_item_id} unless it is processing; "
        "current status is pending"
    )


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
    assert analysis_result.json()["detail"] == (
        f"Cannot record analysis results for queue item {queue_item_id} unless it is "
        "processing; current status is pending"
    )


def test_queue_status_validation_retains_plural_batch_diagnostics() -> None:
    with pytest.raises(HTTPException) as exc_info:
        code_analysis._require_queue_status(
            {
                41: {"status": "pending"},
                42: {"status": "processing"},
            },
            expected_status="error",
            action="retry",
        )

    assert exc_info.value.detail == (
        "Cannot retry queue items unless they are error: 41=pending, 42=processing"
    )


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
            if "SELECT queue.id, queue.file_id, queue.lease_token" in sql and "lease_activity_at" in sql:
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
    assert rejected.json()["detail"] == (
        f"Cannot retry queue item {queue_item['id']} unless it is error; "
        "current status is processing"
    )

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
            "agent_name": queue_item["agent_name"],
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
            "agent_name": queue_item["agent_name"],
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
    _classify_file(client, engagement_key, int(helper_file["id"]), "high", 79)

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
            "agent_name": queue_item["agent_name"],
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
                "priority": 79,
                "reason": "shared parser helper",
                "trigger_context": {"vuln_class": "web-app-injection"},
            },
            {
                "file_path": "src/helpers.py",
                "priority": 79,
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
            "agent_name": helper_item["agent_name"],
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
            "agent_name": queue_item["agent_name"],
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
            "agent_name": queue_item["agent_name"],
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
            "agent_name": first_item["agent_name"],
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

    second_item = _claim_file_for_reanalysis(
        client,
        engagement_key,
        file_id,
        priority=100,
        reason="Revisit an incorrectly excluded SSRF family",
    )
    second_done = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/done",
        json={
            "item_ids": [second_item["id"]],
            "agent_name": second_item["agent_name"],
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
    _classify_file(client, engagement_key, int(helper_file["id"]), "high", 79)

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
            "agent_name": queue_item["agent_name"],
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
                        "priority": 79,
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


def test_trigger_status_does_not_trust_mutable_file_analysis_rollup(client, isolate_settings):
    engagement_key = "2026-08-05-code-trigger-derived-status"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="trigger-derived-status-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser = next(row for row in files if row["file_path"] == "src/parser.py")
    helper = next(row for row in files if row["file_path"] == "src/helpers.py")
    _classify_file(client, engagement_key, int(parser["id"]), "critical", 100)
    claim = _claim_file_for_analysis(client, engagement_key, int(parser["id"]))
    with db_module.get_connection() as connection:
        connection.execute(
            "UPDATE code_files SET analysis_status = 'analyzed' WHERE id = ?",
            (helper["id"],),
        )

    recorded = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-results",
        json=_owned(
            claim,
            queue_item_id=claim["id"],
            disposition="clean",
            evidence="Helper call requires a separate review.",
            cross_file_triggers=[
                {
                    "file_path": "src/helpers.py",
                    "vuln_class": "error-handling",
                    "reason": "Caller-visible error mapping crosses into the helper.",
                }
            ],
        ),
    )
    assert recorded.status_code == 201, recorded.text

    triggers = client.get(
        f"/engagements/{engagement_key}/assessment/code/triggers"
    ).json()
    assert len(triggers) == 1
    assert triggers[0]["status"] == "pending"


def test_late_cross_file_trigger_requires_its_bound_post_trigger_review(
    client, isolate_settings
):
    engagement_key = "2026-08-05-code-trigger-post-trigger-review"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="post-trigger-review-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser = next(row for row in files if row["file_path"] == "src/parser.py")
    helper = next(row for row in files if row["file_path"] == "src/helpers.py")
    _classify_file(client, engagement_key, int(parser["id"]), "critical", 100)
    _classify_file(client, engagement_key, int(helper["id"]), "high", 79)
    base = f"/engagements/{engagement_key}/assessment/code"

    old_helper_claim = _claim_file_for_analysis(
        client, engagement_key, int(helper["id"]), priority=79
    )
    old_helper_done = client.post(
        f"{base}/analysis-queue/done",
        json=_owned(
            old_helper_claim,
            item_ids=[old_helper_claim["id"]],
            disposition="clean",
            notes="Helper review completed before any cross-file hypothesis existed.",
            cwe_coverage=_network_input_coverage(default_effort=80),
        ),
    )
    assert old_helper_done.status_code == 200, old_helper_done.text

    parser_claim = _claim_file_for_analysis(
        client, engagement_key, int(parser["id"]), priority=100
    )
    trigger_result = client.post(
        f"{base}/analysis-results",
        json=_owned(
            parser_claim,
            queue_item_id=parser_claim["id"],
            disposition="clean",
            evidence="The parser delegates attacker-controlled framing to the helper.",
            cross_file_triggers=[
                {
                    "file_path": "src/helpers.py",
                    "vuln_class": "error-handling",
                    "reason": "Review helper behavior under the newly discovered parser contract.",
                },
                {
                    "file_path": "src/helpers.py",
                    "vuln_class": "path-traversal",
                    "reason": "Review whether helper normalization permits path escapes.",
                }
            ],
        ),
    )
    assert trigger_result.status_code == 201, trigger_result.text
    triggers = client.get(f"{base}/triggers").json()
    assert {row["vuln_class"] for row in triggers} == {
        "error-handling",
        "path-traversal",
    }
    assert {row["status"] for row in triggers} == {"pending"}
    assert {row["resolved_queue_item_id"] for row in triggers} == {None}

    requeue = client.post(
        f"{base}/analysis-queue/requeue",
        json={
            "items": [
                {
                    "file_id": helper["id"],
                        "priority": 79,
                    "reason": "Review the new parser/helper contract.",
                    "trigger_context": {
                        "vuln_class": "error-handling",
                        "trigger_id": triggers[0]["id"],
                        "source": "caller-spoof",
                        "reason": "caller-spoof",
                    },
                }
            ]
        },
    )
    assert requeue.status_code == 201, requeue.text
    assert requeue.json()["inserted"] == 1
    with db_module.get_connection() as connection:
        linked_rows = connection.execute(
            """
            SELECT triggers.status, triggers.resolved_queue_item_id,
                   queue.repo_generation, repos.active_generation
            FROM code_analysis_triggers AS triggers
            JOIN code_analysis_queue AS queue
              ON queue.id = triggers.resolved_queue_item_id
            JOIN code_files AS files ON files.id = triggers.target_file_id
            JOIN code_repos AS repos ON repos.id = files.repo_id
            WHERE triggers.engagement_id = (
                SELECT id FROM engagements WHERE key = ?
            )
            """,
            (engagement_key,),
        ).fetchall()
    assert len(linked_rows) == 2
    assert {row["status"] for row in linked_rows} == {"queued"}
    assert {
        row["repo_generation"] == row["active_generation"] for row in linked_rows
    } == {True}
    linked_item_ids = {row["resolved_queue_item_id"] for row in linked_rows}
    assert len(linked_item_ids) == 1
    linked_item_id = linked_item_ids.pop()
    assert linked_item_id != old_helper_claim["id"]

    follow_up_claim = client.post(
        f"{base}/analysis-queue/fetch",
        json={
            "limit": 1,
            "agent_name": "cross-file-follow-up",
            "item_ids": [linked_item_id],
        },
    )
    assert follow_up_claim.status_code == 200, follow_up_claim.text
    follow_up = follow_up_claim.json()[0]
    derived_triggers = [
        row
        for row in follow_up["cross_file_triggers"]
        if row.get("source") == "code_analysis_trigger"
    ]
    assert {row["vuln_class"] for row in derived_triggers} == {
        "error-handling",
        "path-traversal",
    }
    assert len({row["trigger_id"] for row in derived_triggers}) == 2
    assert not any(
        row.get("source") == "caller-spoof" or row.get("reason") == "caller-spoof"
        for row in follow_up["cross_file_triggers"]
    )
    assert all(
        row.get("source") == "code_analysis_trigger"
        for row in follow_up["cross_file_triggers"]
        if row.get("trigger_id") is not None
    )
    assert {row["status"] for row in client.get(f"{base}/triggers").json()} == {
        "queued"
    }

    follow_up_done = client.post(
        f"{base}/analysis-queue/done",
        json=_owned(
            follow_up,
            item_ids=[follow_up["id"]],
            disposition="clean",
            notes="Reviewed helper under the newly supplied parser contract.",
            cwe_coverage=_network_input_coverage(default_effort=80),
        ),
    )
    assert follow_up_done.status_code == 200, follow_up_done.text
    assert {row["status"] for row in client.get(f"{base}/triggers").json()} == {
        "resolved"
    }

    _append_repo_files(
        client,
        engagement_key,
        int(repo["id"]),
        [
            {
                "file_path": "src/unrelated_generation_bump.py",
                "language": "python",
                "loc": 4,
                "file_hash": _source_hash("unrelated-generation-bump"),
                "header_snippet": "def unrelated(): pass",
                "git_churn_score": 0,
                "has_past_cve_fix": False,
            }
        ],
    )
    stale_triggers = client.get(f"{base}/triggers").json()
    assert {row["status"] for row in stale_triggers} == {"pending"}
    assert {row["resolved_queue_item_id"] for row in stale_triggers} == {None}


def test_requeue_triggered_files_rejects_non_numeric_ids(client, isolate_settings):
    engagement_key = "2026-04-04-code-requeue-invalid-ids"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="requeue-invalid-ids-repo")
    _create_files(client, engagement_key, int(repo["id"]))

    invalid_file_id = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/requeue",
        json={"items": [{"file_id": "abc"}]},
    )
    assert invalid_file_id.status_code == 422
    assert "file_id" in invalid_file_id.text

    invalid_repo_id = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/requeue",
        json={"items": [{"file_path": "src/parser.py", "repo_id": "abc"}]},
    )
    assert invalid_repo_id.status_code == 422
    assert "repo_id" in invalid_repo_id.text


def test_requeue_triggered_files_keeps_guidance_strings_separate_from_trigger_context(client, isolate_settings):
    engagement_key = "2026-04-16-code-requeue-guidance-shape"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="requeue-guidance-shape")
    files = _create_files(client, engagement_key, int(repo["id"]))
    helper_file = next(item for item in files if item["file_path"] == "src/helpers.py")
    _classify_file(client, engagement_key, int(helper_file["id"]), "high", 79)

    requeue = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/requeue",
        json={
            "items": [
                {
                    "file_path": "src/helpers.py",
                    "priority": 79,
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
                    "file_hash": _source_hash("repo-a-only"),
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
                    "file_hash": _source_hash("repo-b-only"),
                    "header_snippet": "",
                    "git_churn_score": 0,
                    "has_past_cve_fix": False,
                },
        ],
    )
    assert any(row["file_path"] == "repo_b_only.py" for row in unique_files)

    _create_root_finding(client, engagement_key, "CH-090")
    _create_root_finding(client, engagement_key, "CH-091")
    _ensure_finding_author_dispatch(client, engagement_key, "AUTHOR-CH-001")
    _ensure_finding_author_dispatch(client, engagement_key, "AUTHOR-CH-002")
    finding_a = client.post(
        f"/engagements/{engagement_key}/assessment/findings",
        json={
            "slug": "CH-001",
            "title": "Parser trust boundary bypass",
            "severity": "high",
            "workflow_status": "active",
            "verification_status": "unreviewed",
            "defect_family": "trust-boundary-bypass",
            "root_cause_key": "scope-repo-a-parser",
            "auth_context": "anonymous",
            "canonical_location": "file:repo_a_only.py:12",
            "summary": "Repo A finding should stay scoped to repo A coverage.",
            "evidence_ref": "findings.md",
            "notes": "",
            "source_name": "code-vuln-hunter",
            "details": {"evidence": "A"},
            "provenance": {
                "agent_id": "AUTHOR-CH-001",
                "agent_name": "code-vuln-hunter",
                "code_snapshot": _finding_code_snapshot(
                    client, engagement_key, int(repo_a["id"])
                ),
            },
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
            "verification_status": "unreviewed",
            "defect_family": "sink-exposure",
            "root_cause_key": "scope-repo-b-helper",
            "auth_context": "anonymous",
            "canonical_location": "file:repo_b_only.py:20",
            "summary": "Repo B finding should stay scoped to repo B coverage.",
            "evidence_ref": "findings.md",
            "notes": "",
            "source_name": "code-vuln-hunter",
            "details": {"evidence": "B"},
            "provenance": {
                "agent_id": "AUTHOR-CH-002",
                "agent_name": "code-vuln-hunter",
                "code_snapshot": _finding_code_snapshot(
                    client, engagement_key, int(repo_b["id"])
                ),
            },
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
            "agent_name": queue_item["agent_name"],
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
    author_agent_id = "AUTHOR-CH-001"
    _ensure_finding_author_dispatch(client, engagement_key, author_agent_id)
    finding = client.post(
        f"/engagements/{engagement_key}/assessment/findings",
        json={
            "slug": "CH-001",
            "title": "Parser variant",
            "severity": "high",
            "workflow_status": "active",
            "verification_status": "unreviewed",
            "defect_family": "trust-boundary-bypass",
            "root_cause_key": "variant-filter-parser",
            "auth_context": "anonymous",
            "canonical_location": "file:src/parser.py:12",
            "summary": "Variant should disappear from coverage after suppression.",
            "evidence_ref": "findings.md",
            "notes": "",
            "source_name": "code-vuln-hunter",
                "details": {"evidence": "A"},
                "provenance": {
                    "agent_id": author_agent_id,
                    "agent_name": "code-vuln-hunter",
                "code_snapshot": _finding_code_snapshot(
                    client, engagement_key, int(repo["id"])
                ),
            },
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

    verify = _verify_code_finding(
        client,
        engagement_key,
        int(repo["id"]),
        "CH-001",
        disposition="false_positive",
        reason_code="guarded-path",
        reason_text="Guard closes the variant in production.",
        artifact_ref="tools/analysis-state/code-verification/CH-001.json",
        details={
            "kill_check": 4,
            "kill_reason": "Guard closes the path in production.",
            "evidence": "Validation rejects the attacker-controlled branch.",
            "impact": "No reachable issue remains.",
        },
    )
    assert verify["finding"]["verification_status"] == "false_positive"

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
    _ensure_finding_author_dispatch(client, engagement_key, "AUTHOR-VA-001")
    finding = client.post(
        f"/engagements/{engagement_key}/assessment/findings",
        json={
            "slug": "VA-001",
            "title": "HTTP variant",
            "severity": "high",
            "workflow_status": "active",
            "verification_status": "unreviewed",
            "defect_family": "authz-bypass",
            "root_cause_key": "http-variant",
            "auth_context": "anonymous",
            "canonical_location": "https://example.com/api/export",
            "summary": "Non-code finding should not inflate code variant counts.",
            "evidence_ref": "findings.md",
            "notes": "",
            "source_name": "vulnerability-analyst",
            "details": {"evidence": "A"},
            "provenance": {
                "agent_id": "AUTHOR-VA-001",
                "agent_name": "vulnerability-analyst",
            },
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
                    "file_hash": _source_hash("shared-a"),
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
                    "file_hash": _source_hash("shared-b"),
                    "header_snippet": "",
                    "git_churn_score": 0,
                    "has_past_cve_fix": False,
                },
        ],
    )
    assert shared_files_b[0]["file_path"] == "src/shared.py"

    _create_root_finding(client, engagement_key, "CH-090")
    _ensure_finding_author_dispatch(client, engagement_key, "AUTHOR-CH-001")
    finding = client.post(
        f"/engagements/{engagement_key}/assessment/findings",
        json={
            "slug": "CH-001",
            "title": "Shared path finding",
            "severity": "high",
            "workflow_status": "active",
            "verification_status": "unreviewed",
            "defect_family": "trust-boundary-bypass",
            "root_cause_key": "shared-path-finding",
            "auth_context": "anonymous",
            "canonical_location": "file:src/shared.py:12",
            "summary": "Ambiguous file-path findings should not be double-attributed across repos.",
            "evidence_ref": "findings.md",
            "notes": "",
            "source_name": "code-vuln-hunter",
            "details": {"evidence": "A"},
            "provenance": {
                "agent_id": "AUTHOR-CH-001",
                "agent_name": "code-vuln-hunter",
                "code_snapshot": _finding_code_snapshot(
                    client, engagement_key, int(repo_a["id"])
                ),
            },
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
    assert repo_a_payload["findings_summary"]["total_code_findings"] == 1
    assert repo_a_payload["findings_summary"]["variant_count"] == 1

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
    assert {item["file_path"] for item in scoped_files.json()["items"]} == {
        "src/parser.py",
        "src/helpers.py",
    }


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
            "agent_name": queue_item["agent_name"],
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


@pytest.mark.parametrize(
    "field_name",
    ["total_functions", "total_entry_points", "total_sinks", "total_exports"],
)
def test_file_patch_rejects_parser_owned_structural_metadata(
    client, isolate_settings, field_name
):
    engagement_key = f"2026-04-15-code-file-patch-structural-{field_name}"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key=f"patch-structural-{field_name}")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser_file = next(item for item in files if item["file_path"] == "src/parser.py")

    response = client.patch(
        f"/engagements/{engagement_key}/assessment/code/files/{parser_file['id']}",
        json={field_name: 3},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == (
        f"file patch does not accept fields: {field_name}"
    )
    persisted = client.get(
        f"/engagements/{engagement_key}/assessment/code/files/{parser_file['id']}"
    ).json()
    assert persisted[field_name] == 0


def test_bulk_structural_metadata_requires_all_totals(client, isolate_settings):
    engagement_key = "2026-04-15-code-bulk-structural-required"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="bulk-structural-required")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser_file = next(item for item in files if item["file_path"] == "src/parser.py")
    binding = client.get(
        f"/engagements/{engagement_key}/assessment/code/repos/{repo['id']}"
    ).json()

    response = client.post(
        f"/engagements/{engagement_key}/assessment/code/files/bulk-structural-metadata",
        json={
            "repo_id": repo["id"],
            "repo_generation": binding["active_generation"],
            "source_manifest_digest": binding["source_manifest_digest"],
            "structural_index_manifest_path": "tools/analysis-state/structural-index/manifest.json",
            "updates": [{
                "file_id": parser_file["id"],
                "source_sha256": parser_file["file_hash"],
                "total_functions": 3,
            }],
        },
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
    binding = client.get(
        f"/engagements/{engagement_key}/assessment/code/repos/{repo['id']}"
    ).json()

    response = client.post(
        f"/engagements/{engagement_key}/assessment/code/files/bulk-structural-metadata",
        json={
            "repo_id": repo["id"],
            "repo_generation": binding["active_generation"],
            "source_manifest_digest": binding["source_manifest_digest"],
            "structural_index_manifest_path": "tools/analysis-state/structural-index/manifest.json",
            "updates": [
                {
                    "file_id": parser_file["id"],
                    "source_sha256": parser_file["file_hash"],
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


def test_bulk_structural_metadata_rejects_conflicting_debt_contracts(
    client, isolate_settings
):
    engagement_key = "2026-08-04-code-structural-debt-validation"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="structural-debt-validation")
    files = _create_files(client, engagement_key, int(repo["id"]))
    base = f"/engagements/{engagement_key}/assessment/code"
    binding = client.get(f"{base}/repos/{repo['id']}").json()
    payload = _complete_structural_payload(
        repo_id=int(repo["id"]),
        repo_generation=int(binding["active_generation"]),
        source_manifest_digest=str(binding["source_manifest_digest"]),
        updates=[
            {
                "file_id": row["id"],
                "source_sha256": row["file_hash"],
                "total_functions": 1,
                "total_entry_points": 1,
                "total_sinks": 2,
                "total_exports": 0,
            }
            for row in files
        ],
    )

    complete_but_truncated = json.loads(json.dumps(payload))
    complete_but_truncated["updates"][0]["structural_artifact_truncated"] = True
    complete_but_truncated["updates"][0]["structural_truncated_dimensions"] = [
        "security_sinks"
    ]
    response = client.post(
        f"{base}/files/bulk-structural-metadata", json=complete_but_truncated
    )
    assert response.status_code == 422
    assert "complete" in response.text.lower() and "truncat" in response.text.lower()

    mismatched_signals = json.loads(json.dumps(payload))
    mismatched_signals["updates"][0]["structural_signal_counts"]["entry_points"] = 99
    response = client.post(f"{base}/files/bulk-structural-metadata", json=mismatched_signals)
    assert response.status_code == 422
    assert "entry_points" in response.text

    unavailable_value_overrides = {
        "functions": {"total_functions": 1},
        "exports": {"total_exports": 1},
        "entry_points": {"total_entry_points": 1},
        "imports": {"structural_signal_counts": {"imports": 1}},
        "security_sinks": {"total_sinks": 2},
        "security_sources": {"structural_signal_counts": {"security_sources": 1}},
    }
    for dimension, overrides in unavailable_value_overrides.items():
        unavailable_but_signaled = json.loads(json.dumps(payload))
        update = unavailable_but_signaled["updates"][0]
        signal_overrides = overrides.pop("structural_signal_counts", {})
        update.update(
            {
                "structural_analysis_status": "degraded",
                "structural_analysis_mode": "streaming_security_fallback",
                "structural_degradation_reason": "tree_sitter_resource_limit",
                "structural_unavailable_dimensions": [dimension],
                **overrides,
            }
        )
        update["structural_signal_counts"].update(signal_overrides)
        unavailable_but_signaled.update(
            {
                "degraded_files": 1,
                "degraded_file_paths": [str(files[0]["file_path"])],
                "analysis_status_counts": {
                    "complete": 1,
                    "degraded": 1,
                    "unsupported": 0,
                },
            }
        )
        response = client.post(
            f"{base}/files/bulk-structural-metadata", json=unavailable_but_signaled
        )
        assert response.status_code == 422, dimension
        assert "unavailable" in response.text.lower()

    incomplete_fallback_debt = json.loads(json.dumps(payload))
    incomplete_fallback_debt["updates"][0].update(
        {
            "total_functions": 0,
            "structural_analysis_status": "degraded",
            "structural_analysis_mode": "streaming_security_fallback",
            "structural_degradation_reason": "tree_sitter_resource_limit",
            "structural_unavailable_dimensions": ["functions"],
        }
    )
    incomplete_fallback_debt.update(
        {
            "degraded_files": 1,
            "degraded_file_paths": [str(files[0]["file_path"])],
            "analysis_status_counts": {
                "complete": 1,
                "degraded": 1,
                "unsupported": 0,
            },
        }
    )
    response = client.post(
        f"{base}/files/bulk-structural-metadata", json=incomplete_fallback_debt
    )
    assert response.status_code == 422
    assert "baseline" in response.text.lower()

    ambiguous_unsupported = json.loads(json.dumps(payload))
    ambiguous_unsupported["updates"][0].update(
        {
            "total_functions": 0,
            "total_entry_points": 0,
            "total_sinks": 0,
            "total_exports": 0,
            "structural_analysis_status": "unsupported",
            "structural_analysis_mode": "none",
            "structural_degradation_reason": None,
            "structural_bytes_scanned": 0,
            "structural_unavailable_dimensions": [],
            "structural_signal_counts": {
                "entry_points": 0,
                "imports": 0,
                "security_sinks": 0,
                "security_sources": 0,
            },
        }
    )
    ambiguous_unsupported["analysis_status_counts"] = {
        "complete": 1,
        "degraded": 0,
        "unsupported": 1,
    }
    response = client.post(
        f"{base}/files/bulk-structural-metadata", json=ambiguous_unsupported
    )
    assert response.status_code == 422
    assert "unsupported" in response.text.lower()

    signaled_unsupported = json.loads(json.dumps(payload))
    signaled_unsupported["updates"][0].update(
        {
            "structural_analysis_status": "unsupported",
            "structural_analysis_mode": "none",
            "structural_degradation_reason": "unsupported_language",
            "structural_unavailable_dimensions": [
                "call_sites",
                "classes",
                "dataflow",
                "entry_points",
                "exports",
                "functions",
                "imports",
                "security_sinks",
                "security_sources",
            ],
            "total_exports": 1,
            "structural_signal_counts": {
                "entry_points": 1,
                "imports": 1,
                "security_sinks": 2,
                "security_sources": 1,
            },
        }
    )
    signaled_unsupported["analysis_status_counts"] = {
        "complete": 1,
        "degraded": 0,
        "unsupported": 1,
    }
    response = client.post(
        f"{base}/files/bulk-structural-metadata", json=signaled_unsupported
    )
    assert response.status_code == 422
    assert "unsupported" in response.text.lower() and "zero" in response.text.lower()

    forged_aggregate = json.loads(json.dumps(payload))
    forged_aggregate["analysis_status_counts"] = {
        "complete": 1,
        "degraded": 0,
        "unsupported": 1,
    }
    response = client.post(f"{base}/files/bulk-structural-metadata", json=forged_aggregate)
    assert response.status_code == 400
    assert "aggregate debt metadata" in response.json()["detail"]


@pytest.mark.parametrize("analysis_mode", ["tree_sitter", "lightweight_regex"])
def test_bulk_structural_metadata_accepts_bounded_parser_signal_truncation(
    client, isolate_settings, analysis_mode
):
    engagement_key = f"2026-08-04-code-parser-truncation-{analysis_mode}"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(
        client,
        engagement_key,
        repo_key=f"parser-truncation-{analysis_mode}",
    )
    files = _create_files(client, engagement_key, int(repo["id"]))
    base = f"/engagements/{engagement_key}/assessment/code"
    binding = client.get(f"{base}/repos/{repo['id']}").json()
    payload = _complete_structural_payload(
        repo_id=int(repo["id"]),
        repo_generation=int(binding["active_generation"]),
        source_manifest_digest=str(binding["source_manifest_digest"]),
        updates=[
            {
                "file_id": row["id"],
                "source_sha256": row["file_hash"],
                "total_functions": 1,
                "total_entry_points": 1,
                "total_sinks": 2,
                "total_exports": 0,
            }
            for row in files
        ],
    )
    truncated = payload["updates"][0]
    truncated_path = files[0]["file_path"]
    truncated.update(
        {
            "structural_analysis_status": "degraded",
            "structural_analysis_mode": analysis_mode,
            "structural_degradation_reason": "artifact_signal_limit",
            "structural_unavailable_dimensions": [],
            "structural_artifact_truncated": True,
            "structural_truncated_dimensions": ["security_sinks"],
        }
    )
    payload.update(
        {
            "degraded_files": 1,
            "degraded_file_paths": [truncated_path],
            "artifact_truncated_files": 1,
            "artifact_truncated_file_paths": [truncated_path],
            "analysis_status_counts": {
                "complete": len(files) - 1,
                "degraded": 1,
                "unsupported": 0,
            },
        }
    )

    response = client.post(f"{base}/files/bulk-structural-metadata", json=payload)

    assert response.status_code == 200, response.text
    persisted = {
        row["id"]: row
        for row in client.get(f"{base}/files?repo_id={repo['id']}&limit=20").json()["items"]
    }[truncated["file_id"]]
    assert persisted["structural_analysis_status"] == "degraded"
    assert persisted["structural_analysis_mode"] == analysis_mode
    assert persisted["structural_degradation_reason"] == "artifact_signal_limit"
    assert persisted["structural_unavailable_dimensions"] == []
    assert persisted["structural_artifact_truncated"] is True
    assert persisted["structural_truncated_dimensions"] == ["security_sinks"]
    classify = client.get(f"{base}/readiness?target_phase=classify-map").json()
    assert classify["transition_ready"] is True
    assert any(
        "1 unreviewed admitted file(s)" in warning
        and "1 degraded, 0 unsupported, 1 truncated" in warning
        for warning in classify["quality_gate"]["warnings"]
    )
    verify_codes = {
        blocker["code"]
        for blocker in client.get(
            f"{base}/readiness?target_phase=verify-variant"
        ).json()["blockers"]
    }
    assert "structural_analysis_debt_unreviewed" in verify_codes


def test_unsupported_structural_metadata_is_explicit_review_debt(
    client, isolate_settings
):
    engagement_key = "2026-08-04-code-unsupported-structural-debt"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="unsupported-structural-debt")
    files = _create_files(client, engagement_key, int(repo["id"]))
    base = f"/engagements/{engagement_key}/assessment/code"
    binding = client.get(f"{base}/repos/{repo['id']}").json()
    payload = _complete_structural_payload(
        repo_id=int(repo["id"]),
        repo_generation=int(binding["active_generation"]),
        source_manifest_digest=str(binding["source_manifest_digest"]),
        updates=[
            {
                "file_id": row["id"],
                "source_sha256": row["file_hash"],
                "total_functions": 1,
                "total_entry_points": 1,
                "total_sinks": 2,
                "total_exports": 0,
            }
            for row in files
        ],
    )
    unsupported_path = str(files[0]["file_path"])
    unavailable = [
        "call_sites",
        "classes",
        "dataflow",
        "entry_points",
        "exports",
        "functions",
        "imports",
        "security_sinks",
        "security_sources",
    ]
    payload["updates"][0].update(
        {
            "total_functions": 0,
            "total_entry_points": 0,
            "total_sinks": 0,
            "total_exports": 0,
            "structural_analysis_status": "unsupported",
            "structural_analysis_mode": "none",
            "structural_degradation_reason": "unsupported_language",
            "structural_unavailable_dimensions": unavailable,
            "structural_signal_counts": {
                "entry_points": 0,
                "imports": 0,
                "security_sinks": 0,
                "security_sources": 0,
            },
        }
    )
    payload["analysis_status_counts"] = {
        "complete": 1,
        "degraded": 0,
        "unsupported": 1,
    }

    response = client.post(f"{base}/files/bulk-structural-metadata", json=payload)

    assert response.status_code == 200, response.text
    persisted = {
        row["id"]: row
        for row in client.get(f"{base}/files?repo_id={repo['id']}&limit=20").json()["items"]
    }[payload["updates"][0]["file_id"]]
    assert persisted["structural_analysis_status"] == "unsupported"
    assert persisted["structural_degradation_reason"] == "unsupported_language"
    assert persisted["structural_unavailable_dimensions"] == unavailable
    classify = client.get(f"{base}/readiness?target_phase=classify-map").json()
    assert classify["transition_ready"] is True
    assert any(
        "1 unreviewed admitted file(s)" in warning
        and "0 degraded, 1 unsupported, 0 truncated" in warning
        for warning in classify["quality_gate"]["warnings"]
    )
    verify = client.get(f"{base}/readiness?target_phase=verify-variant").json()
    debt = next(
        blocker
        for blocker in verify["blockers"]
        if blocker["code"] == "structural_analysis_debt_unreviewed"
    )
    assert unsupported_path in debt["message"]
    assert debt["overrideable"] is False


def test_structural_index_update_is_all_or_none_snapshot_cas(client, isolate_settings):
    engagement_key = "2026-08-04-code-structural-cas"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="structural-cas-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    base = f"/engagements/{engagement_key}/assessment/code"
    binding = client.get(f"{base}/repos/{repo['id']}").json()
    updates = [
        {
            "file_id": row["id"],
            "source_sha256": row["file_hash"],
            "total_functions": index + 3,
            "total_entry_points": 1,
            "total_sinks": 2,
            "total_exports": 0,
        }
        for index, row in enumerate(files)
    ]
    payload = _complete_structural_payload(
        repo_id=int(repo["id"]),
        repo_generation=int(binding["active_generation"]),
        source_manifest_digest=str(binding["source_manifest_digest"]),
        updates=updates,
    )
    legacy_contract = {**payload, "structural_index_schema": "structural-index/v4"}
    rejected_contract = client.post(
        f"{base}/files/bulk-structural-metadata", json=legacy_contract
    )
    assert rejected_contract.status_code == 409
    assert "schema" in rejected_contract.json()["detail"].lower()

    accepted = client.post(f"{base}/files/bulk-structural-metadata", json=payload)
    assert accepted.status_code == 200, accepted.text
    assert accepted.json() == {
        "repo_id": repo["id"],
        "repo_generation": binding["active_generation"],
        "source_manifest_digest": binding["source_manifest_digest"],
        "structural_index_schema": "structural-index/v6",
        "structural_input_digest": payload["structural_input_digest"],
        "structural_index_manifest_path": "tools/analysis-state/structural-index/manifest.json",
        "degraded_files": 0,
        "degraded_file_paths": [],
        "artifact_truncated_files": 0,
        "artifact_truncated_file_paths": [],
        "analysis_status_counts": {"complete": 2, "degraded": 0, "unsupported": 0},
        "updated": 2,
    }
    indexed = client.get(f"{base}/repos/{repo['id']}").json()
    assert indexed["structural_index_schema"] == "structural-index/v6"
    assert indexed["structural_index_generation"] == binding["active_generation"]
    assert indexed["structural_index_manifest_path"].endswith("manifest.json")

    stale = dict(payload)
    stale["updates"] = [dict(item) for item in payload["updates"]]
    stale["updates"][0]["total_functions"] = 999
    stale["updates"][1]["source_sha256"] = _source_hash("stale-source-hash")
    rejected = client.post(f"{base}/files/bulk-structural-metadata", json=stale)
    assert rejected.status_code == 409
    assert "source hash" in rejected.json()["detail"].lower()
    after = {
        row["id"]: row
        for row in client.get(f"{base}/files?repo_id={repo['id']}&limit=20").json()["items"]
    }
    assert after[updates[0]["file_id"]]["total_functions"] == updates[0]["total_functions"]

    stale_generation = {**payload, "repo_generation": int(binding["active_generation"]) - 1}
    rejected = client.post(
        f"{base}/files/bulk-structural-metadata", json=stale_generation
    )
    assert rejected.status_code == 409
    assert "generation" in rejected.json()["detail"].lower()

    manifest_fields = {
        "file_path", "language", "loc", "file_hash", "header_snippet",
        "git_churn_score", "has_past_cve_fix",
    }
    manifest = [{key: row[key] for key in manifest_fields} for row in files]
    manifest[0]["file_hash"] = _source_hash("changed-after-structural-index")
    _refresh_repo_files(client, engagement_key, int(repo["id"]), manifest)
    refreshed = client.get(f"{base}/repos/{repo['id']}").json()
    assert refreshed["active_generation"] == int(binding["active_generation"]) + 1
    assert refreshed["structural_index_schema"] == ""
    assert refreshed["structural_index_generation"] is None
    assert refreshed["structural_index_manifest_path"] == ""
    readiness = client.get(f"{base}/readiness?target_phase=classify-map").json()
    assert any(
        blocker["code"] == "structural_index_stale"
        and blocker["repo_id"] == repo["id"]
        for blocker in readiness["blockers"]
    )


def test_structural_publication_rejects_payload_from_prior_file_language_identity(
    client, isolate_settings
):
    engagement_key = "2026-08-05-code-structural-language-cas"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="structural-language-cas-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser = next(row for row in files if row["file_path"] == "src/parser.py")
    base = f"/engagements/{engagement_key}/assessment/code"
    changed_to_c = client.patch(f"{base}/files/{parser['id']}", json={"language": "c"})
    assert changed_to_c.status_code == 200, changed_to_c.text
    current_files = client.get(f"{base}/files?repo_id={repo['id']}&limit=20").json()["items"]
    binding = client.get(f"{base}/repos/{repo['id']}").json()
    updates = [
        {
            "file_id": row["id"],
            "source_sha256": row["file_hash"],
            "total_functions": 2,
            "total_entry_points": 1,
            "total_sinks": 1,
            "total_exports": 0,
        }
        for row in current_files
    ]
    c_payload = _complete_structural_payload(
        repo_id=int(repo["id"]),
        repo_generation=int(binding["active_generation"]),
        source_manifest_digest=str(binding["source_manifest_digest"]),
        updates=updates,
    )
    first = client.post(f"{base}/files/bulk-structural-metadata", json=c_payload)
    assert first.status_code == 200, first.text
    c_update = next(row for row in c_payload["updates"] if row["file_id"] == parser["id"])
    assert c_update["indexed_language"] == "c"

    corrected = client.patch(f"{base}/files/{parser['id']}", json={"language": "c++"})
    assert corrected.status_code == 200, corrected.text
    assert corrected.json()["language"] == "c++"
    invalidated = client.get(f"{base}/files?repo_id={repo['id']}&limit=20").json()["items"]
    assert {row["total_functions"] for row in invalidated} == {0}

    stale = client.post(f"{base}/files/bulk-structural-metadata", json=c_payload)

    assert stale.status_code == 409
    assert "language" in stale.json()["detail"].lower()
    still_invalidated = client.get(f"{base}/files?repo_id={repo['id']}&limit=20").json()["items"]
    assert {row["total_functions"] for row in still_invalidated} == {0}
    assert client.get(f"{base}/repos/{repo['id']}").json()[
        "structural_index_generation"
    ] is None

    cpp_payload = _complete_structural_payload(
        repo_id=int(repo["id"]),
        repo_generation=int(binding["active_generation"]),
        source_manifest_digest=str(binding["source_manifest_digest"]),
        updates=updates,
    )
    cpp_update = next(
        row for row in cpp_payload["updates"] if row["file_id"] == parser["id"]
    )
    assert cpp_update["indexed_language"] == "cpp"
    assert cpp_payload["structural_input_digest"] != c_payload["structural_input_digest"]
    accepted = client.post(f"{base}/files/bulk-structural-metadata", json=cpp_payload)
    assert accepted.status_code == 200, accepted.text


def test_structural_input_digest_matches_cli_known_vector():
    assert code_analysis.STRUCTURAL_INDEX_SCHEMA == CLI_STRUCTURAL_INDEX_SCHEMA
    assert code_analysis.STRUCTURAL_INDEX_SCHEMA == "structural-index/v6"
    source_manifest_digest = "ab" * 32
    files = [
        {
            "file_path": "src/a.cc",
            "file_hash": "22" * 32,
            "language": "c++",
        },
        {
            "file_path": "src/z.c",
            "file_hash": "11" * 32,
            "language": "c",
        },
    ]
    backend_digest = code_analysis.structural_input_identity_digest(
        repo_id=17,
        repo_generation=3,
        source_manifest_digest_value=source_manifest_digest,
        files=files,
    )
    cli_digest = cli_structural_input_digest(
        {
            "src/a.cc": {
                "source_sha256": "22" * 32,
                "language": "cpp",
            },
            "src/z.c": {
                "source_sha256": "11" * 32,
                "language": "c",
            },
        },
        repo_id=17,
        repo_generation=3,
        source_manifest_digest=source_manifest_digest,
    )
    assert backend_digest == cli_digest
    assert backend_digest == "ddb3ff3e88c77b435174036a8012a2d64fa42fc04b66b7355a8ca4b5a13e1a06"


def test_threat_model_binding_becomes_stale_without_destroying_artifact(client, isolate_settings):
    engagement_key = "2026-08-04-code-threat-binding"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="threat-binding-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    base = f"/engagements/{engagement_key}/assessment/code"
    binding = client.get(f"{base}/repos/{repo['id']}").json()
    payload = {
        "repo_id": repo["id"],
        "repo_generation": binding["active_generation"],
        "source_manifest_digest": binding["source_manifest_digest"],
        "threat_model": {"targets": ["parser"], "trust_boundaries": ["network"]},
    }
    recorded = client.post(f"{base}/threat-model", json=payload)
    assert recorded.status_code == 200, recorded.text
    assert recorded.json()["threat_model_generation"] == binding["active_generation"]
    current = client.get(f"{base}/threat-model/{repo['id']}")
    assert current.status_code == 200, current.text
    assert current.json() == {
        "repo_id": repo["id"],
        "repo_generation": binding["active_generation"],
        "active_generation": binding["active_generation"],
        "source_manifest_digest": binding["source_manifest_digest"],
        "current": True,
        "threat_model": payload["threat_model"],
    }

    manifest_fields = {
        "file_path", "language", "loc", "file_hash", "header_snippet",
        "git_churn_score", "has_past_cve_fix",
    }
    manifest = [{key: row[key] for key in manifest_fields} for row in files]
    manifest[0]["file_hash"] = _source_hash("changed-after-threat-model")
    _refresh_repo_files(client, engagement_key, int(repo["id"]), manifest)

    stale = client.get(f"{base}/threat-model/{repo['id']}").json()
    assert stale["current"] is False
    assert stale["repo_generation"] == binding["active_generation"]
    assert stale["active_generation"] == int(binding["active_generation"]) + 1
    assert stale["threat_model"] == payload["threat_model"]
    rejected = client.post(f"{base}/threat-model", json=payload)
    assert rejected.status_code == 409
    assert "generation" in rejected.json()["detail"].lower()


def test_readiness_separates_snapshot_lifecycle_blockers_from_quality_warnings(
    client, isolate_settings
):
    engagement_key = "2026-08-04-code-readiness"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="readiness-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    base = f"/engagements/{engagement_key}/assessment/code"
    binding = client.get(f"{base}/repos/{repo['id']}").json()

    classify_map = client.get(f"{base}/readiness?target_phase=classify-map")
    assert classify_map.status_code == 200, classify_map.text
    payload = classify_map.json()
    assert payload["target_phase"] == "classify-map"
    assert payload["transition_ready"] is False
    assert payload["quality_gate"] == {"passed": True, "warnings": []}
    assert payload["blockers"] == [
        {
            "code": "structural_index_stale",
            "message": "Structural index is not bound to the current repository snapshot.",
            "overrideable": False,
            "repo_id": repo["id"],
        }
    ]

    indexed = client.post(
        f"{base}/files/bulk-structural-metadata",
        json=_complete_structural_payload(
            repo_id=int(repo["id"]),
            repo_generation=int(binding["active_generation"]),
            source_manifest_digest=str(binding["source_manifest_digest"]),
            updates=[
                {
                    "file_id": row["id"],
                    "source_sha256": row["file_hash"],
                    "total_functions": 1,
                    "total_entry_points": 1,
                    "total_sinks": 0,
                    "total_exports": 0,
                }
                for row in files
            ],
        ),
    )
    assert indexed.status_code == 200, indexed.text
    assert client.get(
        f"{base}/readiness?target_phase=classify-map"
    ).json()["transition_ready"] is True

    hunt = client.get(f"{base}/readiness?target_phase=hunt").json()
    assert hunt["transition_ready"] is False
    assert {item["code"] for item in hunt["blockers"]} == {
        "threat_model_stale",
        "files_unclassified",
    }
    assert {
        item["code"]: item["overrideable"] for item in hunt["blockers"]
    } == {
        "threat_model_stale": False,
        "files_unclassified": True,
    }

    threat = client.post(
        f"{base}/threat-model",
        json={
            "repo_id": repo["id"],
            "repo_generation": binding["active_generation"],
            "source_manifest_digest": binding["source_manifest_digest"],
            "threat_model": {"trust_boundaries": ["network"]},
        },
    )
    assert threat.status_code == 200, threat.text
    for row in files:
        _classify_file(client, engagement_key, int(row["id"]), "low", 10)
    ready = client.get(f"{base}/readiness?target_phase=hunt").json()
    assert ready["transition_ready"] is True
    assert ready["blockers"] == []


def test_verify_readiness_requires_every_file_accounted_but_skip_is_not_semantic_review(
    client, isolate_settings
):
    engagement_key = "2026-08-05-code-readiness-all-files"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="readiness-all-files-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser = next(row for row in files if row["file_path"] == "src/parser.py")
    helper = next(row for row in files if row["file_path"] == "src/helpers.py")
    base = f"/engagements/{engagement_key}/assessment/code"
    binding = client.get(f"{base}/repos/{repo['id']}").json()
    assert client.post(
        f"{base}/files/bulk-structural-metadata",
        json=_complete_structural_payload(
            repo_id=int(repo["id"]),
            repo_generation=int(binding["active_generation"]),
            source_manifest_digest=str(binding["source_manifest_digest"]),
            updates=[
                {
                    "file_id": row["id"],
                    "source_sha256": row["file_hash"],
                    "total_functions": 0,
                    "total_entry_points": 0,
                    "total_sinks": 0,
                    "total_exports": 0,
                }
                for row in files
            ],
        ),
    ).status_code == 200
    assert client.post(
        f"{base}/threat-model",
        json={
            "repo_id": repo["id"],
            "repo_generation": binding["active_generation"],
            "source_manifest_digest": binding["source_manifest_digest"],
            "threat_model": {"trust_boundaries": ["network"]},
        },
    ).status_code == 200
    _classify_file(client, engagement_key, int(parser["id"]), "high", 79)
    _classify_file(client, engagement_key, int(helper["id"]), "low", 10)
    with db_module.get_connection() as connection:
        connection.execute(
            """
            INSERT INTO code_analysis_queue (
                engagement_id, file_id, status, disposition, repo_generation
            )
            VALUES (
                (SELECT id FROM engagements WHERE key = ?), ?, 'done', 'clean', ?
            )
            """,
            (engagement_key, helper["id"], binding["active_generation"]),
        )

    before = client.get(f"{base}/readiness?target_phase=verify-variant").json()
    unaccounted = next(
        blocker
        for blocker in before["blockers"]
        if blocker["code"] == "admitted_files_unaccounted"
    )
    assert "2 admitted file(s)" in unaccounted["message"]
    coverage = client.get(f"{base}/coverage?repo_id={repo['id']}").json()
    assert coverage["by_classification"]["low"]["analyzed"] == 0

    for file_row in (parser, helper):
        if int(file_row["id"]) == int(helper["id"]):
            claim = _claim_file_for_reanalysis(
                client,
                engagement_key,
                int(file_row["id"]),
                reason="Replace an incomplete legacy terminal receipt",
            )
        else:
            claim = _claim_file_for_analysis(
                client, engagement_key, int(file_row["id"])
            )
        skipped = client.post(
            f"{base}/analysis-queue/done",
            json=_owned(
                claim,
                item_ids=[claim["id"]],
                disposition="skipped",
                skip_reason="generated-code",
            ),
        )
        assert skipped.status_code == 200, skipped.text

    after = client.get(f"{base}/readiness?target_phase=verify-variant").json()
    after_codes = {blocker["code"] for blocker in after["blockers"]}
    assert "admitted_files_unaccounted" not in after_codes
    assert "critical_high_incomplete" in after_codes


def test_coverage_skip_reasons_come_from_current_terminal_queue_receipts(
    client, isolate_settings
):
    engagement_key = "2026-08-05-code-coverage-skip-receipts"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="coverage-skip-receipts-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    helper = next(row for row in files if row["file_path"] == "src/helpers.py")
    base = f"/engagements/{engagement_key}/assessment/code"
    _classify_file(client, engagement_key, int(helper["id"]), "low", 10)
    claim = _claim_file_for_analysis(client, engagement_key, int(helper["id"]))
    skipped = client.post(
        f"{base}/analysis-queue/done",
        json=_owned(
            claim,
            item_ids=[claim["id"]],
            disposition="skipped",
            skip_reason="generated-code",
        ),
    )
    assert skipped.status_code == 200, skipped.text

    coverage = client.get(f"{base}/coverage?repo_id={repo['id']}")

    assert coverage.status_code == 200, coverage.text
    assert coverage.json()["confidence"]["skip_reasons"] == {"generated-code": 1}

    queued = client.post(
        f"{base}/analysis-queue",
        json={
            "mode": "reanalysis",
            "reason": "Re-open skipped file for an independent review",
            "items": [
                {"file_id": helper["id"], "priority": 10, "supersedes": claim["id"]}
            ],
        },
    )
    assert queued.status_code == 201, queued.text
    assert queued.json()["reanalysis"] == 1
    assert client.get(f"{base}/coverage?repo_id={repo['id']}").json()[
        "confidence"
    ]["skip_reasons"] == {}
    db_path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    with sqlite3.connect(str(db_path)) as connection:
        replacement_id, replacement_generation, active_generation = connection.execute(
            """
            SELECT queue.id, queue.repo_generation, repos.active_generation
            FROM code_analysis_queue AS queue
            JOIN code_files AS files ON files.id = queue.file_id
            JOIN code_repos AS repos ON repos.id = files.repo_id
            WHERE queue.file_id = ? ORDER BY queue.id DESC LIMIT 1
            """,
            (helper["id"],),
        ).fetchone()
    assert replacement_generation == active_generation
    replacement_claim = client.post(
        f"{base}/analysis-queue/fetch",
        json={
            "limit": 1,
            "agent_name": "replacement-agent",
            "item_ids": [replacement_id],
        },
    ).json()[0]
    replacement = client.post(
        f"{base}/analysis-queue/done",
        json=_owned(
            replacement_claim,
            item_ids=[replacement_claim["id"]],
            disposition="skipped",
            skip_reason="test-fixture",
        ),
    )
    assert replacement.status_code == 200, replacement.text
    replaced_coverage = client.get(f"{base}/coverage?repo_id={repo['id']}").json()
    assert replaced_coverage["confidence"]["skip_reasons"] == {"test-fixture": 1}

    final_queue = client.post(
        f"{base}/analysis-queue",
        json={
            "mode": "reanalysis",
            "reason": "Run a third independent review",
            "items": [
                {
                    "file_id": helper["id"],
                    "priority": 10,
                    "supersedes": replacement_claim["id"],
                }
            ],
        },
    )
    assert final_queue.status_code == 201, final_queue.text
    assert final_queue.json()["reanalysis"] == 1
    assert client.get(f"{base}/coverage?repo_id={repo['id']}").json()[
        "confidence"
    ]["skip_reasons"] == {}
    with sqlite3.connect(str(db_path)) as connection:
        final_id = connection.execute(
            "SELECT MAX(id) FROM code_analysis_queue WHERE file_id = ?",
            (helper["id"],),
        ).fetchone()[0]
    final_claim = client.post(
        f"{base}/analysis-queue/fetch",
        json={"limit": 1, "agent_name": "final-agent", "item_ids": [final_id]},
    ).json()[0]
    final = client.post(
        f"{base}/analysis-queue/done",
        json=_owned(
            final_claim,
            item_ids=[final_claim["id"]],
            disposition="clean",
            notes="Latest attempt completed with a clean source review.",
                cwe_coverage=[
                    {
                        "family": "error-handling",
                        "effort": 20,
                        "notes": "Reviewed helper error paths.",
                    },
                    {
                        "family": "algorithmic-dos",
                        "effort": 20,
                        "notes": "Reviewed helper complexity and resource bounds.",
                    },
                ],
        ),
    )
    assert final.status_code == 200, final.text
    assert client.get(f"{base}/coverage?repo_id={repo['id']}").json()[
        "confidence"
    ]["skip_reasons"] == {}


@pytest.mark.parametrize(
    "legacy_coverage",
    ["[ ]", "{malformed", "[{}]", "[null]", '["x"]', "{}", "null", '"x"'],
)
def test_semantic_review_proof_rejects_noncanonical_or_malformed_coverage_json(
    client, isolate_settings, legacy_coverage
):
    engagement_key = "2026-08-05-code-review-json-" + hashlib.sha256(
        legacy_coverage.encode("utf-8")
    ).hexdigest()[:8]
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key=f"{engagement_key}-repo")
    parser = next(
        row for row in _create_files(client, engagement_key, int(repo["id"]))
        if row["file_path"] == "src/parser.py"
    )
    _classify_file(client, engagement_key, int(parser["id"]), "high", 79)
    base = f"/engagements/{engagement_key}/assessment/code"
    binding = client.get(f"{base}/repos/{repo['id']}").json()
    with db_module.get_connection() as connection:
        connection.execute(
            """
            INSERT INTO code_analysis_queue (
                engagement_id, file_id, status, disposition, analysis_notes,
                cwe_coverage_json, repo_generation
            ) VALUES (
                (SELECT id FROM engagements WHERE key = ?), ?, 'done', 'clean',
                'legacy forged review', ?, ?
            )
            """,
            (
                engagement_key,
                parser["id"],
                legacy_coverage,
                binding["active_generation"],
            ),
        )

    coverage = client.get(f"{base}/coverage?repo_id={repo['id']}").json()
    readiness = client.get(f"{base}/readiness?target_phase=verify-variant").json()

    assert coverage["by_classification"]["high"]["analyzed"] == 0
    assert "admitted_files_unaccounted" in {
        blocker["code"] for blocker in readiness["blockers"]
    }


def test_readiness_rejects_current_generation_and_path_without_current_index_schema(
    client, isolate_settings
):
    engagement_key = "2026-08-04-code-structural-metadata-incomplete"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="structural-metadata-incomplete")
    _create_files(client, engagement_key, int(repo["id"]))
    base = f"/engagements/{engagement_key}/assessment/code"
    binding = client.get(f"{base}/repos/{repo['id']}").json()
    with db_module.get_connection() as connection:
        connection.execute(
            """
            UPDATE code_repos
            SET structural_index_generation = ?, structural_index_manifest_path = ?
            WHERE id = ?
            """,
            (
                binding["active_generation"],
                "tools/analysis-state/legacy-current-index/manifest.json",
                repo["id"],
            ),
        )

    legacy = client.get(f"{base}/repos/{repo['id']}").json()
    readiness = client.get(f"{base}/readiness?target_phase=classify-map")

    assert readiness.status_code == 200, readiness.text
    assert legacy["structural_index_schema"] == ""
    blocker = next(
        item
        for item in readiness.json()["blockers"]
        if item["code"] == "structural_index_stale"
    )
    assert blocker["repo_id"] == repo["id"]
    assert blocker["overrideable"] is False
    assert "current repository snapshot" in blocker["message"].lower()


def test_degraded_structural_metadata_is_durable_and_requires_manual_review(
    client, isolate_settings
):
    engagement_key = "2026-08-04-code-structural-debt"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="structural-debt-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    base = f"/engagements/{engagement_key}/assessment/code"
    binding = client.get(f"{base}/repos/{repo['id']}").json()
    parser = next(row for row in files if row["file_path"] == "src/parser.py")
    helper = next(row for row in files if row["file_path"] == "src/helpers.py")
    unavailable = ["call_sites", "classes", "dataflow", "exports", "functions"]

    published = client.post(
        f"{base}/files/bulk-structural-metadata",
        json=_bind_structural_identity({
            "repo_id": repo["id"],
            "repo_generation": binding["active_generation"],
            "source_manifest_digest": binding["source_manifest_digest"],
            "structural_index_manifest_path": (
                "tools/analysis-state/structural-index/manifest.json"
            ),
            "degraded_files": 1,
            "degraded_file_paths": ["src/helpers.py"],
            "artifact_truncated_files": 0,
            "artifact_truncated_file_paths": [],
            "analysis_status_counts": {
                "complete": 1,
                "degraded": 1,
                "unsupported": 0,
            },
            "updates": [
                {
                    "file_id": parser["id"],
                    "source_sha256": parser["file_hash"],
                    "total_functions": 3,
                    "total_entry_points": 1,
                    "total_sinks": 2,
                    "total_exports": 0,
                    "structural_analysis_status": "complete",
                    "structural_analysis_mode": "tree_sitter",
                    "structural_degradation_reason": None,
                    "structural_source_size": 2048,
                    "structural_bytes_scanned": 2048,
                    "structural_unavailable_dimensions": [],
                    "structural_artifact_truncated": False,
                    "structural_truncated_dimensions": [],
                    "structural_signal_counts": {
                        "entry_points": 1,
                        "imports": 0,
                        "security_sinks": 2,
                        "security_sources": 0,
                    },
                },
                {
                    "file_id": helper["id"],
                    "source_sha256": helper["file_hash"],
                    "total_functions": 0,
                    "total_entry_points": 1,
                    "total_sinks": 4,
                    "total_exports": 0,
                    "structural_analysis_status": "degraded",
                    "structural_analysis_mode": "streaming_security_fallback",
                    "structural_degradation_reason": "tree_sitter_resource_limit",
                    "structural_source_size": 9 * 1024 * 1024,
                    "structural_bytes_scanned": 9 * 1024 * 1024,
                    "structural_unavailable_dimensions": unavailable,
                    "structural_artifact_truncated": False,
                    "structural_truncated_dimensions": [],
                    "structural_signal_counts": {
                        "entry_points": 1,
                        "imports": 2,
                        "security_sinks": 4,
                        "security_sources": 3,
                    },
                },
            ],
        }),
    )
    assert published.status_code == 200, published.text
    assert published.json()["degraded_files"] == 1

    persisted_repo = client.get(f"{base}/repos/{repo['id']}").json()
    assert persisted_repo["structural_index_schema"] == "structural-index/v6"
    assert persisted_repo["structural_degraded_files"] == 1
    assert persisted_repo["structural_degraded_file_paths"] == ["src/helpers.py"]
    assert persisted_repo["structural_analysis_status_counts"] == {
        "complete": 1,
        "degraded": 1,
        "unsupported": 0,
    }
    persisted_files = {
        row["id"]: row
        for row in client.get(f"{base}/files?repo_id={repo['id']}&limit=20").json()["items"]
    }
    degraded = persisted_files[helper["id"]]
    assert degraded["structural_analysis_status"] == "degraded"
    assert degraded["structural_analysis_mode"] == "streaming_security_fallback"
    assert degraded["structural_degradation_reason"] == "tree_sitter_resource_limit"
    assert degraded["structural_bytes_scanned"] == degraded["structural_source_size"]
    assert degraded["structural_unavailable_dimensions"] == unavailable
    assert degraded["structural_signal_counts"]["security_sources"] == 3

    classify = client.get(f"{base}/readiness?target_phase=classify-map").json()
    assert "structural_analysis_debt_unreviewed" not in {
        blocker["code"] for blocker in classify["blockers"]
    }
    assert classify["transition_ready"] is True
    assert classify["quality_gate"]["passed"] is False
    assert any(
        "1 unreviewed admitted file(s)" in warning
        and "1 degraded, 0 unsupported, 0 truncated" in warning
        for warning in classify["quality_gate"]["warnings"]
    )
    hunt = client.get(f"{base}/readiness?target_phase=hunt").json()
    assert "structural_analysis_debt_unreviewed" not in {
        blocker["code"] for blocker in hunt["blockers"]
    }
    assert hunt["quality_gate"]["passed"] is False
    assert any(
        "1 unreviewed admitted file(s)" in warning
        and "1 degraded, 0 unsupported, 0 truncated" in warning
        for warning in hunt["quality_gate"]["warnings"]
    )
    verify = client.get(f"{base}/readiness?target_phase=verify-variant").json()
    debt = next(
        blocker
        for blocker in verify["blockers"]
        if blocker["code"] == "structural_analysis_debt_unreviewed"
    )
    assert debt["repo_id"] == repo["id"]
    assert debt["overrideable"] is False
    assert "src/helpers.py" in debt["message"]

    with db_module.get_connection() as connection:
        connection.execute(
            "UPDATE code_files SET analysis_status = 'analyzed' WHERE id = ?",
            (helper["id"],),
        )
    forged_review = client.get(f"{base}/readiness?target_phase=verify-variant").json()
    assert "structural_analysis_debt_unreviewed" in {
        blocker["code"] for blocker in forged_review["blockers"]
    }

    _classify_file(client, engagement_key, int(helper["id"]), "low", 10)
    skipped_claim = _claim_file_for_analysis(client, engagement_key, int(helper["id"]))
    skipped = client.post(
        f"{base}/analysis-queue/done",
        json=_owned(
            skipped_claim,
            item_ids=[skipped_claim["id"]],
            disposition="skipped",
            skip_reason="generated-code",
        ),
    )
    assert skipped.status_code == 200, skipped.text
    after_skip = client.get(f"{base}/readiness?target_phase=verify-variant").json()
    assert "structural_analysis_debt_unreviewed" in {
        blocker["code"] for blocker in after_skip["blockers"]
    }

    claim = _claim_file_for_reanalysis(
        client,
        engagement_key,
        int(helper["id"]),
        reason="Complete the mandatory manual review after the documented skip.",
    )
    result = client.post(
        f"{base}/analysis-results",
        json=_owned(
            claim,
            queue_item_id=claim["id"],
            disposition="clean",
            evidence="Reviewed every sealed source byte after structural parser degradation.",
        ),
    )
    assert result.status_code == 201, result.text
    reviewed = client.post(
        f"{base}/analysis-queue/done",
        json=_owned(
            claim,
            item_ids=[claim["id"]],
            disposition="clean",
            notes="Manual sealed-source review completed.",
                cwe_coverage=[
                    {"family": "manual-structural-review", "effort": 100},
                    {"family": "algorithmic-dos", "effort": 80},
                    {"family": "error-handling", "effort": 80},
                ],
        ),
    )
    assert reviewed.status_code == 200, reviewed.text
    after_review = client.get(f"{base}/readiness?target_phase=verify-variant").json()
    assert "structural_analysis_debt_unreviewed" not in {
        blocker["code"] for blocker in after_review["blockers"]
    }
    reviewed_hunt = client.get(f"{base}/readiness?target_phase=hunt").json()
    assert not any(
        "structural coverage debt" in warning.lower()
        for warning in reviewed_hunt["quality_gate"]["warnings"]
    )

    manifest_fields = {
        "file_path",
        "language",
        "loc",
        "file_hash",
        "header_snippet",
        "git_churn_score",
        "has_past_cve_fix",
    }
    changed_manifest = [{key: row[key] for key in manifest_fields} for row in files]
    changed_manifest[0]["file_hash"] = _source_hash(
        "structural-debt-reviewed-source-change"
    )
    next_snapshot = _verified_repo_payload(
        client,
        engagement_key,
        "structural-debt-repo",
        changed_manifest,
        source_origin_path="/tmp/structural-debt-repo-next",
    )
    started = client.post(f"{base}/repos/refresh/start", json=next_snapshot)
    assert started.status_code == 201, started.text
    token = started.json()["refresh_token"]
    assert client.post(
        f"{base}/repos/{repo['id']}/refresh/files",
        json={"refresh_token": token, "files": changed_manifest},
    ).status_code == 200
    committed = client.post(
        f"{base}/repos/{repo['id']}/refresh/commit",
        json={"refresh_token": token, "manifest_complete": True},
    )
    assert committed.status_code == 200, committed.text
    assert committed.json()["generation_changed"] is True

    reset_repo = client.get(f"{base}/repos/{repo['id']}").json()
    assert reset_repo["structural_index_schema"] == ""
    assert reset_repo["structural_degraded_files"] == 0
    assert reset_repo["structural_degraded_file_paths"] == []
    assert reset_repo["structural_artifact_truncated_files"] == 0
    assert reset_repo["structural_artifact_truncated_file_paths"] == []
    assert reset_repo["structural_analysis_status_counts"] == {}
    reset_files = client.get(f"{base}/files?repo_id={repo['id']}&limit=20").json()["items"]
    assert {row["structural_analysis_status"] for row in reset_files} == {"pending"}
    assert all(row["structural_unavailable_dimensions"] == [] for row in reset_files)
    assert all(row["structural_signal_counts"] == {} for row in reset_files)


def test_variant_receipt_is_dispatch_bound_current_and_idempotent(
    client, isolate_settings
):
    engagement_key = "2026-08-05-code-variant-receipt-current"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="variant-receipt-current")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser = next(row for row in files if row["file_path"] == "src/parser.py")
    helper = next(row for row in files if row["file_path"] == "src/helpers.py")
    _classify_file(client, engagement_key, int(parser["id"]), "medium", 49)
    _create_code_parent_finding(
        client,
        engagement_key,
        int(repo["id"]),
        slug="VR-101",
    )
    _verify_code_finding(client, engagement_key, int(repo["id"]), "VR-101")
    base = f"/engagements/{engagement_key}/assessment/code"
    dispatch = _register_variant_dispatch(
        client,
        engagement_key,
        agent_id="variant-current",
        finding_slugs=["VR-101"],
    )
    payload = _variant_receipt_payload(
        client,
        engagement_key,
        int(repo["id"]),
        parser,
        dispatch,
        parent_finding_slugs=["VR-101"],
    )
    db_path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    with sqlite3.connect(str(db_path)) as connection:
        connection.execute(
            "UPDATE code_files SET variant_check_status = 'done' WHERE id = ?",
            (parser["id"],),
        )
        connection.commit()
    before = client.get(f"{base}/readiness?target_phase=fuzz").json()
    assert "variant_checks_incomplete" in {
        blocker["code"] for blocker in before["blockers"]
    }
    assert client.get(f"{base}/files/{parser['id']}").json()[
        "variant_check_status"
    ] == "pending"
    patched_projection = client.patch(
        f"{base}/files/{parser['id']}",
        json={"notes": "Non-identity metadata must not expose forged receipt state."},
    )
    assert patched_projection.status_code == 200, patched_projection.text
    assert patched_projection.json()["variant_check_status"] == "pending"

    first = client.post(f"{base}/variant-checks", json=payload)
    assert first.status_code == 201, first.text
    assert first.json()["current"] is True
    assert first.json()["parent_finding_slugs"] == ["VR-101"]
    assert first.json()["file_path"] == parser["file_path"]
    replay = client.post(f"{base}/variant-checks", json=payload)
    assert replay.status_code == 201, replay.text
    assert replay.json()["id"] == first.json()["id"]
    assert replay.json()["current"] is True
    current = client.get(f"{base}/variant-checks?file_id={parser['id']}").json()
    assert [row["id"] for row in current] == [first.json()["id"]]
    assert client.get(f"{base}/files/{parser['id']}").json()[
        "variant_check_status"
    ] == "done"
    after_parser = client.get(f"{base}/readiness?target_phase=fuzz").json()
    assert "variant_checks_incomplete" in {
        blocker["code"] for blocker in after_parser["blockers"]
    }
    helper_receipt = client.post(
        f"{base}/variant-checks",
        json=_variant_receipt_payload(
            client,
            engagement_key,
            int(repo["id"]),
            helper,
            dispatch,
            parent_finding_slugs=["VR-101"],
        ),
    )
    assert helper_receipt.status_code == 201, helper_receipt.text
    after = client.get(f"{base}/readiness?target_phase=fuzz").json()
    assert "variant_checks_incomplete" not in {
        blocker["code"] for blocker in after["blockers"]
    }


def test_variant_readiness_is_not_applicable_until_a_current_phase2_root_exists(
    client, isolate_settings
):
    engagement_key = "2026-08-06-code-variant-no-parent"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="variant-no-parent")
    files = _create_files(client, engagement_key, int(repo["id"]))
    base = f"/engagements/{engagement_key}/assessment/code"

    without_parent = client.get(f"{base}/readiness?target_phase=complete")

    assert without_parent.status_code == 200, without_parent.text
    assert "variant_checks_incomplete" not in {
        blocker["code"] for blocker in without_parent.json()["blockers"]
    }
    empty_dispatch = client.post(
        f"/engagements/{engagement_key}/assessment/dispatches",
        json={
            "agent_id": "variant-empty-scope",
            "agent_role": "code-variant-hunter",
            "task": "This dispatch must not exist without a parent finding.",
            "status": "in-progress",
            "dispatch_mode": "hypothesis-driven",
            "finding_slugs": [],
            "skills": "code-variant-analysis",
        },
    )
    assert empty_dispatch.status_code == 400, empty_dispatch.text
    unscoped_dispatches = []
    for agent_id, finding_field in (
        ("variant-cve-shape-omitted", "omitted"),
        ("variant-cve-shape-null", None),
    ):
        dispatch_payload = {
            "agent_id": agent_id,
            "agent_role": "code-variant-hunter",
            "task": "Search Phase 2 CVE bug-shape intelligence without receipt authority.",
            "status": "in-progress",
            "dispatch_mode": "wide",
            "skills": "code-variant-analysis",
        }
        if finding_field != "omitted":
            dispatch_payload["finding_slugs"] = finding_field
        response = client.post(
            f"/engagements/{engagement_key}/assessment/dispatches",
            json=dispatch_payload,
        )
        assert response.status_code == 201, response.text
        assert response.json()["finding_slugs"] is None
        unscoped_dispatches.append(response.json())
    with db_module.get_connection() as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM code_variant_dispatch_scopes WHERE dispatch_id IN (?, ?)",
            tuple(row["id"] for row in unscoped_dispatches),
        ).fetchone()[0] == 0
    empty_receipt = client.post(
        f"{base}/variant-checks",
        json=_variant_receipt_payload(
            client,
            engagement_key,
            int(repo["id"]),
            files[0],
            {"id": 999_999},
            parent_finding_slugs=[],
        ),
    )
    assert empty_receipt.status_code == 400, empty_receipt.text
    assert client.get(f"{base}/variant-checks").json() == []

    _create_code_parent_finding(
        client,
        engagement_key,
        int(repo["id"]),
        slug="WF-001",
    )
    unscoped_receipt = client.post(
        f"{base}/variant-checks",
        json=_variant_receipt_payload(
            client,
            engagement_key,
            int(repo["id"]),
            files[0],
            unscoped_dispatches[0],
            parent_finding_slugs=["WF-001"],
        ),
    )
    assert unscoped_receipt.status_code == 409, unscoped_receipt.text
    assert "immutable start-time scope" in unscoped_receipt.json()["detail"]
    with_unverified_parent = client.get(f"{base}/readiness?target_phase=complete")
    assert with_unverified_parent.status_code == 200, with_unverified_parent.text
    unverified_codes = {
        item["code"] for item in with_unverified_parent.json()["blockers"]
    }
    assert "variant_checks_incomplete" in unverified_codes
    assert "variant_parent_verification_incomplete" in unverified_codes

    _verify_code_finding(client, engagement_key, int(repo["id"]), "WF-001")
    with_parent = client.get(f"{base}/readiness?target_phase=complete")
    assert with_parent.status_code == 200, with_parent.text
    blocker = next(
        item
        for item in with_parent.json()["blockers"]
        if item["code"] == "variant_checks_incomplete"
    )
    assert blocker == {
        "code": "variant_checks_incomplete",
        "message": (
            f"Repository has {len(files)} incomplete admitted-file variant check(s)."
        ),
        "overrideable": True,
        "repo_id": repo["id"],
    }


def test_variant_dispatch_scope_is_exact_current_phase2_root_set_and_excludes_children(
    client, isolate_settings
):
    engagement_key = "2026-08-07-code-variant-exact-phase2-scope"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="variant-exact-phase2-scope")
    _create_files(client, engagement_key, int(repo["id"]))
    _create_code_parent_finding(
        client, engagement_key, int(repo["id"]), slug="EX-001"
    )
    _create_code_parent_finding(
        client,
        engagement_key,
        int(repo["id"]),
        slug="EX-002",
        line=20,
        allow_remint=True,
    )
    _create_code_parent_finding(
        client,
        engagement_key,
        int(repo["id"]),
        slug="CV-901",
        source_name="code-variant-hunter",
        line=30,
        allow_remint=True,
        links=[
            {
                "link_kind": "variant_of",
                "target_kind": "finding",
                "target_ref": "EX-001",
            }
        ],
    )
    endpoint = f"/engagements/{engagement_key}/assessment/dispatches"

    def start(agent_id: str, finding_slugs: list[str]):
        return client.post(
            endpoint,
            json={
                "agent_id": agent_id,
                "agent_role": "code-variant-hunter",
                "task": "Scan the exact frozen Phase 2 root set.",
                "status": "in-progress",
                "dispatch_mode": "hypothesis-driven",
                "finding_slugs": finding_slugs,
                "skills": "code-variant-analysis",
            },
        )

    omitted = start("variant-scope-omitted-root", ["EX-001"])
    assert omitted.status_code == 409, omitted.text
    assert "exact current Phase 2 root set" in omitted.json()["detail"]
    child_added = start(
        "variant-scope-child-added", ["CV-901", "EX-001", "EX-002"]
    )
    assert child_added.status_code == 409, child_added.text
    assert "exact current Phase 2 root set" in child_added.json()["detail"]

    accepted = start("variant-scope-exact", ["EX-001", "EX-002"])
    assert accepted.status_code == 201, accepted.text
    assert accepted.json()["finding_slugs"] == ["EX-001", "EX-002"]
@pytest.mark.parametrize("verified", [False, True])
def test_draft_code_finding_blocks_fuzz_and_complete_until_promoted(
    client, isolate_settings, verified
):
    engagement_key = f"2026-08-06-code-draft-finding-{int(verified)}"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key=f"draft-finding-{int(verified)}")
    files = _create_files(client, engagement_key, int(repo["id"]))
    base = f"/engagements/{engagement_key}/assessment/code"
    slug = f"DF-{int(verified) + 1:03d}"
    _create_code_parent_finding(
        client,
        engagement_key,
        int(repo["id"]),
        slug=slug,
        workflow_status="draft",
    )
    if verified:
        response = _verify_code_finding(
            client,
            engagement_key,
            int(repo["id"]),
            slug,
            reason_text="Confirmed against the current sealed source snapshot.",
        )
        assert response["finding"]["verification_status"] == "confirmed"

    verify_entry = client.get(
        f"{base}/readiness?target_phase=verify-variant"
    ).json()
    assert "draft_code_findings_unresolved" not in {
        blocker["code"] for blocker in verify_entry["blockers"]
    }
    for target_phase in ("fuzz", "complete"):
        readiness = client.get(
            f"{base}/readiness?target_phase={target_phase}"
        ).json()
        draft_blocker = next(
            blocker
            for blocker in readiness["blockers"]
            if blocker["code"] == "draft_code_findings_unresolved"
        )
        assert draft_blocker == {
            "code": "draft_code_findings_unresolved",
            "message": (
                "Repository has 1 unresolved draft code finding(s); re-review and "
                "rebind when needed, then promote, merge, or kill each draft before "
                "leaving verification."
            ),
            "overrideable": False,
            "repo_id": repo["id"],
        }
        assert "variant_checks_incomplete" not in {
            blocker["code"] for blocker in readiness["blockers"]
        }

    report_readiness = client.get(
        f"/engagements/{engagement_key}/assessment/report-readiness"
    )
    assert report_readiness.status_code == 200, report_readiness.text
    report_draft = next(
        blocker
        for blocker in report_readiness.json()["blockers"]
        if blocker["kind"] == "draft_finding_needs_disposition"
        and blocker["slug"] == slug
    )
    assert report_draft["snapshot_status"] == "current"

    promoted = client.patch(
        f"/engagements/{engagement_key}/assessment/findings/{slug}",
        json={
            "workflow_status": "active",
            "source_name": "operator",
            "reason_code": "verification-triage-complete",
            "reason_text": "Promote the current-source draft into the reportable workflow.",
        },
    )
    assert promoted.status_code == 200, promoted.text
    after = client.get(f"{base}/readiness?target_phase=fuzz").json()
    assert "draft_code_findings_unresolved" not in {
        blocker["code"] for blocker in after["blockers"]
    }
    variant_blockers = [
        blocker
        for blocker in after["blockers"]
        if blocker["code"] == "variant_checks_incomplete"
    ]
    assert variant_blockers[0]["message"] == (
        f"Repository has {len(files)} incomplete admitted-file variant check(s)."
    )
    verification_blockers = [
        blocker
        for blocker in after["blockers"]
        if blocker["code"] == "variant_parent_verification_incomplete"
    ]
    assert bool(verification_blockers) is (not verified)


def test_code_readiness_blocks_current_stale_and_unbound_drafts_but_not_terminalized(
    client, isolate_settings
):
    engagement_key = "2026-08-06-code-draft-binding-states"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="draft-binding-states")
    files = _create_files(client, engagement_key, int(repo["id"]))
    base = f"/engagements/{engagement_key}/assessment/code"
    _create_code_parent_finding(
        client,
        engagement_key,
        int(repo["id"]),
        slug="DS-001",
        workflow_status="draft",
    )

    manifest_fields = {
        "file_path",
        "language",
        "loc",
        "file_hash",
        "header_snippet",
        "git_churn_score",
        "has_past_cve_fix",
    }
    changed_manifest = [{key: row[key] for key in manifest_fields} for row in files]
    changed_manifest[0]["file_hash"] = _source_hash("draft-binding-state-refresh")
    _refresh_repo_files(client, engagement_key, int(repo["id"]), changed_manifest)

    _create_code_parent_finding(
        client,
        engagement_key,
        int(repo["id"]),
        slug="DC-001",
        workflow_status="draft",
    )
    _create_code_parent_finding(
        client,
        engagement_key,
        int(repo["id"]),
        slug="DM-001",
        workflow_status="draft",
        line=20,
    )
    _create_code_parent_finding(
        client,
        engagement_key,
        int(repo["id"]),
        slug="DM-002",
        workflow_status="active",
        line=20,
    )
    merged = client.post(
        f"/engagements/{engagement_key}/assessment/findings/merge",
        json={
            "source_slug": "DM-001",
            "target_slug": "DM-002",
            "reason": "same current-source defect",
        },
    )
    assert merged.status_code == 200, merged.text

    _create_code_parent_finding(
        client,
        engagement_key,
        int(repo["id"]),
        slug="DK-001",
        workflow_status="draft",
        line=30,
    )
    killed = _verify_code_finding(
        client,
        engagement_key,
        int(repo["id"]),
        "DK-001",
        disposition="false_positive",
        reason_code="guard-proven",
        reason_text="Current sealed source proves a complete containment guard.",
        details={"kill_check": 2, "kill_reason": "Containment is enforced."},
    )
    assert killed["finding"]["verification_status"] == "false_positive"

    _create_code_parent_finding(
        client,
        engagement_key,
        int(repo["id"]),
        slug="DU-001",
        workflow_status="draft",
        line=40,
        allow_remint=True,
    )
    with db_module.get_connection() as connection:
        connection.execute(
            "UPDATE assessment_findings SET provenance_json = '{}' WHERE slug = ?",
            ("DU-001",),
        )
        connection.commit()
    _create_code_parent_finding(
        client,
        engagement_key,
        int(repo["id"]),
        slug="DB-001",
        workflow_status="draft",
        line=50,
        allow_remint=True,
    )
    blocked = _verify_code_finding(
        client,
        engagement_key,
        int(repo["id"]),
        "DB-001",
        disposition="blocked",
        reason_code="verification-prerequisite-unavailable",
        reason_text="The independent verification prerequisite is unavailable.",
        details={"block_reason": "The required test environment is unavailable."},
    )
    assert blocked["finding"]["verification_status"] == "blocked"

    readiness = client.get(f"{base}/readiness?target_phase=complete")
    assert readiness.status_code == 200, readiness.text
    assert readiness.json()["track"] == "code"
    blockers = readiness.json()["blockers"]
    repo_blocker = next(
        row for row in blockers if row["code"] == "draft_code_findings_unresolved"
    )
    assert repo_blocker["repo_id"] == repo["id"]
    assert "2 unresolved draft code finding(s)" in repo_blocker["message"]
    unbound_blocker = next(
        row
        for row in blockers
        if row["code"] == "unbound_draft_code_findings_unresolved"
    )
    assert "1 draft code finding(s)" in unbound_blocker["message"]
    findings = {
        row["slug"]: row
        for row in client.get(
            f"/engagements/{engagement_key}/assessment/findings"
        ).json()
    }
    assert findings["DM-001"]["workflow_status"] == "merged"
    assert findings["DK-001"]["workflow_status"] == "false_positive"


def test_code_readiness_does_not_drop_draft_bound_to_inactive_repository(
    client, isolate_settings
):
    engagement_key = "2026-08-06-code-draft-inactive-repo"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="draft-inactive-repo")
    _create_files(client, engagement_key, int(repo["id"]))
    _create_code_parent_finding(
        client,
        engagement_key,
        int(repo["id"]),
        slug="DI-001",
        workflow_status="draft",
    )
    with db_module.get_connection() as connection:
        connection.execute(
            "UPDATE code_repos SET active_generation = 0 WHERE id = ?",
            (repo["id"],),
        )

    response = client.get(
        f"/engagements/{engagement_key}/assessment/code/readiness?target_phase=complete"
    )

    assert response.status_code == 200, response.text
    blockers = response.json()["blockers"]
    unbound = next(
        row
        for row in blockers
        if row["code"] == "unbound_draft_code_findings_unresolved"
    )
    assert "1 draft code finding(s)" in unbound["message"]
    assert not any(
        row["code"] == "draft_code_findings_unresolved"
        and row.get("repo_id") == repo["id"]
        for row in blockers
    )


def test_variant_receipt_rejects_stale_authority_and_unsafe_evidence(
    client, isolate_settings
):
    engagement_key = "2026-08-05-code-variant-receipt-authority"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="variant-receipt-authority")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser = next(row for row in files if row["file_path"] == "src/parser.py")
    _classify_file(client, engagement_key, int(parser["id"]), "critical", 100)
    _create_code_parent_finding(
        client,
        engagement_key,
        int(repo["id"]),
        slug="CH-701",
    )
    _verify_code_finding(client, engagement_key, int(repo["id"]), "CH-701")
    dispatch = _register_variant_dispatch(
        client,
        engagement_key,
        agent_id="variant-authority",
        finding_slugs=["CH-701"],
    )
    payload = _variant_receipt_payload(
        client,
        engagement_key,
        int(repo["id"]),
        parser,
        dispatch,
        parent_finding_slugs=["CH-701"],
    )
    base = f"/engagements/{engagement_key}/assessment/code"

    _create_root_finding(client, engagement_key, "OT-901")
    mutable_output_update = client.patch(
        f"/engagements/{engagement_key}/assessment/dispatches/variant-authority",
        json={"finding_slugs": ["CH-701", "OT-901"]},
    )
    assert mutable_output_update.status_code == 409, mutable_output_update.text
    frozen_dispatch = client.get(
        f"/engagements/{engagement_key}/assessment/dispatches/variant-authority"
    )
    assert frozen_dispatch.status_code == 200, frozen_dispatch.text
    assert frozen_dispatch.json()["finding_slugs"] == ["CH-701"]

    mismatched_parent = client.post(
        f"{base}/variant-checks",
        json={**payload, "parent_finding_slugs": []},
    )
    assert mismatched_parent.status_code == 400
    stale_generation = client.post(
        f"{base}/variant-checks",
        json={**payload, "repo_generation": int(payload["repo_generation"]) + 1},
    )
    assert stale_generation.status_code == 409
    stale_source = client.post(
        f"{base}/variant-checks",
        json={**payload, "source_manifest_digest": _source_hash("stale-manifest")},
    )
    assert stale_source.status_code == 409
    stale_file = client.post(
        f"{base}/variant-checks",
        json={**payload, "file_sha256": _source_hash("stale-file")},
    )
    assert stale_file.status_code == 409

    for unsafe_ref in (
        " ../outside.json",
        "../outside.json",
        "/tmp/outside.json",
        "tools/analysis-state/padded.json ",
        "tools/analysis-state/bad\x00.json",
    ):
        rejected = client.post(
            f"{base}/variant-checks",
            json={**payload, "evidence_ref": unsafe_ref},
        )
        assert rejected.status_code in {400, 422}, (unsafe_ref, rejected.text)
    whitespace_rationale = client.post(
        f"{base}/variant-checks",
        json={**payload, "rationale": "   "},
    )
    assert whitespace_rationale.status_code == 422
    too_many_parents = client.post(
        f"{base}/variant-checks",
        json={
            **payload,
            "parent_finding_slugs": [
                f"CH-CAP-{index:04d}"
                for index in range(code_analysis.MAX_VARIANT_PARENT_FINDINGS + 1)
            ],
        },
    )
    assert too_many_parents.status_code == 422

    recorded = client.post(f"{base}/variant-checks", json=payload)
    assert recorded.status_code == 201, recorded.text
    assert recorded.json()["dispatch_agent_id"] == "variant-authority"
    assert recorded.json()["dispatch_agent_role"] == "code-variant-hunter"
    mutable_output_after_receipt = client.patch(
        f"/engagements/{engagement_key}/assessment/dispatches/variant-authority",
        json={"finding_slugs": ["OT-901"]},
    )
    assert mutable_output_after_receipt.status_code == 409
    assert client.get(f"{base}/variant-checks").json()[0]["current"] is True
    completed_dispatch = client.patch(
        f"/engagements/{engagement_key}/assessment/dispatches/variant-authority",
        json={"status": "completed"},
    )
    assert completed_dispatch.status_code == 200
    assert client.get(f"{base}/variant-checks").json()[0]["current"] is True
    failed_dispatch = client.patch(
        f"/engagements/{engagement_key}/assessment/dispatches/variant-authority",
        json={"status": "failed"},
    )
    assert failed_dispatch.status_code == 200
    assert client.get(f"{base}/variant-checks").json()[0]["current"] is True
    restored_dispatch = client.patch(
        f"/engagements/{engagement_key}/assessment/dispatches/variant-authority",
        json={"status": "completed"},
    )
    assert restored_dispatch.status_code == 200
    assert client.get(f"{base}/variant-checks").json()[0]["current"] is True

    with db_module.get_connection() as connection:
        original_identity = connection.execute(
            """
            SELECT variant_input_digest, receipt_fingerprint
            FROM code_variant_check_receipts WHERE id = ?
            """,
            (recorded.json()["id"],),
        ).fetchone()
        connection.execute(
            "UPDATE code_variant_check_receipts SET variant_input_digest = ? WHERE id = ?",
            (_source_hash("corrupt-input-digest"), recorded.json()["id"]),
        )
    assert client.get(f"{base}/variant-checks").json() == []
    with db_module.get_connection() as connection:
        connection.execute(
            """
            UPDATE code_variant_check_receipts
            SET variant_input_digest = ?, receipt_fingerprint = ? WHERE id = ?
            """,
            (*original_identity, recorded.json()["id"]),
        )
    assert client.get(f"{base}/variant-checks").json()[0]["current"] is True
    with db_module.get_connection() as connection:
        connection.execute(
            "DELETE FROM code_variant_dispatch_scopes WHERE dispatch_id = ?",
            (dispatch["id"],),
        )
    assert client.get(f"{base}/variant-checks").json() == []
    assert "variant_checks_incomplete" in {
        blocker["code"]
        for blocker in client.get(f"{base}/readiness?target_phase=fuzz").json()[
            "blockers"
        ]
    }

    legacy = _register_variant_dispatch(
        client,
        engagement_key,
        agent_id="variant-legacy-scope",
        finding_slugs=["CH-701"],
    )
    with db_module.get_connection() as connection:
        connection.execute(
            "DELETE FROM code_variant_dispatch_scopes WHERE dispatch_id = ?",
            (legacy["id"],),
        )
    missing_scope = client.post(
        f"{base}/variant-checks",
        json={**payload, "dispatch_id": legacy["id"]},
    )
    assert missing_scope.status_code == 409
    assert "immutable start-time scope" in missing_scope.json()["detail"]

    over_cap = client.post(
        f"/engagements/{engagement_key}/assessment/dispatches",
        json={
            "agent_id": "variant-over-cap",
            "agent_role": "code-variant-hunter",
            "task": "Rejected impossible variant scope.",
            "status": "in-progress",
            "finding_slugs": [
                f"CAP-{index:04d}"
                for index in range(code_analysis.MAX_VARIANT_PARENT_FINDINGS + 1)
            ],
        },
    )
    assert over_cap.status_code == 400
    unsorted_scope = client.post(
        f"/engagements/{engagement_key}/assessment/dispatches",
        json={
            "agent_id": "variant-duplicate-scope",
            "agent_role": "code-variant-hunter",
            "task": "Rejected noncanonical variant scope.",
            "status": "in-progress",
            "finding_slugs": ["CH-701", "CH-701"],
        },
    )
    assert unsorted_scope.status_code == 400
    with db_module.get_connection() as connection:
        assert connection.execute(
            """
            SELECT COUNT(*) FROM assessment_dispatches
            WHERE agent_id IN ('variant-over-cap', 'variant-duplicate-scope')
            """
        ).fetchone()[0] == 0

    wrong_role = _register_variant_dispatch(
        client,
        engagement_key,
        agent_id="variant-wrong-role",
        finding_slugs=["CH-701"],
        role="code-vuln-hunter",
    )
    rejected_role = client.post(
        f"{base}/variant-checks",
        json={**payload, "dispatch_id": wrong_role["id"]},
    )
    assert rejected_role.status_code == 409
    blocked = _register_variant_dispatch(
        client,
        engagement_key,
        agent_id="variant-blocked",
        finding_slugs=["CH-701"],
        status="blocked",
    )
    rejected_status = client.post(
        f"{base}/variant-checks",
        json={**payload, "dispatch_id": blocked["id"]},
    )
    assert rejected_status.status_code == 409
    other_engagement = "2026-08-05-code-variant-receipt-other-engagement"
    write_engagement(isolate_settings["engagements_dir"], other_engagement)
    foreign_repo = _create_repo(
        client,
        other_engagement,
        repo_key="variant-foreign-engagement",
    )
    _create_code_parent_finding(
        client,
        other_engagement,
        int(foreign_repo["id"]),
        slug="FX-701",
    )
    foreign_dispatch = _register_variant_dispatch(
        client,
        other_engagement,
        agent_id="variant-foreign-engagement",
        finding_slugs=["FX-701"],
    )
    rejected_foreign = client.post(
        f"{base}/variant-checks",
        json={**payload, "dispatch_id": foreign_dispatch["id"]},
    )
    assert rejected_foreign.status_code == 409
    with db_module.get_connection() as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM code_variant_check_receipts WHERE dispatch_id = ?",
            (foreign_dispatch["id"],),
        ).fetchone()[0] == 0


def test_variant_receipt_scope_survives_kill_excludes_children_and_detects_new_parent(
    client, isolate_settings
):
    engagement_key = "2026-08-05-code-variant-receipt-parent-race"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="variant-parent-race")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser = next(row for row in files if row["file_path"] == "src/parser.py")
    helper = next(row for row in files if row["file_path"] == "src/helpers.py")
    _classify_file(client, engagement_key, int(parser["id"]), "critical", 100)
    _create_code_parent_finding(
        client,
        engagement_key,
        int(repo["id"]),
        slug="CH-801",
    )
    dispatch = _register_variant_dispatch(
        client,
        engagement_key,
        agent_id="variant-parent-race",
        finding_slugs=["CH-801"],
    )
    payload = _variant_receipt_payload(
        client,
        engagement_key,
        int(repo["id"]),
        parser,
        dispatch,
        parent_finding_slugs=["CH-801"],
    )
    base = f"/engagements/{engagement_key}/assessment/code"
    killed = _verify_code_finding(
        client,
        engagement_key,
        int(repo["id"]),
        "CH-801",
        disposition="false_positive",
        reason_code="not-current-parent",
        reason_text="Independent source review proved the original root unreachable.",
        details={
            "kill_check": 4,
            "kill_reason": "The original root is unreachable in the sealed source snapshot.",
        },
    )
    assert killed["finding"]["workflow_status"] == "false_positive"
    recorded = client.post(f"{base}/variant-checks", json=payload)
    assert recorded.status_code == 201, recorded.text
    assert recorded.json()["current"] is True

    _create_code_parent_finding(
        client,
        engagement_key,
        int(repo["id"]),
        slug="CV-801",
        source_name="code-variant-hunter",
        line=20,
        allow_remint=True,
        links=[
            {
                "link_kind": "variant_of",
                "target_kind": "finding",
                "target_ref": "CH-801",
            }
        ],
    )
    assert client.get(f"{base}/variant-checks").json()[0]["current"] is True

    _create_code_parent_finding(
        client,
        engagement_key,
        int(repo["id"]),
        slug="CH-802",
        severity="medium",
        line=30,
        allow_remint=True,
    )
    _verify_code_finding(client, engagement_key, int(repo["id"]), "CH-802")
    assert client.get(f"{base}/variant-checks").json() == []
    raced_receipt = client.post(
        f"{base}/variant-checks",
        json=_variant_receipt_payload(
            client,
            engagement_key,
            int(repo["id"]),
            helper,
            dispatch,
            parent_finding_slugs=["CH-801"],
        ),
    )
    assert raced_receipt.status_code == 201, raced_receipt.text
    assert raced_receipt.json()["current"] is False
    assert client.get(f"{base}/variant-checks").json() == []
    history = client.get(f"{base}/variant-checks?include_stale=true").json()
    assert {row["id"] for row in history} == {
        receipt_id
        for receipt_id in (recorded.json()["id"], raced_receipt.json()["id"])
    }
    assert all(row["current"] is False for row in history)
    assert client.get(f"{base}/files/{parser['id']}").json()[
        "variant_check_status"
    ] == "pending"
    readiness = client.get(f"{base}/readiness?target_phase=fuzz").json()
    assert "variant_checks_incomplete" in {
        blocker["code"] for blocker in readiness["blockers"]
    }


def test_variant_receipt_replay_does_not_demote_newer_current_receipt(
    client, isolate_settings
):
    engagement_key = "2026-08-05-code-variant-receipt-replay-order"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="variant-replay-order")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser = next(row for row in files if row["file_path"] == "src/parser.py")
    helper = next(row for row in files if row["file_path"] == "src/helpers.py")
    _classify_file(client, engagement_key, int(parser["id"]), "critical", 100)
    _create_code_parent_finding(
        client,
        engagement_key,
        int(repo["id"]),
        slug="VR-201",
    )
    dispatch = _register_variant_dispatch(
        client,
        engagement_key,
        agent_id="variant-replay-order",
        finding_slugs=["VR-201"],
    )
    first_payload = _variant_receipt_payload(
        client,
        engagement_key,
        int(repo["id"]),
        parser,
        dispatch,
        parent_finding_slugs=["VR-201"],
    )
    base = f"/engagements/{engagement_key}/assessment/code"
    first = client.post(f"{base}/variant-checks", json=first_payload).json()
    second_payload = {
        **first_payload,
        "evidence_ref": "tools/analysis-state/variant-check-second.json",
        "rationale": "A later complete review rechecked the same frozen scope.",
    }
    second = client.post(f"{base}/variant-checks", json=second_payload).json()
    assert second["id"] != first["id"]
    replay = client.post(f"{base}/variant-checks", json=first_payload)
    assert replay.status_code == 201, replay.text
    assert replay.json()["id"] == first["id"]
    assert replay.json()["current"] is False
    current = client.get(f"{base}/variant-checks").json()
    assert [row["id"] for row in current] == [second["id"]]
    first_page = client.get(
        f"{base}/variant-checks?include_stale=true&limit=1&offset=0"
    )
    second_page = client.get(
        f"{base}/variant-checks?include_stale=true&limit=1&offset=1"
    )
    assert [row["id"] for row in first_page.json()] == [second["id"]]
    assert [row["id"] for row in second_page.json()] == [first["id"]]
    assert client.get(
        f"{base}/variant-checks?limit={code_analysis.MAX_VARIANT_RECEIPT_PAGE + 1}"
    ).status_code == 422
    assert client.get(f"{base}/files/{parser['id']}").json()[
        "variant_check_status"
    ] == "done"
    helper_receipt = client.post(
        f"{base}/variant-checks",
        json=_variant_receipt_payload(
            client,
            engagement_key,
            int(repo["id"]),
            helper,
            dispatch,
            parent_finding_slugs=["VR-201"],
        ),
    )
    assert helper_receipt.status_code == 201, helper_receipt.text
    readiness = client.get(f"{base}/readiness?target_phase=fuzz").json()
    assert "variant_checks_incomplete" not in {
        blocker["code"] for blocker in readiness["blockers"]
    }


def test_variant_readiness_query_count_is_independent_of_admitted_file_count(
    client, isolate_settings
):
    def measure(file_count: int, suffix: str) -> tuple[int, int]:
        engagement_key = f"2026-08-06-variant-query-scale-{suffix}"
        write_engagement(isolate_settings["engagements_dir"], engagement_key)
        repo = _create_repo(client, engagement_key, repo_key=f"variant-query-{suffix}")
        _create_files(client, engagement_key, int(repo["id"]))
        extra_count = file_count - 2
        files = _append_repo_files(
            client,
            engagement_key,
            int(repo["id"]),
            [
                {
                    "file_path": f"src/variant_{index:03d}.py",
                    "language": "python",
                    "loc": 5,
                    "file_hash": _source_hash(f"variant-query-{suffix}-{index}"),
                    "header_snippet": f"def variant_{index:03d}(): pass\n",
                    "git_churn_score": 0,
                    "has_past_cve_fix": False,
                }
                for index in range(extra_count)
            ],
        )
        slug = "QS-001" if suffix == "small" else "QL-001"
        _create_code_parent_finding(
            client,
            engagement_key,
            int(repo["id"]),
            slug=slug,
        )
        verified = _verify_code_finding(
            client,
            engagement_key,
            int(repo["id"]),
            slug,
            reason_text="Current sealed source proves the report-durable root pattern.",
        )
        assert verified["finding"]["verification_status"] == "confirmed"
        dispatch = _register_variant_dispatch(
            client,
            engagement_key,
            agent_id=f"variant-query-{suffix}",
            finding_slugs=[slug],
        )
        for file_row in files:
            receipt = client.post(
                f"/engagements/{engagement_key}/assessment/code/variant-checks",
                json=_variant_receipt_payload(
                    client,
                    engagement_key,
                    int(repo["id"]),
                    file_row,
                    dispatch,
                    parent_finding_slugs=[slug],
                ),
            )
            assert receipt.status_code == 201, receipt.text

        engagement_id = int(client.get(f"/engagements/{engagement_key}").json()["id"])
        statements: list[str] = []
        with db_module.get_connection() as connection:
            connection.set_trace_callback(statements.append)
            try:
                code_analysis.code_readiness(engagement_id, target_phase="fuzz")
            finally:
                connection.set_trace_callback(None)
        code_selects = sum(
            statement.lstrip().upper().startswith("SELECT") for statement in statements
        )
        statements.clear()
        with db_module.get_connection() as connection:
            connection.set_trace_callback(statements.append)
            try:
                code_analysis.report_durable_finding_variant_receipt_obligations(
                    engagement_id
                )
            finally:
                connection.set_trace_callback(None)
        report_selects = sum(
            statement.lstrip().upper().startswith("SELECT") for statement in statements
        )
        return code_selects, report_selects

    two_file_code_selects, two_file_report_selects = measure(2, "small")
    twelve_file_code_selects, twelve_file_report_selects = measure(12, "large")

    assert twelve_file_code_selects <= two_file_code_selects + 3, {
        "two_files": two_file_code_selects,
        "twelve_files": twelve_file_code_selects,
    }
    assert twelve_file_code_selects <= 60, twelve_file_code_selects
    assert twelve_file_report_selects <= two_file_report_selects + 1, {
        "two_files": two_file_report_selects,
        "twelve_files": twelve_file_report_selects,
    }
    assert twelve_file_report_selects <= 12, twelve_file_report_selects


def test_variant_projection_queries_are_skipped_without_parent_obligations(
    client, isolate_settings
):
    engagement_key = "2026-08-07-variant-projection-not-applicable"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="variant-projection-none")
    _create_files(client, engagement_key, int(repo["id"]))
    engagement_id = int(client.get(f"/engagements/{engagement_key}").json()["id"])

    statements: list[str] = []
    with db_module.get_connection() as connection:
        connection.set_trace_callback(statements.append)
        try:
            code_analysis.code_readiness(engagement_id, target_phase="fuzz")
            assert (
                code_analysis.report_durable_finding_variant_receipt_obligations(
                    engagement_id
                )
                == []
            )
        finally:
            connection.set_trace_callback(None)

    variant_projection_statements = [
        statement
        for statement in statements
        if "CODE_VARIANT_CHECK_RECEIPTS AS RECEIPTS" in statement.upper()
        or "CODE_VARIANT_DISPATCH_SCOPES AS SCOPES" in statement.upper()
    ]
    assert variant_projection_statements == []


def test_variant_projection_bounds_historical_receipts_scopes_and_removed_files(
    client, isolate_settings
):
    engagement_key = "2026-08-07-variant-projection-history-bound"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="variant-projection-history")
    files = _create_files(client, engagement_key, int(repo["id"]))
    _create_code_parent_finding(
        client, engagement_key, int(repo["id"]), slug="PB-001"
    )
    dispatch = _register_variant_dispatch(
        client,
        engagement_key,
        agent_id="variant-projection-current",
        finding_slugs=["PB-001"],
    )
    base = f"/engagements/{engagement_key}/assessment/code"
    current_receipt_ids: set[int] = set()
    for file_row in files:
        response = client.post(
            f"{base}/variant-checks",
            json=_variant_receipt_payload(
                client,
                engagement_key,
                int(repo["id"]),
                file_row,
                dispatch,
                parent_finding_slugs=["PB-001"],
            ),
        )
        assert response.status_code == 201, response.text
        current_receipt_ids.add(int(response.json()["id"]))

    engagement_id = int(client.get(f"/engagements/{engagement_key}").json()["id"])
    template_receipt_id = min(current_receipt_ids)
    historical_count = 250
    with db_module.get_connection() as connection:
        for index in range(historical_count):
            dispatch_cursor = connection.execute(
                """
                INSERT INTO assessment_dispatches (
                    engagement_id, agent_id, agent_role, task, dispatched_at, status
                ) VALUES (?, ?, 'code-variant-hunter', 'historical removed-file scan',
                          '2026-01-01T00:00:00Z', 'completed')
                """,
                (engagement_id, f"variant-history-{index:04d}"),
            )
            historical_dispatch_id = int(dispatch_cursor.lastrowid)
            connection.execute(
                """
                INSERT INTO code_variant_dispatch_scopes (
                    dispatch_id, engagement_id, parent_finding_slugs_json,
                    parent_finding_set_digest
                )
                SELECT ?, engagement_id, parent_finding_slugs_json,
                       parent_finding_set_digest
                FROM code_variant_dispatch_scopes
                WHERE dispatch_id = ?
                """,
                (historical_dispatch_id, dispatch["id"]),
            )
            connection.execute(
                """
                INSERT INTO code_variant_check_receipts (
                    engagement_id, dispatch_id, dispatch_agent_id,
                    dispatch_agent_role, current_file_id, repo_id,
                    repo_generation, source_manifest_digest, file_path,
                    file_sha256, language, classification, role, slot_types_json,
                    parent_finding_slugs_json, parent_finding_set_digest,
                    variant_input_digest, status, evidence_ref, rationale,
                    receipt_fingerprint
                )
                SELECT engagement_id, ?, ?, dispatch_agent_role, ?, repo_id,
                       repo_generation, source_manifest_digest, ?, file_sha256,
                       language, classification, role, slot_types_json,
                       parent_finding_slugs_json, parent_finding_set_digest,
                       variant_input_digest, status, evidence_ref, rationale, ?
                FROM code_variant_check_receipts
                WHERE id = ?
                """,
                (
                    historical_dispatch_id,
                    f"variant-history-{index:04d}",
                    1_000_000 + index,
                    f"removed/history_{index:04d}.py",
                    _source_hash(f"variant-history-receipt-{index}"),
                    template_receipt_id,
                ),
            )

        repo_rows = [
            dict(row)
            for row in connection.execute(
                "SELECT * FROM code_repos WHERE engagement_id = ?",
                (engagement_id,),
            ).fetchall()
        ]
        file_rows = [
            dict(row)
            for row in connection.execute(
                "SELECT * FROM code_files WHERE engagement_id = ? ORDER BY id",
                (engagement_id,),
            ).fetchall()
        ]
        parent_slugs = code_analysis._current_phase2_variant_parent_slugs_by_repo(
            connection, engagement_id, {int(repo["id"])}
        )
        projection = code_analysis._load_variant_receipt_projection(
            connection,
            engagement_id,
            repo_rows=repo_rows,
            file_rows=file_rows,
            parent_slugs=parent_slugs,
        )
        plan = connection.execute(
            "EXPLAIN QUERY PLAN "
            + code_analysis._LATEST_CURRENT_VARIANT_RECEIPTS_SQL,
            (
                engagement_id,
                code_analysis._VARIANT_DISPATCH_ROLE,
                engagement_id,
            ),
        ).fetchall()
        index_columns = [
            str(row[2])
            for row in connection.execute(
                "PRAGMA index_info(idx_code_variant_receipts_latest_file)"
            ).fetchall()
        ]

    assert set(projection.latest_receipts) == {int(row["id"]) for row in files}
    assert {int(row["id"]) for row in projection.latest_receipts.values()} == (
        current_receipt_ids
    )
    assert set(projection.dispatch_scopes) == {int(dispatch["id"])}
    assert len(projection.latest_receipts) == len(files)
    assert len(projection.dispatch_scopes) == 1
    assert index_columns == ["engagement_id", "current_file_id", "id"]
    plan_text = "\n".join(str(tuple(row)) for row in plan)
    assert "idx_code_variant_receipts_latest_file" in plan_text
    assert "SCAN candidate" not in plan_text


@pytest.mark.parametrize("verification_status", ["confirmed", "downgraded"])
def test_report_readiness_requires_current_variant_receipts_for_report_durable_code_findings(
    client, isolate_settings, verification_status
):
    engagement_key = f"2026-08-06-report-variant-receipt-{verification_status}"
    engagement_dir = write_engagement(
        isolate_settings["engagements_dir"], engagement_key
    )
    scope_path = engagement_dir / "scope.json"
    scope = json.loads(scope_path.read_text(encoding="utf-8"))
    scope["engagement_type"] = "code"
    scope["current_phase"] = "verify-variant"
    scope_path.write_text(json.dumps(scope), encoding="utf-8")

    repo = _create_repo(
        client,
        engagement_key,
        repo_key=f"report-variant-receipt-{verification_status}",
    )
    _create_files(client, engagement_key, int(repo["id"]))
    files = _append_repo_files(
        client,
        engagement_key,
        int(repo["id"]),
        [
            {
                "file_path": "build/CMakeLists.txt",
                "language": "cmake",
                "loc": 20,
                "file_hash": _source_hash("hash-build"),
                "header_snippet": "add_library(parser src/parser.py)\n",
                "git_churn_score": 1,
                "has_past_cve_fix": False,
            }
        ],
    )
    parser = next(row for row in files if row["file_path"] == "src/parser.py")
    helper = next(row for row in files if row["file_path"] == "src/helpers.py")
    build_file = next(
        row for row in files if row["file_path"] == "build/CMakeLists.txt"
    )
    _classify_file(client, engagement_key, int(parser["id"]), "medium", 49)
    _classify_file(client, engagement_key, int(helper["id"]), "low", 10)
    classified_build = client.post(
        f"/engagements/{engagement_key}/assessment/code/files/bulk-classify",
        json={
            "classifications": [
                {
                    "file_id": build_file["id"],
                    "classification": "skip",
                    "role": "build-configuration",
                    "slot_types": [],
                    "analysis_priority": 0,
                }
            ]
        },
    )
    assert classified_build.status_code == 200, classified_build.text

    # An intel lead is advisory input, not an authoritative Phase 3 parent
    # finding. It must not create a variant-receipt obligation by itself.
    lead = client.post(
        f"/engagements/{engagement_key}/intel/notes",
        json={
            "title": "Lead: inspect parser siblings",
            "body_markdown": "A hypothesis remains, but no finding has been confirmed.",
            "lead_status": "open",
        },
    )
    assert lead.status_code == 201, lead.text
    report_endpoint = f"/engagements/{engagement_key}/assessment/report-readiness"
    lead_only = client.get(report_endpoint)
    assert lead_only.status_code == 200, lead_only.text
    assert "finding_variant_receipts_incomplete" not in {
        blocker["kind"] for blocker in lead_only.json()["blockers"]
    }

    evidence_path = engagement_dir / "notes" / "VF-001.md"
    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    evidence_path.write_text("VF-001 current sealed-source proof", encoding="utf-8")
    author_agent_id = "AUTHOR-VF-001"
    _ensure_finding_author_dispatch(client, engagement_key, author_agent_id)
    finding = client.post(
        f"/engagements/{engagement_key}/assessment/findings",
        json={
            "slug": "VF-001",
            "title": "Report-durable parser trust-boundary bypass",
            "severity": "high",
            "workflow_status": "active",
            "verification_status": "unreviewed",
            "defect_family": "parser-memory-safety",
            "root_cause_key": "parser-memory-safety-vf-001",
            "auth_context": "anonymous",
            "canonical_location": "file:src/parser.py:10",
            "summary": "A current report-durable code finding requires its variant pass.",
            "evidence_ref": "notes/VF-001.md",
            "source_name": "code-vuln-hunter",
            "details": {
                "cvss_score": 8.1,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                "steps_to_reproduce": ["Submit a crafted parser input."],
                "remediation": "Validate the trust-boundary input before parsing.",
                "impact": "An attacker can cross the parser trust boundary.",
                "evidence": "The current sealed source preserves the reachable path.",
                },
                "provenance": {
                    "agent_id": author_agent_id,
                    "agent_name": "code-vuln-hunter",
                "code_snapshot": _finding_code_snapshot(
                    client, engagement_key, int(repo["id"])
                ),
            },
            "links": [],
        },
    )
    assert finding.status_code == 201, finding.text
    verified = _verify_code_finding(
        client,
        engagement_key,
        int(repo["id"]),
        "VF-001",
        disposition=verification_status,
        reason_text="Independent review preserved the report-durable source finding.",
    )
    assert verified["finding"]["verification_status"] == verification_status
    artifact = client.post(
        f"/engagements/{engagement_key}/assessment/artifacts",
        json={
            "path": "notes/VF-001.md",
            "kind": "evidence",
            "related_finding_slug": "VF-001",
        },
    )
    assert artifact.status_code == 201, artifact.text

    blocked = client.get(report_endpoint)
    assert blocked.status_code == 200, blocked.text
    receipt_blockers = [
        blocker
        for blocker in blocked.json()["blockers"]
        if blocker["kind"] == "finding_variant_receipts_incomplete"
    ]
    assert receipt_blockers == [
        {
            "kind": "finding_variant_receipts_incomplete",
            "repo_id": repo["id"],
            "slugs": ["VF-001"],
            "missing_file_count": 3,
            "missing_file_ids": [
                build_file["id"],
                helper["id"],
                parser["id"],
            ],
            "missing_file_paths": [
                "build/CMakeLists.txt",
                "src/helpers.py",
                "src/parser.py",
            ],
            "detail": (
                "report-durable current code finding(s) VF-001 have no complete current "
                "variant-scan receipt for 3 admitted current repository file(s): "
                "build/CMakeLists.txt, src/helpers.py, src/parser.py"
            ),
        }
    ]
    blocked_export = client.post(
        f"/engagements/{engagement_key}/assessment/report-export",
        json={"mode": "final"},
    )
    assert blocked_export.status_code == 409, blocked_export.text
    assert any(
        blocker["kind"] == "finding_variant_receipts_incomplete"
        for blocker in blocked_export.json()["detail"]["blockers"]
    )

    for target_phase in ("fuzz", "complete"):
        code_readiness = client.get(
            f"/engagements/{engagement_key}/assessment/code/readiness"
            f"?target_phase={target_phase}"
        )
        assert code_readiness.status_code == 200, code_readiness.text
        variant_blockers = [
            blocker
            for blocker in code_readiness.json()["blockers"]
            if blocker["code"] == "variant_checks_incomplete"
        ]
        assert variant_blockers == [
            {
                "code": "variant_checks_incomplete",
                "message": (
                    "Repository has 3 incomplete admitted-file variant check(s)."
                ),
                "overrideable": True,
                "repo_id": repo["id"],
            }
        ]

    phase = client.get(
        f"/engagements/{engagement_key}/assessment/phase-readiness?phase=report"
    )
    assert phase.status_code == 200, phase.text
    assert phase.json()["ready"] is False
    assert receipt_blockers[0] in phase.json()["blockers"]

    from assess.lib.coverage_checks import render_report_readiness

    ready, _, blocker_lines, _ = render_report_readiness(blocked.json())
    assert ready is False
    assert any(
        "finding_variant_receipts_incomplete | VF-001" in line
        for line in blocker_lines
    )

    dispatch = _register_variant_dispatch(
        client,
        engagement_key,
        agent_id="variant-report-receipt",
        finding_slugs=["VF-001"],
    )
    receipt = client.post(
        f"/engagements/{engagement_key}/assessment/code/variant-checks",
        json=_variant_receipt_payload(
            client,
            engagement_key,
            int(repo["id"]),
            parser,
            dispatch,
            parent_finding_slugs=["VF-001"],
        ),
    )
    assert receipt.status_code == 201, receipt.text
    assert receipt.json()["current"] is True

    after_medium = client.get(report_endpoint)
    assert after_medium.status_code == 200, after_medium.text
    after_medium_blocker = next(
        blocker
        for blocker in after_medium.json()["blockers"]
        if blocker["kind"] == "finding_variant_receipts_incomplete"
    )
    assert after_medium_blocker["missing_file_paths"] == [
        "build/CMakeLists.txt",
        "src/helpers.py",
    ]
    after_medium_code = client.get(
        f"/engagements/{engagement_key}/assessment/code/readiness?target_phase=fuzz"
    ).json()
    assert next(
        blocker["message"]
        for blocker in after_medium_code["blockers"]
        if blocker["code"] == "variant_checks_incomplete"
    ) == "Repository has 2 incomplete admitted-file variant check(s)."

    low_payload = _variant_receipt_payload(
        client,
        engagement_key,
        int(repo["id"]),
        helper,
        dispatch,
        parent_finding_slugs=["VF-001"],
    )
    low_receipt = client.post(
        f"/engagements/{engagement_key}/assessment/code/variant-checks",
        json={
            **low_payload,
            "evidence_ref": "tools/analysis-state/variant-low-clean.json",
            "rationale": (
                "Clean: traced the helper's wrappers and found no reachable copy "
                "of the confirmed parser pattern."
            ),
        },
    )
    assert low_receipt.status_code == 201, low_receipt.text
    assert low_receipt.json()["current"] is True
    after_low = client.get(report_endpoint)
    assert after_low.status_code == 200, after_low.text
    after_low_blocker = next(
        blocker
        for blocker in after_low.json()["blockers"]
        if blocker["kind"] == "finding_variant_receipts_incomplete"
    )
    assert after_low_blocker["missing_file_paths"] == ["build/CMakeLists.txt"]
    after_low_code = client.get(
        f"/engagements/{engagement_key}/assessment/code/readiness?target_phase=fuzz"
    ).json()
    assert next(
        blocker["message"]
        for blocker in after_low_code["blockers"]
        if blocker["code"] == "variant_checks_incomplete"
    ) == "Repository has 1 incomplete admitted-file variant check(s)."

    skip_payload = _variant_receipt_payload(
        client,
        engagement_key,
        int(repo["id"]),
        build_file,
        dispatch,
        parent_finding_slugs=["VF-001"],
    )
    skip_receipt = client.post(
        f"/engagements/{engagement_key}/assessment/code/variant-checks",
        json={
            **skip_payload,
            "evidence_ref": "tools/analysis-state/variant-build-not-applicable.json",
            "rationale": (
                "Not applicable: this build file was inspected for configuration or "
                "instantiation of the parent pattern and contains neither."
            ),
        },
    )
    assert skip_receipt.status_code == 201, skip_receipt.text
    assert skip_receipt.json()["current"] is True

    cleared = client.get(report_endpoint)
    assert cleared.status_code == 200, cleared.text
    assert "finding_variant_receipts_incomplete" not in {
        blocker["kind"] for blocker in cleared.json()["blockers"]
    }
    cleared_code = client.get(
        f"/engagements/{engagement_key}/assessment/code/readiness?target_phase=fuzz"
    ).json()
    assert "variant_checks_incomplete" not in {
        blocker["code"] for blocker in cleared_code["blockers"]
    }
    cleared_phase = client.get(
        f"/engagements/{engagement_key}/assessment/phase-readiness?phase=report"
    )
    assert cleared_phase.status_code == 200, cleared_phase.text
    assert "finding_variant_receipts_incomplete" not in {
        blocker["kind"] for blocker in cleared_phase.json()["blockers"]
    }


def test_variant_receipt_history_survives_file_replacement(client, isolate_settings):
    engagement_key = "2026-08-05-code-variant-receipt-file-removal"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="variant-file-removal")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser = next(row for row in files if row["file_path"] == "src/parser.py")
    helper = next(row for row in files if row["file_path"] == "src/helpers.py")
    _classify_file(client, engagement_key, int(parser["id"]), "critical", 100)
    _create_code_parent_finding(
        client,
        engagement_key,
        int(repo["id"]),
        slug="VR-301",
    )
    _verify_code_finding(client, engagement_key, int(repo["id"]), "VR-301")
    dispatch = _register_variant_dispatch(
        client,
        engagement_key,
        agent_id="variant-file-removal",
        finding_slugs=["VR-301"],
    )
    payload = _variant_receipt_payload(
        client,
        engagement_key,
        int(repo["id"]),
        parser,
        dispatch,
        parent_finding_slugs=["VR-301"],
    )
    base = f"/engagements/{engagement_key}/assessment/code"
    receipt = client.post(f"{base}/variant-checks", json=payload)
    assert receipt.status_code == 201, receipt.text
    manifest_fields = {
        "file_path",
        "language",
        "loc",
        "file_hash",
        "header_snippet",
        "git_churn_score",
        "has_past_cve_fix",
    }
    _refresh_repo_files(
        client,
        engagement_key,
        int(repo["id"]),
        [
            {key: helper[key] for key in manifest_fields},
            {
                **{key: parser[key] for key in manifest_fields},
                "file_hash": _source_hash("replacement-parser"),
                "header_snippet": "def replacement_parser(data): pass",
            },
        ],
    )
    _classify_file(client, engagement_key, int(parser["id"]), "critical", 100)
    _create_code_parent_finding(
        client,
        engagement_key,
        int(repo["id"]),
        slug="VR-302",
        line=20,
        allow_remint=True,
    )
    _verify_code_finding(client, engagement_key, int(repo["id"]), "VR-302")

    history = client.get(
        f"{base}/variant-checks?file_id={parser['id']}&include_stale=true"
    )
    assert history.status_code == 200, history.text
    assert [row["id"] for row in history.json()] == [receipt.json()["id"]]
    assert history.json()[0]["current"] is False
    db_path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    with sqlite3.connect(str(db_path)) as connection:
        persisted = connection.execute(
            """
            SELECT current_file_id, repo_generation, file_path, file_sha256
            FROM code_variant_check_receipts WHERE id = ?
            """,
            (receipt.json()["id"],),
        ).fetchone()
    assert persisted == (
        parser["id"],
        receipt.json()["repo_generation"],
        parser["file_path"],
        parser["file_hash"],
    )
    replacement = client.get(f"{base}/files/{parser['id']}").json()
    assert replacement["file_hash"] != parser["file_hash"]
    assert replacement["variant_check_status"] == "pending"
    assert "variant_checks_incomplete" in {
        blocker["code"]
        for blocker in client.get(f"{base}/readiness?target_phase=fuzz").json()[
            "blockers"
        ]
    }


def test_fuzz_readiness_keeps_effort_warnings_advisory(client, isolate_settings):
    engagement_key = "2026-08-04-code-readiness-effort-advisory"
    engagement_dir = write_engagement(
        isolate_settings["engagements_dir"], engagement_key
    )
    repo = _create_repo(client, engagement_key, repo_key="readiness-effort-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    base = f"/engagements/{engagement_key}/assessment/code"
    binding = client.get(f"{base}/repos/{repo['id']}").json()
    assert client.post(
        f"{base}/files/bulk-structural-metadata",
        json=_complete_structural_payload(
            repo_id=int(repo["id"]),
            repo_generation=int(binding["active_generation"]),
            source_manifest_digest=str(binding["source_manifest_digest"]),
            updates=[
                {
                    "file_id": row["id"],
                    "source_sha256": row["file_hash"],
                    "total_functions": 0,
                    "total_entry_points": 1,
                    "total_sinks": 0,
                    "total_exports": 0,
                }
                for row in files
            ],
        ),
    ).status_code == 200
    assert client.post(
        f"{base}/threat-model",
        json={
            "repo_id": repo["id"],
            "repo_generation": binding["active_generation"],
            "source_manifest_digest": binding["source_manifest_digest"],
            "threat_model": {"trust_boundaries": ["network"]},
        },
    ).status_code == 200
    parser = next(row for row in files if row["file_path"] == "src/parser.py")
    helper = next(row for row in files if row["file_path"] == "src/helpers.py")
    _classify_file(client, engagement_key, int(parser["id"]), "critical", 100)
    _classify_file(client, engagement_key, int(helper["id"]), "low", 10)
    claim = _claim_file_for_analysis(client, engagement_key, int(parser["id"]))
    completed = client.post(
        f"{base}/analysis-queue/done",
        json=_owned(
            claim,
            item_ids=[claim["id"]],
            disposition="clean",
            notes="Completed a deliberately shallow review for advisory-gate coverage.",
            cwe_coverage=_network_input_coverage(default_effort=10),
        ),
    )
    assert completed.status_code == 200, completed.text
    helper_claim = _claim_file_for_analysis(client, engagement_key, int(helper["id"]))
    helper_skipped = client.post(
        f"{base}/analysis-queue/done",
        json=_owned(
            helper_claim,
            item_ids=[helper_claim["id"]],
            disposition="skipped",
            skip_reason="generated-code",
        ),
    )
    assert helper_skipped.status_code == 200, helper_skipped.text

    applicability = engagement_dir / "tools" / "fuzz-state" / "applicability.json"
    applicability.parent.mkdir(parents=True, exist_ok=True)
    applicability.write_text(
        '{"decision":"not_required","reason":"managed language"}',
        encoding="utf-8",
    )
    decision = _record_fuzz_decision(
        client,
        engagement_key,
        binding,
        decision="not_required",
    )
    assert decision.status_code == 201, decision.text

    readiness = client.get(f"{base}/readiness?target_phase=fuzz")
    assert readiness.status_code == 200, readiness.text
    payload = readiness.json()
    assert payload["transition_ready"] is True
    assert payload["blockers"] == []
    assert payload["quality_gate"]["passed"] is False
    assert any("effort" in warning.lower() for warning in payload["quality_gate"]["warnings"])


def test_fuzz_entry_requires_phase2_root_triage_but_allows_pending_runtime_proof(
    client, isolate_settings
):
    engagement_key = "2026-08-07-code-fuzz-pending-runtime-proof"
    engagement_dir = write_engagement(
        isolate_settings["engagements_dir"], engagement_key
    )
    repo = _create_repo(client, engagement_key, repo_key="fuzz-pending-runtime-proof")
    files = _create_files(client, engagement_key, int(repo["id"]))
    base = f"/engagements/{engagement_key}/assessment/code"
    binding = client.get(f"{base}/repos/{repo['id']}").json()
    indexed = client.post(
        f"{base}/files/bulk-structural-metadata",
        json=_complete_structural_payload(
            repo_id=int(repo["id"]),
            repo_generation=int(binding["active_generation"]),
            source_manifest_digest=str(binding["source_manifest_digest"]),
            updates=[
                {
                    "file_id": row["id"],
                    "source_sha256": row["file_hash"],
                    "total_functions": 0,
                    "total_entry_points": 1,
                    "total_sinks": 0,
                    "total_exports": 0,
                }
                for row in files
            ],
        ),
    )
    assert indexed.status_code == 200, indexed.text
    threat = client.post(
        f"{base}/threat-model",
        json={
            "repo_id": repo["id"],
            "repo_generation": binding["active_generation"],
            "source_manifest_digest": binding["source_manifest_digest"],
            "threat_model": {"trust_boundaries": ["network"]},
        },
    )
    assert threat.status_code == 200, threat.text
    parser = next(row for row in files if row["file_path"] == "src/parser.py")
    helper = next(row for row in files if row["file_path"] == "src/helpers.py")
    _classify_file(client, engagement_key, int(parser["id"]), "critical", 100)
    _classify_file(client, engagement_key, int(helper["id"]), "low", 10)
    parser_claim = _claim_file_for_analysis(
        client, engagement_key, int(parser["id"])
    )
    parser_done = client.post(
        f"{base}/analysis-queue/done",
        json=_owned(
            parser_claim,
            item_ids=[parser_claim["id"]],
            disposition="clean",
            notes="Completed the current-source parser review.",
            cwe_coverage=_network_input_coverage(default_effort=80),
        ),
    )
    assert parser_done.status_code == 200, parser_done.text
    helper_claim = _claim_file_for_analysis(
        client, engagement_key, int(helper["id"])
    )
    helper_done = client.post(
        f"{base}/analysis-queue/done",
        json=_owned(
            helper_claim,
            item_ids=[helper_claim["id"]],
            disposition="skipped",
            skip_reason="generated-code",
        ),
    )
    assert helper_done.status_code == 200, helper_done.text

    _create_code_parent_finding(
        client, engagement_key, int(repo["id"]), slug="PR-001"
    )
    dispatch = _register_variant_dispatch(
        client,
        engagement_key,
        agent_id="variant-pending-runtime-proof",
        finding_slugs=["PR-001"],
    )
    for file_row in files:
        receipt = client.post(
            f"{base}/variant-checks",
            json=_variant_receipt_payload(
                client,
                engagement_key,
                int(repo["id"]),
                file_row,
                dispatch,
                parent_finding_slugs=["PR-001"],
            ),
        )
        assert receipt.status_code == 201, receipt.text

    applicability = engagement_dir / "tools" / "fuzz-state" / "applicability.json"
    applicability.parent.mkdir(parents=True, exist_ok=True)
    applicability.write_text(
        '{"decision":"required","target_ids":["parser-entry"]}',
        encoding="utf-8",
    )
    decision = _record_fuzz_decision(
        client,
        engagement_key,
        binding,
        decision="required",
        target_ids=["parser-entry"],
    )
    assert decision.status_code == 201, decision.text

    unreviewed = client.get(f"{base}/readiness?target_phase=fuzz").json()
    assert {item["code"] for item in unreviewed["blockers"]} == {
        "variant_parent_verification_incomplete"
    }
    disputed = _verify_code_finding(
        client,
        engagement_key,
        int(repo["id"]),
        "PR-001",
        disposition="disputed",
    )
    assert disputed["finding"]["verification_status"] == "disputed"
    disputed_readiness = client.get(
        f"{base}/readiness?target_phase=fuzz"
    ).json()
    assert {item["code"] for item in disputed_readiness["blockers"]} == {
        "variant_parent_verification_incomplete"
    }

    pending = _verify_code_finding(
        client,
        engagement_key,
        int(repo["id"]),
        "PR-001",
        disposition="pending_runtime_proof",
    )
    assert pending["finding"]["verification_status"] == "pending_runtime_proof"
    ready = client.get(f"{base}/readiness?target_phase=fuzz").json()
    assert ready["transition_ready"] is True
    assert ready["blockers"] == []


def test_complete_readiness_requires_snapshot_current_verification_and_blind_triage_for_info(
    client, isolate_settings
):
    engagement_key = "2026-08-04-code-readiness-complete-findings"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="readiness-complete-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    base = f"/engagements/{engagement_key}/assessment/code"
    binding = client.get(f"{base}/repos/{repo['id']}").json()
    assert client.post(
        f"{base}/files/bulk-structural-metadata",
        json=_complete_structural_payload(
            repo_id=int(repo["id"]),
            repo_generation=int(binding["active_generation"]),
            source_manifest_digest=str(binding["source_manifest_digest"]),
            updates=[
                {
                    "file_id": row["id"],
                    "source_sha256": row["file_hash"],
                    "total_functions": 1,
                    "total_entry_points": 0,
                    "total_sinks": 0,
                    "total_exports": 0,
                }
                for row in files
            ],
        ),
    ).status_code == 200
    assert client.post(
        f"{base}/threat-model",
        json={
            "repo_id": repo["id"],
            "repo_generation": binding["active_generation"],
            "source_manifest_digest": binding["source_manifest_digest"],
            "threat_model": {"trust_boundaries": []},
        },
    ).status_code == 200
    for row in files:
        _classify_file(client, engagement_key, int(row["id"]), "low", 10)
    _ensure_finding_author_dispatch(client, engagement_key, "AUTHOR-CH-001")
    finding = client.post(
        f"/engagements/{engagement_key}/assessment/findings",
        json={
            "slug": "CH-001",
            "title": "Informational code finding needing triage",
            "severity": "info",
            "workflow_status": "active",
            "verification_status": "unreviewed",
            "defect_family": "hardening",
            "root_cause_key": "info-triage",
            "auth_context": "anonymous",
            "canonical_location": "file:src/parser.py:1",
            "summary": "Every reportable severity must receive an explicit verdict.",
            "evidence_ref": "tools/analysis-state/info.json",
            "notes": "",
            "source_name": "code-vuln-hunter",
            "details": {"evidence": "informational hardening observation"},
            "provenance": {
                "agent_id": "AUTHOR-CH-001",
                "agent_name": "code-vuln-hunter",
                "code_snapshot": _finding_code_snapshot(
                    client, engagement_key, int(repo["id"])
                ),
            },
            "links": [],
        },
    )
    assert finding.status_code == 201, finding.text

    readiness = client.get(f"{base}/readiness?target_phase=complete")
    assert readiness.status_code == 200, readiness.text
    by_code = {item["code"]: item for item in readiness.json()["blockers"]}
    assert by_code["findings_unverified"]["overrideable"] is True
    assert by_code["findings_blind_triage_incomplete"]["overrideable"] is True
    assert "finding_snapshot_stale" not in by_code

    with db_module.get_connection() as connection:
        connection.execute(
            """
            UPDATE assessment_findings
            SET canonical_location = '	file:src/parser.py:1', provenance_json = '{}'
            WHERE engagement_id = (
                SELECT id FROM engagements WHERE key = ?
            ) AND slug = 'CH-001'
            """,
            (engagement_key,),
        )

    legacy_readiness = client.get(f"{base}/readiness?target_phase=complete")
    assert legacy_readiness.status_code == 200, legacy_readiness.text
    legacy_by_code = {
        item["code"]: item for item in legacy_readiness.json()["blockers"]
    }
    assert legacy_by_code["finding_snapshot_stale"]["overrideable"] is False

    with db_module.get_connection() as connection:
        connection.execute(
            """
            UPDATE assessment_findings
            SET canonical_location = 'FILE:src/parser.py:1'
            WHERE engagement_id = (
                SELECT id FROM engagements WHERE key = ?
            ) AND slug = 'CH-001'
            """,
            (engagement_key,),
        )

    uppercase_readiness = client.get(f"{base}/readiness?target_phase=complete")
    assert uppercase_readiness.status_code == 200, uppercase_readiness.text
    uppercase_codes = {
        item["code"] for item in uppercase_readiness.json()["blockers"]
    }
    assert "finding_snapshot_stale" not in uppercase_codes

    with db_module.get_connection() as connection:
        connection.execute(
            """
            UPDATE assessment_findings
            SET provenance_json = ?
            WHERE engagement_id = (
                SELECT id FROM engagements WHERE key = ?
            ) AND slug = 'CH-001'
            """,
            (
                json.dumps(
                    {
                        "code_snapshot": {
                            "repo_id": repo["id"],
                            "repo_generation": binding["active_generation"],
                            "source_manifest_digest": "0" * 64,
                        }
                    }
                ),
                engagement_key,
            ),
        )

    bound_uppercase_readiness = client.get(
        f"{base}/readiness?target_phase=complete"
    )
    assert bound_uppercase_readiness.status_code == 200, bound_uppercase_readiness.text
    bound_uppercase_by_code = {
        item["code"]: item
        for item in bound_uppercase_readiness.json()["blockers"]
    }
    assert bound_uppercase_by_code["finding_snapshot_stale"]["overrideable"] is False


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
        json={"items": [{"file_id": parser_file["id"], "priority": 95}]},
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
                    "file_hash": _source_hash("hash-c"),
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
        json={
            "repo_id": repo["id"],
            "repo_generation": client.get(
                f"/engagements/{first_key}/assessment/code/repos/{repo['id']}"
            ).json()["active_generation"],
            "source_manifest_digest": client.get(
                f"/engagements/{first_key}/assessment/code/repos/{repo['id']}"
            ).json()["source_manifest_digest"],
            "threat_model": {"targets": ["parser"]},
        },
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
        json=_verified_repo_payload(client, engagement_key, "same-repo"),
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
            "source_snapshot_quality": "legacy-unverified",
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
                    "priority": 95,
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
            "agent_name": work_item["agent_name"],
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
                    "priority": 95,
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
            "agent_name": queue_item["agent_name"],
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
        json={"items": [{"file_id": parser_file["id"], "priority": 95}]},
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
            "agent_name": queue_item["agent_name"],
            "lease_token": queue_item["lease_token"],
            "disposition": "clean",
            "notes": "Stale worker should not complete this item",
            "cwe_coverage": _network_input_coverage(default_effort=80),
        },
    )
    assert done.status_code == 409
    assert done.json()["detail"] == (
        f"Cannot complete queue item {queue_item['id']} unless it is processing; "
        "current status is pending"
    )


def test_queue_error_rejects_items_reclaimed_after_validation(client, isolate_settings, monkeypatch):
    engagement_key = "2026-04-09-code-queue-error-race"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="queue-error-race-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser_file = next(item for item in files if item["file_path"] == "src/parser.py")
    _classify_file(client, engagement_key, int(parser_file["id"]), "critical", 95)

    queue_response = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue",
        json={"items": [{"file_id": parser_file["id"], "priority": 95}]},
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
            "agent_name": queue_item["agent_name"],
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
        json={"items": [{"file_id": parser_file["id"], "priority": 95}]},
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
            "agent_name": queue_item["agent_name"],
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
        json={"items": [{"file_id": parser_file["id"], "priority": 95}]},
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
        priority=95,
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
            "agent_name": queue_item["agent_name"],
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
    _classify_file(client, engagement_key, int(helper_file["id"]), "high", 79)
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

    distinct_hypothesis = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-results",
        json=payload
        | {
            "notes": "A distinct same-family contract also needs review.",
            "cross_file_triggers": [
                {
                    "file_path": "src/helpers.py",
                    "reason": "helper decodes a second attacker-controlled framing mode",
                    "vuln_class": "web-app-injection",
                }
            ],
        },
    )
    assert distinct_hypothesis.status_code == 201, distinct_hypothesis.text

    first_done = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/done",
        json=_owned(
            queue_item,
            item_ids=[queue_item["id"]],
            disposition="clean",
            notes="Completed the first source review.",
            cwe_coverage=_network_input_coverage(default_effort=80),
        ),
    )
    assert first_done.status_code == 200, first_done.text
    second_queue = _claim_file_for_reanalysis(
        client,
        engagement_key,
        int(parser_file["id"]),
        reason="Independently confirm the cross-file trigger",
    )
    second_source_payload = {
        **payload,
        "queue_item_id": second_queue["id"],
        "agent_name": second_queue["agent_name"],
        "lease_token": second_queue["lease_token"],
        "notes": "A later source review independently raised the same hypothesis.",
    }
    later_source = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-results",
        json=second_source_payload,
    )
    assert later_source.status_code == 201, later_source.text
    later_source_retry = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-results",
        json=second_source_payload | {"notes": "Exact retry from the same review."},
    )
    assert later_source_retry.status_code == 201, later_source_retry.text

    coverage = client.get(
        f"/engagements/{engagement_key}/assessment/code/coverage?repo_id={repo['id']}"
    )
    assert coverage.status_code == 200
    assert coverage.json()["trigger_summary"]["pending"] == 3
    triggers = client.get(
        f"/engagements/{engagement_key}/assessment/code/triggers"
    ).json()
    assert len(triggers) == 3
    assert len({(row["source_queue_item_id"], row["reason"]) for row in triggers}) == 3

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

    _ensure_finding_author_dispatch(client, engagement_key, "AUTHOR-CH-777")
    finding = client.post(
        f"/engagements/{engagement_key}/assessment/findings",
        json={
            "slug": "CH-777",
            "title": "Parser finding",
            "severity": "medium",
            "workflow_status": "active",
            "verification_status": "unreviewed",
            "defect_family": "integer-overflow",
            "root_cause_key": "suppressed-parser-finding",
            "auth_context": "anonymous",
            "canonical_location": "file:src/parser.py:10",
            "summary": "The current parser result awaits verifier disposition.",
            "evidence_ref": "tools/analysis-state/finding.json",
            "notes": "Awaiting verifier review.",
            "source_name": "code-vuln-hunter",
            "details": {
                "evidence": "validate_length() blocks the arithmetic path.",
                "impact": "No live issue.",
            },
            "provenance": {
                "agent_id": "AUTHOR-CH-777",
                "agent_name": "code-vuln-hunter",
                "code_snapshot": _finding_code_snapshot(
                    client, engagement_key, int(repo["id"])
                ),
            },
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
    assert result_response.json()["finding_workflow_status"] == "active"
    assert result_response.json()["finding_verification_status"] == "unreviewed"
    assert "finding_verification_state" not in result_response.json()
    assert "finding_verification_disposition" not in result_response.json()

    with db_module.get_connection() as connection:
        connection.execute(
            """
            UPDATE assessment_findings
            SET status = 'false_positive', verification_status = 'false_positive'
            WHERE engagement_id = (
                SELECT id FROM engagements WHERE key = ?
            ) AND slug = 'CH-777'
            """,
            (engagement_key,),
        )

    results_list = client.get(
        f"/engagements/{engagement_key}/assessment/code/analysis-results?file_id={parser_file['id']}"
    )
    assert results_list.status_code == 200
    assert len(results_list.json()) == 1
    assert results_list.json()[0]["finding_workflow_status"] == "false_positive"
    assert results_list.json()[0]["finding_verification_status"] == "false_positive"
    assert "finding_verification_state" not in results_list.json()[0]
    assert "finding_verification_disposition" not in results_list.json()[0]


def test_coverage_detail_cwe(client, isolate_settings):
    """GET coverage?detail=cwe returns files with applicable_families and
    cwe_coverage from the canonical latest completed attempt."""
    engagement_key = "2026-04-04-cwe-detail"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="cwe-detail-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser_file = next(item for item in files if item["file_path"] == "src/parser.py")
    helper_file = next(item for item in files if item["file_path"] == "src/helpers.py")
    _classify_file(client, engagement_key, int(parser_file["id"]), "critical", 95)
    _classify_file(client, engagement_key, int(helper_file["id"]), "high", 70)

    # Create the initial parser review. The second pass is an explicit,
    # terminal-linked reanalysis below rather than an accidental duplicate.
    queue_response = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue",
        json={
            "items": [
                {"file_id": parser_file["id"], "priority": 95, "slot_types": ["NETWORK-INPUT"]},
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
            "agent_name": item1["agent_name"],
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

    reanalysis_response = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue",
        json={
            "mode": "reanalysis",
            "reason": "Close the remaining CWE effort gaps",
            "items": [
                {
                    "file_id": parser_file["id"],
                    "priority": 95,
                    "slot_types": ["NETWORK-INPUT"],
                    "supersedes": item1["id"],
                }
            ],
        },
    )
    assert reanalysis_response.status_code == 201, reanalysis_response.text
    assert reanalysis_response.json()["reanalysis"] == 1

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
            "agent_name": item2["agent_name"],
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

    # Parser file should expose only the latest reanalysis proof.
    parser_entry = next(f for f in payload["files"] if f["file_id"] == parser_file["id"])
    assert parser_entry["classification"] == "critical"
    assert "NETWORK-INPUT" in parser_entry["slot_types"]
    assert len(parser_entry["applicable_families"]) > 0

    # Historical attempts do not inflate the current proof.
    injection_entry = next(e for e in parser_entry["cwe_coverage"] if e["family"] == "web-app-injection")
    assert injection_entry["effort"] == 90
    assert injection_entry["entry_chains_traced"] == 3
    assert injection_entry["functions_analyzed"] == 7
    assert injection_entry["total_entry_chains"] == 8
    assert injection_entry["notes"] == "full trace"

    # The older higher SSRF claim is superseded by the latest reanalysis.
    ssrf_entry = next(e for e in parser_entry["cwe_coverage"] if e["family"] == "ssrf")
    assert ssrf_entry["effort"] == 70
    assert ssrf_entry["entry_chains_traced"] == 2
    assert ssrf_entry["functions_analyzed"] == 3
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

    _publish_structural_totals(
        client,
        engagement_key,
        int(repo["id"]),
        files,
        {int(parser_file["id"]): {"total_functions": 10}},
    )
    _classify_file(client, engagement_key, int(parser_file["id"]), "critical", 95)
    queue_item = _claim_file_for_analysis(client, engagement_key, int(parser_file["id"]))

    # Complete WITHOUT recording any analysis results
    done = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/done",
        json={
            "item_ids": [queue_item["id"]],
            "agent_name": queue_item["agent_name"],
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

    _publish_structural_totals(
        client,
        engagement_key,
        int(repo["id"]),
        files,
        {int(parser_file["id"]): {"total_functions": 5}},
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
            "agent_name": queue_item["agent_name"],
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


def test_coverage_integrity_treats_claimed_exceeds_total_as_advisory(client, isolate_settings):
    """An index undercount can focus review but cannot reject deeper observed coverage."""
    engagement_key = "2026-05-12-integrity-exceeds"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="integrity-exceeds-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser_file = next(item for item in files if item["file_path"] == "src/parser.py")

    _publish_structural_totals(
        client,
        engagement_key,
        int(repo["id"]),
        files,
        {int(parser_file["id"]): {"total_functions": 3}},
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
            "agent_name": queue_item["agent_name"],
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
    assert integrity["plausible"] is True
    assert integrity["authoritative_blockers"] == []
    assert any("exceeds" in item for item in integrity["advisories"])


def test_coverage_integrity_skips_not_applicable_entries(client, isolate_settings):
    """Not-applicable entries do not trigger integrity warnings."""
    engagement_key = "2026-05-12-integrity-na"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="integrity-na-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser_file = next(item for item in files if item["file_path"] == "src/parser.py")

    _publish_structural_totals(
        client,
        engagement_key,
        int(repo["id"]),
        files,
        {int(parser_file["id"]): {"total_functions": 5}},
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
        {"family": "error-handling", "disposition": "not_applicable", "effort": 0, "functions_analyzed": 0},
    ]

    done = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/done",
        json={
            "item_ids": [queue_item["id"]],
            "agent_name": queue_item["agent_name"],
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
            "agent_name": queue_item["agent_name"],
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


def _seed_queue_contract_file(client, isolate_settings, suffix: str):
    engagement_key = f"2026-08-05-queue-contract-{suffix}"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key=f"queue-contract-{suffix}")
    file_row = next(
        row
        for row in _create_files(client, engagement_key, int(repo["id"]))
        if row["file_path"] == "src/parser.py"
    )
    _classify_file(client, engagement_key, int(file_row["id"]), "critical", 80)
    return engagement_key, repo, file_row


def test_initial_queue_retry_updates_pending_row_without_duplication(client, isolate_settings):
    engagement_key, _, file_row = _seed_queue_contract_file(
        client, isolate_settings, "pending-retry"
    )
    endpoint = f"/engagements/{engagement_key}/assessment/code/analysis-queue"

    created = client.post(
        endpoint,
        json={
            "mode": "initial",
            "items": [
                {
                    "file_id": file_row["id"],
                    "priority": 80,
                    "batch_theme": "initial-map",
                    "slot_types": ["NETWORK-INPUT"],
                    "guidance_hypotheses": ["first guidance"],
                }
            ],
        },
    )
    assert created.status_code == 201, created.text
    first = created.json()
    assert first["inserted"] == 1
    assert first["outcomes"][0]["outcome"] == "inserted"
    queue_item_id = first["outcomes"][0]["queue_item_id"]

    retried = client.post(
        endpoint,
        json={
            "mode": "initial",
            "items": [
                {
                    "file_id": file_row["id"],
                    "priority": 80,
                    "batch_theme": "architect-final",
                    "slot_types": ["NETWORK-INPUT", "FILE-CONTENT"],
                    "guidance_hypotheses": ["fresh guidance"],
                }
            ],
        },
    )
    assert retried.status_code == 201, retried.text
    payload = retried.json()
    assert payload == {
        "mode": "initial",
        "inserted": 0,
        "updated": 1,
        "already_active": 0,
        "conflicts": 0,
        "reanalysis": 0,
        "total": 1,
        "outcomes": [
            {
                "file_id": file_row["id"],
                "queue_item_id": queue_item_id,
                "outcome": "updated",
                "status": "pending",
                "detail": "updated pending initial queue item",
            }
        ],
    }

    with db_module.get_connection() as connection:
        rows = connection.execute(
            """
            SELECT id, priority, batch_theme, slot_types_json,
                   guidance_hypotheses_json, status
            FROM code_analysis_queue
            WHERE engagement_id = (
                SELECT id FROM engagements WHERE key = ?
            ) AND file_id = ?
            """,
            (engagement_key, file_row["id"]),
        ).fetchall()
    assert len(rows) == 1
    assert dict(rows[0]) == {
        "id": queue_item_id,
        "priority": 80,
        "batch_theme": "architect-final",
        "slot_types_json": '["NETWORK-INPUT","FILE-CONTENT"]',
        "guidance_hypotheses_json": '["fresh guidance"]',
        "status": "pending",
    }


def test_initial_queue_duplicate_file_ids_roll_back_whole_batch(client, isolate_settings):
    engagement_key, _, file_row = _seed_queue_contract_file(
        client, isolate_settings, "duplicate-batch"
    )
    response = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue",
        json={
            "mode": "initial",
            "items": [
                {"file_id": file_row["id"], "priority": 60},
                {"file_id": file_row["id"], "priority": 90},
            ],
        },
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "queue request contains duplicate file IDs"

    with db_module.get_connection() as connection:
        count = connection.execute(
            "SELECT COUNT(*) FROM code_analysis_queue WHERE file_id = ?",
            (file_row["id"],),
        ).fetchone()[0]
    assert count == 0


def test_queue_priority_mismatch_rejects_whole_batch_before_mutation(
    client, isolate_settings
):
    engagement_key, repo, parser_file = _seed_queue_contract_file(
        client, isolate_settings, "priority-mismatch"
    )
    helper_file = next(
        row
        for row in client.get(
            f"/engagements/{engagement_key}/assessment/code/files"
            f"?repo_id={repo['id']}&limit=20"
        ).json()["items"]
        if row["file_path"] == "src/helpers.py"
    )
    _classify_file(client, engagement_key, int(helper_file["id"]), "high", 60)

    response = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue",
        json={
            "mode": "initial",
            "items": [
                {"file_id": parser_file["id"], "priority": 80},
                {"file_id": helper_file["id"], "priority": 61},
            ],
        },
    )
    assert response.status_code == 409, response.text
    assert response.json()["detail"] == (
        f"queue priority for file {helper_file['id']} must equal current "
        "analysis_priority 60 (received 61)"
    )

    with db_module.get_connection() as connection:
        count = connection.execute(
            "SELECT COUNT(*) FROM code_analysis_queue WHERE engagement_id = "
            "(SELECT id FROM engagements WHERE key = ?)",
            (engagement_key,),
        ).fetchone()[0]
    assert count == 0


def test_initial_queue_requires_explicit_priority(client, isolate_settings):
    engagement_key, _, file_row = _seed_queue_contract_file(
        client, isolate_settings, "missing-priority"
    )
    response = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue",
        json={"mode": "initial", "items": [{"file_id": file_row["id"]}]},
    )
    assert response.status_code == 422, response.text
    with db_module.get_connection() as connection:
        count = connection.execute(
            "SELECT COUNT(*) FROM code_analysis_queue WHERE file_id = ?",
            (file_row["id"],),
        ).fetchone()[0]
    assert count == 0


def test_queue_batch_rolls_back_when_later_item_normalization_fails(
    client, isolate_settings
):
    engagement_key, repo, parser_file = _seed_queue_contract_file(
        client, isolate_settings, "normalization-rollback"
    )
    helper_file = next(
        row
        for row in client.get(
            f"/engagements/{engagement_key}/assessment/code/files"
            f"?repo_id={repo['id']}&limit=20"
        ).json()["items"]
        if row["file_path"] == "src/helpers.py"
    )
    _classify_file(client, engagement_key, int(helper_file["id"]), "high", 60)
    engagement_id = client.get(f"/engagements/{engagement_key}").json()["id"]

    with pytest.raises(HTTPException) as excinfo:
        code_analysis.bulk_create_queue_items(
            engagement_id,
            [
                {"file_id": parser_file["id"], "priority": 80},
                {
                    "file_id": helper_file["id"],
                    "priority": 60,
                    "slot_types": ["NOT-A-REAL-SLOT"],
                },
            ],
            mode="initial",
        )
    assert excinfo.value.status_code == 400

    with db_module.get_connection() as connection:
        count = connection.execute(
            "SELECT COUNT(*) FROM code_analysis_queue WHERE engagement_id = ?",
            (engagement_id,),
        ).fetchone()[0]
    assert count == 0


def test_initial_queue_retry_never_mutates_live_lease_and_fetch_uses_agent_name(
    client, isolate_settings
):
    engagement_key, _, file_row = _seed_queue_contract_file(
        client, isolate_settings, "live-lease"
    )
    base = f"/engagements/{engagement_key}/assessment/code"
    initial_item = {
        "file_id": file_row["id"],
        "priority": 80,
        "batch_theme": "live-batch",
        "slot_types": ["NETWORK-INPUT"],
    }
    assert client.post(
        f"{base}/analysis-queue",
        json={"mode": "initial", "items": [initial_item]},
    ).status_code == 201
    claim_response = client.post(
        f"{base}/analysis-queue/fetch",
        json={"limit": 1, "agent_name": "hunter-live"},
    )
    assert claim_response.status_code == 200, claim_response.text
    claim = claim_response.json()[0]
    assert claim["agent_name"] == "hunter-live"
    assert "assigned_agent" not in claim
    original_lease = claim["lease_token"]

    same_retry = client.post(
        f"{base}/analysis-queue",
        json={"mode": "initial", "items": [initial_item]},
    )
    assert same_retry.status_code == 201, same_retry.text
    assert same_retry.json()["already_active"] == 1
    assert same_retry.json()["outcomes"][0]["outcome"] == "already_active"

    conflicting_retry = client.post(
        f"{base}/analysis-queue",
        json={
            "mode": "initial",
            "items": [
                {
                    **initial_item,
                    "batch_theme": "must-not-replace-live-work",
                }
            ],
        },
    )
    assert conflicting_retry.status_code == 201, conflicting_retry.text
    assert conflicting_retry.json()["conflicts"] == 1
    assert conflicting_retry.json()["outcomes"][0]["outcome"] == "conflict"

    with db_module.get_connection() as connection:
        row = connection.execute(
            """
            SELECT priority, batch_theme, status, assigned_agent, lease_token
            FROM code_analysis_queue WHERE id = ?
            """,
            (claim["id"],),
        ).fetchone()
    assert dict(row) == {
        "priority": 80,
        "batch_theme": "live-batch",
        "status": "processing",
        "assigned_agent": "hunter-live",
        "lease_token": original_lease,
    }


def test_initial_queue_retry_never_updates_pending_row_with_lease_identity(
    client, isolate_settings
):
    engagement_key, _, file_row = _seed_queue_contract_file(
        client, isolate_settings, "pending-lease-identity"
    )
    base = f"/engagements/{engagement_key}/assessment/code"
    created = client.post(
        f"{base}/analysis-queue",
        json={
            "items": [
                {
                    "file_id": file_row["id"],
                    "priority": 80,
                    "batch_theme": "original",
                }
            ]
        },
    ).json()
    queue_item_id = created["outcomes"][0]["queue_item_id"]
    with db_module.get_connection() as connection:
        connection.execute(
            """
            UPDATE code_analysis_queue
            SET assigned_agent = 'legacy-owner', lease_token = 'legacy-lease'
            WHERE id = ?
            """,
            (queue_item_id,),
        )

    identical_retry = client.post(
        f"{base}/analysis-queue",
        json={
            "items": [
                {
                    "file_id": file_row["id"],
                    "priority": 80,
                    "batch_theme": "original",
                }
            ]
        },
    )
    assert identical_retry.status_code == 201, identical_retry.text
    assert identical_retry.json()["conflicts"] == 1

    retried = client.post(
        f"{base}/analysis-queue",
        json={
            "items": [
                {
                    "file_id": file_row["id"],
                    "priority": 80,
                    "batch_theme": "must-not-replace",
                }
            ]
        },
    )
    assert retried.status_code == 201, retried.text
    assert retried.json()["conflicts"] == 1
    with db_module.get_connection() as connection:
        row = connection.execute(
            """
            SELECT batch_theme, assigned_agent, lease_token
            FROM code_analysis_queue WHERE id = ?
            """,
            (queue_item_id,),
        ).fetchone()
    assert dict(row) == {
        "batch_theme": "original",
        "assigned_agent": "legacy-owner",
        "lease_token": "legacy-lease",
    }

    fetched = client.post(
        f"{base}/analysis-queue/fetch",
        json={"limit": 1, "agent_name": "must-not-steal-corrupt-lease"},
    )
    assert fetched.status_code == 200, fetched.text
    assert fetched.json() == []
    with db_module.get_connection() as connection:
        row = connection.execute(
            """
            SELECT status, assigned_agent, lease_token
            FROM code_analysis_queue WHERE id = ?
            """,
            (queue_item_id,),
        ).fetchone()
    assert dict(row) == {
        "status": "pending",
        "assigned_agent": "legacy-owner",
        "lease_token": "legacy-lease",
    }
    stats = client.get(f"{base}/analysis-queue/stats")
    assert stats.status_code == 200, stats.text
    assert stats.json() == {
        "pending": 0,
        "processing": 0,
        "done": 0,
        "error": 0,
        "needs_context": 0,
        "total": 0,
        "historical_total": 1,
            "superseded_history": 0,
            "invalid_active_identity": 1,
            "invalid_active_history": 0,
    }


def test_explicit_reanalysis_requires_terminal_predecessor_and_records_audit_link(
    client, isolate_settings
):
    engagement_key, _, file_row = _seed_queue_contract_file(
        client, isolate_settings, "reanalysis"
    )
    base = f"/engagements/{engagement_key}/assessment/code"
    item = {
        "file_id": file_row["id"],
        "priority": 80,
        "batch_theme": "phase-2a",
    }
    created = client.post(
        f"{base}/analysis-queue",
        json={"mode": "initial", "items": [item]},
    ).json()
    original_id = created["outcomes"][0]["queue_item_id"]
    claim = client.post(
        f"{base}/analysis-queue/fetch",
        json={"limit": 1, "agent_name": "hunter-a"},
    ).json()[0]
    done = client.post(
        f"{base}/analysis-queue/done",
        json={
            "item_ids": [claim["id"]],
            "agent_name": claim.get("agent_name", claim.get("assigned_agent")),
            "lease_token": claim["lease_token"],
            "disposition": "skipped",
            "notes": "Reviewed and intentionally skipped.",
            "cwe_coverage": [],
            "skip_reason": "test-fixture",
        },
    )
    assert done.status_code == 200, done.text

    accidental_retry = client.post(
        f"{base}/analysis-queue",
        json={"mode": "initial", "items": [item]},
    )
    assert accidental_retry.status_code == 201, accidental_retry.text
    assert accidental_retry.json()["conflicts"] == 1

    reason = "Phase 2C independent adversarial reread"
    missing_predecessor = client.post(
        f"{base}/analysis-queue",
        json={
            "mode": "reanalysis",
            "reason": reason,
            "items": [{**item, "batch_theme": "phase-2c"}],
        },
    )
    assert missing_predecessor.status_code == 422
    assert "supersedes" in missing_predecessor.text

    mismatched_priority = client.post(
        f"{base}/analysis-queue",
        json={
            "mode": "reanalysis",
            "reason": reason,
            "items": [
                {
                    **item,
                    "priority": 81,
                    "batch_theme": "phase-2c",
                    "supersedes": original_id,
                }
            ],
        },
    )
    assert mismatched_priority.status_code == 409, mismatched_priority.text

    reanalysis = client.post(
        f"{base}/analysis-queue",
        json={
            "mode": "reanalysis",
            "reason": reason,
            "items": [{**item, "batch_theme": "phase-2c", "supersedes": original_id}],
        },
    )
    assert reanalysis.status_code == 201, reanalysis.text
    payload = reanalysis.json()
    assert payload["reanalysis"] == 1
    assert payload["outcomes"][0]["outcome"] == "reanalysis"
    reanalysis_id = payload["outcomes"][0]["queue_item_id"]

    with db_module.get_connection() as connection:
        rows = connection.execute(
            """
            SELECT id, queue_mode, reanalysis_reason,
                   reanalysis_of_queue_item_id, status
            FROM code_analysis_queue
            WHERE file_id = ? ORDER BY id
            """,
            (file_row["id"],),
        ).fetchall()
    assert [dict(row) for row in rows] == [
        {
            "id": original_id,
            "queue_mode": "initial",
            "reanalysis_reason": "",
            "reanalysis_of_queue_item_id": None,
            "status": "done",
        },
        {
            "id": reanalysis_id,
            "queue_mode": "reanalysis",
            "reanalysis_reason": reason,
            "reanalysis_of_queue_item_id": original_id,
            "status": "pending",
        },
    ]

    duplicate_reanalysis = client.post(
        f"{base}/analysis-queue",
        json={
            "mode": "reanalysis",
            "reason": reason,
            "items": [{**item, "batch_theme": "phase-2c", "supersedes": original_id}],
        },
    )
    assert duplicate_reanalysis.status_code == 201
    assert duplicate_reanalysis.json()["already_active"] == 1


def test_reanalysis_history_does_not_block_content_refresh(client, isolate_settings):
    engagement_key, repo, file_row = _seed_queue_contract_file(
        client, isolate_settings, "refresh-delete"
    )
    base = f"/engagements/{engagement_key}/assessment/code"
    initial = _claim_file_for_analysis(client, engagement_key, int(file_row["id"]), priority=80)
    completed = client.post(
        f"{base}/analysis-queue/done",
        json=_owned(
            initial,
            item_ids=[initial["id"]],
            disposition="skipped",
            skip_reason="test-fixture",
        ),
    )
    assert completed.status_code == 200, completed.text
    reanalysis = client.post(
        f"{base}/analysis-queue",
        json={
            "mode": "reanalysis",
            "reason": "Review the changed parser surface independently.",
            "items": [
                {
                    "file_id": file_row["id"],
                    "priority": 80,
                    "supersedes": initial["id"],
                }
            ],
        },
    )
    assert reanalysis.status_code == 201, reanalysis.text

    manifest_fields = {
        "file_path",
        "language",
        "loc",
        "file_hash",
        "header_snippet",
        "git_churn_score",
        "has_past_cve_fix",
    }
    current_files = client.get(
        f"{base}/files?repo_id={repo['id']}&limit=20&include_header_snippet=true"
    ).json()["items"]
    manifest = [{key: row[key] for key in manifest_fields} for row in current_files]
    for row in manifest:
        if row["file_path"] == file_row["file_path"]:
            row["file_hash"] = _source_hash("refresh-delete-changed")
            row["loc"] = int(row["loc"]) + 1

    refreshed = _refresh_repo_files(
        client,
        engagement_key,
        int(repo["id"]),
        manifest,
    )
    refreshed_file = next(
        row for row in refreshed if row["file_path"] == file_row["file_path"]
    )
    assert refreshed_file["classification"] == "unclassified"
    with db_module.get_connection() as connection:
        count = connection.execute(
            "SELECT COUNT(*) FROM code_analysis_queue WHERE file_id = ?",
            (file_row["id"],),
        ).fetchone()[0]
    assert count == 0


def test_concurrent_fetch_never_promotes_stale_generation_history(
    client, isolate_settings
):
    engagement_key, repo, file_row = _seed_queue_contract_file(
        client, isolate_settings, "stale-fetch"
    )
    base = f"/engagements/{engagement_key}/assessment/code"
    first = client.post(
        f"{base}/analysis-queue",
        json={"items": [{"file_id": file_row["id"], "priority": 80}]},
    )
    assert first.status_code == 201, first.text
    stale_id = first.json()["outcomes"][0]["queue_item_id"]

    manifest_fields = {
        "file_path",
        "language",
        "loc",
        "file_hash",
        "header_snippet",
        "git_churn_score",
        "has_past_cve_fix",
    }
    current_files = client.get(
        f"{base}/files?repo_id={repo['id']}&limit=20&include_header_snippet=true"
    ).json()["items"]
    manifest = [{key: row[key] for key in manifest_fields} for row in current_files]
    next(row for row in manifest if row["file_path"] == "src/helpers.py")[
        "file_hash"
    ] = _source_hash("stale-fetch-next-generation")
    _refresh_repo_files(client, engagement_key, int(repo["id"]), manifest)

    current = client.post(
        f"{base}/analysis-queue",
        json={"items": [{"file_id": file_row["id"], "priority": 80}]},
    )
    assert current.status_code == 201, current.text
    current_id = current.json()["outcomes"][0]["queue_item_id"]
    engagement_id = client.get(f"/engagements/{engagement_key}").json()["id"]

    def fetch(agent_name: str):
        return code_analysis.fetch_queue_items(
            engagement_id,
            1,
            agent_name,
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        claims = [
            future.result(timeout=5)
            for future in (
                pool.submit(fetch, "stale-fetch-a"),
                pool.submit(fetch, "stale-fetch-b"),
            )
        ]
    claimed = [item for batch in claims for item in batch]
    assert [item["id"] for item in claimed] == [current_id]

    with db_module.get_connection() as connection:
        rows = [
            dict(row)
            for row in connection.execute(
                """
                SELECT id, repo_generation, status, assigned_agent
                FROM code_analysis_queue
                WHERE file_id = ? ORDER BY id
                """,
                (file_row["id"],),
            ).fetchall()
        ]
        active_generation = connection.execute(
            "SELECT active_generation FROM code_repos WHERE id = ?",
            (repo["id"],),
        ).fetchone()[0]
    assert rows == [
        {
            "id": stale_id,
            "repo_generation": int(active_generation) - 1,
            "status": "pending",
            "assigned_agent": "",
        },
        {
            "id": current_id,
            "repo_generation": active_generation,
            "status": "processing",
            "assigned_agent": claimed[0]["agent_name"],
        },
    ]


def test_concurrent_initial_queue_retries_serialize_to_one_row(client, isolate_settings):
    engagement_key, _, file_row = _seed_queue_contract_file(
        client, isolate_settings, "race"
    )
    engagement_id = client.get(f"/engagements/{engagement_key}").json()["id"]
    item = {
        "file_id": file_row["id"],
        "priority": 80,
        "batch_theme": "race",
        "slot_types": [],
        "guidance_hypotheses": [],
    }

    def submit():
        return code_analysis.bulk_create_queue_items(
            engagement_id,
            [item],
            mode="initial",
            reason="",
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = [future.result(timeout=5) for future in [pool.submit(submit), pool.submit(submit)]]

    assert sorted(result["inserted"] for result in results) == [0, 1]
    assert sorted(result["already_active"] for result in results) == [0, 1]
    with db_module.get_connection() as connection:
        rows = connection.execute(
            "SELECT id, status FROM code_analysis_queue WHERE file_id = ?",
            (file_row["id"],),
        ).fetchall()
    assert len(rows) == 1
    assert rows[0]["status"] == "pending"


def test_queue_stats_projects_latest_attempt_and_reports_preserved_history(
    client, isolate_settings
):
    engagement_key, _, file_row = _seed_queue_contract_file(
        client, isolate_settings, "stats-history"
    )
    base = f"/engagements/{engagement_key}/assessment/code"
    _classify_file(client, engagement_key, int(file_row["id"]), "critical", 90)
    queued = client.post(
        f"{base}/analysis-queue",
        json={"items": [{"file_id": file_row["id"], "priority": 90}]},
    )
    assert queued.status_code == 201, queued.text

    reopened = client.patch(
        f"{base}/files/{file_row['id']}",
        json={"role": "network-parser-v2"},
    )
    assert reopened.status_code == 200, reopened.text

    with db_module.get_connection() as connection:
        history = [
            dict(row)
            for row in connection.execute(
                """
                SELECT status, disposition, batch_theme
                FROM code_analysis_queue
                WHERE file_id = ? ORDER BY id
                """,
                (file_row["id"],),
            ).fetchall()
        ]
    assert history == [
        {"status": "done", "disposition": "superseded", "batch_theme": ""},
        {
            "status": "pending",
            "disposition": "",
            "batch_theme": "metadata-refresh-review",
        },
    ]

    stats = client.get(f"{base}/analysis-queue/stats")
    assert stats.status_code == 200, stats.text
    assert stats.json() == {
        "pending": 1,
        "processing": 0,
        "done": 0,
        "error": 0,
        "needs_context": 0,
        "total": 1,
        "historical_total": 2,
        "superseded_history": 1,
        "invalid_active_identity": 0,
        "invalid_active_history": 0,
    }


def _seed_priority_contract_files(client, isolate_settings, suffix: str):
    engagement_key = f"2026-08-05-priority-contract-{suffix}"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key=f"priority-contract-{suffix}")
    files = _create_files(client, engagement_key, int(repo["id"]))
    return engagement_key, repo, files


def _classification_record(
    file_id: int,
    classification: str,
    priority: int,
    *,
    slot_types: list[str] | None = None,
) -> dict[str, object]:
    return {
        "file_id": file_id,
        "classification": classification,
        "role": "parser" if classification in {"critical", "high"} else "helper",
        "slot_types": (
            ["NETWORK-INPUT"]
            if slot_types is None and classification in {"critical", "high"}
            else (slot_types or [])
        ),
        "analysis_priority": priority,
    }


@pytest.mark.parametrize(
    ("classification", "priority"),
    [
        ("critical", 80),
        ("critical", 100),
        ("high", 50),
        ("high", 79),
        ("medium", 20),
        ("medium", 49),
        ("low", 5),
        ("low", 19),
        ("skip", 0),
    ],
)
def test_bulk_classify_accepts_priority_band_boundaries(
    client, isolate_settings, classification, priority
):
    engagement_key, _, files = _seed_priority_contract_files(
        client, isolate_settings, f"valid-{classification}-{priority}"
    )
    file_row = files[0]
    response = client.post(
        f"/engagements/{engagement_key}/assessment/code/files/bulk-classify",
        json={
            "classifications": [
                _classification_record(int(file_row["id"]), classification, priority)
            ]
        },
    )
    assert response.status_code == 200, response.text
    persisted = client.get(
        f"/engagements/{engagement_key}/assessment/code/files/{file_row['id']}"
    ).json()
    assert (persisted["classification"], persisted["analysis_priority"]) == (
        classification,
        priority,
    )


@pytest.mark.parametrize(
    ("classification", "priority"),
    [
        ("critical", 79),
        ("high", 49),
        ("high", 80),
        ("medium", 19),
        ("medium", 50),
        ("low", 4),
        ("low", 20),
        ("skip", 1),
    ],
)
def test_bulk_classify_rejects_priority_outside_classification_band(
    client, isolate_settings, classification, priority
):
    engagement_key, _, files = _seed_priority_contract_files(
        client, isolate_settings, f"invalid-{classification}-{priority}"
    )
    file_row = files[0]
    response = client.post(
        f"/engagements/{engagement_key}/assessment/code/files/bulk-classify",
        json={
            "classifications": [
                _classification_record(int(file_row["id"]), classification, priority)
            ]
        },
    )
    assert response.status_code == 400, response.text
    assert "analysis_priority" in response.json()["detail"]
    persisted = client.get(
        f"/engagements/{engagement_key}/assessment/code/files/{file_row['id']}"
    ).json()
    assert (persisted["classification"], persisted["analysis_priority"]) == (
        "unclassified",
        0,
    )


def test_bulk_classify_requires_explicit_priority(client, isolate_settings):
    engagement_key, _, files = _seed_priority_contract_files(
        client, isolate_settings, "required"
    )
    file_row = files[0]
    response = client.post(
        f"/engagements/{engagement_key}/assessment/code/files/bulk-classify",
        json={
            "classifications": [
                {
                    "file_id": file_row["id"],
                    "classification": "high",
                    "role": "parser",
                    "slot_types": ["NETWORK-INPUT"],
                }
            ]
        },
    )
    assert response.status_code == 422, response.text
    assert "analysis_priority" in response.text


def test_bulk_classify_priority_failure_rolls_back_whole_batch(
    client, isolate_settings
):
    engagement_key, _, files = _seed_priority_contract_files(
        client, isolate_settings, "rollback"
    )
    response = client.post(
        f"/engagements/{engagement_key}/assessment/code/files/bulk-classify",
        json={
            "classifications": [
                _classification_record(int(files[0]["id"]), "low", 5),
                _classification_record(int(files[1]["id"]), "skip", 1),
            ]
        },
    )
    assert response.status_code == 400, response.text
    persisted = client.get(
        f"/engagements/{engagement_key}/assessment/code/files?limit=20"
    ).json()["items"]
    assert {
        (row["classification"], row["analysis_priority"]) for row in persisted
    } == {("unclassified", 0)}


def test_bulk_classify_rejects_duplicate_file_ids_before_mutation(
    client, isolate_settings
):
    engagement_key, _, files = _seed_priority_contract_files(
        client, isolate_settings, "duplicate-classification"
    )
    file_id = int(files[0]["id"])

    response = client.post(
        f"/engagements/{engagement_key}/assessment/code/files/bulk-classify",
        json={
            "classifications": [
                _classification_record(file_id, "low", 5),
                _classification_record(file_id, "high", 70),
            ]
        },
    )

    assert response.status_code == 400, response.text
    row = client.get(
        f"/engagements/{engagement_key}/assessment/code/files/{file_id}"
    ).json()
    assert row["classification"] == "unclassified"
    assert row["analysis_priority"] == 0


def test_file_patch_validates_resulting_classification_priority_pair(
    client, isolate_settings
):
    engagement_key, _, files = _seed_priority_contract_files(
        client, isolate_settings, "partial-patch"
    )
    file_row = files[0]
    base = f"/engagements/{engagement_key}/assessment/code"
    _classify_file(client, engagement_key, int(file_row["id"]), "high", 70)

    classification_only = client.patch(
        f"{base}/files/{file_row['id']}", json={"classification": "critical"}
    )
    assert classification_only.status_code == 400, classification_only.text
    priority_only = client.patch(
        f"{base}/files/{file_row['id']}", json={"analysis_priority": 80}
    )
    assert priority_only.status_code == 400, priority_only.text
    persisted = client.get(f"{base}/files/{file_row['id']}").json()
    assert (persisted["classification"], persisted["analysis_priority"]) == (
        "high",
        70,
    )

    atomic = client.patch(
        f"{base}/files/{file_row['id']}",
        json={"classification": "critical", "analysis_priority": 80},
    )
    assert atomic.status_code == 200, atomic.text
    skipped = client.patch(
        f"{base}/files/{file_row['id']}",
        json={"classification": "skip", "analysis_priority": 0},
    )
    assert skipped.status_code == 200, skipped.text
    invalid_skip = client.patch(
        f"{base}/files/{file_row['id']}", json={"analysis_priority": 1}
    )
    assert invalid_skip.status_code == 400, invalid_skip.text
    persisted = client.get(f"{base}/files/{file_row['id']}").json()
    assert (persisted["classification"], persisted["analysis_priority"]) == (
        "skip",
        0,
    )


@pytest.mark.parametrize("priority", [True, 70.5, "70"])
def test_file_patch_rejects_non_integer_priority(
    client, isolate_settings, priority
):
    engagement_key, _, files = _seed_priority_contract_files(
        client, isolate_settings, f"patch-type-{type(priority).__name__}"
    )
    file_row = files[0]
    response = client.patch(
        f"/engagements/{engagement_key}/assessment/code/files/{file_row['id']}",
        json={"analysis_priority": priority},
    )
    assert response.status_code == 400, response.text


def test_bulk_classify_accepts_exec_policy_slot(client, isolate_settings):
    engagement_key, _, files = _seed_priority_contract_files(
        client, isolate_settings, "exec-policy"
    )
    file_row = files[0]
    response = client.post(
        f"/engagements/{engagement_key}/assessment/code/files/bulk-classify",
        json={
            "classifications": [
                _classification_record(
                    int(file_row["id"]),
                    "high",
                    70,
                    slot_types=["EXEC-POLICY"],
                )
            ]
        },
    )
    assert response.status_code == 200, response.text
    assert client.get(
        f"/engagements/{engagement_key}/assessment/code/files/{file_row['id']}"
    ).json()["slot_types"] == ["EXEC-POLICY"]


@pytest.mark.parametrize("mutation_mode", ["bulk", "patch"])
def test_priority_change_updates_unleased_pending_queue(
    client, isolate_settings, mutation_mode
):
    engagement_key, _, files = _seed_priority_contract_files(
        client, isolate_settings, f"pending-{mutation_mode}"
    )
    file_row = files[0]
    base = f"/engagements/{engagement_key}/assessment/code"
    _classify_file(client, engagement_key, int(file_row["id"]), "high", 70)
    queued = client.post(
        f"{base}/analysis-queue",
        json={"items": [{"file_id": file_row["id"], "priority": 70}]},
    )
    assert queued.status_code == 201, queued.text

    if mutation_mode == "bulk":
        changed = client.post(
            f"{base}/files/bulk-classify",
            json={
                "classifications": [
                    _classification_record(int(file_row["id"]), "high", 75)
                ]
            },
        )
    else:
        changed = client.patch(
            f"{base}/files/{file_row['id']}", json={"analysis_priority": 75}
        )
    assert changed.status_code == 200, changed.text
    with db_module.get_connection() as connection:
        queue_row = connection.execute(
            "SELECT priority, status FROM code_analysis_queue WHERE file_id = ?",
            (file_row["id"],),
        ).fetchone()
    assert tuple(queue_row) == (75, "pending")


@pytest.mark.parametrize("mutation_mode", ["bulk", "patch"])
def test_priority_change_rejects_live_processing_queue(
    client, isolate_settings, mutation_mode
):
    engagement_key, _, files = _seed_priority_contract_files(
        client, isolate_settings, f"processing-{mutation_mode}"
    )
    file_row = files[0]
    base = f"/engagements/{engagement_key}/assessment/code"
    _classify_file(client, engagement_key, int(file_row["id"]), "high", 70)
    claim = _claim_file_for_analysis(
        client, engagement_key, int(file_row["id"]), priority=70
    )

    if mutation_mode == "bulk":
        changed = client.post(
            f"{base}/files/bulk-classify",
            json={
                "classifications": [
                    _classification_record(int(file_row["id"]), "high", 75)
                ]
            },
        )
    else:
        changed = client.patch(
            f"{base}/files/{file_row['id']}", json={"analysis_priority": 75}
        )
    assert changed.status_code == 409, changed.text
    persisted = client.get(f"{base}/files/{file_row['id']}").json()
    assert persisted["analysis_priority"] == 70
    heartbeat = client.post(
        f"{base}/analysis-queue/heartbeat",
        json={
            "item_id": claim["id"],
            "agent_name": claim["agent_name"],
            "lease_token": claim["lease_token"],
        },
    )
    assert heartbeat.status_code == 200, heartbeat.text


@pytest.mark.parametrize(
    ("blocked_status", "retry_path", "retry_payload"),
    [
        ("error", "retry-error", {"reason": "retry failed worker"}),
        (
            "needs_context",
            "retry-needs-context",
            {"reason": "context supplied"},
        ),
    ],
)
def test_blocked_queue_retry_refreshes_current_file_priority(
    client, isolate_settings, blocked_status, retry_path, retry_payload
):
    engagement_key, _, files = _seed_priority_contract_files(
        client, isolate_settings, f"retry-{blocked_status}"
    )
    file_row = files[0]
    base = f"/engagements/{engagement_key}/assessment/code"
    _classify_file(client, engagement_key, int(file_row["id"]), "high", 70)
    queued = client.post(
        f"{base}/analysis-queue",
        json={"items": [{"file_id": file_row["id"], "priority": 70}]},
    ).json()
    queue_id = queued["outcomes"][0]["queue_item_id"]
    with db_module.get_connection() as connection:
        connection.execute(
            "UPDATE code_analysis_queue SET status = ? WHERE id = ?",
            (blocked_status, queue_id),
        )
    changed = client.patch(
        f"{base}/files/{file_row['id']}", json={"analysis_priority": 75}
    )
    assert changed.status_code == 200, changed.text
    retried = client.post(
        f"{base}/analysis-queue/{retry_path}",
        json={"item_ids": [queue_id], **retry_payload},
    )
    assert retried.status_code == 200, retried.text
    with db_module.get_connection() as connection:
        queue_row = connection.execute(
            "SELECT priority, status FROM code_analysis_queue WHERE id = ?",
            (queue_id,),
        ).fetchone()
    assert tuple(queue_row) == (75, "pending")


def test_trigger_requeue_derives_priority_merges_context_and_blocks_initial_overwrite(
    client, isolate_settings
):
    engagement_key, _, files = _seed_priority_contract_files(
        client, isolate_settings, "trigger-merge"
    )
    file_row = files[0]
    base = f"/engagements/{engagement_key}/assessment/code"
    _classify_file(client, engagement_key, int(file_row["id"]), "high", 70)
    first = client.post(
        f"{base}/analysis-queue/requeue",
        json={
            "items": [
                {
                    "file_id": file_row["id"],
                    "reason": "first trigger",
                    "guidance_hypotheses": ["first guidance"],
                }
            ]
        },
    )
    assert first.status_code == 201, first.text
    second = client.post(
        f"{base}/analysis-queue/requeue",
        json={
            "items": [
                {
                    "file_id": file_row["id"],
                    "reason": "second trigger",
                    "guidance_hypotheses": ["second guidance"],
                }
            ]
        },
    )
    assert second.status_code == 201, second.text
    with db_module.get_connection() as connection:
        row = connection.execute(
            """
            SELECT id, priority, queue_mode, guidance_hypotheses_json,
                   cross_file_triggers_json
            FROM code_analysis_queue WHERE file_id = ?
            """,
            (file_row["id"],),
        ).fetchone()
    assert row["priority"] == 70
    assert row["queue_mode"] == "trigger"
    assert json.loads(row["guidance_hypotheses_json"]) == [
        "first guidance",
        "second guidance",
    ]
    assert {entry["reason"] for entry in json.loads(row["cross_file_triggers_json"])} == {
        "first trigger",
        "second trigger",
    }

    initial = client.post(
        f"{base}/analysis-queue",
        json={"items": [{"file_id": file_row["id"], "priority": 70}]},
    )
    assert initial.status_code == 201, initial.text
    assert initial.json()["conflicts"] == 1
    with db_module.get_connection() as connection:
        protected = connection.execute(
            "SELECT id, queue_mode, cross_file_triggers_json FROM code_analysis_queue WHERE file_id = ?",
            (file_row["id"],),
        ).fetchone()
    assert protected["id"] == row["id"]
    assert protected["queue_mode"] == "trigger"
    assert len(json.loads(protected["cross_file_triggers_json"])) == 2


def test_trigger_requeue_rejects_unclassified_and_mismatched_priority(
    client, isolate_settings
):
    engagement_key, _, files = _seed_priority_contract_files(
        client, isolate_settings, "trigger-reject"
    )
    file_row = files[0]
    endpoint = (
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/requeue"
    )
    unclassified = client.post(
        endpoint, json={"items": [{"file_id": file_row["id"]}]}
    )
    assert unclassified.status_code == 409, unclassified.text
    _classify_file(client, engagement_key, int(file_row["id"]), "high", 70)
    mismatched = client.post(
        endpoint,
        json={"items": [{"file_id": file_row["id"], "priority": 71}]},
    )
    assert mismatched.status_code == 409, mismatched.text
    with db_module.get_connection() as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM code_analysis_queue WHERE file_id = ?",
            (file_row["id"],),
        ).fetchone()[0] == 0


def test_concurrent_trigger_requeue_serializes_to_one_merged_active_row(
    client, isolate_settings
):
    engagement_key, _, files = _seed_priority_contract_files(
        client, isolate_settings, "trigger-race"
    )
    file_row = files[0]
    _classify_file(client, engagement_key, int(file_row["id"]), "high", 70)
    engagement_id = client.get(f"/engagements/{engagement_key}").json()["id"]

    def submit(reason: str):
        return code_analysis.requeue_triggered_files(
            engagement_id,
            [{"file_id": file_row["id"], "reason": reason}],
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = [
            future.result(timeout=5)
            for future in (
                pool.submit(submit, "race-a"),
                pool.submit(submit, "race-b"),
            )
        ]
    assert sorted(result["inserted"] for result in results) == [0, 1]
    with db_module.get_connection() as connection:
        rows = connection.execute(
            """
            SELECT priority, status, queue_mode, cross_file_triggers_json
            FROM code_analysis_queue WHERE file_id = ?
            """,
            (file_row["id"],),
        ).fetchall()
    assert len(rows) == 1
    assert (rows[0]["priority"], rows[0]["status"], rows[0]["queue_mode"]) == (
        70,
        "pending",
        "trigger",
    )
    assert {entry["reason"] for entry in json.loads(rows[0]["cross_file_triggers_json"])} == {
        "race-a",
        "race-b",
    }


def test_concurrent_initial_and_trigger_writers_keep_one_trigger_protected_row(
    client, isolate_settings
):
    engagement_key, _, files = _seed_priority_contract_files(
        client, isolate_settings, "trigger-initial-race"
    )
    file_row = files[0]
    _classify_file(client, engagement_key, int(file_row["id"]), "high", 70)
    engagement_id = client.get(f"/engagements/{engagement_key}").json()["id"]
    barrier = Barrier(2)

    def submit_initial():
        barrier.wait(timeout=5)
        return code_analysis.bulk_create_queue_items(
            engagement_id,
            [{"file_id": file_row["id"], "priority": 70}],
        )

    def submit_trigger():
        barrier.wait(timeout=5)
        return code_analysis.requeue_triggered_files(
            engagement_id,
            [{"file_id": file_row["id"], "reason": "race trigger"}],
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        initial_future = pool.submit(submit_initial)
        trigger_future = pool.submit(submit_trigger)
        initial_result = initial_future.result(timeout=5)
        trigger_result = trigger_future.result(timeout=5)

    assert initial_result["inserted"] + trigger_result["inserted"] == 1
    with db_module.get_connection() as connection:
        rows = connection.execute(
            """
            SELECT queue_mode, cross_file_triggers_json
            FROM code_analysis_queue
            WHERE file_id = ? AND status IN ('pending', 'processing')
            """,
            (file_row["id"],),
        ).fetchall()
    assert len(rows) == 1
    assert rows[0]["queue_mode"] == "trigger"
    assert json.loads(rows[0]["cross_file_triggers_json"])[0]["reason"] == "race trigger"


def test_fetch_quarantines_multiple_active_current_generation_attempts(
    client, isolate_settings
):
    engagement_key, repo, file_row = _seed_queue_contract_file(
        client, isolate_settings, "legacy-duplicate-fetch"
    )
    base = f"/engagements/{engagement_key}/assessment/code"
    current_generation = client.get(f"{base}/repos/{repo['id']}").json()[
        "active_generation"
    ]
    with db_module.get_connection() as connection:
        ids = [
            int(
                connection.execute(
                    """
                    INSERT INTO code_analysis_queue (
                        engagement_id, file_id, priority, status, repo_generation,
                        queue_mode
                    ) VALUES ((SELECT id FROM engagements WHERE key = ?), ?, 80,
                              'pending', ?, 'initial')
                    RETURNING id
                    """,
                        (engagement_key, file_row["id"], current_generation),
                ).fetchone()[0]
            )
            for _ in range(2)
        ]
    fetched = client.post(
        f"{base}/analysis-queue/fetch",
        json={"limit": 10, "agent_name": "latest-only"},
    )
    assert fetched.status_code == 200, fetched.text
    assert fetched.json() == []
    with db_module.get_connection() as connection:
        states = [
            tuple(row)
            for row in connection.execute(
                "SELECT id, status FROM code_analysis_queue WHERE file_id = ? ORDER BY id",
                (file_row["id"],),
                ).fetchall()
        ]
    assert states == [(ids[0], "pending"), (ids[1], "pending")]
    stats = client.get(f"{base}/analysis-queue/stats").json()
    assert stats["pending"] == 0
    assert stats["total"] == 0
    assert stats["invalid_active_history"] == 1, stats


def test_latest_failed_reanalysis_blocks_older_successful_receipt(
    client, isolate_settings
):
    engagement_key, _, file_row = _seed_queue_contract_file(
        client, isolate_settings, "latest-reanalysis-error"
    )
    base = f"/engagements/{engagement_key}/assessment/code"
    initial = _claim_file_for_analysis(
        client, engagement_key, int(file_row["id"]), priority=80
    )
    result = client.post(
        f"{base}/analysis-results",
        json=_owned(
            initial,
            queue_item_id=initial["id"],
            disposition="clean",
            function_name="parse",
            evidence="reviewed current source",
        ),
    )
    assert result.status_code == 201, result.text
    done = client.post(
        f"{base}/analysis-queue/done",
        json=_owned(
            initial,
            item_ids=[initial["id"]],
            disposition="clean",
            notes="initial review complete",
            cwe_coverage=_network_input_coverage(default_effort=80),
        ),
    )
    assert done.status_code == 200, done.text
    assert client.get(f"{base}/coverage").json()["by_classification"]["critical"][
        "analyzed"
    ] == 1

    reread = _claim_file_for_reanalysis(
        client,
        engagement_key,
        int(file_row["id"]),
        reason="independent adversarial reread",
        priority=80,
        agent_name="reread-worker",
    )
    failed = client.post(
        f"{base}/analysis-queue/error",
        json=_owned(reread, item_ids=[reread["id"]], notes="worker failed"),
    )
    assert failed.status_code == 200, failed.text

    stats = client.get(f"{base}/analysis-queue/stats").json()
    assert stats["error"] == 1
    assert stats["done"] == 0
    coverage = client.get(f"{base}/coverage").json()
    assert coverage["by_classification"]["critical"]["analyzed"] == 0
    assert coverage["gate"]["passed"] is False
    assert client.get(f"{base}/files/{file_row['id']}").json()[
        "analysis_status"
    ] == "in_progress"


@pytest.mark.parametrize("older_status", ["error", "needs_context"])
def test_readiness_ignores_superseded_blocked_attempt_after_latest_done(
    client, isolate_settings, older_status
):
    engagement_key, repo, file_row = _seed_queue_contract_file(
        client, isolate_settings, f"readiness-latest-{older_status}"
    )
    base = f"/engagements/{engagement_key}/assessment/code"
    current_generation = client.get(f"{base}/repos/{repo['id']}").json()[
        "active_generation"
    ]
    with db_module.get_connection() as connection:
        connection.execute(
            """
            INSERT INTO code_analysis_queue (
                engagement_id, file_id, priority, status, repo_generation
            ) VALUES ((SELECT id FROM engagements WHERE key = ?), ?, 80, ?, ?)
            """,
            (engagement_key, file_row["id"], older_status, current_generation),
        )
        connection.execute(
            """
            INSERT INTO code_analysis_queue (
                engagement_id, file_id, priority, status, disposition,
                skip_reason, cwe_coverage_json, repo_generation
            ) VALUES ((SELECT id FROM engagements WHERE key = ?), ?, 80, 'done',
                      'skipped', 'test-fixture', '[]', ?)
            """,
            (engagement_key, file_row["id"], current_generation),
        )

    readiness = client.get(
        f"{base}/readiness?target_phase=verify-variant"
    ).json()
    blocker_codes = {blocker["code"] for blocker in readiness["blockers"]}
    assert "analysis_queue_active" not in blocker_codes
    assert "needs_context_unresolved" not in blocker_codes


@pytest.mark.parametrize("resolved_disposition", ["clean", "finding"])
def test_verify_variant_readiness_blocks_only_current_suspicious_attempt(
    client, isolate_settings, capsys, resolved_disposition
):
    engagement_key, repo, file_row = _seed_queue_contract_file(
        client, isolate_settings, f"suspicious-resolution-{resolved_disposition}"
    )
    base = f"/engagements/{engagement_key}/assessment/code"

    suspicious = _claim_file_for_analysis(
        client,
        engagement_key,
        int(file_row["id"]),
        priority=80,
        agent_name="suspicious-worker",
    )
    result = client.post(
        f"{base}/analysis-results",
        json=_owned(
            suspicious,
            queue_item_id=suspicious["id"],
            disposition="suspicious",
            function_name="parse",
            evidence="The current sealed source still has an unresolved candidate path.",
        ),
    )
    assert result.status_code == 201, result.text
    completed = client.post(
        f"{base}/analysis-queue/done",
        json=_owned(
            suspicious,
            item_ids=[suspicious["id"]],
            disposition="suspicious",
            notes="Candidate requires a finding or clean terminal reanalysis.",
            cwe_coverage=_network_input_coverage(default_effort=80),
        ),
    )
    assert completed.status_code == 200, completed.text

    hunt = client.get(f"{base}/readiness?target_phase=hunt").json()
    assert "unresolved_suspicious_analysis" not in {
        blocker["code"] for blocker in hunt["blockers"]
    }

    blocked = client.get(
        f"{base}/readiness?target_phase=verify-variant"
    ).json()
    suspicious_blockers = [
        blocker
        for blocker in blocked["blockers"]
        if blocker["code"] == "unresolved_suspicious_analysis"
    ]
    assert suspicious_blockers == [
        {
            "code": "unresolved_suspicious_analysis",
            "message": "Repository has 1 current suspicious analysis attempt(s) requiring a finding or clean terminal reanalysis.",
            "overrideable": False,
            "repo_id": repo["id"],
        }
    ]

    from assess.commands import code_coverage as code_coverage_command

    code_coverage_command._print_transition_readiness("verify-variant", blocked)
    rendered = capsys.readouterr().out
    assert "Transition Readiness (verify-variant): BLOCKED" in rendered
    assert "[unresolved_suspicious_analysis]" in rendered
    assert "[integrity; non-overrideable]" in rendered

    report_endpoint = f"/engagements/{engagement_key}/assessment/report-readiness"
    blocked_report = client.get(report_endpoint)
    assert blocked_report.status_code == 200, blocked_report.text
    assert [
        blocker
        for blocker in blocked_report.json()["blockers"]
        if blocker["kind"] == "unresolved_suspicious_analysis"
    ] == [
        {
            "kind": "unresolved_suspicious_analysis",
            "repo_id": repo["id"],
            "suspicious_count": 1,
            "detail": (
                "repository has 1 current suspicious code-analysis attempt(s); "
                "promote each to a finding or complete a clean terminal reanalysis"
            ),
        }
    ]
    from assess.lib.coverage_checks import render_report_readiness

    report_ready, _, report_blocker_lines, _ = render_report_readiness(
        blocked_report.json()
    )
    assert report_ready is False
    assert any(
        "unresolved_suspicious_analysis" in line
        for line in report_blocker_lines
    )

    resolved = _claim_file_for_reanalysis(
        client,
        engagement_key,
        int(file_row["id"]),
        reason=f"Resolve the prior candidate as {resolved_disposition}.",
        priority=80,
        agent_name="resolution-worker",
    )
    if resolved_disposition == "finding":
        _create_code_parent_finding(
            client,
            engagement_key,
            int(repo["id"]),
            slug="CH-901",
        )
        finding_result = client.post(
            f"{base}/analysis-results",
            json=_owned(
                resolved,
                queue_item_id=resolved["id"],
                disposition="finding",
                function_name="parse",
                evidence="The candidate is now promoted to a durable finding result.",
                finding_slug="CH-901",
            ),
        )
        assert finding_result.status_code == 201, finding_result.text
    resolved_done = client.post(
        f"{base}/analysis-queue/done",
        json=_owned(
            resolved,
            item_ids=[resolved["id"]],
            disposition=resolved_disposition,
            notes="Independent terminal reanalysis resolved the candidate.",
            cwe_coverage=_network_input_coverage(default_effort=80),
        ),
    )
    assert resolved_done.status_code == 200, resolved_done.text
    after_resolution = client.get(
        f"{base}/readiness?target_phase=verify-variant"
    ).json()
    assert "unresolved_suspicious_analysis" not in {
        blocker["code"] for blocker in after_resolution["blockers"]
    }
    after_resolution_report = client.get(report_endpoint)
    assert after_resolution_report.status_code == 200, after_resolution_report.text
    assert "unresolved_suspicious_analysis" not in {
        blocker["kind"] for blocker in after_resolution_report.json()["blockers"]
    }

    # A source-generation advance turns both prior attempts into retained history.
    # Neither an old-generation suspicious row nor a same-generation superseded
    # suspicious row may poison readiness for the new sealed source identity.
    current_files = client.get(
        f"{base}/files?repo_id={repo['id']}&limit=20&include_header_snippet=true"
    ).json()["items"]
    manifest_fields = {
        "file_path",
        "language",
        "loc",
        "file_hash",
        "header_snippet",
        "git_churn_score",
        "has_past_cve_fix",
    }
    manifest = [{key: row[key] for key in manifest_fields} for row in current_files]
    manifest[0]["file_hash"] = _source_hash(
        f"{repo['repo_key']}-suspicious-resolution-source-change"
    )
    next_snapshot = _verified_repo_payload(
        client,
        engagement_key,
        str(repo["repo_key"]),
        manifest,
        source_origin_path=f"/tmp/{repo['repo_key']}-next-generation",
    )
    started = client.post(f"{base}/repos/refresh/start", json=next_snapshot)
    assert started.status_code == 201, started.text
    token = started.json()["refresh_token"]
    staged = client.post(
        f"{base}/repos/{repo['id']}/refresh/files",
        json={"refresh_token": token, "files": manifest},
    )
    assert staged.status_code == 200, staged.text
    committed = client.post(
        f"{base}/repos/{repo['id']}/refresh/commit",
        json={"refresh_token": token, "manifest_complete": True},
    )
    assert committed.status_code == 200, committed.text
    assert committed.json()["generation_changed"] is True
    assert committed.json()["repo_generation"] > suspicious["repo_generation"]

    after_generation_change = client.get(
        f"{base}/readiness?target_phase=verify-variant"
    ).json()
    assert "unresolved_suspicious_analysis" not in {
        blocker["code"] for blocker in after_generation_change["blockers"]
    }
    after_generation_report = client.get(report_endpoint)
    assert after_generation_report.status_code == 200, after_generation_report.text
    assert "unresolved_suspicious_analysis" not in {
        blocker["kind"] for blocker in after_generation_report.json()["blockers"]
    }


@pytest.mark.parametrize("resolved_disposition", ["clean", "finding"])
def test_suspicious_obligation_survives_nonsemantic_reanalysis_states_until_resolution(
    client, isolate_settings, resolved_disposition
):
    engagement_key, repo, file_row = _seed_queue_contract_file(
        client,
        isolate_settings,
        f"suspicious-carry-{resolved_disposition}",
    )
    base = f"/engagements/{engagement_key}/assessment/code"
    report_endpoint = (
        f"/engagements/{engagement_key}/assessment/report-readiness"
    )

    def assert_suspicious_obligation() -> None:
        code_blockers = client.get(
            f"{base}/readiness?target_phase=verify-variant"
        ).json()["blockers"]
        assert [
            blocker["code"]
            for blocker in code_blockers
            if blocker["code"] == "unresolved_suspicious_analysis"
        ] == ["unresolved_suspicious_analysis"]
        report_blockers = client.get(report_endpoint).json()["blockers"]
        assert [
            blocker["kind"]
            for blocker in report_blockers
            if blocker["kind"] == "unresolved_suspicious_analysis"
        ] == ["unresolved_suspicious_analysis"]

    suspicious = _claim_file_for_analysis(
        client,
        engagement_key,
        int(file_row["id"]),
        priority=80,
        agent_name="suspicious-carry-worker",
    )
    suspicious_result = client.post(
        f"{base}/analysis-results",
        json=_owned(
            suspicious,
            queue_item_id=suspicious["id"],
            disposition="suspicious",
            function_name="parse",
            evidence="Current source contains an unresolved candidate path.",
        ),
    )
    assert suspicious_result.status_code == 201, suspicious_result.text
    suspicious_done = client.post(
        f"{base}/analysis-queue/done",
        json=_owned(
            suspicious,
            item_ids=[suspicious["id"]],
            disposition="suspicious",
            notes="Targeted semantic reanalysis remains required.",
            cwe_coverage=_network_input_coverage(default_effort=80),
        ),
    )
    assert suspicious_done.status_code == 200, suspicious_done.text
    assert_suspicious_obligation()

    queued = client.post(
        f"{base}/analysis-queue",
        json={
            "mode": "reanalysis",
            "reason": "Exercise every nonsemantic successor state.",
            "items": [
                {
                    "file_id": file_row["id"],
                    "priority": 80,
                    "supersedes": suspicious["id"],
                }
            ],
        },
    )
    assert queued.status_code == 201, queued.text
    reanalysis_id = queued.json()["outcomes"][0]["queue_item_id"]
    assert_suspicious_obligation()  # pending

    fetched = client.post(
        f"{base}/analysis-queue/fetch",
        json={
            "limit": 1,
            "agent_name": "carry-reanalysis-worker",
            "item_ids": [reanalysis_id],
        },
    )
    assert fetched.status_code == 200, fetched.text
    reanalysis = fetched.json()[0]
    assert_suspicious_obligation()  # processing

    errored = client.post(
        f"{base}/analysis-queue/error",
        json=_owned(
            reanalysis,
            item_ids=[reanalysis_id],
            notes="Transient worker failure.",
        ),
    )
    assert errored.status_code == 200, errored.text
    assert_suspicious_obligation()  # error

    retry_error = client.post(
        f"{base}/analysis-queue/retry-error",
        json={"item_ids": [reanalysis_id], "reason": "Retry with context."},
    )
    assert retry_error.status_code == 200, retry_error.text
    reanalysis = client.post(
        f"{base}/analysis-queue/fetch",
        json={
            "limit": 1,
            "agent_name": "carry-context-worker",
            "item_ids": [reanalysis_id],
        },
    ).json()[0]
    needs_context = client.post(
        f"{base}/analysis-queue/needs-context",
        json=_owned(
            reanalysis,
            item_ids=[reanalysis_id],
            expansion_request={"request": "Need the generated wrapper body."},
        ),
    )
    assert needs_context.status_code == 200, needs_context.text
    assert_suspicious_obligation()  # needs_context

    retry_context = client.post(
        f"{base}/analysis-queue/retry-needs-context",
        json={
            "item_ids": [reanalysis_id],
            "reason": "Generated wrapper source supplied.",
        },
    )
    assert retry_context.status_code == 200, retry_context.text
    reanalysis = client.post(
        f"{base}/analysis-queue/fetch",
        json={
            "limit": 1,
            "agent_name": "carry-skip-worker",
            "item_ids": [reanalysis_id],
        },
    ).json()[0]
    skipped = client.post(
        f"{base}/analysis-queue/done",
        json=_owned(
            reanalysis,
            item_ids=[reanalysis_id],
            disposition="skipped",
            skip_reason="test-fixture",
        ),
    )
    assert skipped.status_code == 200, skipped.text
    assert_suspicious_obligation()  # skipped

    resolution = _claim_file_for_reanalysis(
        client,
        engagement_key,
        int(file_row["id"]),
        reason=f"Resolve carried candidate as {resolved_disposition}.",
        priority=80,
        agent_name="carry-resolution-worker",
    )
    if resolved_disposition == "finding":
        _create_code_parent_finding(
            client,
            engagement_key,
            int(repo["id"]),
            slug="CH-902",
        )
        finding_result = client.post(
            f"{base}/analysis-results",
            json=_owned(
                resolution,
                queue_item_id=resolution["id"],
                disposition="finding",
                function_name="parse",
                evidence="The carried candidate is a current durable finding.",
                finding_slug="CH-902",
            ),
        )
        assert finding_result.status_code == 201, finding_result.text
    resolved = client.post(
        f"{base}/analysis-queue/done",
        json=_owned(
            resolution,
            item_ids=[resolution["id"]],
            disposition=resolved_disposition,
            notes="Semantic reanalysis resolved the carried suspicious obligation.",
            cwe_coverage=_network_input_coverage(default_effort=80),
        ),
    )
    assert resolved.status_code == 200, resolved.text
    assert "unresolved_suspicious_analysis" not in {
        blocker["code"]
        for blocker in client.get(
            f"{base}/readiness?target_phase=verify-variant"
        ).json()["blockers"]
    }
    assert "unresolved_suspicious_analysis" not in {
        blocker["kind"] for blocker in client.get(report_endpoint).json()["blockers"]
    }


def _insert_malformed_terminal_attempt(
    engagement_key: str,
    file_id: int,
    repo_generation: int,
    disposition: str,
    *,
    finding_slug: str = "",
) -> int:
    with db_module.get_connection() as connection:
        queue_id = int(
            connection.execute(
                """
                INSERT INTO code_analysis_queue (
                    engagement_id, file_id, priority, status, disposition,
                    analysis_notes, skip_reason, cwe_coverage_json,
                    repo_generation, queue_mode
                ) VALUES (
                    (SELECT id FROM engagements WHERE key = ?), ?, 80, 'done', ?,
                    ?, ?, ?, ?, 'reanalysis'
                )
                RETURNING id
                """,
                (
                    engagement_key,
                    file_id,
                    disposition,
                    "legacy terminal notes" if disposition == "clean" else "",
                    "test-fixture" if disposition == "skipped" else "",
                    (
                        "[]"
                        if disposition == "skipped"
                        else json.dumps(_network_input_coverage(default_effort=80))
                    ),
                    repo_generation,
                ),
            ).fetchone()[0]
        )
        if disposition in {"finding", "suspicious"}:
            connection.execute(
                """
                INSERT INTO code_analysis_results (
                    engagement_id, queue_item_id, file_id, disposition,
                    evidence, finding_slug, repo_generation
                ) VALUES (
                    (SELECT id FROM engagements WHERE key = ?), ?, ?, ?, ?, ?, ?
                )
                """,
                (
                    engagement_key,
                    queue_id,
                    file_id,
                    disposition,
                    "forged legacy evidence",
                    finding_slug,
                    repo_generation,
                ),
            )
    return queue_id


@pytest.mark.parametrize("malformed_successor", ["clean", "finding", "skipped"])
def test_malformed_terminal_successor_cannot_resolve_suspicious_obligation(
    client, isolate_settings, malformed_successor
):
    engagement_key, repo, file_row = _seed_queue_contract_file(
        client,
        isolate_settings,
        f"malformed-successor-{malformed_successor}",
    )
    base = f"/engagements/{engagement_key}/assessment/code"
    suspicious = _claim_file_for_analysis(
        client,
        engagement_key,
        int(file_row["id"]),
        priority=80,
        agent_name="legitimate-suspicious-worker",
    )
    recorded = client.post(
        f"{base}/analysis-results",
        json=_owned(
            suspicious,
            queue_item_id=suspicious["id"],
            disposition="suspicious",
            function_name="parse",
            evidence="A legitimate claimed review found an unresolved candidate.",
        ),
    )
    assert recorded.status_code == 201, recorded.text
    completed = client.post(
        f"{base}/analysis-queue/done",
        json=_owned(
            suspicious,
            item_ids=[suspicious["id"]],
            disposition="suspicious",
            notes="Legitimate suspicious terminal review.",
            cwe_coverage=_network_input_coverage(default_effort=80),
        ),
    )
    assert completed.status_code == 200, completed.text

    finding_slug = ""
    if malformed_successor == "finding":
        _create_code_parent_finding(
            client,
            engagement_key,
            int(repo["id"]),
            slug="CH-920",
        )
        finding_slug = "CH-920"
    repo_generation = int(
        client.get(f"{base}/repos/{repo['id']}").json()["active_generation"]
    )
    forged_id = _insert_malformed_terminal_attempt(
        engagement_key,
        int(file_row["id"]),
        repo_generation,
        malformed_successor,
        finding_slug=finding_slug,
    )

    code_blockers = client.get(
        f"{base}/readiness?target_phase=verify-variant"
    ).json()["blockers"]
    assert "unresolved_suspicious_analysis" in {
        blocker["code"] for blocker in code_blockers
    }
    report_blockers = client.get(
        f"/engagements/{engagement_key}/assessment/report-readiness"
    ).json()["blockers"]
    assert "unresolved_suspicious_analysis" in {
        blocker["kind"] for blocker in report_blockers
    }
    with db_module.get_connection() as connection:
        assert connection.execute(
            "SELECT status FROM code_analysis_queue WHERE id = ?",
            (forged_id,),
        ).fetchone()[0] == "done"


@pytest.mark.parametrize(
    "malformed_disposition",
    ["clean", "finding", "suspicious", "skipped"],
)
def test_malformed_terminal_attempt_cannot_account_for_admitted_file_review(
    client, isolate_settings, malformed_disposition
):
    engagement_key, repo, file_row = _seed_queue_contract_file(
        client,
        isolate_settings,
        f"malformed-accounting-{malformed_disposition}",
    )
    finding_slug = ""
    if malformed_disposition == "finding":
        _create_code_parent_finding(
            client,
            engagement_key,
            int(repo["id"]),
            slug="CH-921",
        )
        finding_slug = "CH-921"
    base = f"/engagements/{engagement_key}/assessment/code"
    repo_generation = int(
        client.get(f"{base}/repos/{repo['id']}").json()["active_generation"]
    )
    _insert_malformed_terminal_attempt(
        engagement_key,
        int(file_row["id"]),
        repo_generation,
        malformed_disposition,
        finding_slug=finding_slug,
    )

    readiness = client.get(
        f"{base}/readiness?target_phase=verify-variant"
    ).json()
    unaccounted = next(
        blocker
        for blocker in readiness["blockers"]
        if blocker["code"] == "admitted_files_unaccounted"
    )
    assert unaccounted["message"] == (
        "Repository has 2 admitted file(s) without a current terminal review "
        "or evidence-based structured skip."
    )


def test_suspicious_semantic_ordering_clean_then_suspicious_then_skip(
    client, isolate_settings
):
    engagement_key, _, file_row = _seed_queue_contract_file(
        client,
        isolate_settings,
        "semantic-ordering",
    )
    base = f"/engagements/{engagement_key}/assessment/code"
    clean = _claim_file_for_analysis(
        client,
        engagement_key,
        int(file_row["id"]),
        priority=80,
        agent_name="ordering-clean-worker",
    )
    clean_done = client.post(
        f"{base}/analysis-queue/done",
        json=_owned(
            clean,
            item_ids=[clean["id"]],
            disposition="clean",
            notes="Initial semantic review found no candidate.",
            cwe_coverage=_network_input_coverage(default_effort=80),
        ),
    )
    assert clean_done.status_code == 200, clean_done.text
    assert "unresolved_suspicious_analysis" not in {
        blocker["code"]
        for blocker in client.get(
            f"{base}/readiness?target_phase=verify-variant"
        ).json()["blockers"]
    }

    suspicious = _claim_file_for_reanalysis(
        client,
        engagement_key,
        int(file_row["id"]),
        reason="New evidence reopens the candidate.",
        priority=80,
        agent_name="ordering-suspicious-worker",
    )
    recorded = client.post(
        f"{base}/analysis-results",
        json=_owned(
            suspicious,
            queue_item_id=suspicious["id"],
            disposition="suspicious",
            function_name="parse",
            evidence="New evidence creates an unresolved semantic candidate.",
        ),
    )
    assert recorded.status_code == 201, recorded.text
    suspicious_done = client.post(
        f"{base}/analysis-queue/done",
        json=_owned(
            suspicious,
            item_ids=[suspicious["id"]],
            disposition="suspicious",
            notes="Reopened by a later semantic review.",
            cwe_coverage=_network_input_coverage(default_effort=80),
        ),
    )
    assert suspicious_done.status_code == 200, suspicious_done.text

    skipped = _claim_file_for_reanalysis(
        client,
        engagement_key,
        int(file_row["id"]),
        reason="A later nonsemantic pass cannot resolve the candidate.",
        priority=80,
        agent_name="ordering-skip-worker",
    )
    skipped_done = client.post(
        f"{base}/analysis-queue/done",
        json=_owned(
            skipped,
            item_ids=[skipped["id"]],
            disposition="skipped",
            skip_reason="test-fixture",
        ),
    )
    assert skipped_done.status_code == 200, skipped_done.text
    assert "unresolved_suspicious_analysis" in {
        blocker["code"]
        for blocker in client.get(
            f"{base}/readiness?target_phase=verify-variant"
        ).json()["blockers"]
    }
    assert "unresolved_suspicious_analysis" in {
        blocker["kind"]
        for blocker in client.get(
            f"/engagements/{engagement_key}/assessment/report-readiness"
        ).json()["blockers"]
    }


def test_finding_analysis_result_requires_current_reportable_root_file_finding(
    client, isolate_settings
):
    engagement_key = "2026-08-06-finding-result-binding"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="finding-result-primary")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser = next(row for row in files if row["file_path"] == "src/parser.py")
    _classify_file(client, engagement_key, int(parser["id"]), "critical", 100)
    _create_code_parent_finding(
        client,
        engagement_key,
        int(repo["id"]),
        slug="CH-910",
    )
    refreshed = _refresh_one_file_metadata(
        client,
        engagement_key,
        int(repo["id"]),
        int(parser["id"]),
        file_hash=_source_hash("finding-result-current-source"),
    )
    parser = next(row for row in refreshed if row["file_path"] == "src/parser.py")
    _classify_file(client, engagement_key, int(parser["id"]), "critical", 100)
    _create_code_parent_finding(
        client,
        engagement_key,
        int(repo["id"]),
        slug="CH-911",
    )
    _create_code_parent_finding(
        client,
        engagement_key,
        int(repo["id"]),
        slug="CV-912",
        source_name="code-variant-hunter",
        allow_remint=True,
        links=[
            {
                "link_kind": "variant_of",
                "target_kind": "finding",
                "target_ref": "CH-911",
            }
        ],
    )
    _create_code_parent_finding(
        client,
        engagement_key,
        int(repo["id"]),
        slug="CH-913",
        allow_remint=True,
    )
    with db_module.get_connection() as connection:
        connection.execute(
            """
            UPDATE assessment_findings
            SET status = 'false_positive'
            WHERE engagement_id = (
                SELECT id FROM engagements WHERE key = ?
            ) AND slug = ?
            """,
            (engagement_key, "CH-913"),
        )

    other_repo = _create_repo(
        client,
        engagement_key,
        repo_key="finding-result-secondary",
    )
    _create_files(client, engagement_key, int(other_repo["id"]))
    _create_code_parent_finding(
        client,
        engagement_key,
        int(other_repo["id"]),
        slug="CH-914",
        line=14,
        allow_remint=True,
    )

    claim = _claim_file_for_analysis(
        client,
        engagement_key,
        int(parser["id"]),
        priority=100,
        agent_name="finding-binding-worker",
    )
    base = f"/engagements/{engagement_key}/assessment/code"
    invalid_cases = [
        ("", 400, "finding_slug"),
        ("CH-999", 409, "unknown"),
        ("CH-910", 409, "current"),
        ("CH-914", 409, "same repository"),
        ("CV-912", 409, "root"),
        ("CH-913", 409, "reportable"),
    ]
    for finding_slug, expected_status, expected_detail in invalid_cases:
        rejected = client.post(
            f"{base}/analysis-results",
            json=_owned(
                claim,
                queue_item_id=claim["id"],
                disposition="finding",
                function_name="parse",
                evidence="Evidence alone cannot establish durable finding linkage.",
                finding_slug=finding_slug,
            ),
        )
        assert rejected.status_code == expected_status, (
            finding_slug,
            rejected.text,
        )
        assert expected_detail in rejected.json()["detail"].lower()

    assert client.get(f"{base}/analysis-results?file_id={parser['id']}").json() == []
    accepted = client.post(
        f"{base}/analysis-results",
        json=_owned(
            claim,
            queue_item_id=claim["id"],
            disposition="finding",
            function_name="parse",
            evidence="Current source evidence links to the durable root finding.",
            finding_slug="CH-911",
        ),
    )
    assert accepted.status_code == 201, accepted.text
    assert accepted.json()["finding_slug"] == "CH-911"


@pytest.mark.parametrize("priority", [True, 80.5, "80"])
def test_queue_priority_requires_strict_integer_at_api(
    client, isolate_settings, priority
):
    engagement_key, _, file_row = _seed_queue_contract_file(
        client, isolate_settings, f"strict-{type(priority).__name__}"
    )
    response = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue",
        json={"items": [{"file_id": file_row["id"], "priority": priority}]},
    )
    assert response.status_code == 422, response.text


@pytest.mark.parametrize(
    "invalid_id_factory",
    [lambda file_id: True, lambda file_id: file_id + 0.5, lambda file_id: str(file_id)],
    ids=["bool", "fractional", "string"],
)
def test_bulk_classify_requires_strict_integer_file_id(
    client, isolate_settings, invalid_id_factory
):
    engagement_key, _, files = _seed_priority_contract_files(
        client, isolate_settings, f"classify-id-{invalid_id_factory.__name__}"
    )
    file_id = int(files[0]["id"])

    response = client.post(
        f"/engagements/{engagement_key}/assessment/code/files/bulk-classify",
        json={
            "classifications": [
                _classification_record(
                    invalid_id_factory(file_id),
                    "high",
                    70,
                )
            ]
        },
    )

    assert response.status_code == 422, response.text


@pytest.mark.parametrize(
    "invalid_id_factory",
    [lambda file_id: True, lambda file_id: file_id + 0.5, lambda file_id: str(file_id)],
    ids=["bool", "fractional", "string"],
)
def test_queue_create_requires_strict_integer_file_id(
    client, isolate_settings, invalid_id_factory
):
    engagement_key, _, file_row = _seed_queue_contract_file(
        client, isolate_settings, f"queue-id-{invalid_id_factory.__name__}"
    )
    file_id = int(file_row["id"])

    response = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue",
        json={
            "items": [
                {"file_id": invalid_id_factory(file_id), "priority": 80}
            ]
        },
    )

    assert response.status_code == 422, response.text


def _seed_superseded_active_queue_history(
    engagement_key: str,
    file_id: int,
    repo_generation: int,
    *,
    older_status: str = "pending",
    assigned_agent: str = "",
    lease_token: str = "",
) -> tuple[int, int]:
    with db_module.get_connection() as connection:
        active_id = int(
            connection.execute(
                """
                INSERT INTO code_analysis_queue (
                    engagement_id, file_id, priority, status, repo_generation,
                    queue_mode, assigned_agent, lease_token, consumed_at
                ) VALUES ((SELECT id FROM engagements WHERE key = ?), ?, 70,
                          ?, ?, 'initial', ?, ?,
                          CASE WHEN ? = 'processing' THEN '2000-01-01T00:00:00Z' END)
                RETURNING id
                """,
                (
                    engagement_key,
                    file_id,
                    older_status,
                    repo_generation,
                    assigned_agent,
                    lease_token,
                    older_status,
                ),
            ).fetchone()[0]
        )
        latest_id = int(
            connection.execute(
                """
                INSERT INTO code_analysis_queue (
                    engagement_id, file_id, priority, status, disposition,
                    skip_reason, cwe_coverage_json, repo_generation, queue_mode
                ) VALUES ((SELECT id FROM engagements WHERE key = ?), ?, 70,
                          'done', 'skipped', 'test-fixture', '[]', ?, 'initial')
                RETURNING id
                """,
                (engagement_key, file_id, repo_generation),
            ).fetchone()[0]
        )
    return active_id, latest_id


def test_priority_change_rejects_superseded_active_queue_attempt(
    client, isolate_settings
):
    engagement_key, repo, files = _seed_priority_contract_files(
        client, isolate_settings, "priority-superseded-active"
    )
    file_id = int(files[0]["id"])
    base = f"/engagements/{engagement_key}/assessment/code"
    _classify_file(client, engagement_key, file_id, "high", 70)
    repo_generation = int(client.get(f"{base}/repos/{repo['id']}").json()["active_generation"])
    active_id, _ = _seed_superseded_active_queue_history(
        engagement_key,
        file_id,
        repo_generation,
    )

    response = client.patch(
        f"{base}/files/{file_id}", json={"analysis_priority": 75}
    )

    assert response.status_code == 409, response.text
    with db_module.get_connection() as connection:
        row = connection.execute(
            "SELECT priority, queue_mode, cross_file_triggers_json FROM code_analysis_queue WHERE id = ?",
            (active_id,),
        ).fetchone()
    assert tuple(row) == (70, "initial", "[]")
    assert client.get(f"{base}/files/{file_id}").json()["analysis_priority"] == 70


def test_initial_queue_create_rejects_superseded_active_queue_attempt(
    client, isolate_settings
):
    engagement_key, repo, files = _seed_priority_contract_files(
        client, isolate_settings, "initial-superseded-active"
    )
    file_id = int(files[0]["id"])
    base = f"/engagements/{engagement_key}/assessment/code"
    _classify_file(client, engagement_key, file_id, "high", 70)
    repo_generation = int(client.get(f"{base}/repos/{repo['id']}").json()["active_generation"])
    active_id, _ = _seed_superseded_active_queue_history(
        engagement_key,
        file_id,
        repo_generation,
    )

    response = client.post(
        f"{base}/analysis-queue",
        json={"items": [{"file_id": file_id, "priority": 70}]},
    )

    assert response.status_code == 201, response.text
    assert response.json()["conflicts"] == 1
    assert response.json()["outcomes"][0]["status"] == "superseded-active"
    with db_module.get_connection() as connection:
        row = connection.execute(
            "SELECT priority, queue_mode, cross_file_triggers_json FROM code_analysis_queue WHERE id = ?",
            (active_id,),
        ).fetchone()
    assert tuple(row) == (70, "initial", "[]")


@pytest.mark.parametrize(
    ("older_status", "endpoint", "payload"),
    [
        ("error", "retry-error", {"reason": "retry stale error"}),
        (
            "needs_context",
            "retry-needs-context",
            {"reason": "supply stale context"},
        ),
    ],
)
def test_queue_retry_rejects_superseded_exact_attempt_id(
    client, isolate_settings, older_status, endpoint, payload
):
    engagement_key, repo, files = _seed_priority_contract_files(
        client, isolate_settings, f"retry-superseded-{older_status}"
    )
    file_id = int(files[0]["id"])
    base = f"/engagements/{engagement_key}/assessment/code"
    _classify_file(client, engagement_key, file_id, "high", 70)
    repo_generation = int(client.get(f"{base}/repos/{repo['id']}").json()["active_generation"])
    older_id, _ = _seed_superseded_active_queue_history(
        engagement_key,
        file_id,
        repo_generation,
        older_status=older_status,
    )

    response = client.post(
        f"{base}/analysis-queue/{endpoint}",
        json={"item_ids": [older_id], **payload},
    )

    assert response.status_code == 409, response.text
    with db_module.get_connection() as connection:
        assert connection.execute(
            "SELECT status FROM code_analysis_queue WHERE id = ?", (older_id,)
        ).fetchone()[0] == older_status


@pytest.mark.parametrize(
    "operation",
    ["done", "error", "needs-context", "heartbeat", "analysis-result"],
)
def test_queue_lifecycle_rejects_superseded_processing_attempt_id(
    client, isolate_settings, operation
):
    engagement_key, repo, files = _seed_priority_contract_files(
        client, isolate_settings, f"lifecycle-superseded-{operation}"
    )
    file_id = int(files[0]["id"])
    base = f"/engagements/{engagement_key}/assessment/code"
    _classify_file(client, engagement_key, file_id, "high", 70)
    repo_generation = int(client.get(f"{base}/repos/{repo['id']}").json()["active_generation"])
    older_id, _ = _seed_superseded_active_queue_history(
        engagement_key,
        file_id,
        repo_generation,
        older_status="processing",
        assigned_agent="legacy-worker",
        lease_token="legacy-lease",
    )
    owned = {
        "agent_name": "legacy-worker",
        "lease_token": "legacy-lease",
    }
    if operation == "done":
        response = client.post(
            f"{base}/analysis-queue/done",
            json={
                "item_ids": [older_id],
                **owned,
                "disposition": "skipped",
                "skip_reason": "test-fixture",
            },
        )
    elif operation == "error":
        response = client.post(
            f"{base}/analysis-queue/error",
            json={"item_ids": [older_id], **owned, "notes": "stale error"},
        )
    elif operation == "needs-context":
        response = client.post(
            f"{base}/analysis-queue/needs-context",
            json={
                "item_ids": [older_id],
                **owned,
                "expansion_request": {"request": "stale context"},
            },
        )
    elif operation == "heartbeat":
        response = client.post(
            f"{base}/analysis-queue/heartbeat",
            json={"item_id": older_id, **owned},
        )
    else:
        response = client.post(
            f"{base}/analysis-results",
            json={
                "queue_item_id": older_id,
                "file_id": file_id,
                **owned,
                "disposition": "clean",
            },
        )

    assert response.status_code == 409, response.text
    with db_module.get_connection() as connection:
        assert connection.execute(
            "SELECT status FROM code_analysis_queue WHERE id = ?", (older_id,)
        ).fetchone()[0] == "processing"


def test_reset_stale_ignores_superseded_processing_attempt(
    client, isolate_settings
):
    engagement_key, repo, files = _seed_priority_contract_files(
        client, isolate_settings, "reset-superseded-processing"
    )
    file_id = int(files[0]["id"])
    base = f"/engagements/{engagement_key}/assessment/code"
    _classify_file(client, engagement_key, file_id, "high", 70)
    repo_generation = int(client.get(f"{base}/repos/{repo['id']}").json()["active_generation"])
    older_id, _ = _seed_superseded_active_queue_history(
        engagement_key,
        file_id,
        repo_generation,
        older_status="processing",
        assigned_agent="legacy-worker",
        lease_token="legacy-lease",
    )

    response = client.post(
        f"{base}/analysis-queue/reset-stale", json={"minutes": 1}
    )

    assert response.status_code == 200, response.text
    assert response.json()["reset"] == 0
    with db_module.get_connection() as connection:
        assert connection.execute(
            "SELECT status FROM code_analysis_queue WHERE id = ?", (older_id,)
        ).fetchone()[0] == "processing"


@pytest.mark.parametrize("recovery", ["retry-error", "reset-stale"])
def test_caller_spoofed_metadata_theme_cannot_bypass_priority_refresh(
    client, isolate_settings, recovery
):
    engagement_key, _, files = _seed_priority_contract_files(
        client, isolate_settings, f"spoofed-metadata-theme-{recovery}"
    )
    file_id = int(files[0]["id"])
    base = f"/engagements/{engagement_key}/assessment/code"
    _classify_file(client, engagement_key, file_id, "high", 70)
    queued = client.post(
        f"{base}/analysis-queue",
        json={
            "items": [
                {
                    "file_id": file_id,
                    "priority": 70,
                    "batch_theme": "metadata-refresh-review",
                }
            ]
        },
    )
    assert queued.status_code == 201, queued.text
    queue_id = int(queued.json()["outcomes"][0]["queue_item_id"])
    claimed = client.post(
        f"{base}/analysis-queue/fetch",
        json={
            "limit": 1,
            "agent_name": "spoof-test-worker",
            "item_ids": [queue_id],
        },
    ).json()[0]

    if recovery == "retry-error":
        errored = client.post(
            f"{base}/analysis-queue/error",
            json=_owned(claimed, item_ids=[queue_id], notes="transient failure"),
        )
        assert errored.status_code == 200, errored.text
        changed = client.patch(
            f"{base}/files/{file_id}", json={"analysis_priority": 75}
        )
        assert changed.status_code == 200, changed.text
        recovered = client.post(
            f"{base}/analysis-queue/retry-error",
            json={"item_ids": [queue_id], "reason": "retry"},
        )
        assert recovered.status_code == 200, recovered.text
    else:
        with db_module.get_connection() as connection:
            connection.execute(
                "UPDATE code_files SET analysis_priority = 75 WHERE id = ?",
                (file_id,),
            )
            connection.execute(
                """
                UPDATE code_analysis_queue
                SET consumed_at = '2000-01-01T00:00:00Z',
                    last_heartbeat_at = '2000-01-01T00:00:00Z'
                WHERE id = ?
                """,
                (queue_id,),
            )
        recovered = client.post(
            f"{base}/analysis-queue/reset-stale", json={"minutes": 1}
        )
        assert recovered.status_code == 200, recovered.text
        assert recovered.json()["reset"] == 1

    with db_module.get_connection() as connection:
        row = connection.execute(
            "SELECT priority, queue_mode, batch_theme FROM code_analysis_queue WHERE id = ?",
            (queue_id,),
        ).fetchone()
    assert tuple(row) == (75, "initial", "metadata-refresh-review")


@pytest.mark.parametrize("invalid_item_id", [True, 1.0, 1.5, "1"])
def test_queue_fetch_and_completion_require_strict_integer_item_ids(
    client, isolate_settings, invalid_item_id
):
    engagement_key, _, _ = _seed_priority_contract_files(
        client, isolate_settings, f"strict-item-id-{type(invalid_item_id).__name__}"
    )
    base = f"/engagements/{engagement_key}/assessment/code"

    fetched = client.post(
        f"{base}/analysis-queue/fetch",
        json={
            "limit": 1,
            "agent_name": "strict-id-worker",
            "item_ids": [invalid_item_id],
        },
    )
    completed = client.post(
        f"{base}/analysis-queue/done",
        json={
            "item_ids": [invalid_item_id],
            "agent_name": "strict-id-worker",
            "lease_token": "strict-id-lease",
            "disposition": "skipped",
            "skip_reason": "test-fixture",
        },
    )

    assert fetched.status_code == 422, fetched.text
    assert completed.status_code == 422, completed.text


def test_latest_error_removes_older_cwe_detail_and_effort_proof(
    client, isolate_settings
):
    engagement_key, _, file_row = _seed_queue_contract_file(
        client, isolate_settings, "latest-error-cwe-proof"
    )
    base = f"/engagements/{engagement_key}/assessment/code"
    initial = _claim_file_for_analysis(
        client, engagement_key, int(file_row["id"]), priority=80
    )
    result = client.post(
        f"{base}/analysis-results",
        json=_owned(
            initial,
            queue_item_id=initial["id"],
            disposition="clean",
            function_name="parse_request",
            evidence="Reviewed the current request parser.",
            cwe_coverage=_network_input_coverage(default_effort=80),
        ),
    )
    assert result.status_code == 201, result.text
    done = client.post(
        f"{base}/analysis-queue/done",
        json=_owned(
            initial,
            item_ids=[initial["id"]],
            disposition="clean",
            notes="Initial review completed.",
            cwe_coverage=_network_input_coverage(default_effort=80),
        ),
    )
    assert done.status_code == 200, done.text
    reread = _claim_file_for_reanalysis(
        client,
        engagement_key,
        int(file_row["id"]),
        reason="fresh independent reread",
        priority=80,
        agent_name="reread-worker",
    )
    failed = client.post(
        f"{base}/analysis-queue/error",
        json=_owned(reread, item_ids=[reread["id"]], notes="reread failed"),
    )
    assert failed.status_code == 200, failed.text

    detail = client.get(f"{base}/coverage?detail=cwe").json()
    file_detail = next(
        entry for entry in detail["files"] if entry["file_id"] == file_row["id"]
    )
    assert file_detail["cwe_coverage"] == []
    assert file_detail["analysis_effort"] == {
        "current_result_rows": 0,
        "evidenced_result_rows": 0,
        "distinct_functions_with_results": 0,
        "total_functions": 0,
        "function_coverage_pct": 0.0,
    }


def test_trigger_requeue_rejects_superseded_active_queue_attempt(
    client, isolate_settings
):
    engagement_key, repo, files = _seed_priority_contract_files(
        client, isolate_settings, "trigger-superseded-active"
    )
    file_id = int(files[0]["id"])
    base = f"/engagements/{engagement_key}/assessment/code"
    _classify_file(client, engagement_key, file_id, "high", 70)
    repo_generation = int(client.get(f"{base}/repos/{repo['id']}").json()["active_generation"])
    active_id, _ = _seed_superseded_active_queue_history(
        engagement_key,
        file_id,
        repo_generation,
    )

    response = client.post(
        f"{base}/analysis-queue/requeue",
        json={"items": [{"file_id": file_id, "reason": "fresh trigger context"}]},
    )

    assert response.status_code == 409, response.text
    with db_module.get_connection() as connection:
        row = connection.execute(
            "SELECT priority, queue_mode, cross_file_triggers_json FROM code_analysis_queue WHERE id = ?",
            (active_id,),
        ).fetchone()
    assert tuple(row) == (70, "initial", "[]")


def _record_fuzz_decision(
    client,
    engagement_key: str,
    repo: dict[str, object],
    *,
    decision: str,
    target_ids: list[str] | None = None,
    evidence_ref: str = "tools/fuzz-state/applicability.json",
):
    return client.post(
        f"/engagements/{engagement_key}/assessment/code/fuzz/decision",
        json={
            "repo_id": repo["id"],
            "repo_generation": repo["active_generation"],
            "source_manifest_digest": repo["source_manifest_digest"],
            "decision": decision,
            "target_ids": target_ids or [],
            "evidence_ref": evidence_ref,
            "rationale": (
                "Reviewed language inventory, high-risk parser classifications, "
                "existing fuzz coverage, and current verified findings."
            ),
        },
    )


def _register_fuzz_dispatch(client, engagement_key: str, *, agent_id: str):
    response = client.post(
        f"/engagements/{engagement_key}/assessment/dispatches",
        json={
            "agent_id": agent_id,
            "agent_role": "code-fuzz-engineer",
            "task": "Build and run the generation-bound sanitizer campaign.",
            "status": "in-progress",
            "dispatch_mode": "deep-manual",
            "finding_slugs": [],
            "skills": "code-fuzz-campaign",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _record_current_confirmed_memory_finding(
    client,
    engagement_key: str,
    repo_id: int,
    *,
    slug: str = "VF-003",
    defect_family: str = "use-after-free",
    workflow_status: str = "active",
    verification_status: str = "confirmed",
    expected_status: int = 201,
):
    author_agent_id = f"AUTHOR-{slug}"
    _ensure_finding_author_dispatch(client, engagement_key, author_agent_id)
    response = client.post(
        f"/engagements/{engagement_key}/assessment/findings",
        json={
            "slug": slug,
            "title": "Confirmed use-after-free in parser reset",
            "severity": "high",
            "workflow_status": workflow_status,
            "verification_status": "unreviewed",
            "defect_family": defect_family,
            "root_cause_key": f"uaf-{slug.lower()}",
            "auth_context": "anonymous",
            "canonical_location": "file:src/parser.cpp:42",
            "summary": "A state sequence frees and then reuses the parser buffer.",
            "evidence_ref": f"notes/{slug}.md",
            "notes": "Confirmed against the sealed source generation.",
            "source_name": "code-vuln-hunter",
            "details": {
                "evidence": "reset() frees state retained by continue_parse().",
                "impact": "Attacker-controlled sequencing can corrupt memory.",
            },
            "provenance": {
                "agent_id": author_agent_id,
                "agent_name": "code-vuln-hunter",
                "code_snapshot": _finding_code_snapshot(
                    client, engagement_key, repo_id
                ),
            },
            "links": [],
        },
    )
    assert response.status_code == expected_status, response.text
    if expected_status == 201 and verification_status != "unreviewed":
        verified = _verify_code_finding(
            client,
            engagement_key,
            repo_id,
            slug,
            disposition=verification_status,
        )
        assert verified["finding"]["verification_status"] == verification_status
    return response


def test_fuzz_applicability_decision_is_current_source_bound_and_required_at_entry(
    client, isolate_settings
):
    engagement_key = "2026-08-06-fuzz-applicability"
    engagement_dir = write_engagement(
        isolate_settings["engagements_dir"], engagement_key
    )
    repo = _create_repo(client, engagement_key, repo_key="fuzz-applicability")
    evidence = engagement_dir / "tools" / "fuzz-state" / "applicability.json"
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.write_text('{"languages":["python"],"risky_targets":[]}', encoding="utf-8")
    base = f"/engagements/{engagement_key}/assessment/code"

    missing = client.get(f"{base}/readiness?target_phase=fuzz").json()
    assert "fuzz_decision_missing" in {
        blocker["code"] for blocker in missing["blockers"]
    }

    recorded = _record_fuzz_decision(
        client, engagement_key, repo, decision="not_required"
    )
    assert recorded.status_code == 201, recorded.text
    assert recorded.json()["current"] is True
    state = client.get(f"{base}/fuzz/state?repo_id={repo['id']}")
    assert state.status_code == 200, state.text
    assert state.json()["decision"] == "not_required"
    assert state.json()["source"] == "recorded"
    after = client.get(f"{base}/readiness?target_phase=fuzz").json()
    assert "fuzz_decision_missing" not in {
        blocker["code"] for blocker in after["blockers"]
    }

    stale = _record_fuzz_decision(
        client,
        engagement_key,
        {**repo, "active_generation": int(repo["active_generation"]) + 1},
        decision="not_required",
    )
    assert stale.status_code == 409
    assert "generation is stale" in stale.json()["detail"]

    oversized = engagement_dir / "tools" / "fuzz-state" / "oversized.json"
    oversized.write_bytes(b"x" * (code_fuzz_completion.MAX_FUZZ_EVIDENCE_BYTES + 1))
    rejected_evidence = _record_fuzz_decision(
        client,
        engagement_key,
        repo,
        decision="not_required",
        evidence_ref="tools/fuzz-state/oversized.json",
    )
    assert rejected_evidence.status_code == 413


def test_confirmed_memory_finding_forces_fuzz_and_terminal_receipt_gates_completion(
    client, isolate_settings
):
    engagement_key = "2026-08-06-fuzz-forced-campaign"
    engagement_dir = write_engagement(
        isolate_settings["engagements_dir"], engagement_key
    )
    repo = _create_repo(client, engagement_key, repo_key="fuzz-forced-campaign")
    state_dir = engagement_dir / "tools" / "fuzz-state"
    state_dir.mkdir(parents=True, exist_ok=True)
    (state_dir / "applicability.json").write_text("{}", encoding="utf-8")
    (state_dir / "campaign.json").write_text(
        '{"engine":"libFuzzer","sanitizers":["asan","ubsan"]}',
        encoding="utf-8",
    )
    _record_current_confirmed_memory_finding(
        client, engagement_key, int(repo["id"])
    )
    base = f"/engagements/{engagement_key}/assessment/code"

    state = client.get(f"{base}/fuzz/state?repo_id={repo['id']}")
    assert state.status_code == 200, state.text
    assert state.json()["decision"] is None
    assert state.json()["forced_decision"] == "required"
    assert state.json()["source"] == "none"
    assert state.json()["required_finding_slugs"] == ["VF-003"]
    assert state.json()["pending_finding_slugs"] == ["VF-003"]
    assert state.json()["applicability_ready"] is False
    assert state.json()["completion_ready"] is False

    waived = _record_fuzz_decision(
        client, engagement_key, repo, decision="not_required"
    )
    assert waived.status_code == 409
    assert "current non-killed native memory-safety finding" in waived.json()["detail"]

    entry = client.get(f"{base}/readiness?target_phase=fuzz").json()
    assert "fuzz_decision_missing" in {
        blocker["code"] for blocker in entry["blockers"]
    }
    assert "fuzz_campaign_incomplete" not in {
        blocker["code"] for blocker in entry["blockers"]
    }
    assert entry["fuzz_completion"]["pending_finding_slugs"] == ["VF-003"]

    required_without_target = _record_fuzz_decision(
        client, engagement_key, repo, decision="required"
    )
    assert required_without_target.status_code == 422
    whitespace_decision = client.post(
        f"{base}/fuzz/decision",
        json={
            "repo_id": repo["id"],
            "repo_generation": repo["active_generation"],
            "source_manifest_digest": repo["source_manifest_digest"],
            "decision": "required",
            "target_ids": ["parser-reset-state-sequence"],
            "evidence_ref": "tools/fuzz-state/applicability.json",
            "rationale": "   ",
        },
    )
    assert whitespace_decision.status_code == 422
    required = _record_fuzz_decision(
        client,
        engagement_key,
        repo,
        decision="required",
        target_ids=["parser-reset-state-sequence"],
    )
    assert required.status_code == 201, required.text
    after_decision = client.get(f"{base}/readiness?target_phase=fuzz").json()
    assert "fuzz_decision_missing" not in {
        blocker["code"] for blocker in after_decision["blockers"]
    }

    before_complete = client.get(f"{base}/readiness?target_phase=complete").json()
    assert "fuzz_campaign_incomplete" in {
        blocker["code"] for blocker in before_complete["blockers"]
    }
    before_report = client.get(
        f"/engagements/{engagement_key}/assessment/report-readiness"
    ).json()
    assert "fuzz_campaign_incomplete" in {
        blocker["kind"] for blocker in before_report["blockers"]
    }

    dispatch = _register_fuzz_dispatch(
        client, engagement_key, agent_id="fuzz-forced-worker"
    )
    common_receipt = {
        "dispatch_id": dispatch["id"],
        "repo_id": repo["id"],
        "repo_generation": repo["active_generation"],
        "source_manifest_digest": repo["source_manifest_digest"],
        "target_id": "parser-reset-state-sequence",
        "covered_finding_slugs": ["VF-003"],
        "engine": "libfuzzer",
        "sanitizers": ["address", "undefined"],
        "run_budget_seconds": 60,
        "executions": 25000,
        "evidence_ref": "tools/fuzz-state/campaign.json",
        "rationale": "Built the real parser entrypoint and exercised reset/continue sequences.",
    }
    out_of_scope = client.post(
        f"{base}/fuzz/campaign-receipts",
        json={**common_receipt, "target_id": "unassigned-target", "outcome": "completed_no_crash", "crash_count": 0, "triage_summary": "No crash observed."},
    )
    assert out_of_scope.status_code == 409
    assert "decision target scope" in out_of_scope.json()["detail"]
    empty_campaign = client.post(
        f"{base}/fuzz/campaign-receipts",
        json={
            **common_receipt,
            "executions": 0,
            "outcome": "completed_no_crash",
            "crash_count": 0,
            "triage_summary": "No mutations actually executed.",
        },
    )
    assert empty_campaign.status_code == 422
    for field_name, value in (
        ("engine", " libfuzzer"),
        ("triage_summary", "   "),
        ("rationale", "campaign rationale "),
    ):
        invalid_text = client.post(
            f"{base}/fuzz/campaign-receipts",
            json={
                **common_receipt,
                field_name: value,
                "outcome": "completed_crashes_triaged",
                "crash_count": 1,
                "triage_summary": (
                    value if field_name == "triage_summary" else "Crash independently triaged."
                ),
            },
        )
        assert invalid_text.status_code == 422, (field_name, invalid_text.text)
    failed = client.post(
        f"{base}/fuzz/campaign-receipts",
        json={
            **common_receipt,
            "outcome": "campaign_failed",
            "crash_count": 0,
            "triage_summary": "Runner exited before reaching the declared budget.",
        },
    )
    assert failed.status_code == 201, failed.text
    assert failed.json()["covering"] is False
    still_blocked = client.get(f"{base}/readiness?target_phase=complete").json()
    assert "fuzz_campaign_incomplete" in {
        blocker["code"] for blocker in still_blocked["blockers"]
    }

    completed = client.post(
        f"{base}/fuzz/campaign-receipts",
        json={
            **common_receipt,
            "outcome": "completed_no_crash",
            "crash_count": 0,
            "triage_summary": "No sanitizer crash observed during the bounded campaign.",
        },
    )
    assert completed.status_code == 201, completed.text
    assert completed.json()["covering"] is True
    assert completed.json()["current"] is True
    assert completed.json()["dispatch_agent_id"] == "fuzz-forced-worker"

    after_complete = client.get(f"{base}/readiness?target_phase=complete").json()
    assert "fuzz_campaign_incomplete" not in {
        blocker["code"] for blocker in after_complete["blockers"]
    }
    after_report = client.get(
        f"/engagements/{engagement_key}/assessment/report-readiness"
    ).json()
    assert "fuzz_campaign_incomplete" not in {
        blocker["kind"] for blocker in after_report["blockers"]
    }

    (state_dir / "campaign.json").write_text(
        '{"engine":"libFuzzer","tampered":true}', encoding="utf-8"
    )
    stale_history = client.get(
        f"{base}/fuzz/campaign-receipts?repo_id={repo['id']}&include_stale=true"
    )
    assert stale_history.status_code == 200, stale_history.text
    completed_history = next(
        row for row in stale_history.json() if row["id"] == completed.json()["id"]
    )
    assert completed_history["current"] is False
    assert completed_history["covering"] is False
    stale_state = client.get(f"{base}/fuzz/state?repo_id={repo['id']}").json()
    assert stale_state["pending_target_ids"] == ["parser-reset-state-sequence"]
    assert stale_state["pending_finding_slugs"] == ["VF-003"]


def test_fuzz_campaign_receipt_rejects_cross_engagement_and_forged_dispatches(
    client, isolate_settings
):
    first_key = "2026-08-06-fuzz-dispatch-owner"
    second_key = "2026-08-06-fuzz-dispatch-attacker"
    first_dir = write_engagement(isolate_settings["engagements_dir"], first_key)
    second_dir = write_engagement(isolate_settings["engagements_dir"], second_key)
    first_repo = _create_repo(client, first_key, repo_key="fuzz-owner")
    second_repo = _create_repo(client, second_key, repo_key="fuzz-attacker")
    for root in (first_dir, second_dir):
        evidence = root / "tools" / "fuzz-state" / "campaign.json"
        evidence.parent.mkdir(parents=True, exist_ok=True)
        evidence.write_text("{}", encoding="utf-8")
    dispatch = _register_fuzz_dispatch(client, first_key, agent_id="fuzz-owner-worker")
    payload = {
        "dispatch_id": dispatch["id"],
        "repo_id": second_repo["id"],
        "repo_generation": second_repo["active_generation"],
        "source_manifest_digest": second_repo["source_manifest_digest"],
        "target_id": "forged-target",
        "covered_finding_slugs": [],
        "engine": "libfuzzer",
        "sanitizers": ["address"],
        "run_budget_seconds": 60,
        "executions": 1,
        "outcome": "completed_no_crash",
        "crash_count": 0,
        "triage_summary": "No crash observed.",
        "evidence_ref": "tools/fuzz-state/campaign.json",
        "rationale": "Attempted to reuse a dispatch from another engagement.",
    }
    cross = client.post(
        f"/engagements/{second_key}/assessment/code/fuzz/campaign-receipts",
        json=payload,
    )
    assert cross.status_code == 409
    assert "dispatch in this engagement" in cross.json()["detail"]

    wrong_role = _register_variant_dispatch(
        client,
        second_key,
        agent_id="not-a-fuzz-worker",
        finding_slugs=[],
        role="code-vuln-hunter",
    )
    forged = client.post(
        f"/engagements/{second_key}/assessment/code/fuzz/campaign-receipts",
        json={**payload, "dispatch_id": wrong_role["id"]},
    )
    assert forged.status_code == 409
    assert "role=code-fuzz-engineer" in forged.json()["detail"]

    stale = client.post(
        f"/engagements/{first_key}/assessment/code/fuzz/campaign-receipts",
        json={
            **payload,
            "repo_id": first_repo["id"],
            "repo_generation": int(first_repo["active_generation"]) + 1,
            "source_manifest_digest": first_repo["source_manifest_digest"],
        },
    )
    assert stale.status_code == 409
    assert "generation is stale" in stale.json()["detail"]


def test_fuzz_forcing_covers_all_native_memory_families_and_draft_reopens(
    client, isolate_settings
):
    engagement_key = "2026-08-06-fuzz-native-families"
    engagement_dir = write_engagement(
        isolate_settings["engagements_dir"], engagement_key
    )
    repo = _create_repo(client, engagement_key, repo_key="fuzz-native-families")
    evidence = engagement_dir / "tools" / "fuzz-state" / "applicability.json"
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.write_text("{}", encoding="utf-8")
    families = (
        "buffer-overflow",
        "format-string",
        "integer-overflow",
        "null-dereference",
        "type-confusion",
        "uninitialized-memory",
        "use-after-free",
    )
    slugs: list[str] = []
    for index, family in enumerate(families, start=1):
        slug = f"MF-{index:03d}"
        slugs.append(slug)
        _record_current_confirmed_memory_finding(
            client,
            engagement_key,
            int(repo["id"]),
            slug=slug,
            defect_family=family,
            workflow_status="active" if family == "use-after-free" else "draft",
            verification_status=(
                "unreviewed" if family == "null-dereference" else "confirmed"
            ),
        )

    reopened = client.patch(
        f"/engagements/{engagement_key}/assessment/findings/{slugs[-1]}",
        json={"workflow_status": "draft"},
    )
    assert reopened.status_code == 200, reopened.text
    state = client.get(
        f"/engagements/{engagement_key}/assessment/code/fuzz/state?repo_id={repo['id']}"
    )
    assert state.status_code == 200, state.text
    assert state.json()["required_finding_slugs"] == sorted(slugs)
    assert state.json()["forced_decision"] == "required"

    relabel = client.patch(
        f"/engagements/{engagement_key}/assessment/findings/{slugs[0]}",
        json={"defect_family": "injection"},
    )
    assert relabel.status_code == 400
    assert "verification" in relabel.json()["detail"]
    rerecord = _record_current_confirmed_memory_finding(
        client,
        engagement_key,
        int(repo["id"]),
        slug=slugs[0],
        defect_family="injection",
        expected_status=400,
    )
    assert "verification" in rerecord.json()["detail"]
    still_forced = client.get(
        f"/engagements/{engagement_key}/assessment/code/fuzz/state?repo_id={repo['id']}"
    ).json()
    assert still_forced["required_finding_slugs"] == sorted(slugs)

    killed = _verify_code_finding(
        client,
        engagement_key,
        int(repo["id"]),
        slugs[1],
        disposition="false_positive",
        reason_code="not-reachable",
        reason_text="Verifier proved the suspected format path unreachable.",
        details={
            "kill_check": 4,
            "kill_reason": "No attacker-controlled format string reaches the sink.",
        },
    )
    assert killed["finding"]["verification_status"] == "false_positive"
    after_kill = client.get(
        f"/engagements/{engagement_key}/assessment/code/fuzz/state?repo_id={repo['id']}"
    ).json()
    assert after_kill["required_finding_slugs"] == sorted(
        set(slugs) - {slugs[1]}
    )


def test_fuzz_decision_is_immutable_per_current_identity_and_replay_is_idempotent(
    client, isolate_settings
):
    engagement_key = "2026-08-06-fuzz-decision-immutable"
    engagement_dir = write_engagement(
        isolate_settings["engagements_dir"], engagement_key
    )
    repo = _create_repo(client, engagement_key, repo_key="fuzz-decision-immutable")
    evidence = engagement_dir / "tools" / "fuzz-state" / "applicability.json"
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.write_text('{"review":"initial"}', encoding="utf-8")

    first = _record_fuzz_decision(
        client,
        engagement_key,
        repo,
        decision="required",
        target_ids=["parser-a", "parser-b"],
    )
    assert first.status_code == 201, first.text
    assert first.json()["created"] is True
    replay = _record_fuzz_decision(
        client,
        engagement_key,
        repo,
        decision="required",
        target_ids=["parser-a", "parser-b"],
    )
    assert replay.status_code == 200, replay.text
    assert replay.json()["id"] == first.json()["id"]
    assert replay.json()["created"] is False
    assert replay.json()["current"] is True

    shrunk = _record_fuzz_decision(
        client,
        engagement_key,
        repo,
        decision="required",
        target_ids=["parser-a"],
    )
    assert shrunk.status_code == 409
    waived = _record_fuzz_decision(
        client, engagement_key, repo, decision="not_required"
    )
    assert waived.status_code == 409
    assert "current fuzz decision" in waived.json()["detail"]

    with db_module.get_connection() as connection:
        engagement_id = int(
            connection.execute(
                "SELECT id FROM engagements WHERE key = ?", (engagement_key,)
            ).fetchone()["id"]
        )
        audit_count = int(
            connection.execute(
                "SELECT COUNT(*) AS count FROM activity_entries "
                "WHERE engagement_id = ? AND title = 'code-record fuzz-decision'",
                (engagement_id,),
            ).fetchone()["count"]
        )
    assert audit_count == 1


def test_fuzz_decision_history_is_bounded_paginated_and_marks_superseded_rows(
    client, isolate_settings
):
    engagement_key = "2026-08-06-fuzz-decision-history"
    engagement_dir = write_engagement(
        isolate_settings["engagements_dir"], engagement_key
    )
    repo = _create_repo(client, engagement_key, repo_key="fuzz-decision-history")
    evidence = engagement_dir / "tools" / "fuzz-state" / "applicability.json"
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.write_text('{"revision":1}', encoding="utf-8")
    first = _record_fuzz_decision(
        client,
        engagement_key,
        repo,
        decision="not_required",
    )
    assert first.status_code == 201, first.text

    _record_current_confirmed_memory_finding(
        client,
        engagement_key,
        int(repo["id"]),
        slug="MF-998",
        defect_family="buffer-overflow",
    )
    second = _record_fuzz_decision(
        client,
        engagement_key,
        repo,
        decision="required",
        target_ids=["parser-a"],
    )
    assert second.status_code == 201, second.text
    base = f"/engagements/{engagement_key}/assessment/code/fuzz/decisions"
    page_one = client.get(
        f"{base}?repo_id={repo['id']}&include_stale=true&limit=1&offset=0"
    )
    page_two = client.get(
        f"{base}?repo_id={repo['id']}&include_stale=true&limit=1&offset=1"
    )
    assert page_one.status_code == 200, page_one.text
    assert page_two.status_code == 200, page_two.text
    assert [row["id"] for row in page_one.json()] == [second.json()["id"]]
    assert page_one.json()[0]["current"] is True
    assert [row["id"] for row in page_two.json()] == [first.json()["id"]]
    assert page_two.json()[0]["current"] is False
    too_large = client.get(f"{base}?limit=1001")
    assert too_large.status_code == 422


def test_new_forced_finding_invalidates_not_required_and_allows_strengthening(
    client, isolate_settings
):
    engagement_key = "2026-08-06-fuzz-decision-strengthen"
    engagement_dir = write_engagement(
        isolate_settings["engagements_dir"], engagement_key
    )
    repo = _create_repo(client, engagement_key, repo_key="fuzz-decision-strengthen")
    evidence = engagement_dir / "tools" / "fuzz-state" / "applicability.json"
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.write_text("{}", encoding="utf-8")
    skipped = _record_fuzz_decision(
        client, engagement_key, repo, decision="not_required"
    )
    assert skipped.status_code == 201, skipped.text

    _record_current_confirmed_memory_finding(
        client,
        engagement_key,
        int(repo["id"]),
        slug="MF-999",
        defect_family="buffer-overflow",
    )
    invalidated = client.get(
        f"/engagements/{engagement_key}/assessment/code/fuzz/state?repo_id={repo['id']}"
    ).json()
    assert invalidated["decision"] is None
    assert invalidated["forced_decision"] == "required"
    decision_history = (
        f"/engagements/{engagement_key}/assessment/code/fuzz/decisions"
        f"?repo_id={repo['id']}"
    )
    assert client.get(decision_history).json() == []
    invalid_history = client.get(f"{decision_history}&include_stale=true").json()
    assert len(invalid_history) == 1
    assert invalid_history[0]["decision"] == "not_required"
    assert invalid_history[0]["current"] is False
    strengthened = _record_fuzz_decision(
        client,
        engagement_key,
        repo,
        decision="required",
        target_ids=["parser-a"],
    )
    assert strengthened.status_code == 201, strengthened.text
    assert strengthened.json()["current"] is True


def test_latest_invalid_fuzz_decision_fails_closed_without_older_fallback(
    client, isolate_settings
):
    engagement_key = "2026-08-06-fuzz-decision-latest-invalid"
    engagement_dir = write_engagement(
        isolate_settings["engagements_dir"], engagement_key
    )
    repo = _create_repo(client, engagement_key, repo_key="fuzz-decision-latest-invalid")
    state_dir = engagement_dir / "tools" / "fuzz-state"
    state_dir.mkdir(parents=True, exist_ok=True)
    older_evidence = state_dir / "older-decision.json"
    latest_evidence = state_dir / "latest-decision.json"
    older_evidence.write_text('{"decision":"older"}', encoding="utf-8")
    latest_evidence.write_text('{"decision":"latest"}', encoding="utf-8")
    older = _record_fuzz_decision(
        client,
        engagement_key,
        repo,
        decision="required",
        target_ids=["parser-a"],
        evidence_ref="tools/fuzz-state/older-decision.json",
    )
    assert older.status_code == 201, older.text
    latest_rationale = (
        "A later historical row used to verify newest-row fail-closed selection."
    )
    latest_sha256 = hashlib.sha256(latest_evidence.read_bytes()).hexdigest()
    latest_fingerprint = code_fuzz_completion._decision_fingerprint(
        repo_id=int(repo["id"]),
        repo_generation=int(repo["active_generation"]),
        source_manifest_digest=str(repo["source_manifest_digest"]),
        decision="required",
        target_ids=["parser-a"],
        evidence_ref="tools/fuzz-state/latest-decision.json",
        evidence_sha256=latest_sha256,
        rationale=latest_rationale,
    )
    with db_module.get_connection() as connection:
        engagement_id = int(
            connection.execute(
                "SELECT id FROM engagements WHERE key = ?", (engagement_key,)
            ).fetchone()["id"]
        )
        cursor = connection.execute(
            """
            INSERT INTO code_fuzz_decisions (
                engagement_id, repo_id, repo_generation, source_manifest_digest,
                decision, target_ids_json, evidence_ref, evidence_sha256,
                rationale, decision_fingerprint
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                engagement_id,
                repo["id"],
                repo["active_generation"],
                repo["source_manifest_digest"],
                "required",
                '["parser-a"]',
                "tools/fuzz-state/latest-decision.json",
                latest_sha256,
                latest_rationale,
                latest_fingerprint,
            ),
        )
        latest_id = int(cursor.lastrowid)
    latest_evidence.write_text('{"decision":"tampered"}', encoding="utf-8")

    state = client.get(
        f"/engagements/{engagement_key}/assessment/code/fuzz/state?repo_id={repo['id']}"
    ).json()
    assert state["decision"] is None
    assert state["applicability_ready"] is False
    base = f"/engagements/{engagement_key}/assessment/code/fuzz/decisions"
    assert client.get(f"{base}?repo_id={repo['id']}").json() == []
    history = client.get(
        f"{base}?repo_id={repo['id']}&include_stale=true"
    ).json()
    assert [row["current"] for row in history] == [False, False]
    assert history[0]["id"] == latest_id
    replay_older = _record_fuzz_decision(
        client,
        engagement_key,
        repo,
        decision="required",
        target_ids=["parser-a"],
        evidence_ref="tools/fuzz-state/older-decision.json",
    )
    assert replay_older.status_code == 409
    assert "newest fuzz decision is invalid" in replay_older.json()["detail"]


def _fuzz_campaign_payload(
    dispatch: dict[str, object],
    repo: dict[str, object],
    *,
    evidence_ref: str,
    outcome: str,
    rationale: str,
) -> dict[str, object]:
    return {
        "dispatch_id": dispatch["id"],
        "repo_id": repo["id"],
        "repo_generation": repo["active_generation"],
        "source_manifest_digest": repo["source_manifest_digest"],
        "target_id": "parser-a",
        "covered_finding_slugs": [],
        "engine": "libfuzzer",
        "sanitizers": ["address"],
        "run_budget_seconds": 60,
        "executions": 0 if outcome == "campaign_failed" else 100,
        "outcome": outcome,
        "crash_count": 0,
        "triage_summary": (
            "Runner failed before completion."
            if outcome == "campaign_failed"
            else "No sanitizer crash observed in the bounded campaign."
        ),
        "evidence_ref": evidence_ref,
        "rationale": rationale,
    }


def test_fuzz_state_ignores_unbounded_failure_history_and_campaign_list_pages(
    client, isolate_settings, monkeypatch
):
    engagement_key = "2026-08-06-fuzz-bounded-state"
    engagement_dir = write_engagement(
        isolate_settings["engagements_dir"], engagement_key
    )
    repo = _create_repo(client, engagement_key, repo_key="fuzz-bounded-state")
    state_dir = engagement_dir / "tools" / "fuzz-state"
    state_dir.mkdir(parents=True, exist_ok=True)
    (state_dir / "applicability.json").write_text("{}", encoding="utf-8")
    (state_dir / "campaign.json").write_text("{}", encoding="utf-8")
    decision = _record_fuzz_decision(
        client,
        engagement_key,
        repo,
        decision="required",
        target_ids=["parser-a"],
    )
    assert decision.status_code == 201, decision.text
    dispatch = _register_fuzz_dispatch(
        client, engagement_key, agent_id="fuzz-bounded-worker"
    )
    base = f"/engagements/{engagement_key}/assessment/code/fuzz/campaign-receipts"
    for index in range(24):
        failed = client.post(
            base,
            json=_fuzz_campaign_payload(
                dispatch,
                repo,
                evidence_ref="tools/fuzz-state/campaign.json",
                outcome="campaign_failed",
                rationale=f"Failure attempt {index:02d} retained for audit.",
            ),
        )
        assert failed.status_code == 201, failed.text
    completed = client.post(
        base,
        json=_fuzz_campaign_payload(
            dispatch,
            repo,
            evidence_ref="tools/fuzz-state/campaign.json",
            outcome="completed_no_crash",
            rationale="Terminal bounded campaign completed.",
        ),
    )
    assert completed.status_code == 201, completed.text

    original_evidence_identity = code_fuzz_completion._evidence_identity
    evidence_reads: list[str] = []

    def counted_evidence_identity(engagement_root: str, evidence_ref: str):
        evidence_reads.append(evidence_ref)
        return original_evidence_identity(engagement_root, evidence_ref)

    monkeypatch.setattr(
        code_fuzz_completion, "_evidence_identity", counted_evidence_identity
    )
    state = client.get(
        f"/engagements/{engagement_key}/assessment/code/fuzz/state?repo_id={repo['id']}"
    )
    assert state.status_code == 200, state.text
    assert state.json()["completion_ready"] is True
    assert len(evidence_reads) <= 2

    first_page = client.get(f"{base}?include_stale=true&limit=10&offset=0")
    second_page = client.get(f"{base}?include_stale=true&limit=10&offset=10")
    assert first_page.status_code == 200, first_page.text
    assert second_page.status_code == 200, second_page.text
    assert len(first_page.json()) == 10
    assert len(second_page.json()) == 10
    assert {row["id"] for row in first_page.json()}.isdisjoint(
        {row["id"] for row in second_page.json()}
    )
    assert any(row["outcome"] == "campaign_failed" for row in second_page.json())
    assert client.get(f"{base}?limit=101").status_code == 422


def test_latest_covering_fuzz_receipt_with_invalid_evidence_fails_closed(
    client, isolate_settings
):
    engagement_key = "2026-08-06-fuzz-latest-fails-closed"
    engagement_dir = write_engagement(
        isolate_settings["engagements_dir"], engagement_key
    )
    repo = _create_repo(client, engagement_key, repo_key="fuzz-latest-fails-closed")
    state_dir = engagement_dir / "tools" / "fuzz-state"
    state_dir.mkdir(parents=True, exist_ok=True)
    (state_dir / "applicability.json").write_text("{}", encoding="utf-8")
    (state_dir / "older.json").write_text('{"run":"older"}', encoding="utf-8")
    (state_dir / "latest.json").write_text('{"run":"latest"}', encoding="utf-8")
    assert _record_fuzz_decision(
        client,
        engagement_key,
        repo,
        decision="required",
        target_ids=["parser-a"],
    ).status_code == 201
    dispatch = _register_fuzz_dispatch(
        client, engagement_key, agent_id="fuzz-latest-worker"
    )
    base = f"/engagements/{engagement_key}/assessment/code/fuzz/campaign-receipts"
    older = client.post(
        base,
        json=_fuzz_campaign_payload(
            dispatch,
            repo,
            evidence_ref="tools/fuzz-state/older.json",
            outcome="completed_no_crash",
            rationale="Older valid bounded campaign.",
        ),
    )
    latest = client.post(
        base,
        json=_fuzz_campaign_payload(
            dispatch,
            repo,
            evidence_ref="tools/fuzz-state/latest.json",
            outcome="completed_no_crash",
            rationale="Latest bounded campaign supersedes the older result.",
        ),
    )
    assert older.status_code == 201, older.text
    assert latest.status_code == 201, latest.text
    (state_dir / "latest.json").write_text('{"run":"tampered"}', encoding="utf-8")

    state = client.get(
        f"/engagements/{engagement_key}/assessment/code/fuzz/state?repo_id={repo['id']}"
    )
    assert state.status_code == 200, state.text
    assert state.json()["completion_ready"] is False
    assert state.json()["pending_target_ids"] == ["parser-a"]
    history = client.get(
        f"{base}?include_stale=true&limit=1&offset=0"
    )
    assert history.status_code == 200, history.text
    assert history.json()[0]["id"] == latest.json()["id"]
    assert history.json()[0]["current"] is False
