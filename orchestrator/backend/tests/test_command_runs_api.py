"""Tests for the vigil assess command-run audit API."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import stat
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from app import db as db_module
from app.services import artifact_index, state_manager
from app.services.state_manager import command_runs as command_runs_service


ENGAGEMENT_KEY = "2026-04-17-120000-example"


def _write_engagement(engagements_dir: Path, key: str = ENGAGEMENT_KEY) -> Path:
    engagement_dir = engagements_dir / key
    (engagement_dir / "sessions").mkdir(parents=True, exist_ok=True)
    (engagement_dir / "engagement.json").write_text(
        json.dumps(
            {
                "key": key,
                "target": "https://example.com",
                "hostname": "example.com",
                "created_at": "2026-04-17T12:00:00Z",
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
                "status": "in_progress",
                "current_phase": "recon",
            }
        ),
        encoding="utf-8",
    )
    (engagement_dir / "log.md").write_text("# Engagement Log\n", encoding="utf-8")
    return engagement_dir


def _post(client, payload):
    return client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs",
        json=payload,
    )


def _base_payload(**overrides):
    payload = {
        "command": "nmap -sV 10.0.0.1",
        "argv": ["nmap", "-sV", "10.0.0.1"],
        "tool_name": "nmap_scan",
        "route": "/api/tools/nmap/scan",
        "agent_name": "recon-specialist",
        "phase": "recon",
        "return_code": 0,
        "timed_out": False,
        "success": True,
        "started_at": "2026-04-17T12:00:00Z",
        "completed_at": "2026-04-17T12:00:02Z",
        "duration_ms": 2000,
        "stdout": "Nmap scan report for 10.0.0.1\n22/tcp open ssh\n",
        "stderr": "",
        "notes": "",
        # Command-metadata fields default to None so every payload starts
        # backward-compatible with the pre-metadata contract. Tests that
        # exercise the new fields override these explicitly.
        "technique": None,
        "intent": None,
        "probe_kind": None,
        "destructive": None,
    }
    payload.update(overrides)
    if payload.get("status") in {"queued", "running"} and "duration_ms" not in overrides:
        payload["duration_ms"] = 0
    for stream in ("stdout", "stderr"):
        path_value = payload.get(f"{stream}_path")
        if path_value:
            path = Path(path_value)
            try:
                metadata = os.stat(path, follow_symlinks=False)
            except OSError:
                continue
            if not stat.S_ISREG(metadata.st_mode):
                continue
            os.chmod(path.parent, 0o700)
            os.chmod(path, 0o600)
            metadata = os.stat(path, follow_symlinks=False)
            payload.setdefault(f"{stream}_spill_device", metadata.st_dev)
            payload.setdefault(f"{stream}_spill_inode", metadata.st_ino)
    return payload


def _unique_run_uuid_indexes(connection: sqlite3.Connection) -> list[str]:
    names: list[str] = []
    for row in connection.execute("PRAGMA index_list(assessment_command_runs)"):
        index_name = str(row[1])
        if not bool(row[2]):
            continue
        indexed_columns = [
            str(info[2])
            for info in connection.execute(f"PRAGMA index_info({index_name})")
        ]
        if indexed_columns == ["run_uuid"]:
            names.append(index_name)
    return names


def test_fresh_command_runs_schema_has_single_run_uuid_unique_index(
    client, isolate_settings
):
    db_path = db_module.database_path()
    with sqlite3.connect(str(db_path)) as connection:
        assert len(_unique_run_uuid_indexes(connection)) == 1


def test_record_and_list_command_run_round_trips(client, isolate_settings):
    _write_engagement(isolate_settings["engagements_dir"])

    response = _post(client, _base_payload())
    assert response.status_code == 201, response.text
    created = response.json()
    assert created["tool_name"] == "nmap_scan"
    assert created["agent_name"] == "recon-specialist"
    assert created["phase"] == "recon"
    assert created["success"] is True
    assert created["timed_out"] is False
    assert created["output_retention_status"] == "retained"
    assert created["stdout_preview"].startswith("Nmap scan report")
    assert len(created["stdout_sha256"]) == 64
    assert len(created["command_hash"]) == 64

    listing = client.get(f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs")
    assert listing.status_code == 200
    rows = listing.json()
    assert len(rows) == 1
    assert rows[0]["id"] == created["id"]


def test_one_shot_command_run_without_status_infers_terminal_state(
    client, isolate_settings
):
    _write_engagement(isolate_settings["engagements_dir"])

    payload = _base_payload(
        command="nmap -sV 10.0.0.8",
        argv=["nmap", "-sV", "10.0.0.8"],
        return_code=0,
        success=True,
    )
    first = _post(client, payload)
    assert first.status_code == 201, first.text
    first_row = first.json()
    assert first_row["status"] == "completed"

    second = _post(client, payload)
    assert second.status_code == 201, second.text
    second_row = second.json()
    assert second_row["status"] == "completed"
    assert second_row["superseded_by_id"] is None
    assert second_row.get("dedup_predecessor_id") is None


def test_foreign_lane_recency_aggregate_counts_target_facing_history(
    client, isolate_settings
):
    _write_engagement(isolate_settings["engagements_dir"])
    target_facing = json.dumps({"target_facing": True})
    rows = (
        _base_payload(
            command="curl https://example.com/current",
            agent_name="current-agent",
            notes=target_facing,
            started_at="2026-09-10T12:00:00Z",
        ),
        _base_payload(
            command="curl https://example.com/older",
            agent_name="other-agent",
            notes=target_facing,
            started_at="2026-09-10T11:58:00Z",
        ),
        _base_payload(
            command="curl https://example.com/latest",
            agent_name="other-agent",
            notes=target_facing,
            started_at="2026-09-10T11:59:30Z",
        ),
        _base_payload(
            command="curl https://example.com/non-target",
            agent_name="other-agent",
            notes=json.dumps({"target_facing": False}),
            started_at="2026-09-10T12:01:00Z",
        ),
        _base_payload(
            command="curl https://example.com/malformed",
            agent_name="other-agent",
            notes="{not-json",
            started_at="2026-09-10T12:02:00Z",
        ),
    )
    for payload in rows:
        response = _post(client, payload)
        assert response.status_code == 201, response.text
    with command_runs_service._common.get_connection() as connection:
        connection.execute(
            """
            UPDATE assessment_command_runs
            SET started_at = '', created_at = ?
            WHERE engagement_id = (SELECT id FROM engagements WHERE key = ?)
              AND command = ?
            """,
            (
                "2026-09-10T11:59:30Z",
                ENGAGEMENT_KEY,
                "curl https://example.com/latest",
            ),
        )

    response = client.get(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/foreign-lane-recency",
        params={"agent_name": "current-agent"},
    )

    assert response.status_code == 200, response.text
    assert response.json() == {
        "foreign_count": 2,
        "latest_started_at": "2026-09-10T11:59:30Z",
    }


def test_job_patch_accepts_stop_failed_terminal_status(client, isolate_settings):
    _write_engagement(isolate_settings["engagements_dir"])

    created = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/jobs",
        json={
            "status": "running",
            "audit_metadata": {"technique": "RECON", "intent": "long sweep"},
        },
    )
    assert created.status_code == 201, created.text
    job_id = created.json()["id"]

    stopped = client.patch(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/jobs/{job_id}",
        json={"status": "stop_failed"},
    )

    assert stopped.status_code == 200, stopped.text
    assert stopped.json()["status"] == "stop_failed"
    listed = client.get(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/jobs",
        params={"status": "stop_failed"},
    )
    assert listed.status_code == 200
    assert [row["id"] for row in listed.json()] == [job_id]


def test_list_command_runs_filters_by_phase_agent_tool_and_success(
    client, isolate_settings
):
    _write_engagement(isolate_settings["engagements_dir"])
    assert _post(client, _base_payload()).status_code == 201
    assert (
        _post(
            client,
            _base_payload(
                command="gobuster dir -u https://example.com -w /lists/common.txt",
                tool_name="gobuster_scan",
                agent_name="recon-specialist",
                phase="recon",
                return_code=1,
                success=False,
                stdout="",
                stderr="wordlist missing",
            ),
        ).status_code
        == 201
    )
    assert (
        _post(
            client,
            _base_payload(
                command="sqlmap -u https://example.com/?id=1 --batch",
                tool_name="sqlmap_scan",
                agent_name="vulnerability-analyst",
                phase="consume-test",
            ),
        ).status_code
        == 201
    )

    def fetch(query):
        response = client.get(
            f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs?{query}"
        )
        assert response.status_code == 200
        return response.json()

    assert len(fetch("phase=recon")) == 2
    assert len(fetch("agent_name=vulnerability-analyst")) == 1
    assert len(fetch("tool_name=sqlmap_scan")) == 1
    assert len(fetch("success=true")) == 2
    assert len(fetch("success=false")) == 1
    assert len(fetch("limit=1")) == 1


def test_list_command_runs_filters_by_exact_auth_context(client, isolate_settings):
    _write_engagement(isolate_settings["engagements_dir"])
    # Insert the requested identity first so a backend that silently ignores
    # ``auth_context`` returns the newer cap-alpha row under ``limit=1``.
    for identity in ("cap-beta", "cap-alpha"):
        response = _post(
            client,
            _base_payload(
                command=f"curl https://example.com/whoami as {identity}",
                tool_name="curl",
                technique="AUTH",
                auth_context=identity,
            ),
        )
        assert response.status_code == 201, response.text

    response = client.get(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs",
        params={"technique": "AUTH", "auth_context": "cap-beta", "limit": 1},
    )

    assert response.status_code == 200, response.text
    assert [row["auth_context"] for row in response.json()] == ["cap-beta"]


def test_list_command_runs_filters_output_needing_attention(client, isolate_settings):
    _write_engagement(isolate_settings["engagements_dir"])
    row_ids = []
    for index in range(7):
        response = _post(
            client,
            _base_payload(command=f"output-attention-{index}"),
        )
        assert response.status_code == 201, response.text
        row_ids.append(response.json()["id"])

    with sqlite3.connect(str(db_module.database_path())) as connection:
        connection.execute(
            "UPDATE assessment_command_runs SET output_retention_status = 'integrity_failure' WHERE id = ?",
            (row_ids[0],),
        )
        connection.execute(
            "UPDATE assessment_command_runs SET output_cleanup_status = 'warning' WHERE id = ?",
            (row_ids[1],),
        )
        connection.execute(
            "UPDATE assessment_command_runs SET output_retention_status = 'preview_only' WHERE id = ?",
            (row_ids[2],),
        )
        connection.execute(
            "UPDATE assessment_command_runs SET output_retention_status = 'unmeasured' WHERE id = ?",
            (row_ids[3],),
        )
        connection.execute(
            "UPDATE assessment_command_runs SET output_retention_status = 'partially_measured' WHERE id = ?",
            (row_ids[4],),
        )
        connection.execute(
            "UPDATE assessment_command_runs SET output_retention_status = 'measurement_conflict' WHERE id = ?",
            (row_ids[5],),
        )

    response = client.get(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs?output_attention=true"
    )

    assert response.status_code == 200, response.text
    assert {row["id"] for row in response.json()} == set(row_ids[:6])


def test_list_command_runs_fts_search_finds_keyword(client, isolate_settings):
    _write_engagement(isolate_settings["engagements_dir"])
    assert _post(client, _base_payload()).status_code == 201
    assert (
        _post(
            client,
            _base_payload(
                command="httpx -l /tmp/targets.txt",
                argv=["httpx", "-l", "/tmp/targets.txt"],
                tool_name="execute_command",
                stdout="example.com 200 OK",
            ),
        ).status_code
        == 201
    )

    def search(term):
        response = client.get(
            f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs?q={term}"
        )
        assert response.status_code == 200
        return response.json()

    nmap_hits = search("nmap")
    assert len(nmap_hits) == 1
    assert nmap_hits[0]["tool_name"] == "nmap_scan"

    httpx_hits = search("httpx")
    assert len(httpx_hits) == 1
    assert httpx_hits[0]["tool_name"] == "execute_command"


def test_list_command_runs_finding_aliases_rank_and_explain_matches(
    client, isolate_settings
):
    _write_engagement(isolate_settings["engagements_dir"])
    direct = _post(
        client,
        _base_payload(
            command="curl https://example.com/users/47 # VA-047",
            argv=["curl", "https://example.com/users/47"],
            tool_name="execute_command",
            intent="validate VA-047 IDOR",
            target_host="example.com",
        ),
    )
    assert direct.status_code == 201, direct.text
    compact = _post(
        client,
        _base_payload(
            command="curl https://example.com/admin",
            argv=["curl", "https://example.com/admin"],
            tool_name="execute_command",
            intent="follow-up for VA047",
            target_host="example.com",
        ),
    )
    assert compact.status_code == 201, compact.text

    result_sets = []
    for query in ("VA-047", "VA047", "VA 047", "FINDING-VA-047"):
        response = client.get(
            f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs",
            params={"q": query, "show_matches": "true"},
        )
        assert response.status_code == 200, response.text
        rows = response.json()
        result_sets.append({row["id"] for row in rows})
        assert any(row.get("matches") for row in rows)

    assert len({frozenset(ids) for ids in result_sets}) == 1
    assert {direct.json()["id"], compact.json()["id"]} <= result_sets[0]


def test_list_command_runs_distant_returns_nonmatching_scope_candidates(
    client, isolate_settings
):
    _write_engagement(isolate_settings["engagements_dir"])
    matched = _post(
        client,
        _base_payload(
            command="curl https://example.com/users/47 # VA-047",
            argv=["curl", "https://example.com/users/47"],
            tool_name="execute_command",
            intent="validate VA-047 IDOR",
            target_host="example.com",
        ),
    )
    assert matched.status_code == 201, matched.text
    gap = _post(
        client,
        _base_payload(
            command="curl https://example.com/users/48",
            argv=["curl", "https://example.com/users/48"],
            tool_name="execute_command",
            intent="adjacent user id probe",
            target_host="example.com",
        ),
    )
    assert gap.status_code == 201, gap.text

    response = client.get(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs",
        params={"q": "VA047", "sort": "distant"},
    )
    assert response.status_code == 200, response.text
    ids = {row["id"] for row in response.json()}
    assert gap.json()["id"] in ids
    assert matched.json()["id"] not in ids


def test_large_stdout_spills_to_artifact_file(client, isolate_settings):
    engagement_dir = _write_engagement(isolate_settings["engagements_dir"])
    big = ("A" * 1024 + "\n") * 200  # ~200 KiB — well above 64 KiB cap
    artifact_dir = engagement_dir / "custom-artifacts"
    response = _post(
        client,
        _base_payload(
            command="big-dump --all",
            tool_name="execute_command",
            stdout=big,
            engagement_artifact_dir=str(artifact_dir),
            run_uuid="abc_123-XYZ",
        ),
    )
    assert response.status_code == 201, response.text
    created = response.json()
    assert created["output_retention_status"] == "artifact"
    assert created["stdout_artifact_ref"]
    artifact_file = Path(created["stdout_artifact_ref"])
    assert artifact_file.exists()
    assert artifact_file.name == "abc_123-XYZ.stdout.log"
    assert artifact_file.read_text(encoding="utf-8") == big
    # Preview is capped; full bytes live only in the artifact file.
    assert len(created["stdout_preview"].encode("utf-8")) <= 65_536 + 8


def test_oversized_inline_command_output_still_reaches_retention(
    client, isolate_settings
):
    _write_engagement(isolate_settings["engagements_dir"])
    big = "A" * (1_048_576 + 1)

    response = _post(
        client,
        _base_payload(stdout=big),
    )

    assert response.status_code == 201, response.text
    created = response.json()
    assert created["output_retention_status"] == "artifact"
    assert Path(created["stdout_artifact_ref"]).read_text(encoding="utf-8") == big


def test_finalize_preview_has_api_ceiling(client, isolate_settings):
    _write_engagement(isolate_settings["engagements_dir"])

    response = client.patch(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/1",
        json={
            "status": "completed",
            "ended_at": "2026-04-17T12:00:02Z",
            "stdout_preview": "A" * (65_536 + 1),
        },
    )

    assert response.status_code == 422


def test_duplicate_run_uuid_does_not_overwrite_existing_artifact(
    client, isolate_settings
):
    engagement_dir = _write_engagement(isolate_settings["engagements_dir"])
    artifact_dir = engagement_dir / "custom-artifacts"
    first_output = ("A" * 1024 + "\n") * 200
    second_output = ("B" * 1024 + "\n") * 200

    first = _post(
        client,
        _base_payload(
            command="big-dump --all",
            tool_name="execute_command",
            stdout=first_output,
            engagement_artifact_dir=str(artifact_dir),
            run_uuid="dup-run",
        ),
    )
    assert first.status_code == 201, first.text
    artifact_file = Path(first.json()["stdout_artifact_ref"])
    assert artifact_file.read_text(encoding="utf-8") == first_output

    duplicate = _post(
        client,
        _base_payload(
            command="big-dump --different",
            tool_name="execute_command",
            stdout=second_output,
            engagement_artifact_dir=str(artifact_dir),
            run_uuid="dup-run",
        ),
    )

    assert duplicate.status_code == 409
    assert "run_uuid" in duplicate.text
    assert artifact_file.read_text(encoding="utf-8") == first_output


def test_host_exec_pre_exec_exact_replay_returns_the_committed_row(
    client, isolate_settings
):
    engagement_dir = _write_engagement(isolate_settings["engagements_dir"])
    run_uuid = "host-preexec-lost-response"
    output_dir = engagement_dir / "scans" / "host-exec"
    output_dir.mkdir(parents=True)
    stdout_path = output_dir / f"{run_uuid}.out"
    stderr_path = output_dir / f"{run_uuid}.err"
    stdout_path.write_bytes(b"")
    stderr_path.write_bytes(b"")
    payload = _base_payload(
        command="echo safe",
        argv=["echo", "safe"],
        tool_name="echo",
        route="ignored-by-server",
        run_uuid=run_uuid,
        status="running",
        return_code=None,
        success=None,
        completed_at="",
        stdout="",
        stderr="",
        stdout_path=str(stdout_path),
        stderr_path=str(stderr_path),
        notes='{"intent":"lost response recovery"}',
    )
    endpoint = (
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/host-exec"
    )

    first = client.post(endpoint, json=payload)
    replay = client.post(endpoint, json=payload)

    assert first.status_code == 201, first.text
    assert replay.status_code == 201, replay.text
    assert replay.json()["id"] == first.json()["id"]
    assert replay.json()["idempotent_replay"] is True
    listing = client.get(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs"
    ).json()
    assert [row["id"] for row in listing] == [first.json()["id"]]

    changed = {**payload, "notes": '{"intent":"different execution"}'}
    mismatch = client.post(endpoint, json=changed)
    assert mismatch.status_code == 409
    assert "run_uuid" in mismatch.text


def test_host_exec_replay_identity_uses_serialized_argv_not_display_command(
    client, isolate_settings
):
    engagement_dir = _write_engagement(isolate_settings["engagements_dir"])
    run_uuid = "host-preexec-argv-identity"
    output_dir = engagement_dir / "scans" / "host-exec"
    output_dir.mkdir(parents=True)
    stdout_path = output_dir / f"{run_uuid}.out"
    stderr_path = output_dir / f"{run_uuid}.err"
    stdout_path.write_bytes(b"")
    stderr_path.write_bytes(b"")
    payload = _base_payload(
        command="printf a b",
        argv=["printf", "a b"],
        tool_name="printf",
        route="ignored-by-server",
        run_uuid=run_uuid,
        status="running",
        return_code=None,
        success=None,
        completed_at="",
        stdout="",
        stderr="",
        stdout_path=str(stdout_path),
        stderr_path=str(stderr_path),
    )
    endpoint = f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/host-exec"

    first = client.post(endpoint, json=payload)
    assert first.status_code == 201, first.text
    with db_module.get_connection() as connection:
        connection.execute(
            """
            UPDATE assessment_command_runs
            SET command = ?, command_hash = ?
            WHERE id = ?
            """,
            ("repaired display text", "repaired-display-hash", first.json()["id"]),
        )

    exact_argv_replay = client.post(endpoint, json=payload)
    assert exact_argv_replay.status_code == 201, exact_argv_replay.text
    assert exact_argv_replay.json()["id"] == first.json()["id"]
    assert exact_argv_replay.json()["idempotent_replay"] is True

    same_display_distinct_argv = {
        **payload,
        "argv": ["printf a", "b"],
        "command": "printf a b",
    }
    collision = client.post(endpoint, json=same_display_distinct_argv)
    assert collision.status_code == 409, collision.text
    assert "run_uuid" in collision.text


def test_command_run_rejects_artifact_dir_outside_engagement_root(
    client, isolate_settings, tmp_path
):
    _write_engagement(isolate_settings["engagements_dir"])
    outside_dir = tmp_path / "outside-artifacts"

    response = _post(
        client,
        _base_payload(
            engagement_artifact_dir=str(outside_dir),
            stdout=("A" * 1024) * 200,
        ),
    )

    assert response.status_code == 400
    assert "engagement_artifact_dir" in response.text
    assert not outside_dir.exists()


def test_command_run_rejects_path_like_run_uuid(client, isolate_settings):
    engagement_dir = _write_engagement(isolate_settings["engagements_dir"])

    response = _post(
        client,
        _base_payload(
            run_uuid="../escape",
            stdout=("A" * 1024) * 200,
        ),
    )

    assert response.status_code == 400
    assert "run_uuid" in response.text
    assert not (engagement_dir.parent / "escape.stdout.log").exists()


def test_retention_suppresses_noisy_static_asset_filter(client, isolate_settings):
    _write_engagement(isolate_settings["engagements_dir"])
    # Matches the default static-asset-filter rule in command_run_retention.json
    cmd = "cat /tmp/urls | grep -viE '\\.(jpg|jpeg|png|gif|webp|svg|ico|woff2?|ttf|eot)(\\?|$)'"
    response = _post(
        client,
        _base_payload(
            command=cmd,
            tool_name="execute_command",
            stdout="https://example.com/home\nhttps://example.com/login\n" * 10,
        ),
    )
    assert response.status_code == 201, response.text
    created = response.json()
    assert created["output_retention_status"] == "suppressed"
    assert created["stdout_preview"] == ""
    assert created["stdout_suppression_reason"] == "static-asset-filter"
    # Hash is still computed so reuse-by-hash lookups still work.
    assert created["stdout_sha256"]


def test_host_exec_suppression_erases_spills_and_removes_artifact_index_rows(
    client, isolate_settings
):
    engagement_dir = _write_engagement(isolate_settings["engagements_dir"])
    run_uuid = "host-suppressed-run"
    output_dir = engagement_dir / "scans" / "host-exec"
    output_dir.mkdir(parents=True)
    stdout_path = output_dir / f"{run_uuid}.out"
    stderr_path = output_dir / f"{run_uuid}.err"
    stdout_path.touch(mode=0o600)
    stderr_path.touch(mode=0o600)
    command = "cat urls | grep -viE '\\.(jpg|jpeg|png|gif|webp|svg|ico|woff2?|ttf|eot)'"
    created = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/host-exec",
        json=_base_payload(
            command=f"sh -c {command}",
            argv=["sh", "-c", command],
            tool_name="execute_command",
            route="ignored-by-server",
            run_uuid=run_uuid,
            status="running",
            return_code=None,
            success=None,
            completed_at="",
            stdout="",
            stderr="",
            stdout_path=str(stdout_path),
            stderr_path=str(stderr_path),
        ),
    ).json()
    suppressed = b"https://example.com/logo.png\n" * 100
    stdout_path.write_bytes(suppressed)
    leaked_index = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/artifacts",
        json={
            "path": str(stdout_path),
            "kind": "command-run-output",
            "related_finding_slug": "VA-legacy-link",
        },
    )
    assert leaked_index.status_code == 201, leaked_index.text
    assert "logo.png" in leaked_index.json()["preview_text"]

    response = client.patch(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/{created['id']}",
        json={
            "status": "completed",
            "return_code": 0,
            "ended_at": "2026-04-17T12:00:05Z",
        },
    )

    assert response.status_code == 200, response.text
    finalized = response.json()
    assert finalized["output_retention_status"] == "suppression_deferred"
    assert finalized["stdout_suppression_reason"] == "static-asset-filter"
    assert finalized["stdout_bytes"] == len(suppressed)
    assert finalized["stdout_sha256"] == hashlib.sha256(suppressed).hexdigest()
    assert finalized["stdout_preview"] == ""
    assert finalized["stdout_artifact_ref"] == ""
    assert stdout_path.is_file()
    assert stderr_path.is_file()
    assert stdout_path.read_bytes() == suppressed
    assert stderr_path.read_bytes() == b""
    assert finalized["output_cleanup_status"] == "deferred"
    assert "raw spill bytes remain on disk" in finalized["output_cleanup_warning"]
    assert finalized["stdout_spill_device"] == os.stat(stdout_path).st_dev
    assert finalized["stdout_spill_inode"] == os.stat(stdout_path).st_ino
    assert stat.S_IMODE(os.stat(stdout_path).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(output_dir).st_mode) == 0o700

    relative_paths = {
        row["relative_path"]
        for row in client.get(
            f"/engagements/{ENGAGEMENT_KEY}/assessment/artifacts/search",
            params={"kind": "command-run-output"},
        ).json()
    }
    assert f"scans/host-exec/{run_uuid}.out" not in relative_paths
    assert f"scans/host-exec/{run_uuid}.err" not in relative_paths

    blocked_reregister = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/artifacts",
        json={"path": str(stdout_path), "kind": "command-run-output"},
    )
    assert blocked_reregister.status_code == 409, blocked_reregister.text

    # A later generic refresh only revisits indexed rows; it must not resurrect
    # a suppressed command path even if a file is recreated at that name.
    stdout_path.write_text("replacement must stay unindexed", encoding="utf-8")
    refresh = client.post(f"/engagements/{ENGAGEMENT_KEY}/assessment/artifacts/refresh")
    assert refresh.status_code == 200, refresh.text
    refreshed_paths = {
        row["relative_path"]
        for row in client.get(
            f"/engagements/{ENGAGEMENT_KEY}/assessment/artifacts/search",
            params={"kind": "command-run-output"},
        ).json()
    }
    assert f"scans/host-exec/{run_uuid}.out" not in refreshed_paths
    blocked_replacement = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/artifacts",
        json={"path": str(stdout_path), "kind": "command-run-output"},
    )
    assert blocked_replacement.status_code == 409, blocked_replacement.text


def test_host_exec_suppression_preserves_bytes_when_index_cleanup_fails_before_commit(
    client, isolate_settings, monkeypatch
):
    engagement_dir = _write_engagement(isolate_settings["engagements_dir"])
    run_uuid = "host-suppressed-index-rollback"
    output_dir = engagement_dir / "scans" / "host-exec"
    output_dir.mkdir(parents=True)
    stdout_path = output_dir / f"{run_uuid}.out"
    stderr_path = output_dir / f"{run_uuid}.err"
    stdout_bytes = b"https://example.com/logo.png\n"
    stderr_bytes = b"warning before cleanup\n"
    stdout_path.write_bytes(stdout_bytes)
    stderr_path.write_bytes(stderr_bytes)
    command = "cat urls | grep -viE '\\.(jpg|jpeg|png|gif|webp|svg|ico|woff2?|ttf|eot)'"
    created = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/host-exec",
        json=_base_payload(
            command=f"sh -c {command}",
            argv=["sh", "-c", command],
            tool_name="execute_command",
            route="ignored-by-server",
            run_uuid=run_uuid,
            status="running",
            return_code=None,
            success=None,
            completed_at="",
            stdout="",
            stderr="",
            stdout_path=str(stdout_path),
            stderr_path=str(stderr_path),
        ),
    ).json()

    def fail_index_cleanup(*_args, **_kwargs):
        raise RuntimeError("artifact index unavailable")

    monkeypatch.setattr(
        artifact_index, "remove_verified_command_output", fail_index_cleanup
    )

    with pytest.raises(RuntimeError, match="artifact index unavailable"):
        client.patch(
            f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/{created['id']}",
            json={
                "status": "completed",
                "return_code": 0,
                "ended_at": "2026-04-17T12:00:05Z",
            },
        )

    assert stdout_path.read_bytes() == stdout_bytes
    assert stderr_path.read_bytes() == stderr_bytes
    refetched = client.get(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/{created['id']}"
    ).json()
    assert refetched["status"] == "running"
    assert refetched["stdout_sha256"] == ""


def test_host_exec_suppression_cleanup_failure_keeps_committed_terminal_truth(
    client, isolate_settings, monkeypatch
):
    engagement_dir = _write_engagement(isolate_settings["engagements_dir"])
    run_uuid = "host-suppressed-cleanup-warning"
    output_dir = engagement_dir / "scans" / "host-exec"
    output_dir.mkdir(parents=True)
    stdout_path = output_dir / f"{run_uuid}.out"
    stderr_path = output_dir / f"{run_uuid}.err"
    stdout_bytes = b"https://example.com/logo.png\n"
    stdout_path.write_bytes(stdout_bytes)
    stderr_path.write_bytes(b"")
    command = "cat urls | grep -viE '\\.(jpg|jpeg|png|gif|webp|svg|ico|woff2?|ttf|eot)'"
    created = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/host-exec",
        json=_base_payload(
            command=f"sh -c {command}",
            argv=["sh", "-c", command],
            tool_name="execute_command",
            route="ignored-by-server",
            run_uuid=run_uuid,
            status="running",
            return_code=None,
            success=None,
            completed_at="",
            stdout="",
            stderr="",
            stdout_path=str(stdout_path),
            stderr_path=str(stderr_path),
        ),
    ).json()
    monkeypatch.setattr(
        command_runs_service,
        "_cleanup_suppressed_host_exec_spills",
        lambda _spills: (_ for _ in ()).throw(OSError("simulated cleanup failure")),
    )

    response = client.patch(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/{created['id']}",
        json={
            "status": "completed",
            "return_code": 0,
            "ended_at": "2026-04-17T12:00:05Z",
        },
    )

    assert response.status_code == 200, response.text
    finalized = response.json()
    assert finalized["status"] == "completed"
    assert finalized["output_retention_status"] == "suppression_deferred"
    assert finalized["stdout_bytes"] == len(stdout_bytes)
    assert finalized["stdout_sha256"] == hashlib.sha256(stdout_bytes).hexdigest()
    assert "simulated cleanup failure" in finalized["output_cleanup_warning"]


def test_host_exec_suppression_never_truncates_a_hardlinked_inode(
    client, isolate_settings
):
    engagement_dir = _write_engagement(isolate_settings["engagements_dir"])
    run_uuid = "host-suppressed-hardlink"
    output_dir = engagement_dir / "scans" / "host-exec"
    output_dir.mkdir(parents=True)
    stdout_path = output_dir / f"{run_uuid}.out"
    stderr_path = output_dir / f"{run_uuid}.err"
    original = b"https://example.com/logo.png\n"
    stdout_path.write_bytes(original)
    stderr_path.write_bytes(b"")
    victim_path = engagement_dir / "must-not-be-truncated.txt"
    os.link(stdout_path, victim_path)
    command = "cat urls | grep -viE '\\.(jpg|jpeg|png|gif|webp|svg|ico|woff2?|ttf|eot)'"
    created = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/host-exec",
        json=_base_payload(
            command=f"sh -c {command}",
            argv=["sh", "-c", command],
            tool_name="execute_command",
            route="ignored-by-server",
            run_uuid=run_uuid,
            status="running",
            return_code=None,
            success=None,
            completed_at="",
            stdout="",
            stderr="",
            stdout_path=str(stdout_path),
            stderr_path=str(stderr_path),
        ),
    ).json()

    response = client.patch(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/{created['id']}",
        json={
            "status": "completed",
            "return_code": 0,
            "ended_at": "2026-04-17T12:00:05Z",
        },
    )

    assert response.status_code == 200, response.text
    finalized = response.json()
    assert victim_path.read_bytes() == original
    assert stdout_path.read_bytes() == original
    assert "hardlink" in finalized["output_cleanup_warning"].lower()
    assert finalized["output_cleanup_status"] == "warning"


def test_host_exec_suppression_detects_same_inode_content_change_before_cleanup(
    client, isolate_settings, monkeypatch
):
    engagement_dir = _write_engagement(isolate_settings["engagements_dir"])
    run_uuid = "host-suppressed-content-change"
    output_dir = engagement_dir / "scans" / "host-exec"
    output_dir.mkdir(parents=True)
    stdout_path = output_dir / f"{run_uuid}.out"
    stderr_path = output_dir / f"{run_uuid}.err"
    original = b"https://example.com/logo.png\n"
    changed = b"X" * len(original)
    stdout_path.write_bytes(original)
    stderr_path.write_bytes(b"")
    command = "cat urls | grep -viE '\\.(jpg|jpeg|png|gif|webp|svg|ico|woff2?|ttf|eot)'"
    created = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/host-exec",
        json=_base_payload(
            command=f"sh -c {command}",
            argv=["sh", "-c", command],
            tool_name="execute_command",
            route="ignored-by-server",
            run_uuid=run_uuid,
            status="running",
            return_code=None,
            success=None,
            completed_at="",
            stdout="",
            stderr="",
            stdout_path=str(stdout_path),
            stderr_path=str(stderr_path),
        ),
    ).json()
    real_cleanup = command_runs_service._cleanup_suppressed_host_exec_spills

    def mutate_then_cleanup(spills):
        stdout_path.write_bytes(changed)
        return real_cleanup(spills)

    monkeypatch.setattr(
        command_runs_service,
        "_cleanup_suppressed_host_exec_spills",
        mutate_then_cleanup,
    )

    response = client.patch(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/{created['id']}",
        json={
            "status": "completed",
            "return_code": 0,
            "ended_at": "2026-04-17T12:00:05Z",
        },
    )

    assert response.status_code == 200, response.text
    finalized = response.json()
    assert stdout_path.read_bytes() == changed
    assert "content changed" in finalized["output_cleanup_warning"].lower()
    assert finalized["output_cleanup_status"] == "warning"


def test_host_exec_suppression_cleanup_never_unlinks_a_mutable_name(
    client, isolate_settings, monkeypatch
):
    engagement_dir = _write_engagement(isolate_settings["engagements_dir"])
    run_uuid = "host-suppressed-no-unlink"
    output_dir = engagement_dir / "scans" / "host-exec"
    output_dir.mkdir(parents=True)
    stdout_path = output_dir / f"{run_uuid}.out"
    stderr_path = output_dir / f"{run_uuid}.err"
    stdout_path.write_text("https://example.com/logo.png\n", encoding="utf-8")
    stderr_path.write_bytes(b"")
    command = "cat urls | grep -viE '\\.(jpg|jpeg|png|gif|webp|svg|ico|woff2?|ttf|eot)'"
    created = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/host-exec",
        json=_base_payload(
            command=f"sh -c {command}",
            argv=["sh", "-c", command],
            tool_name="execute_command",
            route="ignored-by-server",
            run_uuid=run_uuid,
            status="running",
            return_code=None,
            success=None,
            completed_at="",
            stdout="",
            stderr="",
            stdout_path=str(stdout_path),
            stderr_path=str(stderr_path),
        ),
    ).json()

    def fail_if_unlinked(*_args, **_kwargs):
        pytest.fail("suppression cleanup must not unlink a mutable pathname")

    monkeypatch.setattr(command_runs_service.os, "unlink", fail_if_unlinked)

    response = client.patch(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/{created['id']}",
        json={
            "status": "completed",
            "return_code": 0,
            "ended_at": "2026-04-17T12:00:05Z",
        },
    )

    assert response.status_code == 200, response.text
    assert stdout_path.is_file()
    assert stdout_path.read_text(encoding="utf-8") == "https://example.com/logo.png\n"
    assert stderr_path.is_file()
    assert response.json()["output_cleanup_status"] == "deferred"


def test_host_exec_suppression_only_requires_read_access_to_spills(
    client, isolate_settings
):
    engagement_dir = _write_engagement(isolate_settings["engagements_dir"])
    run_uuid = "host-suppressed-read-only"
    output_dir = engagement_dir / "scans" / "host-exec"
    output_dir.mkdir(parents=True)
    stdout_path = output_dir / f"{run_uuid}.out"
    stderr_path = output_dir / f"{run_uuid}.err"
    stdout_path.write_text("https://example.com/logo.png\n", encoding="utf-8")
    stderr_path.write_bytes(b"")
    script = "cat urls | grep -viE '\\.(jpg|jpeg|png|gif|webp|svg|ico|woff2?|ttf|eot)'"
    created_response = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/host-exec",
        json=_base_payload(
            command=f"sh -c {script}",
            argv=["sh", "-c", script],
            tool_name="execute_command",
            route="ignored-by-server",
            run_uuid=run_uuid,
            status="running",
            return_code=None,
            success=None,
            completed_at="",
            stdout="",
            stderr="",
            stdout_path=str(stdout_path),
            stderr_path=str(stderr_path),
        ),
    )
    assert created_response.status_code == 201, created_response.text
    os.chmod(stdout_path, 0o400)
    os.chmod(stderr_path, 0o400)

    response = client.patch(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/{created_response.json()['id']}",
        json={
            "status": "completed",
            "return_code": 0,
            "ended_at": "2026-04-17T12:00:05Z",
        },
    )

    assert response.status_code == 200, response.text
    assert response.json()["output_cleanup_status"] == "deferred"
    assert stdout_path.read_text(encoding="utf-8") == "https://example.com/logo.png\n"


def test_host_exec_suppression_crash_leaves_durable_cleanup_pending_state(
    client, isolate_settings, monkeypatch
):
    engagement_dir = _write_engagement(isolate_settings["engagements_dir"])
    run_uuid = "host-suppressed-cleanup-crash"
    output_dir = engagement_dir / "scans" / "host-exec"
    output_dir.mkdir(parents=True)
    stdout_path = output_dir / f"{run_uuid}.out"
    stderr_path = output_dir / f"{run_uuid}.err"
    stdout_path.write_text("https://example.com/logo.png\n", encoding="utf-8")
    stderr_path.write_bytes(b"")
    command = "cat urls | grep -viE '\\.(jpg|jpeg|png|gif|webp|svg|ico|woff2?|ttf|eot)'"
    created = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/host-exec",
        json=_base_payload(
            command=f"sh -c {command}",
            argv=["sh", "-c", command],
            tool_name="execute_command",
            route="ignored-by-server",
            run_uuid=run_uuid,
            status="running",
            return_code=None,
            success=None,
            completed_at="",
            stdout="",
            stderr="",
            stdout_path=str(stdout_path),
            stderr_path=str(stderr_path),
        ),
    ).json()

    retained_descriptors: list[int] = []
    real_cleanup = command_runs_service._cleanup_suppressed_host_exec_spills

    def crash_after_capturing_descriptors(spills):
        for _path, retention in spills:
            retained_descriptors.extend(
                [
                    int(retention["file_descriptor"]),
                    int(retention["directory_descriptor"]),
                ]
            )
        raise SystemExit("simulated worker crash")

    monkeypatch.setattr(
        command_runs_service,
        "_cleanup_suppressed_host_exec_spills",
        crash_after_capturing_descriptors,
    )

    with pytest.raises(SystemExit, match="simulated worker crash"):
        command_runs_service.finalize_command_run(
            int(created["engagement_id"]),
            command_run_id=int(created["id"]),
            status_value="completed",
            return_code=0,
            ended_at="2026-04-17T12:00:05Z",
        )

    refetched = client.get(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/{created['id']}"
    ).json()
    assert refetched["status"] == "completed"
    assert refetched["output_retention_status"] == "suppression_pending"
    assert refetched["output_cleanup_status"] == "pending"
    assert retained_descriptors
    for descriptor in retained_descriptors:
        with pytest.raises(OSError):
            os.fstat(descriptor)

    monkeypatch.setattr(
        command_runs_service,
        "_cleanup_suppressed_host_exec_spills",
        real_cleanup,
    )
    recovered = command_runs_service.finalize_command_run(
        int(created["engagement_id"]),
        command_run_id=int(created["id"]),
        status_value="completed",
        return_code=0,
        ended_at="2026-04-17T12:00:06Z",
    )
    assert recovered["recovered_pending_output"] is True
    assert recovered["output_cleanup_status"] == "deferred"
    assert recovered["output_retention_status"] == "suppression_deferred"


@pytest.mark.parametrize("recovery_error", [False, True])
def test_host_exec_integrity_pending_recovers_after_postcommit_worker_crash(
    recovery_error, client, isolate_settings, monkeypatch
):
    engagement_dir = _write_engagement(isolate_settings["engagements_dir"])
    run_uuid = f"host-integrity-postcommit-crash-{int(recovery_error)}"
    output_dir = engagement_dir / "scans" / "host-exec"
    output_dir.mkdir(parents=True)
    stdout_path = output_dir / f"{run_uuid}.out"
    stderr_path = output_dir / f"{run_uuid}.err"
    stdout_path.write_bytes(b"trusted retained output\n")
    stderr_path.write_bytes(b"")
    created_response = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/host-exec",
        json=_base_payload(
            command="echo retained",
            argv=["echo", "retained"],
            tool_name="echo",
            route="ignored-by-server",
            run_uuid=run_uuid,
            status="running",
            return_code=None,
            success=None,
            completed_at="",
            stdout="",
            stderr="",
            stdout_path=str(stdout_path),
            stderr_path=str(stderr_path),
        ),
    )
    assert created_response.status_code == 201, created_response.text
    created = created_response.json()
    real_verify = artifact_index._verified_snapshot_payload
    monkeypatch.setattr(
        artifact_index,
        "_verified_snapshot_payload",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            SystemExit("simulated postcommit worker crash")
        ),
    )

    with pytest.raises(SystemExit, match="simulated postcommit worker crash"):
        command_runs_service.finalize_command_run(
            int(created["engagement_id"]),
            command_run_id=int(created["id"]),
            status_value="completed",
            return_code=0,
            ended_at="2026-04-17T12:00:05Z",
        )

    pending = client.get(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/{created['id']}"
    ).json()
    assert pending["status"] == "completed"
    assert pending["output_retention_status"] == "artifact"
    assert pending["output_integrity_status"] == "pending"
    assert pending["stdout_artifact_ref"]

    if recovery_error:
        monkeypatch.setattr(
            artifact_index,
            "_verified_snapshot_payload",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                OSError("simulated recovery read failure")
            ),
        )
    else:
        monkeypatch.setattr(
            artifact_index,
            "_verified_snapshot_payload",
            real_verify,
        )
    recovered = command_runs_service.finalize_command_run(
        int(created["engagement_id"]),
        command_run_id=int(created["id"]),
        status_value="completed",
        return_code=0,
        ended_at="2026-04-17T12:00:06Z",
    )
    assert recovered["recovered_pending_output"] is True
    if recovery_error:
        assert recovered["output_integrity_status"] == "warning"
        assert recovered["output_retention_status"] == "integrity_failure"
        assert "simulated recovery read failure" in recovered[
            "output_integrity_warning"
        ]
        assert recovered["stdout_artifact_ref"] == ""
    else:
        assert recovered["output_integrity_status"] == "verified"
        assert Path(recovered["stdout_artifact_ref"]).read_bytes() == (
            b"trusted retained output\n"
        )


def test_host_exec_retained_artifact_path_is_bound_to_hashed_bytes(
    client, isolate_settings, monkeypatch
):
    engagement_dir = _write_engagement(isolate_settings["engagements_dir"])
    run_uuid = "host-retained-path-pin"
    output_dir = engagement_dir / "scans" / "host-exec"
    output_dir.mkdir(parents=True)
    stdout_path = output_dir / f"{run_uuid}.out"
    stderr_path = output_dir / f"{run_uuid}.err"
    original = b"trusted compiler output\n"
    replacement = b"attacker replacement\n"
    stdout_path.write_bytes(original)
    stderr_path.write_bytes(b"")
    created = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/host-exec",
        json=_base_payload(
            command="cmake --build build",
            argv=["cmake", "--build", "build"],
            tool_name="cmake",
            route="ignored-by-server",
            run_uuid=run_uuid,
            status="running",
            return_code=None,
            success=None,
            completed_at="",
            stdout="",
            stderr="",
            stdout_path=str(stdout_path),
            stderr_path=str(stderr_path),
        ),
    ).json()
    real_register = artifact_index.register_verified_command_output
    swapped = False

    def swap_original_then_register(*args, **kwargs):
        nonlocal swapped
        if not swapped:
            swapped = True
            stdout_path.replace(output_dir / "original-moved.out")
            stdout_path.write_bytes(replacement)
        return real_register(*args, **kwargs)

    monkeypatch.setattr(
        artifact_index, "register_verified_command_output", swap_original_then_register
    )

    response = client.patch(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/{created['id']}",
        json={
            "status": "completed",
            "return_code": 0,
            "ended_at": "2026-04-17T12:00:05Z",
        },
    )

    assert response.status_code == 200, response.text
    finalized = response.json()
    artifact_path = Path(finalized["stdout_artifact_ref"])
    assert swapped is True
    assert artifact_path.read_bytes() == original
    assert (
        hashlib.sha256(artifact_path.read_bytes()).hexdigest()
        == finalized["stdout_sha256"]
    )
    indexed_paths = {
        row["relative_path"]
        for row in client.get(
            f"/engagements/{ENGAGEMENT_KEY}/assessment/artifacts/search",
            params={"kind": "command-run-output"},
        ).json()
    }
    assert f"scans/host-exec/{run_uuid}.out" not in indexed_paths
    assert f"scans/host-exec/{run_uuid}.err" not in indexed_paths
    assert f"scans/command-runs/{run_uuid}.stdout.log" in indexed_paths


def test_host_exec_snapshot_publication_fsyncs_directory_metadata(
    client, isolate_settings, monkeypatch
):
    engagement_dir = _write_engagement(isolate_settings["engagements_dir"])
    run_uuid = "host-snapshot-directory-fsync"
    output_dir = engagement_dir / "scans" / "host-exec"
    output_dir.mkdir(parents=True)
    stdout_path = output_dir / f"{run_uuid}.out"
    stderr_path = output_dir / f"{run_uuid}.err"
    stdout_path.write_bytes(b"durable evidence\n")
    stderr_path.write_bytes(b"")
    created = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/host-exec",
        json=_base_payload(
            command="echo durable",
            argv=["echo", "durable"],
            tool_name="echo",
            route="ignored-by-server",
            run_uuid=run_uuid,
            status="running",
            return_code=None,
            success=None,
            completed_at="",
            stdout="",
            stderr="",
            stdout_path=str(stdout_path),
            stderr_path=str(stderr_path),
        ),
    ).json()
    real_fsync = command_runs_service.os.fsync
    directory_syncs = 0

    def track_fsync(descriptor):
        nonlocal directory_syncs
        if stat.S_ISDIR(os.fstat(descriptor).st_mode):
            directory_syncs += 1
        return real_fsync(descriptor)

    monkeypatch.setattr(command_runs_service.os, "fsync", track_fsync)

    response = client.patch(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/{created['id']}",
        json={
            "status": "completed",
            "return_code": 0,
            "ended_at": "2026-04-17T12:00:05Z",
        },
    )

    assert response.status_code == 200, response.text
    assert directory_syncs >= 2


def test_host_exec_publication_failure_never_deletes_preexisting_snapshot(
    client, isolate_settings
):
    engagement_dir = _write_engagement(isolate_settings["engagements_dir"])
    run_uuid = "host-preexisting-snapshot"
    output_dir = engagement_dir / "scans" / "host-exec"
    snapshot_dir = engagement_dir / "scans" / "command-runs"
    output_dir.mkdir(parents=True)
    snapshot_dir.mkdir(parents=True)
    stdout_path = output_dir / f"{run_uuid}.out"
    stderr_path = output_dir / f"{run_uuid}.err"
    stdout_path.write_text("trusted output\n", encoding="utf-8")
    stderr_path.write_bytes(b"")
    preexisting = snapshot_dir / f"{run_uuid}.stdout.log"
    preexisting.write_text("preexisting evidence must survive\n", encoding="utf-8")
    created = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/host-exec",
        json=_base_payload(
            command="echo trusted",
            argv=["echo", "trusted"],
            tool_name="echo",
            route="ignored-by-server",
            run_uuid=run_uuid,
            status="running",
            return_code=None,
            success=None,
            completed_at="",
            stdout="",
            stderr="",
            stdout_path=str(stdout_path),
            stderr_path=str(stderr_path),
        ),
    ).json()

    response = client.patch(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/{created['id']}",
        json={
            "status": "completed",
            "return_code": 0,
            "ended_at": "2026-04-17T12:00:05Z",
        },
    )

    assert response.status_code == 409, response.text
    assert preexisting.read_text(encoding="utf-8") == "preexisting evidence must survive\n"
    refetched = client.get(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/{created['id']}"
    ).json()
    assert refetched["status"] == "running"


def test_host_exec_postcommit_snapshot_identity_check_clears_swapped_ref(
    client, isolate_settings, monkeypatch
):
    engagement_dir = _write_engagement(isolate_settings["engagements_dir"])
    run_uuid = "host-snapshot-final-gap"
    output_dir = engagement_dir / "scans" / "host-exec"
    output_dir.mkdir(parents=True)
    stdout_path = output_dir / f"{run_uuid}.out"
    stderr_path = output_dir / f"{run_uuid}.err"
    stdout_path.write_text("trusted output A\n", encoding="utf-8")
    stderr_path.write_bytes(b"")
    created = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/host-exec",
        json=_base_payload(
            command="echo trusted",
            argv=["echo", "trusted"],
            tool_name="echo",
            route="ignored-by-server",
            run_uuid=run_uuid,
            status="running",
            return_code=None,
            success=None,
            completed_at="",
            stdout="",
            stderr="",
            stdout_path=str(stdout_path),
            stderr_path=str(stderr_path),
        ),
    ).json()
    real_fstat = os.fstat
    artifact_registered = False
    swapped = False
    real_register = artifact_index.register_verified_command_output

    def mark_registered(*args, **kwargs):
        nonlocal artifact_registered
        result = real_register(*args, **kwargs)
        artifact_registered = True
        return result

    def swap_after_path_stat(descriptor):
        nonlocal swapped
        if artifact_registered and not swapped:
            snapshot = (
                engagement_dir
                / "scans"
                / "command-runs"
                / f"{run_uuid}.stdout.log"
            )
            if snapshot.exists():
                swapped = True
                snapshot.replace(snapshot.with_suffix(".trusted-moved"))
                snapshot.write_text("replacement B\n", encoding="utf-8")
        return real_fstat(descriptor)

    monkeypatch.setattr(artifact_index, "register_verified_command_output", mark_registered)
    monkeypatch.setattr(command_runs_service.os, "fstat", swap_after_path_stat)

    response = client.patch(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/{created['id']}",
        json={
            "status": "completed",
            "return_code": 0,
            "ended_at": "2026-04-17T12:00:05Z",
        },
    )

    assert swapped is True
    assert response.status_code == 409, response.text
    refetched = client.get(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/{created['id']}"
    ).json()
    assert refetched["status"] == "completed"
    assert refetched["stdout_artifact_ref"] == ""
    artifacts = client.get(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/artifacts/search",
        params={"kind": "command-run-output"},
    ).json()
    swapped_artifact = next(
        row for row in artifacts if row["relative_path"].endswith("stdout.log")
    )
    assert swapped_artifact["present"] is False
    assert swapped_artifact["integrity_status"] == "mismatch"
    assert swapped_artifact["sha256"] == hashlib.sha256(b"trusted output A\n").hexdigest()


@pytest.mark.parametrize("replacement_kind", ["symlink", "regular"])
def test_verified_snapshot_get_and_refresh_reject_path_replacement(
    client, isolate_settings, replacement_kind
):
    engagement_dir = _write_engagement(isolate_settings["engagements_dir"])
    run_uuid = "host-snapshot-readthrough"
    output_dir = engagement_dir / "scans" / "host-exec"
    output_dir.mkdir(parents=True)
    stdout_path = output_dir / f"{run_uuid}.out"
    stderr_path = output_dir / f"{run_uuid}.err"
    original = b"trusted output\n"
    stdout_path.write_bytes(original)
    stderr_path.write_bytes(b"")
    created = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/host-exec",
        json=_base_payload(
            command="echo trusted",
            argv=["echo", "trusted"],
            tool_name="echo",
            route="ignored-by-server",
            run_uuid=run_uuid,
            status="running",
            return_code=None,
            success=None,
            completed_at="",
            stdout="",
            stderr="",
            stdout_path=str(stdout_path),
            stderr_path=str(stderr_path),
        ),
    ).json()
    finalized = client.patch(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/{created['id']}",
        json={
            "status": "completed",
            "return_code": 0,
            "ended_at": "2026-04-17T12:00:05Z",
        },
    ).json()
    snapshot = Path(finalized["stdout_artifact_ref"])
    artifacts = client.get(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/artifacts/search",
        params={"kind": "command-run-output"},
    ).json()
    artifact = next(row for row in artifacts if row["relative_path"].endswith("stdout.log"))
    original_sha = artifact["sha256"]
    moved = snapshot.with_suffix(".trusted-moved")
    outside_secret = engagement_dir.parent / "outside-secret.txt"
    outside_secret.write_text("outside secret must never be indexed\n", encoding="utf-8")
    snapshot.replace(moved)
    if replacement_kind == "symlink":
        snapshot.symlink_to(outside_secret)
    else:
        snapshot.write_text("regular replacement must never be indexed\n", encoding="utf-8")

    fetched = client.get(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/artifacts/{artifact['id']}"
    )
    assert fetched.status_code == 409, fetched.text
    refreshed = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/artifacts/refresh"
    )
    assert refreshed.status_code == 200, refreshed.text
    after = next(
        row
        for row in client.get(
            f"/engagements/{ENGAGEMENT_KEY}/assessment/artifacts/search",
            params={"kind": "command-run-output"},
        ).json()
        if row["id"] == artifact["id"]
    )
    assert after["present"] is False
    assert after["sha256"] == original_sha
    assert "outside secret" not in after["preview_text"]
    assert "regular replacement" not in after["preview_text"]


def test_generic_artifact_registration_uses_nofollow_descriptor_walk(
    client, isolate_settings, monkeypatch
):
    engagement_dir = _write_engagement(isolate_settings["engagements_dir"])
    notes_dir = engagement_dir / "notes"
    notes_dir.mkdir()
    artifact_path = notes_dir / "race.txt"
    artifact_path.write_text("safe engagement data\n", encoding="utf-8")
    outside_dir = engagement_dir.parent / "outside-artifacts"
    outside_dir.mkdir()
    outside_path = outside_dir / artifact_path.name
    outside_path.write_text("outside secret must never be indexed\n", encoding="utf-8")
    moved_notes = engagement_dir / "notes-before-swap"
    real_payload = artifact_index._file_payload_if_changed
    swapped = False

    def swap_parent_after_normalization(*args, **kwargs):
        nonlocal swapped
        if not swapped:
            swapped = True
            notes_dir.replace(moved_notes)
            notes_dir.symlink_to(outside_dir, target_is_directory=True)
        return real_payload(*args, **kwargs)

    monkeypatch.setattr(
        artifact_index,
        "_file_payload_if_changed",
        swap_parent_after_normalization,
    )

    response = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/artifacts",
        json={"path": str(artifact_path), "kind": "note"},
    )

    assert swapped is True
    assert response.status_code == 409, response.text
    indexed = client.get(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/artifacts/search",
        params={"q": "outside secret"},
    ).json()
    assert indexed == []


def test_generic_artifact_registration_supports_engagement_root_directory(
    client, isolate_settings
):
    engagement_dir = _write_engagement(isolate_settings["engagements_dir"])

    response = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/artifacts",
        json={"path": str(engagement_dir), "kind": "evidence-directory"},
    )

    assert response.status_code == 201, response.text
    artifact = response.json()
    assert artifact["relative_path"] == "."
    assert artifact["present"] is True
    assert artifact["size_bytes"] == 0
    assert artifact["sha256"] == ""


def test_generic_upsert_cannot_rebind_verified_snapshot_metadata_or_provenance(
    client, isolate_settings
):
    engagement_dir = _write_engagement(isolate_settings["engagements_dir"])
    run_uuid = "host-verified-upsert-race"
    output_dir = engagement_dir / "scans" / "host-exec"
    output_dir.mkdir(parents=True)
    stdout_path = output_dir / f"{run_uuid}.out"
    stderr_path = output_dir / f"{run_uuid}.err"
    stdout_path.write_bytes(b"trusted evidence\n")
    stderr_path.write_bytes(b"")
    created_response = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/host-exec",
        json=_base_payload(
            command="echo trusted",
            argv=["echo", "trusted"],
            tool_name="echo",
            route="ignored-by-server",
            run_uuid=run_uuid,
            status="running",
            return_code=None,
            success=None,
            completed_at="",
            stdout="",
            stderr="",
            stdout_path=str(stdout_path),
            stderr_path=str(stderr_path),
        ),
    )
    assert created_response.status_code == 201, created_response.text
    created = created_response.json()
    finalized_response = client.patch(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/{created['id']}",
        json={
            "status": "completed",
            "return_code": 0,
            "ended_at": "2026-04-17T12:00:05Z",
        },
    )
    assert finalized_response.status_code == 200, finalized_response.text
    relative_path = Path(finalized_response.json()["stdout_artifact_ref"]).relative_to(
        engagement_dir.resolve()
    ).as_posix()
    other_run = _post(
        client,
        _base_payload(
            command="echo unrelated",
            argv=["echo", "unrelated"],
            run_uuid="generic-upsert-attacker",
        ),
    ).json()

    artifact_index._store_artifact(
        int(created["engagement_id"]),
        relative_path=relative_path,
        kind="attacker-kind",
        media_type="text/plain",
        file_data={
            "present": True,
            "size_bytes": 8,
            "sha256": hashlib.sha256(b"attacker").hexdigest(),
            "preview_text": "attacker",
            "indexed_text": "attacker",
        },
        sensitive=True,
        producer_agent_id="attacker-agent",
        producer_agent_role="attacker-role",
        producer_command_run_id=int(other_run["id"]),
        related_finding_slug="VA-attacker",
        related_chain_key="attacker-chain",
        related_surface_id=None,
        related_request_variant_id=None,
    )

    artifact = next(
        row
        for row in client.get(
            f"/engagements/{ENGAGEMENT_KEY}/assessment/artifacts/search",
            params={"kind": "command-run-output"},
        ).json()
        if row["relative_path"] == relative_path
    )
    assert artifact["sha256"] == hashlib.sha256(b"trusted evidence\n").hexdigest()
    assert artifact["preview_text"] == "trusted evidence\n"
    assert artifact["producer_command_run_id"] == created["id"]
    assert artifact["producer_agent_role"] == created["agent_name"]
    assert artifact["related_finding_slug"] is None


def test_concurrent_host_finalizers_share_canonical_output_truth(
    client, isolate_settings, monkeypatch
):
    engagement_dir = _write_engagement(isolate_settings["engagements_dir"])
    run_uuid = "host-concurrent-finalize-owner"
    output_dir = engagement_dir / "scans" / "host-exec"
    output_dir.mkdir(parents=True)
    stdout_path = output_dir / f"{run_uuid}.out"
    stderr_path = output_dir / f"{run_uuid}.err"
    stdout_path.write_text("https://example.com/logo.png\n", encoding="utf-8")
    stderr_path.write_bytes(b"")
    command = "cat urls | grep -viE '\\.(jpg|jpeg|png|gif|webp|svg|ico|woff2?|ttf|eot)'"
    created = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/host-exec",
        json=_base_payload(
            command=f"sh -c {command}",
            argv=["sh", "-c", command],
            tool_name="execute_command",
            route="ignored-by-server",
            run_uuid=run_uuid,
            status="running",
            return_code=None,
            success=None,
            completed_at="",
            stdout="",
            stderr="",
            stdout_path=str(stdout_path),
            stderr_path=str(stderr_path),
        ),
    ).json()
    real_apply = command_runs_service._apply_host_exec_spill_retention
    first_hash_started = threading.Event()
    release_first = threading.Event()
    call_lock = threading.Lock()
    call_count = 0

    def track_hash_owner(*args, **kwargs):
        nonlocal call_count
        result = real_apply(*args, **kwargs)
        with call_lock:
            call_count += 1
            ordinal = call_count
        if ordinal == 1:
            first_hash_started.set()
            assert release_first.wait(timeout=5)
        return result

    monkeypatch.setattr(
        command_runs_service, "_apply_host_exec_spill_retention", track_hash_owner
    )
    endpoint = f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/{created['id']}"
    payload = {
        "status": "completed",
        "return_code": 0,
        "ended_at": "2026-04-17T12:00:05Z",
    }

    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(client.patch, endpoint, json=payload)
        assert first_hash_started.wait(timeout=5)
        second = executor.submit(client.patch, endpoint, json=payload)
        release_first.set()
        responses = [first.result(timeout=5), second.result(timeout=5)]

    assert all(response.status_code in {200, 409} for response in responses)
    successful = [
        response.json() for response in responses if response.status_code == 200
    ]
    conflicts = [
        response.json() for response in responses if response.status_code == 409
    ]
    assert len(successful) in {1, 2}
    assert len(successful) + len(conflicts) == 2
    assert call_count == 2 * len(successful)
    assert {
        result["stdout_sha256"] for result in successful
    } == {hashlib.sha256(b"https://example.com/logo.png\n").hexdigest()}

    # After the terminal transaction commits, either the original owner can
    # finish deferred cleanup before the waiter acquires SQLite's write lock,
    # or the waiter can safely recover that pending work. Both schedules retain
    # one terminal write and identical output truth.
    if conflicts:
        assert conflicts[0]["detail"]["existing"]["stdout_sha256"] == successful[0][
            "stdout_sha256"
        ]
    else:
        assert sum(
            result.get("recovered_pending_output") is True for result in successful
        ) == 1


def test_host_exec_suppression_rejects_entry_swapped_before_unlink(
    client, isolate_settings, monkeypatch
):
    engagement_dir = _write_engagement(isolate_settings["engagements_dir"])
    run_uuid = "host-suppression-swap"
    output_dir = engagement_dir / "scans" / "host-exec"
    output_dir.mkdir(parents=True)
    stdout_path = output_dir / f"{run_uuid}.out"
    stderr_path = output_dir / f"{run_uuid}.err"
    stdout_path.write_text("https://example.com/logo.png\n", encoding="utf-8")
    stderr_path.write_bytes(b"")
    command = "cat urls | grep -viE '\\.(jpg|jpeg|png|gif|webp|svg|ico|woff2?|ttf|eot)'"
    created = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/host-exec",
        json=_base_payload(
            command=f"sh -c {command}",
            argv=["sh", "-c", command],
            tool_name="execute_command",
            route="ignored-by-server",
            run_uuid=run_uuid,
            status="running",
            return_code=None,
            success=None,
            completed_at="",
            stdout="",
            stderr="",
            stdout_path=str(stdout_path),
            stderr_path=str(stderr_path),
        ),
    ).json()
    secret = engagement_dir / "secret.txt"
    secret.write_text("must not be unlinked", encoding="utf-8")
    moved_spill = output_dir / "attacker-retained.out"
    real_stat = os.stat
    swapped = False

    def swap_before_lstat(path, *args, **kwargs):
        nonlocal swapped
        if (
            not swapped
            and os.fspath(path) == stdout_path.name
            and kwargs.get("dir_fd") is not None
            and kwargs.get("follow_symlinks") is False
        ):
            swapped = True
            stdout_path.replace(moved_spill)
            stdout_path.symlink_to(secret)
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(command_runs_service.os, "stat", swap_before_lstat)

    response = client.patch(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/{created['id']}",
        json={
            "status": "completed",
            "return_code": 0,
            "ended_at": "2026-04-17T12:00:05Z",
        },
    )

    assert swapped is True
    assert response.status_code == 200, response.text
    finalized = response.json()
    assert finalized["status"] == "completed"
    assert finalized["output_retention_status"] == "suppression_deferred"
    assert "changed before cleanup" in finalized["output_cleanup_warning"]
    assert secret.read_text(encoding="utf-8") == "must not be unlinked"
    assert stdout_path.is_symlink()
    assert moved_spill.is_file()
    assert moved_spill.read_text(encoding="utf-8") == "https://example.com/logo.png\n"
    refetched = client.get(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/{created['id']}"
    ).json()
    assert refetched["status"] == "completed"
    assert refetched["output_retention_status"] == "suppression_deferred"
    assert refetched["stdout_sha256"]


def test_host_exec_suppression_uses_retained_parent_dirfd_after_directory_swap(
    client, isolate_settings, monkeypatch
):
    engagement_dir = _write_engagement(isolate_settings["engagements_dir"])
    run_uuid = "host-parent-dir-swap"
    output_dir = engagement_dir / "scans" / "host-exec"
    output_dir.mkdir(parents=True)
    stdout_path = output_dir / f"{run_uuid}.out"
    stderr_path = output_dir / f"{run_uuid}.err"
    stdout_path.write_text("https://example.com/logo.png\n", encoding="utf-8")
    stderr_path.write_bytes(b"")
    command = "cat urls | grep -viE '\\.(jpg|jpeg|png|gif|webp|svg|ico|woff2?|ttf|eot)'"
    created = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/host-exec",
        json=_base_payload(
            command=f"sh -c {command}",
            argv=["sh", "-c", command],
            tool_name="execute_command",
            route="ignored-by-server",
            run_uuid=run_uuid,
            status="running",
            return_code=None,
            success=None,
            completed_at="",
            stdout="",
            stderr="",
            stdout_path=str(stdout_path),
            stderr_path=str(stderr_path),
        ),
    ).json()
    attacker_dir = engagement_dir / "attacker-output"
    attacker_dir.mkdir()
    attacker_stdout = attacker_dir / stdout_path.name
    attacker_stderr = attacker_dir / stderr_path.name
    attacker_stdout.write_text("attacker data must survive", encoding="utf-8")
    attacker_stderr.write_text("attacker stderr must survive", encoding="utf-8")
    moved_dir = engagement_dir / "verified-output-moved"
    real_cleanup = command_runs_service._cleanup_suppressed_host_exec_spills
    swapped = False

    def swap_parent_then_cleanup(spills):
        nonlocal swapped
        swapped = True
        output_dir.replace(moved_dir)
        output_dir.symlink_to(attacker_dir, target_is_directory=True)
        return real_cleanup(spills)

    monkeypatch.setattr(
        command_runs_service,
        "_cleanup_suppressed_host_exec_spills",
        swap_parent_then_cleanup,
    )

    response = client.patch(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/{created['id']}",
        json={
            "status": "completed",
            "return_code": 0,
            "ended_at": "2026-04-17T12:00:05Z",
        },
    )

    assert response.status_code == 200, response.text
    assert swapped is True
    assert "physical cleanup deferred" in response.json()["output_cleanup_warning"]
    assert response.json()["output_cleanup_status"] == "deferred"
    assert attacker_stdout.read_text(encoding="utf-8") == "attacker data must survive"
    assert attacker_stderr.read_text(encoding="utf-8") == "attacker stderr must survive"
    assert (moved_dir / stdout_path.name).read_text(encoding="utf-8") == (
        "https://example.com/logo.png\n"
    )
    assert (moved_dir / stderr_path.name).read_bytes() == b""


def test_host_exec_suppression_never_enters_a_check_then_truncate_race(
    client, isolate_settings, monkeypatch
):
    engagement_dir = _write_engagement(isolate_settings["engagements_dir"])
    run_uuid = "host-unlink-swap"
    output_dir = engagement_dir / "scans" / "host-exec"
    output_dir.mkdir(parents=True)
    stdout_path = output_dir / f"{run_uuid}.out"
    stderr_path = output_dir / f"{run_uuid}.err"
    original = b"https://example.com/logo.png\n"
    stdout_path.write_bytes(original)
    stderr_path.write_bytes(b"")
    command = "cat urls | grep -viE '\\.(jpg|jpeg|png|gif|webp|svg|ico|woff2?|ttf|eot)'"
    created = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/host-exec",
        json=_base_payload(
            command=f"sh -c {command}",
            argv=["sh", "-c", command],
            tool_name="execute_command",
            route="ignored-by-server",
            run_uuid=run_uuid,
            status="running",
            return_code=None,
            success=None,
            completed_at="",
            stdout="",
            stderr="",
            stdout_path=str(stdout_path),
            stderr_path=str(stderr_path),
        ),
    ).json()
    hardlink_victim = engagement_dir / "late-hardlink-victim.txt"

    def exploit_if_truncated(descriptor, length):
        os.link(stdout_path, hardlink_victim)
        os.ftruncate(descriptor, length)
        pytest.fail("suppression must not truncate a path-reachable inode")

    monkeypatch.setattr(command_runs_service.os, "ftruncate", exploit_if_truncated)

    response = client.patch(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/{created['id']}",
        json={
            "status": "completed",
            "return_code": 0,
            "ended_at": "2026-04-17T12:00:05Z",
        },
    )

    assert response.status_code == 200, response.text
    finalized = response.json()
    assert finalized["status"] == "completed"
    assert finalized["stdout_sha256"] == hashlib.sha256(original).hexdigest()
    assert finalized["output_cleanup_status"] == "deferred"
    assert "physical cleanup deferred" in finalized["output_cleanup_warning"]
    assert stdout_path.read_bytes() == original
    assert not hardlink_victim.exists()


def test_invalid_retention_preview_bytes_falls_back_to_default(
    client, isolate_settings, tmp_path, monkeypatch
):
    _write_engagement(isolate_settings["engagements_dir"])
    retention_config = tmp_path / "command_run_retention.json"
    retention_config.write_text(
        json.dumps({"preview_bytes": "64k", "suppress_patterns": []}),
        encoding="utf-8",
    )
    monkeypatch.setenv("COMMAND_RUN_RETENTION_CONFIG", str(retention_config))
    state_manager._retention_config.cache_clear()

    try:
        response = _post(client, _base_payload(stdout="small output"))
    finally:
        state_manager._retention_config.cache_clear()

    assert response.status_code == 201, response.text
    created = response.json()
    assert created["output_retention_status"] == "retained"
    assert created["stdout_preview"] == "small output"


def test_retention_preview_bytes_is_capped_even_when_configured_higher(
    client, isolate_settings, tmp_path, monkeypatch
):
    _write_engagement(isolate_settings["engagements_dir"])
    retention_config = tmp_path / "command_run_retention.json"
    retention_config.write_text(
        json.dumps({"preview_bytes": 10_000_000, "suppress_patterns": []}),
        encoding="utf-8",
    )
    monkeypatch.setenv("COMMAND_RUN_RETENTION_CONFIG", str(retention_config))
    state_manager._retention_config.cache_clear()

    try:
        response = _post(client, _base_payload(stdout="x" * (128 * 1024)))
    finally:
        state_manager._retention_config.cache_clear()

    assert response.status_code == 201, response.text
    created = response.json()
    assert len(created["stdout_preview"].encode("utf-8")) == 65_536
    assert created["output_retention_status"] == "artifact"


def test_host_exec_empty_spill_fallback_respects_configured_preview_byte_budget(
    client, isolate_settings, tmp_path, monkeypatch
):
    engagement_dir = _write_engagement(isolate_settings["engagements_dir"])
    retention_config = tmp_path / "command_run_retention.json"
    retention_config.write_text(
        json.dumps({"preview_bytes": 10, "suppress_patterns": []}),
        encoding="utf-8",
    )
    monkeypatch.setenv("COMMAND_RUN_RETENTION_CONFIG", str(retention_config))
    state_manager._retention_config.cache_clear()
    run_uuid = "host-fallback-preview-cap"
    output_dir = engagement_dir / "scans" / "host-exec"
    output_dir.mkdir(parents=True)
    stdout_path = output_dir / f"{run_uuid}.out"
    stderr_path = output_dir / f"{run_uuid}.err"
    stdout_path.write_bytes(b"")
    stderr_path.write_bytes(b"")
    created = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/host-exec",
        json=_base_payload(
            command="echo fallback",
            argv=["echo", "fallback"],
            tool_name="echo",
            route="ignored-by-server",
            run_uuid=run_uuid,
            status="running",
            return_code=None,
            success=None,
            completed_at="",
            stdout="",
            stderr="",
            stdout_path=str(stdout_path),
            stderr_path=str(stderr_path),
        ),
    ).json()

    try:
        response = client.patch(
            f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/{created['id']}",
            json={
                "status": "failed",
                "return_code": 1,
                "ended_at": "2026-04-17T12:00:05Z",
                "stdout_preview": "x" * 100,
            },
        )
    finally:
        state_manager._retention_config.cache_clear()

    assert response.status_code == 200, response.text
    finalized = response.json()
    assert finalized["stdout_preview"] == "x" * 10
    assert finalized["stdout_bytes"] == 10


def test_host_exec_spill_preview_never_expands_past_byte_budget_on_decode(
    client, isolate_settings, tmp_path, monkeypatch
):
    engagement_dir = _write_engagement(isolate_settings["engagements_dir"])
    retention_config = tmp_path / "command_run_retention.json"
    retention_config.write_text(
        json.dumps({"preview_bytes": 10, "suppress_patterns": []}),
        encoding="utf-8",
    )
    monkeypatch.setenv("COMMAND_RUN_RETENTION_CONFIG", str(retention_config))
    state_manager._retention_config.cache_clear()
    run_uuid = "host-invalid-utf8-preview-cap"
    output_dir = engagement_dir / "scans" / "host-exec"
    output_dir.mkdir(parents=True)
    stdout_path = output_dir / f"{run_uuid}.out"
    stderr_path = output_dir / f"{run_uuid}.err"
    stdout_path.write_bytes(b"\xff" * 20)
    stderr_path.write_bytes(b"")
    created = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/host-exec",
        json=_base_payload(
            command="printf invalid",
            argv=["printf", "invalid"],
            tool_name="printf",
            route="ignored-by-server",
            run_uuid=run_uuid,
            status="running",
            return_code=None,
            success=None,
            completed_at="",
            stdout="",
            stderr="",
            stdout_path=str(stdout_path),
            stderr_path=str(stderr_path),
        ),
    ).json()

    try:
        response = client.patch(
            f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/{created['id']}",
            json={
                "status": "completed",
                "return_code": 0,
                "ended_at": "2026-04-17T12:00:05Z",
            },
        )
    finally:
        state_manager._retention_config.cache_clear()

    assert response.status_code == 200, response.text
    assert len(response.json()["stdout_preview"].encode("utf-8")) <= 10


def test_unreadable_retention_config_falls_back_to_default(
    client, isolate_settings, tmp_path, monkeypatch
):
    _write_engagement(isolate_settings["engagements_dir"])
    bad_config_path = tmp_path / "command_run_retention.json"
    bad_config_path.mkdir()
    monkeypatch.setenv("COMMAND_RUN_RETENTION_CONFIG", str(bad_config_path))
    state_manager._retention_config.cache_clear()

    try:
        response = _post(client, _base_payload(stdout="small output"))
    finally:
        state_manager._retention_config.cache_clear()

    assert response.status_code == 201, response.text
    created = response.json()
    assert created["output_retention_status"] == "retained"
    assert created["stdout_preview"] == "small output"


def test_list_command_runs_strips_previews_unless_include_output(
    client, isolate_settings
):
    _write_engagement(isolate_settings["engagements_dir"])
    big = "B" * 4_000  # well under the 64 KiB cap so it's a normal preview
    assert _post(client, _base_payload(stdout=big)).status_code == 201

    # Default list — previews stripped, char counts surfaced for the caller.
    rows = client.get(f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs").json()
    assert rows[0]["stdout_preview"] == ""
    assert rows[0]["stdout_preview_chars"] == 4_000
    # Hashes/refs still present so reuse decisions don't require a follow-up call.
    assert len(rows[0]["stdout_sha256"]) == 64
    assert rows[0]["output_retention_status"] == "retained"

    # Opt-in to full preview when the caller really wants it.
    rows_full = client.get(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs?include_output=true"
    ).json()
    assert len(rows_full[0]["stdout_preview"]) == 4_000


def test_tool_bin_is_derived_and_filterable(client, isolate_settings):
    _write_engagement(isolate_settings["engagements_dir"])
    assert (
        _post(
            client,
            _base_payload(
                command="curl -s https://example.com/health",
                argv=["curl", "-s", "https://example.com/health"],
                tool_name="execute_command",
            ),
        ).status_code
        == 201
    )
    assert (
        _post(
            client,
            _base_payload(
                command="FOO=bar sqlmap --batch -u https://example.com",
                argv=None,
                tool_name="execute_command",
            ),
        ).status_code
        == 201
    )
    assert (
        _post(
            client,
            _base_payload(
                command="bash -lc 'nuclei -l /engagements/example/scans/targets.txt'",
                argv=[
                    "bash",
                    "-lc",
                    "nuclei -l /engagements/example/scans/targets.txt",
                ],
                tool_name="execute_command",
            ),
        ).status_code
        == 201
    )
    assert (
        _post(
            client,
            _base_payload(
                command="timeout 120 httpx -l targets.txt -json",
                argv=None,
                tool_name="execute_command",
            ),
        ).status_code
        == 201
    )

    rows = client.get(f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs").json()
    bins = {r["tool_bin"] for r in rows}
    assert "curl" in bins
    assert "sqlmap" in bins  # env-assignment prefix stripped
    assert "nuclei" in bins  # shell wrapper stripped
    assert "httpx" in bins  # timeout wrapper stripped
    curl_only = client.get(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs?tool_bin=curl"
    ).json()
    assert len(curl_only) == 1
    assert curl_only[0]["command"].startswith("curl")
    nuclei_only = client.get(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs?tool_bin=nuclei"
    ).json()
    assert len(nuclei_only) == 1
    assert "nuclei -l" in nuclei_only[0]["command"]


def test_shell_wrapper_command_string_detection_ignores_non_command_flags(
    client, isolate_settings
):
    _write_engagement(isolate_settings["engagements_dir"])
    assert (
        _post(
            client,
            _base_payload(
                command="bash --norc -lc 'nuclei -l /engagements/example/scans/targets.txt'",
                argv=[
                    "bash",
                    "--norc",
                    "-lc",
                    "nuclei -l /engagements/example/scans/targets.txt",
                ],
                tool_name="execute_command",
            ),
        ).status_code
        == 201
    )
    assert (
        _post(
            client,
            _base_payload(
                command="bash --rcfile /tmp/rc.sh script.sh",
                argv=["bash", "--rcfile", "/tmp/rc.sh", "script.sh"],
                tool_name="execute_command",
            ),
        ).status_code
        == 201
    )

    rows = client.get(f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs").json()
    by_command = {row["command"]: row["tool_bin"] for row in rows}
    assert (
        by_command["bash --norc -lc 'nuclei -l /engagements/example/scans/targets.txt'"]
        == "nuclei"
    )
    assert by_command["bash --rcfile /tmp/rc.sh script.sh"] == "bash"


def test_shell_wrapper_command_string_skips_setup_builtins_before_scanner(
    client, isolate_settings
):
    _write_engagement(isolate_settings["engagements_dir"])
    assert (
        _post(
            client,
            _base_payload(
                command="bash -lc 'cd /engagements/example && export MODE=fast; nuclei -l targets.txt'",
                argv=[
                    "bash",
                    "-lc",
                    "cd /engagements/example && export MODE=fast; nuclei -l targets.txt",
                ],
                tool_name="execute_command",
            ),
        ).status_code
        == 201
    )

    rows = client.get(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs?tool_bin=nuclei"
    ).json()
    assert len(rows) == 1
    assert rows[0]["tool_bin"] == "nuclei"
    assert "cd /engagements/example" in rows[0]["command"]


def test_audit_source_stored_and_filterable(client, isolate_settings):
    _write_engagement(isolate_settings["engagements_dir"])
    assert _post(client, _base_payload()).status_code == 201  # default header
    assert (
        _post(
            client, _base_payload(command="a", audit_source="env_fallback", argv=["a"])
        ).status_code
        == 201
    )

    env_fallback = client.get(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs?audit_source=env_fallback"
    ).json()
    assert len(env_fallback) == 1
    assert env_fallback[0]["audit_source"] == "env_fallback"


@pytest.mark.parametrize("audit_source", ["header", "stdin", "argv"])
def test_host_exec_accepts_cli_audit_source_values(
    client, isolate_settings, audit_source: str
):
    _write_engagement(isolate_settings["engagements_dir"])

    response = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/host-exec",
        json=_base_payload(
            command=f"echo {audit_source}",
            argv=["echo", audit_source],
            tool_name="host-exec",
            route="/ignored-by-server",
            audit_source=audit_source,
            host_record_kind="policy_refusal",
            status="failed",
            return_code=None,
            success=False,
            duration_ms=0,
            stdout="",
            stderr="scope policy refused execution",
            stdout_path=None,
            stderr_path=None,
        ),
    )

    assert response.status_code == 201, response.text
    created = response.json()
    assert created["route"] == "host_exec"
    assert created["audit_source"] == audit_source


def test_host_exec_finalize_retains_recorded_spill_files_without_inline_output(
    client, isolate_settings, monkeypatch
):
    engagement_dir = _write_engagement(isolate_settings["engagements_dir"])
    run_uuid = "host-retention-run"
    output_dir = engagement_dir / "scans" / "host-exec"
    output_dir.mkdir(parents=True)
    stdout_path = output_dir / f"{run_uuid}.out"
    stderr_path = output_dir / f"{run_uuid}.err"
    stdout_bytes = b"HEAD\n" + (b"x" * (128 * 1024)) + b"\nTAIL\n"
    stderr_bytes = b"compiler warning\n"
    stdout_path.touch(mode=0o600)
    stderr_path.touch(mode=0o600)

    created_response = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/host-exec",
        json=_base_payload(
            command="cmake --build build",
            argv=["cmake", "--build", "build"],
            tool_name="cmake",
            route="ignored-by-server",
            run_uuid=run_uuid,
            status="running",
            return_code=None,
            success=None,
            completed_at="",
            stdout="",
            stderr="",
            stdout_path=str(stdout_path),
            stderr_path=str(stderr_path),
        ),
    )
    assert created_response.status_code == 201, created_response.text
    created = created_response.json()
    assert created["output_retention_status"] == "empty"

    # host-exec creates and fills these only after the pre-exec row exists.
    stdout_path.write_bytes(stdout_bytes)
    stderr_path.write_bytes(stderr_bytes)
    index_calls: list[str] = []
    real_register = artifact_index.register_verified_command_output

    def track_verified_index(*args, **kwargs):
        index_calls.append(str(kwargs["relative_path"]))
        return real_register(*args, **kwargs)

    monkeypatch.setattr(
        artifact_index, "register_verified_command_output", track_verified_index
    )

    # This is the real host-exec transport shape: previews are bounded and the
    # full output is never copied into the finalize request body.
    response = client.patch(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/{created['id']}",
        json={
            "status": "completed",
            "return_code": 0,
            "ended_at": "2026-04-17T12:00:05Z",
            "duration_ms": 5000,
            "stdout_preview": "HEAD\n... output omitted ...\nTAIL\n",
            "stderr_preview": "compiler warning\n",
        },
    )

    assert response.status_code == 200, response.text
    finalized = response.json()
    assert finalized["output_retention_status"] == "artifact"
    assert finalized["stdout_bytes"] == len(stdout_bytes)
    assert finalized["stderr_bytes"] == len(stderr_bytes)
    assert finalized["stdout_sha256"] == hashlib.sha256(stdout_bytes).hexdigest()
    assert finalized["stderr_sha256"] == hashlib.sha256(stderr_bytes).hexdigest()
    stdout_artifact = engagement_dir / "scans" / "command-runs" / f"{run_uuid}.stdout.log"
    stderr_artifact = engagement_dir / "scans" / "command-runs" / f"{run_uuid}.stderr.log"
    assert finalized["stdout_artifact_ref"] == str(stdout_artifact.resolve())
    assert finalized["stderr_artifact_ref"] == str(stderr_artifact.resolve())
    assert stdout_artifact.read_bytes() == stdout_bytes
    assert stderr_artifact.read_bytes() == stderr_bytes
    assert finalized["stdout_preview"].startswith("HEAD\n")
    assert len(finalized["stdout_preview"].encode("utf-8")) <= 65_536
    assert finalized["stderr_preview"] == "compiler warning\n"
    assert sorted(index_calls) == [
        f"scans/command-runs/{run_uuid}.stderr.log",
        f"scans/command-runs/{run_uuid}.stdout.log",
    ]

    artifacts = client.get(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/artifacts/search",
        params={"kind": "command-run-output"},
    )
    assert artifacts.status_code == 200, artifacts.text
    by_path = {row["relative_path"]: row for row in artifacts.json()}
    for path, body in ((stdout_artifact, stdout_bytes), (stderr_artifact, stderr_bytes)):
        relative = path.relative_to(engagement_dir).as_posix()
        assert by_path[relative]["present"] is True
        assert by_path[relative]["size_bytes"] == len(body)
        assert by_path[relative]["sha256"] == hashlib.sha256(body).hexdigest()

    duplicate = client.patch(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/{created['id']}",
        json={
            "status": "killed",
            "return_code": -9,
            "ended_at": "2026-04-17T12:00:06Z",
        },
    )
    assert duplicate.status_code == 409
    existing = duplicate.json()["detail"]["existing"]
    assert existing["status"] == "completed"
    assert existing["stdout_sha256"] == finalized["stdout_sha256"]
    assert existing["stdout_artifact_ref"] == finalized["stdout_artifact_ref"]
    assert len(index_calls) == 2


def test_host_exec_finalize_rejects_spill_path_outside_engagement(
    client, isolate_settings, tmp_path
):
    engagement_dir = _write_engagement(isolate_settings["engagements_dir"])
    output_dir = engagement_dir / "scans" / "host-exec"
    output_dir.mkdir(parents=True)
    outside = tmp_path / "outside.out"
    outside.write_text("must not be read", encoding="utf-8")
    stderr_path = output_dir / "host-escape-run.err"
    stderr_path.touch(mode=0o600)
    response = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/host-exec",
        json=_base_payload(
            command="echo escaped",
            argv=["echo", "escaped"],
            tool_name="echo",
            route="ignored-by-server",
            run_uuid="host-escape-run",
            status="running",
            return_code=None,
            success=None,
            completed_at="",
            stdout="",
            stderr="",
            stdout_path=str(outside),
            stderr_path=str(stderr_path),
        ),
    )

    assert response.status_code == 400
    assert "inside the engagement" in response.text
    assert client.get(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs?route=host_exec"
    ).json() == []


def test_command_run_finalize_rejects_unbounded_inline_output_fields(
    client, isolate_settings
):
    _write_engagement(isolate_settings["engagements_dir"])
    created = _post(
        client,
        _base_payload(
            status="running",
            return_code=None,
            success=None,
            completed_at="",
            stdout="",
            stderr="",
        ),
    ).json()

    response = client.patch(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/{created['id']}",
        json={
            "status": "completed",
            "return_code": 0,
            "ended_at": "2026-04-17T12:00:05Z",
            "stdout": "A" * (128 * 1024),
        },
    )

    assert response.status_code == 422
    refetched = client.get(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/{created['id']}"
    ).json()
    assert refetched["status"] == "running"


@pytest.mark.parametrize(
    "field,value",
    [
        ("return_code", 10**100),
        ("duration_ms", 10**100),
        ("peak_rss_bytes", 10**100),
        ("cpu_user_seconds", 10**13),
        ("cpu_system_seconds", 10**13),
    ],
)
def test_command_run_finalize_rejects_unbounded_sqlite_values(
    client, isolate_settings, field, value
):
    _write_engagement(isolate_settings["engagements_dir"])
    created = _post(
        client,
        _base_payload(
            status="running",
            return_code=None,
            success=None,
            completed_at="",
            stdout="",
            stderr="",
        ),
    ).json()
    payload = {
        "status": "completed",
        "return_code": 0,
        "ended_at": "2026-04-17T12:00:05Z",
        field: value,
    }

    response = client.patch(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/{created['id']}",
        json=payload,
    )

    assert response.status_code == 422, response.text
    refetched = client.get(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/{created['id']}"
    ).json()
    assert refetched["status"] == "running"


@pytest.mark.parametrize(
    "overrides",
    [
        {"stdout": "unexpected inline output"},
        {"stderr": "unexpected inline error"},
        {"argv": ["echo"] * 257},
        {"argv": ["x" * 4097]},
        {"argv": ["x" * 1024] * 65},
        {"timed_out": True},
        {"duration_ms": 1},
        {"peak_rss_bytes": 1},
        {"cpu_user_seconds": 0.1},
        {"cpu_system_seconds": 0.1},
        {"command_hash": "attacker-claimed-hash"},
        {"stdout_sha256": "attacker-claimed-hash"},
        {"stderr_sha256": "attacker-claimed-hash"},
        {"command": "different from argv"},
        {"timeout_seconds_requested": 10**100},
        {"finding_id": 10**100},
    ],
)
def test_host_exec_pre_exec_request_rejects_inline_output_and_unbounded_argv(
    client, isolate_settings, overrides
):
    engagement_dir = _write_engagement(isolate_settings["engagements_dir"])
    run_uuid = "bounded-host-request"
    output_dir = engagement_dir / "scans" / "host-exec"
    output_dir.mkdir(parents=True)
    payload = _base_payload(
        command="echo safe",
        argv=["echo", "safe"],
        tool_name="echo",
        route="ignored-by-server",
        run_uuid=run_uuid,
        status="running",
        return_code=None,
        success=None,
        completed_at="",
        stdout="",
        stderr="",
        stdout_path=str(output_dir / f"{run_uuid}.out"),
        stderr_path=str(output_dir / f"{run_uuid}.err"),
    )
    payload.update(overrides)

    response = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/host-exec",
        json=payload,
    )

    assert response.status_code == 422, response.text


def test_host_exec_policy_refusal_is_bounded_and_has_no_spill_paths(
    client, isolate_settings
):
    _write_engagement(isolate_settings["engagements_dir"])
    response = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/host-exec",
        json=_base_payload(
            command="blocked-command",
            argv=["blocked-command"],
            tool_name="blocked-command",
            route="ignored-by-server",
            host_record_kind="policy_refusal",
            status="failed",
            return_code=None,
            success=False,
            completed_at="2026-04-17T12:00:01Z",
            duration_ms=0,
            stdout="",
            stderr="scope policy refused execution",
            stdout_path=None,
            stderr_path=None,
        ),
    )

    assert response.status_code == 201, response.text
    assert response.json()["status"] == "failed"


@pytest.mark.parametrize(
    "overrides",
    [
        {"return_code": 1},
        {"timed_out": True},
        {"duration_ms": 1},
        {"peak_rss_bytes": 1},
        {"cpu_user_seconds": 0.1},
        {"cpu_system_seconds": 0.1},
        {"command_hash": "client-claimed"},
        {"stdout_sha256": "client-claimed"},
        {"stderr_sha256": "client-claimed"},
        {"engagement_artifact_dir": "/tmp/not-allowed"},
        {"force": True},
        {"stdout_spill_device": 1},
    ],
)
def test_host_exec_policy_refusal_rejects_process_and_server_owned_fields(
    client, isolate_settings, overrides
):
    _write_engagement(isolate_settings["engagements_dir"])
    payload = _base_payload(
        command="blocked-command",
        argv=["blocked-command"],
        tool_name="blocked-command",
        route="ignored-by-server",
        host_record_kind="policy_refusal",
        status="failed",
        return_code=None,
        success=False,
        completed_at="2026-04-17T12:00:01Z",
        duration_ms=0,
        stdout="",
        stderr="scope policy refused execution",
        stdout_path=None,
        stderr_path=None,
    )
    payload.update(overrides)

    response = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/host-exec",
        json=payload,
    )

    assert response.status_code == 422, response.text


def test_one_shot_command_run_keeps_large_inline_output_contract(
    client, isolate_settings
):
    _write_engagement(isolate_settings["engagements_dir"])
    response = _post(client, _base_payload(stdout="x" * (128 * 1024)))

    assert response.status_code == 201, response.text
    assert response.json()["stdout_bytes"] == 128 * 1024


def test_ordinary_command_run_endpoint_reserves_host_exec_route(
    client, isolate_settings
):
    _write_engagement(isolate_settings["engagements_dir"])
    response = _post(
        client,
        _base_payload(
            route="host_exec",
            status="running",
            return_code=None,
            success=None,
            completed_at="",
            stdout="x" * (128 * 1024),
            argv=["echo"] * 300,
        ),
    )

    assert response.status_code == 422, response.text


def test_unquiesced_host_process_is_terminal_lost_without_claiming_output(
    client, isolate_settings
):
    engagement_dir = _write_engagement(isolate_settings["engagements_dir"])
    run_uuid = "host-unquiesced-lost"
    output_dir = engagement_dir / "scans" / "host-exec"
    output_dir.mkdir(parents=True)
    stdout_path = output_dir / f"{run_uuid}.out"
    stderr_path = output_dir / f"{run_uuid}.err"
    stdout_path.write_text("still mutable output\n", encoding="utf-8")
    stderr_path.write_text("child escaped termination\n", encoding="utf-8")
    created_response = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/host-exec",
        json=_base_payload(
            command="sh -c background-child",
            argv=["sh", "-c", "background-child"],
            tool_name="sh",
            route="ignored-by-server",
            run_uuid=run_uuid,
            status="running",
            return_code=None,
            success=None,
            completed_at="",
            stdout="",
            stderr="",
            stdout_path=str(stdout_path),
            stderr_path=str(stderr_path),
        ),
    )
    assert created_response.status_code == 201, created_response.text
    created = created_response.json()

    response = client.patch(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/{created['id']}",
        json={
            "status": "lost",
            "return_code": 1,
            "ended_at": "2026-04-17T12:00:05Z",
            "duration_ms": 5000,
            "stderr_preview": "process group could not be quiesced",
            "output_quiesced": False,
        },
    )

    assert response.status_code == 200, response.text
    finalized = response.json()
    assert finalized["status"] == "lost"
    assert finalized["output_recovery_observed_at"]
    assert finalized["output_retention_status"] == "untrusted"
    assert finalized["output_integrity_status"] == "warning"
    assert "could not be quiesced" in finalized["output_integrity_warning"]
    assert finalized["stdout_sha256"] == ""
    assert finalized["stderr_sha256"] == ""
    assert finalized["stdout_bytes"] == 0
    assert finalized["stderr_bytes"] == 0
    assert finalized["stdout_artifact_ref"] == ""
    assert finalized["stderr_artifact_ref"] == ""
    assert stdout_path.read_text(encoding="utf-8") == "still mutable output\n"
    blocked = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/artifacts",
        json={"path": str(stdout_path), "kind": "command-run-output"},
    )
    assert blocked.status_code == 409, blocked.text


def test_host_exec_finalize_rejects_missing_recorded_spill(client, isolate_settings):
    engagement_dir = _write_engagement(isolate_settings["engagements_dir"])
    run_uuid = "host-missing-run"
    output_dir = engagement_dir / "scans" / "host-exec"
    output_dir.mkdir(parents=True)
    missing_path = output_dir / f"{run_uuid}.out"
    stderr_path = output_dir / f"{run_uuid}.err"
    stderr_path.write_bytes(b"")
    response = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/host-exec",
        json=_base_payload(
            command="echo missing",
            argv=["echo", "missing"],
            tool_name="echo",
            route="ignored-by-server",
            run_uuid=run_uuid,
            status="running",
            return_code=None,
            success=None,
            completed_at="",
            stdout="",
            stderr="",
            stdout_path=str(missing_path),
            stderr_path=str(stderr_path),
        ),
    )

    assert response.status_code == 422, response.text
    assert client.get(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs?route=host_exec"
    ).json() == []


def test_host_exec_finalize_resists_symlink_swap_at_open(
    client, isolate_settings, monkeypatch
):
    engagement_dir = _write_engagement(isolate_settings["engagements_dir"])
    run_uuid = "host-swap-run"
    output_dir = engagement_dir / "scans" / "host-exec"
    output_dir.mkdir(parents=True)
    stdout_path = output_dir / f"{run_uuid}.out"
    stderr_path = output_dir / f"{run_uuid}.err"
    stdout_path.touch(mode=0o600)
    stderr_path.touch(mode=0o600)
    created = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/host-exec",
        json=_base_payload(
            command="echo safe",
            argv=["echo", "safe"],
            tool_name="echo",
            route="ignored-by-server",
            run_uuid=run_uuid,
            status="running",
            return_code=None,
            success=None,
            completed_at="",
            stdout="",
            stderr="",
            stdout_path=str(stdout_path),
            stderr_path=str(stderr_path),
        ),
    ).json()
    stdout_path.write_text("safe output\n", encoding="utf-8")
    stderr_path.write_bytes(b"")
    secret = engagement_dir / "secret.txt"
    secret.write_text("must not become command output\n", encoding="utf-8")

    real_open = os.open
    swapped = False

    def swap_before_open(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal swapped
        if not swapped and os.fspath(path) == stdout_path.name and dir_fd is not None:
            swapped = True
            stdout_path.unlink()
            stdout_path.symlink_to(secret)
        if dir_fd is None:
            return real_open(path, flags, mode)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(command_runs_service.os, "open", swap_before_open)

    response = client.patch(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/{created['id']}",
        json={
            "status": "completed",
            "return_code": 0,
            "ended_at": "2026-04-17T12:00:05Z",
        },
    )

    assert swapped is True
    assert response.status_code == 400
    assert "symlink" in response.text.lower()
    refetched = client.get(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/{created['id']}"
    ).json()
    assert refetched["status"] == "running"
    assert refetched["stdout_sha256"] == ""


def test_host_exec_finalize_rejects_parent_directory_symlink_redirect(
    client, isolate_settings
):
    engagement_dir = _write_engagement(isolate_settings["engagements_dir"])
    run_uuid = "host-parent-symlink"
    output_dir = engagement_dir / "scans" / "host-exec"
    output_dir.mkdir(parents=True)
    stdout_path = output_dir / f"{run_uuid}.out"
    stderr_path = output_dir / f"{run_uuid}.err"
    stdout_path.write_text("trusted output\n", encoding="utf-8")
    stderr_path.write_bytes(b"")
    created = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/host-exec",
        json=_base_payload(
            command="echo safe",
            argv=["echo", "safe"],
            tool_name="echo",
            route="ignored-by-server",
            run_uuid=run_uuid,
            status="running",
            return_code=None,
            success=None,
            completed_at="",
            stdout="",
            stderr="",
            stdout_path=str(stdout_path),
            stderr_path=str(stderr_path),
        ),
    ).json()
    moved_dir = engagement_dir / "trusted-output-moved"
    attacker_dir = engagement_dir / "attacker-output-dir"
    attacker_dir.mkdir()
    attacker_stdout = attacker_dir / stdout_path.name
    attacker_stderr = attacker_dir / stderr_path.name
    attacker_stdout.write_text("attacker replacement\n", encoding="utf-8")
    attacker_stderr.write_text("attacker replacement stderr\n", encoding="utf-8")
    output_dir.replace(moved_dir)
    output_dir.symlink_to(attacker_dir, target_is_directory=True)

    response = client.patch(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/{created['id']}",
        json={
            "status": "completed",
            "return_code": 0,
            "ended_at": "2026-04-17T12:00:05Z",
        },
    )

    assert response.status_code == 400
    assert "symlink" in response.text.lower()
    assert (moved_dir / stdout_path.name).read_text(encoding="utf-8") == "trusted output\n"
    assert attacker_stdout.read_text(encoding="utf-8") == "attacker replacement\n"
    assert attacker_stderr.read_text(encoding="utf-8") == "attacker replacement stderr\n"
    refetched = client.get(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/{created['id']}"
    ).json()
    assert refetched["status"] == "running"


def test_host_exec_finalize_rolls_back_when_verified_artifact_indexing_fails(
    client, isolate_settings, monkeypatch
):
    engagement_dir = _write_engagement(isolate_settings["engagements_dir"])
    run_uuid = "host-index-rollback"
    output_dir = engagement_dir / "scans" / "host-exec"
    output_dir.mkdir(parents=True)
    stdout_path = output_dir / f"{run_uuid}.out"
    stderr_path = output_dir / f"{run_uuid}.err"
    stdout_path.touch(mode=0o600)
    stderr_path.touch(mode=0o600)
    created = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/host-exec",
        json=_base_payload(
            command="echo transactional",
            argv=["echo", "transactional"],
            tool_name="echo",
            route="ignored-by-server",
            run_uuid=run_uuid,
            status="running",
            return_code=None,
            success=None,
            completed_at="",
            stdout="",
            stderr="",
            stdout_path=str(stdout_path),
            stderr_path=str(stderr_path),
        ),
    ).json()
    stdout_path.write_text("transactional\n", encoding="utf-8")
    stderr_path.write_bytes(b"")
    real_register = artifact_index.register_verified_command_output

    def index_then_fail(*args, **kwargs):
        real_register(*args, **kwargs)
        raise RuntimeError("artifact index unavailable")

    monkeypatch.setattr(
        artifact_index, "register_verified_command_output", index_then_fail
    )

    with pytest.raises(RuntimeError, match="artifact index unavailable"):
        client.patch(
            f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/{created['id']}",
            json={
                "status": "completed",
                "return_code": 0,
                "ended_at": "2026-04-17T12:00:05Z",
            },
        )

    refetched = client.get(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/{created['id']}"
    ).json()
    assert refetched["status"] == "running"
    assert refetched["output_retention_status"] == "empty"
    artifacts = client.get(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/artifacts/search",
        params={"kind": "command-run-output"},
    ).json()
    assert artifacts == []
    assert stdout_path.read_text(encoding="utf-8") == "transactional\n"
    orphan = (
        engagement_dir / "scans" / "command-runs" / f"{run_uuid}.stdout.log"
    )
    assert orphan.read_text(encoding="utf-8") == "transactional\n"

    monkeypatch.setattr(
        artifact_index,
        "register_verified_command_output",
        real_register,
    )
    retry = client.patch(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/{created['id']}",
        json={
            "status": "completed",
            "return_code": 0,
            "ended_at": "2026-04-17T12:00:06Z",
        },
    )
    assert retry.status_code == 200, retry.text
    finalized = retry.json()
    assert finalized["status"] == "completed"
    assert finalized["output_integrity_status"] == "verified"
    assert Path(finalized["stdout_artifact_ref"]).read_bytes() == b"transactional\n"


def test_list_command_runs_filters_by_route_lane(client, isolate_settings):
    _write_engagement(isolate_settings["engagements_dir"])
    # Container/kali typed-verb row — route is stamped 'vigil assess kali/<tool>'.
    assert (
        _post(
            client,
            _base_payload(
                command="kali nmap run",
                argv=["nmap", "x"],
                route="vigil assess kali/nmap",
            ),
        ).status_code
        == 201
    )
    # Host-native row via the host-exec endpoint — server forces route='host_exec'.
    assert (
        client.post(
            f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/host-exec",
            json=_base_payload(
                command="httpx -l hosts.txt",
                argv=["httpx", "-l", "hosts.txt"],
                tool_name="host-exec",
                route="ignored-by-server",
                host_record_kind="policy_refusal",
                status="failed",
                return_code=None,
                success=False,
                duration_ms=0,
                stdout="",
                stderr="scope policy refused execution",
                stdout_path=None,
                stderr_path=None,
            ),
        ).status_code
        == 201
    )

    host_rows = client.get(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs?route=host_exec"
    ).json()
    assert len(host_rows) == 1
    assert host_rows[0]["route"] == "host_exec"

    kali_rows = client.get(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs?route=kali"
    ).json()
    assert len(kali_rows) == 1
    assert kali_rows[0]["route"].startswith("vigil assess kali/")


def test_artifact_dir_defaults_to_engagement_root_when_omitted(
    client, isolate_settings
):
    engagement_dir = _write_engagement(isolate_settings["engagements_dir"])
    big = ("X" * 1024) * 200  # 200 KiB — over the 64 KiB cap
    response = _post(
        client,
        _base_payload(
            command="huge-dump",
            argv=["huge-dump"],
            tool_name="execute_command",
            stdout=big,
            engagement_artifact_dir=None,  # caller did NOT supply one
        ),
    )
    assert response.status_code == 201, response.text
    created = response.json()
    assert created["output_retention_status"] == "artifact"
    ref = Path(created["stdout_artifact_ref"])
    # Should land under <engagement_root>/scans/command-runs/
    assert ref.exists(), f"artifact not written to {ref}"
    assert ref.parent == (engagement_dir / "scans" / "command-runs").resolve()
    assert ref.read_text(encoding="utf-8") == big


def test_argv_json_not_leaked_into_response(client, isolate_settings):
    _write_engagement(isolate_settings["engagements_dir"])
    created = _post(client, _base_payload()).json()
    assert "argv_json" not in created  # deserialized into argv, raw text dropped
    assert created["argv"] == ["nmap", "-sV", "10.0.0.1"]


def test_init_db_rebuilds_command_run_fts_after_legacy_shape(isolate_settings):
    db_path = db_module.database_path()
    with sqlite3.connect(str(db_path)) as connection:
        connection.execute(
            """
            CREATE TABLE engagements (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT NOT NULL UNIQUE,
                target TEXT NOT NULL,
                status TEXT NOT NULL,
                engagement_root TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        connection.execute(
            """
            INSERT INTO engagements (id, key, target, status, engagement_root)
            VALUES (1, ?, 'https://example.com', 'in_progress', ?)
            """,
            (ENGAGEMENT_KEY, str(isolate_settings["engagements_dir"] / ENGAGEMENT_KEY)),
        )
        connection.execute(
            """
            CREATE TABLE assessment_command_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                run_uuid TEXT NOT NULL UNIQUE,
                command TEXT NOT NULL,
                argv_json TEXT NOT NULL DEFAULT '[]',
                tool_name TEXT NOT NULL,
                route TEXT NOT NULL DEFAULT '',
                agent_name TEXT NOT NULL,
                phase TEXT NOT NULL,
                return_code INTEGER,
                timed_out INTEGER NOT NULL DEFAULT 0,
                success INTEGER NOT NULL DEFAULT 0,
                started_at TEXT NOT NULL,
                completed_at TEXT NOT NULL,
                duration_ms INTEGER NOT NULL DEFAULT 0,
                command_hash TEXT NOT NULL,
                stdout_sha256 TEXT NOT NULL DEFAULT '',
                stderr_sha256 TEXT NOT NULL DEFAULT '',
                stdout_preview TEXT NOT NULL DEFAULT '',
                stderr_preview TEXT NOT NULL DEFAULT '',
                output_retention_status TEXT NOT NULL DEFAULT 'retained',
                stdout_suppression_reason TEXT NOT NULL DEFAULT '',
                stderr_suppression_reason TEXT NOT NULL DEFAULT '',
                stdout_artifact_ref TEXT NOT NULL DEFAULT '',
                stderr_artifact_ref TEXT NOT NULL DEFAULT '',
                stdout_bytes INTEGER NOT NULL DEFAULT 0,
                stderr_bytes INTEGER NOT NULL DEFAULT 0,
                indexed_for_embeddings_at TEXT,
                notes TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE
            )
            """
        )
        connection.execute(
            """
            INSERT INTO assessment_command_runs (
                id, engagement_id, run_uuid, command, argv_json, tool_name, route,
                agent_name, phase, return_code, timed_out, success, started_at,
                completed_at, duration_ms, command_hash, stdout_preview, notes
            ) VALUES (
                1, 1, 'legacy-run', 'legacy nmap scan', '[]', 'nmap_scan', '',
                'legacy-agent', 'recon', 0, 0, 1, '2026-04-17T12:00:00Z',
                '2026-04-17T12:00:01Z', 1000, 'hash', 'legacy output', ''
            )
            """
        )
        connection.execute(
            """
            CREATE VIRTUAL TABLE assessment_command_runs_fts
            USING fts5(
                command,
                tool_name,
                agent_name,
                phase,
                stdout_preview,
                stderr_preview,
                stdout_suppression_reason,
                stderr_suppression_reason,
                notes,
                content='assessment_command_runs',
                content_rowid='id',
                tokenize='unicode61'
            )
            """
        )
        connection.commit()

    db_module.init_db()

    rows = state_manager.list_command_runs(1, q="legacy")
    assert len(rows) == 1
    assert rows[0]["command"] == "legacy nmap scan"
    assert rows[0]["tool_bin"] == ""


def test_get_command_run_returns_full_record(client, isolate_settings):
    _write_engagement(isolate_settings["engagements_dir"])
    created = _post(client, _base_payload()).json()
    response = client.get(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/{created['id']}"
    )
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == created["id"]
    assert data["stdout_preview"].startswith("Nmap scan report")
    assert data["argv"] == ["nmap", "-sV", "10.0.0.1"]


def test_get_command_run_404_for_unknown_id(client, isolate_settings):
    _write_engagement(isolate_settings["engagements_dir"])
    response = client.get(f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/999")
    assert response.status_code == 404


# ──────────────────────────────────────────────────────────────────────────
# Command-metadata fields: technique, intent, probe_kind, destructive
# ──────────────────────────────────────────────────────────────────────────


def test_command_metadata_round_trip_with_all_four_fields(client, isolate_settings):
    """POST + list round-trip with all four metadata fields set to representative values."""
    _write_engagement(isolate_settings["engagements_dir"])
    response = _post(
        client,
        _base_payload(
            command="curl -sS https://target/probe",
            technique="SSRF",
            intent="verify metadata-field plumbing end-to-end",
            probe_kind="fingerprint",
            destructive=False,
        ),
    )
    assert response.status_code == 201, response.text
    created = response.json()
    assert created["technique"] == "SSRF"
    assert created["intent"] == "verify metadata-field plumbing end-to-end"
    assert created["probe_kind"] == "fingerprint"
    assert created["destructive"] is False

    listing = client.get(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs?include_output=true"
    )
    assert listing.status_code == 200
    rows = listing.json()
    assert len(rows) == 1
    row = rows[0]
    assert row["technique"] == "SSRF"
    assert row["intent"] == "verify metadata-field plumbing end-to-end"
    assert row["probe_kind"] == "fingerprint"
    assert row["destructive"] is False


def test_command_metadata_filters_narrow_correctly(client, isolate_settings):
    """Each of the four filter axes narrows the result set as expected."""
    _write_engagement(isolate_settings["engagements_dir"])
    # Row A: SSRF / payload / destructive=True / intent mentions "verify"
    assert (
        _post(
            client,
            _base_payload(
                command="curl -sS 'https://target/?url=http://169.254.169.254/'",
                technique="SSRF",
                intent="verify SSRF to instance metadata service",
                probe_kind="payload",
                destructive=True,
            ),
        ).status_code
        == 201
    )
    # Row B: SQLI / exploit / destructive=False / intent mentions "dump"
    assert (
        _post(
            client,
            _base_payload(
                command="sqlmap -u https://target/?id=1 --dump",
                tool_name="sqlmap_scan",
                technique="SQLI",
                intent="dump users table to prove impact",
                probe_kind="exploit",
                destructive=False,
            ),
        ).status_code
        == 201
    )
    # Row C: RECON / fingerprint / destructive unset / intent mentions "verify"
    assert (
        _post(
            client,
            _base_payload(
                command="nmap -sV target",
                technique="RECON",
                intent="verify open ports and versions",
                probe_kind="fingerprint",
                destructive=None,
            ),
        ).status_code
        == 201
    )

    def fetch(query: str):
        response = client.get(
            f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs?{query}"
        )
        assert response.status_code == 200, response.text
        return response.json()

    ssrf_rows = fetch("technique=SSRF")
    assert len(ssrf_rows) == 1
    assert ssrf_rows[0]["technique"] == "SSRF"

    exploit_rows = fetch("probe_kind=exploit")
    assert len(exploit_rows) == 1
    assert exploit_rows[0]["probe_kind"] == "exploit"

    destructive_rows = fetch("destructive=true")
    assert len(destructive_rows) == 1
    assert destructive_rows[0]["destructive"] is True

    not_destructive_rows = fetch("destructive=false")
    assert len(not_destructive_rows) == 1
    assert not_destructive_rows[0]["destructive"] is False

    # intent_q uses FTS5 scoped to the intent column — two rows match "verify".
    verify_rows = fetch("intent_q=verify")
    assert len(verify_rows) == 2
    for row in verify_rows:
        assert "verify" in (row["intent"] or "").lower()


def test_command_metadata_intent_is_fts_searchable_via_q(client, isolate_settings):
    """Intent text is indexed in FTS5 — the global ?q= param finds substrings."""
    _write_engagement(isolate_settings["engagements_dir"])
    assert (
        _post(
            client,
            _base_payload(
                command="curl -sS https://target/admin",
                intent="checking administrative endpoint exposure",
            ),
        ).status_code
        == 201
    )
    assert (
        _post(
            client,
            _base_payload(
                command="curl -sS https://target/public",
                intent="baseline of public home page",
            ),
        ).status_code
        == 201
    )

    # FTS5 tokenises words — searching a unique intent token should return
    # exactly the row whose intent contains it.
    response = client.get(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs?q=administrative"
    )
    assert response.status_code == 200
    rows = response.json()
    assert len(rows) == 1
    assert rows[0]["intent"] == "checking administrative endpoint exposure"


def test_command_metadata_backward_compat_omitted_fields(client, isolate_settings):
    """POST without the four new fields still works; serializer returns nulls."""
    _write_engagement(isolate_settings["engagements_dir"])
    payload = _base_payload()
    # Strip the metadata keys entirely to prove they're optional on the wire,
    # not just nullable in the pydantic model.
    for key in ("technique", "intent", "probe_kind", "destructive"):
        payload.pop(key, None)

    response = _post(client, payload)
    assert response.status_code == 201, response.text
    created = response.json()
    assert created["technique"] is None
    assert created["intent"] is None
    assert created["probe_kind"] is None
    assert created["destructive"] is None


def test_command_metadata_enum_permissive_accepts_unknown_technique(
    client, isolate_settings
):
    """Technique stores values verbatim — no Literal validation at the API level."""
    _write_engagement(isolate_settings["engagements_dir"])
    response = _post(
        client,
        _base_payload(
            technique="MADEUP",
            probe_kind="custom-not-in-enum",
        ),
    )
    assert response.status_code == 201, response.text
    created = response.json()
    assert created["technique"] == "MADEUP"
    assert created["probe_kind"] == "custom-not-in-enum"

    # And the filter matches it back exactly.
    rows = client.get(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs?technique=MADEUP"
    ).json()
    assert len(rows) == 1
    assert rows[0]["technique"] == "MADEUP"


def test_command_metadata_intent_is_trimmed_to_400_chars(client, isolate_settings):
    """Intent is trimmed server-side to 400 characters (L3-5)."""
    _write_engagement(isolate_settings["engagements_dir"])
    long_intent = "A" * 600
    response = _post(client, _base_payload(intent=long_intent))
    assert response.status_code == 201, response.text
    created = response.json()
    assert created["intent"] is not None
    assert len(created["intent"]) == 400
    assert created["intent"] == "A" * 400


# ──────────────────────────────────────────────────────────────────────────
# Command-run cutover fields: status lifecycle, output spill paths, dedup,
# resource snapshot, scope/auth context, finalize PATCH, phase requirement
# ──────────────────────────────────────────────────────────────────────────


def test_create_accepts_new_lifecycle_fields(client, isolate_settings):
    """Pre-exec POST accepts status=running plus the new audit-pipeline fields."""
    _write_engagement(isolate_settings["engagements_dir"])
    response = _post(
        client,
        _base_payload(
            status="running",
            stdout_path="/engagements/example/scans/kali/run-1.out",
            stderr_path="/engagements/example/scans/kali/run-1.err",
            working_dir="/engagements/example",
            scope_version="abcd1234beef5678",
            auth_context="cookies",
            timeout_seconds_requested=1800,
        ),
    )
    assert response.status_code == 201, response.text
    created = response.json()
    assert created["status"] == "running"
    assert created["stdout_path"] == "/engagements/example/scans/kali/run-1.out"
    assert created["stderr_path"] == "/engagements/example/scans/kali/run-1.err"
    assert created["working_dir"] == "/engagements/example"
    assert created["scope_version"] == "abcd1234beef5678"
    assert created["auth_context"] == "cookies"
    assert created["timeout_seconds_requested"] == 1800


def test_finalize_patch_transitions_status(client, isolate_settings):
    """PATCH /command-runs/{id} moves a running row to a terminal state and
    persists return_code, ended_at, and the resource snapshot fields."""
    _write_engagement(isolate_settings["engagements_dir"])
    created = _post(
        client,
        _base_payload(
            status="running",
            stdout_path="/engagements/example/scans/kali/run-2.out",
            stderr_path="/engagements/example/scans/kali/run-2.err",
        ),
    ).json()
    assert created["status"] == "running"
    response = client.patch(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/{created['id']}",
        json={
            "status": "completed",
            "return_code": 0,
            "ended_at": "2026-04-17T12:00:05Z",
            "duration_ms": 5000,
            "stdout_preview": "scan complete",
            "timed_out": False,
            "partial_results": False,
            "peak_rss_bytes": 12_345_678,
            "cpu_user_seconds": 1.25,
            "cpu_system_seconds": 0.75,
        },
    )
    assert response.status_code == 200, response.text
    updated = response.json()
    assert updated["status"] == "completed"
    assert updated["return_code"] == 0
    assert updated["duration_ms"] == 5000
    assert updated["peak_rss_bytes"] == 12_345_678
    assert updated["cpu_user_seconds"] == 1.25
    assert updated["cpu_system_seconds"] == 0.75
    assert updated["success"] is True


def test_finalize_uses_server_owned_recovery_observation_not_client_end_time(
    client, isolate_settings
):
    _write_engagement(isolate_settings["engagements_dir"])
    created = _post(
        client,
        _base_payload(
            status="running",
            completed_at="",
            return_code=None,
            success=None,
        ),
    ).json()
    before = datetime.now(timezone.utc)

    response = client.patch(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/{created['id']}",
        json={
            "status": "completed",
            "return_code": 0,
            "ended_at": "2099-01-01T00:00:00Z",
            "duration_ms": 1,
        },
    )

    after = datetime.now(timezone.utc)
    assert response.status_code == 200, response.text
    finalized = response.json()
    observed_at = datetime.fromisoformat(
        finalized["output_recovery_observed_at"].replace("Z", "+00:00")
    )
    if observed_at.tzinfo is None:
        observed_at = observed_at.replace(tzinfo=timezone.utc)
    assert finalized["completed_at"].startswith("2099-01-01T00:00:00")
    assert before - timedelta(seconds=2) <= observed_at <= after + timedelta(seconds=2)


def test_migration_records_recovery_observation_for_terminal_pending_command_runs(
    client, isolate_settings
):
    _write_engagement(isolate_settings["engagements_dir"])
    created = _post(
        client,
        _base_payload(
            status="running",
            completed_at="",
            return_code=None,
            success=None,
        ),
    ).json()
    with db_module.get_connection() as connection:
        columns = {
            row[1]
            for row in connection.execute("PRAGMA table_info(assessment_command_runs)")
        }
        if "output_recovery_observed_at" in columns:
            connection.execute(
                "ALTER TABLE assessment_command_runs DROP COLUMN output_recovery_observed_at"
            )
        connection.execute(
            """
            UPDATE assessment_command_runs
            SET status = 'completed', completed_at = '2099-01-01T00:00:00Z',
                output_integrity_status = 'pending'
            WHERE id = ?
            """,
            (created["id"],),
        )
    db_module.close_thread_connection()
    before = datetime.now(timezone.utc)

    db_module.init_db()

    after = datetime.now(timezone.utc)
    with sqlite3.connect(str(db_module.database_path())) as connection:
        columns = {
            row[1]
            for row in connection.execute("PRAGMA table_info(assessment_command_runs)")
        }
        assert "output_recovery_observed_at" in columns
        row = connection.execute(
            "SELECT completed_at, output_recovery_observed_at "
            "FROM assessment_command_runs WHERE id = ?",
            (created["id"],),
        ).fetchone()
    assert row is not None
    assert row[0] == "2099-01-01T00:00:00Z"
    observed_at = datetime.fromisoformat(str(row[1]).replace("Z", "+00:00"))
    if observed_at.tzinfo is None:
        observed_at = observed_at.replace(tzinfo=timezone.utc)
    assert before - timedelta(seconds=2) <= observed_at <= after + timedelta(seconds=2)


def test_finalize_patch_queued_to_terminal_succeeds(client, isolate_settings):
    """Queued pre-exec rows are non-terminal and can be finalized."""
    _write_engagement(isolate_settings["engagements_dir"])
    created = _post(
        client,
        _base_payload(
            status="queued",
            stdout_path="/engagements/example/scans/kali/run-queued.out",
            stderr_path="/engagements/example/scans/kali/run-queued.err",
        ),
    ).json()
    assert created["status"] == "queued"

    response = client.patch(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/{created['id']}",
        json={
            "status": "completed",
            "return_code": 0,
            "ended_at": "2026-04-17T12:00:05Z",
            "duration_ms": 5000,
            "stdout_preview": "queued worker completed",
        },
    )
    assert response.status_code == 200, response.text
    updated = response.json()
    assert updated["status"] == "completed"
    assert updated["return_code"] == 0
    assert updated["success"] is True

    refetched = client.get(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/{created['id']}"
    ).json()
    assert refetched["status"] == "completed"


def test_finalize_patch_round_trips_partial_results(client, isolate_settings):
    """partial_results is now a real column on assessment_command_runs and is
    persisted by finalize_command_run when the agent reports it."""
    _write_engagement(isolate_settings["engagements_dir"])
    created = _post(
        client,
        _base_payload(
            command="long-scan --running",
            argv=["long-scan", "--running"],
            status="running",
        ),
    ).json()
    response = client.patch(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/{created['id']}",
        json={
            "status": "timed_out",
            "return_code": None,
            "ended_at": "2026-04-17T12:00:05Z",
            "duration_ms": 5000,
            "stdout_preview": "partial output",
            "timed_out": True,
            "partial_results": True,
        },
    )
    assert response.status_code == 200, response.text
    updated = response.json()
    assert updated["status"] == "timed_out"
    assert updated["timed_out"] is True
    assert updated["partial_results"] is True

    listing = client.get(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs?include_output=true"
    ).json()
    assert any(row["partial_results"] is True for row in listing)


def test_finalize_patch_404_for_unknown_id(client, isolate_settings):
    _write_engagement(isolate_settings["engagements_dir"])
    response = client.patch(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/9999",
        json={
            "status": "completed",
            "return_code": 0,
            "ended_at": "2026-04-17T12:00:05Z",
        },
    )
    assert response.status_code == 404


def test_finalize_patch_rejects_invalid_status(client, isolate_settings):
    """The CommandRunFinalize Literal blocks any value outside the
    {running, completed, failed, timed_out, killed, lost} set."""
    _write_engagement(isolate_settings["engagements_dir"])
    created = _post(client, _base_payload(status="running")).json()
    response = client.patch(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/{created['id']}",
        json={
            "status": "queued",
            "ended_at": "2026-04-17T12:00:05Z",
        },
    )
    assert response.status_code == 422


def test_finalize_patch_running_to_running_is_idempotent_noop(client, isolate_settings):
    """B4 edge: a refresh PATCH that does not change lifecycle state must
    return the existing row unchanged with noop=true so the operator can
    re-PATCH metadata without flipping state."""
    _write_engagement(isolate_settings["engagements_dir"])
    created = _post(client, _base_payload(status="running")).json()
    response = client.patch(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/{created['id']}",
        json={
            "status": "running",
            "ended_at": "2026-04-17T12:00:05Z",
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["noop"] is True
    assert body["status"] == "running"
    assert body["id"] == created["id"]


def test_finalize_patch_terminal_to_terminal_returns_409(client, isolate_settings):
    """B4: a row already in a terminal state cannot be finalized again. The
    second PATCH returns 409 with the existing row in the response body and
    leaves the original terminal state untouched. Without this, the worker's
    completed PATCH races the operator's stop PATCH and the second writer
    silently overwrites the first's status, return_code, and duration_ms."""
    _write_engagement(isolate_settings["engagements_dir"])
    created = _post(client, _base_payload(status="running")).json()
    first = client.patch(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/{created['id']}",
        json={
            "status": "completed",
            "return_code": 0,
            "ended_at": "2026-04-17T12:00:05Z",
            "duration_ms": 5000,
            "stdout_preview": "first finalize",
        },
    )
    assert first.status_code == 200, first.text
    first_body = first.json()
    assert first_body["status"] == "completed"

    second = client.patch(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/{created['id']}",
        json={
            "status": "killed",
            "return_code": -9,
            "ended_at": "2026-04-17T12:00:10Z",
            "duration_ms": 9999,
            "stdout_preview": "second finalize would clobber",
        },
    )
    assert second.status_code == 409, second.text
    detail = second.json()["detail"]
    assert "already finalized" in detail["message"]
    existing = detail["existing"]
    assert existing["id"] == created["id"]
    assert existing["status"] == "completed"
    assert existing["return_code"] == 0
    assert existing["duration_ms"] == 5000
    assert existing["noop"] is True

    refetched = client.get(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/{created['id']}"
    ).json()
    assert refetched["status"] == "completed"
    assert refetched["return_code"] == 0
    assert refetched["duration_ms"] == 5000


def test_finalize_patch_concurrent_double_patch_is_consistent(client, isolate_settings):
    """B4 concurrency contract: two near-simultaneous PATCHes must produce a
    consistent row state — exactly one writer's payload lands in the DB,
    the other returns 409 carrying that canonical row. The bug this test
    guards against is the read-then-update race where both writers pass a
    SELECT-based terminal check and both UPDATEs land, with the loser
    silently overwriting the winner's status/return_code/duration_ms.

    We use a ThreadPoolExecutor against the FastAPI TestClient. The TestClient
    runs requests sequentially within a single asyncio loop, so this test
    exercises the *gate* (UPDATE ... WHERE status is still pre-terminal)
    rather than true OS-level concurrency, but the gate is the load-bearing
    invariant: after the first writer commits, the second writer's UPDATE
    matches zero rows and the rowcount=0 branch must funnel into the same
    409 path.
    """
    from concurrent.futures import ThreadPoolExecutor

    _write_engagement(isolate_settings["engagements_dir"])
    created = _post(client, _base_payload(status="running")).json()
    cmd_run_id = created["id"]

    payload_a = {
        "status": "completed",
        "return_code": 0,
        "ended_at": "2026-04-17T12:00:05Z",
        "duration_ms": 5000,
        "stdout_preview": "writer-A finalize",
    }
    payload_b = {
        "status": "killed",
        "return_code": -9,
        "ended_at": "2026-04-17T12:00:10Z",
        "duration_ms": 10000,
        "stdout_preview": "writer-B finalize",
    }

    def fire(payload):
        return client.patch(
            f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/{cmd_run_id}",
            json=payload,
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        fa = pool.submit(fire, payload_a)
        fb = pool.submit(fire, payload_b)
        ra, rb = fa.result(), fb.result()

    statuses = {ra.status_code, rb.status_code}
    # Either both succeed-with-noop (impossible — one row, one status) OR
    # one 200 + one 409. The bug shape is "two 200s with conflicting state".
    assert statuses == {200, 409}, (
        f"concurrent finalize must produce 200+409, got {ra.status_code}+{rb.status_code}: "
        f"{ra.text} | {rb.text}"
    )

    # The DB-side row must reflect whichever writer won — the 409 response
    # carries the canonical existing row, and re-fetching agrees with it.
    winner_response = ra if ra.status_code == 200 else rb
    loser_response = rb if ra.status_code == 200 else ra
    winner_payload = winner_response.json()
    loser_existing = loser_response.json()["detail"]["existing"]
    assert winner_payload["status"] == loser_existing["status"]
    assert winner_payload["return_code"] == loser_existing["return_code"]
    assert winner_payload["duration_ms"] == loser_existing["duration_ms"]

    refetched = client.get(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/{cmd_run_id}"
    ).json()
    assert refetched["status"] == winner_payload["status"]
    assert refetched["return_code"] == winner_payload["return_code"]
    assert refetched["duration_ms"] == winner_payload["duration_ms"]


def test_finalize_patch_running_to_terminal_succeeds(client, isolate_settings):
    """B4 sanity: the normal happy path still works — a running row promotes
    to a terminal state and the DB row reflects the PATCH payload."""
    _write_engagement(isolate_settings["engagements_dir"])
    created = _post(client, _base_payload(status="running")).json()
    response = client.patch(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/{created['id']}",
        json={
            "status": "completed",
            "return_code": 0,
            "ended_at": "2026-04-17T12:00:05Z",
            "duration_ms": 1234,
            "stdout_preview": "ok",
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "completed"
    assert body["return_code"] == 0
    assert body["duration_ms"] == 1234
    assert body.get("noop") is not True


def test_dedup_window_inserts_new_row_linked_to_predecessor(client, isolate_settings):
    """ISSUE-003: Two identical (command, argv) POSTs inside the dedup window
    with force=False MUST insert a new row whose ``superseded_by_id`` points at
    the predecessor. The previous row-merge behavior (returning the predecessor's
    id without inserting) collapsed two real subprocess executions into one
    audit row under the CLI's warn-and-continue default — the audit pipeline
    then lied about coverage. New behavior: dedup is a relationship between
    rows, not a row-merge, so ``list-command-runs`` reflects every execution
    attempt."""
    _write_engagement(isolate_settings["engagements_dir"])
    payload = _base_payload(
        command="nmap -p 22 10.0.0.1",
        argv=["nmap", "-p", "22", "10.0.0.1"],
        status="running",
    )
    first = _post(client, payload)
    assert first.status_code == 201, first.text
    first_row = first.json()
    second = _post(client, payload)
    assert second.status_code == 201, second.text
    second_row = second.json()
    assert second_row["id"] != first_row["id"], (
        "dedup hit must insert a NEW row, not return the predecessor's id"
    )
    assert second_row["superseded_by_id"] == first_row["id"], (
        "dedup hit must populate superseded_by_id pointing at the predecessor"
    )
    assert second_row.get("dedup_predecessor_id") == first_row["id"], (
        "dedup_predecessor_id is the no-subprocess hint surface for the CLI"
    )

    listing = client.get(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs"
    ).json()
    assert len(listing) == 2, "dedup hit must insert a row, not skip the insert"


def test_dedup_force_flag_inserts_unlinked_row(client, isolate_settings):
    """force=True is the deliberate-retry escape hatch: a new row is inserted
    and ``superseded_by_id`` is NOT set — the operator declared this is an
    independent retry, not a peer of the in-flight predecessor."""
    _write_engagement(isolate_settings["engagements_dir"])
    payload = _base_payload(
        command="nmap -p 22 10.0.0.1",
        argv=["nmap", "-p", "22", "10.0.0.1"],
        status="running",
    )
    first = _post(client, payload)
    assert first.status_code == 201, first.text
    first_row = first.json()
    forced_payload = dict(payload, force=True)
    response = _post(client, forced_payload)
    assert response.status_code == 201, response.text
    second_row = response.json()
    assert second_row["superseded_by_id"] is None, (
        "force=True must suppress the dedup relationship — operator deliberate retry"
    )
    assert second_row.get("dedup_predecessor_id") is None
    assert second_row["id"] != first_row["id"]

    listing = client.get(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs"
    ).json()
    assert len(listing) == 2


def test_dedup_does_not_link_after_finalize(client, isolate_settings):
    """A finalized predecessor must NOT link a fresh in-flight row — dedup
    only applies to currently-running or queued rows."""
    _write_engagement(isolate_settings["engagements_dir"])
    payload = _base_payload(
        command="nmap -p 22 10.0.0.1",
        argv=["nmap", "-p", "22", "10.0.0.1"],
        status="running",
    )
    first = _post(client, payload).json()
    finalize = client.patch(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/{first['id']}",
        json={
            "status": "completed",
            "return_code": 0,
            "ended_at": "2026-04-17T12:00:05Z",
        },
    )
    assert finalize.status_code == 200
    second = _post(client, payload)
    assert second.status_code == 201
    assert second.json()["superseded_by_id"] is None


def test_dedup_links_to_latest_in_flight_duplicate_peer(client, isolate_settings):
    """If the original primary finishes while a duplicate peer is still active,
    the next duplicate should link to that active peer instead of becoming a
    fresh primary."""
    _write_engagement(isolate_settings["engagements_dir"])
    payload = _base_payload(
        command="nmap -p 22 10.0.0.1",
        argv=["nmap", "-p", "22", "10.0.0.1"],
        status="running",
    )
    first = _post(client, payload).json()
    second = _post(client, payload).json()
    assert second["superseded_by_id"] == first["id"]

    finalize = client.patch(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/{first['id']}",
        json={
            "status": "completed",
            "return_code": 0,
            "ended_at": "2026-04-17T12:00:05Z",
        },
    )
    assert finalize.status_code == 200

    third = _post(client, payload)
    assert third.status_code == 201, third.text
    third_row = third.json()
    assert third_row["superseded_by_id"] == second["id"]
    assert third_row.get("dedup_predecessor_id") == second["id"]


def test_dedup_respects_env_window_zero(client, isolate_settings, monkeypatch):
    """KALI_AUDIT_DEDUP_WINDOW_SECONDS=0 disables dedup entirely."""
    _write_engagement(isolate_settings["engagements_dir"])
    monkeypatch.setenv("KALI_AUDIT_DEDUP_WINDOW_SECONDS", "0")
    payload = _base_payload(
        command="nmap -p 80 10.0.0.1",
        argv=["nmap", "-p", "80", "10.0.0.1"],
        status="running",
    )
    assert _post(client, payload).status_code == 201
    second = _post(client, payload)
    assert second.status_code == 201
    assert second.json()["superseded_by_id"] is None


def test_phase_required_returns_422_when_missing(client, isolate_settings):
    """phase is required-from-input; omitting it returns 422."""
    _write_engagement(isolate_settings["engagements_dir"])
    payload = _base_payload()
    payload.pop("phase", None)
    response = _post(client, payload)
    assert response.status_code == 422
    assert "phase" in response.text.lower()


def test_phase_accepts_half_phase_tags(client, isolate_settings):
    """recon-pivot and exploit-recon are valid phase values for mid-engagement
    dispatches that cross between formal phase boundaries."""
    _write_engagement(isolate_settings["engagements_dir"])
    for phase_value in ("recon-pivot", "exploit-recon"):
        response = _post(
            client,
            _base_payload(
                phase=phase_value,
                command=f"echo {phase_value}",
                argv=["echo", phase_value],
            ),
        )
        assert response.status_code == 201, response.text
        assert response.json()["phase"] == phase_value


def test_finalize_broadcasts_via_websocket(client, isolate_settings):
    _write_engagement(isolate_settings["engagements_dir"])
    created = _post(
        client,
        _base_payload(
            status="running",
            command="nmap -p 22 10.0.0.2",
            argv=["nmap", "-p", "22", "10.0.0.2"],
        ),
    ).json()
    with client.websocket_connect(f"/ws/engagements/{ENGAGEMENT_KEY}") as websocket:
        response = client.patch(
            f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/{created['id']}",
            json={
                "status": "completed",
                "return_code": 0,
                "ended_at": "2026-04-17T12:00:05Z",
            },
        )
        assert response.status_code == 200
        payload = websocket.receive_json()
        assert payload["type"] == "assessment.updated"
        assert payload["record_type"] == "command_run"
        assert payload["payload"]["id"] == created["id"]
        assert payload["payload"]["status"] == "completed"


def test_pre_existing_rows_keep_status_completed_default_after_alter(
    client, isolate_settings
):
    """Run the ALTER-migration path: a row inserted before the status column
    existed must come back as status='completed' once init_db has migrated
    the schema. The DB DEFAULT for the column is 'completed' for legacy rows."""
    _write_engagement(isolate_settings["engagements_dir"])
    db_path = db_module.database_path()
    # Start with a clean simulated legacy DB.
    db_path.unlink(missing_ok=True)
    with sqlite3.connect(str(db_path)) as connection:
        connection.execute(
            """
            CREATE TABLE engagements (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT NOT NULL UNIQUE,
                target TEXT NOT NULL,
                status TEXT NOT NULL,
                engagement_root TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        connection.execute(
            """
            INSERT INTO engagements (id, key, target, status, engagement_root)
            VALUES (1, ?, 'https://example.com', 'in_progress', ?)
            """,
            (ENGAGEMENT_KEY, str(isolate_settings["engagements_dir"] / ENGAGEMENT_KEY)),
        )
        connection.execute(
            """
            CREATE TABLE assessment_command_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                run_uuid TEXT NOT NULL UNIQUE,
                command TEXT NOT NULL,
                argv_json TEXT NOT NULL DEFAULT '[]',
                tool_name TEXT NOT NULL,
                tool_bin TEXT NOT NULL DEFAULT '',
                route TEXT NOT NULL DEFAULT '',
                agent_name TEXT NOT NULL,
                phase TEXT NOT NULL,
                audit_source TEXT NOT NULL DEFAULT 'header',
                return_code INTEGER,
                timed_out INTEGER NOT NULL DEFAULT 0,
                success INTEGER NOT NULL DEFAULT 0,
                started_at TEXT NOT NULL,
                completed_at TEXT NOT NULL,
                duration_ms INTEGER NOT NULL DEFAULT 0,
                command_hash TEXT NOT NULL,
                stdout_sha256 TEXT NOT NULL DEFAULT '',
                stderr_sha256 TEXT NOT NULL DEFAULT '',
                stdout_preview TEXT NOT NULL DEFAULT '',
                stderr_preview TEXT NOT NULL DEFAULT '',
                output_retention_status TEXT NOT NULL DEFAULT 'retained',
                stdout_suppression_reason TEXT NOT NULL DEFAULT '',
                stderr_suppression_reason TEXT NOT NULL DEFAULT '',
                stdout_artifact_ref TEXT NOT NULL DEFAULT '',
                stderr_artifact_ref TEXT NOT NULL DEFAULT '',
                stdout_bytes INTEGER NOT NULL DEFAULT 0,
                stderr_bytes INTEGER NOT NULL DEFAULT 0,
                indexed_for_embeddings_at TEXT,
                notes TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE
            )
            """
        )
        connection.execute(
            """
            INSERT INTO assessment_command_runs (
                id, engagement_id, run_uuid, command, argv_json, tool_name, route,
                agent_name, phase, return_code, timed_out, success, started_at,
                completed_at, duration_ms, command_hash, stdout_preview, notes
            ) VALUES (
                1, 1, 'legacy-status', 'legacy nmap', '[]', 'nmap_scan', '',
                'legacy-agent', 'recon', 0, 0, 1, '2026-04-17T12:00:00Z',
                '2026-04-17T12:00:01Z', 1000, 'hash', 'legacy', ''
            )
            """
        )
        connection.commit()

    db_module.init_db()
    rows = state_manager.list_command_runs(1)
    assert len(rows) == 1
    assert rows[0]["status"] == "completed"


def test_legacy_command_runs_without_run_uuid_are_backfilled(client, isolate_settings):
    """Legacy DBs created before run_uuid existed must be migrated in place.

    The backend now queries and inserts assessment_command_runs.run_uuid before
    writing artifacts. Without an additive migration, old local DBs fail on the
    first post-upgrade command run.
    """
    _write_engagement(isolate_settings["engagements_dir"])
    db_path = db_module.database_path()
    db_path.unlink(missing_ok=True)
    with sqlite3.connect(str(db_path)) as connection:
        connection.execute(
            """
            CREATE TABLE engagements (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT NOT NULL UNIQUE,
                target TEXT NOT NULL,
                status TEXT NOT NULL,
                engagement_root TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        connection.execute(
            """
            INSERT INTO engagements (id, key, target, status, engagement_root)
            VALUES (1, ?, 'https://example.com', 'in_progress', ?)
            """,
            (ENGAGEMENT_KEY, str(isolate_settings["engagements_dir"] / ENGAGEMENT_KEY)),
        )
        connection.execute(
            """
            CREATE TABLE assessment_command_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                command TEXT NOT NULL,
                argv_json TEXT NOT NULL DEFAULT '[]',
                tool_name TEXT NOT NULL,
                tool_bin TEXT NOT NULL DEFAULT '',
                route TEXT NOT NULL DEFAULT '',
                agent_name TEXT NOT NULL,
                phase TEXT NOT NULL,
                audit_source TEXT NOT NULL DEFAULT 'header',
                status TEXT NOT NULL DEFAULT 'completed',
                return_code INTEGER,
                timed_out INTEGER NOT NULL DEFAULT 0,
                success INTEGER NOT NULL DEFAULT 0,
                started_at TEXT NOT NULL,
                completed_at TEXT NOT NULL,
                duration_ms INTEGER NOT NULL DEFAULT 0,
                command_hash TEXT NOT NULL,
                stdout_sha256 TEXT NOT NULL DEFAULT '',
                stderr_sha256 TEXT NOT NULL DEFAULT '',
                stdout_preview TEXT NOT NULL DEFAULT '',
                stderr_preview TEXT NOT NULL DEFAULT '',
                output_retention_status TEXT NOT NULL DEFAULT 'retained',
                stdout_suppression_reason TEXT NOT NULL DEFAULT '',
                stderr_suppression_reason TEXT NOT NULL DEFAULT '',
                stdout_artifact_ref TEXT NOT NULL DEFAULT '',
                stderr_artifact_ref TEXT NOT NULL DEFAULT '',
                stdout_bytes INTEGER NOT NULL DEFAULT 0,
                stderr_bytes INTEGER NOT NULL DEFAULT 0,
                indexed_for_embeddings_at TEXT,
                notes TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE
            )
            """
        )
        connection.execute(
            """
            INSERT INTO assessment_command_runs (
                id, engagement_id, command, argv_json, tool_name, tool_bin, route,
                agent_name, phase, audit_source, status, return_code, timed_out,
                success, started_at, completed_at, duration_ms, command_hash,
                stdout_preview, notes
            ) VALUES (
                1, 1, 'legacy nmap', '[]', 'nmap_scan', 'nmap', '',
                'legacy-agent', 'recon', 'header', 'completed', 0, 0,
                1, '2026-04-17T12:00:00Z', '2026-04-17T12:00:01Z',
                1000, 'hash', 'legacy', ''
            )
            """
        )
        connection.commit()

    db_module.init_db()

    with sqlite3.connect(str(db_path)) as connection:
        columns = {
            row[1]
            for row in connection.execute("PRAGMA table_info(assessment_command_runs)")
        }
        assert "run_uuid" in columns
        assert len(_unique_run_uuid_indexes(connection)) == 1
        row = connection.execute(
            "SELECT run_uuid FROM assessment_command_runs WHERE id = 1"
        ).fetchone()
        assert row is not None
        assert row[0] == "legacy-1"

    created = state_manager.record_command_run(
        1,
        command="nmap -sV 127.0.0.1",
        argv=["nmap", "-sV", "127.0.0.1"],
        tool_name="nmap",
        agent_name="recon-specialist",
        phase="recon",
        started_at="2026-04-17T12:01:00Z",
        completed_at="2026-04-17T12:01:01Z",
        run_uuid="fresh-run",
        status="completed",
    )
    assert created["run_uuid"] == "fresh-run"


# ---------------------------------------------------------------------------
# C30 — target_host column + parser + --target-host filter
# ---------------------------------------------------------------------------


def test_extract_target_host_per_verb():
    """C30: the parser must extract a target host for httpx / nuclei / ffuf /
    sqlmap and return empty for unhandled verbs. The host is lowercased,
    scheme/port/path stripped, and credentials dropped."""
    import importlib.util

    repo_root = Path(__file__).resolve().parents[3]
    spec = importlib.util.spec_from_file_location(
        "kali_audit_c30",
        repo_root / "agent" / "scripts" / "assess" / "lib" / "kali_audit.py",
    )
    assert spec and spec.loader
    # Bootstrap sys.path so `from .audit_enums import ...` resolves
    import sys as _sys

    scripts_root = repo_root / "agent" / "scripts"
    if str(scripts_root) not in _sys.path:
        _sys.path.insert(0, str(scripts_root))
    # Reload to pick up the path
    for module_name in list(_sys.modules):
        if module_name == "assess" or module_name.startswith("assess."):
            _sys.modules.pop(module_name, None)
    from assess.lib.kali_audit import _extract_target_host  # type: ignore[import-not-found]

    # httpx -u <url>
    assert (
        _extract_target_host("httpx", ["-u", "https://www.example.com:8443/path"])
        == "www.example.com"
    )
    # nuclei -u <target>
    assert (
        _extract_target_host("nuclei", ["-u", "http://api.target.test"])
        == "api.target.test"
    )
    # nuclei -l <file> → list mode, no single host
    assert _extract_target_host("nuclei", ["-l", "/engagements/x/hosts.txt"]) == ""
    # ffuf -u with FUZZ marker
    assert (
        _extract_target_host("ffuf", ["-u", "https://Admin.Example.test/FUZZ"])
        == "admin.example.test"
    )
    # sqlmap -u <url> with credentials
    assert (
        _extract_target_host("sqlmap", ["-u", "https://user:pass@target.test/v1?id=1"])
        == "target.test"
    )
    # Unhandled verb returns empty
    assert _extract_target_host("nmap-scan", ["--target", "10.0.0.1"]) == ""

    # Bracketed IPv6 URLs: extract the address inside the brackets so
    # `--target-host 2001:db8::1` matches rows produced from
    # `https://[2001:db8::1]:8443`. Without this, the row stored
    # `[2001:db8::1]:8443` and host-scoped queries silently missed it.
    assert (
        _extract_target_host("httpx", ["-u", "https://[2001:db8::1]:8443/path"])
        == "2001:db8::1"
    )
    assert _extract_target_host("nuclei", ["-u", "http://[::1]/"]) == "::1"
    assert (
        _extract_target_host("ffuf", ["-u", "https://[2001:DB8::1]/FUZZ"])
        == "2001:db8::1"
    )
    assert (
        _extract_target_host("sqlmap", ["-u", "https://user:pw@[fe80::1]:443/v1?id=1"])
        == "fe80::1"
    )


def test_list_command_runs_filters_by_target_host(client, isolate_settings):
    """C30: --target-host (exact, case-insensitive) returns only matching rows."""
    _write_engagement(isolate_settings["engagements_dir"])
    # POST a row with target_host=app.example.test
    payload_one = _base_payload()
    payload_one["command"] = "nuclei -u https://app.example.test"
    payload_one["argv"] = ["nuclei", "-u", "https://app.example.test"]
    payload_one["tool_name"] = "nuclei"
    payload_one["target_host"] = "app.example.test"
    _post(client, payload_one)
    # And a row against a different host
    payload_two = _base_payload(run_uuid="run-other")
    payload_two["command"] = "nuclei -u https://other.example.test"
    payload_two["argv"] = ["nuclei", "-u", "https://other.example.test"]
    payload_two["tool_name"] = "nuclei"
    payload_two["target_host"] = "other.example.test"
    _post(client, payload_two)
    # And a row with empty target_host (unhandled verb)
    payload_three = _base_payload(run_uuid="run-bare")
    payload_three["command"] = "echo no-target"
    payload_three["tool_name"] = "exec"
    _post(client, payload_three)

    # Filter to app.example.test → exactly one row
    response = client.get(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs",
        params={"target_host": "app.example.test"},
    )
    assert response.status_code == 200
    rows = response.json()
    assert len(rows) == 1
    assert rows[0]["target_host"] == "app.example.test"

    # Case-insensitive match
    response = client.get(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs",
        params={"target_host": "APP.EXAMPLE.TEST"},
    )
    assert response.status_code == 200
    assert len(response.json()) == 1

    # No filter returns all rows
    response = client.get(f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs")
    assert response.status_code == 200
    assert len(response.json()) == 3


def test_kali_route_finalize_records_the_wrapper_measured_output_truth(
    client, isolate_settings
):
    """Byte/hash/retention columns must reflect real output on EVERY route.

    Retention was recomputed only for the ``host_exec`` lane, so a
    ``vigil assess kali/<tool>`` row kept the pre-exec placeholders forever:
    stdout_bytes=0, no sha256, output_retention_status='empty' — while the row
    held a real preview. Evidence that exists read as evidence destroyed.
    """
    _write_engagement(isolate_settings["engagements_dir"])
    created = _post(
        client,
        _base_payload(
            status="running",
            route="vigil assess kali/nmap_scan",
            # The real pre-exec POST carries no inline output — the wrapper is
            # still streaming it to its own file.
            stdout="",
            stderr="",
            stdout_path="/engagements/example/scans/kali/run-9.out",
            stderr_path="/engagements/example/scans/kali/run-9.err",
        ),
    ).json()
    assert created["stdout_bytes"] == 0
    assert created["output_retention_status"] == "empty"

    digest = "a" * 64
    response = client.patch(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/{created['id']}",
        json={
            "status": "completed",
            "return_code": 0,
            "ended_at": "2026-04-17T12:00:05Z",
            "duration_ms": 5000,
            "stdout_preview": "22/tcp open ssh",
            "stderr_preview": "",
            "stdout_bytes": 4096,
            "stderr_bytes": 0,
            "stdout_sha256": digest,
            "stderr_sha256": "",
            "timed_out": False,
            "partial_results": False,
        },
    )
    assert response.status_code == 200, response.text
    updated = response.json()
    assert updated["stdout_bytes"] == 4096
    assert updated["stderr_bytes"] == 0
    assert updated["stdout_sha256"] == digest
    assert updated["stderr_sha256"] == ""
    assert updated["output_retention_status"] == "retained"


def test_kali_route_finalize_with_preview_but_no_byte_truth_marks_preview_only(
    client, isolate_settings
):
    """A preview is evidence of output, but not evidence of its total byte size."""
    _write_engagement(isolate_settings["engagements_dir"])
    created = _post(
        client,
        _base_payload(
            status="running", route="vigil assess kali/nmap_scan", stdout="", stderr=""
        ),
    ).json()
    response = client.patch(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/{created['id']}",
        json={
            "status": "completed",
            "return_code": 0,
            "ended_at": "2026-04-17T12:00:05Z",
            "duration_ms": 5000,
            "stdout_preview": "22/tcp open ssh",
        },
    )
    assert response.status_code == 200, response.text
    updated = response.json()
    assert updated["stdout_bytes"] == 0
    assert updated["stdout_preview"] == "22/tcp open ssh"
    assert updated["output_retention_status"] == "preview_only"


def test_kali_route_finalize_without_preview_or_byte_truth_marks_unmeasured(
    client, isolate_settings
):
    """Missing measurements must remain distinguishable from measured zero."""
    _write_engagement(isolate_settings["engagements_dir"])
    created = _post(
        client,
        _base_payload(
            status="running", route="vigil assess kali/nmap_scan", stdout="", stderr=""
        ),
    ).json()
    response = client.patch(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/{created['id']}",
        json={
            "status": "completed",
            "return_code": 0,
            "ended_at": "2026-04-17T12:00:05Z",
            "duration_ms": 5000,
        },
    )
    assert response.status_code == 200, response.text
    updated = response.json()
    assert updated["stdout_bytes"] == 0
    assert updated["stderr_bytes"] == 0
    assert updated["stdout_preview"] == ""
    assert updated["stderr_preview"] == ""
    assert updated["output_retention_status"] == "unmeasured"


def test_kali_route_finalize_with_no_output_records_empty_retention(
    client, isolate_settings
):
    """Zero measured bytes is a real observation, distinct from 'not reported'."""
    _write_engagement(isolate_settings["engagements_dir"])
    created = _post(
        client,
        _base_payload(
            status="running", route="vigil assess kali/curl", stdout="", stderr=""
        ),
    ).json()
    response = client.patch(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/{created['id']}",
        json={
            "status": "completed",
            "return_code": 0,
            "ended_at": "2026-04-17T12:00:05Z",
            "duration_ms": 5000,
            "stdout_bytes": 0,
            "stderr_bytes": 0,
            "stdout_sha256": "",
            "stderr_sha256": "",
        },
    )
    assert response.status_code == 200, response.text
    updated = response.json()
    assert updated["stdout_bytes"] == 0
    assert updated["stdout_sha256"] == ""
    assert updated["output_retention_status"] == "empty"


def test_kali_route_finalize_rejects_false_empty_measurement_claim(
    client, isolate_settings
):
    """A non-empty preview contradicts reported zero-byte output."""
    _write_engagement(isolate_settings["engagements_dir"])
    created = _post(
        client,
        _base_payload(
            status="running", route="vigil assess kali/nmap_scan", stdout="", stderr=""
        ),
    ).json()
    response = client.patch(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/{created['id']}",
        json={
            "status": "completed",
            "return_code": 0,
            "ended_at": "2026-04-17T12:00:05Z",
            "stdout_preview": "observed output",
            "stdout_bytes": 0,
            "stderr_bytes": 0,
        },
    )

    assert response.status_code == 200, response.text
    updated = response.json()
    assert updated["stdout_preview"] == "observed output"
    assert updated["output_retention_status"] == "measurement_conflict"


def test_kali_route_finalize_marks_partial_stream_measurement(
    client, isolate_settings
):
    """One stream total cannot establish the combined output byte truth."""
    _write_engagement(isolate_settings["engagements_dir"])
    created = _post(
        client,
        _base_payload(
            status="running", route="vigil assess kali/nmap_scan", stdout="", stderr=""
        ),
    ).json()
    response = client.patch(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/{created['id']}",
        json={
            "status": "completed",
            "return_code": 0,
            "ended_at": "2026-04-17T12:00:05Z",
            "stdout_bytes": 17,
            "stdout_sha256": "a" * 64,
        },
    )

    assert response.status_code == 200, response.text
    updated = response.json()
    assert updated["stdout_bytes"] == 17
    assert updated["stderr_bytes"] == 0
    assert updated["output_retention_status"] == "partially_measured"


def test_kali_route_omitted_output_fields_preserve_existing_measured_truth(
    client, isolate_settings
):
    """Final status-only PATCHes must not downgrade output already measured."""
    _write_engagement(isolate_settings["engagements_dir"])
    created = _post(
        client,
        _base_payload(
            status="running",
            route="vigil assess kali/nmap_scan",
            stdout="already measured",
            stderr="",
        ),
    ).json()
    assert created["stdout_bytes"] == len("already measured")
    assert created["output_retention_status"] == "retained"

    response = client.patch(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/{created['id']}",
        json={
            "status": "completed",
            "return_code": 0,
            "ended_at": "2026-04-17T12:00:05Z",
            "stdout_preview": "",
            "stderr_preview": "",
        },
    )

    assert response.status_code == 200, response.text
    updated = response.json()
    assert updated["stdout_bytes"] == created["stdout_bytes"]
    assert updated["stdout_sha256"] == created["stdout_sha256"]
    assert updated["stdout_preview"] == created["stdout_preview"]
    assert updated["output_retention_status"] == "retained"
