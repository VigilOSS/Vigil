"""Tests for the aith assess command-run audit API."""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from app import db as db_module
from app.services import state_manager


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


def test_fresh_command_runs_schema_has_single_run_uuid_unique_index(client, isolate_settings):
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


def test_one_shot_command_run_without_status_infers_terminal_state(client, isolate_settings):
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


def test_list_command_runs_filters_by_phase_agent_tool_and_success(client, isolate_settings):
    _write_engagement(isolate_settings["engagements_dir"])
    assert _post(client, _base_payload()).status_code == 201
    assert _post(
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
    ).status_code == 201
    assert _post(
        client,
        _base_payload(
            command="sqlmap -u https://example.com/?id=1 --batch",
            tool_name="sqlmap_scan",
            agent_name="vulnerability-analyst",
            phase="consume-test",
        ),
    ).status_code == 201

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


def test_list_command_runs_fts_search_finds_keyword(client, isolate_settings):
    _write_engagement(isolate_settings["engagements_dir"])
    assert _post(client, _base_payload()).status_code == 201
    assert _post(
        client,
        _base_payload(
            command="httpx -l /tmp/targets.txt",
            argv=["httpx", "-l", "/tmp/targets.txt"],
            tool_name="execute_command",
            stdout="example.com 200 OK",
        ),
    ).status_code == 201

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


def test_list_command_runs_finding_aliases_rank_and_explain_matches(client, isolate_settings):
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


def test_list_command_runs_distant_returns_nonmatching_scope_candidates(client, isolate_settings):
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


def test_duplicate_run_uuid_does_not_overwrite_existing_artifact(client, isolate_settings):
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


def test_command_run_rejects_artifact_dir_outside_engagement_root(client, isolate_settings, tmp_path):
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


def test_invalid_retention_preview_bytes_falls_back_to_default(client, isolate_settings, tmp_path, monkeypatch):
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


def test_unreadable_retention_config_falls_back_to_default(client, isolate_settings, tmp_path, monkeypatch):
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


def test_list_command_runs_strips_previews_unless_include_output(client, isolate_settings):
    _write_engagement(isolate_settings["engagements_dir"])
    big = "B" * 4_000  # well under the 64 KiB cap so it's a normal preview
    assert _post(client, _base_payload(stdout=big)).status_code == 201

    # Default list — previews stripped, char counts surfaced for the caller.
    rows = client.get(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs"
    ).json()
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
    assert _post(
        client,
        _base_payload(
            command="curl -s https://example.com/health",
            argv=["curl", "-s", "https://example.com/health"],
            tool_name="execute_command",
        ),
    ).status_code == 201
    assert _post(
        client,
        _base_payload(
            command="FOO=bar sqlmap --batch -u https://example.com",
            argv=None,
            tool_name="execute_command",
        ),
    ).status_code == 201
    assert _post(
        client,
        _base_payload(
            command="bash -lc 'nuclei -l /engagements/example/scans/targets.txt'",
            argv=["bash", "-lc", "nuclei -l /engagements/example/scans/targets.txt"],
            tool_name="execute_command",
        ),
    ).status_code == 201
    assert _post(
        client,
        _base_payload(
            command="timeout 120 httpx -l targets.txt -json",
            argv=None,
            tool_name="execute_command",
        ),
    ).status_code == 201

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


def test_shell_wrapper_command_string_detection_ignores_non_command_flags(client, isolate_settings):
    _write_engagement(isolate_settings["engagements_dir"])
    assert _post(
        client,
        _base_payload(
            command="bash --norc -lc 'nuclei -l /engagements/example/scans/targets.txt'",
            argv=["bash", "--norc", "-lc", "nuclei -l /engagements/example/scans/targets.txt"],
            tool_name="execute_command",
        ),
    ).status_code == 201
    assert _post(
        client,
        _base_payload(
            command="bash --rcfile /tmp/rc.sh script.sh",
            argv=["bash", "--rcfile", "/tmp/rc.sh", "script.sh"],
            tool_name="execute_command",
        ),
    ).status_code == 201

    rows = client.get(f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs").json()
    by_command = {row["command"]: row["tool_bin"] for row in rows}
    assert by_command["bash --norc -lc 'nuclei -l /engagements/example/scans/targets.txt'"] == "nuclei"
    assert by_command["bash --rcfile /tmp/rc.sh script.sh"] == "bash"


def test_shell_wrapper_command_string_skips_setup_builtins_before_scanner(client, isolate_settings):
    _write_engagement(isolate_settings["engagements_dir"])
    assert _post(
        client,
        _base_payload(
            command="bash -lc 'cd /engagements/example && export MODE=fast; nuclei -l targets.txt'",
            argv=["bash", "-lc", "cd /engagements/example && export MODE=fast; nuclei -l targets.txt"],
            tool_name="execute_command",
        ),
    ).status_code == 201

    rows = client.get(f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs?tool_bin=nuclei").json()
    assert len(rows) == 1
    assert rows[0]["tool_bin"] == "nuclei"
    assert "cd /engagements/example" in rows[0]["command"]


def test_audit_source_stored_and_filterable(client, isolate_settings):
    _write_engagement(isolate_settings["engagements_dir"])
    assert _post(client, _base_payload()).status_code == 201  # default header
    assert _post(
        client, _base_payload(command="a", audit_source="env_fallback", argv=["a"])
    ).status_code == 201

    env_fallback = client.get(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs?audit_source=env_fallback"
    ).json()
    assert len(env_fallback) == 1
    assert env_fallback[0]["audit_source"] == "env_fallback"


def test_artifact_dir_defaults_to_engagement_root_when_omitted(client, isolate_settings):
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
    response = client.get(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs/999"
    )
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
    assert _post(
        client,
        _base_payload(
            command="curl -sS 'https://target/?url=http://169.254.169.254/'",
            technique="SSRF",
            intent="verify SSRF to instance metadata service",
            probe_kind="payload",
            destructive=True,
        ),
    ).status_code == 201
    # Row B: SQLI / exploit / destructive=False / intent mentions "dump"
    assert _post(
        client,
        _base_payload(
            command="sqlmap -u https://target/?id=1 --dump",
            tool_name="sqlmap_scan",
            technique="SQLI",
            intent="dump users table to prove impact",
            probe_kind="exploit",
            destructive=False,
        ),
    ).status_code == 201
    # Row C: RECON / fingerprint / destructive unset / intent mentions "verify"
    assert _post(
        client,
        _base_payload(
            command="nmap -sV target",
            technique="RECON",
            intent="verify open ports and versions",
            probe_kind="fingerprint",
            destructive=None,
        ),
    ).status_code == 201

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
    assert _post(
        client,
        _base_payload(
            command="curl -sS https://target/admin",
            intent="checking administrative endpoint exposure",
        ),
    ).status_code == 201
    assert _post(
        client,
        _base_payload(
            command="curl -sS https://target/public",
            intent="baseline of public home page",
        ),
    ).status_code == 201

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


def test_command_metadata_enum_permissive_accepts_unknown_technique(client, isolate_settings):
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


def test_command_metadata_intent_is_trimmed_to_200_chars(client, isolate_settings):
    """Intent is trimmed server-side to 200 characters."""
    _write_engagement(isolate_settings["engagements_dir"])
    long_intent = "A" * 500
    response = _post(client, _base_payload(intent=long_intent))
    assert response.status_code == 201, response.text
    created = response.json()
    assert created["intent"] is not None
    assert len(created["intent"]) == 200
    assert created["intent"] == "A" * 200


# ──────────────────────────────────────────────────────────────────────────
# Wave-1 cutover fields: status lifecycle, output spill paths, dedup,
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
            _base_payload(phase=phase_value, command=f"echo {phase_value}", argv=["echo", phase_value]),
        )
        assert response.status_code == 201, response.text
        assert response.json()["phase"] == phase_value


def test_finalize_broadcasts_via_websocket(client, isolate_settings):
    _write_engagement(isolate_settings["engagements_dir"])
    created = _post(
        client,
        _base_payload(status="running", command="nmap -p 22 10.0.0.2", argv=["nmap", "-p", "22", "10.0.0.2"]),
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


def test_pre_existing_rows_keep_status_completed_default_after_alter(client, isolate_settings):
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
            row[1] for row in connection.execute("PRAGMA table_info(assessment_command_runs)")
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
    assert _extract_target_host("httpx", ["-u", "https://www.example.com:8443/path"]) == "www.example.com"
    # nuclei -u <target>
    assert _extract_target_host("nuclei", ["-u", "http://api.target.test"]) == "api.target.test"
    # nuclei -l <file> → list mode, no single host
    assert _extract_target_host("nuclei", ["-l", "/engagements/x/hosts.txt"]) == ""
    # ffuf -u with FUZZ marker
    assert _extract_target_host("ffuf", ["-u", "https://Admin.Example.test/FUZZ"]) == "admin.example.test"
    # sqlmap -u <url> with credentials
    assert _extract_target_host("sqlmap", ["-u", "https://user:pass@target.test/v1?id=1"]) == "target.test"
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
    assert _extract_target_host("ffuf", ["-u", "https://[2001:DB8::1]/FUZZ"]) == "2001:db8::1"
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
