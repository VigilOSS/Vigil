"""Tests for the Kali MCP command-run audit API."""
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

    rows = client.get(f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs").json()
    bins = {r["tool_bin"] for r in rows}
    assert "curl" in bins
    assert "sqlmap" in bins  # env-assignment prefix stripped
    curl_only = client.get(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs?tool_bin=curl"
    ).json()
    assert len(curl_only) == 1
    assert curl_only[0]["command"].startswith("curl")


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
