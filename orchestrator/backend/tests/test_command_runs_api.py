"""Tests for the Kali MCP command-run audit API."""
from __future__ import annotations

import json
from pathlib import Path

import pytest


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
