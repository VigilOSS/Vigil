from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
from types import ModuleType, SimpleNamespace
import sys
from urllib.parse import parse_qs

import pytest


def _scripts_root() -> Path:
    return Path(__file__).resolve().parents[3] / "agent" / "scripts"


def _load_script_module(name: str, relative_path: str):
    scripts_root = _scripts_root()
    if str(scripts_root) not in sys.path:
        sys.path.insert(0, str(scripts_root))
    module_path = Path(__file__).resolve().parents[3] / relative_path
    spec = importlib.util.spec_from_file_location(name, module_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_proxy_addon_module():
    mitmproxy_module = ModuleType("mitmproxy")
    mitmproxy_module.http = SimpleNamespace(HTTPFlow=object)
    mitmproxy_module.ctx = SimpleNamespace(
        options=SimpleNamespace(engagement_dir=""),
        log=SimpleNamespace(info=lambda *a, **k: None, warn=lambda *a, **k: None, error=lambda *a, **k: None),
    )
    sys.modules["mitmproxy"] = mitmproxy_module
    return _load_script_module("test_proxy_addon_module", "agent/scripts/proxy_addon.py")


def test_kali_runtime_dockerfiles_package_audit_enum_module() -> None:
    repo_root = Path(__file__).resolve().parents[3]
    required_copy = "COPY docker/kali-mcp-runtime/audit_enums.py /opt/mcp-tools/audit_enums.py"
    for dockerfile in (
        repo_root / "agent" / "docker" / "runtime-full" / "Dockerfile",
        repo_root / "agent" / "docker" / "runtime-lightweight" / "Dockerfile",
    ):
        contents = dockerfile.read_text(encoding="utf-8")
        assert required_copy in contents


def test_kali_runtime_dockerfiles_package_ping_for_mcp_smoke_tests() -> None:
    repo_root = Path(__file__).resolve().parents[3]
    for dockerfile in (
        repo_root / "agent" / "docker" / "runtime-full" / "Dockerfile",
        repo_root / "agent" / "docker" / "runtime-lightweight" / "Dockerfile",
    ):
        contents = dockerfile.read_text(encoding="utf-8")
        assert "iputils-ping=3:20250605-1+b1" in contents


def test_list_intel_search_uses_canonical_entity_type(monkeypatch, tmp_path: Path, capsys) -> None:
    module = _load_script_module(
        "test_list_intel_search_module",
        "agent/scripts/assess/commands/list_intel.py",
    )

    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(engagement_dir),
        ),
    )

    captured: list[tuple[str, str]] = []

    class FakeClient:
        def __init__(self, base_url: str, engagement_key: str) -> None:
            self.base_url = base_url
            self.engagement_key = engagement_key

        def get_engagement(self, endpoint: str, query: str = ""):
            captured.append((endpoint, query))
            return []

        def close(self) -> None:
            return None

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)

    for intel_type in ("cve", "tech-component"):
        module.run(
            SimpleNamespace(
                engagement_dir=tmp_path,
                q="2024",
                intel_type=intel_type,
                limit=50,
                as_json=True,
            )
        )

    assert [endpoint for endpoint, _ in captured] == ["intel/search", "intel/search"]
    assert parse_qs(captured[0][1])["entity_type"] == ["cve"]
    assert parse_qs(captured[1][1])["entity_type"] == ["tech_component"]
    assert "[]" in capsys.readouterr().out


def test_record_proposal_rejects_invalid_finding_payload(tmp_path: Path, capsys) -> None:
    module = _load_script_module(
        "test_record_proposal_module",
        "agent/scripts/assess/commands/record_proposal.py",
    )
    session_dir = tmp_path / "session-a"
    session_dir.mkdir()
    payload_path = tmp_path / "proposal.json"
    payload_path.write_text(
        json.dumps({"type": "finding_record", "payload": {"severity": "high"}}),
        encoding="utf-8",
    )

    with pytest.raises(SystemExit) as excinfo:
        module.run(SimpleNamespace(session_dir=str(session_dir), json_file=str(payload_path)))

    assert excinfo.value.code == 1
    assert "payload.title is required" in capsys.readouterr().err
    assert not (session_dir / "proposals" / "proposals.jsonl").exists()


def test_record_proposal_accepts_valid_credential_payload(tmp_path: Path, capsys) -> None:
    module = _load_script_module(
        "test_record_proposal_valid_module",
        "agent/scripts/assess/commands/record_proposal.py",
    )
    session_dir = tmp_path / "session-a"
    session_dir.mkdir()
    payload_path = tmp_path / "proposal.json"
    payload_path.write_text(
        json.dumps(
            {
                "type": "credential",
                "payload": {
                    "credential_key": "vpn-admin",
                    "kind": "password",
                    "principal": "admin@example.com",
                    "secret": "hunter2",
                    "status": "discovered",
                },
            }
        ),
        encoding="utf-8",
    )

    module.run(SimpleNamespace(session_dir=str(session_dir), json_file=str(payload_path)))
    output = capsys.readouterr().out
    proposals_file = session_dir / "proposals" / "proposals.jsonl"

    assert "Recorded proposal" in output
    lines = proposals_file.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    recorded = json.loads(lines[0])
    assert recorded["type"] == "credential"
    assert recorded["payload"]["credential_key"] == "vpn-admin"


def test_proxy_addon_loads_legacy_scope_keys(tmp_path: Path) -> None:
    module = _load_proxy_addon_module()
    engagement_dir = tmp_path / "engagement"
    engagement_dir.mkdir()
    (engagement_dir / "scope.json").write_text(
        json.dumps(
            {
                "hostname": "example.com",
                "scope_hosts": ["*.example.com"],
                "scope": ["legacy.example.net"],
            }
        ),
        encoding="utf-8",
    )

    collector = module.CaseCollector()
    collector.engagement_dir = str(engagement_dir)
    collector._load_scope()

    assert collector._is_in_scope("example.com") is True
    assert collector._is_in_scope("api.example.com") is True
    assert collector._is_in_scope("legacy.example.net") is True
    assert collector._is_in_scope("out-of-scope.test") is False


def test_filter_scope_keeps_only_exactly_scoped_hosts(monkeypatch, tmp_path: Path, capsys) -> None:
    module = _load_script_module(
        "test_filter_scope_module",
        "agent/scripts/assess/commands/filter_scope.py",
    )
    engagement_dir = tmp_path / "engagement"
    engagement_dir.mkdir()
    # Strict apex-wildcard semantics: a wildcard-only entry does NOT match its
    # bare apex. The fixture lists `*.example.com` without a sibling
    # `example.com`, so apex URLs against example.com are excluded. Adding a
    # bare-host entry alongside the wildcard would re-admit them.
    (engagement_dir / "scope.json").write_text(
        json.dumps(
            {
                "hosts": [
                    "*.example.com",
                    "https://app.other.test/base",
                    "api.example.net",
                ]
            }
        ),
        encoding="utf-8",
    )
    input_file = tmp_path / "urls.txt"
    input_file.write_text(
        "\n".join(
            [
                "https://api.example.com/a",
                "https://example.com/apex",
                "https://evil-example.com/no",
                "https://app.other.test/v1",
                "api.example.net:8443",
                "https://api.example.net.evil.test",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir=None: SimpleNamespace(
            engagement_dir=str(engagement_dir),
            engagement_key="eng",
            base_url="http://example.test",
        ),
    )
    module.run(
        SimpleNamespace(
            engagement_dir=engagement_dir,
            input_file=str(input_file),
            output=None,
        )
    )

    captured = capsys.readouterr()
    assert captured.out.splitlines() == [
        "https://api.example.com/a",
        "https://app.other.test/v1",
        "api.example.net:8443",
    ]
    # The apex URL should produce a strict-semantics warning on stderr.
    assert "https://example.com/apex" in captured.err
    assert "bare apex is excluded" in captured.err


def test_code_ingest_posts_backend_contract_fields(monkeypatch, tmp_path: Path) -> None:
    module = _load_script_module(
        "test_code_ingest_contract_module",
        "agent/scripts/assess/commands/code_ingest.py",
    )
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    (repo_dir / "service.py").write_text("def parse(data):\n    return data\n", encoding="utf-8")

    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(engagement_dir),
        ),
    )

    calls: list[tuple[str, dict[str, object]]] = []

    class FakeClient:
        def __init__(self, base_url: str, engagement_key: str) -> None:
            self.base_url = base_url
            self.engagement_key = engagement_key

        def post(self, endpoint: str, payload: dict[str, object]):
            calls.append((endpoint, payload))
            if endpoint == "code/repos":
                return {"id": 41}
            if endpoint == "code/files":
                return {"inserted": len(payload["files"])}
            raise AssertionError(f"unexpected endpoint: {endpoint}")

        def close(self) -> None:
            return None

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)

    module.run(
        SimpleNamespace(
            repo_path=str(repo_dir),
            name="demo-repo",
            language=None,
            repo_key=None,
            engagement_dir=Path("/tmp/eng"),
        )
    )

    repo_call = next(payload for endpoint, payload in calls if endpoint == "code/repos")
    files_call = next(payload for endpoint, payload in calls if endpoint == "code/files")

    assert "repo_key" in repo_call
    assert "repo_path" in repo_call
    assert "path" not in repo_call
    assert "primary_language" not in repo_call
    assert files_call["files"][0]["file_path"] == "service.py"
    assert "file_hash" in files_call["files"][0]
    assert "path" not in files_call["files"][0]
    assert "sha256" not in files_call["files"][0]


def test_export_findings_uses_canonical_findings_and_renders_details(monkeypatch, tmp_path: Path, capsys) -> None:
    module = _load_script_module(
        "test_export_findings_module",
        "agent/scripts/assess/commands/export_findings.py",
    )
    engagement_dir = tmp_path / "engagement"
    engagement_dir.mkdir()

    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(engagement_dir),
        ),
    )
    monkeypatch.setattr(module, "load_scope", lambda engagement_dir: {"engagement_name": "Demo Engagement"})

    class FakeClient:
        def __init__(self, base_url: str, engagement_key: str) -> None:
            self.base_url = base_url
            self.engagement_key = engagement_key

        def get(self, endpoint: str):
            assert endpoint == "findings"
            return [
                {
                    "slug": "finding-002",
                    "title": "False positive finding",
                    "severity": "low",
                    "workflow_status": "false_positive",
                    "verification_state": "verified",
                    "verification_disposition": "false_positive",
                    "summary": "Should still be exported",
                    "details_json": json.dumps({}),
                },
                {
                    "slug": "finding-001",
                    "title": "Parser issue",
                    "severity": "high",
                    "workflow_status": "merged",
                    "verification_state": "disputed",
                    "verification_disposition": "downgraded",
                    "summary": "Summary text",
                    "merged_into_slug": "finding-010",
                    "details_json": json.dumps(
                        {
                            "request_method": "POST",
                            "cwe_id": "CWE-79",
                            "references": ["https://example.test/advisory", {"id": 7}, 42],
                            "entry_point": "parse_input",
                            "sink": "render_output",
                            "steps_to_reproduce": ["send payload", 2],
                        }
                    ),
                },
            ]

        def close(self) -> None:
            return None

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)

    module.run(SimpleNamespace(engagement_dir=engagement_dir))

    output = capsys.readouterr().out
    findings_md = (engagement_dir / "findings.md").read_text(encoding="utf-8")

    assert "Exported 2 findings" in output
    assert "False positive finding" in findings_md
    assert "- **Workflow**: false_positive" in findings_md
    assert "Parser issue" in findings_md
    assert "- **Merged Into**: finding-010" in findings_md
    assert "- **Location**: POST" not in findings_md
    assert "- **CWE**: CWE-79" in findings_md
    assert "- **Entry Point**: parse_input" in findings_md
    assert "- **Sink**: render_output" in findings_md
    assert "- **References**: https://example.test/advisory, {'id': 7}, 42" in findings_md
    assert "1. send payload" in findings_md
    assert "2. 2" in findings_md


def test_export_findings_preserves_legacy_non_mapping_poc_headers() -> None:
    module = _load_script_module(
        "test_export_findings_headers_module",
        "agent/scripts/assess/commands/export_findings.py",
    )

    rendered = module._render_finding(
        {
            "slug": "finding-001",
            "title": "Legacy headers",
            "details_json": json.dumps(
                {
                    "poc_request": {
                        "method": "GET",
                        "url": "https://example.test",
                        "headers": "Accept: text/html",
                    },
                    "poc_response": {
                        "status": 200,
                        "headers": ["Content-Type: text/plain"],
                        "body_excerpt": "ok",
                    },
                }
            ),
        }
    )

    assert "**PoC Request:**" in rendered
    assert "GET https://example.test" in rendered
    assert "Accept: text/html" in rendered
    assert "**PoC Response:**" in rendered
    assert "HTTP 200" in rendered
    assert "Content-Type: text/plain" in rendered


def test_code_index_sync_requires_repo_id_for_multi_repo_engagement(monkeypatch, tmp_path: Path, capsys) -> None:
    module = _load_script_module(
        "test_code_index_sync_multi_repo_module",
        "agent/scripts/assess/commands/code_index_sync.py",
    )
    engagement_dir = tmp_path / "engagement"
    manifest_dir = engagement_dir / "tools" / "analysis-state"
    manifest_dir.mkdir(parents=True)
    (manifest_dir / "structural-index-manifest.json").write_text(
        json.dumps({"path_to_index": {"src/main.go": "a.json"}}),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(engagement_dir),
        ),
    )

    class FakeClient:
        def __init__(self, base_url: str, engagement_key: str) -> None:
            self.base_url = base_url
            self.engagement_key = engagement_key

        def get(self, endpoint: str):
            assert endpoint == "code/repos"
            return [{"id": 1}, {"id": 2}]

        def close(self) -> None:
            return None

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)

    with pytest.raises(SystemExit) as excinfo:
        module.run(
            SimpleNamespace(
                engagement_dir=engagement_dir,
                manifest=None,
                index_dir=None,
                repo_id=None,
            )
        )

    assert excinfo.value.code == 1
    assert "--repo-id" in capsys.readouterr().err


def test_code_record_modules_rejects_auto_derived_key_collisions(monkeypatch, tmp_path: Path, capsys) -> None:
    module = _load_script_module(
        "test_code_record_modules_collision_module",
        "agent/scripts/assess/commands/code_record_modules.py",
    )
    engagement_dir = tmp_path / "engagement"
    engagement_dir.mkdir()
    modules_path = tmp_path / "modules.json"
    modules_path.write_text(
        json.dumps(
            [
                {"name": "Auth/API"},
                {"name": "Auth API"},
            ]
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(engagement_dir),
        ),
    )

    class FakeClient:
        def __init__(self, base_url: str, engagement_key: str) -> None:
            self.base_url = base_url
            self.engagement_key = engagement_key

        def get(self, endpoint: str):
            assert endpoint == "code/modules?repo_id=5"
            return []

        def post(self, endpoint: str, payload: dict[str, object]):
            raise AssertionError("should not post when derived keys collide")

        def close(self) -> None:
            return None

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)

    with pytest.raises(SystemExit) as excinfo:
        module.run(
            SimpleNamespace(
                engagement_dir=engagement_dir,
                repo_id="5",
                modules_json=str(modules_path),
            )
        )

    assert excinfo.value.code == 1
    assert "Provide explicit module_key values" in capsys.readouterr().err


def test_merge_session_posts_workflow_status_without_legacy_status(monkeypatch, tmp_path: Path) -> None:
    module = _load_script_module(
        "test_merge_session_module",
        "agent/scripts/assess/commands/merge_session.py",
    )
    engagement_dir = tmp_path / "engagement"
    session_dir = engagement_dir / "sessions" / "session-a"
    proposals_dir = session_dir / "proposals"
    proposals_dir.mkdir(parents=True)
    (proposals_dir / "proposals.jsonl").write_text(
        json.dumps(
            {
                "type": "finding_record",
                "payload": {
                    "title": "Parser trust boundary bypass",
                    "status": "confirmed",
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (engagement_dir / "sessions" / "index.json").write_text(
        json.dumps(
            [{"session_id": "session-a", "status": "open", "assigned_targets": ["EX-001"]}]
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(engagement_dir),
        ),
    )
    monkeypatch.setattr(module, "session_dir_path", lambda eng_dir, session_id: str(session_dir))
    monkeypatch.setattr(module, "finding_lock_path", lambda eng_dir: str(engagement_dir / ".findings.lock"))
    monkeypatch.setattr(module, "next_finding_id", lambda base_url, engagement_key, source_name: "EX-001")

    captured: list[tuple[str, dict[str, object]]] = []

    class FakeClient:
        def __init__(self, base_url: str, engagement_key: str) -> None:
            self.base_url = base_url
            self.engagement_key = engagement_key

        def post(self, endpoint: str, payload: dict[str, object]):
            captured.append((endpoint, payload))
            return {"finding": {"slug": payload["slug"], "title": payload["title"]}}

        def close(self) -> None:
            return None

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)

    module.run(SimpleNamespace(engagement_dir=engagement_dir, session_id="session-a", yes=True))

    endpoint, payload = captured[0]
    assert endpoint == "findings"
    assert payload["workflow_status"] == "active"
    assert "status" not in payload
    session_index = json.loads((engagement_dir / "sessions" / "index.json").read_text(encoding="utf-8"))
    assert session_index[0]["assigned_targets"] == ["EX-001"]
    assert "assigned_findings" not in session_index[0]


def test_merge_session_validates_session_index_before_backend_posts(monkeypatch, tmp_path: Path) -> None:
    module = _load_script_module(
        "test_merge_session_prevalidate_module",
        "agent/scripts/assess/commands/merge_session.py",
    )
    engagement_dir = tmp_path / "engagement"
    session_dir = engagement_dir / "sessions" / "session-a"
    proposals_dir = session_dir / "proposals"
    proposals_dir.mkdir(parents=True)
    (proposals_dir / "proposals.jsonl").write_text(
        json.dumps(
            {
                "type": "finding_record",
                "payload": {
                    "title": "Parser trust boundary bypass",
                    "status": "confirmed",
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (engagement_dir / "sessions" / "index.json").write_text(
        json.dumps(
            [{"session_id": "session-a", "status": "open", "assigned_findings": ["EX-001"]}]
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(engagement_dir),
        ),
    )
    monkeypatch.setattr(module, "session_dir_path", lambda eng_dir, session_id: str(session_dir))

    class FakeClient:
        def __init__(self, base_url: str, engagement_key: str) -> None:
            self.base_url = base_url
            self.engagement_key = engagement_key

        def post(self, endpoint: str, payload: dict[str, object]):
            raise AssertionError("should validate session index before backend posts")

        def close(self) -> None:
            return None

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)

    with pytest.raises(SystemExit, match="assigned_findings is no longer supported"):
        module.run(SimpleNamespace(engagement_dir=engagement_dir, session_id="session-a", yes=True))


def test_list_command_runs_failed_excludes_timeouts_by_default() -> None:
    module = _load_script_module(
        "test_list_command_runs_module",
        "agent/scripts/assess/commands/list_command_runs.py",
    )

    query = module._build_query(
        SimpleNamespace(
            q="",
            agent_name="",
            phase="",
            tool_name="",
            tool_bin="",
            audit_source="",
            technique="",
            probe_kind="",
            intent_q="",
            success=False,
            failed=True,
            destructive=False,
            not_destructive=False,
            timed_out=False,
            include_output=False,
            limit=50,
            offset=0,
        )
    )

    assert "success=false" in query
    assert "timed_out=false" in query


def test_list_command_runs_table_displays_tool_bin_for_execute_command() -> None:
    module = _load_script_module(
        "test_list_command_runs_render_module",
        "agent/scripts/assess/commands/list_command_runs.py",
    )

    rendered = module._render_table(
        [
            {
                "id": 1,
                "created_at": "2026-04-22T00:00:00Z",
                "phase": "recon",
                "agent_name": "recon-specialist",
                "tool_name": "command",
                "tool_bin": "nuclei",
                "technique": "RECON",
                "probe_kind": "fingerprint",
                "destructive": False,
                "return_code": 0,
                "timed_out": False,
                "intent": "reactive sweep",
                "command": "nuclei -l /engagements/eng/scans/targets.txt",
            }
        ]
    )

    assert "nuclei(command)" in rendered
    assert "\tcommand\t" not in rendered


def test_log_actor_kind_parses_before_or_after_subcommand() -> None:
    module = _load_script_module(
        "test_log_entry_actor_kind_module",
        "agent/scripts/assess/commands/log_entry.py",
    )

    parser = argparse.ArgumentParser(prog="aith assess")
    parser.add_argument(
        "--actor-kind",
        dest="actor_kind",
        default=None,
        choices=["operator", "agent", "hook", "system"],
    )
    subparsers = parser.add_subparsers(dest="command")
    module.register(subparsers)

    before = parser.parse_args(
        ["--actor-kind", "operator", "log", "agent", "title", "action", "result"]
    )
    after = parser.parse_args(
        ["log", "agent", "title", "action", "result", "--actor-kind", "operator"]
    )

    assert before.actor_kind == "operator"
    assert after.actor_kind == "operator"


def test_list_command_runs_failed_with_timed_out_preserves_timeout_filter() -> None:
    module = _load_script_module(
        "test_list_command_runs_timeout_module",
        "agent/scripts/assess/commands/list_command_runs.py",
    )

    query = module._build_query(
        SimpleNamespace(
            q="",
            agent_name="",
            phase="",
            tool_name="",
            tool_bin="",
            audit_source="",
            technique="",
            probe_kind="",
            intent_q="",
            success=False,
            failed=True,
            destructive=False,
            not_destructive=False,
            timed_out=True,
            include_output=False,
            limit=50,
            offset=0,
        )
    )

    assert "success=false" in query
    assert "timed_out=true" in query
    assert "timed_out=false" not in query


def test_session_index_rejects_legacy_assigned_findings_key(tmp_path: Path) -> None:
    module = _load_script_module(
        "test_sessions_module",
        "agent/scripts/assess/lib/sessions.py",
    )
    engagement_dir = tmp_path / "engagement"
    sessions_dir = engagement_dir / "sessions"
    sessions_dir.mkdir(parents=True)
    (sessions_dir / "index.json").write_text(
        json.dumps(
            [{"session_id": "session-a", "status": "open", "assigned_findings": ["EX-001"]}]
        ),
        encoding="utf-8",
    )

    with pytest.raises(SystemExit, match="assigned_findings is no longer supported"):
        module.load_session_index(str(engagement_dir))


def test_save_session_index_rejects_legacy_assigned_findings_key(tmp_path: Path) -> None:
    module = _load_script_module(
        "test_sessions_save_module",
        "agent/scripts/assess/lib/sessions.py",
    )
    engagement_dir = tmp_path / "engagement"
    (engagement_dir / "sessions").mkdir(parents=True)

    with pytest.raises(SystemExit, match="assigned_findings is no longer supported"):
        module.save_session_index(
            str(engagement_dir),
            [{"session_id": "session-a", "status": "open", "assigned_findings": ["EX-001"]}],
        )


def test_review_exploits_lists_backend_candidates(monkeypatch, tmp_path: Path, capsys) -> None:
    module = _load_script_module(
        "test_review_exploits_module",
        "agent/scripts/assess/commands/review_exploits.py",
    )

    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(engagement_dir),
        ),
    )
    monkeypatch.setattr(
        module,
        "load_scope",
        lambda engagement_dir: {
            "current_phase": "exploit",
            "exploit_policy": "selected",
            "exploit_review_state": "pending",
        },
    )

    monkeypatch.setattr(
        module,
        "load_exploit_candidates",
        lambda cfg: [
            {
                "slug": "ACTIVE-001",
                "severity": "high",
                "workflow_status": "active",
                "verification_state": "verified",
                "verification_disposition": "confirmed",
                "candidate_reason": "verified_high",
                "title": "Live issue",
                "canonical_location": "file:src/parser.py:10",
            },
            {
                "slug": "CHAIN-001",
                "severity": "info",
                "workflow_status": "active",
                "verification_state": "verified",
                "verification_disposition": "downgraded",
                "candidate_reason": "verified_chain_required",
                "title": "Chain-only primitive",
                "canonical_location": "https://example.test/export",
            },
        ],
    )

    module.run(SimpleNamespace(engagement_dir=tmp_path))

    output = capsys.readouterr().out
    assert "candidate_rule: verified findings only" in output
    assert "ACTIVE-001 | high | active | confirmed | verified_high | Live issue" in output
    assert "CHAIN-001 | info | active | downgraded | verified_chain_required | Chain-only primitive" in output


def test_launch_session_prompt_uses_workflow_status(monkeypatch, tmp_path: Path) -> None:
    module = _load_script_module(
        "test_launch_session_module",
        "agent/scripts/assess/commands/launch_session.py",
    )
    engagement_dir = tmp_path / "engagement"
    (engagement_dir / "sessions").mkdir(parents=True)
    (engagement_dir / "scope.json").write_text(
        json.dumps(
            {
                "current_phase": "exploit",
                "exploit_policy": "selected",
                "exploit_review_state": "approved",
                "approved_targets": ["ACTIVE-001"],
            }
        ),
        encoding="utf-8",
    )
    (engagement_dir / "sessions" / "index.json").write_text("[]", encoding="utf-8")

    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(engagement_dir),
        ),
    )
    monkeypatch.setattr(module, "ensure_session_index", lambda eng_dir: None)
    monkeypatch.setattr(module, "resolve_approved_target_slugs", lambda cfg, scope: ["ACTIVE-001"])

    class FakeClient:
        def __init__(self, base_url: str, engagement_key: str) -> None:
            self.base_url = base_url
            self.engagement_key = engagement_key

        def get(self, endpoint: str):
            assert endpoint == "findings"
            return [
                {
                    "slug": "ACTIVE-001",
                    "severity": "high",
                    "workflow_status": "active",
                    "title": "Live issue",
                }
            ]

        def close(self) -> None:
            return None

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)

    module.run(
        SimpleNamespace(
            engagement_dir=engagement_dir,
            session_id="session-a",
            slugs=["ACTIVE-001"],
        )
    )

    prompt = (engagement_dir / "sessions" / "session-a" / "prompt.md").read_text(encoding="utf-8")
    assignment = json.loads(
        (engagement_dir / "sessions" / "session-a" / "assignment.json").read_text(encoding="utf-8")
    )
    session_index = json.loads((engagement_dir / "sessions" / "index.json").read_text(encoding="utf-8"))
    assert "ACTIVE-001 | high | active | Live issue" in prompt
    assert assignment["assigned_targets"] == ["ACTIVE-001"]
    assert session_index[0]["assigned_targets"] == ["ACTIVE-001"]


def test_launch_session_rejects_existing_session_without_truncating_proposals(monkeypatch, tmp_path: Path, capsys) -> None:
    module = _load_script_module(
        "test_launch_session_existing_module",
        "agent/scripts/assess/commands/launch_session.py",
    )
    engagement_dir = tmp_path / "engagement"
    session_dir = engagement_dir / "sessions" / "session-a"
    proposals_dir = session_dir / "proposals"
    proposals_dir.mkdir(parents=True)
    proposals_file = proposals_dir / "proposals.jsonl"
    proposals_file.write_text('{"type":"finding_record"}\n', encoding="utf-8")
    (engagement_dir / "scope.json").write_text(
        json.dumps(
            {
                "current_phase": "exploit",
                "exploit_policy": "selected",
                "exploit_review_state": "approved",
                "approved_targets": ["ACTIVE-001"],
            }
        ),
        encoding="utf-8",
    )
    (engagement_dir / "sessions" / "index.json").write_text(
        json.dumps([{"session_id": "session-a", "status": "active"}]),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(engagement_dir),
        ),
    )
    monkeypatch.setattr(module, "resolve_approved_target_slugs", lambda cfg, scope: ["ACTIVE-001"])

    with pytest.raises(SystemExit) as excinfo:
        module.run(
            SimpleNamespace(
                engagement_dir=engagement_dir,
                session_id="session-a",
                slugs=["ACTIVE-001"],
            )
        )

    assert excinfo.value.code == 1
    assert "session already exists: session-a" in capsys.readouterr().err
    assert proposals_file.read_text(encoding="utf-8") == '{"type":"finding_record"}\n'


def test_check_report_readiness_surfaces_backend_blockers(monkeypatch, tmp_path: Path, capsys) -> None:
    module = _load_script_module(
        "test_check_report_readiness_module",
        "agent/scripts/assess/commands/check_report_readiness.py",
    )

    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(engagement_dir),
        ),
    )

    class FakeClient:
        def __init__(self, base_url: str, engagement_key: str) -> None:
            self.base_url = base_url
            self.engagement_key = engagement_key

        def get(self, endpoint: str):
            assert endpoint == "report-readiness"
            return {
                "ready": False,
                "blockers": [
                    {
                        "kind": "verification",
                        "slug": "VA-001",
                        "detail": "Finding remains unreviewed.",
                    }
                ],
            }

        def close(self) -> None:
            return None

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)

    with pytest.raises(SystemExit) as excinfo:
        module.run(SimpleNamespace(engagement_dir=tmp_path))

    assert excinfo.value.code == 1
    err = capsys.readouterr().err
    assert "Final report blockers remain:" in err
    assert "verification | VA-001: Finding remains unreviewed." in err
