from __future__ import annotations

import asyncio
import importlib.util
import json
from pathlib import Path
from types import ModuleType, SimpleNamespace
import sys

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


def test_patched_kali_client_preserves_audit_context_for_async_tools(monkeypatch) -> None:
    module = _load_script_module(
        "test_patched_kali_client_module",
        "docker/kali-mcp-runtime/patched_kali_client.py",
    )

    class FakeFastMCP:
        def tool(self, *args, **kwargs):
            def decorator(fn):
                return fn

            return decorator

    mcp_module = ModuleType("mcp")
    server_module = ModuleType("mcp.server")
    fastmcp_module = ModuleType("mcp.server.fastmcp")
    fastmcp_module.FastMCP = FakeFastMCP
    monkeypatch.setitem(sys.modules, "mcp", mcp_module)
    monkeypatch.setitem(sys.modules, "mcp.server", server_module)
    monkeypatch.setitem(sys.modules, "mcp.server.fastmcp", fastmcp_module)

    module._wrap_fastmcp_tool_decorator()
    observed_headers: list[dict[str, str]] = []

    async def upstream_tool() -> str:
        observed_headers.append(module._current_audit_headers())
        await asyncio.sleep(0)
        observed_headers.append(module._current_audit_headers())
        return "ok"

    wrapped = FakeFastMCP().tool(name="async-tool")(upstream_tool)
    signature = module.inspect.signature(wrapped)

    assert module.inspect.iscoroutinefunction(wrapped)
    assert signature.parameters["engagement_key"].kind == module.inspect.Parameter.KEYWORD_ONLY
    assert signature.parameters["agent_name"].kind == module.inspect.Parameter.KEYWORD_ONLY
    assert signature.parameters["phase"].kind == module.inspect.Parameter.KEYWORD_ONLY

    result = asyncio.run(
        wrapped(engagement_key="eng-1", agent_name="recon-agent", phase="recon")
    )

    assert result == "ok"
    assert observed_headers == [
        {
            "X-Engagement-Key": "eng-1",
            "X-Agent-Name": "recon-agent",
            "X-Phase": "recon",
        },
        {
            "X-Engagement-Key": "eng-1",
            "X-Agent-Name": "recon-agent",
            "X-Phase": "recon",
        },
    ]
    assert getattr(module._AUDIT_CONTEXT, "headers", {}) == {}


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
            [{"session_id": "session-a", "status": "open", "assigned_targets": ["FINDING-EX-001"]}]
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
    monkeypatch.setattr(module, "next_finding_id", lambda base_url, engagement_key, source_name: "FINDING-EX-001")

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
    assert session_index[0]["assigned_targets"] == ["FINDING-EX-001"]
    assert "assigned_findings" not in session_index[0]


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
            [{"session_id": "session-a", "status": "open", "assigned_findings": ["FINDING-EX-001"]}]
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
            [{"session_id": "session-a", "status": "open", "assigned_findings": ["FINDING-EX-001"]}],
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
                "slug": "FINDING-ACTIVE-001",
                "severity": "high",
                "workflow_status": "active",
                "verification_state": "verified",
                "verification_disposition": "confirmed",
                "candidate_reason": "verified_high",
                "title": "Live issue",
                "canonical_location": "file:src/parser.py:10",
            },
            {
                "slug": "FINDING-CHAIN-001",
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
    assert "FINDING-ACTIVE-001 | high | active | confirmed | verified_high | Live issue" in output
    assert "FINDING-CHAIN-001 | info | active | downgraded | verified_chain_required | Chain-only primitive" in output


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
                "approved_targets": ["FINDING-ACTIVE-001"],
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
    monkeypatch.setattr(module, "resolve_approved_target_slugs", lambda cfg, scope: ["FINDING-ACTIVE-001"])

    class FakeClient:
        def __init__(self, base_url: str, engagement_key: str) -> None:
            self.base_url = base_url
            self.engagement_key = engagement_key

        def get(self, endpoint: str):
            assert endpoint == "findings"
            return [
                {
                    "slug": "FINDING-ACTIVE-001",
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
            slugs=["FINDING-ACTIVE-001"],
        )
    )

    prompt = (engagement_dir / "sessions" / "session-a" / "prompt.md").read_text(encoding="utf-8")
    assignment = json.loads(
        (engagement_dir / "sessions" / "session-a" / "assignment.json").read_text(encoding="utf-8")
    )
    session_index = json.loads((engagement_dir / "sessions" / "index.json").read_text(encoding="utf-8"))
    assert "FINDING-ACTIVE-001 | high | active | Live issue" in prompt
    assert assignment["assigned_targets"] == ["FINDING-ACTIVE-001"]
    assert session_index[0]["assigned_targets"] == ["FINDING-ACTIVE-001"]


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
                "approved_targets": ["FINDING-ACTIVE-001"],
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
    monkeypatch.setattr(module, "resolve_approved_target_slugs", lambda cfg, scope: ["FINDING-ACTIVE-001"])

    with pytest.raises(SystemExit) as excinfo:
        module.run(
            SimpleNamespace(
                engagement_dir=engagement_dir,
                session_id="session-a",
                slugs=["FINDING-ACTIVE-001"],
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
                        "slug": "FINDING-VA-001",
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
    assert "verification | FINDING-VA-001: Finding remains unreviewed." in err
