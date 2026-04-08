from __future__ import annotations

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
        json.dumps([{"session_id": "session-a", "status": "open"}]),
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
    monkeypatch.setattr(module, "session_index_path", lambda eng_dir: str(engagement_dir / "sessions" / "index.json"))
    monkeypatch.setattr(module, "finding_lock_path", lambda eng_dir: str(engagement_dir / ".findings.lock"))
    monkeypatch.setattr(module, "next_finding_id", lambda eng_dir, source_name: "FINDING-EX-001")
    monkeypatch.setattr(module, "sync_finding_markdown", lambda path, finding: None)
    monkeypatch.setattr(module, "update_finding_count", lambda path: None)

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


def test_review_exploits_uses_workflow_status_filter(monkeypatch, tmp_path: Path, capsys) -> None:
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
            "current_phase": "exploitation",
            "exploit_policy": "selected",
            "exploit_review_state": "pending",
        },
    )

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
                    "canonical_location": "file:src/parser.py:10",
                },
                {
                    "slug": "FINDING-DRAFT-001",
                    "severity": "medium",
                    "workflow_status": "draft",
                    "title": "Needs triage",
                    "canonical_location": "",
                },
                {
                    "slug": "FINDING-FP-001",
                    "severity": "critical",
                    "workflow_status": "false_positive",
                    "title": "Killed issue",
                    "canonical_location": "",
                },
                {
                    "slug": "FINDING-REPORTED-001",
                    "severity": "low",
                    "workflow_status": "reported",
                    "title": "Already reported",
                    "canonical_location": "",
                },
            ]

        def close(self) -> None:
            return None

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)

    module.run(SimpleNamespace(engagement_dir=tmp_path))

    output = capsys.readouterr().out
    assert "FINDING-ACTIVE-001 | high | active | Live issue" in output
    assert "FINDING-DRAFT-001 | medium | draft | Needs triage" in output
    assert "FINDING-FP-001" not in output
    assert "FINDING-REPORTED-001" not in output
