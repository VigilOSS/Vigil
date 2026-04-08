from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import sys

import pytest


def _load_assess_module(module_filename: str, module_name: str):
    repo_root = Path(__file__).resolve().parents[3]
    scripts_root = repo_root / "agent" / "scripts"
    if str(scripts_root) not in sys.path:
        sys.path.insert(0, str(scripts_root))
    module_path = repo_root / "agent" / "scripts" / "assess" / "commands" / module_filename
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_code_coverage_module():
    return _load_assess_module("code_coverage.py", "test_code_coverage_command")


def _load_code_ingest_module():
    return _load_assess_module("code_ingest.py", "test_code_ingest_command")


def _load_code_classify_module():
    return _load_assess_module("code_classify.py", "test_code_classify_command")


def _load_code_dispatch_module():
    return _load_assess_module("code_dispatch.py", "test_code_dispatch_command")


def test_code_coverage_is_informational_by_default(monkeypatch, capsys):
    module = _load_code_coverage_module()

    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir: SimpleNamespace(base_url="http://example.test", engagement_key="eng"),
    )

    class FakeClient:
        def __init__(self, base_url: str, engagement_key: str) -> None:
            self.base_url = base_url
            self.engagement_key = engagement_key

        def get(self, endpoint: str):
            return {
                "total_files": 1,
                "by_classification": {"critical": {"count": 1, "analyzed": 0}},
                "function_level": {"total_contexts": 1, "analyzed": 0, "needs_context": 1, "pending": 0},
                "gate": {"passed": False, "reasons": ["Critical files not fully analyzed: 0/1"]},
            }

        def close(self) -> None:
            return None

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)

    module.run(SimpleNamespace(engagement_dir=Path("/tmp/eng"), repo_id=None, require_gate_pass=False))
    output = capsys.readouterr().out
    assert "Coverage Gate: FAIL" in output


def test_code_coverage_can_enforce_gate_failures(monkeypatch):
    module = _load_code_coverage_module()

    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir: SimpleNamespace(base_url="http://example.test", engagement_key="eng"),
    )

    class FakeClient:
        def __init__(self, base_url: str, engagement_key: str) -> None:
            self.base_url = base_url
            self.engagement_key = engagement_key

        def get(self, endpoint: str):
            return {"gate": {"passed": False, "reasons": ["blocked"]}}

        def close(self) -> None:
            return None

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)

    with pytest.raises(SystemExit) as excinfo:
        module.run(SimpleNamespace(engagement_dir=Path("/tmp/eng"), repo_id=None, require_gate_pass=True))
    assert excinfo.value.code == 1


def test_code_ingest_repo_key_uses_name_and_canonical_path_hash():
    module = _load_code_ingest_module()

    first = module._repo_key_for_path("Demo Repo", "/tmp/source/demo")
    second = module._repo_key_for_path("Demo Repo", "/tmp/other/demo")
    repeat = module._repo_key_for_path("Demo Repo", "/tmp/source/demo")

    assert first.startswith("demo-repo-")
    assert repeat == first
    assert second != first


def test_code_ingest_header_snippet_is_capped(tmp_path):
    module = _load_code_ingest_module()

    css_file = tmp_path / "style.css"
    css_file.write_text("data:" + ("A" * 9000) + "\nbody { color: red; }\n", encoding="utf-8")

    snippet = module._read_header(str(css_file))

    assert len(snippet) == 8192
    assert snippet.startswith("data:")


def test_code_classify_resolves_file_path_to_file_id(monkeypatch, tmp_path):
    module = _load_code_classify_module()

    payload_path = tmp_path / "classifications.json"
    payload_path.write_text(
        json.dumps([
            {
                "file_path": "src/parser.py",
                "classification": "critical",
                "role": "parser",
                "slot_types": ["NETWORK-INPUT"],
                "analysis_priority": 95,
            }
        ]),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir: SimpleNamespace(base_url="http://example.test", engagement_key="eng"),
    )

    captured: dict[str, object] = {}

    class FakeClient:
        def __init__(self, base_url: str, engagement_key: str) -> None:
            self.base_url = base_url
            self.engagement_key = engagement_key

        def get(self, endpoint: str):
            assert endpoint == "code/files?limit=5000"
            return [{"id": 42, "repo_id": 7, "file_path": "src/parser.py"}]

        def post(self, endpoint: str, payload: dict):
            captured["endpoint"] = endpoint
            captured["payload"] = payload
            return {"updated": 1}

        def close(self) -> None:
            return None

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)

    module.run(SimpleNamespace(engagement_dir=tmp_path, classifications_json=str(payload_path)))

    assert captured["endpoint"] == "code/files/bulk-classify"
    posted = captured["payload"]["classifications"][0]
    assert posted["file_id"] == 42
    assert "file_path" not in posted


def test_code_dispatch_queue_flattens_batch_wrappers_and_resolves_paths(monkeypatch, tmp_path):
    module = _load_code_dispatch_module()

    queue_path = tmp_path / "queue.json"
    queue_path.write_text(
        json.dumps(
            [
                {
                    "batch_theme": "auth-module",
                    "priority": 91,
                    "slot_types": ["NETWORK-INPUT"],
                    "guidance_hypotheses": ["Check auth boundary first"],
                    "files": [
                        "src/parser.py",
                        "src/helpers/*.py",
                    ],
                },
                {
                    "items": [
                        {
                            "file_path": "src/routes.py",
                            "priority": 70,
                            "guidance_hypotheses": ["Trace request handlers"],
                        }
                    ]
                },
            ]
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir: SimpleNamespace(base_url="http://example.test", engagement_key="eng", engagement_dir=str(tmp_path)),
    )

    def fake_snapshot(engagement_dir: str, category: str, label: str, payload, source_path=None, metadata=None):
        path = tmp_path / f"{category}-{label}.json"
        path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        return path

    monkeypatch.setattr(module, "write_json_snapshot", fake_snapshot)

    captured: dict[str, object] = {}

    class FakeClient:
        def __init__(self, base_url: str, engagement_key: str) -> None:
            self.base_url = base_url
            self.engagement_key = engagement_key

        def get(self, endpoint: str):
            assert endpoint == "code/files?limit=5000"
            return [
                {"id": 10, "repo_id": 1, "file_path": "src/parser.py"},
                {"id": 11, "repo_id": 1, "file_path": "src/helpers/auth.py"},
                {"id": 12, "repo_id": 1, "file_path": "src/routes.py"},
            ]

        def post(self, endpoint: str, payload: dict):
            captured["endpoint"] = endpoint
            captured["payload"] = payload
            return {"queued": len(payload["items"])}

        def close(self) -> None:
            return None

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)

    module.run(SimpleNamespace(action="queue", extra=[str(queue_path)], engagement_dir=tmp_path))

    assert captured["endpoint"] == "code/analysis-queue"
    assert captured["payload"]["items"] == [
        {
            "file_id": 10,
            "priority": 91,
            "batch_theme": "auth-module",
            "slot_types": ["NETWORK-INPUT"],
            "guidance_hypotheses": ["Check auth boundary first"],
        },
        {
            "file_id": 11,
            "priority": 91,
            "batch_theme": "auth-module",
            "slot_types": ["NETWORK-INPUT"],
            "guidance_hypotheses": ["Check auth boundary first"],
        },
        {
            "file_id": 12,
            "priority": 70,
            "batch_theme": "",
            "slot_types": [],
            "guidance_hypotheses": ["Trace request handlers"],
        },
    ]


def test_code_dispatch_done_requires_single_item_and_posts_cwe_coverage(monkeypatch, tmp_path):
    module = _load_code_dispatch_module()

    coverage_path = tmp_path / "coverage.json"
    coverage_path.write_text(
        json.dumps([{"family": "web-app-injection", "effort": 85}]),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(tmp_path),
        ),
    )

    def fake_snapshot(engagement_dir: str, category: str, label: str, payload, source_path=None, metadata=None):
        path = tmp_path / f"{category}-{label}.json"
        path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        return path

    monkeypatch.setattr(module, "write_json_snapshot", fake_snapshot)

    captured: dict[str, object] = {}

    class FakeClient:
        def __init__(self, base_url: str, engagement_key: str) -> None:
            self.base_url = base_url
            self.engagement_key = engagement_key

        def post(self, endpoint: str, payload: dict):
            captured["endpoint"] = endpoint
            captured["payload"] = payload
            return {"updated": 1}

        def close(self) -> None:
            return None

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)

    module.run(
        SimpleNamespace(
            action="done",
            extra=["42", "clean", str(coverage_path), "Reviewed"],
            engagement_dir=tmp_path,
        )
    )

    assert captured["endpoint"] == "code/analysis-queue/done"
    assert captured["payload"] == {
        "item_ids": [42],
        "disposition": "clean",
        "notes": "Reviewed",
        "cwe_coverage": [{"family": "web-app-injection", "effort": 85}],
    }

    with pytest.raises(SystemExit) as excinfo:
        module.run(
            SimpleNamespace(
                action="done",
                extra=["42,43", "clean", str(coverage_path)],
                engagement_dir=tmp_path,
            )
        )
    assert excinfo.value.code == 1


def _load_code_audit_module():
    repo_root = Path(__file__).resolve().parents[3]
    scripts_root = repo_root / "agent" / "scripts"
    if str(scripts_root) not in sys.path:
        sys.path.insert(0, str(scripts_root))
    module_path = repo_root / "agent" / "scripts" / "assess" / "lib" / "code_audit.py"
    spec = importlib.util.spec_from_file_location("test_code_audit", module_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_ctags_handles_missing_binary(tmp_path, monkeypatch):
    module = _load_code_ingest_module()

    # Make ctags unfindable
    monkeypatch.setattr(module, "_which", lambda binary: None)

    result = module._setup_ctags(str(tmp_path))
    assert result["available"] is False


def test_code_audit_write_snapshot_creates_manifest_and_keeps_metadata(tmp_path):
    module = _load_code_audit_module()

    engagement_dir = tmp_path / "engagement"
    snapshot = module.write_json_snapshot(
        str(engagement_dir),
        category="code-contexts-submit",
        label="module 1 batch",
        payload={"contexts": 1},
        source_path="/tmp/input.json",
        metadata={"command": "code-record-contexts", "count": 1},
    )

    assert snapshot.is_file()
    assert snapshot.name.endswith("-code-contexts-submit-module-1-batch.json")

    manifest_path = engagement_dir / "tools" / "analysis-state" / module.MANIFEST_FILENAME
    assert manifest_path.is_file()
    manifest = json.loads(manifest_path.read_text())
    assert manifest["artifact_count"] == 1
    entry = manifest["entries"][0]
    assert entry["name"] == snapshot.name
    assert entry["kind"] == "code-contexts-submit"
    assert entry["label"] == "module 1 batch"
    assert entry["source_path"] == "/tmp/input.json"
    assert entry["metadata"]["command"] == "code-record-contexts"


def test_code_audit_manifest_ignores_legacy_noncanonical_files(tmp_path):
    module = _load_code_audit_module()

    engagement_dir = tmp_path / "engagement"
    state_dir = engagement_dir / "tools" / "analysis-state"
    state_dir.mkdir(parents=True, exist_ok=True)
    (state_dir / "module15_contexts.json").write_text('{"contexts": []}\n', encoding="utf-8")
    (state_dir / "finding-verification-wave-1.md").write_text("# verification\n", encoding="utf-8")

    module.write_json_snapshot(
        str(engagement_dir),
        category="code-analysis-submit",
        label="batch one",
        payload={"results": 1},
    )

    manifest = json.loads((state_dir / "artifact-manifest.json").read_text())
    assert manifest["artifact_count"] == 1
    assert manifest["entries"][0]["kind"] == "code-analysis-submit"
