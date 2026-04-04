from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace
import sys

import pytest


def _load_code_coverage_module():
    repo_root = Path(__file__).resolve().parents[3]
    scripts_root = repo_root / "agent" / "scripts"
    if str(scripts_root) not in sys.path:
        sys.path.insert(0, str(scripts_root))
    module_path = repo_root / "agent" / "scripts" / "assess" / "commands" / "code_coverage.py"
    spec = importlib.util.spec_from_file_location("test_code_coverage_command", module_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_code_ingest_module():
    repo_root = Path(__file__).resolve().parents[3]
    scripts_root = repo_root / "agent" / "scripts"
    if str(scripts_root) not in sys.path:
        sys.path.insert(0, str(scripts_root))
    module_path = repo_root / "agent" / "scripts" / "assess" / "commands" / "code_ingest.py"
    spec = importlib.util.spec_from_file_location("test_code_ingest_command", module_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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
