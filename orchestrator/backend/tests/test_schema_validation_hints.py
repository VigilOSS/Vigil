"""Tests for the agent-side schema validation `Did you mean` hint.

When a payload uses a field name close to but not in the allowed set
(``source`` vs ``source_name``, ``agent`` vs ``agent_name``), the
validation error should include a structured suggestion so operators can
self-correct without re-reading the contract.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def _load_module(name: str, relative: str):
    repo_root = Path(__file__).resolve().parents[3]
    scripts_root = repo_root / "agent" / "scripts"
    if str(scripts_root) not in sys.path:
        sys.path.insert(0, str(scripts_root))
    module_path = repo_root / relative
    spec = importlib.util.spec_from_file_location(name, module_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _validation_module():
    return _load_module(
        "test_schema_validation_module",
        "agent/scripts/assess/lib/schema_validation.py",
    )


def test_did_you_mean_suggests_source_name_when_source_used():
    module = _validation_module()
    schema = module.load_schema("intel-tech-component.schema.json")
    payload = {"component": "vendor-saas-platform", "source": "wappalyzer"}

    errors = module.collect_validation_errors(payload, schema)
    matches = [e for e in errors if "source" in e and "is not allowed" in e]
    assert matches, errors
    assert "Did you mean: source_name?" in matches[0]


def test_did_you_mean_omitted_for_truly_unknown_field():
    module = _validation_module()
    schema = module.load_schema("intel-tech-component.schema.json")
    payload = {"component": "x", "fizzbuzz": "y"}

    errors = module.collect_validation_errors(payload, schema)
    matches = [e for e in errors if "fizzbuzz" in e]
    assert matches, errors
    # Random short token shouldn't trigger a high-confidence match.
    assert "Did you mean" not in matches[0]
