from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys


def _load_schema_generator_module():
    repo_root = Path(__file__).resolve().parents[3]
    module_path = repo_root / "orchestrator" / "backend" / "scripts" / "generate_agent_schemas.py"
    spec = importlib.util.spec_from_file_location("test_generate_agent_schemas", module_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_generated_agent_schemas_match_committed_bundle():
    module = _load_schema_generator_module()

    bundle = module.build_schema_bundle()

    assert "session-proposal.schema.json" not in bundle
    for filename, expected in bundle.items():
        actual = json.loads((module.AGENT_SCHEMA_DIR / filename).read_text(encoding="utf-8"))
        assert actual == expected


def test_schema_generator_check_mode_passes_for_committed_bundle(capsys):
    module = _load_schema_generator_module()

    exit_code = module.main(["--check"])

    assert exit_code == 0
    assert "in sync" in capsys.readouterr().out.lower()


def test_finding_record_accepts_lifecycle_analysis_detail_keys():
    module = _load_schema_generator_module()

    schema = module.build_schema_bundle()["finding-record.schema.json"]
    properties = schema["properties"]["details"]["properties"]

    for key in (
        "precondition_analysis",
        "severity_ceiling",
        "root_cause_candidates",
        "notes_provenance",
    ):
        assert key in properties
