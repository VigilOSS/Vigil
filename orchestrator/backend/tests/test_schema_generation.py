from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path


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


def test_finding_record_schema_exposes_reserved_code_snapshot_contract():
    module = _load_schema_generator_module()

    schema = module.build_schema_bundle()["finding-record.schema.json"]
    code_snapshot = schema["properties"]["provenance"]["properties"]["code_snapshot"]

    assert code_snapshot["additionalProperties"] is False
    assert code_snapshot["required"] == [
        "repo_id",
        "repo_generation",
        "source_manifest_digest",
    ]
    assert code_snapshot["properties"]["repo_id"]["minimum"] == 1
    assert code_snapshot["properties"]["repo_generation"]["minimum"] == 1
    digest = code_snapshot["properties"]["source_manifest_digest"]
    assert digest["minLength"] == 64
    assert digest["maxLength"] == 64
    assert digest["pattern"] == "^[0-9a-f]{64}$"


def test_finding_record_schema_requires_snapshot_binding_for_file_findings():
    module = _load_schema_generator_module()

    schema = module.build_schema_bundle()["finding-record.schema.json"]

    assert {
        "if": {
            "required": ["canonical_location"],
            "properties": {"canonical_location": {"pattern": r"^\s*file:"}},
        },
        "then": {
            "required": ["provenance"],
            "properties": {
                "provenance": {
                    "required": ["code_snapshot"],
                    "properties": {
                        "code_snapshot": {"type": "object"},
                    },
                },
            },
        },
    } in schema["allOf"]


def test_finding_record_file_examples_carry_complete_snapshot_binding():
    module = _load_schema_generator_module()

    schema = module.build_schema_bundle()["finding-record.schema.json"]
    file_examples = [
        example
        for example in schema["examples"]
        if example["canonical_location"].startswith("file:")
    ]

    assert file_examples
    for example in file_examples:
        binding = example["provenance"]["code_snapshot"]
        assert binding["repo_id"] >= 1
        assert binding["repo_generation"] >= 1
        assert re.fullmatch(r"[0-9a-f]{64}", binding["source_manifest_digest"])


def test_fuzz_schemas_expose_canonical_lists_and_conditional_invariants():
    module = _load_schema_generator_module()
    bundle = module.build_schema_bundle()

    decision = bundle["code-fuzz-decision.schema.json"]
    assert decision["properties"]["target_ids"]["uniqueItems"] is True
    assert {
        "if": {"properties": {"decision": {"const": "required"}}},
        "then": {"properties": {"target_ids": {"minItems": 1}}},
    } in decision["allOf"]
    assert {
        "if": {"properties": {"decision": {"const": "not_required"}}},
        "then": {"properties": {"target_ids": {"maxItems": 0}}},
    } in decision["allOf"]

    campaign = bundle["code-fuzz-campaign-receipt.schema.json"]
    assert campaign["properties"]["covered_finding_slugs"]["uniqueItems"] is True
    assert campaign["properties"]["sanitizers"]["uniqueItems"] is True
    assert {
        "if": {"properties": {"outcome": {"const": "completed_no_crash"}}},
        "then": {
            "properties": {
                "crash_count": {"const": 0},
                "executions": {"minimum": 1},
            }
        },
    } in campaign["allOf"]
    assert {
        "if": {
            "properties": {"outcome": {"const": "completed_crashes_triaged"}}
        },
        "then": {
            "properties": {
                "crash_count": {"minimum": 1},
                "executions": {"minimum": 1},
            }
        },
    } in campaign["allOf"]


def test_code_analysis_result_schema_exposes_skip_and_explicit_supersession():
    module = _load_schema_generator_module()

    schema = module.build_schema_bundle()["code-analysis-result.schema.json"]

    assert schema["properties"]["disposition"]["enum"] == [
        "finding",
        "suspicious",
        "clean",
        "needs_context",
        "skipped",
    ]
    supersedes = schema["properties"]["supersedes"]
    assert supersedes["exclusiveMinimum"] == 0
    for identity_part in (
        "queue item",
        "file",
        "grouped source anchors",
        "this attempt's lease or one it adopted",
    ):
        assert identity_part in supersedes["description"]
    reviewed_spans = schema["properties"]["reviewed_spans"]
    assert "sealed callable registry publication" in reviewed_spans["description"]
    assert "whole-file" in reviewed_spans["description"]
    for incomplete_dimension in ("truncated", "unavailable", "unsupported"):
        assert incomplete_dimension in reviewed_spans["description"]
