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


def test_required_schema_properties_are_not_described_as_optional():
    module = _load_schema_generator_module()

    contradictions: list[str] = []

    def walk(node: object, path: str) -> None:
        if isinstance(node, list):
            for child in node:
                walk(child, path)
            return
        if not isinstance(node, dict):
            return
        required = node.get("required")
        properties = node.get("properties")
        if isinstance(required, list) and isinstance(properties, dict):
            for name in required:
                description = str(properties.get(name, {}).get("description", ""))
                if description.strip().lower().startswith("optional"):
                    contradictions.append(f"{path}.{name}")
        for key, child in node.items():
            walk(child, f"{path}.{key}")

    for filename, schema in module.build_schema_bundle().items():
        walk(schema, filename)

    assert contradictions == []


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


def test_finding_record_schema_carries_the_blue_annotation_vocabulary():
    """``vigil blue`` writes these, and ``details`` is a closed allow-list.

    The generated schema is what the CLI validator enforces, so a blue key
    missing here is a blue verb that exits non-zero having written nothing.
    """
    module = _load_schema_generator_module()

    details = module.build_schema_bundle()["finding-record.schema.json"][
        "properties"
    ]["details"]["properties"]

    for key in (
        "tier",
        "tier_notes",
        "evidence_refs",
        "containment_status",
        "containment_action",
        "containment_command_run_id",
        "checks",
        "devils_advocate",
        "network_window_utc",
        "coverage",
        "cross_skill_correlation_ids",
        "disposition_recommendation",
        "respond_review",
        "alert_normalized",
        "platform",
        "source_signal",
        "alert_external_id",
        "tenant_ref_paths_consulted",
    ):
        assert key in details, key
        assert details[key]["x-vigil-extension"] == "blue/v1"


def test_finding_record_schema_carries_the_keys_the_renderers_read():
    """A key a renderer reads but no door can write is permanently unset."""
    module = _load_schema_generator_module()

    details = module.build_schema_bundle()["finding-record.schema.json"][
        "properties"
    ]["details"]["properties"]

    # The fence info string for poc_code, read by the operator views and the
    # report renderer. Free text by design: the renderers neutralise a hint
    # they cannot render rather than dropping the capture.
    assert details["poc_language"]["type"] == "string"
    assert "enum" not in details["poc_language"]
    # The executed commands behind the cited replay steps.
    replay = details["replay_commands"]
    assert replay["type"] == "array"
    assert replay["items"] == {"type": "integer", "minimum": 1}


def test_finding_detail_aliases_route_names_that_are_not_homeless():
    """Projected from the backend table so both doors quote one sentence.

    An alias may never name a key that IS registered: the suggester only reaches
    the table for a REFUSED key, so an alias for a live key is dead text.
    """
    module = _load_schema_generator_module()

    details = module.build_schema_bundle()["finding-record.schema.json"][
        "properties"
    ]["details"]
    aliases = details["x-vigil-field-aliases"]

    assert aliases["risk"].startswith("details.impact")
    assert "details.severity_rationale" in aliases["risk"]
    assert aliases["indicators"] == "details.iocs"
    assert "details.replies[].new_evidence" in aliases["new_evidence"]
    assert "record-reply" in aliases["new_evidence"]
    for name in aliases:
        assert name not in details["properties"], name


def test_finding_record_schema_closes_provenance_on_one_vocabulary():
    """Both doors, one list.

    The record door refused four keys the update door accepted, the backend
    stored, a skill prescribes and the operator views render. The server-stamped
    blocks stay declared because this schema also validates STORED records, and
    because the code-snapshot attestation is read back off an incoming
    provenance to mark a copied binding.
    """
    module = _load_schema_generator_module()

    provenance = module.build_schema_bundle()["finding-record.schema.json"][
        "properties"
    ]["provenance"]

    assert provenance["additionalProperties"] is False
    assert set(provenance["properties"]) == {
        "agent_id",
        "agent_name",
        "artifact",
        "code_snapshot",
        "reported_by",
        "captured_at",
        "artifact_ref",
        "evidence_quote",
        "verified_by",
        "reviewed_by",
        "command_run_id",
        "code_snapshot_attestation",
        "superseded_code_snapshot",
        "original_canonical_location",
        "operator_authority",
        "superseded_operator_authority",
    }


def test_the_finding_verify_request_carries_the_operator_authority_citation():
    """A waiver that names no evidence is indistinguishable from an unbacked claim."""
    from app.api.assessment import FindingVerifyRequest

    fields = FindingVerifyRequest.model_fields
    assert fields["operator_authority"].annotation is bool
    assert fields["operator_authority"].default is False
    assert fields["operator_authority_intel_id"].default is None
