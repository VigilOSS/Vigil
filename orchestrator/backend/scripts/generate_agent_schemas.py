"""Generate the committed agent schema bundle from backend request models plus explicit overlays."""
from __future__ import annotations

import argparse
import copy
import json
from dataclasses import dataclass, field
from pathlib import Path
import sys
from typing import Any


BACKEND_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = Path(__file__).resolve().parents[3]
AGENT_SCHEMA_DIR = REPO_ROOT / "agent" / "schemas"
AGENT_SCRIPTS_DIR = REPO_ROOT / "agent" / "scripts"

for path in (BACKEND_ROOT, AGENT_SCRIPTS_DIR):
    path_str = str(path)
    if path_str not in sys.path:
        sys.path.insert(0, path_str)

from app.api.assessment import (  # noqa: E402
    AccessRecordRequest,
    AttackChainRecordRequest,
    CredentialRecordRequest,
    FindingRecordRequest,
    JobRecord,
    ProbeRunRecordRequest,
)
from app.api.code_analysis import AnalysisResultRecord, CodeFileClassification  # noqa: E402
from assess.lib.contracts import get_contract  # noqa: E402


@dataclass(frozen=True)
class SchemaSpec:
    filename: str
    model: type[Any]
    title: str
    description: str | None = None
    overlay: dict[str, Any] = field(default_factory=dict)


def _finding_record_examples() -> list[dict[str, Any]]:
    contract = get_contract("record-finding")
    if contract is None:
        raise RuntimeError("record-finding contract is required to generate finding examples")

    examples: list[dict[str, Any]] = []
    for example in contract.examples:
        normalized = copy.deepcopy(example)
        normalized.setdefault("severity", "medium")
        normalized.setdefault("workflow_status", "active")
        normalized.setdefault("verification_state", "unreviewed")
        normalized.setdefault("verification_disposition", "none")
        normalized.setdefault("defect_family", normalized.get("title", "finding"))
        normalized.setdefault("root_cause_key", "")
        normalized.setdefault("auth_context", "anonymous")
        normalized.setdefault("canonical_location", "")
        normalized.setdefault("summary", normalized.get("title", ""))
        normalized.setdefault("evidence_ref", "")
        normalized.setdefault("notes", "")
        normalized.setdefault("source_name", "vulnerability-analyst")
        details = normalized.get("details") or {}
        if not isinstance(details, dict):
            details = {}
        details.setdefault("discovered_by", "vulnerability-analyst")
        normalized["details"] = details
        normalized.setdefault(
            "provenance",
            {
                "agent_name": "vulnerability-analyst",
            },
        )
        normalized.setdefault("links", [])
        examples.append(normalized)
    return examples


_FINDING_DETAIL_PROPERTIES = {
    "discovered_by": {
        "type": "string",
        "description": "Agent name that first identified this finding",
    },
    "owasp_category": {
        "type": "string",
        "description": "OWASP Top 10 category (for example, A03:2021 Injection)",
    },
    "cwe_id": {
        "type": "string",
        "description": "CWE identifier (for example, CWE-89 for SQL injection)",
    },
    "parameter": {
        "type": "string",
        "description": "Affected parameter name or input vector",
    },
    "slot_type": {
        "type": "string",
        "description": "Code-analysis slot type or attack input class associated with the finding",
    },
    "request_method": {
        "type": "string",
        "description": "HTTP method or triggering action (for example, GET, POST, PUT, DELETE)",
    },
    "evidence": {
        "type": "string",
        "minLength": 1,
        "description": "Exact response excerpt, artifact reference, or replayable proof",
    },
    "kill_reason": {
        "type": "string",
        "description": "Structured verifier rationale when a finding is marked false_positive",
    },
    "kill_check": {
        "type": "integer",
        "minimum": 1,
        "maximum": 5,
        "description": "Verification check number responsible for the false-positive verdict",
    },
    "entry_point": {
        "type": "string",
        "description": "Source of attacker-controlled data (for example, function name, HTTP parameter, file read site)",
    },
    "sink": {
        "type": "string",
        "description": "Dangerous operation receiving tainted data (for example, memcpy call, SQL query, exec invocation)",
    },
    "taint_path": {
        "type": "string",
        "description": "Ordered attacker-controlled data flow from entry point to sink (narrative form)",
    },
    "guards_evaluated": {
        "type": "string",
        "description": "Guard analysis showing which checks exist and why they fail or can be bypassed",
    },
    "impact": {
        "type": "string",
        "minLength": 1,
        "description": "Concrete attacker outcome and affected scope",
    },
    "cvss_vector": {
        "type": "string",
        "description": "CVSS 3.1 vector string (for example, CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)",
    },
    "cvss_score": {
        "type": "number",
        "minimum": 0,
        "maximum": 10,
        "description": "Numeric CVSS 3.1 base score",
    },
    "remediation": {
        "type": "string",
        "description": "Recommended fix or the control that failed",
    },
    "steps_to_reproduce": {
        "type": "array",
        "items": {"type": "string"},
        "description": "Ordered reproduction steps, one string per step",
    },
    "poc_code": {
        "type": "string",
        "description": "Proof-of-concept exploit code or script that demonstrates the vulnerability",
    },
    "poc_request": {
        "type": "object",
        "description": "Structured HTTP request that triggers the vulnerability",
        "properties": {
            "method": {"type": "string"},
            "url": {"type": "string"},
            "headers": {"type": "object", "additionalProperties": {"type": "string"}},
            "body": {"type": "string"},
        },
    },
    "poc_response": {
        "type": "object",
        "description": "Observed HTTP response confirming the vulnerability",
        "properties": {
            "status": {"type": "integer"},
            "headers": {"type": "object", "additionalProperties": {"type": "string"}},
            "body_excerpt": {"type": "string"},
        },
    },
    "references": {
        "type": "array",
        "items": {"type": "string"},
        "description": "External references such as CVE IDs, advisory URLs, or related documentation links",
    },
    "chain_required": {
        "type": "boolean",
        "description": "Whether this finding remains actionable only as part of a larger exploit chain",
    },
    "chain_rationale": {
        "type": "string",
        "description": "Why the finding matters primarily as a chain step instead of a standalone report item",
    },
    "required_followup": {
        "type": "array",
        "items": {"type": "string"},
        "description": "Concrete follow-up steps needed to validate or complete the chain",
    },
    "variant_of": {
        "type": "string",
        "description": "Finding slug of the original finding when this record is a verified variant",
    },
    "original_pattern": {
        "type": "string",
        "description": "Abstract pattern signature copied from the original finding during variant analysis",
    },
}


def _schema_specs() -> tuple[SchemaSpec, ...]:
    return (
        SchemaSpec(
            filename="access-record.schema.json",
            model=AccessRecordRequest,
            title="Assessment Access Record",
            overlay={
                "additionalProperties": False,
                "properties": {
                    "credential_id": {"type": "integer", "minimum": 1},
                    "service_id": {"type": "integer", "minimum": 1},
                }
            },
        ),
        SchemaSpec(
            filename="attack-chain.schema.json",
            model=AttackChainRecordRequest,
            title="Assessment Attack Chain",
            overlay={
                "additionalProperties": False,
                "properties": {
                    "chain_key": {"type": "string", "maxLength": 256},
                    "links": {
                        "items": {
                            "additionalProperties": False,
                            "properties": {
                                "entity_id": {"type": "integer", "minimum": 1},
                            }
                        }
                    },
                }
            },
        ),
        SchemaSpec(
            filename="credential.schema.json",
            model=CredentialRecordRequest,
            title="Assessment Credential Record",
            overlay={"additionalProperties": False},
        ),
        SchemaSpec(
            filename="probe-run.schema.json",
            model=ProbeRunRecordRequest,
            title="Assessment Probe Run",
            overlay={
                "additionalProperties": False,
                "properties": {
                    "request_variant_id": {"type": "integer", "minimum": 1},
                    "service_id": {"type": "integer", "minimum": 1},
                    "coverage_item_id": {"type": "integer", "minimum": 1},
                    "observed_http_status": {"type": "integer"},
                }
            },
        ),
        SchemaSpec(
            filename="job.schema.json",
            model=JobRecord,
            title="Assessment Job Record",
            description="Durable payload for assessment_jobs lifecycle records emitted by `aith assess kali job ...`.",
            overlay={
                "additionalProperties": False,
                "properties": {
                    "id": {"type": "integer", "minimum": 1},
                    "engagement_id": {"type": "integer", "minimum": 1},
                    "parent_command_run_id": {
                        "type": ["integer", "null"],
                        "minimum": 1,
                        "description": "ID of the assessment_command_runs row that initiated this dtach-supervised job.",
                    },
                    "status": {
                        "enum": ["queued", "running", "completed", "failed", "killed", "lost", "stop_failed"],
                        "description": "Job lifecycle state. queued: row written, dtach not yet attached. running: dtach attached, worker live. completed/failed/killed/lost/stop_failed: terminal states.",
                    },
                    "started_at": {"description": "ISO8601 timestamp when the dtach worker first attached."},
                    "ended_at": {"description": "ISO8601 timestamp when the dtach worker exited or was killed."},
                    "exit_code": {
                        "type": ["integer", "null"],
                        "description": "Worker process exit code on terminal status.",
                    },
                    "dtach_socket_path": {
                        "description": "Path to the dtach control socket, used by `aith assess kali job tail` to reattach.",
                    },
                    "stdout_path": {
                        "description": "Path to the worker's stdout spill file under ${ENGAGEMENT_DIR}/scans/kali/.",
                    },
                    "stderr_path": {
                        "description": "Path to the worker's stderr spill file under ${ENGAGEMENT_DIR}/scans/kali/.",
                    },
                    "audit_metadata": {
                        "type": ["object", "null"],
                        "description": "Audit metadata (technique, intent, probe_kind, destructive, phase, agent_name) captured at dispatch time.",
                    },
                    "created_at": {"description": "ISO8601 timestamp the job row was first written."},
                    "updated_at": {"description": "ISO8601 timestamp of the most recent PATCH."},
                },
            },
        ),
        SchemaSpec(
            filename="finding-record.schema.json",
            model=FindingRecordRequest,
            title="Assessment Finding Record",
            overlay={
                "required": [
                    "title",
                    "severity",
                    "workflow_status",
                    "verification_state",
                    "verification_disposition",
                    "defect_family",
                    "root_cause_key",
                    "auth_context",
                    "canonical_location",
                    "summary",
                    "evidence_ref",
                    "notes",
                    "details",
                ],
                "examples": _finding_record_examples(),
                "properties": {
                    "slug": {"type": "string", "minLength": 1, "maxLength": 256},
                    "severity": {
                        "enum": ["info", "low", "medium", "high", "critical"],
                    },
                    "workflow_status": {
                        "enum": ["draft", "active", "exploited", "blocked", "false_positive", "merged", "reported"],
                    },
                    "verification_state": {
                        "enum": ["unreviewed", "verified", "disputed"],
                    },
                    "verification_disposition": {
                        "enum": ["none", "confirmed", "downgraded", "false_positive"],
                    },
                    "defect_family": {"maxLength": 128},
                    "root_cause_key": {"maxLength": 256},
                    "auth_context": {"maxLength": 128},
                    "canonical_location": {"maxLength": 1024},
                    "summary": {"maxLength": 4096},
                    "evidence_ref": {"maxLength": 1024},
                    "notes": {"maxLength": 20000},
                    "source_name": {"maxLength": 128},
                    "details": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": ["evidence", "impact"],
                        "properties": _FINDING_DETAIL_PROPERTIES,
                    },
                    "provenance": {
                        "type": "object",
                        "additionalProperties": False,
                        "properties": {
                            "agent_name": {
                                "type": "string",
                                "description": "Name of the agent that produced this finding",
                            },
                            "artifact": {
                                "type": "string",
                                "description": "Optional artifact reference associated with the finding provenance",
                            },
                        },
                    },
                    "request_variant_id": {"type": "integer", "minimum": 1},
                    "service_id": {"type": "integer", "minimum": 1},
                    "surface_id": {"type": "integer", "minimum": 1},
                    "links": {
                        "items": {
                            "type": "object",
                            "additionalProperties": False,
                            "required": ["target_kind"],
                            "properties": {
                                "link_kind": {"type": "string", "default": "related"},
                                "target_kind": {"type": "string", "minLength": 1},
                                "target_id": {"type": "integer", "minimum": 1},
                                "target_ref": {"type": "string"},
                                "notes": {"type": "string"},
                                "provenance": {
                                    "type": "object",
                                    "additionalProperties": False,
                                    "properties": {
                                        "agent_name": {"type": "string"},
                                    },
                                },
                            },
                        }
                    },
                },
            },
        ),
        SchemaSpec(
            filename="code-file-classification.schema.json",
            model=CodeFileClassification,
            title="Code File Classification",
            description="Classification payload for bulk-classifying source code files by security relevance.",
            overlay={
                "examples": [
                    {
                        "file_id": 42,
                        "classification": "critical",
                        "language": "c++",
                        "role": "protocol_parser",
                        "slot_types": ["NETWORK-INPUT", "PROTOCOL-FIELD"],
                        "analysis_priority": 95,
                    }
                ],
                "properties": {
                    "file_id": {
                        "description": "Backend ID of the code_files record to classify.",
                    },
                    "classification": {
                        "enum": ["critical", "high", "medium", "low", "skip"],
                        "description": "Security relevance tier. critical: parses untrusted input, auth, crypto, protocol state machines. high: memory mgmt, command building, file I/O. medium: utility, string handling. low: build, test infra. skip: generated, docs, vendored.",
                    },
                    "role": {
                        "description": "Functional role of the file (for example, protocol_parser, auth_handler, crypto_impl, entry_point, memory_allocator, config_parser, utility, test, build, documentation).",
                    },
                    "language": {
                        "type": "string",
                        "description": "Optional language correction when ingestion guessed wrong. Omit when the stored language is already correct.",
                    },
                    "slot_types": {
                        "description": "Types of untrusted data that flow into this file. Required for critical and high files. Allowed values are the 8 public slot types; context-specific families like auth, crypto, and error handling are derived from role/language by the backend.",
                        "default": [],
                    },
                    "analysis_priority": {
                        "description": "Priority score combining classification tier, git churn, entry-point proximity, and past CVE history. critical: 80-100, high: 50-79, medium: 20-49, low: 5-19, skip: 0.",
                    },
                },
            },
        ),
        SchemaSpec(
            filename="code-analysis-result.schema.json",
            model=AnalysisResultRecord,
            title="Code Analysis Result",
            description="Per-function analysis result payload recorded by code-vuln-hunter after analyzing a source code file.",
            overlay={
                "additionalProperties": False,
                "examples": [
                    {
                        "file_id": 15,
                        "agent_name": "code-vuln-hunter",
                        "function_name": "parseurl",
                        "hypothesis": "Attacker-controlled URL scheme length passed to memcpy without bounds check",
                        "evidence": "In parseurl() at line 342, schemelen is derived from user-supplied URL without validation. memcpy(buf, scheme, schemelen) copies attacker-controlled bytes into fixed-size heap buffer.",
                        "disposition": "finding",
                        "confidence": "high",
                        "finding_slug": "CH-001",
                        "cwe_id": "CWE-122",
                        "slot_type": "URL-COMPONENT",
                        "notes": "Guard at line 305 uses signed int comparison allowing negative bypass.",
                        "cwe_coverage": [
                            {
                                "family": "buffer-overflow",
                                "effort": 85,
                                "functions_analyzed": 12,
                                "entry_chains_traced": 4,
                                "total_entry_chains": 5,
                                "notes": "Full taint tracing on all memcpy/memmove sinks reachable from network input.",
                            },
                            {
                                "family": "integer-overflow",
                                "effort": 40,
                                "functions_analyzed": 6,
                                "entry_chains_traced": 1,
                                "total_entry_chains": 3,
                                "notes": "Checked obvious arithmetic on lengths; deeper cross-file flows not yet traced.",
                            },
                        ],
                        "cross_file_triggers": [
                            {
                                "file_path": "src/url_helpers.c",
                                "reason": "parseurl delegates scheme validation to url_validate_scheme() which may have its own bounds issue",
                                "vuln_class": "buffer-overflow",
                            }
                        ],
                    }
                ],
                "properties": {
                    "queue_item_id": {
                        "type": ["integer", "null"],
                        "description": "ID of the code_analysis_queue item this result corresponds to.",
                    },
                    "file_id": {
                        "description": "ID of the code_files record containing the analyzed function.",
                    },
                    "agent_name": {
                        "description": "Name of the agent that produced this result.",
                    },
                    "function_name": {
                        "description": "Name of the analyzed function.",
                    },
                    "hypothesis": {
                        "description": "The vulnerability hypothesis tested. What could go wrong and why.",
                    },
                    "evidence": {
                        "description": "Evidence supporting the disposition. For findings: code snippet + taint path + guard failure. For clean: brief reasoning why no vulnerability exists.",
                    },
                    "disposition": {
                        "enum": ["finding", "suspicious", "clean", "needs_context"],
                        "description": "Analysis result. finding: confirmed vulnerability. suspicious: needs variant analysis or deeper context. clean: no vulnerability. needs_context: blocked on missing code.",
                    },
                    "confidence": {
                        "enum": ["high", "medium", "low"],
                        "description": "high: full taint trace + guards evaluated. medium: trace but unresolved callees. low: pattern match only.",
                    },
                    "finding_slug": {
                        "description": "If disposition is 'finding', the slug of the assessment_findings record created. Empty otherwise.",
                    },
                    "cwe_id": {
                        "description": "Specific CWE ID (for example, CWE-122, CWE-190). Must be specific, not generic (CWE-119).",
                    },
                    "slot_type": {
                        "description": "Shannon slot type classification of the vulnerability (for example, BUFFER-WRITE, FORMAT-STRING, INTEGER-OVERFLOW, USE-AFTER-FREE, CMD-INJECTION).",
                    },
                    "notes": {
                        "description": "Additional notes, context expansion requests, or follow-up recommendations.",
                    },
                    "cwe_coverage": {
                        "items": {
                            "type": "object",
                            "required": ["family", "effort"],
                            "properties": {
                                "family": {
                                    "type": "string",
                                    "description": "Vulnerability class name (for example, sql-injection, path-traversal)",
                                },
                                "effort": {
                                    "type": "integer",
                                    "minimum": 0,
                                    "maximum": 100,
                                    "description": "How thoroughly this class was analyzed. 0-20: glanced at imports/exports. 20-40: checked obvious sinks. 40-60: examined entry-point functions with basic taint tracing. 60-80: full taint tracing on entry-point chains + error paths. 80-100: exhaustive analysis including cross-file flows and bypass attempts.",
                                },
                                "functions_analyzed": {
                                    "type": "integer",
                                    "default": 0,
                                    "description": "Number of functions in this file examined for this vulnerability class",
                                },
                                "entry_chains_traced": {
                                    "type": "integer",
                                    "default": 0,
                                    "description": "Number of entry-point chains from call graph traced end-to-end for this class",
                                },
                                "total_entry_chains": {
                                    "type": "integer",
                                    "default": 0,
                                    "description": "Total entry-point chains relevant to this class (denominator for coverage ratio)",
                                },
                                "notes": {
                                    "type": "string",
                                    "default": "",
                                    "description": "Brief explanation of what was or was not analyzed and why",
                                },
                            },
                        },
                        "default": [],
                        "description": "Per-vulnerability-class effort records. Effort is a gradient (0-100), not binary.",
                    },
                    "cross_file_triggers": {
                        "items": {
                            "type": "object",
                            "properties": {
                                "file_path": {"type": "string"},
                                "reason": {"type": "string"},
                                "vuln_class": {"type": "string"},
                            },
                        },
                        "default": [],
                        "description": "Files connected via call graph that need re-analysis based on this file's findings",
                    },
                },
            },
        ),
    )


def _resolve_ref(ref: str, defs: dict[str, Any]) -> dict[str, Any]:
    prefix = "#/$defs/"
    if not ref.startswith(prefix):
        raise ValueError(f"Unsupported schema reference: {ref}")
    return copy.deepcopy(defs[ref.removeprefix(prefix)])


def _collapse_union(branches: list[dict[str, Any]]) -> dict[str, Any] | None:
    if len(branches) != 2:
        return None
    null_branch = next((branch for branch in branches if branch.get("type") == "null"), None)
    non_null_branch = next((branch for branch in branches if branch.get("type") != "null"), None)
    if null_branch is None or non_null_branch is None:
        return None

    merged = copy.deepcopy(non_null_branch)
    branch_type = merged.get("type")
    if isinstance(branch_type, list):
        merged["type"] = [item for item in branch_type if item != "null"] + ["null"]
    elif isinstance(branch_type, str):
        merged["type"] = [branch_type, "null"]
    else:
        return None
    return merged


def _normalize_schema(schema: dict[str, Any], defs: dict[str, Any] | None = None) -> dict[str, Any]:
    defs = dict(defs or {})
    local_defs = schema.get("$defs")
    if isinstance(local_defs, dict):
        defs.update(local_defs)

    if "$ref" in schema:
        resolved = _resolve_ref(str(schema["$ref"]), defs)
        return _normalize_schema(resolved, defs)

    union_key = "anyOf" if "anyOf" in schema else "oneOf" if "oneOf" in schema else None
    if union_key is not None:
        branches = [_normalize_schema(branch, defs) for branch in schema[union_key]]
        collapsed = _collapse_union(branches)
        if collapsed is None:
            raise ValueError(f"Unsupported schema union in {union_key}: {branches!r}")
        retained = {
            key: value
            for key, value in schema.items()
            if key not in {"$defs", "$ref", "anyOf", "oneOf"}
        }
        return _normalize_schema(deep_merge(collapsed, retained), defs)

    normalized: dict[str, Any] = {}
    for key, value in schema.items():
        if key == "$defs":
            continue
        if key == "properties" and isinstance(value, dict):
            normalized[key] = {
                name: _normalize_schema(child, defs) if isinstance(child, dict) else child
                for name, child in value.items()
            }
            continue
        if key == "items" and isinstance(value, dict):
            normalized[key] = _normalize_schema(value, defs)
            continue
        if key == "additionalProperties" and isinstance(value, dict):
            normalized[key] = _normalize_schema(value, defs)
            continue
        normalized[key] = copy.deepcopy(value)
    return normalized


def deep_merge(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    merged = copy.deepcopy(base)
    for key, value in overlay.items():
        current = merged.get(key)
        if isinstance(current, dict) and isinstance(value, dict):
            merged[key] = deep_merge(current, value)
        else:
            merged[key] = copy.deepcopy(value)
    return merged


def build_schema_bundle() -> dict[str, dict[str, Any]]:
    bundle: dict[str, dict[str, Any]] = {}
    for spec in _schema_specs():
        normalized = _normalize_schema(spec.model.model_json_schema())
        generated = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": f"https://security-research.local/schemas/{spec.filename}",
            "$comment": f"Generated by orchestrator/backend/scripts/generate_agent_schemas.py from {spec.model.__module__}.{spec.model.__name__} plus agent-side overlays where the CLI contract is intentionally stricter than the backend model.",
            **normalized,
            "title": spec.title,
            **({"description": spec.description} if spec.description else {}),
        }
        bundle[spec.filename] = deep_merge(generated, spec.overlay)
    return bundle


def write_schema_bundle(bundle: dict[str, dict[str, Any]], output_dir: Path = AGENT_SCHEMA_DIR) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    for filename, schema in bundle.items():
        path = output_dir / filename
        path.write_text(json.dumps(schema, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def find_schema_drift(bundle: dict[str, dict[str, Any]], output_dir: Path = AGENT_SCHEMA_DIR) -> list[str]:
    drifted: list[str] = []
    for filename, expected in bundle.items():
        path = output_dir / filename
        if not path.is_file():
            drifted.append(filename)
            continue
        actual = json.loads(path.read_text(encoding="utf-8"))
        if actual != expected:
            drifted.append(filename)
    return drifted


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate or verify the committed agent schema bundle from backend models.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Fail if committed agent schemas drift from the generated bundle.",
    )
    args = parser.parse_args(argv)

    bundle = build_schema_bundle()
    if args.check:
        drifted = find_schema_drift(bundle)
        if drifted:
            for filename in drifted:
                print(f"Schema drift: {filename}", file=sys.stderr)
            print(
                "Run `uv run --directory orchestrator/backend python scripts/generate_agent_schemas.py` to rewrite the committed bundle.",
                file=sys.stderr,
            )
            return 1
        print("Agent schema bundle is in sync.")
        return 0

    write_schema_bundle(bundle)
    print(f"Wrote {len(bundle)} generated schemas to {AGENT_SCHEMA_DIR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
