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
from app.services.state_manager._common import SubmissionStatus, VerificationDisposition  # noqa: E402
from assess.lib.contracts import get_contract  # noqa: E402


# Sourced from the canonical backend StrEnum so the agent-side overlay can never
# drift from the values the backend actually persists + serializes on GET
# /findings (e.g. ``pending_runtime_proof``). Enum iteration order is stable, so
# this keeps the generated schema deterministic.
_VERIFICATION_DISPOSITION_VALUES = [member.value for member in VerificationDisposition]
# Likewise sourced from the canonical SubmissionStatus StrEnum.
_SUBMISSION_STATUS_VALUES = [member.value for member in SubmissionStatus]


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
        "description": "Agent name that first identified this finding (e.g. 'vulnerability-analyst').",
    },
    "owasp_category": {
        "type": "string",
        "description": "OWASP Top 10 2021 category code and name (e.g. 'A03:2021 Injection').",
    },
    "cwe_id": {
        "type": "string",
        "description": "CWE identifier (e.g. 'CWE-89' for SQL injection, 'CWE-122' for heap buffer overflow).",
    },
    "parameter": {
        "type": "string",
        "description": "Exact name of the affected input: query param, header, JSON key, or form field (e.g. 'q', 'X-User-Id', 'username').",
    },
    "slot_type": {
        "type": "string",
        "description": "Code-analysis input class for the attack (e.g. 'URL-COMPONENT', 'NETWORK-INPUT', 'PROTOCOL-FIELD').",
    },
    "request_method": {
        "type": "string",
        "description": "HTTP verb that triggers the finding (e.g. 'GET', 'POST', 'PUT', 'DELETE').",
    },
    "evidence": {
        "type": "string",
        "minLength": 1,
        "description": "Verbatim proof: exact response excerpt, artifact path, or replayable request/response. Must be sufficient to reproduce independently.",
    },
    "kill_reason": {
        "type": "string",
        "description": "Verifier rationale for false_positive verdict: which check failed and why the issue is not exploitable.",
    },
    "kill_check": {
        "type": "integer",
        "minimum": 1,
        "maximum": 5,
        "description": "Verification check number (1-5) that produced the false-positive verdict.",
    },
    "entry_point": {
        "type": "string",
        "description": "Where attacker-controlled data enters the program (e.g. 'curl_url_set(CURLURLPART_URL, attacker_url)', 'POST /upload body field filename').",
    },
    "sink": {
        "type": "string",
        "description": "Dangerous operation that consumes tainted data (e.g. 'memcpy(buf, scheme, schemelen) at lib/urlapi.c:342', 'sqlite3_exec(db, query)').",
    },
    "taint_path": {
        "type": "string",
        "description": "Arrow-delimited data flow from entry_point to sink (e.g. 'curl_url_set -> parseurl() -> memcpy(buf, scheme, schemelen)').",
    },
    "guards_evaluated": {
        "type": "string",
        "description": "List each relevant bounds/validation check and state whether it is absent, bypassable, or ineffective (e.g. 'No bounds check on schemelen before memcpy').",
    },
    "impact": {
        "type": "string",
        "minLength": 1,
        "description": "Concrete attacker outcome: what data is exposed or what action can be taken, and who is affected (e.g. 'Anonymous attacker can read all DB rows', 'Remote code execution via heap corruption').",
    },
    "cvss_vector": {
        "type": "string",
        "minLength": 1,
        "description": "CVSS 3.1 vector string (e.g. 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N').",
    },
    "cvss_score": {
        "type": "number",
        "exclusiveMinimum": 0,
        "maximum": 10,
        "description": "CVSS 3.1 base score (0.1-10.0). Must match cvss_vector.",
    },
    "remediation": {
        "type": "string",
        "description": "Specific fix or missing control (e.g. 'Use parameterized queries', 'Add bounds check on schemelen before memcpy').",
    },
    "steps_to_reproduce": {
        "type": "array",
        "items": {"type": "string"},
        "description": "Ordered reproduction steps, one action per string. Start from initial access state; end at impact observation.",
    },
    "poc_code": {
        "type": "string",
        "description": "Minimal exploit code or script that reproduces the finding. Omit if poc_request/poc_response is sufficient.",
    },
    "poc_request": {
        "type": "object",
        "description": "HTTP request that triggers the vulnerability.",
        "properties": {
            "method": {"type": "string"},
            "url": {"type": "string"},
            "headers": {"type": "object", "additionalProperties": {"type": "string"}},
            "body": {"type": "string"},
        },
    },
    "poc_response": {
        "type": "object",
        "description": "Observed HTTP response that confirms the vulnerability.",
        "properties": {
            "status": {"type": "integer"},
            "headers": {"type": "object", "additionalProperties": {"type": "string"}},
            "body_excerpt": {"type": "string"},
        },
    },
    "references": {
        "type": "array",
        "items": {"type": "string"},
        "description": "CVE IDs, NVD/advisory URLs, or CWE links relevant to this finding.",
    },
    "chain_required": {
        "type": "boolean",
        "description": "Set true only when this finding has no standalone impact and is meaningful only as part of an exploit chain.",
    },
    "chain_rationale": {
        "type": "string",
        "description": "Required when chain_required is true: explain which chain step this enables and why standalone impact is insufficient.",
    },
    "required_followup": {
        "type": "array",
        "items": {"type": "string"},
        "description": "Concrete next steps needed to validate or complete the chain (e.g. 'Confirm reachable network caller for the URL parser').",
    },
    "variant_of": {
        "type": "string",
        "description": "Slug of the root finding when this record is a verified same-class variant (e.g. 'sqli-search-q').",
    },
    "original_pattern": {
        "type": "string",
        "description": "Abstract pattern signature copied verbatim from the root finding during variant analysis.",
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
                    "access_key": {
                        "description": "Stable dedupe key for this access entry. Use kebab-case: '<principal>-<target>-<level>' (e.g. 'admin-db01-root').",
                    },
                    "credential_id": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "ID of the credential record used to gain this access. Omit if no credential record exists yet.",
                    },
                    "service_id": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "ID of the service this access applies to. Omit if access is not tied to a specific service.",
                    },
                    "principal": {
                        "description": "Account or identity that holds this access (e.g. 'root', 'admin@corp.example', 'arn:aws:iam::123:role/Prod').",
                    },
                    "access_level": {
                        "description": "Privilege tier obtained (e.g. 'read', 'admin', 'root', 'domain-admin', 'rce'). Use the most specific label that fits.",
                    },
                    "target_ref": {
                        "description": "What the principal can access: host, URL, database, cloud resource ARN, or scope (e.g. 'db01.internal', 'https://app.example/', 'arn:aws:s3:::prod-bucket').",
                    },
                    "status": {
                        "description": "Validity state of this access. Use 'active' when confirmed working, 'revoked' when credentials are burned or blocked.",
                    },
                    "evidence_ref": {
                        "description": "Path or ID of the artifact proving access (e.g. 'scans/ssh-session.log'). Leave empty if evidence is in notes.",
                    },
                    "notes": {
                        "description": "How access was obtained, lateral-movement path, or operational caveats.",
                    },
                    "provenance": {
                        "description": "Agent or tool that recorded this access (e.g. {\"agent_name\": \"post-exploitation\"}).",
                    },
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
                    "chain_key": {
                        "type": "string",
                        "maxLength": 256,
                        "description": "Stable kebab-case identifier for this chain (e.g. 'anon-rce-via-sqli-lfi'). Omit to auto-generate.",
                    },
                    "title": {
                        "description": "One-line chain summary: initial access + pivots + terminal impact (e.g. 'Anon SQLi → LFI → RCE on app server').",
                    },
                    "status": {
                        "description": "Chain lifecycle state (e.g. 'active', 'exploited', 'reported'). Mirrors finding workflow_status vocabulary.",
                    },
                    "severity": {
                        "description": "Combined chain severity — set to the highest severity of constituent findings unless the chain itself escalates impact.",
                    },
                    "narrative": {
                        "description": "Step-by-step attack story: initial foothold, each pivot, and terminal impact. Reference linked finding slugs inline.",
                    },
                    "evidence_ref": {
                        "description": "Path or ID of the artifact documenting the chain (e.g. 'scans/chain-rce-proof.txt'). Leave empty if evidence is in linked findings.",
                    },
                    "provenance": {
                        "description": "Agent that assembled this chain (e.g. {\"agent_name\": \"vulnerability-analyst\"}).",
                    },
                    "links": {
                        "items": {
                            "additionalProperties": False,
                            "properties": {
                                "relation": {
                                    "description": "How this entity participates in the chain (e.g. 'step', 'prerequisite', 'outcome', 'credential-used').",
                                },
                                "entity_kind": {
                                    "description": "Type of the linked entity (e.g. 'finding', 'credential', 'access_record').",
                                },
                                "entity_id": {
                                    "type": "integer",
                                    "minimum": 1,
                                    "description": "Database ID of the linked entity. Provide entity_id OR entity_ref, not both.",
                                },
                                "entity_ref": {
                                    "description": "Slug or string reference when entity_id is unavailable (e.g. 'sqli-search-q').",
                                },
                                "notes": {
                                    "description": "How this step connects to the next or why this entity is part of the chain.",
                                },
                                "provenance": {
                                    "description": "Agent that created this link (e.g. {\"agent_name\": \"vulnerability-analyst\"}).",
                                },
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
            overlay={
                "additionalProperties": False,
                "properties": {
                    "credential_key": {
                        "description": "Stable dedupe key for this credential. Use kebab-case: '<principal>-<kind>' (e.g. 'admin-ssh-key', 'svc-db-password').",
                    },
                    "kind": {
                        "description": "Credential type. Common values: 'password', 'ssh-key', 'api-key', 'bearer-token', 'cookie', 'ntlm-hash', 'kerberos-ticket', 'aws-access-key', 'certificate', 'oauth-token'.",
                    },
                    "principal": {
                        "description": "Account this credential authenticates (e.g. 'root', 'admin@corp.example', 'svc-deploy').",
                    },
                    "source_name": {
                        "description": "Tool or agent that recovered this credential (e.g. 'mimikatz', 'post-exploitation').",
                    },
                    "status": {
                        "description": "Validity state: 'discovered' (found, not yet tested), 'valid' (confirmed working), 'invalid' (tested and rejected), 'revoked'.",
                    },
                    "notes": {
                        "description": "Where found, how extracted, scope of access, or any operational caveats.",
                    },
                    "provenance": {
                        "description": "Agent or tool that recorded this credential (e.g. {\"agent_name\": \"post-exploitation\"}).",
                    },
                    "identity": {
                        "description": "Human-readable display name or alias for the principal (e.g. 'John Smith', 'deploy-bot'). Distinct from principal login name.",
                    },
                },
            },
        ),
        SchemaSpec(
            filename="probe-run.schema.json",
            model=ProbeRunRecordRequest,
            title="Assessment Probe Run",
            overlay={
                "additionalProperties": False,
                "properties": {
                    "request_variant_id": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "ID of the request variant this probe targeted. Ties the probe to a specific endpoint definition.",
                    },
                    "service_id": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "ID of the service under test. Omit when request_variant_id is provided (service is inferred).",
                    },
                    "coverage_item_id": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "ID of the coverage item this probe fulfills. Links probe runs to the coverage tracking table.",
                    },
                    "auth_context": {
                        "description": "Authentication state used during the probe (e.g. 'anonymous', 'user', 'admin', or a credential slug).",
                    },
                    "input_slot": {
                        "description": "Attack surface class where the payload was injected (e.g. 'query-param', 'json-body', 'http-header', 'path-segment', 'cookie').",
                    },
                    "attack_family": {
                        "description": "Vuln class being tested (e.g. 'sqli', 'xss', 'ssrf', 'lfi', 'rce', 'auth-bypass'). Required.",
                    },
                    "payload_family": {
                        "description": "Payload sub-category or wordlist name (e.g. 'boolean-blind', 'time-based', 'polyglot-xss').",
                    },
                    "payload_value": {
                        "description": "Exact payload string sent in the probe. Include URL-encoding if relevant.",
                    },
                    "tool_name": {
                        "description": "Tool or script that sent the probe (e.g. 'sqlmap', 'ffuf', 'burp', 'custom-script'). Required.",
                    },
                    "agent_name": {
                        "description": "Agent that dispatched this probe (e.g. 'vulnerability-analyst'). Defaults to empty when tool ran directly.",
                    },
                    "result_status": {
                        "description": "Outcome: 'signal' = anomaly detected, warrants escalation to a finding. 'tested' = ran cleanly, no anomaly. 'no-signal' = explicit negative result. 'attempted' = sent but outcome unclear. 'blocked' = WAF/control stopped probe. 'error' = tool or network failure.",
                    },
                    "observed_http_status": {
                        "type": "integer",
                        "description": "HTTP response status code received (e.g. 200, 403, 500). Null for non-HTTP probes.",
                    },
                    "signal_type": {
                        "description": "What anomaly was detected when result_status is 'signal' (e.g. 'time-delay', 'error-disclosure', 'different-response-length').",
                    },
                    "evidence_ref": {
                        "description": "Path or ID of the artifact capturing the probe exchange (e.g. 'scans/ffuf-run1.json').",
                    },
                    "notes": {
                        "description": "Freeform observations about this probe run (anomalies, tool warnings, raw output excerpts).",
                    },
                    "target_host": {
                        "description": "Hostname or IP of the probed target (e.g. 'api.example.com', '10.0.1.5').",
                    },
                    "target_path": {
                        "description": "URL path probed (e.g. '/api/v1/search'). Include query string only if it was fixed across all payloads.",
                    },
                    "target_port": {
                        "description": "TCP port probed. Omit when port is implied by the scheme (80/443).",
                    },
                }
            },
        ),
        SchemaSpec(
            filename="job.schema.json",
            model=JobRecord,
            title="Assessment Job Record",
            description="Read-only lifecycle record returned by `vigil assess kali job list/status`. Do not construct manually — the orchestrator writes these rows.",
            overlay={
                "additionalProperties": False,
                "properties": {
                    "id": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "Database primary key for this job row.",
                    },
                    "engagement_id": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "Engagement this job belongs to.",
                    },
                    "parent_command_run_id": {
                        "type": ["integer", "null"],
                        "minimum": 1,
                        "description": "ID of the assessment_command_runs row that spawned this dtach job.",
                    },
                    "status": {
                        "enum": ["queued", "running", "completed", "failed", "killed", "lost", "stop_failed"],
                        "description": "Lifecycle state. 'queued': row written, dtach not yet started. 'running': worker live. Terminal: 'completed' (exit 0), 'failed' (exit !=0), 'killed' (SIGKILL), 'lost' (socket gone), 'stop_failed' (kill attempt failed).",
                    },
                    "started_at": {"description": "ISO 8601 UTC timestamp when the dtach worker first attached. Null until 'running'."},
                    "ended_at": {"description": "ISO 8601 UTC timestamp when the worker exited or was killed. Null until terminal."},
                    "exit_code": {
                        "type": ["integer", "null"],
                        "description": "Process exit code. 0 = success; non-zero = failure. Null until terminal status.",
                    },
                    "dtach_socket_path": {
                        "description": "Filesystem path to the dtach control socket. Pass to `vigil assess kali job tail` to reattach to a running job.",
                    },
                    "stdout_path": {
                        "description": "Absolute path to the stdout spill file under ${ENGAGEMENT_DIR}/scans/kali/.",
                    },
                    "stderr_path": {
                        "description": "Absolute path to the stderr spill file under ${ENGAGEMENT_DIR}/scans/kali/.",
                    },
                    "audit_metadata": {
                        "type": ["object", "null"],
                        "description": "Structured fields captured at dispatch: technique, intent, probe_kind, destructive (bool), phase, agent_name.",
                    },
                    "created_at": {"description": "ISO 8601 UTC timestamp when the job row was inserted."},
                    "updated_at": {"description": "ISO 8601 UTC timestamp of the last status update."},
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
                    "slug": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 256,
                        "description": "Stable kebab-case identifier for this finding (e.g. 'sqli-search-q'). Omit to auto-generate.",
                    },
                    "title": {
                        "description": "One-line finding name: vuln class + location (e.g. 'Blind SQL injection in /search?q').",
                    },
                    "severity": {
                        "description": "CVSS-aligned impact rating. Use 'critical' only for CVSS >=9.0 or trivially exploitable RCE/auth-bypass.",
                        "enum": ["info", "low", "medium", "high", "critical"],
                    },
                    "workflow_status": {
                        "description": "Lifecycle state. New findings: 'active'. Post-exploitation confirmed: 'exploited'. WAF/control stopped testing: 'blocked'. Duplicate absorbed into another record: 'merged'. Delivered to client: 'reported'.",
                        "enum": ["draft", "active", "exploited", "blocked", "false_positive", "merged", "reported"],
                    },
                    "verification_state": {
                        "description": "Human review state. Leave 'unreviewed' when first recording; set 'verified' after confirming exploitability; 'disputed' when contested.",
                        "enum": ["unreviewed", "verified", "disputed"],
                    },
                    "verification_disposition": {
                        "description": "Verifier outcome. 'none': not yet checked. 'pending_runtime_proof': needs live PoC. 'confirmed': exploitability proven. 'downgraded': real but severity reduced. 'false_positive': not exploitable.",
                        "enum": list(_VERIFICATION_DISPOSITION_VALUES),
                    },
                    "defect_family": {
                        "maxLength": 128,
                        "description": "Short vuln-class label for grouping (e.g. 'sql-injection', 'buffer-overflow', 'ssrf'). Use kebab-case.",
                    },
                    "root_cause_key": {
                        "maxLength": 256,
                        "description": "Stable key linking variants to a shared root cause (e.g. 'missing-input-sanitization-search'). Omit if not part of a variant cluster.",
                    },
                    "auth_context": {
                        "maxLength": 128,
                        "description": "Authentication state when the finding was triggered. Use 'anonymous', a role name (e.g. 'user', 'admin'), or credential slug.",
                    },
                    "canonical_location": {
                        "maxLength": 1024,
                        "description": "Primary affected location. URL for network findings (e.g. 'https://target.example/search?q'); 'file:path:line' for code findings.",
                    },
                    "summary": {
                        "maxLength": 4096,
                        "description": "2-5 sentence description: what is vulnerable, how it is triggered, and the attacker impact.",
                    },
                    "evidence_ref": {
                        "maxLength": 1024,
                        "description": "Path or identifier for supporting artifact (e.g. 'scans/sqlmap.txt', 'artifacts/burp-export.xml'). Leave empty if evidence is inline in details.evidence.",
                    },
                    "notes": {
                        "maxLength": 20000,
                        "description": "Freeform operational notes: retesting observations, partial progress, raw tool output. Not shown in reports.",
                    },
                    "source_name": {
                        "maxLength": 128,
                        "description": "Agent or tool that produced this record (e.g. 'vulnerability-analyst', 'nuclei'). Mirrors provenance.agent_name for quick filtering.",
                    },
                    "details": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": [
                            "evidence",
                            "impact",
                        ],
                        "properties": _FINDING_DETAIL_PROPERTIES,
                    },
                    "provenance": {
                        "type": "object",
                        "additionalProperties": False,
                        "properties": {
                            "agent_name": {
                                "type": "string",
                                "description": "Agent that produced this finding (e.g. 'vulnerability-analyst'). Mirror of source_name.",
                            },
                            "artifact": {
                                "type": "string",
                                "description": "Path or ID of the artifact this finding was derived from.",
                            },
                        },
                    },
                    "evidence_type": {
                        "description": "Strength of evidence. 'network-confirmed': live exploit or observed response. 'code-inferred': static/dataflow analysis without runtime proof. 'theoretical': logic-based hypothesis, no code or traffic evidence. 'informational': non-exploitable observation.",
                    },
                    "submission_status": {
                        "description": "External bug-bounty/program submission state, ORTHOGONAL to workflow_status (report-inclusion). 'none': not submitted. 'submitted': sent to the program. 'accepted'/'rejected'/'duplicate': program triage outcome. 'needs_info': program requested more detail. Omit to keep the default 'none'.",
                        "enum": list(_SUBMISSION_STATUS_VALUES),
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
                                "link_kind": {
                                    "type": "string",
                                    "default": "related",
                                    "description": "Relationship type (e.g. 'related', 'exploits', 'chained-with', 'variant-of').",
                                },
                                "target_kind": {
                                    "type": "string",
                                    "minLength": 1,
                                    "description": "Entity type of the link target (e.g. 'finding', 'credential', 'access_record', 'attack_chain').",
                                },
                                "target_id": {
                                    "type": "integer",
                                    "minimum": 1,
                                    "description": "Database ID of the target entity. Provide target_id OR target_ref, not both.",
                                },
                                "target_ref": {
                                    "type": "string",
                                    "description": "Slug or string reference for the target when target_id is unavailable.",
                                },
                                "notes": {
                                    "type": "string",
                                    "description": "Why this link exists or how the two entities are related.",
                                },
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
                        "description": "Untrusted data types that flow into this file. Set at least one for critical/high files — omitting it on those tiers degrades taint-path scheduling. The 8 values above are the only accepted slot types; auth/crypto/error families are derived from role+language by the backend.",
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
                        "queue_item_id": 42,
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
                        "description": "ID of the claimed code_analysis_queue item this result corresponds to. The backend derives file_id from this queue item.",
                    },
                    "file_id": {
                        "description": "Optional consistency check. When supplied, it must match the file_id on queue_item_id; the backend records the queue-derived file_id.",
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
                    "audit_metadata": {
                        "description": "Arbitrary key/value bag for agent-specific audit context (token counts, tool versions, analysis timestamps). Not used for security decisions; included verbatim in audit logs.",
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
                                "disposition": {
                                    "type": "string",
                                    "enum": ["analyzed", "not_applicable"],
                                    "default": "analyzed",
                                    "description": "Whether this class was analyzed or marked not-applicable for this file. Use not_applicable when the class cannot apply (e.g., buffer-overflow in a pure Python module).",
                                },
                                "not_applicable": {
                                    "type": "boolean",
                                    "default": False,
                                    "description": "Shorthand flag: true means disposition=not_applicable. Backend accepts either form.",
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
                                "file_path": {
                                    "type": "string",
                                    "description": "Repo-relative path to the file that should be re-analyzed (e.g., 'src/url_helpers.c').",
                                },
                                "reason": {
                                    "type": "string",
                                    "description": "Why this file needs re-analysis — name the specific function/callee and the data flow that crosses the boundary.",
                                },
                                "vuln_class": {
                                    "type": "string",
                                    "description": "Vulnerability class to focus on in the downstream file (matches cwe_coverage family names, e.g., 'buffer-overflow').",
                                },
                            },
                        },
                        "default": [],
                        "description": "Files reachable via call graph whose analysis should be (re)triggered based on findings in this file. Only emit when a taint flow actually crosses the file boundary.",
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
            "$id": f"https://vigil.local/schemas/{spec.filename}",
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
