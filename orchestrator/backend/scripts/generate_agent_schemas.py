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
    contract = get_contract("finding record")
    if contract is None:
        raise RuntimeError("finding record contract is required to generate finding examples")

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
        "type": ["string", "array"],
        "items": {"type": "string"},
        "description": "Ordered reproduction steps, starting from initial access state and ending at impact observation. Preferred form is ONE string holding the whole block with your own numbering — renderers emit it verbatim, and prose elsewhere in the submission that cites a step number only resolves against numbers you wrote. A list of strings is also accepted, one action per string.",
    },
    "attack_scenario": {
        "type": "string",
        "description": "Realistic adversary, starting access, and action, ending at first compromise. Renders as the submission's Attack Scenario section; omit when the reproduction already carries the narrative.",
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
    "precondition_analysis": {
        "type": ["string", "object", "array"],
        "description": "Conditions required for exploitation and evidence establishing whether each condition is attacker-reachable.",
    },
    "severity_ceiling": {
        "type": ["string", "object"],
        "description": "Program- or precondition-derived upper bound on severity, including the reason for the cap when structured.",
    },
    "root_cause_candidates": {
        "type": ["array", "object"],
        "description": "Candidate shared causes considered during deduplication or grouping.",
    },
    "notes_provenance": {
        "type": ["string", "array", "object"],
        "description": "Attribution for lifecycle-repair or analysis notes without changing the finding's discovery source.",
    },
    "roe_blocked": {
        "type": "boolean",
        "description": "Set true when the primitive is proved but the program's rules of engagement forbid the final proof step; grade at impact-if-true. Distinct from a provisioning/access wall (see block_reason) and from chain_required (which needs another bug).",
    },
    # Platform taxonomy for an external submission. `export submission` reads
    # these (falling back to `cwe_id` for weakness) and its final gate REQUIRES
    # the platform's own field — VRT for Bugcrowd, weakness for HackerOne — so
    # `details` must accept them or a submission cannot be recorded complete.
    "vrt_category": {
        "type": "string",
        "description": "Bugcrowd VRT category for this finding (e.g. 'broken_access_control.idor'). Overridden by the --vrt-category flag on export.",
    },
    "weakness": {
        "type": "string",
        "description": "HackerOne weakness for this finding (e.g. 'CWE-639 Authorization Bypass Through User-Controlled Key'). Overridden by the --weakness flag on export; falls back to cwe_id.",
    },
    # Code/fuzzing detail keys, recorded by code-fuzz-engineer on a crash finding
    # so the verifier and report-writer can judge reachability without re-running
    # the campaign.
    "crash_input": {
        "type": "string",
        "description": "Path to the minimized crash input that reproduces the fault.",
    },
    "asan_report": {
        "type": "string",
        "description": "ASAN/UBSAN summary line identifying the fault class and location.",
    },
    "attacker_trace": {
        "type": "string",
        "description": "Full byte-to-crash trace: how attacker-controlled input reaches the faulting operation.",
    },
    "caller_feasibility": {
        "type": "string",
        "description": "Which real entry points reach this code path, and under what conditions.",
    },
    "fp_gates": {
        "type": ["object", "array", "string"],
        "description": "Results of every false-positive gate applied to this crash, so a reviewer sees which gates passed rather than a bare verdict.",
    },
    "campaign_id": {
        "type": ["string", "integer"],
        "description": "Identifier of the fuzzing campaign that produced this crash.",
    },
    "fuzzer_confirmation": {
        "type": "boolean",
        "description": "True when a fuzzer reproduced this finding, distinguishing it from a static-only inference.",
    },
    # Reachability of disclosed material in a code engagement: severity follows the
    # access path, so both keys are populated together.
    "attacker_access_path": {
        "type": "string",
        "enum": [
            "public_web_exposure",
            "runtime_file_read_lfi",
            "exposed_build_artifact",
            "repository_or_backup_disclosure",
            "privileged_insider",
            "unknown",
        ],
        "description": "How a real attacker obtains the disclosed bytes. Severity must follow this access path.",
    },
    "exposure_prerequisite": {
        "type": "string",
        "description": "The concrete condition that gives a real attacker the bytes (e.g. 'file is served from a public S3 path', 'confirmed LFI reads this path').",
    },
    "bounded_or_systemic": {
        "type": "string",
        "description": "Whether the observed impact is bounded to one object/tenant or systemic across them. Record the verdict when it is established — it cannot be reconstructed later.",
    },
    "credential_id": {
        "type": ["string", "integer"],
        "description": "Identifier of the captured credential row this finding's PoC depends on, so a chain prerequisite stays traceable.",
    },
    "related_intel_ids": {
        "type": "array",
        "description": "Identifiers of intel rows enriched from this finding's indicators.",
    },
    "disposition": {
        "type": "string",
        "description": "Incident-response disposition in the blue vocabulary, carried for the report-writer.",
    },
    # Incident-response detail keys. Blue role prompts (investigator,
    # alert-triage-specialist) instruct these on every finding they record, and
    # report readiness REQUIRES a non-empty ``mitre_techniques`` for a blue
    # engagement — so ``details`` must accept them or `finding record` rejects the
    # documented blue finding shape outright. Shapes stay permissive because the
    # role prompts define the contents, not this schema.
    "mitre_techniques": {
        "type": "array",
        "items": {"type": "string"},
        "description": "MITRE ATT&CK technique IDs (e.g. 'T1078') this finding maps to. Required on a blue-engagement finding before report readiness passes.",
    },
    "timeline": {
        "type": "array",
        "description": "Ordered incident timeline entries, each a UTC ISO-8601 event citing its `source_file` and `command_run_id` per agent/rules/ir-evidence.md. Appended across investigation rungs, never replaced.",
    },
    "iocs": {
        "type": "array",
        "description": "Indicators of compromise observed for this finding (IP, domain, email, file hash, OAuth client_id, URL). Each one gets an `intel_*` row via `vigil assess intel record`.",
    },
    "confidence": {
        "type": "string",
        "enum": ["low", "medium", "high"],
        "description": "Stated confidence in the finding's disposition, paired with severity_rationale. Single-signal triage is `low` by definition.",
    },
    "severity_rationale": {
        "type": "string",
        "description": "One-line justification for the assigned severity, per the impact-based severity model in agent/rules/triage.md.",
    },
    "block_reason": {
        "type": "string",
        "description": "Why the finding cannot be advanced right now — a provisioning/access wall blocking the next proof step (as opposed to an ROE policy wall or a missing-bug chain park). Surfaced in the resume-brief Attempts ledger.",
    },
    "unblock_requirements": {
        "type": "object",
        "description": "What must be provisioned to lift the block so the finding can be driven to proof. When the unblocker is another finding or chain, link it with `vigil assess finding link <slug> --link-kind unblocked_by ...`.",
        "properties": {
            "kind": {
                "type": "string",
                "description": "Category of what is needed: account | line | device | credential | access.",
            },
            "description": {
                "type": "string",
                "description": "Concretely what to provision (e.g. 'a test account in the org-admin group with role-management entitlement').",
            },
            "requested_from": {
                "type": "string",
                "description": "Who can provide it (e.g. 'program contact', 'target admin').",
            },
        },
    },
    "attempts_summary": {
        "type": "string",
        "description": "One-line summary of what was tried and the result, for the resume-brief Attempts ledger (e.g. 'anonymous + member + billing-admin sessions all 403 at the function gate').",
    },
    "variant_of": {
        "type": "string",
        "description": "Slug of the root finding when this record is a verified same-class variant (e.g. 'sqli-search-q').",
    },
    "original_pattern": {
        "type": "string",
        "description": "Abstract pattern signature copied verbatim from the root finding during variant analysis.",
    },
    "run": {
        "type": "string",
        "description": "One-line reproduction command for the operational overlay (e.g. 'bash scans/va-003-poc.sh'). Surfaced by export submission as the **Run:** header line so a re-render/--overwrite rebuilds it from the finding instead of wiping the operator's hand-applied overlay.",
    },
    "pass_if": {
        "type": "string",
        "description": "Success criterion for the operational overlay (e.g. 'HTTP 200 returns another member's order record'). Surfaced by export submission as the **Pass if:** header line.",
    },
    "replies": {
        "type": "array",
        "description": "Append-only thread of OUTGOING replies to the program on this submitted finding (Bugcrowd comment / HackerOne activity reply / direct follow-up). Written by `vigil assess record-reply` via read-modify-write and re-rendered by `export reply`; never hand-edited (a shallow details merge would clobber the array).",
        "items": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "seq": {
                    "type": "integer",
                    "minimum": 1,
                    "description": "1-based, monotonic reply index. export reply/record-reply pick max(seq)+1 for a new reply.",
                },
                "platform": {
                    "type": "string",
                    "enum": ["bugcrowd", "hackerone", "direct"],
                    "description": "Reply channel: bugcrowd (comment), hackerone (activity reply), or direct (reply email).",
                },
                "in_response_to": {
                    "type": "string",
                    "description": "Verbatim triager ask this reply answers.",
                },
                "reply_to_seq": {
                    "type": ["integer", "null"],
                    "description": "Optional threading pointer to a prior reply seq (default: the last reply).",
                },
                "body": {
                    "type": "string",
                    "description": "Authored reply prose — exactly what is sent. The ONLY pasteable block in the rendered reply.",
                },
                "new_evidence": {
                    "type": "string",
                    "description": "Optional NEW proof authored for THIS reply. Third-party PII partial-masked; self-owned/synthetic shown in full (submission-format.md PII rules).",
                },
                "new_evidence_ref": {
                    "type": "string",
                    "description": "Optional pointer to raw new-evidence (e.g. 'scans/<file>').",
                },
                "sent_status": {
                    "type": "string",
                    "enum": ["draft", "sent"],
                    "description": "Operator-marked send state. 'sent' is set only via `record-reply --sent`, never inferred.",
                },
                "created_at": {
                    "type": "string",
                    "description": "ISO-8601 timestamp stamped when record-reply first created the entry.",
                },
                "sent_at": {
                    "type": ["string", "null"],
                    "description": "ISO-8601 timestamp stamped when `--sent` marked the reply sent; null while a draft.",
                },
                "author": {
                    "type": "string",
                    "description": "Agent/operator that authored the reply (e.g. 'report-writer').",
                },
            },
        },
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
                    "work_item_ids": {
                        "type": "array",
                        "items": {"type": "integer", "minimum": 1},
                        "description": "OVERRIDE the default work-buffer drain. A covering probe carrying coverage_item_id drains its FK-linked work-items by default; pass explicit ids to narrow the drain to exactly these (marked 'done' atomically with the probe). Unknown ids are skipped, not an error.",
                    },
                    "resolve_surface_id": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "OVERRIDE the default surface advance. A covering probe carrying request_variant_id advances its FK-linked discovered surface(s) to 'partially-covered' by default; pass a surface id to advance exactly that one instead.",
                    },
                    "no_drain": {
                        "type": "boolean",
                        "description": "SUPPRESS the default FK-derived cascade (both the work-item drain and the surface advance). The probe is still recorded; the buffer and surfaces are left untouched.",
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
                        "description": "Lifecycle state settable at record time. New findings: 'active'. Post-exploitation confirmed: 'exploited'. WAF/control stopped testing: 'blocked'. Duplicate absorbed into another record: 'merged'. Delivered to client: 'reported'. NOTE: the blue-team/IR states (contained, eradicated, recovered) are intentionally NOT recordable here — they are applied only via `vigil assess finding update`, so this finding record enum is deliberately narrower than the full WorkflowStatus vocabulary.",
                        "enum": ["draft", "active", "exploited", "blocked", "false_positive", "merged", "reported"],
                    },
                    "verification_state": {
                        "description": "Human review state. Leave 'unreviewed' when first recording; set 'verified' after confirming exploitability; 'disputed' when contested.",
                        "enum": ["unreviewed", "verified", "disputed"],
                    },
                    "verification_disposition": {
                        "description": "Verifier outcome (stored field). 'none': not yet checked. 'pending_runtime_proof': needs live PoC. 'blocked': the attempt could not even start (missing provisioning); requires details.block_reason and is held OUT of the report. 'confirmed': exploitability proven. 'downgraded': real but severity reduced. 'false_positive': not exploitable. NOTE: `vigil assess finding verify --disposition` additionally accepts 'disputed', which is a verify ACTION that sets verification_state='disputed' and leaves this field at 'none' — 'disputed' is never persisted as a disposition, so it is intentionally absent from this stored enum.",
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
                        "maxLength": 4096,
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
                    "request_variant_id": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "ID of the request variant this finding concerns. Recorded as a finding_link to that request-variant surface, not stored as a finding column. Omit when the finding is not tied to a specific request variant.",
                    },
                    "service_id": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "ID of the service this finding concerns. Recorded as a finding_link to that service surface, not stored as a finding column. Omit when the finding is not tied to a specific service.",
                    },
                    "surface_id": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "ID of the attack surface this finding concerns. Recorded as a finding_link to that surface, not stored as a finding column. Omit when the finding is not tied to a specific surface.",
                    },
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
                        "lease_token": "lease-7f6c0d12",
                        "function_name": "parseurl",
                        "hypothesis": "Attacker-controlled URL scheme length passed to memcpy without bounds check",
                        "evidence": "In parseurl() at line 342, schemelen is derived from user-supplied URL without validation. memcpy(buf, scheme, schemelen) copies attacker-controlled bytes into fixed-size heap buffer.",
                        "evidence_ref": "tools/analysis-state/code-evidence/parseurl-taint.txt",
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
                    "evidence_ref": {
                        "description": "Optional engagement-owned artifact path supporting the disposition. A finding or suspicious closeout requires non-empty inline evidence or this artifact reference on a current result for the active lease.",
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
