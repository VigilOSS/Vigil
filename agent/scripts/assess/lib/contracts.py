"""Stable CLI contract metadata for helper-owned assessment commands."""
from __future__ import annotations

from dataclasses import dataclass
import json
import re
from typing import Any

from .schema_validation import load_schema


@dataclass(frozen=True)
class CommandContract:
    name: str
    summary: str
    schema_name: str
    preferred_invocations: tuple[str, ...]
    author_supplied_fields: tuple[str, ...]
    helper_defaults: tuple[tuple[str, str], ...] = ()
    notes: tuple[str, ...] = ()
    common_mistakes: tuple[tuple[str, str], ...] = ()
    examples: tuple[dict[str, Any], ...] = ()


_CONTRACTS: dict[str, CommandContract] = {
    "record-finding": CommandContract(
        name="record-finding",
        summary="Create or upsert a finding through helper-normalized lifecycle defaults.",
        schema_name="finding-record.schema.json",
        preferred_invocations=(
            "assess.py record-finding <agent-name> <finding-json-file>",
        ),
        author_supplied_fields=(
            "title",
            "details.evidence",
            "details.impact",
        ),
        helper_defaults=(
            ("slug", "allocated from the engagement-local finding sequence when omitted"),
            ("source_name", "<agent-name>"),
            ("severity", "medium"),
            ("workflow_status", "active"),
            ("verification_state", "unreviewed"),
            ("verification_disposition", "none"),
            ("defect_family", "title when omitted"),
            ("root_cause_key", '""'),
            ("auth_context", "anonymous"),
            ("canonical_location", '""'),
            ("summary", "title when omitted"),
            ("evidence_ref", '""'),
            ("notes", '""'),
            ("details.discovered_by", "<agent-name>"),
            ("provenance.agent_name", "<agent-name>"),
            ("provenance.artifact", "findings.md"),
            ("links", "[]"),
        ),
        notes=(
            "Do not guess top-level lifecycle fields from memory. Omit them unless you are intentionally overriding the helper defaults.",
            "Code-specific evidence fields such as details.taint_path, details.guards_evaluated, details.slot_type, details.variant_of, and details.original_pattern are valid finding details.",
        ),
        common_mistakes=(
            ("status", "use workflow_status for lifecycle overrides, or omit it and keep the helper default"),
            ("confidence", "confidence belongs in code-record-analysis output, not finding records"),
            ("cwe", "use details.cwe_id"),
            ("cwe_id", "use details.cwe_id when storing CWE metadata"),
            ("description", "use summary for the short finding statement or notes for replayable proof"),
            ("evidence", "use details.evidence"),
            ("impact", "use details.impact"),
        ),
        examples=(
            {
                "title": "Blind SQL injection in search",
                "severity": "high",
                "defect_family": "sql-injection",
                "canonical_location": "https://target.example/search?q",
                "summary": "Boolean-blind SQL injection on the search endpoint",
                "evidence_ref": "scans/sqlmap.txt",
                "notes": "curl 'https://target.example/search?q=test%27+AND+1%3D1--+-' -> 200 with results",
                "details": {
                    "owasp_category": "A03:2021 Injection",
                    "cwe_id": "CWE-89",
                    "request_method": "GET",
                    "parameter": "q",
                    "evidence": "Replayable request/response pair in scans/sqlmap.txt",
                    "impact": "Anonymous attackers can extract arbitrary data from the backing store",
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    "cvss_score": 7.5,
                    "remediation": "Use parameterized queries for all search input",
                    "steps_to_reproduce": [
                        "Send GET /search?q=test'+AND+1=1--+-",
                        "Observe normal search results returned",
                    ],
                },
            },
            {
                "title": "Heap buffer overflow in URL parser via overlong scheme",
                "severity": "high",
                "defect_family": "buffer-overflow",
                "canonical_location": "file:lib/urlapi.c:342",
                "summary": "Attacker-controlled URL scheme exceeding 64 bytes overflows heap buffer in parseurl()",
                "details": {
                    "cwe_id": "CWE-122",
                    "impact": "Remote code execution via heap corruption",
                    "evidence": "memcpy(buf, scheme, schemelen) copies attacker-controlled bytes without a bounds check",
                    "taint_path": "curl_url_set(CURLURLPART_URL, attacker_url) -> parseurl() -> memcpy(buf, scheme, schemelen)",
                    "guards_evaluated": "No bounds check on schemelen before memcpy",
                    "slot_type": "URL-COMPONENT",
                },
            },
        ),
    ),
    "verify-finding": CommandContract(
        name="verify-finding",
        summary="Apply a verification transition to an existing finding through the audit ledger.",
        schema_name="backend FindingVerifyRequest",
        preferred_invocations=(
            "assess.py verify-finding <slug> <verification-json>",
            'assess.py verify-finding <slug> --disposition downgraded --reason "..." --new-severity low',
        ),
        author_supplied_fields=(
            "disposition",
            "reason_text",
        ),
        notes=(
            "Use this for confirmed, downgraded, and disputed verification outcomes.",
            "For false_positive decisions, you can use this command with details.kill_reason/details.kill_check, or use kill-finding for the shorter helper flow.",
        ),
        common_mistakes=(
            ("rationale", "use reason_text"),
            ("status", "verification is a transition, not a raw status patch"),
        ),
        examples=(
            {
                "disposition": "confirmed",
                "reason_text": "Reproduced as written.",
            },
            {
                "disposition": "downgraded",
                "reason_text": "Impact is lower after retest.",
                "new_severity": "low",
            },
        ),
    ),
    "kill-finding": CommandContract(
        name="kill-finding",
        summary="Persist a false_positive verification with the required kill metadata.",
        schema_name="backend FindingVerifyRequest (false_positive)",
        preferred_invocations=(
            'assess.py kill-finding <slug> --reason "..." --kill-reason "..." --kill-check <1-5>',
        ),
        author_supplied_fields=(
            "reason_text",
            "details.kill_reason",
            "details.kill_check",
        ),
        notes=(
            "Use this when you already have the kill rationale and do not need a custom JSON payload file.",
        ),
        common_mistakes=(
            ("rationale", "use reason_text"),
            ("status", "false-positive lifecycle changes belong in kill-finding, not raw patch"),
        ),
        examples=(
            {
                "disposition": "false_positive",
                "reason_text": "Guard blocks the path.",
                "details": {
                    "kill_reason": "validate_length() enforces an 8KB cap",
                    "kill_check": 2,
                },
            },
        ),
    ),
    "update-finding": CommandContract(
        name="update-finding",
        summary="Patch non-verification finding fields on an existing slug.",
        schema_name="backend FindingPatchRequest",
        preferred_invocations=(
            "assess.py update-finding <slug> <patch-json-file>",
            'assess.py update-finding <slug> --status reported --reason "Published in report"',
        ),
        author_supplied_fields=(
            "at least one patch field",
        ),
        notes=(
            "Use this for workflow and metadata updates that are not verification lifecycle transitions.",
            "Use reset-finding when you are reopening a previously verified or false-positive finding for re-triage.",
            "Verification disposition changes, disputed reviews, and false_positive kills belong in verify-finding or kill-finding.",
        ),
        common_mistakes=(
            ("verification_state", "use verify-finding or kill-finding for verification lifecycle changes"),
            ("verification_disposition", "use verify-finding or kill-finding for verification lifecycle changes"),
            ("workflow_status=false_positive", "use kill-finding instead of update-finding"),
        ),
        examples=(
            {
                "workflow_status": "reported",
                "reason_text": "Published in report.",
            },
            {
                "severity": "low",
                "summary": "Retest reduced the confirmed impact.",
            },
        ),
    ),
    "reset-finding": CommandContract(
        name="reset-finding",
        summary="Reopen a previously verified or false-positive finding for re-triage.",
        schema_name="backend FindingPatchRequest (reopen)",
        preferred_invocations=(
            'assess.py reset-finding <slug> --reason "..." --status draft',
            'assess.py reset-finding <slug> --reason "Retest disproved the kill" --status active',
        ),
        author_supplied_fields=(
            "reason_text",
            "workflow_status",
        ),
        notes=(
            "Use this when new evidence means a verified or false-positive finding should return to the active workflow.",
            "The backend resets verification_state to unreviewed and verification_disposition to none when a false-positive finding is reopened.",
        ),
        common_mistakes=(
            ("verification_state", "reopening is a reset-finding transition, not a manual verification_state patch"),
            ("verification_disposition", "reopening is a reset-finding transition, not a manual verification_disposition patch"),
            ("workflow_status=false_positive", "false_positive is a verification outcome; use kill-finding instead"),
        ),
        examples=(
            {
                "workflow_status": "draft",
                "reason_text": "Retest disproved the earlier kill.",
                "reason_code": "retriage",
            },
        ),
    ),
}


_RAW_ENDPOINT_RULES = (
    (
        "POST",
        re.compile(r"^findings$"),
        "record-finding",
        (
            "Raw POST to findings is disabled because record-finding owns slug allocation and lifecycle defaults.",
        ),
    ),
    (
        "POST",
        re.compile(r"^findings/[^/]+/verify$"),
        "verify-finding",
        (
            "Raw POST to findings/{slug}/verify is disabled because verify-finding and kill-finding own the verification lifecycle.",
            "Use kill-finding when the disposition is false_positive and you want the helper-enforced kill fields.",
        ),
    ),
    (
        "PATCH",
        re.compile(r"^findings/[^/]+$"),
        "update-finding",
        (
            "Raw PATCH to findings/{slug} is disabled because update-finding owns finding patch operations.",
        ),
    ),
)


def contract_names() -> list[str]:
    return sorted(_CONTRACTS)


def get_contract(name: str) -> CommandContract | None:
    return _CONTRACTS.get(name)


def render_contract(name: str) -> str:
    contract = get_contract(name)
    if contract is None:
        available = ", ".join(contract_names())
        raise ValueError(f"Unknown contract '{name}'. Available contracts: {available}")

    lines = [
        f"Command: {contract.name}",
        f"Summary: {contract.summary}",
        f"Schema: {contract.schema_name}",
        "",
        "Preferred invocation:",
    ]
    lines.extend(f"  - {entry}" for entry in contract.preferred_invocations)
    lines.extend(
        [
            "",
            "Author-supplied fields:",
        ]
    )
    lines.extend(f"  - {entry}" for entry in contract.author_supplied_fields)

    if contract.helper_defaults:
        lines.extend(
            [
                "",
                "Helper defaults:",
            ]
        )
        lines.extend(f"  - {key} = {value}" for key, value in contract.helper_defaults)

    schema_properties = _schema_property_names(contract.schema_name)
    if schema_properties:
        lines.extend(
            [
                "",
                "Allowed top-level fields:",
            ]
        )
        lines.extend(f"  - {entry}" for entry in schema_properties)

    if contract.common_mistakes:
        lines.extend(
            [
                "",
                "Common mistakes:",
            ]
        )
        lines.extend(f"  - {wrong} -> {fix}" for wrong, fix in contract.common_mistakes)

    if contract.notes:
        lines.extend(
            [
                "",
                "Notes:",
            ]
        )
        lines.extend(f"  - {entry}" for entry in contract.notes)

    if contract.examples:
        lines.extend(
            [
                "",
                "Examples:",
            ]
        )
        for example in contract.examples:
            lines.append(json.dumps(example, indent=2, ensure_ascii=False))

    return "\n".join(lines)


def raw_endpoint_error(method: str, endpoint: str, payload: Any | None = None) -> str | None:
    normalized_method = method.upper()
    normalized_endpoint = endpoint.strip("/")
    for candidate_method, pattern, contract_name, extra_notes in _RAW_ENDPOINT_RULES:
        if normalized_method != candidate_method:
            continue
        if not pattern.match(normalized_endpoint):
            continue
        contract = get_contract(contract_name)
        assert contract is not None
        lines = [*extra_notes]
        if normalized_method == "PATCH" and contract_name == "update-finding" and _looks_like_verification_payload(payload):
            lines = [
                "Raw PATCH to findings/{slug} is disabled because verification lifecycle changes must use verify-finding or kill-finding.",
                "Use update-finding only for non-verification metadata or workflow changes such as draft/reported.",
            ]
        elif normalized_method == "PATCH" and contract_name == "update-finding":
            lines = [
                "Raw PATCH to findings/{slug} is disabled because helper-owned finding lifecycle changes should use the dedicated commands.",
                "Use update-finding for non-verification metadata or workflow changes, and use reset-finding when reopening a previously verified or false-positive finding.",
            ]
        lines.append("")
        lines.append("Use instead:")
        if normalized_method == "POST" and normalized_endpoint.endswith("/verify"):
            lines.append(f"  - {contract.preferred_invocations[0]}")
            kill_contract = get_contract("kill-finding")
            assert kill_contract is not None
            lines.append(f"  - {kill_contract.preferred_invocations[0]}")
            lines.append("  - assess.py contract verify-finding")
        else:
            lines.append(f"  - {contract.preferred_invocations[0]}")
            if normalized_method == "PATCH" and contract_name == "update-finding":
                reset_contract = get_contract("reset-finding")
                assert reset_contract is not None
                lines.append(f"  - {reset_contract.preferred_invocations[0]}")
            lines.append(f"  - assess.py contract {contract.name}")
            if normalized_method == "PATCH" and contract_name == "update-finding":
                lines.append("  - assess.py contract reset-finding")
        return "\n".join(lines)
    return None


def common_mistake_hints(name: str, payload: dict[str, Any]) -> list[str]:
    contract = get_contract(name)
    if contract is None:
        return []

    hints: list[str] = []
    for wrong, fix in contract.common_mistakes:
        if wrong.startswith("workflow_status="):
            field_name, _, field_value = wrong.partition("=")
            if payload.get(field_name) == field_value:
                hints.append(f"{field_name}={field_value} -> {fix}")
            continue
        if wrong in payload:
            hints.append(f"{wrong} -> {fix}")
    return hints


def _schema_property_names(schema_name: str) -> list[str]:
    if not schema_name.endswith(".schema.json"):
        return []
    schema = load_schema(schema_name)
    properties = schema.get("properties", {})
    if not isinstance(properties, dict):
        return []
    return sorted(str(name) for name in properties)


def _looks_like_verification_payload(payload: Any | None) -> bool:
    if not isinstance(payload, dict):
        return False
    verification_keys = {"verification_state", "verification_disposition"}
    if verification_keys.intersection(payload):
        return True
    return payload.get("workflow_status") == "false_positive"
