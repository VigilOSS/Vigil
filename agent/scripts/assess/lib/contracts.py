"""Stable CLI contract metadata for helper-owned assessment commands."""
from __future__ import annotations

from dataclasses import dataclass, field
import json
import re
from typing import Any

from .intel_types import INTEL_TYPES
from .schema_validation import load_schema


SPECIALIST_DISPATCH_MODES: tuple[str, ...] = (
    "hypothesis-driven",
    "item-iterating",
    "deep-manual",
    "variant-rotation",
)


_SPECIALIST_DISPATCH_REQUIRED_FIELDS: tuple[str, ...] = (
    "role",
    "dispatch_mode",
)


@dataclass
class SpecialistDispatchContract:
    """Mirror of the operator-core "Specialist Dispatch Contract" required-fields list.

    Every field on this dataclass corresponds to a row in the contract table
    documented in ``agent/operator-core.md`` (Specialist Dispatch Contract).
    Use ``validate_specialist_dispatch_contract`` to check a JSON payload
    parsed from disk or stdin — the validator returns a list of error strings.
    """

    role: str
    dispatch_mode: str
    model: str | None = None
    reasoning: str | None = None
    extras: dict[str, Any] = field(default_factory=dict)


def validate_specialist_dispatch_contract(payload: Any) -> tuple[list[str], list[str]]:
    """Validate a parsed specialist dispatch payload.

    Returns ``(errors, warnings)``.
    """
    errors: list[str] = []
    warnings: list[str] = []

    if not isinstance(payload, dict):
        return ["dispatch contract must be a JSON object"], warnings

    for field_name in _SPECIALIST_DISPATCH_REQUIRED_FIELDS:
        if field_name not in payload:
            errors.append(f"missing required field: {field_name}")

    dispatch_mode = payload.get("dispatch_mode")
    if dispatch_mode is not None and dispatch_mode not in SPECIALIST_DISPATCH_MODES:
        errors.append(
            f"dispatch_mode '{dispatch_mode}' is not allowed; "
            f"valid: {', '.join(SPECIALIST_DISPATCH_MODES)}"
        )

    for str_field in ("role",):
        value = payload.get(str_field)
        if value is not None and not isinstance(value, str):
            errors.append(f"{str_field} must be a string")
        elif value is not None and not str(value).strip():
            errors.append(f"{str_field} must be a non-empty string")

    return errors, warnings


# Verbs registered under `aith assess kali ...`. Names are kept in sync with
# the modules under `agent/scripts/assess/commands/kali_*.py`.
KALI_VERBS: tuple[str, ...] = (
    "nmap-scan",
    "nuclei",
    "httpx",
    "wafw00f",
    "ffuf",
    "sqlmap",
    "subfinder",
    "puredns",
    "dnsx",
    "nikto",
    "katana",
    "gau",
    "whatweb",
    "cero",
    "alterx",
    "asnmap",
    "bbot",
    "exec",
    "job",
    "sweep-orphans",
)


_KALI_COMMON_NOTES: tuple[str, ...] = (
    "Every kali verb requires --technique, --intent, --probe-kind, --phase, and --timeout. The CLI rejects calls missing any of these before it ever reaches the backend.",
    "--technique must be one of TECHNIQUE_ENUM; use HEALTH for runtime/tool inventory, META for operator-side metadata, LOG-READ for artifact reads, and OTHER only when no specific class fits.",
    "--agent-name resolves from the explicit flag, $AGENT_NAME, $AITH_AGENT_NAME, then operator. Specialists must ensure AGENT_NAME is exported by their wrapper or pass --agent-name <role> explicitly.",
    "--phase is REQUIRED — pass the phase the dispatch was authorized for, not scope.json.current_phase. Allowed: recon, collect, consume-test, verify, exploit, report, code-ingest, code-classify, code-hunt, code-verify, plus the half-phase tags recon-pivot and exploit-recon.",
    "--destructive marks a write/edit/delete on the target (POST/PUT/PATCH/DELETE, file upload, account creation). Read-only probes leave it off.",
    "--force bypasses the dedup window. Use only when re-running an identical command intentionally is the right call.",
    "--extra-args \"<string>\" is an optional raw-passthrough on every typed verb. The string is shlex-split and appended to the underlying tool argv after the typed-flag-derived args. Use sparingly for long-tail flags the typed verb does not model — the audit row still records the full final argv. --destructive still applies when extra args toggle a destructive mode.",
)


_KALI_COMMON_MISTAKES: tuple[tuple[str, str], ...] = (
    ("missing --phase", "always pass --phase explicitly; no env-var fallback exists"),
    ("technique=recon", "uppercase the audit technique tag (RECON, SSRF, SQLI, ...)"),
    ("intent>200 chars", "intent is trimmed to 200 chars; keep it as a one-line purpose"),
    ("--via-mcp", "MCP path is removed in Wave 1 — `aith assess kali` is the only path"),
)


def _kali_invocation(verb: str) -> tuple[str, ...]:
    if verb == "exec":
        return (
            "aith assess kali exec --technique <enum> --intent \"<one-liner>\" "
            "--probe-kind <kind> --phase <phase> --timeout 1800 -- <command...>",
        )
    return (
        f"aith assess kali {verb} --technique <enum> --intent \"<one-liner>\" "
        f"--probe-kind <kind> --phase <phase> --timeout 1800 [verb-flags]",
    )


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
    "record-intel": CommandContract(
        name="record-intel",
        summary="Record structured intelligence through the helper-owned intel schemas.",
        schema_name="type-specific intel schema",
        preferred_invocations=(
            "aith assess record-intel <type> <intel-json-file>",
            "aith assess contract record-intel <type>",
        ),
        author_supplied_fields=(
            "type-specific required fields",
            "source_name",
            "evidence_ref or provenance when available",
        ),
        notes=(
            "Use a type-specific contract before authoring JSON. Intel schemas are strict (`additionalProperties=false`), so guessed aliases such as `source` fail validation when the contract says `source_name`.",
            "Valid intel types: " + ", ".join(sorted(INTEL_TYPES)),
        ),
        common_mistakes=(
            ("source", "use source_name"),
            ("agent", "use source_name or provenance.agent_name"),
        ),
        examples=(
            {
                "component": "nginx",
                "version": "1.24.0",
                "source_name": "osint-analyst",
                "confidence": "medium",
                "evidence_ref": "scans/whatweb.txt:12",
            },
        ),
    ),
    "record-finding": CommandContract(
        name="record-finding",
        summary="Create or upsert a finding through helper-normalized lifecycle defaults.",
        schema_name="finding-record.schema.json",
        preferred_invocations=(
            "aith assess record-finding <agent-name> <finding-json-file>",
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
            ("provenance.artifact", ""),
            ("links", "[]"),
        ),
        notes=(
            "Do not guess top-level lifecycle fields from memory. Omit them unless you are intentionally overriding the helper defaults. The CLI fills workflow_status, verification_state, verification_disposition, and provenance automatically — supply only the fields shown in the examples.",
            "Code-specific evidence fields such as details.entry_point, details.sink, details.taint_path, details.guards_evaluated, details.slot_type, details.variant_of, and details.original_pattern are valid finding details.",
            "Use details.poc_code for exploit scripts, or details.poc_request / details.poc_response for structured HTTP request/response pairs that demonstrate the vulnerability.",
            "Use details.references for CVE links, advisory URLs, or related documentation (array of strings).",
            "Use details.chain_required/details.chain_rationale/details.required_followup when the finding is concrete and worth tracking, but only becomes exploitation-worthy as part of a larger chain. Specialists set or refine these fields through record-finding or update-finding; verification reviews them but does not own them.",
        ),
        common_mistakes=(
            ("status", "use workflow_status for lifecycle overrides, or omit it and keep the helper default"),
            ("confidence", "confidence belongs in code-record-analysis output, not finding records"),
            ("cwe", "use details.cwe_id"),
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
                    "poc_request": {
                        "method": "GET",
                        "url": "https://target.example/search?q=test'+AND+1=1--+-",
                        "headers": {"Accept": "text/html"},
                        "body": "",
                    },
                    "poc_response": {
                        "status": 200,
                        "headers": {"Content-Type": "text/html"},
                        "body_excerpt": "<div class='results'>3 items found</div>",
                    },
                    "chain_required": False,
                    "references": ["https://cwe.mitre.org/data/definitions/89.html"],
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
                    "entry_point": "curl_url_set(CURLURLPART_URL, attacker_url)",
                    "sink": "memcpy(buf, scheme, schemelen) at lib/urlapi.c:342",
                    "taint_path": "curl_url_set(CURLURLPART_URL, attacker_url) -> parseurl() -> memcpy(buf, scheme, schemelen)",
                    "guards_evaluated": "No bounds check on schemelen before memcpy",
                    "slot_type": "URL-COMPONENT",
                    "chain_required": True,
                    "chain_rationale": "The primitive is meaningful for exploitation, but final report impact depends on chaining it to a reachable crash or controlled allocation path.",
                    "required_followup": [
                        "Exercise the URL parser through a network-reachable caller",
                        "Confirm whether the overflow produces controlled corruption under sanitizer instrumentation",
                    ],
                    "references": ["https://cwe.mitre.org/data/definitions/122.html"],
                },
            },
        ),
    ),
    "verify-finding": CommandContract(
        name="verify-finding",
        summary="Apply a verification transition to an existing finding through the audit ledger.",
        schema_name="backend FindingVerifyRequest",
        preferred_invocations=(
            "aith assess verify-finding <slug> <verification-json>",
            'aith assess verify-finding <slug> --disposition downgraded --reason "..." --new-severity low',
            'aith assess verify-finding <slug> --disposition false_positive --reason "..." --kill-reason "..." --kill-check 2',
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
            'aith assess kill-finding <slug> --reason "..." --kill-reason "..." --kill-check <1-5>',
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
            "aith assess update-finding <slug> <patch-json-file>",
            'aith assess update-finding <slug> --status reported --reason "Published in report"',
            'aith assess update-finding <slug> --inline \'{"workflow_status":"draft","reason_text":"Needs more evidence"}\'',
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
            'aith assess reset-finding <slug> --reason "..." --status draft',
            'aith assess reset-finding <slug> --reason "Retest disproved the kill" --status active',
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
    "resolve-surface": CommandContract(
        name="resolve-surface",
        summary="PATCH an assessment surface by id (set status + rationale).",
        schema_name="backend SurfaceUpdateRequest",
        preferred_invocations=(
            'aith assess resolve-surface <id> --status covered --rationale "..."',
            'aith assess resolve-surface <id> --status not_applicable --rationale "..."',
            'aith assess resolve-surface <id> --status deferred --rationale "..."',
            'aith assess resolve-surface <id> --status partially-covered --rationale "..." --followup-condition "..."',
        ),
        author_supplied_fields=(
            "status",
            "rationale",
            "followup_condition",
        ),
        notes=(
            "Use this to resolve a discovered surface after triage instead of falling back to direct SQL.",
            "Rationale is appended to existing rationale so the audit trail accumulates context across resolutions.",
            "--followup-condition is REQUIRED when --status=partially-covered; it captures the one-line condition the follow-up coverage pass must satisfy.",
        ),
        common_mistakes=(
            ("status=discovered", "discovered is the seed state; resolve to covered, not_applicable, deferred, or partially-covered"),
            ("reason", "use --rationale for the resolution explanation"),
            ("status=partially-covered without --followup-condition", "the follow-up condition is mandatory for partially-covered so the audit trail names what the next pass must satisfy"),
        ),
        examples=(
            {
                "status": "covered",
                "rationale": "vulnerability-analyst confirmed coverage on parameter q",
            },
            {
                "status": "not_applicable",
                "rationale": "static asset, no input vector",
            },
            {
                "status": "partially-covered",
                "rationale": "unauth path tested; admin path requires auth",
                "followup_condition": "needs auth re-test once credentials are issued",
            },
        ),
    ),
    "update-intel": CommandContract(
        name="update-intel",
        summary="PATCH an existing intel row by id without inserting a new history record.",
        schema_name="backend IntelUpdateRequest (per-type updatable column whitelist)",
        preferred_invocations=(
            "aith assess update-intel <type> <id> <patch.json>",
            "aith assess update-intel <type> <id> --inline '{...}'",
        ),
        author_supplied_fields=(
            "at least one updatable column",
        ),
        notes=(
            "Use update-intel for in-place metadata edits. Use supersede-intel when you want to retain the prior row for audit and insert a wholly new record.",
            "The backend rejects fields outside the per-type updatable column whitelist so guessed aliases surface immediately.",
        ),
        common_mistakes=(
            ("source", "use source_name"),
            ("agent", "use source_name or provenance.agent_name"),
        ),
        examples=(
            {"validation_status": "exploited"},
            {"notes": "Confirmed working PoC against staging"},
        ),
    ),
    "supersede-intel": CommandContract(
        name="supersede-intel",
        summary="Insert a replacement intel row; old row stays for audit but is filtered from reports.",
        schema_name="type-specific intel schema for the new payload",
        preferred_invocations=(
            'aith assess supersede-intel <type> <id> <new.json> --rationale "..."',
            'aith assess supersede-intel <type> <id> --inline \'{...}\' --rationale "..."',
        ),
        author_supplied_fields=(
            "type-specific natural-key fields for the new replacement record",
            "--rationale (free text)",
        ),
        notes=(
            "Use this when an intel row was wrong but the operator wants to retain the prior observation for audit.",
            "Metadata-only edits belong to update-intel; supersede-intel requires the replacement row's natural key before making the backend request.",
            "Report-writer filters on superseded_by_id IS NULL so superseded rows do not appear in reports, but stay queryable for cascade-delete and audit.",
        ),
        common_mistakes=(
            ("source", "use source_name"),
            ("rationale-collision", "if the new natural key matches the existing row, use update-intel instead"),
        ),
        examples=(
            {
                "component": "nginx",
                "version": "1.27.0",
                "source_name": "vulnerability-analyst",
                "confidence": "confirmed",
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
    names = list(_CONTRACTS)
    names.extend(f"record-intel {intel_type}" for intel_type in sorted(INTEL_TYPES))
    names.append("kali")
    names.extend(f"kali {verb}" for verb in KALI_VERBS)
    names.append("dispatch")
    names.extend(f"dispatch {verb}" for verb in DISPATCH_VERBS)
    return sorted(names)


def get_contract(name: str) -> CommandContract | None:
    if name.startswith("record-intel "):
        _, _, intel_type = name.partition(" ")
        return _record_intel_contract(intel_type)
    if name == "kali":
        return _kali_root_contract()
    if name.startswith("kali "):
        _, _, verb = name.partition(" ")
        return _kali_verb_contract(verb)
    if name == "dispatch":
        return _dispatch_root_contract()
    if name.startswith("dispatch "):
        _, _, verb = name.partition(" ")
        return _dispatch_verb_contract(verb)
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

    schema_required = _schema_required_names(contract.schema_name)
    if schema_required:
        lines.extend(
            [
                "",
                "Required top-level fields:",
            ]
        )
        lines.extend(f"  - {entry}" for entry in schema_required)

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


def render_contract_epilog(name: str) -> str:
    contract = get_contract(name)
    if contract is None:
        available = ", ".join(contract_names())
        raise ValueError(f"Unknown contract '{name}'. Available contracts: {available}")

    lines = ["Examples:"]
    lines.extend(f"  {entry}" for entry in contract.preferred_invocations)
    lines.extend(
        [
            "",
            "See also:",
            f"  aith assess contract {contract.name}",
        ]
    )
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
            lines.append("  - aith assess contract verify-finding")
        else:
            lines.append(f"  - {contract.preferred_invocations[0]}")
            if normalized_method == "PATCH" and contract_name == "update-finding":
                reset_contract = get_contract("reset-finding")
                assert reset_contract is not None
                lines.append(f"  - {reset_contract.preferred_invocations[0]}")
            lines.append(f"  - aith assess contract {contract.name}")
            if normalized_method == "PATCH" and contract_name == "update-finding":
                lines.append("  - aith assess contract reset-finding")
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


def _schema_required_names(schema_name: str) -> list[str]:
    if not schema_name.endswith(".schema.json"):
        return []
    schema = load_schema(schema_name)
    required = schema.get("required", [])
    if not isinstance(required, list):
        return []
    return sorted(str(name) for name in required)


_KALI_VERB_NOTES: dict[str, tuple[str, ...]] = {
    "nmap-scan": (
        "Top-1000 ports is the default; use --ports full for `-p-`, or pass an explicit list (e.g. 22,80,443).",
        "--scripts default,vuln triggers heavy NSE — set a high --timeout (1800+) or dispatch via `aith assess kali job start`.",
    ),
    "nuclei": (
        "Pass either -u or -l. Severity filters and `-as` (automatic) shape the run.",
        "Long sweeps belong in `aith assess kali job start nuclei ...`.",
    ),
    "sqlmap": (
        "sqlmap's own `--technique` is exposed as `--sql-technique` so it doesn't collide with the audit `--technique` flag.",
    ),
    "cero": (
        "TLS-handshake SAN scraper — connects to TCP/TLS on the listed ports and harvests certificate Subject Alternative Names. Complements CT-log enumeration when targets issue private certs.",
        "Feed CIDR ranges (after asnmap CIDR mapping) for non-DNS subdomain discovery. Pass --only-cidrs when the input is exclusively CIDR.",
        "Default ports are 443,8443; add 9443/8444/etc. via -p when the target advertises additional TLS endpoints.",
        "Read-only TCP/TLS handshakes — leave --destructive off.",
    ),
    "alterx": (
        "Subdomain permutation generator — takes known subdomains and emits permutation candidates for downstream resolution. Pair with `kali puredns resolve` so the permutation list is wildcard-filtered before DNS spend.",
        "Default invocation uses alterx built-in patterns; pass -p '{{sub}}-{{word}}.{{suffix}}' (repeatable) only when the engagement justifies a custom pattern.",
        "Output is a stream of candidate FQDNs; pipe to puredns or write to file via -o.",
    ),
    "asnmap": (
        "ASN/domain/org to CIDR mapper. Use it to feed owned CIDR ranges into `cero` for TLS SAN discovery that CT logs miss.",
        "Pass at least one of -d, -l, -asn, or -org. The wrapper rejects empty invocations before running the tool.",
    ),
    "bbot": (
        "Multi-module recon scanner. Canonical passive subdomain invocation: `bbot -t <target> -p subdomain-enum -rf passive`. Add modules with -m or presets with -p; gate active modules behind --allow-deadly + --destructive.",
        "--allow-deadly requires --destructive — bbot's deadly modules perform real attacks (fuzzing, brute-force, exploit). The CLI hard-fails if --allow-deadly is passed without --destructive so the audit row stays truthful.",
        "Long passive sweeps (`-p subdomain-enum`) regularly run 15-30 minutes — set --timeout 1800 or wrap in `kali job start`.",
    ),
    "exec": (
        "Use only when no typed verb fits. Tool-name attribution falls back to argv[0] for audit recording.",
    ),
    "job": (
        "Long-running probes go through `aith assess kali job start ...`. The dtach session is parented by tini so it survives the calling shell.",
        "Subcommands: start | status | tail | stop | list.",
    ),
    "sweep-orphans": (
        "Host-side reconciler for `assessment_command_runs` rows stuck in status=running past --max-age-seconds. Run after a backend restart, host crash, or any window where finalize PATCHes may have failed.",
        "Liveness probe is `docker exec <container> kill -0 <pid>` against the wrapper-recorded pid file at /tmp/aith-pid-<run_uuid>.pid. The run_uuid comes from the row's run_uuid column, with stdout_path parsing kept only for older rows.",
        "Rows whose PID is alive are left alone (still-running). Rows whose PID is dead OR whose pid file is missing are finalized to status=lost via PATCH command-runs/{id}.",
        "Rows are skipped when Docker probing itself fails, because the command cannot distinguish a live job from an unavailable liveness check.",
        "Use --dry-run first to inspect candidates without writing — a thorough sweep is cheap, an incorrect finalize is not.",
        "Unlike target-facing verbs, sweep-orphans does not take --technique/--intent/--probe-kind/--phase/--timeout — it is a maintenance command, not a probe.",
    ),
}


_KALI_VERB_EXAMPLES: dict[str, tuple[dict[str, Any], ...]] = {
    "nmap-scan": (
        {
            "command": "aith assess kali nmap-scan --target example.com --ports top-1000 --service-detection --technique RECON --intent 'Phase 1 baseline port + service' --probe-kind fingerprint --phase recon --timeout 1800",
        },
    ),
    "nuclei": (
        {
            "command": "aith assess kali nuclei -l hosts.txt -t http/cves/ -severity high,critical -rate-limit 50 -c 25 -bs 25 -jsonl -o scans/nuclei.jsonl --technique RECON --intent 'reactive sweep on Phase-1 URL delta' --probe-kind fingerprint --phase recon --timeout 1800",
        },
    ),
    "sqlmap": (
        {
            "command": "aith assess kali sqlmap -u 'https://target/?id=1' --batch --sql-technique BEUSTQ --level 3 --risk 2 --technique SQLI --intent 'verify SQLi on id parameter' --probe-kind payload --phase consume-test --timeout 1800",
        },
    ),
    "cero": (
        {
            "command": "aith assess kali cero -d 198.51.100.0/24 -p 443,8443,9443 -c 100 -t 4 -o /engagements/$ENGAGEMENT_KEY/scans/cero_sans.txt --technique OSINT --intent 'TLS SAN scraping for non-CT subs' --probe-kind fingerprint --phase recon --timeout 600",
        },
    ),
    "alterx": (
        {
            "command": "aith assess kali alterx -l /engagements/$ENGAGEMENT_KEY/scans/subs_passive.txt -limit 200000 -o /engagements/$ENGAGEMENT_KEY/scans/perms.txt --technique RECON --intent 'permutation candidate generation from passive subs' --probe-kind fingerprint --phase recon --timeout 600",
        },
    ),
    "asnmap": (
        {
            "command": "aith assess kali asnmap -d example.com -silent -o /engagements/$ENGAGEMENT_KEY/scans/asnmap_cidrs.txt --technique OSINT --intent 'map target-owned CIDRs for TLS SAN sweep' --probe-kind fingerprint --phase recon --timeout 600",
        },
    ),
    "bbot": (
        {
            "command": "aith assess kali bbot -t example.com -p subdomain-enum -rf passive -o /engagements/$ENGAGEMENT_KEY/scans/bbot_subs --technique OSINT --intent 'deep passive subdomain enum' --probe-kind fingerprint --phase recon --timeout 1800",
        },
    ),
    "job": (
        {
            "command": "aith assess kali job start --technique CVE-VALIDATION --intent 'long nuclei sweep' --probe-kind fingerprint --phase recon --timeout 21600 -- nuclei -l targets.txt -t http/cves/",
        },
        {
            "command": "aith assess kali job status 42",
        },
    ),
    "sweep-orphans": (
        {
            "command": "aith assess kali sweep-orphans --dry-run",
        },
        {
            "command": "aith assess kali sweep-orphans --max-age-seconds 1800 --container-name security-research",
        },
    ),
}


def _kali_root_contract() -> CommandContract:
    return CommandContract(
        name="kali",
        summary="Run Kali tools inside the runtime container with audit recording.",
        schema_name="(per-verb argparse + CommandRunRecordRequest backend model)",
        preferred_invocations=(
            "aith assess kali <verb> [flags]",
            "aith assess kali --help",
            "aith assess contract kali <verb>",
        ),
        author_supplied_fields=(
            "--technique <enum>",
            "--intent \"<one-line purpose>\"",
            "--probe-kind {fingerprint|baseline|payload|exploit|replay|cleanup}",
            "--phase <enum>",
            "--timeout <seconds>",
        ),
        notes=_KALI_COMMON_NOTES + (
            f"Verbs: {', '.join(KALI_VERBS)}.",
        ),
        common_mistakes=_KALI_COMMON_MISTAKES,
        examples=(
            {"command": "aith assess kali nmap-scan --target example.com --ports top-100 --technique RECON --intent 'fast top-100 sweep' --probe-kind fingerprint --phase recon --timeout 600"},
        ),
    )


def _kali_verb_contract(verb: str) -> CommandContract | None:
    if verb not in KALI_VERBS:
        return None
    examples = _KALI_VERB_EXAMPLES.get(verb, ())

    # `sweep-orphans` is a host-side reconciler, not a target-facing probe —
    # it skips the audit-flag set entirely and has its own flag surface, so
    # composing the standard invocation/author-fields/common-mistakes block
    # would mislead the operator. Document its actual surface instead.
    if verb == "sweep-orphans":
        return CommandContract(
            name="kali sweep-orphans",
            summary=(
                "Reconcile assessment_command_runs rows stuck in status=running "
                "past a threshold age by probing the in-container PID and "
                "finalizing dead rows to status=lost."
            ),
            schema_name="argparse + CommandRunFinalize backend model",
            preferred_invocations=(
                "aith assess kali sweep-orphans --dry-run",
                "aith assess kali sweep-orphans --max-age-seconds 3600",
                "aith assess kali sweep-orphans --container-name security-research",
            ),
            author_supplied_fields=(
                "--max-age-seconds <int> (default 3600)",
                "--container-name <name> (default security-research)",
                "--dry-run (optional, list candidates without writing)",
            ),
            notes=_KALI_VERB_NOTES.get(verb, ()),
            common_mistakes=(
                ("--phase", "sweep-orphans is host-side maintenance and does not take audit flags"),
                ("--technique", "sweep-orphans is host-side maintenance and does not take audit flags"),
            ),
            examples=examples,
        )

    notes = _KALI_COMMON_NOTES + _KALI_VERB_NOTES.get(verb, ())
    invocation = _kali_invocation(verb)
    author_fields: tuple[str, ...] = (
        "--technique <enum>",
        "--intent \"<one-line purpose>\"",
        "--probe-kind <kind>",
        "--phase <phase>",
        "--timeout <seconds>",
        "tool-specific flags (see `aith assess kali "
        + verb
        + " --help`)",
    )
    # `exec` and `job` are raw-passthrough wrappers; they do not expose the
    # typed-verb `--extra-args` flag because every argument after the audit
    # metadata is already raw passthrough.
    if verb not in ("exec", "job"):
        author_fields = author_fields + (
            "--extra-args \"<raw flags>\" (optional, shlex-split passthrough for long-tail flags)",
        )
    return CommandContract(
        name=f"kali {verb}",
        summary=f"Run `{verb}` inside the runtime container with audit recording.",
        schema_name="argparse + CommandRunRecordRequest backend model",
        preferred_invocations=invocation,
        author_supplied_fields=author_fields,
        notes=notes,
        common_mistakes=_KALI_COMMON_MISTAKES,
        examples=examples,
    )


def _record_intel_contract(intel_type: str) -> CommandContract | None:
    if intel_type not in INTEL_TYPES:
        return None
    schema_name, endpoint_segment = INTEL_TYPES[intel_type]
    required = tuple(_schema_required_names(schema_name))
    schema = load_schema(schema_name)
    properties = schema.get("properties", {})
    author_fields = list(required or ("type-specific fields",))
    for optional in ("source_name", "confidence", "evidence_ref", "provenance", "notes"):
        if isinstance(properties, dict) and optional in properties and optional not in author_fields:
            author_fields.append(optional)

    example = _intel_example_payload(intel_type)
    return CommandContract(
        name=f"record-intel {intel_type}",
        summary=f"Record one `{intel_type}` intel row via the record-intel helper.",
        schema_name=schema_name,
        preferred_invocations=(
            f"aith assess record-intel {intel_type} {intel_type}.json",
        ),
        author_supplied_fields=tuple(author_fields),
        notes=(
            f"Posts to /intel/{endpoint_segment}; use the helper rather than raw post so local schema validation catches payload drift first.",
            "Intel schemas are strict. If a field is not listed under Allowed top-level fields, the CLI will reject it before contacting the backend.",
        ),
        common_mistakes=(
            ("source", "use source_name"),
            ("agent_name", "use source_name, or provenance.agent_name when provenance detail is useful"),
        ),
        examples=(example,) if example else (),
    )


def _intel_example_payload(intel_type: str) -> dict[str, Any]:
    examples: dict[str, dict[str, Any]] = {
        "tech-component": {
            "component": "Salesforce",
            "version": "",
            "source_name": "source-analyzer",
            "confidence": "confirmed",
            "evidence_ref": "scans/httpx-tech.txt:7",
        },
        "person": {
            "name": "Jane Doe",
            "role": "Engineering",
            "source_name": "osint-analyst",
        },
        "email": {
            "address": "security@example.com",
            "source_name": "osint-analyst",
        },
        "domain": {
            "identity": "api.example.com",
            "kind": "subdomain",
            "source_name": "subdomain-enumeration",
        },
        "cve": {
            "cve_id": "CVE-2024-1234",
            "affected_component": "example-app",
            "source_name": "osint-analyst",
        },
        "dns-record": {
            "name": "api.example.com",
            "record_type": "A",
            "value": "192.0.2.10",
            "source_name": "subdomain-enumeration",
        },
        "social-profile": {
            "subject_kind": "org",
            "platform": "linkedin",
            "handle": "example",
            "url": "https://www.linkedin.com/company/example/",
            "source_name": "osint-analyst",
        },
        "breach-record": {
            "subject": "user@example.com",
            "breach_name": "Example breach",
            "source_name": "osint-analyst",
        },
        "org-fact": {
            "fact_key": "helpdesk-provider",
            "fact_value": "ExampleDesk",
            "source_name": "osint-analyst",
        },
        "note": {
            "title": "Login page leaks stack trace",
            "body_markdown": "Verbose error references internal package names.",
            "source_name": "vulnerability-analyst",
        },
    }
    return examples.get(intel_type, {})


def _looks_like_verification_payload(payload: Any | None) -> bool:
    if not isinstance(payload, dict):
        return False
    verification_keys = {"verification_state", "verification_disposition"}
    if verification_keys.intersection(payload):
        return True
    return payload.get("workflow_status") == "false_positive"


# ---------------------------------------------------------------------------
# dispatch namespace contracts
#
# Most dispatch verbs are work-buffer SQL primitives (stats, fetch, done, ...)
# documented inline by `aith assess dispatch <db> --help`. The contract
# surface is reserved for verbs whose output shape matters to other agents —
# render-handoff is the first such verb because the rendered blob is meant to
# be pasted verbatim into the next dispatch prompt and we want operators to
# discover the helper rather than freelance their own handoff format.
# ---------------------------------------------------------------------------

DISPATCH_VERBS: tuple[str, ...] = (
    "render-handoff",
    "register",
    "update-status",
    "list",
    "get",
    "record-decision",
    "record-handoff",
)


def _dispatch_root_contract() -> CommandContract:
    return CommandContract(
        name="dispatch",
        summary=(
            "SQLite work-buffer dispatch engine plus operator-glue helpers "
            "(register / update-status / list / get / record-decision / "
            "record-handoff / render-handoff for cross-dispatch continuity)."
        ),
        schema_name="(per-action argparse; backend-backed via assessment_dispatches / _dispatch_handoffs / _dispatch_decisions)",
        preferred_invocations=(
            "aith assess dispatch <db_path> stats|fetch|done|...",
            "aith assess dispatch register --agent-id <id> --agent-role <role> ...",
            "aith assess dispatch update-status <agent-id> --status completed",
            "aith assess dispatch record-handoff --agent-id <id> --agent-role <role> --summary '...'",
            "aith assess dispatch list [--role <role>] [--status <status>]",
            "aith assess dispatch render-handoff <agent-id>",
            "aith assess contract dispatch render-handoff",
        ),
        author_supplied_fields=(
            "<db_path> (cases.db) for work-buffer actions",
            "<action> (e.g. stats, fetch, done, register, render-handoff, ...)",
            "action-specific positional args",
        ),
        notes=(
            "Work-buffer actions (stats/fetch/done/peek/defer-cluster/defer-items/error/"
            "reset-stale/retry-errors/migrate/requeue) require <db_path> as the first "
            "positional. Operator-glue actions (register, update-status, list, get, "
            "record-decision, record-handoff, render-handoff) reject a cases.db prefix.",
            "Dispatch state lives in the orchestrator backend. Use `register` to log a dispatch, `update-status` "
            "to mark it complete, `record-handoff` to durably record the agent's exit "
            "payload, and `render-handoff` to assemble the blob the next dispatch prompt "
            "pastes verbatim.",
            f"Verbs with their own contract entries: {', '.join(DISPATCH_VERBS)}.",
        ),
        common_mistakes=(
            (
                "transcript paste",
                "use `aith assess dispatch render-handoff <prior-agent-id>` and paste the "
                "rendered blob verbatim — the helper pulls findings, artifacts, and "
                "credentials from durable state so the prompt stays small",
            ),
            (
                "stale local DB syntax",
                "backend dispatch actions use `aith assess dispatch record-handoff ...`; "
                "`aith assess dispatch cases.db record-handoff ...` is rejected so handoffs "
                "cannot be written to the wrong state surface",
            ),
        ),
    )


def _dispatch_verb_contract(verb: str) -> CommandContract | None:
    if verb == "render-handoff":
        return CommandContract(
            name="dispatch render-handoff",
            summary=(
                "Render a bounded handoff blob for a prior dispatch's agent_id, "
                "pulled from the assessment backend (dispatch + handoff rows) plus "
                "per-slug finding fetches."
            ),
            schema_name="(reads GET dispatch-handoffs/{agent_id} + GET dispatches/{agent_id} + GET findings/{slug})",
            preferred_invocations=(
                "aith assess dispatch render-handoff <agent-id>",
                "aith assess dispatch render-handoff <agent-id> --max-lines 60",
                "aith assess dispatch render-handoff <agent-id> --include-evidence",
            ),
            author_supplied_fields=(
                "<agent-id> (the prior dispatch's agent_id from `aith assess dispatch list`)",
            ),
            helper_defaults=(
                ("--max-lines", "40 (hard cap; findings list collapses with '... and N more')"),
                ("--include-evidence", "off (one short evidence excerpt per finding when set)"),
                ("--engagement-dir", "resolved from --engagement-dir / $ENGAGEMENT_DIR / cwd"),
                ("scope", "handoff payload's summary / coverage_gaps / next_steps / "
                          "runtime_issues / working_artifacts / open_questions / "
                          "recommended_next_agent / extras"),
                ("credentials filter", "fetched only for vulnerability-analyst and "
                                       "exploit-developer roles, filtered by source_name"),
            ),
            notes=(
                "Exit 2 when the handoff for the given agent-id does not exist in the "
                "backend (404 on dispatch-handoffs/{agent_id}). Specialist dispatches "
                "are expected to write a handoff before exiting; a missing handoff "
                "means the dispatch never wrote one (or the id was mistyped).",
                "404 on a finding slug is rendered inline as 'slug missing in backend' "
                "rather than failing the whole render — the operator may have killed a "
                "finding between dispatch and handoff time. This wording is distinct "
                "from 'fetch error: <reason>' so the operator can tell the two cases "
                "apart (ISSUE-010 fix).",
                "The dispatch row is fetched best-effort — when missing, the renderer "
                "falls back to whatever metadata the handoff row carries.",
                "Cross-reference: agent/operator-core.md 'Cross-Dispatch Continuity'.",
            ),
            common_mistakes=(
                (
                    "transcript excerpts in dispatch prompt",
                    "render-handoff replaces operator discretion with a deterministic "
                    "blob; paste its output instead of copy-pasting from the prior "
                    "agent's transcript",
                ),
                (
                    "raising --max-lines past ~80",
                    "the cap exists to keep the prompt bounded — if the blob is too "
                    "small, narrow the registry's finding_slugs list rather than "
                    "widening the cap",
                ),
            ),
            examples=(
                {
                    "command": "aith assess dispatch render-handoff a424a88b02054913d",
                },
                {
                    "command": "aith assess dispatch render-handoff a424a88b02054913d --max-lines 60 --include-evidence",
                },
            ),
        )
    return None
