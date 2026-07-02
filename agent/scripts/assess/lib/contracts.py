"""Stable CLI contract metadata for helper-owned assessment commands."""
from __future__ import annotations

from dataclasses import dataclass, field
import json
import os
import re
from pathlib import Path
from typing import Any

from .intel_types import INTEL_TYPES
from .kali_audit import ALLOWED_PHASES
from .schema_validation import load_schema


# Canonical engagement-phase vocabulary for the per-phase command catalog. This
# is the SAME enum the kali audit path validates `--phase` against — imported
# from kali_audit, not re-declared — so `vigil assess list-commands --phase <N>`
# and the audit gate can never drift to two divergent phase enums.
CATALOG_PHASES: tuple[str, ...] = ALLOWED_PHASES

# The readiness command (check_phase_readiness) labels the canonical persisted
# "consume-test" phase with the short form "consume" internally. Accept both
# spellings on a --phase filter so a caller who types either resolves to the
# canonical value; this is the one explicit alias bridging the short readiness
# labels to CATALOG_PHASES.
_PHASE_FILTER_ALIASES: dict[str, str] = {
    "consume": "consume-test",
    "consume_test": "consume-test",
}


def canonical_phase(phase: str) -> str:
    """Normalize a phase token to its CATALOG_PHASES spelling.

    Lower-cases and resolves the ``consume``→``consume-test`` short alias so a
    ``--phase`` filter written in either form matches the canonical tags.
    """
    key = (phase or "").strip().lower()
    return _PHASE_FILTER_ALIASES.get(key, key)


SPECIALIST_DISPATCH_MODES: tuple[str, ...] = (
    "hypothesis-driven",
    "item-iterating",
    "deep-manual",
    "variant-rotation",
    "swarm",
)


# Canonical external-submission vocabulary for `update-finding --submission-status`.
# MIRRORS the backend `SubmissionStatus` StrEnum / `SUBMISSION_STATUSES` set in
# orchestrator/backend/app/services/state_manager/_common.py. The CLI (agent/
# scripts) and backend (orchestrator) are separate packages and cannot import
# each other, so the set is duplicated here and pinned in sync by
# test_submission_status (the same convention as SPECIALIST_DISPATCH_MODES vs the
# backend _KNOWN_DISPATCH_MODES). submission_status is ORTHOGONAL to
# workflow_status — it never changes report-inclusion.
SUBMISSION_STATUSES: tuple[str, ...] = (
    "none",
    "submitted",
    "accepted",
    "needs_info",
    "rejected",
    "duplicate",
)


_DISPATCH_MODE_BY_ROLE: dict[str, str] = {
    "vulnerability-analyst": "hypothesis-driven",
    "exploit-developer": "deep-manual",
    "recon-specialist": "item-iterating",
    "osint-analyst": "item-iterating",
    "code-vuln-hunter": "hypothesis-driven",
}

_DEFAULT_DISPATCH_MODE = "hypothesis-driven"


def default_dispatch_mode_for_role(role: str | None) -> str:
    """Return the default ``dispatch_mode`` for a role (L2-1).

    Falls back to ``hypothesis-driven`` for unknown/empty roles. Case-
    insensitive so ``Vulnerability-Analyst`` resolves like the canonical name.
    """
    role_key = str(role or "").strip().lower()
    return _DISPATCH_MODE_BY_ROLE.get(role_key, _DEFAULT_DISPATCH_MODE)


_SPECIALIST_DISPATCH_REQUIRED_FIELDS: tuple[str, ...] = ()


# Roles exempt from the `skills` requirement. The operator coordinates phases
# and dispatch decisions rather than executing a single skill, so requiring an
# explicit skill list on operator dispatches would be misleading. Every other
# specialist role must declare which skills it loaded so the dispatch row is a
# truthful audit of the specialist context.
_DISPATCH_ROLES_WITHOUT_SKILLS: frozenset[str] = frozenset({"operator"})


# Roles whose dispatches must target a host that is actually in scope. OSINT
# and recon are intentionally NOT here: OSINT is permissible against
# adjacent/related domains (cert chains, DNS history, GitHub mirrors), and
# recon-specialist fingerprinting fires before scope-host is even meaningful.
# Vulnerability-analyst and exploit-developer probe live targets, so their
# scope_host must be in `scope.json` hosts (with wildcard semantics applied).
_SCOPE_GATED_ROLES: frozenset[str] = frozenset({
    "vulnerability-analyst",
    "exploit-developer",
})


def _agent_skills_root() -> Path:
    """Resolve agent/skills/ relative to this file or VIGIL_REPO_ROOT.

    Used for warn-only validation that named skills exist on disk. Returning a
    bogus path is harmless because the caller treats a missing directory as
    "skip the on-disk check" rather than a hard error.
    """
    override = os.environ.get("VIGIL_REPO_ROOT")
    if override:
        candidate = Path(override) / "agent" / "skills"
        if candidate.is_dir():
            return candidate
    here = Path(__file__).resolve()
    for parent in here.parents:
        candidate = parent / "agent" / "skills"
        if candidate.is_dir():
            return candidate
    # Fallback when no parent dir holds an `agent/skills/` (e.g. the file is
    # imported from a copied checkout). `__file__` lives at
    # agent/scripts/assess/lib/contracts.py, so parents[3] is the `agent/`
    # directory itself — append `skills` rather than `agent/skills` to avoid
    # building an `agent/agent/skills` path that never exists.
    return Path(__file__).resolve().parents[3] / "skills"


@dataclass
class SpecialistDispatchContract:
    """Documentation mirror of specialist dispatch payloads for ``vigil assess agent start``.

    Aligns with the Specialist Dispatch Contract table in ``agent/operator-core.md``.
    Use ``validate_specialist_dispatch_contract`` to lint a parsed JSON payload.

    The orchestrator expects ``requested_model`` / ``requested_reasoning`` (and optional
    ``actual_model`` / ``actual_reasoning``). Legacy aliases ``model`` / ``reasoning``
    remain valid on POST and populate the requested columns server-side.
    """

    role: str
    dispatch_mode: str
    requested_model: str | None = None
    requested_reasoning: str | None = None
    extras: dict[str, Any] = field(default_factory=dict)


def validate_specialist_dispatch_contract(
    payload: Any,
    *,
    engagement_dir: str | None = None,
    allow_no_skills: bool = False,
) -> tuple[list[str], list[str]]:
    """Validate a parsed specialist dispatch payload.

    When ``engagement_dir`` is provided, additionally check that ``scope_host``
    is in the engagement's ``scope.json`` ``hosts`` for scope-gated roles
    (``vulnerability-analyst``, ``exploit-developer``). This prevents the
    operator-side mistake of dispatching active probing against a related-but-
    out-of-scope domain that recon surfaced. OSINT and recon are NOT gated
    because they legitimately reach adjacent/related domains during discovery.

    L2-2 / L3-6: when ``allow_no_skills`` is set, a missing ``skills`` list is
    downgraded from an error to a WARNING so ad-hoc roles have a real escape
    valve (``vigil assess agent start --allow-no-skills``) rather than a hard
    block on a self-attested signal.

    Returns ``(errors, warnings)``.
    """
    errors: list[str] = []
    warnings: list[str] = []

    if not isinstance(payload, dict):
        return ["agent start contract must be a JSON object"], warnings

    for field_name in _SPECIALIST_DISPATCH_REQUIRED_FIELDS:
        if field_name not in payload:
            errors.append(f"missing required field: {field_name}")

    role_value = payload.get("agent_role", payload.get("role"))
    if "role" not in payload and "agent_role" not in payload:
        errors.append("missing required field: role (or agent_role)")
    if "role" in payload and "agent_role" in payload:
        role_text = str(payload.get("role") or "").strip()
        agent_role_text = str(payload.get("agent_role") or "").strip()
        if role_text and agent_role_text and role_text.lower() != agent_role_text.lower():
            errors.append("role and agent_role must match when both are present")

    dispatch_mode = payload.get("dispatch_mode")
    if dispatch_mode is None:
        defaulted_mode = default_dispatch_mode_for_role(role_value)
        warnings.append(
            f"dispatch_mode not set; defaulting to '{defaulted_mode}' for role "
            f"'{role_value or '<unknown>'}'. Pass --dispatch-mode explicitly to override."
        )
    elif dispatch_mode not in SPECIALIST_DISPATCH_MODES:
        warnings.append(
            f"dispatch_mode '{dispatch_mode}' is not a known mode; "
            f"known modes: {', '.join(SPECIALIST_DISPATCH_MODES)}. "
            "Proceeding (stored as-is) in case this is a newly-coined mode."
        )

    for str_field in ("role", "agent_role"):
        value = payload.get(str_field)
        if value is not None and not isinstance(value, str):
            errors.append(f"{str_field} must be a string")
        elif value is not None and not str(value).strip():
            errors.append(f"{str_field} must be a non-empty string")

    # Skills are required for every specialist role so the dispatch row is a
    # truthful audit of which skill context the agent loaded. Operators are
    # exempt because they coordinate phases rather than executing a single
    # skill. Skip on-disk verification when the skills directory cannot be
    # located so the validator stays usable from arbitrary CWDs.
    role_name = str(role_value).strip() if isinstance(role_value, str) else ""
    skills_value = payload.get("skills")
    skills_list: list[str] = []
    if isinstance(skills_value, str):
        skills_list = [s.strip() for s in skills_value.split(",") if s.strip()]
    elif isinstance(skills_value, list):
        for entry in skills_value:
            if isinstance(entry, str) and entry.strip():
                skills_list.append(entry.strip())
            else:
                errors.append("skills entries must be non-empty strings")
                break
    elif skills_value is not None:
        errors.append("skills must be a comma-separated string or a list of strings")

    if role_name and role_name.lower() not in _DISPATCH_ROLES_WITHOUT_SKILLS:
        if not skills_list:
            if allow_no_skills:
                warnings.append(
                    f"skills not set for role '{role_name}'; proceeding because "
                    "--allow-no-skills was passed. The dispatch row will carry no "
                    "skill audit — list skills from `vigil assess list-skills` when possible."
                )
            else:
                errors.append(
                    f"skills is required for role '{role_name}'; "
                    "list at least one skill name from `vigil assess list-skills` "
                    "(or pass --allow-no-skills for an ad-hoc role)"
                )

    if skills_list:
        skills_root = _agent_skills_root()
        if skills_root.is_dir():
            for skill_name in skills_list:
                skill_path = skills_root / skill_name / "SKILL.md"
                if not skill_path.is_file():
                    warnings.append(
                        f"skill '{skill_name}' has no SKILL.md under {skills_root} "
                        "— typo or repo-relative path mismatch?"
                    )

    # Scope-host gate for active-probing roles. Imported lazily so the
    # contracts module stays importable in test/CI contexts that do not have
    # an engagement directory layout. Missing scope.json silently skips the
    # gate — other paths surface that error; the validator should not
    # duplicate it. Malformed scope.json (exists but unparseable) warns.
    if engagement_dir and role_name and role_name.lower() in _SCOPE_GATED_ROLES:
        scope_host = payload.get("scope_host")
        if isinstance(scope_host, str) and scope_host.strip():
            scope_path = Path(engagement_dir) / "scope.json"
            if scope_path.is_file():
                try:
                    from .scope import (
                        host_admitted,
                        host_in_scope,
                        load_scope,
                        out_of_scope_entries,
                        scope_entries,
                    )
                    scope = load_scope(engagement_dir)
                    entries = scope_entries(scope)
                    deny = out_of_scope_entries(scope)
                except (SystemExit, ValueError, OSError) as exc:
                    warnings.append(f"scope_host gate skipped: {exc}")
                else:
                    probed_host = scope_host.strip()
                    if entries and not host_admitted(probed_host, entries, deny):
                        if host_in_scope(probed_host, entries):
                            # Host IS in the allowlist but is carved out by an
                            # out_of_scope denylist entry — distinct, sharper error.
                            errors.append(
                                f"scope_host '{scope_host}' matches an out_of_scope "
                                "carve-out in scope.json `out_of_scope` and must not "
                                "be probed."
                            )
                        else:
                            errors.append(
                                f"scope_host '{scope_host}' is not in scope.json `hosts` "
                                f"for role '{role_name}'. Active-probing dispatches "
                                "(vulnerability-analyst, exploit-developer) must target a "
                                "host that is explicitly in scope. If this is intentional "
                                "(e.g. cert-chain pivot), reframe as recon/osint, or add "
                                "the host to scope.json first."
                            )

    return errors, warnings


# Verbs registered under `vigil assess kali ...`. Names are kept in sync with
# the modules under `agent/scripts/assess/commands/kali_*.py`.
#
# Two categories live here so the audit-flag invariants stay truthful:
# - KALI_TARGET_VERBS — target-facing probes that REQUIRE the standard
#   audit-flag set (`--technique`, `--intent`, `--probe-kind`, `--phase`,
#   `--timeout`). Common notes and common mistakes apply.
# - KALI_MAINT_VERBS — host-side maintenance commands. They do not touch the
#   target and do not take the audit-flag set. Common notes do NOT apply;
#   each gets a bespoke contract entry.
#
# `KALI_VERBS` is the union for command registration / discovery, but
# documentation and validation must use the right subset so prompts cannot
# tell the operator that `sweep-orphans` requires `--phase` (it does not).
KALI_TARGET_VERBS: tuple[str, ...] = (
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
    "arjun",
    "whatweb",
    "cero",
    "alterx",
    "asnmap",
    "bbot",
    "browser",
    "tlsx",
    "dalfox",
    "robots",
    "exec",
    "job",
)

KALI_MAINT_VERBS: tuple[str, ...] = (
    "sweep-orphans",
    "tool-help",
    "gf",
)

KALI_VERBS: tuple[str, ...] = KALI_TARGET_VERBS + KALI_MAINT_VERBS


_KALI_COMMON_NOTES: tuple[str, ...] = (
    "Every target-facing kali verb requires --technique, --intent, --probe-kind, --phase, and --timeout. The CLI rejects a call missing any of these before it reaches the backend.",
    "--technique must be one of TECHNIQUE_ENUM: use HEALTH for runtime/tool inventory, META for operator-side metadata, LOG-READ for artifact reads, OTHER only when no specific class fits.",
    "--agent-name resolves from the flag, then $AGENT_NAME, $VIGIL_AGENT_NAME, then `operator`. Specialists must export AGENT_NAME in their wrapper or pass --agent-name <role>.",
    "--phase is REQUIRED — pass the phase the dispatch was authorized for, NOT scope.json.current_phase. Allowed: recon, collect, consume-test, verify, exploit, report, code-ingest, code-classify, code-hunt, code-verify, plus half-phase tags recon-pivot and exploit-recon.",
    "--destructive marks a write/edit/delete on the target (POST/PUT/PATCH/DELETE, file upload, account creation). Leave off for read-only probes.",
    "--force bypasses the dedup window. Use only when re-running an identical command is intentional.",
    "--extra-args \"<string>\" (optional, every typed verb): shlex-split and appended to the tool argv after the typed-flag args. Use sparingly for long-tail flags the verb does not model; the audit row records the full final argv. Set --destructive too if the extra args toggle a destructive mode.",
)


_KALI_COMMON_MISTAKES: tuple[tuple[str, str], ...] = (
    ("missing --phase", "always pass --phase explicitly; no env-var fallback exists"),
    ("technique=recon", "uppercase the audit technique tag (RECON, SSRF, SQLI, ...)"),
    ("intent>200 chars", "intent is trimmed to 200 chars; keep it as a one-line purpose"),
    ("--via-mcp", "MCP path is removed in Wave 1 — `vigil assess kali` is the only path"),
)


def _kali_invocation(verb: str) -> tuple[str, ...]:
    if verb == "exec":
        return (
            "vigil assess kali exec --technique <enum> --intent \"<one-liner>\" "
            "--probe-kind <kind> --phase <phase> --timeout 1800 -- <command...>",
        )
    return (
        f"vigil assess kali {verb} --technique <enum> --intent \"<one-liner>\" "
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
    # Engagement phase(s) where this command is meaningful, drawn from the
    # canonical CATALOG_PHASES vocabulary. Drives `vigil assess list-commands
    # --phase <N>`. An empty tuple means a phase-agnostic utility (recorded /
    # queried in any phase) — it is grouped separately, not under a phase.
    phase: tuple[str, ...] = ()


_CONTRACTS: dict[str, CommandContract] = {
    "record-intel": CommandContract(
        name="record-intel",
        phase=("recon", "collect"),
        summary="Record one structured intel row through a type-specific intel schema.",
        schema_name="type-specific intel schema",
        preferred_invocations=(
            "vigil assess record-intel <type> <intel-json-file>",
            "vigil assess contract record-intel <type>",
        ),
        author_supplied_fields=(
            "type-specific required fields",
            "source_name",
            "evidence_ref or provenance when available",
        ),
        notes=(
            "Read `vigil assess contract record-intel <type>` before authoring the JSON. Intel schemas set `additionalProperties=false`, so an alias like `source` is rejected where the schema says `source_name`.",
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
        phase=("consume-test", "verify", "exploit", "code-hunt"),
        summary="Create or upsert a finding through helper-normalized lifecycle defaults.",
        schema_name="finding-record.schema.json",
        preferred_invocations=(
            "vigil assess record-finding <agent-name> <finding-json-file>",
            "vigil assess record-finding <agent-name> <finding-json-file> --update <existing-slug>",
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
            "Omit top-level lifecycle fields unless you are intentionally overriding a helper default. The CLI fills workflow_status, verification_state, verification_disposition, and provenance — supply only the fields shown in the examples.",
            "Code-specific detail fields are valid: details.entry_point, details.sink, details.taint_path, details.guards_evaluated, details.slot_type, details.variant_of, details.original_pattern.",
            "details.poc_code holds exploit scripts; details.poc_request / details.poc_response hold a structured HTTP request/response pair.",
            "details.references is an array of strings for CVE links, advisories, or related docs.",
            "Set details.chain_required/details.chain_rationale/details.required_followup when the finding is concrete but only becomes exploitation-worthy as part of a larger chain. Specialists own these via record-finding/update-finding; verification reviews but does not own them.",
            "Blocked-attempt convention (schema-validated under details): when a technique is proven-shaped but walled off by missing provisioning, set details.block_reason (short why), details.unblock_requirements {kind, description, requested_from}, and details.attempts_summary (what was already tried). These keys are validated by finding-record.schema.json under details (additionalProperties=false); only `kind` carries a documented vocabulary (account|line|device|credential|access) — that vocabulary is a convention, NOT a JSON-Schema-enforced enum. A blocked finding stays OUT of the report; record the wall with `vigil assess block-technique` and, once a finding/chain satisfies it, connect them from the finding side with `vigil assess link-finding <unblocking-finding-slug> --link-kind unblocks --target-kind blocked_technique --target-ref <technique_key>`.",
            "Do not put `link_kind=root_cause` in the `links` array. Record the finding first, then `vigil assess link-finding` after verification — root/sibling grouping is an explicit lifecycle action.",
            "evidence_ref must point at an existing engagement file (auto-registered and linked on record). URL refs, prose refs, and path-shaped refs with no file are REJECTED — they cannot satisfy report-readiness artifact indexing. Put external URLs in details.references; pass --allow-unindexed-evidence only for a theoretical/code-inferred finding with no file.",
            "Dedup keys on (defect_family + root_cause_key + auth_context + canonical_location). A net-new record whose tuple collides with an EXISTING reported/active finding under a different slug is REFUSED, not silently merged. For a genuinely-distinct sibling on the same root cause, give it its OWN root_cause_key/defect_family and attach it with link-finding; pass --update <slug> ONLY to intentionally modify that exact existing finding.",
        ),
        common_mistakes=(
            ("status", "use workflow_status for lifecycle overrides, or omit it and keep the helper default"),
            ("evidence_ref URL/free-text prose", "point it at an existing artifact file; put URLs in details.references; use --allow-unindexed-evidence only for findings with genuinely no artifact"),
            ("confidence", "confidence belongs in code-record-analysis output, not finding records"),
            ("cwe", "use details.cwe_id"),
            ("description", "use summary for the short finding statement or notes for replayable proof"),
            ("evidence", "use details.evidence"),
            ("impact", "use details.impact"),
            ("links[].link_kind=root_cause", "use `vigil assess link-finding <sibling-slug> --root-cause <root-slug>` after verification"),
            ("reusing a reported finding's root_cause_key + canonical_location for a new finding", "differentiate the root_cause_key/defect_family and use link-finding, or pass --update <slug> to modify the existing finding"),
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
                    "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "cvss_score": 8.1,
                    "remediation": "Add bounds check on schemelen before memcpy; reject URLs with scheme longer than 63 bytes",
                    "steps_to_reproduce": [
                        "Craft URL with scheme > 64 bytes",
                        "Pass to curl_url_set",
                        "Observe heap corruption under ASAN",
                    ],
                    "chain_required": True,
                    "chain_rationale": "The primitive is meaningful for exploitation, but final report impact depends on chaining it to a reachable crash or controlled allocation path.",
                    "required_followup": [
                        "Exercise the URL parser through a network-reachable caller",
                        "Confirm whether the overflow produces controlled corruption under sanitizer instrumentation",
                    ],
                    "references": ["https://cwe.mitre.org/data/definitions/122.html"],
                },
            },
            {
                "title": "BFLA on role-grant endpoint (blocked: needs org-admin group)",
                "severity": "high",
                "defect_family": "broken-function-level-authorization",
                "canonical_location": "https://target.example/api/roles/grant",
                "summary": "The role-grant endpoint appears to lack function-level authz, but confirming it requires an account provisioned into the org-admin group.",
                "notes": "Anonymous + member roles 403 at the gate; the grant call is only reachable once inside org-admin — provisioning not available this engagement.",
                "details": {
                    "impact": "If confirmed, a low-privilege user could grant themselves arbitrary roles (privilege escalation).",
                    "evidence": "GET /api/roles/grant returns 403 for member; the UI only renders the grant control for org-admin.",
                    "block_reason": "Cannot reach the role-grant endpoint without an org-admin-group account.",
                    "unblock_requirements": {
                        "kind": "account",
                        "description": "A test account provisioned into the org-admin group with role-management entitlement.",
                        "requested_from": "program contact / target admin",
                    },
                    "attempts_summary": "Tried anonymous, member, and billing-admin sessions; all 403 at the function gate. Recorded via block-technique (BFLA on this host).",
                },
            },
        ),
    ),
    "link-finding": CommandContract(
        name="link-finding",
        phase=("verify", "report"),
        summary="Group findings by root cause, attach intel, or record a generic typed finding link (incl. the unblock path for blocked findings).",
        schema_name="backend RootCauseLinkRequest / FindingLinkRequest",
        preferred_invocations=(
            "vigil assess link-finding <sibling-slug> --root-cause <root-slug> --effect eliminates_finding",
            "vigil assess link-finding <sibling-slug> --root-cause <root-slug> --effect eliminates_attack_path --note 'Root removes this exploit chain; residual XXE remains.'",
            "vigil assess link-finding <sibling-slug> --clear-root-cause",
            "vigil assess link-finding <blocked-slug> --link-kind unblocked_by --target-kind finding --target-ref <unblocking-slug>",
            "vigil assess link-finding <unblocking-finding-slug> --link-kind unblocks --target-kind blocked_technique --target-ref <technique_key>",
            "vigil assess link-finding <slug> --link-kind related --target-kind chain --target-id 12",
        ),
        author_supplied_fields=(
            "finding_slug",
            "root_cause mode: root_cause_slug, root_cause_effect, note",
            "generic mode: --link-kind, --target-kind, and --target-id or --target-ref",
        ),
        helper_defaults=(
            ("source_name", "operator"),
            ("sibling_order", "next available order when omitted"),
            ("provenance", "{}"),
            ("link_kind", "related (generic mode)"),
        ),
        notes=(
            "Root-cause mode (--root-cause): use after findings are verified enough to consolidate. Records intentional grouping without touching root_cause_key, so dedup and human grouping stay separate.",
            "Use --effect eliminates_attack_path when fixing the root removes only the demonstrated chain and the sibling still needs standalone remediation; use eliminates_finding when the root fix retires the sibling entirely.",
            "Generic mode (--link-kind + --target-kind + --target-id/--target-ref): records an arbitrary typed link (POST /findings/{slug}/links). link_kind=root_cause is refused here — use --root-cause.",
            "Unblock path (first-class): a blocked finding stays OUT of the report, but when a finding/chain that satisfies the wall lands, link it with `--link-kind unblocked_by --target-kind finding --target-ref <unblocking-slug>` (or --target-kind chain --target-id <id>) so the operator and the next engagement see the connection.",
            "Blocked TECHNIQUE (from block-technique) unblock: a blocked technique has no slug and cannot be a link SUBJECT — record it on the FINDING side with `--link-kind unblocks --target-kind blocked_technique --target-ref <technique_key>` (the unblocking finding points at the technique key). target_kind is free text, so blocked_technique is accepted without a backend change.",
        ),
        common_mistakes=(
            ("root_cause_key", "do not repurpose root_cause_key as a display grouping field; use link-finding for intentional groups"),
            ("related", "generic related links do not suppress duplicate-root-cause report blockers"),
        ),
    ),
    "block-technique": CommandContract(
        name="block-technique",
        phase=("consume-test", "exploit"),
        summary="Record a technique walled off on a target (account/device/credential/policy wall, WAF) so it is not silently re-attempted.",
        schema_name="backend BlockedTechniqueRecordRequest",
        preferred_invocations=(
            "vigil assess block-technique --technique SSRF --target-kind host --target-ref api.example.com --reason 'egress firewalled; internal metadata endpoint unreachable' --retry-state no_retry",
            "vigil assess block-technique --technique BFLA --target-kind finding --target-ref VA-047 --reason 'needs an account in the org-admin group to reach the role-grant endpoint' --retry-state pending",
            "vigil assess list-blocked-techniques",
        ),
        author_supplied_fields=(
            "--technique (TECHNIQUE_ENUM)",
            "--target-kind",
            "--target-ref",
            "--reason",
        ),
        helper_defaults=(
            ("technique_key", "derived '<technique>:<target_kind>:<target_ref>' when omitted (stable upsert key)"),
            ("retry_state", "pending"),
            ("source_name", "operator"),
        ),
        notes=(
            "A do-today pointer, NOT a finding — a blocked technique stays OUT of the report. It records what was tried-and-walled-off so the operator and the next engagement do not rediscover the wall per-dispatch. Surfaced under the resume-brief Attempts section.",
            "retry_state soft vocab: pending (block may lift once a prerequisite lands) | retryable (worth another attempt now) | no_retry (permanent wall). Free text; these are the documented, resume-legible values.",
            "A blocked technique has NO slug, so it can never be the SUBJECT of link-finding. Record the unblock from the FINDING side: when a finding/chain satisfies the wall, `vigil assess link-finding <unblocking-finding-slug> --link-kind unblocks --target-kind blocked_technique --target-ref <technique_key>`. The unblock path is first-class even though the blocked technique itself is not reported.",
            "Put the wall's provisioning need in details.unblock_requirements on the RELATED finding (kind ∈ account|line|device|credential|access, description, requested_from); the block-technique row carries the short reason + retry_state, and --notes is a one-line cue (also shown in the resume brief), not the durable home for unblock requirements.",
        ),
    ),
    "http": CommandContract(
        name="http",
        summary="Query, export, and configure captured full-flow HTTP traffic (the canonical mitmproxy flow store + per-engagement capture policy).",
        schema_name="assessment_http_flows + assessment_capture_policy tables / /assessment/http-flows + /assessment/capture-policy endpoints",
        preferred_invocations=(
            "vigil assess http list --host api.example.com --method POST --content-type json",
            "vigil assess http show <flow_uid>",
            "vigil assess http search 'admin' --auth-context anonymous --json",
            "vigil assess http export-har --host api.example.com -o traffic/api.har",
            "vigil assess http import-har traffic/api.har",
            "vigil assess http policy",
            "vigil assess http policy set --enabled --capture-request-bodies --max-body-bytes 262144 --content-type-allow application/json",
        ),
        author_supplied_fields=(
            "subcommand: list | show | search | export-har | import-har | policy [set]",
            "list/search/export-har filters: --host / --method / --status / --content-type / --auth-context / --truncated|--no-truncated / --q / --limit / --offset",
            "show: <flow_uid> (or numeric id) positional",
            "export-har: -o/--output <file>",
            "import-har: <har-file> positional",
            "policy set: --enabled/--no-enabled, --capture-request-bodies, --capture-response-bodies, --max-body-bytes, --content-type-allow, --content-type-deny, --redaction-profile",
        ),
        helper_defaults=(
            ("capture policy", "raw-body capture is OFF by default; `policy set` is a partial update (unset fields retain their stored value)"),
            ("query filters", "only non-empty filters are sent; the backend caps list/search at 5000 rows"),
        ),
        notes=(
            "Capture is a per-engagement POLICY (backend state + a `capture-policy.json` filesystem mirror the addon reads offline), NOT a proxy start selector — the shared selector-less proxy routes by hostname and honours this policy per host.",
            "`show` and `export-har` expose only engagement-local metadata + body sidecars; raw bodies stay engagement-local by default.",
            "`export-har` writes HAR 1.2 with Vigil routing/auth/truncation metadata on each entry's `_vigil` field; `import-har` reads `_vigil` for a lossless round-trip.",
            "Prefer these verbs over raw `vigil assess fetch \"http-flows?...\"` — they keep query-string details out of operator instructions.",
        ),
        common_mistakes=(
            ("--enabled to disable capture", "use --no-enabled; --enabled turns raw-body capture ON"),
            ("policy set with no fields", "pass at least one field — an empty update is rejected"),
        ),
    ),
    "record-attempt": CommandContract(
        name="record-attempt",
        phase=("consume-test", "exploit"),
        summary="Record a NON-covering probe attempt (attempted|blocked|no-signal|error) under a lens so a touched-but-inconclusive target is on the ledger without counting as coverage.",
        schema_name="backend ProbeRunRecordRequest (POST /probe-runs)",
        preferred_invocations=(
            "vigil assess record-attempt --result-status blocked --attack-family ssrf --lens tenant-boundary --target-host api.example.com --target-path /fetch --notes 'WAF 403 on every internal host' --finding VA-047",
            "vigil assess record-attempt --result-status no-signal --attack-family idor --target-host app.example.com --target-path /orders/1001 --auth-context member --input-slot path",
            "vigil assess record-attempt --result-status attempted --attack-family open-redirect --lens blind-oob --evidence-ref scans/redirect-probe.txt",
        ),
        author_supplied_fields=(
            "--result-status (attempted|blocked|no-signal|error — non-covering only)",
            "--attack-family (a vuln_taxonomy class)",
            "--lens / --target-host / --target-path / --target-port / --auth-context as applicable",
        ),
        helper_defaults=(
            ("tool_name", "manual"),
            ("auth_context", "anonymous"),
            ("input_slot", "unknown"),
            ("lens", '"" (part of the probe key: a different lens is a distinct attempt)'),
        ),
        notes=(
            "Non-covering by design: `tested`/`signal` (covering) verdicts are NOT accepted here — record those through the normal probe pipeline with real evidence. This verb exists so 'a non-conclusive response is a lead, not a verdict' attempts are captured for the resume-brief Attempts ledger.",
            "The same target under a DIFFERENT --lens is a distinct attempt (lens is hashed into the probe key), not a dedup collision — use it to record the mindset the probe ran under.",
            "--finding <slug> backfills the attempt→finding link (finding_id); it is COALESCE-backfilled on a re-run of the same probe, so a later record-attempt can attach the link an earlier one omitted.",
            "An out-of-vocab --attack-family WARNs but is stored verbatim (the backend persists TEXT for forward-compatibility).",
        ),
        common_mistakes=(
            ("--result-status tested", "covering verdicts are recorded by the probe pipeline with evidence, not by record-attempt; use attempted/blocked/no-signal/error here"),
            ("recording a wall here instead of block-technique", "record-attempt logs a single probe attempt; a durable technique-level wall on a target belongs in `vigil assess block-technique`"),
        ),
    ),
    "list-finding-group": CommandContract(
        name="list-finding-group",
        phase=("report",),
        summary="Inspect a root-cause finding group as the backend will present it to reporting and the UI.",
        schema_name="backend finding group projection",
        preferred_invocations=(
            "vigil assess list-finding-group <root-slug>",
            "vigil assess list-finding-group <root-slug> --json",
        ),
        author_supplied_fields=(
            "root_slug",
        ),
        notes=(
            "Run before report generation to confirm sibling order, residual-path badges, and root/sibling membership.",
        ),
    ),
    "list-report-findings": CommandContract(
        name="list-report-findings",
        phase=("report",),
        summary="Fetch the grouped report finding projection that report-writer consumes.",
        schema_name="backend grouped report-findings projection",
        preferred_invocations=(
            "vigil assess list-report-findings --mode final --json",
            "vigil assess list-report-findings --mode draft --json",
            "vigil assess list-report-findings --mode final",
        ),
        author_supplied_fields=(
            "mode",
        ),
        helper_defaults=(
            ("mode", "final"),
            ("view", "grouped root-cause projection"),
        ),
        notes=(
            "Use this helper instead of raw `vigil assess fetch report-findings?...`. It makes grouped root-cause output the contract and keeps query-string details out of operator instructions.",
            "`--mode final` enforces report-readiness and exits non-zero while blockers remain; `--mode draft` inspects the grouped projection before readiness passes.",
            "`--json` is the report-writer/LLM ingestion form. The default text form is for quick human inspection.",
        ),
    ),
    "resume-brief": CommandContract(
        name="resume-brief",
        summary="Render a bounded resume brief from backend state, command history, handoffs, and indexed artifacts.",
        schema_name="GET /assessment/resume-brief",
        preferred_invocations=(
            "vigil assess resume-brief",
            "vigil assess resume-brief --finding VA-047",
            "vigil assess resume-brief --q \"OIDC static state\" --json",
        ),
        author_supplied_fields=(
            "--q",
            "--finding",
            "--agent-id",
        ),
        notes=(
            "First resume primitive — use instead of manually chaining findings, handoffs, command-runs, and local notes.",
            "Output is bounded; use get-command-run and artifact get for drill-down.",
            "Carries aggregate Surfaces (status×type + top uncovered) and Work Buffer (pending coverage by gf-bucket) rollups plus coverage/read-first intel notes — drill into per-item coverage-items / request-variants / work-buffer only when a rollup flags a bucket.",
            "Carries an Attempts do-today ledger (recorded blocked techniques, non-covering probe runs, and roe_blocked findings) — read it BEFORE re-dispatching a surface so a walled-off technique is not silently re-attempted.",
        ),
        common_mistakes=(
            ("loading local notes first", "run resume-brief, then artifact search/get for linked files"),
        ),
    ),
    "artifact": CommandContract(
        name="artifact",
        summary="Register, refresh, search, fetch, or scratch-mark indexed engagement-local artifact metadata.",
        schema_name="assessment_artifacts table + /assessment/artifacts endpoints",
        preferred_invocations=(
            "vigil assess artifact search VA-047",
            "vigil assess artifact search --finding VA-047",
            "vigil assess artifact get <id>",
            "vigil assess artifact register notes/foo.md --kind note --finding VA-047",
            "vigil assess artifact refresh",
            "vigil assess artifact mark-scratch notes/triage.md",
            "vigil assess artifact mark-scratch --under notes/scratch/",
            "vigil assess artifact unmark-scratch notes/triage.md",
        ),
        author_supplied_fields=(
            "subcommand: search | get | register | mark-scratch | unmark-scratch",
            "register: <path> (positional, required)",
            "get: <artifact_id> (positional int, required)",
            "search: [query...] (positional, optional free-text)",
            "register: --finding / --kind / --agent-id / --command-run-id / --sensitive",
            "search: --finding / --limit / --offset",
            "mark-scratch / unmark-scratch: <target> (id or path) or --under <prefix>",
        ),
        notes=(
            "Each action is a typed subcommand — run `vigil assess artifact <action> --help` for per-action flags.",
            "Large/raw files stay on disk; the backend stores hashes, capped previews, presence, and entity links.",
            "Register paths relative to the engagement root; absolute paths are accepted only when they resolve inside the engagement directory.",
            "`mark-scratch` flags a note non-durable so `check-phase-readiness --phase report` stops blocking on it; the row stays searchable.",
        ),
        common_mistakes=(
            ("pasting full artifact content into prompts", "search first, then get a specific id; content stays capped"),
            ("deleting unlinked notes to clear blockers", "use `mark-scratch` to keep the audit row; delete only when the file should not exist"),
        ),
    ),
    "verify-finding": CommandContract(
        name="verify-finding",
        phase=("verify", "code-verify"),
        summary="Apply a verification transition to an existing finding through the audit ledger.",
        schema_name="backend FindingVerifyRequest",
        preferred_invocations=(
            "vigil assess verify-finding <slug> <verification-json>",
            'vigil assess verify-finding <slug> --disposition downgraded --reason "..." --new-severity low',
            'vigil assess verify-finding <slug> --disposition false_positive --reason "..." --kill-reason "..." --kill-check 2',
        ),
        author_supplied_fields=(
            "disposition",
            "reason_text",
        ),
        notes=(
            "Use for confirmed, downgraded, and disputed verification outcomes.",
            "For false_positive, either pass details.kill_reason/details.kill_check here, or use kill-finding for the shorter flow.",
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
        phase=("verify", "code-verify"),
        summary="Persist a false_positive verification with the required kill metadata.",
        schema_name="backend FindingVerifyRequest (false_positive)",
        preferred_invocations=(
            'vigil assess kill-finding <slug> --reason "..." --kill-reason "..." --kill-check <1-5>',
        ),
        author_supplied_fields=(
            "reason_text",
            "details.kill_reason",
            "details.kill_check",
        ),
        notes=(
            "Use when you have the kill rationale and do not need a custom JSON payload file.",
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
            "vigil assess update-finding <slug> <patch-json-file>",
            'vigil assess update-finding <slug> --status reported --reason "Published in report"',
            'vigil assess update-finding <slug> --inline \'{"workflow_status":"draft","reason_text":"Needs more evidence"}\'',
            'vigil assess update-finding <slug> --details-inline \'{"chain_required":true,"chain_rationale":"...","required_followup":["..."]}\'',
            'vigil assess update-finding <slug> --details-inline \'{"cvss_score":9.1}\' --details-replace',
        ),
        author_supplied_fields=(
            "at least one patch field",
        ),
        notes=(
            "Use for workflow and metadata updates that are NOT verification lifecycle transitions.",
            "Reopening a verified or false-positive finding for re-triage belongs in reset-finding.",
            "Verification disposition changes, disputed reviews, and false_positive kills belong in verify-finding or kill-finding.",
            "--submission-status tracks EXTERNAL bug-bounty/program submission state and is ORTHOGONAL to "
            "--workflow-status (which is report-inclusion). Setting one never changes the other. Allowed values: "
            + ", ".join(SUBMISSION_STATUSES)
            + " (default 'none' = not submitted).",
            "--details-inline '<json object>' merges the given object into the finding's stored details "
            "(the patch payload field is `details`, plain flags or --inline JSON both accept it). Pair with "
            "--details-replace to overwrite the whole details object instead of merging — --details-replace "
            "requires a details payload (via --details-inline or a `details` key in a file/--inline payload) "
            "because running it without one would wipe existing details.",
            "The patch payload field is `details` on write; the API returns it back as `details_json` on read "
            "(GET/list responses). They are the same data under two names — do not conclude a `details` write "
            "was dropped just because the read-back shows `details_json` instead. A top-level `details_json` "
            "key in the patch payload itself is rejected with a 422 (unknown field) — always write `details`.",
        ),
        common_mistakes=(
            ("verification_state", "use verify-finding or kill-finding for verification lifecycle changes"),
            ("verification_disposition", "use verify-finding or kill-finding for verification lifecycle changes"),
            ("workflow_status=false_positive", "use kill-finding instead of update-finding"),
            ("submission_status to mark a finding reported", "submission_status is external submission state; use --workflow-status reported for report-inclusion"),
            ("details_json as a top-level patch field", "the payload field is details (it is stored as / read back as details_json); details_json is rejected with a 422"),
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
            {
                "submission_status": "accepted",
                "reason_text": "Program triaged the report as accepted.",
            },
            {
                "details": {
                    "chain_required": True,
                    "chain_rationale": "This primitive becomes meaningful only after pivoting into the admin export flow.",
                    "required_followup": [
                        "Test sibling privileged write routes",
                        "Attempt authenticated export with stolen token",
                    ],
                },
                "reason_text": "Tagged chain-required after Phase 4 review.",
            },
        ),
    ),
    "reset-finding": CommandContract(
        name="reset-finding",
        summary="Reopen a previously verified or false-positive finding for re-triage.",
        schema_name="backend FindingPatchRequest (reopen)",
        preferred_invocations=(
            'vigil assess reset-finding <slug> --reason "..." --status draft',
            'vigil assess reset-finding <slug> --reason "Retest disproved the kill" --status active',
        ),
        author_supplied_fields=(
            "reason_text",
            "workflow_status",
        ),
        notes=(
            "Use when new evidence means a verified or false-positive finding should return to the active workflow.",
            "Reopening a false-positive finding resets verification_state to unreviewed and verification_disposition to none server-side.",
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
        phase=("collect", "consume-test"),
        summary="PATCH an assessment surface by id (set status + rationale).",
        schema_name="backend SurfaceUpdateRequest",
        preferred_invocations=(
            'vigil assess resolve-surface <id> --status covered --rationale "..."',
            'vigil assess resolve-surface <id> --status not_applicable --rationale "..."',
            'vigil assess resolve-surface <id> --status deferred --rationale "..."',
            'vigil assess resolve-surface <id> --status partially-covered --rationale "..." --followup-condition "..."',
        ),
        author_supplied_fields=(
            "status",
            "rationale",
            "followup_condition",
        ),
        notes=(
            "Resolve a discovered surface after triage instead of falling back to direct SQL.",
            "Rationale is appended to existing rationale, so the audit trail accumulates context across resolutions.",
            "--followup-condition is REQUIRED when --status=partially-covered: the one-line condition the follow-up coverage pass must satisfy.",
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
            "vigil assess update-intel <type> <id> <patch.json>",
            "vigil assess update-intel <type> <id> --inline '{...}'",
        ),
        author_supplied_fields=(
            "at least one updatable column",
        ),
        notes=(
            "update-intel does in-place metadata edits; supersede-intel retains the prior row for audit and inserts a new record.",
            "The backend rejects fields outside the per-type updatable column whitelist, so guessed aliases surface immediately.",
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
            'vigil assess supersede-intel <type> <id> <new.json> --rationale "..."',
            'vigil assess supersede-intel <type> <id> --inline \'{...}\' --rationale "..."',
        ),
        author_supplied_fields=(
            "type-specific natural-key fields for the new replacement record",
            "--rationale (free text)",
        ),
        notes=(
            "Use when an intel row was wrong but the prior observation must stay for audit.",
            "Metadata-only edits belong in update-intel; supersede-intel requires the replacement row's full natural key.",
            "Report-writer filters on superseded_by_id IS NULL, so superseded rows drop out of reports but stay queryable for cascade-delete and audit.",
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
    "code-dispatch": CommandContract(
        name="code-dispatch",
        phase=("code-classify", "code-hunt"),
        summary="Operate the backend code-analysis queue and cross-file trigger lifecycle.",
        schema_name="backend code-analysis queue / trigger request models",
        preferred_invocations=(
            "vigil assess code-dispatch fetch <limit> <agent-name>",
            "vigil assess code-dispatch done <item-id> <disposition> <cwe-coverage-json-file> [notes]",
            "vigil assess code-dispatch list-triggers [status]",
            "vigil assess code-dispatch resolve-triggers <triggers-json-file> <resolution-status> <note>",
            "vigil assess code-dispatch requeue-triggers <triggers-json-file>",
        ),
        author_supplied_fields=(
            "queue item id(s)",
            "bare JSON array for cwe_coverage when completing a queue item",
            "trigger_id/id or file_path/target_file_path when resolving triggers",
            "resolution_status: external_context_unavailable, source_equivalent_analyzed, or not_applicable",
            "resolution_note explaining why the trigger is accepted without requeue",
        ),
        notes=(
            "`resolve-triggers` records accepted terminal trigger gaps — use it when the target implementation is outside the supplied source snapshot, a source equivalent was analyzed, or the trigger family is genuinely not applicable.",
            "Do not inflate CWE effort numbers to satisfy the gate. Use `disposition=not_applicable` on the coverage entry, or `resolve-triggers` for cross-file gaps that cannot be queued.",
            "`list-triggers` defaults to pending triggers, so operators can inspect blockers before resolving or requeueing.",
        ),
        common_mistakes=(
            ("cwe_coverage object wrapper", "`done` requires a bare JSON array, not {'cwe_coverage': [...]}"),
            ("analysis_priority", "queue payloads use `priority`; classification payloads use `analysis_priority`. Preserve the architect's ordering by mapping analysis_priority to priority when queueing."),
            ("missing resolution_note", "accepted trigger gaps need a durable rationale"),
            ("using resolve-triggers for pending source that exists", "use requeue-triggers when the target file is available and needs analysis"),
        ),
        examples=(
            {
                "command": "vigil assess code-dispatch resolve-triggers missing.json external_context_unavailable 'storage DLL source not provided'",
            },
            {
                "command": "vigil assess code-dispatch done 42 clean cwe/42.json 'reviewed parser'",
            },
        ),
    ),
    "code-index": CommandContract(
        name="code-index",
        phase=("code-ingest",),
        summary="Build the structural index under the engagement analysis-state directory.",
        schema_name="structural-index aggregate manifest, per-repo manifest, and per-file index JSON",
        preferred_invocations=(
            "vigil assess code-index <repo-path> --repo-key <repo-key>",
            "vigil assess code-index <repo-path> --output-dir <engagement-dir>/tools/analysis-state",
            "vigil assess code-index-sync --repo-key <repo-key>",
        ),
        author_supplied_fields=(
            "repo_path",
            "repo_key when available",
            "--output-dir only for intentional non-engagement output",
        ),
        helper_defaults=(
            ("output_dir", "<engagement_dir>/tools/analysis-state"),
            ("aggregate manifest", "structural-index-manifest.json"),
            ("per-repo manifest", "structural-index/<repo_key>-manifest.json"),
            ("per-file indexes", "structural-index/<repo_key>/<sha16>.json"),
        ),
        notes=(
            "The aggregate manifest is keyed by repo_key, so multiple source repos share one engagement analysis-state tree without relative-path collisions.",
            "The default output directory is the one code-index-sync consumes, so indexing and sync stay in one engagement-owned tree.",
            "Pass --engagement-dir or set ENGAGEMENT_DIR when running outside an engagement directory; the helper fails closed rather than write an unsynced .code-index tree into the source repo.",
        ),
        common_mistakes=(
            ("running outside engagement context", "pass --engagement-dir or --output-dir explicitly"),
            ("sync cannot find manifest", "use the default tools/analysis-state output or pass the same explicit output path consistently"),
            ("legacy manifest with multiple repos", "pass --repo-id or rebuild the index so repo_key metadata is available"),
        ),
    ),
    "code-classify": CommandContract(
        name="code-classify",
        phase=("code-classify",),
        summary="Bulk-classify code files and persist architect-assigned analysis priority.",
        schema_name="code-file-classification.schema.json",
        preferred_invocations=(
            "vigil assess contract code-classify",
            "vigil assess code-classify <classifications-json-file>",
        ),
        author_supplied_fields=(
            "file_id or file_path",
            "classification",
            "role",
            "slot_types",
            "analysis_priority",
        ),
        helper_defaults=(
            ("file_path", "resolved client-side to file_id before posting"),
            ("repo_id", "optional disambiguator for duplicate file_path values"),
        ),
        notes=(
            "analysis_priority sets classification ordering. The code-dispatch queue has a separate `priority` field; map analysis_priority to priority only when queueing hunt work.",
            "Classification tiers: critical/high/medium/low/skip. analysis_priority is a 0-100 score that orders files inside a tier.",
            "Read `vigil assess contract code-classify` before authoring the file.",
        ),
        common_mistakes=(
            ("priority", "use analysis_priority in code-classify payloads"),
            ("slot_types_json", "use slot_types"),
            ("repo_id without file_path", "repo_id only disambiguates file_path lookup; file_id can stand alone"),
        ),
        examples=(
            {
                "file_id": 42,
                "classification": "critical",
                "role": "parser",
                "slot_types": ["NETWORK-INPUT"],
                "analysis_priority": 95,
            },
        ),
    ),
    "code-record-modules": CommandContract(
        name="code-record-modules",
        phase=("code-ingest", "code-classify"),
        summary="Record repository module boundaries from the architecture mapping pass.",
        schema_name="backend CodeModuleRecord list",
        preferred_invocations=(
            "vigil assess contract code-record-modules",
            "vigil assess code-record-modules <repo-id> <modules-json-file>",
        ),
        author_supplied_fields=(
            "repo_id",
            "module_key or name",
            "name",
            "description",
            "trust_boundary",
            "files",
            "file_ids",
        ),
        helper_defaults=(
            ("module_key", "derived from name when omitted; collisions are rejected"),
        ),
        notes=(
            "This contract is the module-map shape source for code-architect output. Name this helper in prompts rather than embedding a module JSON template.",
            "Provide explicit module_key values when names normalize to the same slug.",
        ),
        common_mistakes=(
            ("module map only in artifacts", "persist durable module boundaries with code-record-modules"),
            ("duplicate auto-derived module_key", "provide explicit module_key values"),
        ),
    ),
    "code-record-threat-model": CommandContract(
        name="code-record-threat-model",
        phase=("code-ingest", "code-classify"),
        summary="Record the repository threat model produced by code-architect.",
        schema_name="backend threat_model object",
        preferred_invocations=(
            "vigil assess contract code-record-threat-model",
            "vigil assess code-record-threat-model <repo-id> <threat-model-json-file>",
        ),
        author_supplied_fields=(
            "repo_id",
            "threat_model object",
        ),
        notes=(
            "This contract is the threat-model shape source for code-architect output. The backend stores the object as durable analysis context for later dispatches.",
            "Keep implementation detail in the artifact; persist durable attacker surfaces, trust boundaries, sensitive operations, and missing context through this helper.",
        ),
        common_mistakes=(
            ("threat model only in markdown", "persist durable threat-model context with code-record-threat-model"),
        ),
    ),
    "code-record-analysis": CommandContract(
        name="code-record-analysis",
        phase=("code-hunt", "code-verify"),
        summary="Record a code-vuln-hunter result against the claimed queue item that produced it.",
        schema_name="code-analysis-result.schema.json",
        preferred_invocations=(
            "vigil assess contract code-record-analysis",
            "vigil assess code-record-analysis <analysis-results-json-file>",
        ),
        author_supplied_fields=(
            "queue_item_id",
            "agent_name",
            "function_name",
            "hypothesis",
            "evidence",
            "disposition",
            "confidence",
            "finding_slug when disposition=finding",
            "cwe_coverage",
            "cross_file_triggers",
        ),
        helper_defaults=(
            ("file_id", "derived by the backend from queue_item_id; optional client-side consistency check only"),
            ("confidence", "medium"),
            ("audit_metadata", "{}"),
            ("cwe_coverage", "[]"),
            ("cross_file_triggers", "[]"),
        ),
        notes=(
            "Record analysis results only for queue items fetched by code-dispatch. queue_item_id is required so stale or copied file_id values cannot attach work to the wrong file.",
            "When file_id is supplied, the backend treats it as a consistency check and rejects it if it differs from the queue item's file.",
            "For a confirmed finding, run record-finding first, then put that slug in finding_slug.",
        ),
        common_mistakes=(
            ("file_id-only result", "include queue_item_id; file_id is optional and queue-derived"),
            ("confidence in finding record", "confidence belongs in code-record-analysis, not record-finding"),
            ("cross_file_triggers object wrapper", "cross_file_triggers is a bare array on the analysis result"),
        ),
        examples=(
            {
                "queue_item_id": 42,
                "agent_name": "code-vuln-hunter",
                "function_name": "parse_message",
                "hypothesis": "Attacker-controlled bytes reach length-sensitive copy code",
                "evidence": "parse_message() bounds checks len before memcpy; no bypass found",
                "disposition": "clean",
                "confidence": "high",
                "cwe_coverage": [
                    {"family": "buffer-overflow", "effort": 85, "notes": "All parser entry chains traced"}
                ],
                "cross_file_triggers": [],
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
    names.append("agent")
    names.extend(f"agent {verb}" for verb in AGENT_VERBS)
    names.append("work-buffer")
    return sorted(names)


def all_command_contracts() -> list[CommandContract]:
    """Every helper-owned command contract, for the per-phase catalog.

    Composes the static ``_CONTRACTS`` registry with the per-verb kali
    contracts (``kali <verb>``), which is the surface ``vigil assess
    list-commands`` groups by phase. The dynamically-derived per-intel-type
    (``record-intel <type>``) and per-agent-verb (``agent <verb>``) detail
    contracts are intentionally excluded — they are drill-down forms of the
    ``record-intel`` / ``agent`` catalog rows, not separate commands.
    """
    contracts: list[CommandContract] = list(_CONTRACTS.values())
    for verb in KALI_VERBS:
        contract = _kali_verb_contract(verb)
        if contract is not None:
            contracts.append(contract)
    return contracts


def commands_by_phase(phase: str) -> list[CommandContract]:
    """Return the command contracts tagged for a given engagement ``phase``.

    ``phase`` is normalized to the canonical CATALOG_PHASES vocabulary (the
    ``consume``→``consume-test`` short alias is resolved). Phase-agnostic
    utilities (empty ``phase`` tuple) are never returned by a phase filter —
    ``list-commands`` surfaces them in a separate group. Results are sorted by
    command name for stable output.
    """
    target = canonical_phase(phase)
    matched = [c for c in all_command_contracts() if target in c.phase]
    return sorted(matched, key=lambda c: c.name)


def get_contract(name: str) -> CommandContract | None:
    if name.startswith("record-intel "):
        _, _, intel_type = name.partition(" ")
        return _record_intel_contract(intel_type)
    if name == "kali":
        return _kali_root_contract()
    if name.startswith("kali "):
        _, _, verb = name.partition(" ")
        return _kali_verb_contract(verb)
    if name == "agent":
        return _dispatch_root_contract()
    if name.startswith("agent "):
        _, _, verb = name.partition(" ")
        return _dispatch_verb_contract(verb)
    if name == "work-buffer":
        return _work_buffer_contract()
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
            f"  vigil assess contract {contract.name}",
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
            lines.append("  - vigil assess contract verify-finding")
        else:
            lines.append(f"  - {contract.preferred_invocations[0]}")
            if normalized_method == "PATCH" and contract_name == "update-finding":
                reset_contract = get_contract("reset-finding")
                assert reset_contract is not None
                lines.append(f"  - {reset_contract.preferred_invocations[0]}")
            lines.append(f"  - vigil assess contract {contract.name}")
            if normalized_method == "PATCH" and contract_name == "update-finding":
                lines.append("  - vigil assess contract reset-finding")
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
        "Default is top-1000 ports; use --ports full for `-p-`, or pass an explicit list (e.g. 22,80,443).",
        "Defaults to `-sT` (TCP connect). Do NOT use `-sS` here — raw SYN probes are dropped by Docker's userland NAT (esp. Docker Desktop/macOS) and silently return 0-open on live hosts. Use `--scan-type sS` only on a bridged-network Linux runtime.",
        "--scripts default,vuln triggers heavy NSE — run synchronously with --timeout 1800+; a long budget is killed cleanly on expiry.",
    ),
    "nuclei": (
        "Pass either -u or -l. LEAD with explicit `-t` template paths — `-as` (automatic) keys off "
        "tech fingerprinting, which a CDN/WAF defeats, so `-as` under-fires alone; treat it as additive.",
        "WAF-resilience: the wrapper injects `-mhe 50` by default so a host's 403 storm does not make "
        "nuclei ABANDON the host after ~30 errors (its own default). Add `-random-agent` and `-H` "
        "browser headers when the edge blocks scanner UAs.",
        "Politeness `-exclude-tags dos,fuzz,intrusive,brute-force` is injected by default (announced on "
        "stderr); pass your own `-exclude-tags` to override it verbatim. The result's `resolved_argv` "
        "shows the exact command that ran after injection.",
        "Long sweeps run synchronously with a generous --timeout. `vigil assess kali job start` is operator-only — specialists never background (see kali-exec skill).",
    ),
    "katana": (
        "Deep + scope-safe + disk-bounded by DEFAULT: `-d 5`, `-fs fqdn` (crawl only the exact seeded "
        "hosts — never wander to out-of-scope sibling subdomains found in links), `-or -ob` (omit "
        "body/raw so a deep crawl does not fill the disk), `-ef <static set>`, and JS endpoint crawling "
        "+ jsluice extraction. Override each with one flag; `--keep-bodies` / `--include-static` undo "
        "the disk/asset defaults for a bounded source pass.",
        "Rate is SAFE by default and decoupled from depth: `-rl 10`, hard-capped at 20 req/s (warn + "
        "clamp above; `--allow-fast-crawl` to exceed) and always clamped DOWN to the program rate "
        "ceiling. Go as deep as you like — politeness comes from the rate cap, not a shallow crawl.",
        "Use `-fs rdn` ONLY when every seed root is itself a wildcard-scoped in-scope entry. Recover "
        "wildcard breadth via subdomain-enum + passive gau, NOT by letting the active crawler roam.",
        "A `--timeout` cut still yields usable output: katana streams routes to `-o` from line 1, so a "
        "timed-out deep crawl leaves partial-but-ingestible results on disk (`partial_results=true`).",
    ),
    "tool-help": (
        "Prints a runtime tool's live `-h`/`--help` from inside the container so you read the EXACT "
        "flags the INSTALLED version supports instead of guessing into --extra-args.",
        "Maintenance, not a probe: takes NO --technique/--intent/--probe-kind/--phase/--timeout and "
        "writes no audit row. Usage: `vigil assess kali tool-help katana`.",
    ),
    "sqlmap": (
        "sqlmap's own `--technique` is exposed as `--sql-technique` so it doesn't collide with the audit `--technique` flag.",
    ),
    "arjun": (
        "Hidden-parameter discovery. Pass -u <url> for one endpoint or -i <file> for a gated list (build the list with `vigil assess arjun-select` — never aim Arjun at a raw URL dump or inert assets).",
        "JSON output (-oJ) is ALWAYS written under scans/arjun/<target>/<hash>.json (even alongside -oT/-oB) so the run is captured for `vigil assess ingest-arjun` — the host-side step that folds discovered params into the work buffer and re-routes the parameterized endpoint (url=->gf:ssrf, file=->gf:lfi, id=->gf:idor/sqli).",
        "-m sets the method: GET (default) | POST | XML | JSON. GET-discovered params land in query_params on ingest; POST/XML/JSON in body_params — set it correctly for modern APIs.",
        "--passive harvests param names from wayback/commoncrawl/otx with no/low target traffic. Use first on rate-sensitive or content-heavy targets, or when active discovery is out of budget.",
        "--headers is auth-aware: pass an authenticated session (Authorization/Cookie) to surface params visible only behind auth. Header-only params are recorded as a signal on ingest (no classifier field maps to a header).",
        "Default wordlist is Arjun's db/large.txt (most thorough); override with -w for a faster list. Politeness knobs: --stable, -d (delay), -T (timeout), -t (threads), --rate-limit.",
        "SQLMAP doctrine: Arjun + the classifier ISOLATE the injectable param; sqlmap confirms and does high-volume blind/time-based extraction. When an enriched row routes to gf:sqli (or carries an id=/numeric param on a DB-ish route), ingest-arjun names `vigil assess kali sqlmap` in triage_rationale as the confirmation step. sqlmap is operator-invoked, never auto-fired. See references/tools/recon/arjun.md.",
    ),
    "cero": (
        "TLS-handshake SAN scraper — connects to TCP/TLS on the listed ports and harvests certificate Subject Alternative Names. Complements CT-log enumeration when targets issue private certs.",
        "Feed CIDR ranges (after asnmap CIDR mapping) for non-DNS subdomain discovery; pass --only-cidrs when the input is exclusively CIDR.",
        "Default ports are 443,8443; add 9443/8444/etc. via -p when the target advertises more TLS endpoints.",
        "Read-only TCP/TLS handshakes — leave --destructive off.",
    ),
    "alterx": (
        "Subdomain permutation generator — emits permutation candidates from known subdomains for downstream resolution. Pair with `kali puredns resolve` so the list is wildcard-filtered before DNS spend.",
        "Default uses alterx built-in patterns; pass -p '{{sub}}-{{word}}.{{suffix}}' (repeatable) only when a custom pattern is justified.",
        "Output is a stream of candidate FQDNs; pipe to puredns or write to file via -o.",
    ),
    "asnmap": (
        "ASN/domain/org to CIDR mapper. Feed owned CIDR ranges into `cero` for TLS SAN discovery that CT logs miss.",
        "Pass at least one of -d, -l, -asn, -org; the wrapper rejects empty invocations before running.",
        "Requires PDCP_API_KEY — without it asnmap exits 0 with EMPTY output. The wrapper detects the missing key and fails loud; pass --allow-no-key to override, or use the whois.cymru.com/RADB/RDAP fallback (see references/tools/recon/asnmap.md).",
    ),
    "bbot": (
        "Multi-module recon scanner. Canonical passive subdomain invocation: `bbot -t <target> -p subdomain-enum -rf passive`. Add modules with -m or presets with -p; gate active modules behind --allow-deadly + --destructive.",
        "--allow-deadly requires --destructive — bbot's deadly modules run real attacks (fuzzing, brute-force, exploit). The CLI hard-fails on --allow-deadly without --destructive so the audit row stays truthful.",
        "Passive sweeps (`-p subdomain-enum`) regularly run 15-30 minutes — set --timeout 1800 or wrap in `kali job start`.",
    ),
    "dnsx": (
        "The typed wrapper applies Docker-safe defaults: --dnsx-profile polite-cdn, --resolver-profile public-tcp, -rl 100, -t 20, -retry 3, -timeout 5.",
        "Do lean bulk resolution first (no -resp/-json), then enrich survivors with -resp -json. Unknown-size or bulk -resp/-json list inputs require --allow-bulk-json.",
        "Rate/thread values above polite-residential require --dnsx-profile bursty-ok; above bursty-ok requires --allow-unsafe-rate.",
        "Common record/filter flags are typed (-aaaa, -mx, -txt, -ns, -soa, -ptr, -asn, -cdn, -rcode, -wd). Use --extra-args only for unmodeled dnsx flags that are not guarded load/transport knobs.",
    ),
    "browser": (
        "Headless chromium (selenium) render of one URL inside the runtime. Returns the ORIGIN HTTP status + final rendered DOM (scans/browser/<host>-<id>.html) + a screenshot (scans/browser/<host>-<id>.png) as one JSON object on stdout.",
        "This is the trustworthy-signal recovery for a curl/httpx run that came back status='waf_challenge': a real browser executes the page JS and clears most JS bot-challenges (Cloudflare 'Just a moment', Akamai, Imperva), so you see the real origin response instead of the interstitial.",
        "Use --wait-selector '<css>' to wait for a specific element (explicit wait, bounded by --page-timeout); otherwise it falls back to --settle seconds after load. --page-timeout defaults to 30s, --settle to 2s.",
        "Read-only navigation — leave --destructive off unless you point it at a state-changing URL.",
    ),
    "tlsx": (
        "Bulk TLS cert harvester: opens TLS handshakes against hosts/IPs and pulls SAN/CN/subject-org/issuer fields + JARM/JA3 fingerprints. The SAN/CN harvest expands the subdomain set (private-CA certs that never hit CT logs); the org/issuer + fingerprints drive cert pivoting (siblings sharing a cert/TLS stack).",
        "Pass <host> / -u <host> for one target or -l <file> for a list (hosts/IPs/CIDRs). A bare invocation defaults to the SAN+CN harvest profile (-san -cn -resp-only -silent) — a clean name list for subdomain expansion. Add -so/-cert for issuer/org, -jarm/-ja3 for fingerprint pivoting, -json for the structured per-field form.",
        "Speaks raw TLS, NOT HTTP — it carries no attribution header and is in the required-header SKIP set (parity with nmap). Read-only handshakes: leave --destructive off.",
        "Complements `cero` (also a SAN scraper): tlsx adds structured JSON + JARM/JA3. The Docker per-dest-IP fan-out hazard applies to whole-CIDR feeds — prefer resolved origin/staging IPs (see references/tools/recon/tlsx.md and cero.md).",
    ),
    "dalfox": (
        "Parameter→XSS confirmation. Chain AFTER arjun: arjun isolates the injectable param, dalfox fires reflection-aware payloads and verifies execution (DOM/HTML/attribute context). Pass -u <url> for one target (dalfox `url` mode) or -i <file> for a list (`file` mode); -p <param> focuses dalfox on the arjun-isolated parameter.",
        "Reflective by DEFAULT — no blind/OOB payloads fire unless you pass --blind <callback>, which sends OOB payloads that may persist (stored XSS): pair --blind with --destructive so the audit row is truthful.",
        "WAF-aware: --waf-evasion enables dalfox's evasion mode; --skip-bav drops the basic-another-vuln scan to keep the run focused on XSS. Politeness: --delay (ms), -w workers. dalfox's own request timeout is --dalfox-timeout (renamed to avoid the audit --timeout collision).",
        "dalfox is required-header INJECTABLE (curl-style -H), so a program marker rides every probe automatically; -H/--cookie pass auth so XSS gated behind a session is reachable.",
    ),
    "robots": (
        "Pre-crawl known-file fetch: probes each host for /robots.txt, /sitemap.xml and /.well-known/security.txt BEFORE the katana crawl — Disallow lines + sitemap URLs routinely name admin/staging paths the crawler would otherwise miss. Pass <host>/-u or -l <list>; override the set with --paths.",
        "SCOPE is the marginal pre-crawl fetch ONLY. katana's own -kf (known-files) flag already expands robots/sitemap/well-known DURING the crawl (kali_katana.py) — run robots first for the high-signal seed, then crawl; do not treat -kf as redundant.",
        "Engine is httpx (tool_bin=httpx in the audit row) probing the well-known paths, so it inherits httpx's required-header injection + scope posture. -mc defaults to 200,301,302,401,403 so a gated-but-present file (401/403) still surfaces. Read-only GETs: leave --destructive off.",
    ),
    "gf": (
        "Pattern-bucket a URL corpus by vuln-param family (ssrf/idor/sqli/lfi/redirect/xss/...). Sends NO target traffic — a pure local text filter — so it is a MAINTENANCE verb: it takes NO --technique/--intent/--probe-kind/--phase/--timeout and writes no audit row.",
        "Complements (does not replace) the inline `assess.lib.classify_buckets` classifier, which is the source-of-truth applied automatically at ingest. Reach for `kali gf` for ad-hoc triage of a corpus on disk you have not ingested, or to cross-check one bucket against the upstream gf pattern library.",
        "Usage: `vigil assess kali gf <pattern> -i <urls-file> [-o <out>]`; `--list` enumerates the installed patterns. The corpus is read host-side and piped over `docker exec -i` to gf in the runtime (no container-path translation).",
    ),
    "exec": (
        "Use only when no typed verb fits. Tool-name attribution falls back to argv[0] for audit recording.",
    ),
    "job": (
        "Long-running probes go through `vigil assess kali job start ...`. The dtach session is parented by tini so it survives the calling shell.",
        "Subcommands: start | status | tail | stop | list.",
    ),
    "sweep-orphans": (
        "Host-side reconciler for `assessment_command_runs` rows stuck in status=running past --max-age-seconds. Run after a backend restart, host crash, or any window where finalize PATCHes may have failed.",
        "Liveness probe: `docker exec <container> kill -0 <pid>` against the wrapper-recorded pid file at /tmp/vigil-pid-<run_uuid>.pid. run_uuid comes from the row's run_uuid column (stdout_path parsing kept only for older rows).",
        "PID alive -> left alone (still-running). PID dead OR pid file missing -> finalized to status=lost via PATCH command-runs/{id}.",
        "Rows are skipped when Docker probing itself fails, since the command cannot distinguish a live job from an unavailable liveness check.",
        "--scope {command-runs|jobs|all} (default command-runs): `jobs` also reconciles stuck assessment_jobs rows (the async dtach-job lifecycle). For jobs the host-readable exit marker is authoritative (marker present -> completed/failed with its real exit code); PID gone with no marker -> lost. This converges any job the agent was killed before it could poll to completion.",
        "Use --dry-run first to inspect candidates without writing — a thorough sweep is cheap, an incorrect finalize is not.",
        "Unlike target-facing verbs, sweep-orphans takes no --technique/--intent/--probe-kind/--phase/--timeout — it is maintenance, not a probe.",
    ),
}


_KALI_VERB_EXAMPLES: dict[str, tuple[dict[str, Any], ...]] = {
    "nmap-scan": (
        {
            "command": "vigil assess kali nmap-scan --target example.com --ports top-1000 --service-detection --technique RECON --intent 'Phase 1 baseline port + service' --probe-kind fingerprint --phase recon --timeout 1800",
        },
    ),
    "nuclei": (
        {
            "command": "vigil assess kali nuclei -l hosts.txt -t http/cves/,http/misconfiguration/,http/exposures/ -severity high,critical -mhe 50 -random-agent -rate-limit 50 -c 25 -bs 25 -jsonl -o scans/nuclei.jsonl --technique RECON --intent 'reactive sweep on Phase-1 URL delta (WAF-resilient)' --probe-kind fingerprint --phase recon --timeout 1800",
        },
    ),
    "katana": (
        {
            "command": "vigil assess kali katana -u https://target.example -o scans/katana_target.jsonl -jsonl --technique DISCOVERY --intent 'deep JS-aware scoped crawl' --probe-kind fingerprint --phase collect --timeout 1800",
        },
        {
            "command": "vigil assess kali katana -u https://app.target.example -headless --allow-fast-crawl -rl 40 -o scans/katana_spa.jsonl -jsonl --technique DISCOVERY --intent 'headless crawl for browser-generated routes' --probe-kind fingerprint --phase collect --timeout 1800",
        },
    ),
    "tool-help": (
        {
            "command": "vigil assess kali tool-help katana",
        },
    ),
    "sqlmap": (
        {
            "command": "vigil assess kali sqlmap -u 'https://target/?id=1' --batch --sql-technique BEUSTQ --level 3 --risk 2 --technique SQLI --intent 'verify SQLi on id parameter' --probe-kind payload --phase consume-test --timeout 1800",
        },
    ),
    "arjun": (
        {
            "command": "vigil assess kali arjun -u https://target/api/item --technique DISCOVERY --intent 'hidden GET param discovery on item endpoint' --probe-kind fingerprint --phase consume-test --timeout 1800",
        },
        {
            "command": "vigil assess kali arjun -i /engagements/$ENGAGEMENT_KEY/scans/arjun/targets.txt.JSON -m JSON --headers $'Authorization: Bearer TOKEN' --stable --rate-limit 10 --technique DISCOVERY --intent 'authed JSON-API hidden-param discovery on gated route list' --probe-kind fingerprint --phase consume-test --timeout 3600",
        },
        {
            "command": "vigil assess kali arjun -u https://target/search --passive --technique OSINT --intent 'passive param-name harvest (wayback/otx/commoncrawl)' --probe-kind fingerprint --phase recon --timeout 600",
        },
    ),
    "cero": (
        {
            "command": "vigil assess kali cero -d 198.51.100.0/24 -p 443,8443,9443 -c 100 -t 4 -o /engagements/$ENGAGEMENT_KEY/scans/cero_sans.txt --technique OSINT --intent 'TLS SAN scraping for non-CT subs' --probe-kind fingerprint --phase recon --timeout 600",
        },
    ),
    "alterx": (
        {
            "command": "vigil assess kali alterx -l /engagements/$ENGAGEMENT_KEY/scans/subs_passive.txt -limit 200000 -o /engagements/$ENGAGEMENT_KEY/scans/perms.txt --technique RECON --intent 'permutation candidate generation from passive subs' --probe-kind fingerprint --phase recon --timeout 600",
        },
    ),
    "asnmap": (
        {
            "command": "vigil assess kali asnmap -d example.com -silent -o /engagements/$ENGAGEMENT_KEY/scans/asnmap_cidrs.txt --technique OSINT --intent 'map target-owned CIDRs for TLS SAN sweep' --probe-kind fingerprint --phase recon --timeout 600",
        },
    ),
    "bbot": (
        {
            "command": "vigil assess kali bbot -t example.com -p subdomain-enum -rf passive -o /engagements/$ENGAGEMENT_KEY/scans/bbot_subs --technique OSINT --intent 'deep passive subdomain enum' --probe-kind fingerprint --phase recon --timeout 1800",
        },
    ),
    "dnsx": (
        {
            "command": "vigil assess kali dnsx -l /engagements/$ENGAGEMENT_KEY/scans/candidates.txt --dnsx-profile polite-cdn --resolver-profile public-tcp -silent -o /engagements/$ENGAGEMENT_KEY/scans/candidates_resolved.txt --technique RECON --intent 'lean dnsx resolution without bulk JSON' --probe-kind baseline --phase recon --timeout 1200",
        },
    ),
    "browser": (
        {
            "command": "vigil assess kali browser https://app.target.example/login --technique RECON --intent 'headless render of WAF-flagged login surface' --probe-kind baseline --phase recon --timeout 120",
        },
        {
            "command": "vigil assess kali browser https://app.target.example/dashboard --wait-selector '#root' --page-timeout 45 --screenshot scans/browser/dash.png --technique RECON --intent 'render SPA dashboard after auth' --probe-kind baseline --phase consume-test --timeout 180",
        },
    ),
    "tlsx": (
        {
            "command": "vigil assess kali tlsx -l /engagements/$ENGAGEMENT_KEY/scans/live_hosts.txt -san -cn -resp-only -silent -o /engagements/$ENGAGEMENT_KEY/scans/tlsx_sans.txt --technique RECON --intent 'TLS SAN/CN harvest for subdomain expansion' --probe-kind fingerprint --phase recon --timeout 600",
        },
        {
            "command": "vigil assess kali tlsx -u origin.target.example -cert -jarm -json -o /engagements/$ENGAGEMENT_KEY/scans/tlsx_origin.json --technique OSINT --intent 'issuer + JARM fingerprint for cert pivoting' --probe-kind fingerprint --phase recon --timeout 300",
        },
    ),
    "dalfox": (
        {
            "command": "vigil assess kali dalfox -u 'https://target.example/search?q=test' -p q --skip-bav --silence -o scans/dalfox_q.txt --technique XSS --intent 'confirm reflected XSS on arjun-surfaced q param' --probe-kind payload --phase consume-test --timeout 1800",
        },
        {
            "command": "vigil assess kali dalfox -i /engagements/$ENGAGEMENT_KEY/scans/arjun_xss_candidates.txt --waf-evasion -w 30 --delay 100 --format json -o scans/dalfox_batch.json --technique XSS --intent 'reflective XSS sweep over arjun param-bearing URLs (WAF-aware)' --probe-kind payload --phase consume-test --timeout 3600",
        },
    ),
    "robots": (
        {
            "command": "vigil assess kali robots -l /engagements/$ENGAGEMENT_KEY/scans/live_hosts.txt -o scans/robots_known_files.txt --technique RECON --intent 'pre-crawl robots/sitemap/security.txt fetch for high-signal path seeds' --probe-kind fingerprint --phase recon --timeout 300",
        },
    ),
    "job": (
        {
            "command": "vigil assess kali job start --technique CVE-VALIDATION --intent 'long nuclei sweep' --probe-kind fingerprint --phase recon --timeout 21600 -- nuclei -l targets.txt -t http/cves/",
        },
        {
            "command": "vigil assess kali job status 42",
        },
    ),
    "sweep-orphans": (
        {
            "command": "vigil assess kali sweep-orphans --dry-run",
        },
        {
            "command": "vigil assess kali sweep-orphans --max-age-seconds 1800 --container-name vigil",
        },
        {
            "command": "vigil assess kali sweep-orphans --scope all --dry-run",
        },
    ),
    "gf": (
        {
            "command": "vigil assess kali gf ssrf -i /engagements/$ENGAGEMENT_KEY/scans/gau_target.txt -o /engagements/$ENGAGEMENT_KEY/scans/gf_ssrf.txt",
        },
        {
            "command": "vigil assess kali gf --list",
        },
    ),
}


# Engagement phase(s) where each kali verb is meaningful, drawn from the
# canonical CATALOG_PHASES / kali_audit.ALLOWED_PHASES vocabulary. Same
# shape/location as _KALI_VERB_NOTES / _KALI_VERB_EXAMPLES: consumed by
# `_kali_verb_contract` to stamp `CommandContract.phase`, which drives
# `vigil assess list-commands --phase <N>`. An empty tuple marks a
# phase-agnostic verb (raw runners + host-side maintenance that run in any
# phase); a verb absent from this map defaults to phase-agnostic too.
_KALI_VERB_PHASES: dict[str, tuple[str, ...]] = {
    # --- target-facing probes ---
    "nmap-scan": ("recon",),
    "nuclei": ("recon", "collect"),
    "httpx": ("recon", "collect"),
    "wafw00f": ("recon",),
    "ffuf": ("collect", "consume-test"),
    "sqlmap": ("consume-test",),
    "subfinder": ("recon", "recon-pivot"),
    "puredns": ("recon", "recon-pivot"),
    "dnsx": ("recon", "recon-pivot"),
    "nikto": ("collect", "consume-test"),
    "katana": ("collect",),
    "gau": ("recon", "collect"),
    "arjun": ("recon", "consume-test"),
    "whatweb": ("recon",),
    "cero": ("recon", "recon-pivot"),
    "alterx": ("recon", "recon-pivot"),
    "asnmap": ("recon", "recon-pivot"),
    "bbot": ("recon",),
    "browser": ("recon", "consume-test", "exploit-recon"),
    "tlsx": ("recon", "recon-pivot"),
    "dalfox": ("consume-test",),
    "robots": ("recon",),
    # exec + job are raw/long-running runners usable in any phase.
    "exec": (),
    "job": (),
    # --- host-side maintenance (no target traffic, any phase) ---
    "sweep-orphans": (),
    "tool-help": (),
    "gf": (),
}


def _kali_root_contract() -> CommandContract:
    return CommandContract(
        name="kali",
        summary="Run Kali tools inside the runtime container with audit recording.",
        schema_name="(per-verb argparse + CommandRunRecordRequest backend model)",
        preferred_invocations=(
            "vigil assess kali <verb> [flags]",
            "vigil assess kali --help",
            "vigil assess contract kali <verb>",
        ),
        author_supplied_fields=(
            "--technique <enum>",
            "--intent \"<one-line purpose>\"",
            "--probe-kind {fingerprint|baseline|payload|exploit|replay|cleanup}",
            "--phase <enum>",
            "--timeout <seconds>",
        ),
        notes=_KALI_COMMON_NOTES + (
            f"Target-facing verbs (require the audit-flag set above): "
            f"{', '.join(KALI_TARGET_VERBS)}.",
            f"Host-side maintenance verbs (no audit flags — they do not touch "
            f"the target): {', '.join(KALI_MAINT_VERBS)}.",
        ),
        common_mistakes=_KALI_COMMON_MISTAKES,
        examples=(
            {"command": "vigil assess kali nmap-scan --target example.com --ports top-100 --technique RECON --intent 'fast top-100 sweep' --probe-kind fingerprint --phase recon --timeout 600"},
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
            phase=_KALI_VERB_PHASES.get(verb, ()),
            summary=(
                "Reconcile assessment_command_runs rows stuck in status=running "
                "past a threshold age by probing the in-container PID and "
                "finalizing dead rows to status=lost."
            ),
            schema_name="argparse + CommandRunFinalize backend model",
            preferred_invocations=(
                "vigil assess kali sweep-orphans --dry-run",
                "vigil assess kali sweep-orphans --max-age-seconds 3600",
                "vigil assess kali sweep-orphans --container-name vigil",
                "vigil assess kali sweep-orphans --scope jobs",
            ),
            author_supplied_fields=(
                "--max-age-seconds <int> (default 3600)",
                "--container-name <name> (default vigil)",
                "--scope {command-runs|jobs|all} (default command-runs)",
                "--dry-run (optional, list candidates without writing)",
            ),
            notes=_KALI_VERB_NOTES.get(verb, ()),
            common_mistakes=(
                ("--phase", "sweep-orphans is host-side maintenance and does not take audit flags"),
                ("--technique", "sweep-orphans is host-side maintenance and does not take audit flags"),
            ),
            examples=examples,
        )

    if verb == "tool-help":
        return CommandContract(
            name="kali tool-help",
            phase=_KALI_VERB_PHASES.get(verb, ()),
            summary=(
                "Print a runtime tool's live -h/--help from inside the container "
                "so you read the EXACT flags the installed version supports."
            ),
            schema_name="argparse (no backend audit row)",
            preferred_invocations=(
                "vigil assess kali tool-help katana",
                "vigil assess kali tool-help nuclei --help-flag --help",
            ),
            author_supplied_fields=(
                "<tool> (positional, e.g. katana)",
                "--help-flag <flag> (optional; default tries -h then --help)",
                "--container-name <name> (optional; default the runtime container)",
            ),
            notes=_KALI_VERB_NOTES.get(verb, ()),
            common_mistakes=(
                ("--phase", "tool-help is host-side maintenance and does not take audit flags"),
                ("--technique", "tool-help is host-side maintenance and does not take audit flags"),
            ),
            examples=examples,
        )

    if verb == "gf":
        return CommandContract(
            name="kali gf",
            phase=_KALI_VERB_PHASES.get(verb, ()),
            summary=(
                "Pattern-bucket a URL corpus by vuln-param family (ssrf/idor/sqli/"
                "lfi/redirect/xss/...). A local text filter — sends no target "
                "traffic, so no audit flags. Complements (does not replace) the "
                "inline assess.lib.classify_buckets classifier applied at ingest."
            ),
            schema_name="argparse (docker exec gf; no backend audit row)",
            preferred_invocations=(
                "vigil assess kali gf <pattern> -i <urls-file> -o <out-file>",
                "vigil assess kali gf ssrf -i scans/gau_target.txt -o scans/gf_ssrf.txt",
                "vigil assess kali gf --list",
            ),
            author_supplied_fields=(
                "<pattern> (positional, e.g. ssrf | idor | sqli | lfi | redirect | xss)",
                "-i / --input <url-file> (the corpus to bucket)",
                "-o / --output <file> (optional; default stdout)",
                "--list (optional, enumerate installed patterns)",
                "--container-name <name> (optional; default the runtime container)",
            ),
            notes=_KALI_VERB_NOTES.get(verb, ()),
            common_mistakes=(
                ("--phase", "gf is a local filter (no target traffic) and does not take audit flags"),
                ("--technique", "gf is a local filter (no target traffic) and does not take audit flags"),
                ("expecting gf to replace the inline classifier", "the classify_buckets classifier runs automatically at ingest; gf is for ad-hoc on-disk triage"),
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
        "tool-specific flags (see `vigil assess kali "
        + verb
        + " --help`)",
    )
    # `exec` and `job` are raw-passthrough wrappers; they do not expose the
    # typed-verb `--extra-args` flag because every argument after the audit
    # metadata is already raw passthrough. `browser` drives a self-contained
    # selenium script (its argv is a fixed `python3 -c <driver> ...` shape), so
    # appending raw tool flags is meaningless — it has its own typed render flags.
    if verb not in ("exec", "job", "browser"):
        author_fields = author_fields + (
            "--extra-args \"<raw flags>\" (optional, shlex-split passthrough for long-tail flags)",
        )
    return CommandContract(
        name=f"kali {verb}",
        phase=_KALI_VERB_PHASES.get(verb, ()),
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
            f"vigil assess record-intel {intel_type} {intel_type}.json",
        ),
        author_supplied_fields=tuple(author_fields),
        notes=(
            f"Posts to /intel/{endpoint_segment}. Use the helper, not raw post, so local schema validation catches payload drift first.",
            "Intel schemas are strict: a field not listed under Allowed top-level fields is rejected before the backend is contacted.",
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
# Agent / work-buffer command contracts
#
# Work-buffer primitives (stats, fetch, done, …) are documented inline on
# ``vigil assess work-buffer``. Contract entries advertise backend-backed agent
# lifecycle helpers plus ``render-handoff``, whose markdown output is pasted into
# the next dispatch prompt.
# ---------------------------------------------------------------------------

# Agent lifecycle sub-verbs that have their own contract entry. The Contract-First
# Rule directs operators to read these before first use, and the
# `vigil assess contract` resolver uses this tuple to advertise what is
# discoverable. Read-only sub-verbs (`list`, `get`) are intentionally absent
# because they do not mutate state and have nothing to validate.
AGENT_VERBS: tuple[str, ...] = (
    "render-handoff",
    "start",
    "done",
    "close",
    "reconcile-stale",
    "abort-duplicate",
    "decision",
    "handoff",
)


def _dispatch_root_contract() -> CommandContract:
    return CommandContract(
        name="agent",
        summary=(
            "Backend agent lifecycle helpers (start / done / list / get / decision / "
            "handoff / render-handoff for cross-dispatch continuity)."
        ),
        schema_name="(per-action argparse; backend-backed via assessment_dispatches / _dispatch_handoffs / _dispatch_decisions)",
        preferred_invocations=(
            "vigil assess agent start --role <role> --task \"...\" --dispatch-mode <mode> --skills <skills>",
            "vigil assess agent done <agent-id> --finding-slugs <slug1,slug2>",
            "vigil assess agent handoff --agent-id <id> --role <role> --summary '...' --handoff-status ready",
            "vigil assess agent close <agent-id>",
            "vigil assess agent reconcile-stale --dry-run",
            "vigil assess agent list [--filter-role <role>] [--status <status>]",
            "vigil assess agent render-handoff <agent-id>",
            "vigil assess work-buffer <db_path> stats|fetch|done|...",
        ),
        author_supplied_fields=(
            "<action> (e.g. start, done, handoff, render-handoff, decision, ...)",
            "action-specific positional args",
        ),
        notes=(
            "Work-buffer actions live under `vigil assess work-buffer <db_path> ...`; "
            "agent lifecycle actions never take a cases.db path.",
            "Dispatch state lives in the orchestrator backend. `agent start` logs a dispatch, "
            "`agent done` patches lifecycle directly, `agent handoff` writes a repeatable checkpoint, `agent close` consumes a ready/blocked handoff into closure, and `agent render-handoff` assembles the blob the next dispatch prompt pastes verbatim.",
            "`agent start` defaults a missing --dispatch-mode from the role (warn, not block) and accepts a newly-coined mode (advisory warn). "
            "Pass --allow-no-skills to proceed for an ad-hoc role with no --skills (warn, not error), and --check-overlap to opt into the advisory in-progress-overlap scan.",
            f"Verbs with their own contract entries: {', '.join(AGENT_VERBS)}.",
        ),
        common_mistakes=(
            (
                "transcript paste",
                "use `vigil assess agent render-handoff <prior-agent-id>` and paste the "
                "rendered blob verbatim — it pulls findings, artifacts, and credentials "
                "from durable state so the prompt stays small",
            ),
            (
                "stale local DB syntax",
                "backend dispatch actions use `vigil assess agent handoff ...`; "
                "`vigil assess work-buffer cases.db handoff ...` is rejected so handoffs "
                "cannot land on the wrong state surface",
            ),
            (
                "defer-items <ids> with stale id list",
                "`defer-items` exits 1 (not 0) when zero rows match — by design, so a typo "
                "or already-processed id list surfaces loudly. `reset-stale` first if the "
                "rows you meant to defer are now in `processing`.",
            ),
        ),
    )


def _work_buffer_contract() -> CommandContract:
    return CommandContract(
        name="work-buffer",
        summary="Operate on the local cases.db work-buffer queue.",
        schema_name="local cases.db work_items schema",
        preferred_invocations=(
            "vigil assess work-buffer <cases.db> stats --by status|source|cluster|host",
            "vigil assess work-buffer <cases.db> peek <type> [limit]",
            "vigil assess work-buffer <cases.db> fetch <type> <limit> <agent-name>",
            "vigil assess work-buffer <cases.db> fetch-by-priority <limit> auto",
            "vigil assess work-buffer <cases.db> done <id1,id2,...>",
            "vigil assess work-buffer <cases.db> defer-cluster <cluster_key> --reason \"...\"",
        ),
        author_supplied_fields=(
            "<cases.db>",
            "<action>",
            "action-specific item ids, type, limit, agent name, or reason",
        ),
        notes=(
            "Work-buffer rows are local batching state, NOT backend agent lifecycle rows. "
            "Use `vigil assess agent …` for backend dispatch rows, handoffs, and decisions.",
            "Mark items done only after the specialist has written durable backend state "
            "(findings, surfaces, probe runs, or coverage) for the work.",
        ),
        common_mistakes=(
            ("using agent handoff syntax here", "`work-buffer` never records handoffs; use `vigil assess agent handoff`"),
            ("reading cases.db directly", "use the helper so migrations, status transitions, and terminal_reason semantics stay consistent"),
        ),
    )


def _dispatch_verb_contract(verb: str) -> CommandContract | None:
    if verb == "render-handoff":
        return CommandContract(
            name="agent render-handoff",
            summary=(
                "Render a bounded handoff blob for a prior dispatch's agent_id, "
                "pulled from the assessment backend (dispatch + handoff rows) plus "
                "per-slug finding fetches."
            ),
            schema_name="(reads GET dispatch-handoffs/{agent_id} + GET dispatches/{agent_id} + GET findings/{slug})",
            preferred_invocations=(
                "vigil assess agent render-handoff <agent-id>",
                "vigil assess agent render-handoff <agent-id> --max-lines 60",
                "vigil assess agent render-handoff <agent-id> --include-evidence",
            ),
            author_supplied_fields=(
                "<agent-id> (the prior dispatch's agent_id from `vigil assess agent list`)",
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
                "Exits 2 when no handoff exists for the agent-id (404 on dispatch-handoffs/{agent_id}) — the dispatch never wrote one, or the id is mistyped. Specialists are expected to write a handoff before exiting.",
                "A 404 on a finding slug renders inline as 'slug missing in backend' (distinct from 'fetch error: <reason>') instead of failing the whole render — the operator may have killed the finding between dispatch and handoff.",
                "The dispatch row is fetched best-effort; when missing, the renderer falls back to the handoff row's metadata.",
                "Cross-reference: agent/operator-core.md 'Cross-Dispatch Continuity'.",
            ),
            common_mistakes=(
                (
                    "transcript excerpts in dispatch prompt",
                    "paste render-handoff output instead of copy-pasting from the prior agent's transcript",
                ),
                (
                    "raising --max-lines past ~80",
                    "the cap keeps the prompt bounded — if the blob is too small, narrow the registry's finding_slugs list rather than widening the cap",
                ),
            ),
            examples=(
                {
                    "command": "vigil assess agent render-handoff a424a88b02054913d",
                },
                {
                    "command": "vigil assess agent render-handoff a424a88b02054913d --max-lines 60 --include-evidence",
                },
            ),
        )
    if verb in {"register", "start"}:
        return CommandContract(
            name="agent start",
            summary=(
                "Register a specialist dispatch in the backend audit ledger so the "
                "row carries role, task, scope, requested model/reasoning, dispatch-mode, and the skills "
                "the agent loaded."
            ),
            schema_name="backend DispatchCreate (POST /dispatches)",
            preferred_invocations=(
                "vigil assess agent start --agent-id <id> --role <role> "
                "--task \"...\" --scope-host <host> --model <name> --reasoning <level> "
                "--dispatch-mode <mode> --skills \"<skill>[,<skill>...]\"",
                "vigil assess agent start --from-json <payload.json>",
            ),
            author_supplied_fields=(
                "--agent-id (unique per dispatch)",
                "--role (specialist role; operator role is reserved for phase coordination)",
                "--dispatch-mode (hypothesis-driven|item-iterating|deep-manual|variant-rotation)",
                "--skills (comma-separated; required for non-operator roles)",
                "--task (one-line objective)",
            ),
            helper_defaults=(
                ("status", "in-progress (set on insert)"),
                ("dispatched_at", "now() when omitted"),
                ("--allow-duplicate", "off — overlapping in-progress dispatches log a warning"),
            ),
            notes=(
                "Specialist dispatches must include `skills`: the backend rejects them otherwise, and the CLI runs the same check locally before sending so typos surface early.",
                "Discover skill names with `vigil assess list-skills` — each value must match a directory under `agent/skills/<name>/`.",
                "Pair with `agent done` when the dispatch finishes; rows left `in-progress` past the dispatch's actual lifetime corrupt dedup checks.",
            ),
            common_mistakes=(
                ("role", "use --role for the agent command; the backend stores agent_role"),
                ("operator role with --skills", "operator dispatches are exempt from the skills requirement; pass --skills only for specialist roles"),
                ("--skills agent/skills/foo/SKILL.md", "pass the bare skill name (e.g. 'gau-triage'); the validator resolves it on disk"),
            ),
            examples=(
                {
                    "command": (
                        "vigil assess agent start --agent-id va-7f3 "
                        "--role vulnerability-analyst --task 'review SSRF candidates' "
                        "--scope-host api.example.com --model claude-opus-4-8 "
                        "--reasoning high --dispatch-mode item-iterating "
                        "--skills 'ssrf-testing,case-dispatching'"
                    ),
                },
            ),
        )
    if verb in {"update-status", "done"}:
        return CommandContract(
            name="agent done",
            summary="Patch the lifecycle status (and optionally finding_slugs / completed_at) of a registered dispatch row.",
            schema_name="backend DispatchUpdate (PATCH /dispatches/{agent_id})",
            preferred_invocations=(
                "vigil assess agent done <agent-id> --status completed --finding-slugs <slug1,slug2>",
                "vigil assess agent done <agent-id> --status failed",
                "vigil assess agent done <agent-id> --status aborted",
            ),
            author_supplied_fields=(
                "<agent-id>",
                "--status (in-progress|completed|failed|aborted|blocked)",
            ),
            helper_defaults=(
                ("--completed-at", "now() when --status is terminal and the flag is omitted"),
                ("--finding-slugs", "appended additively to the row, not replaced"),
            ),
            notes=(
                "Call when a dispatch returns so cross-dispatch dedup, reporting, and the audit trail see the actual outcome.",
                "Pair `--status completed --finding-slugs <slugs>` so the row names the slugs the specialist produced; `vigil assess agent render-handoff` reads from there.",
            ),
            common_mistakes=(
                ("status=done", "status enum is in-progress / completed / failed / aborted / blocked — 'done' is rejected"),
                ("missing finding-slugs on completed run", "the slug list is what links the dispatch to its produced findings; missing it means the next operator cannot trace what came out"),
            ),
            examples=(
                {
                    "command": "vigil assess agent done va-7f3 --status completed --finding-slugs VA-001,VA-002",
                },
            ),
        )
    if verb == "close":
        return CommandContract(
            name="agent close",
            summary="Consume the latest ready/blocked handoff and close the matching dispatch row.",
            schema_name="GET dispatch-handoffs/{agent_id} + PATCH dispatches/{agent_id} + decision-record",
            preferred_invocations=(
                "vigil assess agent close <agent-id>",
                "vigil assess agent close <agent-id> --reason \"ready handoff reviewed\"",
            ),
            author_supplied_fields=(
                "<agent-id>",
                "--reason",
            ),
            notes=(
                "Use after a specialist checkpoint marks handoff_status=ready or blocked. Checkpointed handoffs stay open.",
                "Records a dispatch_closed_from_handoff decision row so automated/stale closure stays auditable.",
            ),
        )
    if verb == "reconcile-stale":
        return CommandContract(
            name="agent reconcile-stale",
            summary="List stale in-progress dispatches and optionally close those with ready/blocked handoffs.",
            schema_name="GET dispatches + GET dispatch-handoffs",
            preferred_invocations=(
                "vigil assess agent reconcile-stale --dry-run",
                "vigil assess agent reconcile-stale --max-age-hours 12 --dry-run",
            ),
            author_supplied_fields=(
                "--max-age-hours",
                "--dry-run",
            ),
            notes=(
                "Dry-run is the review surface: it groups stale rows by handoff availability/status.",
                "Without --dry-run, only ready/blocked handoffs are closable; checkpointed or missing handoffs remain in-progress.",
            ),
        )
    if verb in {"record-handoff", "handoff"}:
        return CommandContract(
            name="agent handoff",
            summary=(
                "Persist a specialist's structured exit handoff (summary, next steps, "
                "coverage gaps, runtime issues, working artifacts) into the backend "
                "audit ledger so the next dispatch can render it."
            ),
            schema_name="backend handoff-record (POST /dispatch-handoffs, idempotent upsert)",
            preferred_invocations=(
                "vigil assess agent handoff --from-json <handoff.json>",
                "vigil assess agent handoff --agent-id <id> --role <role> "
                "--summary \"...\" --handoff-status ready --next-step \"...\" --coverage-gap \"<area>: <reason>\"",
            ),
            author_supplied_fields=(
                "--agent-id",
                "--role",
                "--summary (≤2000 chars; required)",
                "structured payload via --from-json OR repeated --next-step / --coverage-gap / --runtime-issue / --working-artifact / --open-question",
            ),
            helper_defaults=(
                ("upsert", "POST then PATCH on 409 — the operation is idempotent so checkpointing is safe"),
                ("handoff_status", "checkpointed unless --handoff-status is supplied"),
                ("confidence", "omitted when not specified"),
            ),
            notes=(
                "Specialists call this from their closing sequence before exiting; the row is then the canonical 'what was done, what's missing, what's next' record for the dispatch.",
                "`render-handoff <agent-id>` reads this row, fetches each named finding, and emits the bounded markdown blob the next dispatch pastes.",
                "JSON payload schema: agent/references/runtime-guides/handoff-schema.md.",
            ),
            common_mistakes=(
                ("transcript paste in summary", "summary is 2000 chars and bounded — use coverage_gaps / next_steps / runtime_issues for structured continuation, not a transcript dump"),
                ("missing recommended_next_agent", "without it, the operator has to re-derive who picks up; set it from the specialist's perspective"),
            ),
            examples=(
                {
                    "command": (
                        "vigil assess agent handoff --agent-id va-7f3 "
                        "--role vulnerability-analyst "
                        "--summary 'SSRF candidates triaged; 2 confirmed, 1 deferred for OOB' "
                        "--next-step 'Validate confirmed findings against staging' "
                        "--coverage-gap 'admin-panel: requires auth refresh'"
                    ),
                },
            ),
        )
    if verb in {"record-decision", "decision"}:
        return CommandContract(
            name="agent decision",
            summary=(
                "Record a structured operator decision (scope, egress reputation, "
                "dispatch-blocked, vendor-SaaS gate, etc.) into dispatch_decisions for audit."
            ),
            schema_name="backend decision-record (POST /dispatch-decisions)",
            preferred_invocations=(
                "vigil assess agent decision --kind scope_decision --host <host> --vendor <vendor> --choice pending --surfaced-to-user",
                "vigil assess agent decision --kind egress_decision --payload-json '{\"choice\": \"browser-based-tool\", \"egress_block_pct\": 67}'",
                "vigil assess agent decision --kind dispatch_blocked --phase recon --reason \"missing massdns binary in runtime image\" --surfaced-to-user",
            ),
            author_supplied_fields=(
                "--kind (scope_decision|egress_decision|dispatch_blocked|... — the backend accepts any string but report-writer only renders known kinds)",
                "--payload-json OR shorthand flags (--host / --vendor / --choice / --note / --reason / --phase) that build the payload dict",
                "--surfaced-to-user (set when the operator presented the decision to the human; controls whether it appears in user-visible logs)",
            ),
            helper_defaults=(
                ("payload", "constructed from --host/--vendor/--choice/--note/--reason/--phase when --payload-json is omitted"),
                ("surfaced_to_user", "false unless --surfaced-to-user is set"),
            ),
            notes=(
                "Vendor-SaaS scope warnings, egress-block decisions, and dispatch-blocked rows all share this table — keep the --kind taxonomy disciplined so report-writer can summarize by kind.",
                "Set --surfaced-to-user for operator-facing decisions (vendor-SaaS, egress reputation, blocked dispatch) so the human-visible audit log matches what the operator was shown.",
            ),
            common_mistakes=(
                ("freeform reason in --kind", "kinds are vocabulary; put the prose in --note or --reason"),
                ("missing --surfaced-to-user", "user-facing decisions invisible to audit defeats the purpose; set the flag whenever the operator showed the gate to the human"),
            ),
            examples=(
                {
                    "command": (
                        "vigil assess agent decision --kind scope_decision "
                        "--host api.foo.com --vendor 'Vendor SaaS' --choice pending "
                        "--surfaced-to-user"
                    ),
                },
            ),
        )
    if verb == "abort-duplicate":
        return CommandContract(
            name="agent abort-duplicate",
            summary=(
                "Mark an accidentally-duplicated specialist dispatch as aborted and "
                "record a `dispatch_duplicate` decision pointing at the replacement."
            ),
            schema_name="backend DispatchUpdate (PATCH /dispatches/{agent_id}) + decision-record (POST /dispatch-decisions)",
            preferred_invocations=(
                "vigil assess agent abort-duplicate <agent-id> --replacement-agent-id <new-id> --reason \"<text>\"",
            ),
            author_supplied_fields=(
                "<agent-id> (the duplicate to abort)",
                "--replacement-agent-id (the active dispatch that replaces it)",
                "--reason (free text; goes into the decision payload)",
            ),
            helper_defaults=(
                ("status", "aborted"),
                ("completed_at", "now() at the time the abort runs"),
            ),
            notes=(
                "Use instead of `agent done` when the duplicate was noticed AFTER register, so audit retains both the bad row (now aborted) and a paired decision row pointing at the replacement.",
                "`--replacement-agent-id` must already exist in the dispatch registry; the helper checks before aborting so a typo cannot leave the duplicate pointing at a missing canonical dispatch.",
            ),
            common_mistakes=(
                ("aborting the wrong direction", "abort the DUPLICATE id and point --replacement-agent-id at the row you want to keep — flipping these orphans the active dispatch"),
            ),
            examples=(
                {
                    "command": "vigil assess agent abort-duplicate va-bad --replacement-agent-id va-good --reason 'start fired twice — the second one is canonical'",
                },
            ),
        )
    return None
