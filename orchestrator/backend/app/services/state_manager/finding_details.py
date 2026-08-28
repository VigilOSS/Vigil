"""Canonical vocabulary for the finding ``details`` blob, and its enforcement.

``details`` is stored as an open JSON column, so the allow-list is the only thing
that keeps it a contract rather than a junk drawer. It used to be enforced in the
CLI alone, and only on two of the three write verbs — so a key ``finding verify``
happily created was refused by ``finding update``, and evidence was *creatable but
not maintainable*. The vocabulary therefore lives here, beside the enforcement,
and ``scripts/generate_agent_schemas.py`` renders it into
``agent/schemas/finding-record.schema.json`` so the client-side validator is a
projection of the server rule instead of a second copy of it.
"""

from __future__ import annotations

from typing import Any

from fastapi import HTTPException, status

FINDING_DETAIL_PROPERTIES: dict[str, dict[str, Any]] = {
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
        # 0.0 is a real, reachable score: an all-N vector computes to it, and it
        # is the ONLY score the `info` severity band (< 0.1) can hold. Excluding
        # it made an informational finding unrepresentable and pushed authors to
        # a 0.1 fudge that trips both the severity<->CVSS and vector<->score
        # readiness blockers at once.
        "minimum": 0,
        "maximum": 10,
        "description": "CVSS 3.1 base score (0.0-10.0). Must match cvss_vector.",
    },
    "remediation": {
        "type": "string",
        "description": "Specific fix or missing control (e.g. 'Use parameterized queries', 'Add bounds check on schemelen before memcpy').",
    },
    "steps_to_reproduce": {
        "type": ["string", "array"],
        "items": {"type": "string"},
        "description": "Ordered reproduction steps, starting from initial access state and ending at impact observation. Write them FROM WHAT YOU ACTUALLY RAN, with concrete values (the real session cookie, the real object id, the real payload) — an unbound placeholder is a step nobody can follow, and reusing one placeholder across different objects corrupts the sequence. Redaction is the report-writer's job at submission time. Preferred form is ONE string holding the whole block with your own numbering — renderers emit it verbatim, and prose elsewhere in the submission that cites a step number only resolves against numbers you wrote. A list of strings is also accepted, one action per string.",
    },
    # The anti-inference device for ``steps_to_reproduce``: the audit rows that
    # actually produced the reproduction. Without it, "write accurate steps" is an
    # instruction with no verification — a reviewer cannot diff a claimed step
    # against what was executed, and a plausible narrative is indistinguishable
    # from a transcript.
    "repro_runs": {
        "type": "array",
        "items": {"type": ["string", "integer"]},
        "description": "Command-run ids (from `vigil assess command-run list`) that actually produced this reproduction, in step order. A step with no run id behind it was imagined, not executed. `export submission` fetches each row and renders its real argv under OPERATOR DETAILS, so the reproduction is transcribed rather than paraphrased. An id that does not resolve is reported as an advisory, never a refusal — an unreachable run row and an invented one look identical from there.",
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
    "severity_band_rationale": {
        "type": "string",
        "description": "Why the assigned severity band DIVERGES from the band the CVSS base score implies (e.g. business context the vector cannot express). Present and non-empty demotes report-readiness' severity_cvss_mismatch blocker to an advisory; it never excuses the two CVSS-arithmetic blockers.",
    },
    "honest_bounds": {
        "type": "string",
        "description": "What this finding does NOT establish — the limits of the evidence, stated by the author so a reader cannot over-read the claim.",
    },
    "intent_basis_caveat": {
        "type": "string",
        "description": "Caveat on any inference about the target's intent or design rationale, naming what is observed versus what is assumed.",
    },
    "scope_metric_note": {
        "type": "string",
        "description": "Qualification of a count or coverage figure cited by this finding (what the denominator is, and what it excludes).",
    },
    "self_obtainability_verdict": {
        "type": "string",
        "description": "Whether the attacker can obtain the required precondition themselves ('self'), needs a victim action, or needs a privilege they cannot acquire.",
    },
    "mechanism_verdict": {
        "type": "string",
        "description": "Adjudicated verdict on the proposed mechanism after review — what the mechanism actually is, versus what it was first believed to be. Undated: the transition ledger, not a date-stamped key, carries when it was written.",
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
    "correction_history": {
        "type": ["array", "string"],
        "description": "Retraction/correction history for this finding \u2014 quoted supersessions naming the internal slugs they retract. Rendered ONLY under OPERATOR DETAILS; never in the pasteable submission body, so naming a slug here cannot trip the export hygiene gate.",
    },
    "withdrawal_reason": {
        "type": "string",
        "description": "Why the researcher withdrew this submission. REQUIRED when submission_status is set to 'withdrawn' \u2014 a retraction is researcher-initiated, so the record must say why rather than assert a program decision.",
    },
}

def _type_matches(value: Any, declared: str) -> bool:
    if declared == "string":
        return isinstance(value, str)
    if declared == "integer":
        # ``bool`` is an ``int`` subclass; a boolean is never a valid integer here.
        return isinstance(value, int) and not isinstance(value, bool)
    if declared == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if declared == "boolean":
        return isinstance(value, bool)
    if declared == "array":
        return isinstance(value, list)
    if declared == "object":
        return isinstance(value, dict)
    if declared == "null":
        return value is None
    # An unrecognised JSON-Schema type is not a reason to refuse a write.
    return True


def validate_finding_details(
    details: dict[str, Any] | None,
    *,
    already_stored_keys: frozenset[str] | set[str] = frozenset(),
) -> None:
    """Validate the details keys a write AUTHORS against the canonical vocabulary.

    Scoped to the authored payload, mirroring ``_validate_cvss_pair``: a write that
    does not touch a key must never be refused for a value someone else stored.
    That is also what keeps an out-of-range legacy value repairable — the repair
    authors an in-range value, which passes, while the row it sits on is never
    re-validated.

    ``already_stored_keys`` is the server-side half of "a key already persisted on
    the record can always be rewritten": once a key is in the data, refusing to let
    anyone correct it strands it forever. Matching is EXACT key equality — never a
    prefix or fuzzy match, or the typo guard evaporates.
    """

    if not details:
        return
    for key, value in details.items():
        schema = FINDING_DETAIL_PROPERTIES.get(key)
        if schema is None:
            if key in already_stored_keys:
                continue
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    f"details.{key} is not an allowed finding detail key; run "
                    "`vigil assess contract finding record` for the allowed keys"
                ),
            )
        if value is None:
            continue
        declared = schema.get("type")
        declared_types = [declared] if isinstance(declared, str) else list(declared or [])
        if declared_types and not any(_type_matches(value, one) for one in declared_types):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    f"details.{key} must be of type "
                    f"{' or '.join(declared_types)}, got {value!r}"
                ),
            )
        allowed = schema.get("enum")
        if allowed is not None and value not in allowed:
            rendered = ", ".join(repr(item) for item in allowed)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"details.{key} must be one of: {rendered}",
            )
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            minimum = schema.get("minimum")
            if minimum is not None and value < minimum:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"details.{key} must be >= {minimum}",
                )
            maximum = schema.get("maximum")
            if maximum is not None and value > maximum:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"details.{key} must be <= {maximum}",
                )
