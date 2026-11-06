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

import difflib
from typing import Any

from fastapi import HTTPException, status

FINDING_DETAIL_CORE_PROPERTIES: dict[str, dict[str, Any]] = {
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
        "description": "Authored Markdown explaining how the proof establishes the finding. Use short headings when several observations are present and fenced code blocks for exact commands, requests, responses, or tool output; put large raw captures in an artifact or poc_request/poc_response instead. Preserve quoted evidence bytes verbatim and include enough context to reproduce independently.",
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
        "type": ["string", "array"],
        "items": {"type": "string"},
        "description": "Arrow-delimited data flow from entry_point to sink (e.g. 'curl_url_set -> parseurl() -> memcpy(buf, scheme, schemelen)').",
    },
    "guards_evaluated": {
        "type": "string",
        "description": "List each relevant bounds/validation check and state whether it is absent, bypassable, or ineffective (e.g. 'No bounds check on schemelen before memcpy').",
    },
    "ghsa": {
        "type": "object",
        "description": "GitHub private advisory form metadata; credits are assigned by maintainers, not claimed by the reporter.",
        "additionalProperties": False,
        "properties": {
            "ecosystem": {"type": "string"},
            "package_name": {"type": "string"},
            "affected_versions": {"type": "string"},
            "patched_versions": {"type": "string"},
            "cwe_ids": {"type": "array", "items": {"type": "string"}},
            "vulnerable_functions": {"type": "array", "items": {"type": "string"}},
            "request_cve": {"type": "boolean"},
        },
    },
    "impact": {
        "type": "string",
        "minLength": 1,
        "description": "Submission-quality Markdown stating the concrete attacker outcome, what data or action is exposed, and who is affected (e.g. 'Anonymous attacker can read all DB rows', 'Remote code execution via heap corruption').",
    },
    "cvss_vector": {
        "type": "string",
        "minLength": 1,
        "description": "Complete CVSS v3.1 or v4.0 base vector; the CVSS:3.1/ or CVSS:4.0/ prefix declares the version. Threat, temporal, environmental, and supplemental metrics are not accepted.",
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
        "description": "CVSS v3.1 or v4.0 base score (0.0-10.0). Must match cvss_vector using its declared version.",
    },
    "remediation": {
        "type": "string",
        "description": "Submission-quality Markdown naming the specific fix and missing control (e.g. 'Use parameterized queries', 'Add bounds check on schemelen before memcpy').",
    },
    "steps_to_reproduce": {
        "type": ["string", "array"],
        "items": {"type": "string"},
        "description": "Authored Markdown with ordered reproduction steps, starting from initial access state and ending at impact observation. Preferred form is ONE string with explicit 1./2./… numbering, blank lines between complex steps, and fenced code blocks for commands, requests, or responses. Write FROM WHAT YOU ACTUALLY RAN, with concrete values (the real session cookie, object id, and payload), and preserve those values verbatim through submission. An unbound placeholder is a step nobody can follow; a list of strings remains accepted for legacy/simple records.",
    },
    # The anti-inference device for ``steps_to_reproduce``: the audit rows that
    # actually produced the reproduction. Without it, "write accurate steps" is an
    # instruction with no verification — a reviewer cannot diff a claimed step
    # against what was executed, and a plausible narrative is indistinguishable
    # from a transcript.
    "repro_runs": {
        "type": "array",
        "items": {"type": ["string", "integer"]},
        "description": "Command-run ids (from `vigil assess command-run list`) that actually produced this reproduction, in step order. Newly authored ids must resolve in this engagement; legacy missing ids are reported as advisories. `export submission` fetches each row and renders its real argv under OPERATOR DETAILS, so the reproduction is transcribed rather than paraphrased. Leave it empty for a source-derived file finding (`reproduction_basis` `source`: every current verification receipt is a source_observation); its proof receipts back the steps and no run is owed.",
    },
    # The command-run ids behind the REPLAY an operator is told to run, as
    # distinct from ``repro_runs`` (the ids behind the authored reproduction
    # steps). Both are command-run ids; a replay cites the subset a reader is
    # expected to re-execute.
    "replay_commands": {
        "type": "array",
        "items": {"type": "integer", "minimum": 1},
        "description": "Command-run ids (from `vigil assess command-run list`) of the executed commands that back this finding's cited replay steps, in replay order. Each id must resolve in this engagement. Use `repro_runs` for the ids behind the authored steps_to_reproduce; this key names the ones a reader is told to re-execute.",
    },
    "attack_scenario": {
        "type": "string",
        "description": "Realistic adversary, starting access, and action, ending at first compromise. Renders as the submission's Attack Scenario section; omit when the reproduction already carries the narrative.",
    },
    "poc_code": {
        "type": "string",
        "description": "Minimal exploit code or script that reproduces the finding. Omit if poc_request/poc_response is sufficient.",
    },
    # The fence language for ``poc_code``. The operator views and the report
    # renderer read it as the opening fence's info string, so it is deliberately
    # free text: a specialist writes whatever the target's own toolchain calls
    # the language. Hostile values are neutralised at render time (a hint that
    # cannot be a CommonMark info string is dropped, never the capture).
    "poc_language": {
        "type": "string",
        "description": "Language hint for the poc_code fence (e.g. 'python', 'bash', 'http'). Free text, written by whoever authored poc_code; the operator views and the report renderer use it as the fenced block's info string and drop a hint they cannot render without altering the capture.",
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
        "description": "REQUIRED (enforced on write, and by this schema) when chain_required is true: explain which chain step this enables and why standalone impact is insufficient.",
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
    # Shared incident-response fields. Blue role prompts (investigator,
    # alert-triage-specialist) instruct these on every finding they record, and
    # report readiness REQUIRES non-empty ``mitre_techniques`` for a blue
    # engagement. Structured blue collections are versioned below.
    "mitre_techniques": {
        "type": "array",
        "items": {"type": "string"},
        "description": "MITRE ATT&CK technique IDs (e.g. 'T1078') this finding maps to. Required on a blue-engagement finding before report readiness passes.",
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
        "additionalProperties": False,
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
        "description": "Informational attribution to a parent pattern. Child ancestry requires a links entry with link_kind=variant_of, target_kind=finding and the parent slug; independent same-class findings use related.",
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
        "description": "Append-only thread of OUTGOING replies to the program on this submitted finding (Bugcrowd comment / HackerOne activity reply / direct follow-up). Drafts are written by `vigil assess record-reply` via read-modify-write and rendered by `export reply`; sent replies export their separate immutable byte record and are never rerendered from this authored thread.",
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
                    "description": "Threading pointer to a prior reply seq; null when the reply does not thread to one.",
                },
                "body": {
                    "type": "string",
                    "description": "Editable authored reply prose used by the exact-byte renderer at send time. After send, the immutable byte record — not this field — is the historical outbound representation.",
                },
                "new_evidence": {
                    "type": "string",
                    "description": "NEW proof authored for THIS reply, or an empty string when it adds none. Preserve captured credentials, tokens, PII, and other evidence verbatim.",
                },
                "new_evidence_ref": {
                    "type": "string",
                    "description": "Pointer to raw new-evidence (e.g. 'scans/<file>'), or an empty string when there is none.",
                },
                "sent_status": {
                    "type": "string",
                    "enum": ["draft", "sent"],
                    "description": "Operator-marked send state. 'sent' is set only by `record-reply --sent` through the atomic sent-reply byte-capture endpoint, never inferred or accepted through a generic finding update.",
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
                "corrects_seq": {
                    "type": "integer",
                    "minimum": 1,
                    "description": "Sent reply seq superseded by this appended correction version.",
                },
                "event_type": {
                    "type": "string",
                    "enum": ["correction"],
                    "description": "Marks an appended reply as a correction event.",
                },
            },
            "required": [
                "seq",
                "platform",
                "in_response_to",
                "reply_to_seq",
                "body",
                "new_evidence",
                "new_evidence_ref",
                "sent_status",
                "created_at",
                "sent_at",
                "author",
            ],
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


# Workflow-owned fields evolve independently from the cross-workflow core. Keep
# their namespace and version explicit here, while retaining the established flat
# wire shape so existing records and callers do not need a data migration. The
# annotation is also projected into the generated agent schema.
FINDING_DETAIL_EXTENSION_PROPERTIES: dict[str, dict[str, dict[str, Any]]] = {
    "web/v1": {
        "poc_request": {
            "type": "object",
            "additionalProperties": False,
            "description": "HTTP request that triggers the vulnerability.",
            "properties": {
                "method": {"type": "string"},
                "url": {"type": "string"},
                "headers": {
                    "type": "object",
                    "additionalProperties": {"type": "string"},
                },
                "body": {"type": "string"},
            },
        },
        "poc_response": {
            "type": "object",
            "additionalProperties": False,
            "description": "Observed HTTP response that confirms the vulnerability.",
            "properties": {
                "status": {"type": "integer"},
                "headers": {
                    "type": "object",
                    "additionalProperties": {"type": "string"},
                },
                "body_excerpt": {"type": "string"},
            },
        },
    },
    "code/v1": {
        "function": {
            "type": "string",
            "minLength": 1,
            "maxLength": 4096,
            "description": "Function or method containing the vulnerable operation.",
        },
        "discovery_stage": {
            "type": "string",
            "enum": ["hunt", "variant"],
            "description": "Code workflow stage that identified the finding.",
        },
        "source_anchor": {
            "type": "string",
            "minLength": 1,
            "maxLength": 4096,
            "description": "Verbatim source expression anchoring the finding in the reviewed snapshot.",
        },
        "proof_complete": {
            "type": "boolean",
            "description": "True when the code-verification path established a complete source-to-sink proof.",
        },
    },
    "credential/v1": {
        "discovered_credential": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "credential_key",
                "credential_id",
                "principal",
                "kind",
                "minted_identity",
                "session_minted",
            ],
            "properties": {
                "credential_key": {"type": "string", "minLength": 1},
                "credential_id": {"type": ["integer", "null"]},
                "principal": {"type": "string"},
                "kind": {"type": "string"},
                "minted_identity": {"type": ["string", "null"]},
                "session_minted": {"type": "boolean"},
            },
            "description": "Credential-store record and optional replay identity created from a discovered secret.",
        },
    },
    "blue/v1": {
        "timeline": {
            "type": "array",
            "items": {"type": "object"},
            "description": "Ordered incident timeline entries, each a UTC ISO-8601 event citing its `source_file` and `command_run_id` per agent/rules/ir-evidence.md. Appended across investigation rungs, never replaced.",
        },
        "iocs": {
            "type": "array",
            "items": {"type": ["string", "object"]},
            "description": "Indicators of compromise observed for this finding (IP, domain, email, file hash, OAuth client_id, URL). Each one gets an `intel_*` row via `vigil assess intel record`.",
        },
        # The annotations `vigil blue` itself writes. Each of these is sent by a
        # blue wrapper verb or instructed verbatim by a blue role prompt or
        # skill, and `details` is a closed allow-list — so an unregistered key
        # is not a missing nicety, it is a verb that cannot complete.
        "tier": {
            "type": "string",
            "description": "Current IR triage tier for this finding (L1 alert triage, L2 skill-led triage, L3 independent verification, L4 incident lead). Written by `vigil blue tier`.",
        },
        "tier_notes": {
            "type": "string",
            "description": "Why the finding sits at its recorded tier — what the tier pass established and what it left for the next one. Written by `vigil blue tier --notes`.",
        },
        "evidence_refs": {
            "type": "array",
            "items": {"type": ["string", "integer"]},
            "description": "Supporting evidence ids or engagement-local paths cited by a blue verification, beyond the single `evidence_ref` column. Written by `vigil blue verify --evidence-refs`; the column remains the one indexed artifact.",
        },
        "containment_status": {
            "type": "string",
            "description": "Containment state recorded alongside the finding's workflow_status (e.g. 'contained'). Written by `vigil blue contain` after an approved proposal was executed; the authoritative lifecycle value stays on workflow_status.",
        },
        "containment_action": {
            "type": "string",
            "description": "Containment verb actually executed for this finding (revoke_session, reset_cred, disable_account, isolate_host, block_ioc, ...), copied from the approved proposal. Written by `vigil blue contain`.",
        },
        "containment_command_run_id": {
            "type": ["integer", "null"],
            "description": "assessment_command_runs id of the audited execution that performed the containment, or null when the proof is a registered artifact instead. Written by `vigil blue contain --command-run-id`.",
        },
        "checks": {
            "type": "array",
            "items": {"type": "object"},
            "description": "Per-check results from the structured false-positive verification, one entry per numbered check with its result, cited evidence and rationale. Recorded by incident-verifier on `finding verify`; the decisive counter-check/confirm-check remains its own structured payload.",
        },
        "devils_advocate": {
            "type": "array",
            "items": {"type": "object"},
            "description": "Benign hypotheses raised against the finding during verification, each with the counter-evidence that discharged it (or the fact that it was not discharged). Recorded by incident-verifier on `finding verify`.",
        },
        "network_window_utc": {
            "type": ["string", "array", "object"],
            "description": "UTC window the network hunt actually searched, as [start, end] — the trigger window extended backwards per agent/rules/triage.md. Recorded by network-threat-hunt so a beacon conclusion is read against the window that produced it.",
        },
        "coverage": {
            "type": ["string", "object", "array"],
            "description": "What the searched telemetry actually covered: byte and flow counts, retention window, and the slices that were unavailable. Recorded by network-threat-hunt so a negative result is not read as absence of activity.",
        },
        "cross_skill_correlation_ids": {
            "type": "array",
            "items": {"type": ["string", "integer"]},
            "description": "Finding slugs or ids in other blue lanes that corroborate or extend this one (e.g. the EDR finding for a network-side src_ip). Recorded when a skill chains to another instead of closing the finding.",
        },
        "disposition_recommendation": {
            "type": "string",
            "description": "The triage pass's RECOMMENDED disposition, in the blue vocabulary. Advisory only: the verifier reads it and is not bound by it, and the stored verdict remains verification_status.",
        },
        "respond_review": {
            "type": ["string", "object", "array"],
            "description": "The incident lead's respond-phase review of this finding — including an explicit 'no containment warranted' annotation with its cited rationale, which is the only thing that stands in for a recorded containment proposal at the report transition.",
        },
        # The L1 alert-triage skeleton (agent/skills/alert-triage/SKILL.md hands
        # out a complete `finding record` payload), reduced to the keys with no
        # existing home: the actor, the target, the alert's own window and the
        # confidence rationale all have canonical homes already (`iocs`,
        # `network_window_utc`, `severity_rationale`), and registering synonyms
        # for them would turn one vocabulary into two spellings of it.
        "alert_normalized": {
            "type": "object",
            "description": "The L1 parse of the raw alert — actor, target, action, time window and source signal — written ONCE so the verifier and the report-writer read the same parse instead of each re-deriving one from the raw body. Downstream skills anchor their look-back window to `alert_normalized.time_window_utc[0]`.",
        },
        "platform": {
            "type": "string",
            "description": "Platform the alert fired on (gws, m365, aws, okta, edr, network, or another the tenant runs). Selects which tenant reference and containment vocabulary apply. Free text, because a tenant may run a platform outside the containment-proposal enum.",
        },
        "source_signal": {
            "type": ["string", "object"],
            "description": "The detection's own identity as the source emitted it: rule name, rule id, detection control and severity hint. Records WHAT fired, independently of the verdict reached about it, which is what the verifier's source check reads.",
        },
        "alert_external_id": {
            "type": "string",
            "description": "The alert's identifier outside Vigil (SIEM alert UUID, rule id, or a slug the operator assigned), so a recorded finding can be joined back to the source console.",
        },
        "tenant_ref_paths_consulted": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Tenant reference files actually read while triaging this alert. A known-benign claim rests on them, so the paths are recorded rather than implied.",
        },
    },
}


# Names that are refused but NOT homeless: the key has a canonical home under a
# different spelling, or nested inside another key. difflib finds nothing for
# ``risk`` at any sane cutoff, and ranks the wrong siblings first for
# ``new_evidence``, so the route is stated rather than guessed. Owned here beside
# the vocabulary and projected into the generated agent schema (see
# ``scripts/generate_agent_schemas.py``) so the CLI door says the same sentence.
FINDING_DETAIL_KEY_ALIASES: dict[str, str] = {
    "risk": "details.impact (the attacker outcome) + details.severity_rationale (why that rating)",
    "indicators": "details.iocs",
    "new_evidence": "details.replies[].new_evidence (vigil assess record-reply --new-evidence)",
    # The four alert-triage names that are spellings of a key that exists.
    "actor": "details.iocs (the observed principal), or `vigil assess intel record` for an identity row",
    "target": "details.iocs (the acted-upon entity), or `vigil assess intel record` for an identity row",
    "time_window_utc": "details.network_window_utc, or details.alert_normalized.time_window_utc for the alert's own window",
    "confidence_rationale": "details.severity_rationale",
    # Named as effect-table axes and rendered into every finding write verb's
    # contract, but never part of this vocabulary: the claim's proof prose is
    # `evidence` (plus the verification's receipts), and exploitability is
    # carried by the two keys that actually say what it rests on.
    "proof": "details.evidence (authored proof prose) + a proof receipt on the verification",
    "exploitability": "details.precondition_analysis + details.self_obtainability_verdict",
    "poc_description": "details.poc_code with details.poc_language, or details.evidence for the prose",
}


def _detail_properties() -> dict[str, dict[str, Any]]:
    properties = dict(FINDING_DETAIL_CORE_PROPERTIES)
    for extension, extension_properties in FINDING_DETAIL_EXTENSION_PROPERTIES.items():
        duplicate = properties.keys() & extension_properties.keys()
        if duplicate:
            rendered = ", ".join(sorted(duplicate))
            raise RuntimeError(
                f"finding detail keys registered more than once: {rendered}"
            )
        properties.update(
            {
                key: {**schema, "x-vigil-extension": extension}
                for key, schema in extension_properties.items()
            }
        )
    return properties


FINDING_DETAIL_PROPERTIES = _detail_properties()


def _nested_field_paths(
    properties: dict[str, dict[str, Any]],
) -> dict[str, str]:
    """Leaf name -> its dotted path, for keys that live INSIDE another key.

    One level deep, which is as deep as the vocabulary goes: an object key
    contributes ``parent.child`` and an array-of-objects key ``parent[].child``.
    Derived from the properties table rather than listed, so a new sub-field is
    routable the moment it is registered. A leaf name that collides with a
    top-level key, or with another leaf, is dropped — an ambiguous route is
    worse than none.
    """

    paths: dict[str, str] = {}
    ambiguous: set[str] = set()
    for parent, schema in properties.items():
        if not isinstance(schema, dict):
            continue
        items = schema.get("items")
        child_schema, suffix = (
            (items, "[]") if isinstance(items, dict) else (schema, "")
        )
        children = child_schema.get("properties")
        if not isinstance(children, dict):
            continue
        for child in children:
            if child in properties or child in paths:
                ambiguous.add(child)
                continue
            paths[child] = f"details.{parent}{suffix}.{child}"
    for name in ambiguous:
        paths.pop(name, None)
    return paths


FINDING_DETAIL_NESTED_FIELD_PATHS = _nested_field_paths(FINDING_DETAIL_PROPERTIES)


def suggest_detail_key_home(key: str) -> str | None:
    """Where a refused ``details`` key actually belongs, or ``None``.

    Three sources, mirrored exactly by the CLI door
    (``assess.lib.schema_validation``) so the two cannot say different things
    about the same key:

    1. the alias table — a maintainer-curated route, which is knowledge a fuzzy
       matcher does not have, so it answers alone when it has an entry;
    2. an EXACT nested sub-field name, offered FIRST among the guesses: a key
       that is really a misplaced sub-field (``new_evidence``) is otherwise
       ranked below top-level siblings that merely share a substring
       (``evidence``), and difflib finds the dotted path itself too weakly;
    3. ``difflib`` near-misses on any real key, nested paths included, for
       ordinary typos.

    Everything but (1) is a suggestion, not a verdict — a generic leaf name can
    have a plausible nested home and a plausible top-level one, and the caller
    is better served seeing both than being steered to one.
    """

    alias = FINDING_DETAIL_KEY_ALIASES.get(key)
    if alias is not None:
        return alias
    candidates = sorted(FINDING_DETAIL_PROPERTIES) + sorted(
        FINDING_DETAIL_NESTED_FIELD_PATHS.values()
    )
    suggestions: list[str] = []
    nested = FINDING_DETAIL_NESTED_FIELD_PATHS.get(key)
    if nested is not None:
        suggestions.append(nested)
    suggestions.extend(
        match
        for match in difflib.get_close_matches(key, candidates, n=3, cutoff=0.55)
        if match not in suggestions
    )
    return ", ".join(suggestions[:3]) or None


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


def _declared_types(schema: dict[str, Any]) -> list[str]:
    declared = schema.get("type")
    return [declared] if isinstance(declared, str) else list(declared or [])


def _invalid(path: str, message: str) -> None:
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=f"{path} {message}",
    )


def _validate_schema_value(value: Any, schema: dict[str, Any], *, path: str) -> None:
    """Validate the JSON-Schema subset used by finding-detail contracts."""

    declared_types = _declared_types(schema)
    if declared_types and not any(_type_matches(value, one) for one in declared_types):
        _invalid(
            path,
            f"must be of type {' or '.join(declared_types)}, got {value!r}",
        )

    allowed = schema.get("enum")
    if allowed is not None and value not in allowed:
        rendered = ", ".join(repr(item) for item in allowed)
        _invalid(path, f"must be one of: {rendered}")

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        minimum = schema.get("minimum")
        if minimum is not None and value < minimum:
            _invalid(path, f"must be >= {minimum}")
        maximum = schema.get("maximum")
        if maximum is not None and value > maximum:
            _invalid(path, f"must be <= {maximum}")

    if isinstance(value, str):
        minimum_length = schema.get("minLength")
        if minimum_length is not None and len(value) < minimum_length:
            _invalid(path, f"must contain at least {minimum_length} characters")
        maximum_length = schema.get("maxLength")
        if maximum_length is not None and len(value) > maximum_length:
            _invalid(path, f"must contain at most {maximum_length} characters")

    if isinstance(value, list) and isinstance(schema.get("items"), dict):
        item_schema = schema["items"]
        for index, item in enumerate(value):
            _validate_schema_value(item, item_schema, path=f"{path}[{index}]")

    if not isinstance(value, dict):
        return
    properties = schema.get("properties", {})
    if not isinstance(properties, dict):
        return
    additional = schema.get("additionalProperties", True)
    for key, item in value.items():
        item_path = f"{path}.{key}"
        item_schema = properties.get(key)
        if item_schema is not None:
            _validate_schema_value(item, item_schema, path=item_path)
        elif additional is False:
            _invalid(item_path, "is not an allowed field")
        elif isinstance(additional, dict):
            _validate_schema_value(item, additional, path=item_path)
    for key in schema.get("required", []):
        if key not in value:
            _invalid(f"{path}.{key}", "is required")


def _validate_reply_sequence_identity(
    value: Any, *, path: str, status_code: int
) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise HTTPException(
            status_code=status_code,
            detail=f"{path} must be an array",
        )
    rows: list[dict[str, Any]] = []
    seen: set[int] = set()
    for index, row in enumerate(value):
        row_path = f"{path}[{index}]"
        if not isinstance(row, dict):
            raise HTTPException(
                status_code=status_code,
                detail=f"{row_path} must be an object",
            )
        if "seq" not in row:
            raise HTTPException(
                status_code=status_code,
                detail=f"{row_path}.seq is required",
            )
        seq = row.get("seq")
        if not isinstance(seq, int) or isinstance(seq, bool) or seq < 1:
            raise HTTPException(
                status_code=status_code,
                detail=f"{row_path}.seq must be a positive integer",
            )
        if seq in seen:
            raise HTTPException(
                status_code=status_code,
                detail=f"{path} contains duplicate reply seq {seq}",
            )
        seen.add(seq)
        rows.append(row)
    return rows


def _validate_reply_versions(
    value: Any,
    *,
    existing_value: Any = None,
    path: str = "details.replies",
) -> None:
    rows = _validate_reply_sequence_identity(
        value, path=path, status_code=status.HTTP_400_BAD_REQUEST
    )
    existing_rows = existing_value if isinstance(existing_value, list) else []
    existing_by_seq = {
        row.get("seq"): row
        for row in existing_rows
        if isinstance(row, dict) and type(row.get("seq")) is int
    }
    item_schema = FINDING_DETAIL_PROPERTIES["replies"]["items"]
    prior_by_seq: dict[int, dict[str, Any]] = {}
    for index, row in enumerate(rows):
        if index < len(existing_rows) and row == existing_rows[index]:
            prior_by_seq[row["seq"]] = row
            continue
        row_path = f"{path}[{index}]"
        _validate_schema_value(row, item_schema, path=row_path)
        sent_status = row["sent_status"]
        sent_at = row["sent_at"]
        if sent_status == "sent" and (
            not isinstance(sent_at, str) or not sent_at.strip()
        ):
            _invalid(row_path, "sent replies require a nonempty sent_at")
        if sent_status == "draft" and sent_at is not None:
            _invalid(row_path, "draft replies require sent_at=null")
        existing_row = existing_by_seq.get(row["seq"])
        if sent_status == "sent" and (
            existing_row is None or existing_row.get("sent_status") != "sent"
        ):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    f"{row_path} must use the sent-reply byte capture endpoint; "
                    "generic finding writes cannot mark a reply sent"
                ),
            )
        has_pointer = "corrects_seq" in row
        has_event = "event_type" in row
        if has_pointer != has_event or (has_event and row["event_type"] != "correction"):
            _invalid(
                row_path,
                "correction replies require event_type='correction' and corrects_seq",
            )
        reply_to_seq = row["reply_to_seq"]
        if reply_to_seq is not None and reply_to_seq not in prior_by_seq:
            _invalid(row_path, "reply_to_seq must reference a prior reply")
        if has_pointer:
            corrected = prior_by_seq.get(row["corrects_seq"])
            if corrected is None or corrected.get("sent_status") != "sent":
                _invalid(
                    row_path,
                    "correction must reference an existing sent reply",
                )
        prior_by_seq[row["seq"]] = row


def validate_stored_reply_sequence_identity(
    details: dict[str, Any], *, finding_slug: str
) -> None:
    """Fail read projections when reply identity cannot select one exact version."""

    if "replies" not in details:
        return
    try:
        _validate_reply_sequence_identity(
            details["replies"],
            path="details.replies",
            status_code=status.HTTP_409_CONFLICT,
        )
    except HTTPException as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"finding {finding_slug!r} has a corrupt reply thread: {exc.detail}",
        ) from exc


def validate_finding_details(
    details: dict[str, Any] | None,
    *,
    already_stored_keys: frozenset[str] | set[str] = frozenset(),
    existing_details: dict[str, Any] | None = None,
    effective_details: dict[str, Any] | None = None,
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
            suggestion = suggest_detail_key_home(key)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    f"details.{key} is not an allowed finding detail key; "
                    + (f"did you mean: {suggestion}? " if suggestion else "")
                    + "run `vigil assess contract finding record` for the allowed keys"
                ),
            )
        if value is None:
            continue
        if key == "replies":
            effective_value = (
                effective_details.get(key, value)
                if effective_details is not None
                else value
            )
            _validate_reply_versions(
                effective_value,
                existing_value=(existing_details or {}).get(key),
            )
            continue
        _validate_schema_value(value, schema, path=f"details.{key}")
