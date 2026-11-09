"""vigil assess finding verify — dedicated verifier flow for canonical findings."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from assess.lib.client import (
    AssessError,
    AssessmentClient,
    require_artifact_write_response,
    require_finding_write_response,
)
from assess.lib.code_record_input import fail
from assess.lib.code_snapshot_binding import fill_binding
from assess.lib.config import load_config
from assess.lib.contracts import VERIFICATION_TRANSITION_STATUSES, render_contract_epilog
from assess.lib.exploit_targets import is_source_bound
from assess.lib.json_inputs import parse_json_argument, parse_optional_inline_json
from assess.lib.next_test import load_next_test_file, next_test_problems
from assess.lib.schema_validation import collect_patch_validation_errors, load_schema


_FINDING_SCHEMA = load_schema("finding-record.schema.json")


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "verify",
        help="Verify findings with explicit flags or a final transition payload file",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=render_contract_epilog("finding verify"),
    )
    p.add_argument(
        "finding_slug",
        nargs="+",
        help="One or more canonical finding slugs to verify. Batch: every listed slug receives the "
             "SAME verification status/payload/flags (resilient loop with a per-slug failure tally).",
    )
    p.add_argument(
        "--inline",
        dest="legacy_inline_payload",
        help=argparse.SUPPRESS,
    )
    p.add_argument(
        "--payload-file",
        dest="payload_file",
        help="Path to a final JSON verification-transition payload",
    )
    p.add_argument(
        "--status",
        dest="verification_status",
        choices=VERIFICATION_TRANSITION_STATUSES,
        help=(
            "Verification status when building the payload from flags. 'blocked' "
            "requires a block_reason (pass via --details-inline '{\"block_reason\": \"...\"}' "
            "or already present on the finding) and holds the finding out of the report."
        ),
    )
    p.add_argument("--reason", dest="reason_text", help="Required verification rationale when building payload from flags")
    p.add_argument("--reason-code", help="Optional machine-readable reason code")
    p.add_argument(
        "--new-severity",
        help=(
            "Required for downgraded verification, and accepted with any terminal "
            "status (confirmed | downgraded | false_positive) to re-band the finding "
            "in the same attested write. `finding update --severity` invalidates the "
            "verdict; this does not."
        ),
    )
    p.add_argument("--evidence-ref", help="Optional evidence reference")
    p.add_argument("--artifact-ref", help="Optional artifact reference")
    p.add_argument(
        "--narrative",
        default="",
        help=(
            "Optional path to a verification/debate narrative (e.g. an "
            "Ideator-vs-Tracer debate doc). Registered as a "
            "kind=verification-narrative artifact linked to this finding."
        ),
    )
    p.add_argument("--notes", help="Optional verification notes")
    p.add_argument("--source-name", help="Optional source/agent name")
    p.add_argument("--details-inline", help="Inline JSON object merged into the details payload")
    p.add_argument(
        "--agent-id",
        dest="agent_id",
        default=None,
        help="Dispatch agent_id of the agent PERFORMING this verification (e.g. VERIFY-1), "
             "copied verbatim from your Runtime Identity block. Stored as the "
             "provenance.agent_id of this write, which is the identity the backend resolves "
             "into the finding's code_snapshot_attestation: without it a code finding's "
             "stored binding attests to no dispatch at all and reads 'unattested'. It does "
             "NOT rebind the finding's immutable author.",
    )
    p.add_argument("--provenance-inline", help="Inline JSON object for provenance metadata")
    p.add_argument(
        "--proof-receipt-id",
        dest="proof_receipt_ids",
        action="append",
        type=int,
        help="Proof-receipt id produced by the independent verifier (repeatable)",
    )
    p.add_argument(
        "--counter-check-file",
        help="JSON file containing the completed structured false-positive counter-check",
    )
    p.add_argument(
        "--confirm-check-file",
        help="JSON file containing the completed falsification check for confirmed/downgraded",
    )
    p.add_argument(
        "--next-test-file",
        help=(
            "JSON file with the runtime proof plan {hypothesis, confirm_if, falsify_if, "
            "route_hint, prerequisites}. Required with --status pending_runtime_proof and "
            "rejected with any other status; see `vigil assess contract finding verify`."
        ),
    )
    p.add_argument(
        "--severity-variance-file",
        help="JSON file with {normal_band, chosen_severity, actor, reason, proof_receipt_id} when chosen severity differs from its CVSS band; receipt id must also be passed with --proof-receipt-id",
    )
    p.add_argument(
        "--operator-authority",
        dest="operator_authority",
        action="store_true",
        help=(
            "Record this terminal verdict on the OPERATOR's out-of-snapshot evidence "
            "instead of a proof receipt, for a fact that settles the finding but lies "
            "outside the sealed snapshot (a deployment config, a vendor statement). "
            "Requires --intel-id naming the intel row that holds it and --reason. The "
            "verdict is stamped provenance.operator_authority and renders as "
            "operator-authority everywhere, never as dispatch-verified."
        ),
    )
    p.add_argument(
        "--intel-id",
        dest="operator_authority_intel_id",
        type=int,
        default=None,
        help=(
            "Intel row id holding the out-of-snapshot evidence for "
            "--operator-authority. Must resolve in this engagement."
        ),
    )
    p.set_defaults(func=run)


# The terminal dispositions. Mirrors the backend
# ``proofs.TERMINAL_VERIFICATION_STATUSES``; these are the statuses that demand a
# decision receipt (or an operator-authority stamp in its place) and the ones a
# re-band may ride along with.
_TERMINAL_STATUSES = frozenset({"confirmed", "downgraded", "false_positive"})

# Hand-kept mirrors of the backend request models (``FindingCounterCheckRequest``,
# ``FindingConfirmCheckRequest``, ``FindingSeverityVarianceRequest`` in
# ``app/api/assessment.py``), as (field, kind, text max length). Each model is
# ``extra="forbid"``, so a misspelled field used to arrive as a bare 422 with no
# roster while ``--next-test-file`` named every problem locally. Drift is pinned
# by test_finding_verify_decision_contract_mirror.py.
_TEXT, _BOOL, _ID, _ID_LIST, _BAND = "text", "bool", "id", "id_list", "band"
_SEVERITY_BANDS = ("info", "low", "medium", "high", "critical")

_DECISION_FIELDS: dict[str, tuple[tuple[str, str, int | None], ...]] = {
    "counter_check": (
        ("method", _TEXT, 4096),
        ("expected_result", _TEXT, 4096),
        ("observed_result", _TEXT, 4096),
        ("falsified_claim", _TEXT, 4096),
        ("completed", _BOOL, None),
        ("proof_receipt_ids", _ID_LIST, None),
    ),
    "confirm_check": (
        ("method", _TEXT, 4096),
        ("attempted_falsification", _TEXT, 4096),
        ("expected_result", _TEXT, 4096),
        ("observed_result", _TEXT, 4096),
        ("completed", _BOOL, None),
        ("proof_receipt_ids", _ID_LIST, None),
    ),
    "severity_variance": (
        ("normal_band", _BAND, None),
        ("chosen_severity", _BAND, None),
        ("actor", _TEXT, 128),
        ("reason", _TEXT, 4096),
        ("proof_receipt_id", _ID, None),
    ),
}

_DECISION_FLAGS: dict[str, str] = {
    "counter_check": "--counter-check-file",
    "confirm_check": "--confirm-check-file",
    "severity_variance": "--severity-variance-file",
}

# A field that is real on ANOTHER decision model: the problem says where the
# value belongs instead of only that it is refused here.
_MISPLACED_DECISION_FIELDS: dict[tuple[str, str], str] = {
    ("confirm_check", "falsified_claim"): (
        "falsified_claim belongs on a counter check (--counter-check-file), which "
        "is what establishes false_positive. A sub-claim this CONFIRMED finding "
        "does not establish belongs in details.honest_bounds"
    ),
    ("counter_check", "attempted_falsification"): (
        "attempted_falsification belongs on a confirm check (--confirm-check-file); "
        "a counter check's own falsification is its falsified_claim"
    ),
}


def decision_problems(field_name: str, payload) -> list[str]:
    """Every way ``payload`` misses its decision contract; empty when it fits."""
    fields = _DECISION_FIELDS[field_name]
    if not isinstance(payload, dict):
        return [f"{field_name} must be a JSON object"]
    names = {name for name, _kind, _bound in fields}
    problems: list[str] = []
    for key in payload:
        if key in names:
            continue
        misplaced = _MISPLACED_DECISION_FIELDS.get((field_name, key))
        problems.append(
            f"{field_name}.{key} is not a {field_name} field"
            + (f" — {misplaced}" if misplaced else "")
        )
    for name, kind, bound in fields:
        if name not in payload:
            problems.append(f"{field_name}.{name} is required")
            continue
        value = payload[name]
        if kind == _TEXT:
            if not isinstance(value, str):
                problems.append(f"{field_name}.{name} must be a string")
            elif not value.strip():
                problems.append(f"{field_name}.{name} must not be blank")
            elif bound is not None and len(value) > bound:
                problems.append(f"{field_name}.{name} exceeds {bound} characters")
        elif kind == _BOOL:
            if not isinstance(value, bool):
                problems.append(f"{field_name}.{name} must be true or false")
        elif kind == _ID:
            if type(value) is not int or value < 1:
                problems.append(f"{field_name}.{name} must be a proof-receipt id (integer >= 1)")
        elif kind == _ID_LIST:
            if not isinstance(value, list) or not value:
                problems.append(
                    f"{field_name}.{name} must name at least one proof-receipt id"
                )
            elif any(type(item) is not int or item < 1 for item in value):
                problems.append(
                    f"{field_name}.{name} must contain only proof-receipt ids (integers >= 1)"
                )
        elif kind == _BAND and value not in _SEVERITY_BANDS:
            problems.append(
                f"{field_name}.{name} must be one of: {', '.join(_SEVERITY_BANDS)}"
            )
    return problems


def _require_decision_shapes(payload: dict) -> None:
    """Name every malformed decision field locally, before the first write."""
    for field_name, flag in _DECISION_FLAGS.items():
        value = payload.get(field_name)
        if value is None:
            continue
        problems = decision_problems(field_name, value)
        if problems:
            fail("finding verify", f"{flag}: {'; '.join(problems)}")


# A kill carries its own annotations beside the structured counter-check: the
# rationale and the numbered verification check that produced the verdict. The
# backend refuses a false_positive without both, accepting either from this write
# or from what the finding already stores — which is why an absent pair is a
# WARNING here and not a refusal: the CLI cannot see the stored row, and a batch
# would have to read each slug. What it can do is name the whole requirement
# before the round trip instead of after it.
_KILL_DETAIL_FIELDS = ("kill_reason", "kill_check")


def _warn_missing_kill_details(payload: dict, slugs: list[str]) -> None:
    details = payload.get("details")
    stored = details if isinstance(details, dict) else {}
    missing = [name for name in _KILL_DETAIL_FIELDS if name not in stored]
    if not missing:
        return
    print(
        "finding verify: false_positive requires details.kill_reason (why the claim "
        "does not hold) and details.kill_check (the numbered verification check that "
        f"produced the verdict, an integer from 1 to 5). This call authors "
        f"{'neither' if len(missing) == 2 else 'no ' + missing[0]}, so the write is "
        f"refused unless {', '.join(slugs)} already carries "
        f"{'them' if len(missing) == 2 else 'it'}: pass "
        "--details-inline '{\"kill_reason\": \"...\", \"kill_check\": 3}'. A "
        "kill_reason saying the experiment could not be RUN is `blocked`, not "
        "`false_positive`, unless details.required_followup names the test that "
        "would settle it.",
        file=sys.stderr,
    )


_KNOWN_STATUSES = frozenset(VERIFICATION_TRANSITION_STATUSES)

_CONTENT_FLAGS = (
    ("verification_status", "--status"),
    ("reason_text", "--reason"),
    ("reason_code", "--reason-code"),
    ("new_severity", "--new-severity"),
    ("evidence_ref", "--evidence-ref"),
    ("artifact_ref", "--artifact-ref"),
    ("notes", "--notes"),
    ("source_name", "--source-name"),
    ("details_inline", "--details-inline"),
    ("agent_id", "--agent-id"),
    ("provenance_inline", "--provenance-inline"),
    ("proof_receipt_ids", "--proof-receipt-id"),
    ("counter_check_file", "--counter-check-file"),
    ("confirm_check_file", "--confirm-check-file"),
    ("severity_variance_file", "--severity-variance-file"),
    ("next_test_file", "--next-test-file"),
    ("operator_authority", "--operator-authority"),
    ("operator_authority_intel_id", "--intel-id"),
)


def _looks_like_payload(token: str) -> bool:
    """True when a positional token looks like a JSON payload rather than a slug."""
    t = (token or "").strip()
    return bool(t) and (t.startswith(("{", "[")) or t.endswith(".json") or Path(t).is_file())


def _stored_binding_repo_id(finding: dict) -> int | None:
    """The repository the finding's stored binding already names, if any."""
    provenance = finding.get("provenance")
    binding = provenance.get("code_snapshot") if isinstance(provenance, dict) else None
    repo_id = binding.get("repo_id") if isinstance(binding, dict) else None
    return int(repo_id) if type(repo_id) is int and repo_id >= 1 else None


def _request_for_slug(client, payload: dict, slug: str, *, derive_binding: bool) -> dict:
    """Return this slug's request, deriving its code-snapshot binding when owed.

    A ``file:`` finding cannot be verified without ``provenance.code_snapshot``,
    and the binding is the reviewed repository's own current identity — so it is
    read from the repository rather than transcribed. What the verifier supplies
    is the identity half: ``--agent-id`` is the dispatch the backend resolves
    into the stored attestation. An authored ``--provenance-inline`` binding
    always wins, and a STALE stored binding is never derived — rebinding is the
    claim that the new bytes were read, so it stays deliberate.
    ``--payload-file`` is a complete transition document and is sent verbatim.
    """
    provenance = payload.get("provenance")
    if not derive_binding or not isinstance(provenance, dict) or provenance.get("code_snapshot"):
        return payload
    try:
        finding = client.get(f"findings/{slug}")
    except AssessError:
        # The derivation is a convenience; the backend owns the gate. A read that
        # did not answer must not block a write it may have nothing to say about
        # — the POST below still refuses a file: finding with no binding.
        return payload
    if not isinstance(finding, dict) or not is_source_bound(
        str(finding.get("canonical_location", ""))
    ):
        return payload
    if str(finding.get("code_snapshot_status") or "") == "stale":
        # A STALE binding means the source moved under a finding that was already
        # reviewed against older bytes, and re-binding it is the one act that says
        # "I read the new ones". Deriving that silently would let an
        # administrative status change (disputed, blocked — neither needs a proof
        # receipt) clear the report-readiness stale blocker with nobody having
        # looked. Record-time and legacy-unbound derivation stay automatic;
        # a REBIND stays deliberate.
        raise AssessError(
            f"finding verify: {slug} is bound to a superseded source snapshot. "
            "Re-read the current sealed bytes, then re-run with an explicit "
            "--provenance-inline '{\"code_snapshot\": {...}}' copied from Code "
            "Source Identity. The binding is not derived here on purpose: "
            "rebinding is the claim that you reviewed the new bytes."
        )
    request = dict(payload)
    request["provenance"] = dict(provenance)
    fill_binding(
        request["provenance"],
        client,
        repo_id=_stored_binding_repo_id(finding),
        operation="finding verify",
    )
    return request


def _require_next_test_pairing(payload: dict) -> None:
    """A runtime-proof park carries its plan; no other verdict may carry one."""
    parked = payload.get("verification_status") == "pending_runtime_proof"
    plan = payload.get("next_test")
    if parked and plan is None:
        fail(
            "finding verify",
            "pending_runtime_proof requires --next-test-file <plan.json> "
            "(a next_test object {hypothesis, confirm_if, falsify_if, route_hint, "
            "prerequisites}); run `vigil assess contract finding verify` for the shape",
        )
    if not parked and plan is not None:
        fail(
            "finding verify",
            "--next-test-file / next_test applies only to "
            f"--status pending_runtime_proof (got '{payload.get('verification_status')}')",
        )
    problems = next_test_problems(plan) if plan is not None else []
    if problems:
        fail("finding verify", f"{'; '.join(problems)}")


def _provided_content_flags(args) -> list[str]:
    provided = []
    for attr, flag in _CONTENT_FLAGS:
        value = getattr(args, attr, None)
        if value is not None and value is not False:
            provided.append(flag)
    return provided


def run(args) -> None:
    legacy_inline = getattr(args, "legacy_inline_payload", None)
    if legacy_inline is None:
        legacy_inline = getattr(args, "inline_payload", None)
    if legacy_inline is not None:
        fail(
            "finding verify",
            "--inline was removed; use --status/--reason and related "
            "explicit flags, or --payload-file <path> for a final transition payload.",
        )

    slugs = args.finding_slug if isinstance(args.finding_slug, list) else [args.finding_slug]
    # The trailing positional payload arg was removed (it collided with a variadic
    # slug list). Catch a legacy JSON blob / status passed positionally and
    # point the caller at the flag form.
    example_slug = slugs[0] if slugs else "<slug>"
    for token in slugs:
        t = str(token).strip()
        if t in _KNOWN_STATUSES:
            print(
                f"'{t}' looks like a verification status, not a finding slug.\n"
                f"Use: vigil assess finding verify {example_slug} --status {t} --reason \"...\"",
                file=sys.stderr,
            )
            sys.exit(1)
        if _looks_like_payload(t):
            print(
                f"'{t}' looks like a JSON payload, not a finding slug. The positional payload arg "
                "was removed — use --payload-file <path>, and list only finding slugs "
                "positionally.",
                file=sys.stderr,
            )
            sys.exit(1)

    payload_file = getattr(args, "payload_file", None)
    if payload_file is not None:
        if not str(payload_file).strip():
            fail("finding verify", "--payload-file must not be empty")
        provided_flags = _provided_content_flags(args)
        if provided_flags:
            fail(
                "finding verify",
                "--payload-file cannot be combined with request-content flags "
                f"({', '.join(provided_flags)}); put the complete transition in the file or use "
                "explicit verification flags. --narrative may be used with either form.",
            )
    raw_payload = payload_file
    if raw_payload is not None:
        if not Path(raw_payload).is_file():
            print(f"verification payload file not found: {raw_payload}", file=sys.stderr)
            sys.exit(1)
        try:
            payload, _ = parse_json_argument(
                raw_payload,
                inline=False,
                description="verification payload",
            )
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            sys.exit(1)
    else:
        if not args.verification_status or not args.reason_text:
            print(
                "finding verify requires --payload-file or both --status and --reason",
                file=sys.stderr,
            )
            sys.exit(1)
        try:
            details = parse_optional_inline_json(
                args.details_inline,
                default={},
                description="details JSON",
            )
            provenance = parse_optional_inline_json(
                args.provenance_inline,
                default={},
                description="provenance JSON",
            )
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            sys.exit(1)
        if not isinstance(details, dict):
            print("details JSON must be an object", file=sys.stderr)
            sys.exit(1)
        if not isinstance(provenance, dict):
            print("provenance JSON must be an object", file=sys.stderr)
            sys.exit(1)
        verifier_agent_id = (getattr(args, "agent_id", None) or "").strip()
        if verifier_agent_id:
            provenance.setdefault("agent_id", verifier_agent_id)
        structured_decisions: dict[str, dict] = {}
        for field_name, path_value, description in (
            (
                "counter_check",
                getattr(args, "counter_check_file", None),
                "counter-check payload",
            ),
            (
                "confirm_check",
                getattr(args, "confirm_check_file", None),
                "confirm-check payload",
            ),
            (
                "severity_variance",
                getattr(args, "severity_variance_file", None),
                "severity-variance payload",
            ),
        ):
            if not path_value:
                continue
            if not Path(path_value).is_file():
                print(f"{description} file not found: {path_value}", file=sys.stderr)
                sys.exit(1)
            try:
                structured, _ = parse_json_argument(
                    path_value,
                    inline=False,
                    description=description,
                )
            except ValueError as exc:
                print(str(exc), file=sys.stderr)
                sys.exit(1)
            if not isinstance(structured, dict):
                print(f"{description} must be a JSON object", file=sys.stderr)
                sys.exit(1)
            structured_decisions[field_name] = structured
        next_test_file = getattr(args, "next_test_file", None)
        if next_test_file:
            try:
                structured_decisions["next_test"] = load_next_test_file(next_test_file)
            except ValueError as exc:
                fail("finding verify", f"--next-test-file: {exc}")
        payload = {
            "verification_status": args.verification_status,
            "reason_code": args.reason_code,
            "reason_text": args.reason_text,
            "new_severity": args.new_severity,
            "evidence_ref": args.evidence_ref,
            "artifact_ref": args.artifact_ref,
            "notes": args.notes,
            "source_name": args.source_name,
            "details": details,
            "provenance": provenance,
            "proof_receipt_ids": getattr(args, "proof_receipt_ids", None) or [],
            **structured_decisions,
        }
        if getattr(args, "operator_authority", False):
            # Sent only when claimed: the operator-authority door is the one that
            # waives the receipt requirement, so an unasked-for `false` must not
            # travel on every verification.
            payload["operator_authority"] = True
            payload["operator_authority_intel_id"] = getattr(
                args, "operator_authority_intel_id", None
            )
        payload = {key: value for key, value in payload.items() if value is not None}

    if not isinstance(payload, dict):
        print("verification payload must be a JSON object", file=sys.stderr)
        sys.exit(1)
    details = payload.get("details")
    details_schema = _FINDING_SCHEMA["properties"].get("details")
    if details is not None and isinstance(details_schema, dict):
        schema_errors = collect_patch_validation_errors(
            details, details_schema, path="details"
        )
        if schema_errors:
            print("finding verify: payload failed schema validation:", file=sys.stderr)
            for error in schema_errors:
                print(f"  - {error}", file=sys.stderr)
            print(
                "Run `vigil assess contract finding verify` for the allowed details keys.",
                file=sys.stderr,
            )
            sys.exit(1)
    _require_next_test_pairing(payload)
    _require_decision_shapes(payload)
    verification_status = payload.get("verification_status")
    operator_authority = bool(payload.get("operator_authority"))
    if operator_authority:
        if payload.get("operator_authority_intel_id") is None:
            fail(
                "finding verify",
                "--operator-authority requires --intel-id <id> naming "
                "the intel row that holds the out-of-snapshot evidence; record it with "
                "`vigil assess intel record note <file.json>` first and cite the id it "
                "returns",
            )
        if verification_status not in _TERMINAL_STATUSES:
            fail(
                "finding verify",
                "--operator-authority records a terminal verdict "
                f"({' | '.join(sorted(_TERMINAL_STATUSES))}); got "
                f"'{verification_status}'",
            )
        if not str(payload.get("reason_text") or "").strip():
            fail(
                "finding verify",
                "--operator-authority requires --reason stating what "
                "the out-of-snapshot evidence settles",
            )
        carried = [
            flag
            for field_name, flag in (
                ("proof_receipt_ids", "--proof-receipt-id"),
                *_DECISION_FLAGS.items(),
            )
            if payload.get(field_name)
        ]
        if carried:
            fail(
                "finding verify",
                "--operator-authority records no proof receipts, so it "
                f"cannot be combined with {', '.join(carried)}; drop the operator "
                "authority and verify on the receipt, or record the verdict on the "
                "operator's evidence alone",
            )
    elif payload.get("operator_authority_intel_id") is not None:
        fail(
            "finding verify",
            "--intel-id names the evidence behind "
            "--operator-authority and means nothing without it; attach plain intel "
            "with `vigil assess finding link <slug> --intel <id>`",
        )
    if verification_status == "false_positive":
        # Printed before the counter-check refusal below, so a verifier that
        # forgot both learns both in one run. Required with or without operator
        # authority: the kill annotations are the verdict's own record, not
        # evidence, so no waiver covers them.
        _warn_missing_kill_details(payload, slugs)
    if verification_status == "false_positive" and not operator_authority:
        counter_check = payload.get("counter_check")
        if not isinstance(counter_check, dict):
            print(
                "false_positive verification requires --counter-check-file with a "
                "completed structured counter-check",
                file=sys.stderr,
            )
            sys.exit(1)
        if counter_check.get("completed") is not True:
            print(
                "false_positive counter-check must be completed; use blocked or "
                "pending_runtime_proof when the check could not run",
                file=sys.stderr,
            )
            sys.exit(1)
    if (
        verification_status in {"confirmed", "downgraded"}
        and not operator_authority
        and not payload.get("proof_receipt_ids")
    ):
        print(
            "terminal verification requires at least one --proof-receipt-id",
            file=sys.stderr,
        )
        sys.exit(1)
    if verification_status in {"confirmed", "downgraded"} and not operator_authority:
        confirm_check = payload.get("confirm_check")
        if not isinstance(confirm_check, dict) or confirm_check.get("completed") is not True:
            print(
                "confirmed/downgraded verification requires --confirm-check-file "
                "with a completed structured falsification check",
                file=sys.stderr,
            )
            sys.exit(1)
    if verification_status == "downgraded" and not payload.get("new_severity"):
        print("downgraded verification requires new_severity", file=sys.stderr)
        sys.exit(1)
    if payload.get("new_severity") and verification_status not in _TERMINAL_STATUSES:
        # A terminal verdict re-bands in the same attested write; a non-terminal
        # status records no fresh attestation, so the band has to move through the
        # verb that owns the axis — which invalidates the verdict. Fail before the
        # POST (mirrors the backend rejection), and name EVERY slug in the batch:
        # naming only the first would re-band one finding and silently leave the
        # rest at the old severity.
        print(
            "new_severity applies only to a terminal --status "
            f"({', '.join(sorted(_TERMINAL_STATUSES))}); got "
            f"'{verification_status}'. Change the band with "
            f"`vigil assess finding update {' '.join(slugs) or '<slug>'} --severity "
            f"{payload['new_severity']}`, which invalidates the verdict",
            file=sys.stderr,
        )
        sys.exit(1)

    narrative_path = getattr(args, "narrative", "") or ""
    narrative_artifact_path = narrative_path
    producer_role = str(payload.get("source_name") or getattr(args, "source_name", "") or "")

    cfg = load_config(args.engagement_dir)

    # Validate the narrative artifact path before any POST so a typo fails fast
    # instead of silently registering a dangling artifact reference. The
    # artifact endpoint resolves a relative path under the engagement root, so
    # anchor it there too — a CWD-relative check would wrongly reject the
    # supported `--engagement-dir … --narrative notes/debate.md` workflow.
    if narrative_path:
        narrative_file = Path(narrative_path)
        if not narrative_file.is_absolute():
            narrative_file = Path(cfg.engagement_dir) / narrative_path
        if not narrative_file.exists():
            print(
                f"--narrative path does not exist: {narrative_path}",
                file=sys.stderr,
            )
            sys.exit(1)
        try:
            narrative_artifact_path = narrative_file.resolve().relative_to(
                Path(cfg.engagement_dir).resolve()
            ).as_posix()
        except ValueError:
            # The backend owns the authoritative containment refusal. Retain the
            # submitted path here so an impossible success still cannot validate
            # as an unrelated artifact.
            narrative_artifact_path = narrative_path

    results: list = []
    verification_failed = 0
    narrative_failed = 0
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        for slug in slugs:
            try:
                request = _request_for_slug(
                    client, payload, slug, derive_binding=payload_file is None
                )
                result = require_finding_write_response(
                    client.post(f"findings/{slug}/verify", request),
                    finding_slug=slug,
                    operation="finding verify",
                )
            except Exception as exc:  # noqa: BLE001 - one bad slug must not drop the rest
                verification_failed += 1
                print(f"finding verify: {slug} failed: {exc}", file=sys.stderr)
                continue

            results.append(result)
            if narrative_path:
                try:
                    narrative_payload = {
                        "path": narrative_path,
                        "kind": "verification-narrative",
                        "related_finding_slug": slug,
                    }
                    if producer_role:
                        narrative_payload["producer_agent_role"] = producer_role
                    result["narrative_artifact"] = require_artifact_write_response(
                        client.post("artifacts", narrative_payload),
                        artifact_path=narrative_artifact_path,
                        operation=f"register verification narrative for {slug}",
                    )
                except Exception as exc:  # noqa: BLE001 - verification already committed
                    narrative_failed += 1
                    print(
                        f"finding verify: {slug} verification committed; narrative "
                        f"registration failed: {exc}. Do not retry the verification; "
                        "inspect artifact state and reconcile the narrative registration "
                        "separately.",
                        file=sys.stderr,
                    )

    if len(slugs) == 1 and results:
        print(json.dumps(results[0], indent=2, ensure_ascii=False))
    else:
        for result in results:
            print(json.dumps(result, ensure_ascii=False))
        if narrative_path:
            print(
                f"[finding verify] verified {len(results)} finding(s); "
                f"{verification_failed} verification failed; "
                f"{narrative_failed} narrative registration failed.",
                file=sys.stderr,
            )
        else:
            print(
                f"[finding verify] verified {len(results)} finding(s); "
                f"{verification_failed} failed.",
                file=sys.stderr,
            )
    if verification_failed or narrative_failed:
        sys.exit(1)
