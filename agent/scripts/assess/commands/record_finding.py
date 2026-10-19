"""vigil assess finding record — most complex command.

Slug allocate → normalize defaults → schema validate → POST → emit event.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from assess.lib.client import (
    AssessError,
    AssessmentClient,
    require_finding_write_response,
)
from assess.lib.code_snapshot_binding import fill_binding
from assess.lib.config import load_config
from assess.lib.contracts import common_mistake_hints, render_contract
from assess.lib.exploit_targets import is_source_bound
from assess.lib.findings import finding_lock_path, next_finding_id
from assess.lib.locking import file_lock
from assess.lib.next_test import load_next_test_file
from assess.lib.schema_validation import collect_validation_errors, load_schema
from assess.lib.evidence_ref import evidence_ref_exists, is_single_path_shaped


# The confirmation-mode vocabulary, mirroring the backend request models and
# `finding update --evidence-type`. Nullable by design — see the flag help.
_EVIDENCE_TYPES = ("network-confirmed", "code-inferred", "theoretical", "informational")


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "record",
        help="Record a structured finding",
        epilog="See `vigil assess contract finding record` for the canonical payload shape and examples.",
    )
    p.add_argument("agent_name", help="Agent name (e.g. vulnerability-analyst)")
    p.add_argument("json_file", help="Path to finding JSON file")
    p.add_argument(
        "--allow-unindexed-evidence",
        dest="allow_unindexed_evidence",
        action="store_true",
        help="Silence record-time warnings about an unindexed evidence_ref (prose, URL, or a "
             "non-existent path). Recording always succeeds either way — check-phase-readiness --phase report "
             "is the backstop for missing evidence; a URL is rerouted into details.references "
             "regardless. Use for theoretical/code-inferred findings with no captured file yet.",
    )
    p.add_argument(
        "--update",
        dest="update_slug",
        metavar="SLUG",
        default="",
        help="Intentionally MODIFY the existing finding SLUG instead of recording a net-new one "
             "(I-21 opt-in). A net-new record whose dedup tuple (defect_family + root_cause_key + "
             "auth_context + canonical_location) collides with a reported/active finding under a "
             "different slug is otherwise REFUSED, to avoid silently overwriting it. Pass --update "
             "<slug> only when you mean to change that exact finding; for a distinct sibling on the "
             "same root cause, give it a distinct root_cause_key/defect_family and use finding link.",
    )
    p.add_argument(
        "--allow-remint",
        "--force",
        dest="allow_remint",
        action="store_true",
        help="D4 override: mint this finding even though it shares an endpoint + technique with a "
             "finding previously KILLED as false_positive. Without this flag such a re-mint is "
             "REFUSED so a disproven finding cannot silently resurrect at a different "
             "canonical_location. Use only for a genuinely NEW finding that merely coincides on "
             "endpoint + technique; if the prior kill was wrong, run "
             "`finding update <slug> --status draft --reason \"...\"` instead.",
    )
    p.add_argument(
        "--agent-id",
        dest="agent_id",
        default="",
        help="Dispatch agent_id of the agent AUTHORING this finding (e.g. HUNT-RUN-1), copied "
             "verbatim from your Runtime Identity block. Stored as provenance.agent_id, the "
             "finding's durable author identity: terminal verification (confirmed / downgraded / "
             "false_positive) is REFUSED unless it resolves to a dispatch that is not the "
             "verifier's. The positional agent_name is a role, not a dispatch id, so it cannot "
             "stand in. Required for a new finding and checked against this engagement's "
             "dispatches. It may be omitted with --update because the stored author is preserved; "
             "historical rows with missing or invalid authors must first use finding bind-author.",
    )
    p.add_argument(
        "--evidence-type",
        dest="evidence_type",
        default="",
        choices=_EVIDENCE_TYPES,
        help=(
            "C44: classify this finding's confirmation mode, the same vocabulary "
            "`finding update --evidence-type` patches. network-confirmed = captured "
            "HTTP request/response; code-inferred = pattern present in source, no "
            "runtime proof; theoretical = chain-dependent (pair with "
            "details.chain_required + details.chain_rationale); informational = "
            "observation with no proven attack path. Deliberately has NO default: "
            "an unlabelled record stores NULL rather than asserting a confirmation "
            "mode nobody claimed. May also be set as `evidence_type` in the JSON "
            "payload; the two must agree."
        ),
    )
    p.add_argument(
        "--pending-runtime-proof",
        dest="pending_runtime_proof_reason",
        metavar="REASON",
        default="",
        help="Record the finding and park it at verification_status=pending_runtime_proof in "
             "the same invocation, with REASON as the transition rationale. A new finding "
             "always opens at 'unreviewed', so a code finding that is real but has no runtime "
             "trigger yet otherwise costs a second `finding verify` call. The park carries the "
             "same author identity and code-snapshot binding as the record, and the ledger "
             "records the same transition it would have; only the round trip is removed. "
             "Requires --next-test-file.",
    )
    p.add_argument(
        "--next-test-file",
        default="",
        help="Runtime proof plan JSON for the --pending-runtime-proof park: the same "
             "next_test object `finding verify --status pending_runtime_proof --next-test-file` "
             "takes. Required with --pending-runtime-proof and refused without it; both are "
             "checked before anything is recorded.",
    )
    p.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress non-error warnings and duplicate advisories; the canonical slug remains on stdout.",
    )
    p.set_defaults(func=run)


_FINDING_SCHEMA = load_schema("finding-record.schema.json")

# `finding-record.schema.json` lists every verification status because it also
# validates STORED and captured records, so it cannot refuse a record-time value
# the create request model rejects. Record opens the axis; `finding verify` owns
# every move off it, and owns the evidence gates that make those moves mean
# something — a payload that opened at `confirmed` used to clear client
# validation and come back an opaque 422.
_RECORD_TIME_VERIFICATION_STATUS = "unreviewed"


def _require_atomic_candidate_response(
    response: dict, request: dict
) -> dict:
    candidate = response.get("run_candidate")
    finding = response.get("finding")
    required_provenance_fields = {
        "target_key",
        "source_id",
        "source_anchor",
        "originating_result_id",
        "originating_signal_id",
    }
    valid = (
        isinstance(candidate, dict)
        and isinstance(finding, dict)
        and candidate.get("id") == request.get("candidate_id")
        and candidate.get("run_id") == request.get("run_id")
        and candidate.get("state") == "promoted"
        and candidate.get("finding_slug") == finding.get("slug")
        and candidate.get("proof_receipt_ids") == request.get("proof_receipt_ids")
        and required_provenance_fields.issubset(candidate)
        and isinstance(candidate.get("target_key"), str)
        and bool(candidate["target_key"].strip())
        and isinstance(candidate.get("source_anchor"), str)
        and bool(candidate["source_anchor"].strip())
    )
    if not valid:
        raise AssessError(
            "backend response did not preserve the requested candidate provenance"
        )
    return response


def _refuse_non_initial_verification_status(payload: dict) -> None:
    """Refuse a record that opens at anything but ``unreviewed``.

    The backend pins the create request model to ``Literal["unreviewed"]`` so
    that every later disposition goes through ``finding verify`` and its
    evidence gates. Say that here, naming the verb, instead of letting the
    payload pass the schema and come back a 422 that names neither.
    """
    incoming = str(payload.get("verification_status") or "").strip()
    if not incoming or incoming == _RECORD_TIME_VERIFICATION_STATUS:
        return
    slug = str(payload.get("slug") or "<slug>")
    print(
        f"finding record: REFUSED — verification_status={incoming!r} cannot be set at record "
        f"time; a new finding always opens at {_RECORD_TIME_VERIFICATION_STATUS!r}.\n"
        f"  - Record it first, then move the axis with its evidence: "
        f"`vigil assess finding verify {slug} --status {incoming} --reason \"...\"`.",
        file=sys.stderr,
    )
    sys.exit(1)


def _apply_evidence_type(payload: dict, evidence_type: str) -> None:
    """Land ``--evidence-type`` on the payload, refusing a contradicted label.

    No default: an unlabelled record stores NULL rather than asserting a
    confirmation mode nobody claimed. The flag and the JSON key are two
    spellings of one field, so a disagreement is an authoring error — the same
    stance ``--update`` takes on a slug embedded in the payload.
    """
    flag = (evidence_type or "").strip()
    if not flag:
        return
    embedded = str(payload.get("evidence_type") or "").strip()
    if embedded and embedded != flag:
        print(
            f"finding record: REFUSED — --evidence-type {flag!r} contradicts "
            f"evidence_type {embedded!r} in the JSON payload. Set it in one place.",
            file=sys.stderr,
        )
        sys.exit(1)
    payload["evidence_type"] = flag


def _normalize_payload(
    payload: dict,
    *,
    agent_name: str,
    candidate_slug: str,
    dispatch_agent_id: str = "",
    evidence_type: str = "",
) -> dict:
    normalized = dict(payload)
    normalized["slug"] = candidate_slug
    normalized.setdefault("source_name", agent_name)
    normalized.setdefault("severity", "medium")
    normalized.setdefault("workflow_status", "active")
    _refuse_non_initial_verification_status(normalized)
    normalized.setdefault("verification_status", _RECORD_TIME_VERIFICATION_STATUS)
    _apply_evidence_type(normalized, evidence_type)
    normalized.setdefault("defect_family", normalized.get("title", candidate_slug))
    normalized.setdefault("root_cause_key", "")
    normalized.setdefault("auth_context", "anonymous")
    normalized.setdefault("canonical_location", "")
    normalized.setdefault("summary", normalized.get("title", candidate_slug))
    normalized.setdefault("evidence_ref", "")
    normalized.setdefault("notes", "")

    details = normalized.get("details") or {}
    if not isinstance(details, dict):
        details = {}
    details.setdefault("discovered_by", agent_name)
    normalized["details"] = details

    provenance = normalized.get("provenance") or {}
    if not isinstance(provenance, dict):
        provenance = {}
    provenance.setdefault("agent_name", agent_name)
    # agent_name is a ROLE; provenance.agent_id is the authoring DISPATCH, which is
    # what the backend resolves to decide whether a later verifier is independent.
    # Only an explicit carrier can supply it — inferring the dispatch from the role
    # would mis-attribute authorship whenever parallel lanes share a role, and a
    # wrong author is worse than a missing one.
    if dispatch_agent_id:
        provenance.setdefault("agent_id", dispatch_agent_id)
    normalized["provenance"] = provenance

    normalized.setdefault("links", [])
    return normalized


# Evidence-ref shape and existence rules live in ``assess.lib.evidence_ref`` so this
# command, ``finding update`` and ``record-probe`` cannot drift apart on what counts
# as one engagement-local path. That module mirrors the backend indexer
# (``artifact_index._path_ref``), which is the rule that actually decides whether an
# artifact row gets minted.
_evidence_file_exists = evidence_ref_exists
_is_single_path_shaped = is_single_path_shaped


def _normalize_evidence_ref(payload: dict, *, eng_dir: str, engagement_key: str, allow_unindexed: bool) -> None:
    """Normalize evidence_ref at record time WITHOUT blocking the record.

    Recording a real finding mid-hunt must
    always work, even before proof is a registered artifact — check-report-
    readiness is the terminal backstop for missing evidence, not record time.
    So this warns and, for URLs, reroutes — it never exits.

    - existing on-disk file OR directory -> accepted as-is (the backend
      auto-registers it).
    - URL -> rerouted into ``details.references`` and evidence_ref cleared
      (a URL is never an auto-registerable artifact path).
    - composite ("scans/a.out; scans/b.out") / prose ("command-runs 1/2/3") ->
      warned, and the backend mints NO artifact row for it; the record proceeds.
    - path-shaped but non-existent -> warned; the record still proceeds.
    - empty -> warned; evidence may be attached on a later update.

    ``allow_unindexed`` silences the warnings for intentionally-unindexed
    (theoretical / code-inferred) findings; the URL reroute still happens so
    the URL is never lost.
    """
    ref = (payload.get("evidence_ref") or "").strip()

    if ref.startswith(("http://", "https://")):
        details = payload.get("details")
        if not isinstance(details, dict):
            details = {}
            payload["details"] = details
        refs = details.setdefault("references", [])
        if isinstance(refs, list) and ref not in refs:
            refs.append(ref)
        payload["evidence_ref"] = ""
        if not allow_unindexed:
            print(
                f"finding record: evidence_ref '{ref}' is a URL, not a registered artifact path "
                "— rerouted into details.references and cleared evidence_ref. Attach a captured "
                "artifact later so report-readiness can index replayable proof.",
                file=sys.stderr,
            )
        return

    if allow_unindexed:
        return

    if not ref:
        print(
            "finding record: warning — no evidence_ref set; check-phase-readiness --phase report will flag "
            "this finding as missing evidence. Set evidence_ref to a captured artifact path or "
            "pass --allow-unindexed-evidence to silence.",
            file=sys.stderr,
        )
        return

    if _evidence_file_exists(ref, eng_dir, engagement_key):
        return  # existing artifact — the backend registers + links it on record.

    if _is_single_path_shaped(ref):
        print(
            f"finding record: warning — evidence_ref '{ref}' looks like a path but nothing exists "
            "there; recording anyway. check-phase-readiness --phase report will flag it until a real artifact is "
            "attached. Pass --allow-unindexed-evidence to silence.",
            file=sys.stderr,
        )
    else:
        print(
            f"finding record: warning — evidence_ref '{ref}' is not a single engagement-local path "
            "(it reads as prose or joins several references), so NO artifact row is created for it; "
            "recording anyway. Point evidence_ref at ONE captured path — a directory of captured "
            "evidence is fine — put external links in details.references, and use `vigil assess "
            "finding link` / details.evidence for the rest. Pass --allow-unindexed-evidence to silence.",
            file=sys.stderr,
        )


# I-21 (clobber guard): the backend dedup UPSERT matches a net-new record onto
# an existing finding by the (defect_family + root_cause_key + auth_context +
# canonical_location) tuple, NOT by slug. Recording a net-new finding that
# collides that tuple with a load-bearing (reported/active) finding under a
# DIFFERENT slug silently overwrote it. This CLI check fails fast with the same
# actionable guidance the backend match enforces (dual enforcement: a CLI bypass
# cannot defeat the authoritative HTTP guard in state_manager/findings.py).
# ``draft`` is fair game for the historical upsert; ``false_positive`` / ``merged``
# stay semantically sticky — both are outside the guard set, matching the backend.
_CLOBBER_GUARDED_STATUSES = frozenset({"active", "reported"})

# Marker phrases the backend embeds in its refusal 409 details. Used to translate
# a backstop refusal (e.g. a title-tier clobber match the CLI tuple-check does not
# model, a race, or the D4 killed-finding re-mint guard which has no CLI mirror)
# into a clean operator message instead of a raw HTTP dump.
_BACKEND_CLOBBER_MARKER = "Refusing to clobber"
_BACKEND_REMINT_MARKER = "Refusing to re-mint"


def _find_clobbered_finding(
    existing_findings,
    *,
    candidate_slug: str,
    defect_family: str,
    root_cause_key: str,
    auth_context: str,
    canonical_location: str,
) -> dict | None:
    """Return an existing finding a net-new record would silently clobber.

    Mirrors the backend dedup tuple. Returns the matching reported/active finding
    recorded under a DIFFERENT slug, or ``None`` when the record is safe. An empty
    ``defect_family``/``root_cause_key`` cannot collide on the tuple, so the check
    is skipped — the backend's title-fallback tier remains the backstop.
    """
    if not (defect_family and root_cause_key):
        return None
    for finding in existing_findings:
        if not isinstance(finding, dict):
            continue
        if str(finding.get("slug", "")) == candidate_slug:
            continue
        if str(finding.get("workflow_status", "")).strip().lower() not in _CLOBBER_GUARDED_STATUSES:
            continue
        if (
            str(finding.get("defect_family", "")) == defect_family
            and str(finding.get("root_cause_key", "")) == root_cause_key
            and str(finding.get("auth_context", "")) == auth_context
            and str(finding.get("canonical_location", "")) == canonical_location
        ):
            return finding
    return None


def _refuse_clobber(existing: dict) -> None:
    existing_slug = str(existing.get("slug", ""))
    existing_status = str(existing.get("workflow_status", ""))
    print(
        f"finding record: REFUSED — this finding's dedup tuple (defect_family + root_cause_key "
        f"+ auth_context + canonical_location) collides with existing finding {existing_slug} "
        f"(workflow_status={existing_status}); recording it would silently overwrite that "
        f"{existing_status} finding.\n"
        f"  - Distinct sibling on the same root cause? Give it a DISTINCT root_cause_key/"
        f"defect_family, then attach it after recording with "
        f"`vigil assess finding link <this-slug> --root-cause {existing_slug}`.\n"
        f"  - Intend to MODIFY {existing_slug}? Re-run with `--update {existing_slug}`.",
        file=sys.stderr,
    )
    sys.exit(1)


def _resolve_update_target(
    update_slug: str, json_slug: str, *, base_url: str, engagement_key: str
) -> dict:
    """Resolve ``--update <slug>`` to the target slug, validating operator intent.

    --update is the explicit opt-in to MODIFY an existing finding (I-21): it must
    name an EXISTING slug and may not contradict a slug embedded in the JSON. The
    resolved slug becomes the record's slug so the backend matches it directly
    (its first tier) rather than re-running the net-new dedup collision.
    """
    if json_slug and json_slug != update_slug:
        print(
            f"finding record: --update {update_slug} conflicts with slug '{json_slug}' in the "
            f"JSON payload. Drop the JSON slug or set it to {update_slug}.",
            file=sys.stderr,
        )
        sys.exit(1)
    with AssessmentClient(base_url, engagement_key) as client:
        try:
            existing = client.get(f"findings/{update_slug}")
        except AssessError as exc:
            if "HTTP 404" in str(exc):
                existing = None
            else:
                raise
    if not isinstance(existing, dict) or not existing.get("slug"):
        print(
            f"finding record: --update {update_slug} names a finding that does not exist. Record "
            f"it without --update to create a new finding, or pass the correct existing slug.",
            file=sys.stderr,
        )
        sys.exit(1)
    return existing


def _require_authoring_dispatch(
    payload: dict,
    *,
    existing: dict | None,
    base_url: str,
    engagement_key: str,
) -> None:
    """Fail before POST unless the immutable author is a real dispatch."""

    provenance = payload.get("provenance")
    incoming = (
        str(provenance.get("agent_id") or "").strip()
        if isinstance(provenance, dict)
        else ""
    )
    if existing is None:
        author = incoming
        if not author:
            print(
                "finding record: REFUSED — new findings require provenance.agent_id. "
                "Pass --agent-id <your Runtime Identity agent_id>; the role name cannot "
                "identify one dispatch.",
                file=sys.stderr,
            )
            sys.exit(1)
    else:
        stored_provenance = existing.get("provenance")
        author = (
            str(stored_provenance.get("agent_id") or "").strip()
            if isinstance(stored_provenance, dict)
            else ""
        )
        if not author:
            slug = str(existing.get("slug") or "this finding")
            print(
                f"finding record: REFUSED — {slug} is a historical finding with no author. "
                "Run `vigil assess finding bind-author` once before re-recording it.",
                file=sys.stderr,
            )
            sys.exit(1)
        if incoming and incoming != author:
            print(
                "finding record: REFUSED — provenance.agent_id is immutable after "
                f"creation (stored {author!r}, received {incoming!r}).",
                file=sys.stderr,
            )
            sys.exit(1)

    with AssessmentClient(base_url, engagement_key) as client:
        try:
            dispatch = client.get(f"dispatches/{author}")
        except AssessError as exc:
            if "HTTP 404" not in str(exc):
                raise
            dispatch = None
    if not isinstance(dispatch, dict) or dispatch.get("agent_id") != author:
        print(
            f"finding record: REFUSED — provenance.agent_id {author!r} does not resolve "
            "to a dispatch in this engagement. Run `vigil assess finding bind-author` "
            "once to repair this invalid historical binding.",
            file=sys.stderr,
        )
        sys.exit(1)


def _guard_finding_clobber(payload: dict, *, candidate_slug: str, base_url: str, engagement_key: str) -> None:
    """Refuse a net-new record that would silently overwrite a reported/active
    finding under a different slug (I-21). The backend match is the authoritative
    backstop; this fails fast before the POST with the same guidance."""
    with AssessmentClient(base_url, engagement_key) as client:
        findings = client.get("findings")
    if not isinstance(findings, list):
        return
    clobbered = _find_clobbered_finding(
        findings,
        candidate_slug=candidate_slug,
        defect_family=str(payload.get("defect_family", "")),
        root_cause_key=str(payload.get("root_cause_key", "")),
        auth_context=str(payload.get("auth_context", "")),
        canonical_location=str(payload.get("canonical_location", "")),
    )
    if clobbered is not None:
        _refuse_clobber(clobbered)


def _print_backend_clobber_refusal(exc: AssessError) -> bool:
    """If ``exc`` is a backend clobber-guard or D4 re-mint-guard 409, print its
    actionable detail and return True (caller should exit 1). Otherwise return
    False so the caller re-raises and other errors keep their existing handling."""
    message = str(exc)
    if "HTTP 409" not in message or (
        _BACKEND_CLOBBER_MARKER not in message and _BACKEND_REMINT_MARKER not in message
    ):
        return False
    _, _, body = message.partition("\n")
    detail = body
    try:
        parsed = json.loads(body)
    except json.JSONDecodeError:
        parsed = None
    if isinstance(parsed, dict) and isinstance(parsed.get("detail"), str):
        detail = parsed["detail"]
    print(f"finding record: REFUSED — {detail}", file=sys.stderr)
    return True


def _print_duplicate_advisories(response: object, *, quiet: bool) -> None:
    """Surface advisory-only duplicate matches returned by the backend."""
    if quiet or not isinstance(response, dict):
        return
    advisories = response.get("duplicate_advisories")
    if not isinstance(advisories, list):
        return
    for advisory in advisories:
        if not isinstance(advisory, dict):
            continue
        detail = advisory.get("detail")
        if not isinstance(detail, str) or not detail.strip():
            slug = str(advisory.get("slug") or "unknown finding")
            matched_on = str(advisory.get("matched_on") or "an existing submission")
            detail = f"{slug} matches {matched_on}."
        print(f"finding record: duplicate advisory — {detail}", file=sys.stderr)


def _fill_derivable_provenance(payload: dict, *, base_url: str, engagement_key: str) -> None:
    """Derive ``provenance.code_snapshot`` for a file finding that authored none.

    The binding is the repository's own current identity, so the author was only
    ever transcribing it out of Code Source Identity — and a transcription error
    reads as a stale binding rather than as the mistake it is. An authored
    binding is left exactly as written, stale included, so the currency gate
    still sees what the author claimed.
    """
    if not is_source_bound(str(payload.get("canonical_location", ""))):
        return
    provenance = payload["provenance"]
    if provenance.get("code_snapshot"):
        return
    with AssessmentClient(base_url, engagement_key) as client:
        fill_binding(provenance, client, operation="finding record")


def _park_pending_runtime_proof(
    finding_slug: str,
    reason: str,
    *,
    next_test: dict | None,
    provenance: dict,
    agent_name: str,
    base_url: str,
    engagement_key: str,
) -> None:
    """Move the freshly-recorded finding to ``pending_runtime_proof``.

    Record pins the axis to ``unreviewed`` so that every later disposition goes
    through ``finding verify`` and its evidence gates. This is that same verify
    transition, through the same route and the same ledger — it just does not
    make the caller spend a second invocation to reach the one status that needs
    no evidence beyond the reason it is owed.
    """
    payload = {
        "verification_status": "pending_runtime_proof",
        "reason_text": reason,
        "source_name": agent_name,
        "provenance": provenance,
        "next_test": next_test,
    }
    with AssessmentClient(base_url, engagement_key) as client:
        response = client.post(f"findings/{finding_slug}/verify", payload)
    require_finding_write_response(
        response,
        finding_slug=finding_slug,
        operation="finding record --pending-runtime-proof",
    )
    print(
        f"finding record: {finding_slug} recorded and parked at pending_runtime_proof.",
        file=sys.stderr,
    )


def _report_validation_errors(payload: dict, errors: list[str]) -> None:
    print("finding payload invalid after helper defaults:", file=sys.stderr)
    for error in errors:
        print(f"  - {error}", file=sys.stderr)

    hints = common_mistake_hints("finding record", payload)
    if hints:
        print("Common legacy-field fixes:", file=sys.stderr)
        for hint in hints:
            print(f"  - {hint}", file=sys.stderr)

    print("", file=sys.stderr)
    print("Run `vigil assess contract finding record` for the canonical helper contract.", file=sys.stderr)
    print("", file=sys.stderr)
    print(render_contract("finding record"), file=sys.stderr)
    sys.exit(1)


def run(args) -> None:
    cfg = load_config(args.engagement_dir)
    eng_dir = cfg.engagement_dir

    json_path = Path(args.json_file)
    if not json_path.is_file():
        print(f"finding json file not found: {args.json_file}", file=sys.stderr)
        sys.exit(1)

    payload = json.loads(json_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        print("finding payload must be a JSON object", file=sys.stderr)
        sys.exit(1)

    park_reason = (getattr(args, "pending_runtime_proof_reason", "") or "").strip()
    next_test_file = (getattr(args, "next_test_file", "") or "").strip()
    next_test = None
    if bool(park_reason) != bool(next_test_file):
        # Checked before the record: a park that cannot be sent must not leave
        # a recorded-but-unparked finding behind.
        print(
            "finding record: --pending-runtime-proof and --next-test-file go together; "
            "the park is a pending_runtime_proof verification and carries its runtime "
            "proof plan (see `vigil assess contract finding verify`).",
            file=sys.stderr,
        )
        sys.exit(1)
    if next_test_file:
        try:
            next_test = load_next_test_file(next_test_file)
        except ValueError as exc:
            print(f"finding record: --next-test-file: {exc}", file=sys.stderr)
            sys.exit(1)

    agent_name = args.agent_name
    update_slug = (getattr(args, "update_slug", "") or "").strip()

    lock_path = finding_lock_path(eng_dir)
    with file_lock(lock_path):
        candidate_slug = payload.get("slug", "")
        existing_update = None
        if update_slug:
            # --update names the EXACT existing finding to modify; it is the
            # explicit opt-in past the clobber guard. The slug becomes the target
            # so the backend matches by slug rather than by a net-new collision.
            existing_update = _resolve_update_target(
                update_slug,
                candidate_slug,
                base_url=cfg.base_url,
                engagement_key=cfg.engagement_key,
            )
            candidate_slug = str(existing_update["slug"])
        elif not candidate_slug:
            candidate_slug = next_finding_id(cfg.base_url, cfg.engagement_key, agent_name)

        payload = _normalize_payload(
            payload,
            agent_name=agent_name,
            candidate_slug=candidate_slug,
            dispatch_agent_id=(getattr(args, "agent_id", "") or "").strip(),
            evidence_type=(getattr(args, "evidence_type", "") or "").strip(),
        )
        _fill_derivable_provenance(
            payload, base_url=cfg.base_url, engagement_key=cfg.engagement_key
        )
        validation_errors = collect_validation_errors(payload, _FINDING_SCHEMA)
        if validation_errors:
            _report_validation_errors(payload, validation_errors)
        _require_authoring_dispatch(
            payload,
            existing=existing_update,
            base_url=cfg.base_url,
            engagement_key=cfg.engagement_key,
        )

        _normalize_evidence_ref(
            payload,
            eng_dir=eng_dir,
            engagement_key=cfg.engagement_key,
            allow_unindexed=(
                getattr(args, "allow_unindexed_evidence", False)
                or getattr(args, "quiet", False)
            ),
        )

        if not update_slug:
            _guard_finding_clobber(
                payload,
                candidate_slug=candidate_slug,
                base_url=cfg.base_url,
                engagement_key=cfg.engagement_key,
            )

        # D4 override: injected AFTER schema validation (it is a control flag, not a
        # finding-record.schema.json field) so the backend's killed-remint guard is
        # skipped for an intentional distinct re-mint.
        if getattr(args, "allow_remint", False):
            payload["allow_remint"] = True

        with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
            try:
                response = client.post("findings", payload)
            except AssessError as exc:
                # Backstop: the authoritative backend guard refused a clobber the
                # CLI tuple-check did not model (title-tier match, or a race).
                if _print_backend_clobber_refusal(exc):
                    sys.exit(1)
                raise

        try:
            response = require_finding_write_response(
                response,
                finding_slug=candidate_slug,
                operation="finding record",
            )
            if isinstance(payload.get("run_candidate"), dict):
                response = _require_atomic_candidate_response(
                    response, payload["run_candidate"]
                )
        except AssessError as exc:
            print(f"finding record: {exc}", file=sys.stderr)
            sys.exit(1)

        finding = response.get("finding", {})
        if not finding.get("slug") or not finding.get("title"):
            print("finding record: orchestrator backend did not return a canonical finding record", file=sys.stderr)
            sys.exit(1)

        finding_slug = finding["slug"]
        _print_duplicate_advisories(
            response,
            quiet=getattr(args, "quiet", False),
        )

    # Emit event (outside lock)
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        client.post_event({
            "event_type": "finding.created",
            "phase": os.environ.get("ORCHESTRATOR_PHASE", "unknown"),
            "task_name": finding_slug,
            "agent_name": agent_name,
            "summary": f"Recorded {finding_slug}",
        })

    # The record is durable by now, so the canonical slug goes out before the
    # park: a park that fails must not read as a record that never happened.
    print(finding_slug)

    if park_reason:
        try:
            _park_pending_runtime_proof(
                finding_slug,
                park_reason,
                next_test=next_test,
                provenance=payload["provenance"],
                agent_name=agent_name,
                base_url=cfg.base_url,
                engagement_key=cfg.engagement_key,
            )
        except AssessError as exc:
            print(
                f"finding record: {finding_slug} WAS recorded, but parking it at "
                f"pending_runtime_proof failed: {exc}\n"
                f"  - Retry only the park: `vigil assess finding verify {finding_slug} "
                f'--status pending_runtime_proof --reason "{park_reason}" '
                f'--next-test-file {next_test_file}`.',
                file=sys.stderr,
            )
            sys.exit(1)
