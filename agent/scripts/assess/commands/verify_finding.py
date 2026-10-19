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
    p.add_argument("--new-severity", help="Required for downgraded verification")
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
    p.set_defaults(func=run)


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
        print(
            "finding verify: pending_runtime_proof requires --next-test-file <plan.json> "
            "(a next_test object {hypothesis, confirm_if, falsify_if, route_hint, "
            "prerequisites}); run `vigil assess contract finding verify` for the shape",
            file=sys.stderr,
        )
        sys.exit(1)
    if not parked and plan is not None:
        print(
            "finding verify: --next-test-file / next_test applies only to "
            f"--status pending_runtime_proof (got '{payload.get('verification_status')}')",
            file=sys.stderr,
        )
        sys.exit(1)
    problems = next_test_problems(plan) if plan is not None else []
    if problems:
        print(f"finding verify: {'; '.join(problems)}", file=sys.stderr)
        sys.exit(1)


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
        print(
            "finding verify: --inline was removed; use --status/--reason and related "
            "explicit flags, or --payload-file <path> for a final transition payload.",
            file=sys.stderr,
        )
        sys.exit(1)

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
            print("finding verify: --payload-file must not be empty", file=sys.stderr)
            sys.exit(1)
        provided_flags = _provided_content_flags(args)
        if provided_flags:
            print(
                "finding verify: --payload-file cannot be combined with request-content flags "
                f"({', '.join(provided_flags)}); put the complete transition in the file or use "
                "explicit verification flags. --narrative may be used with either form.",
                file=sys.stderr,
            )
            sys.exit(1)
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
                print(f"finding verify: --next-test-file: {exc}", file=sys.stderr)
                sys.exit(1)
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
    if payload.get("verification_status") == "false_positive":
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
    if payload.get("verification_status") in {"confirmed", "downgraded"} and not payload.get(
        "proof_receipt_ids"
    ):
        print(
            "terminal verification requires at least one --proof-receipt-id",
            file=sys.stderr,
        )
        sys.exit(1)
    if payload.get("verification_status") in {"confirmed", "downgraded"}:
        confirm_check = payload.get("confirm_check")
        if not isinstance(confirm_check, dict) or confirm_check.get("completed") is not True:
            print(
                "confirmed/downgraded verification requires --confirm-check-file "
                "with a completed structured falsification check",
                file=sys.stderr,
            )
            sys.exit(1)
    if payload.get("verification_status") == "downgraded" and not payload.get("new_severity"):
        print("downgraded verification requires new_severity", file=sys.stderr)
        sys.exit(1)
    if payload.get("new_severity") and payload.get("verification_status") != "downgraded":
        # Only the downgraded status consumes new_severity; anywhere else it
        # was silently dropped server-side. Fail before the POST with the verb
        # that actually re-bands a finding (mirrors the backend rejection). The
        # remedy names EVERY slug in the batch: naming only the first would
        # re-band one finding and silently leave the rest at the old severity.
        print(
            "new_severity applies only to --status downgraded (got "
            f"'{payload.get('verification_status')}'); change the band with "
            f"`vigil assess finding update {' '.join(slugs) or '<slug>'} --severity "
            f"{payload['new_severity']}`",
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
